import random

import pytest

from cloudforensix.correlation import EntityGraphCorrelator, reconstruct
from cloudforensix.custody import EvidencePackage
from cloudforensix.detector import HybridDetector, RuleDetector
from cloudforensix.isolation import isolate, leakage
from cloudforensix.metrics import detection_metrics, reconstruction_metrics
from cloudforensix.normalizer import Normalizer, is_external
from cloudforensix.pipeline import ForensicPipeline
from cloudforensix.seclog import FRSL, SCHEMES, BloomFilter, HashChain, merkle_levels, merkle_proof, merkle_root, merkle_verify, tamper
from cloudforensix.simulator import BASE_TS, CloudSimulator


@pytest.fixture(scope="module")
def world():
    sim = CloudSimulator(seed=5, n_tenants=3, hours=12, campaigns_per_type=1, attack_start_h=4)
    recs = sim.run()
    inv = sim.inventory()
    ev = Normalizer(inv).parse_all(recs)
    ev.sort(key=lambda e: e.ts)
    return sim, recs, inv, ev


def test_simulator_deterministic():
    a = [r.line for r in CloudSimulator(seed=3, hours=2).run()]
    b = [r.line for r in CloudSimulator(seed=3, hours=2).run()]
    assert a == b


def test_normaliser_recovers_utc(world):
    _, recs, _, ev = world
    assert len(ev) == len(recs)
    assert max(abs(e.ts - recs[e.eid].true_ts) for e in ev) < 1.0


def test_naive_mode_is_skewed(world):
    sim, recs, inv, _ = world
    ev = Normalizer(inv, "naive").parse_all(recs)
    err = max(abs(e.ts - recs[e.eid].true_ts) for e in ev if e.source == "syslog")
    assert err > 3600


def test_is_external():
    assert not is_external("10.1.0.5")
    assert is_external("203.0.113.50")
    assert is_external("185.1.2.3")


def test_merkle_proofs():
    leaves = [bytes([i]) * 32 for i in range(13)]
    lv = merkle_levels(leaves)
    root = merkle_root(leaves)
    for i in range(13):
        assert merkle_verify(leaves[i], merkle_proof(lv, i), root)
    assert not merkle_verify(b"x" * 32, merkle_proof(lv, 0), root)


def test_bloom_no_false_negatives():
    b = BloomFilter(1000, 0.01)
    items = [str(i).encode() for i in range(1000)]
    for x in items:
        b.add(x)
    assert all(x in b for x in items)


@pytest.mark.parametrize("cls", SCHEMES)
def test_clean_logs_verify(cls):
    s = cls()
    for i in range(500):
        s.append(b"entry %d" % i)
    s.seal()
    assert s.verify()


@pytest.mark.parametrize("attack", ["modify", "delete", "insert", "reorder", "truncate"])
@pytest.mark.parametrize("recompute", [False, True])
def test_frsl_detects_insider(attack, recompute):
    s = FRSL(epoch=64)
    for i in range(400):
        s.append(b"entry %d Failure" % i)
    s.seal()
    tamper(s, attack, random.Random(1), recompute)
    assert not s.verify()


def test_hash_chain_defeated_by_recompute():
    s = HashChain()
    for i in range(100):
        s.append(b"e%d" % i)
    tamper(s, "modify", random.Random(0), recompute=True)
    assert s.verify()  # motivates external anchoring


def test_frsl_inclusion_proof_and_bloom():
    s = FRSL(epoch=32)
    for i in range(100):
        s.append(b"rec %d" % i)
    s.seal()
    k, proof = s.prove(57)
    assert s.verify_entry(s.store[57], k, proof)
    assert s.maybe_contains(b"rec 57")


def test_detection_finds_all_campaigns(world):
    _, recs, _, ev = world
    al = HybridDetector(BASE_TS + 4 * 3600).detect(ev)
    m = detection_metrics(al, recs, ev)
    assert m["campaign_detection_rate"] == 1.0
    rules = detection_metrics(RuleDetector().detect(ev), recs, ev)
    assert m["false_alerts"] <= rules["false_alerts"]


def test_reconstruction_improves_recall(world):
    _, recs, _, ev = world
    by = {e.eid: e for e in ev}
    al = HybridDetector(BASE_TS + 4 * 3600).detect(ev)
    inc = EntityGraphCorrelator().correlate(by, al)
    before = reconstruction_metrics(inc, recs, by, seed_only=True)["timeline_recall"]
    after = reconstruction_metrics(reconstruct(inc, ev), recs, by)["timeline_recall"]
    assert after > before and after > 0.9


def test_isolation_removes_foreign_identifiers(world):
    _, _, inv, ev = world
    lo, hi = ev[0].ts, ev[0].ts + 3 * 3600
    lines, _ = isolate(ev, "tenant-a", lo, hi, inv)
    assert leakage(lines, "tenant-a", inv) == 0
    assert leakage([e.raw for e in ev if lo <= e.ts <= hi], "tenant-a", inv) > 0


def test_custody_detects_modification():
    p = EvidencePackage("T")
    p.add("x", b"1")
    p.seal()
    assert p.verify()[0]
    p.artifacts["x"] = b"2"
    assert not p.verify()[0]


def test_pipeline_end_to_end(world, tmp_path):
    sim, recs, inv, _ = world
    pipe = ForensicPipeline(inv, train_hours=4)
    res = pipe.run(recs)
    assert res.store.verify() and res.incidents
    pkg = pipe.package(res, res.incidents[0], tmp_path)
    assert pkg.verify()[0]
    assert (tmp_path / pkg.case_id / "manifest.json").exists()
