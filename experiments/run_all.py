"""Run every experiment of the paper and write tables (CSV/JSON) and figures.

    python experiments/run_all.py            # full run (~ a few minutes)
    python experiments/run_all.py --quick    # reduced sizes for CI

Outputs go to ``results/`` (CSV + summary.json) and ``paper/figures/``.

E1  secure-logging ingest throughput and storage overhead
E2  integrity verification cost: full audit vs single-entry Merkle proof
E3  tamper detection under a malicious-CSP insider (+ unsealed-window study)
E4  live detection quality: rules vs Isolation Forest vs hybrid (5 seeds)
E5  correlation & timeline reconstruction (+ time-normalisation ablation)
E6  multi-tenant evidence isolation (privacy leakage)
E7  CSP dependency and evidence-acquisition time (Table-14 model)
E8  end-to-end pipeline scalability
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cloudforensix.artifacts import (SCENARIO_SOURCES, acquisition_time_model,  # noqa: E402
                                     csp_dependency_index)
from cloudforensix.correlation import (EntityGraphCorrelator, LeaderFollower,  # noqa: E402
                                       TimeWindowCorrelator, reconstruct)
from cloudforensix.custody import EvidencePackage  # noqa: E402
from cloudforensix.detector import AnomalyDetector, HybridDetector, RuleDetector  # noqa: E402
from cloudforensix.isolation import isolate, leakage, naive_collect  # noqa: E402
from cloudforensix.metrics import (clustering_metrics, detection_metrics,  # noqa: E402
                                   reconstruction_metrics)
from cloudforensix.normalizer import Normalizer  # noqa: E402
from cloudforensix.pipeline import ForensicPipeline  # noqa: E402
from cloudforensix.seclog import FRSL, SCHEMES, BloomFilter, H, tamper  # noqa: E402
from cloudforensix.simulator import ATTACK_TYPES, BASE_TS, CloudSimulator  # noqa: E402

RES = ROOT / "results"
FIG = ROOT / "paper" / "figures"
RES.mkdir(exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)

# reference categorical palette, fixed order; slot 1 is always the proposed method
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8.5, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "figure.dpi": 200, "savefig.bbox": "tight", "lines.linewidth": 2,
})
SCHEME_COLOR = {"FRSL (proposed)": C[0], "Plain central log": C[4], "Per-entry hash": C[3],
                "Hash chain": C[2], "Blockchain (PoW)": C[1]}
SUMMARY: dict = {}


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf")
    fig.savefig(FIG / f"{name}.png")
    plt.close(fig)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def payloads(n, seed=1):
    recs = CloudSimulator(seed=seed, hours=max(2, n / 1500)).run()
    lines = [f"{r.source}|{r.line}".encode() for r in recs]
    while len(lines) < n:
        lines += lines
    return lines[:n]


# ------------------------------------------------------------------ E1 / E2
def e1_e2(sizes):
    rows, vrows = [], []
    for n in sizes:
        data = payloads(n)
        raw = sum(len(x) for x in data)
        for cls in SCHEMES:
            ti = float("inf")
            for _ in range(3):           # best of 3 to suppress GC/scheduler noise
                s = cls()
                t0 = time.perf_counter()
                for p in data:
                    s.append(p)
                s.seal()
                ti = min(ti, time.perf_counter() - t0)
            t0 = time.perf_counter()
            ok = s.verify()
            tv = time.perf_counter() - t0
            assert ok, cls.name
            rows.append({"scheme": s.name, "n": n, "ingest_s": ti, "throughput_eps": n / ti,
                         "overhead_bytes": s.overhead_bytes(), "overhead_pct": 100 * s.overhead_bytes() / raw,
                         "full_verify_s": tv})
            if isinstance(s, FRSL):
                idx = random.Random(0).sample(range(n), min(200, n))
                t0 = time.perf_counter()
                plen = 0
                for i in idx:
                    k, proof = s.prove(i)
                    assert s.verify_entry(s.store[i], k, proof)
                    plen += len(proof)
                vrows.append({"n": n, "single_verify_ms": 1000 * (time.perf_counter() - t0) / len(idx),
                              "proof_hashes": plen / len(idx), "proof_bytes": 32 * plen / len(idx),
                              "full_verify_ms": 1000 * tv})
        log(f"E1 n={n} done")
    df, dv = pd.DataFrame(rows), pd.DataFrame(vrows)
    df.to_csv(RES / "e1_logging_overhead.csv", index=False)
    dv.to_csv(RES / "e2_verification.csv", index=False)

    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.5))
    for name, g in df.groupby("scheme", sort=False):
        ax[0].plot(g["n"], g["throughput_eps"], marker="o", ms=4, color=SCHEME_COLOR[name], label=name)
        ax[1].plot(g["n"], g["full_verify_s"], marker="o", ms=4, color=SCHEME_COLOR[name], label=name)
    for a in ax:
        a.set_xscale("log")
        a.set_xlabel("log entries")
    ax[0].set_yscale("log")
    ax[0].set_ylabel("ingest throughput (entries/s)")
    ax[1].set_yscale("log")
    ax[1].set_ylabel("full audit time (s)")
    fig.legend(*ax[0].get_legend_handles_labels(), fontsize=7, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.07))
    save(fig, "e1_throughput_verify")

    big = df[df.n == df.n.max()]
    SUMMARY["E1"] = {r.scheme: {"throughput_eps": round(r.throughput_eps), "overhead_pct": round(r.overhead_pct, 1),
                                "full_verify_s": round(r.full_verify_s, 3)} for r in big.itertuples()}
    SUMMARY["E2"] = dv.round(4).to_dict("records")

    # Bloom filter false-positive check
    bf_rows = []
    for fp in (0.01, 0.001, 0.0001):
        b = BloomFilter(10_000, fp)
        for i in range(10_000):
            b.add(H(b"in%d" % i))
        hits = sum(H(b"out%d" % i) in b for i in range(100_000))
        bf_rows.append({"target_fp": fp, "measured_fp": hits / 100_000, "bytes_per_10k": b.nbytes(), "k": b.k})
    pd.DataFrame(bf_rows).to_csv(RES / "e2_bloom.csv", index=False)
    SUMMARY["E2_bloom"] = bf_rows


# ----------------------------------------------------------------------- E3
ATTACKS = ["modify", "delete", "insert", "reorder", "truncate"]


def e3(trials, n=2000):
    data = payloads(n, seed=3)
    rng = random.Random(42)
    rows = []
    for cls in SCHEMES:
        for rec in (False, True):
            for atk in ATTACKS:
                det = 0
                for _ in range(trials):
                    s = cls(epoch=256) if cls is not SCHEMES[3] else cls(block_size=64, difficulty_bits=8)
                    for p in data:
                        s.append(p)
                    s.seal()
                    tamper(s, atk, rng, rec)
                    det += not s.verify()
                rows.append({"scheme": s.name, "recompute": rec, "attack": atk, "detection_rate": det / trials})
        log(f"E3 {cls.name} done")
    df = pd.DataFrame(rows)
    df.to_csv(RES / "e3_tamper_detection.csv", index=False)

    # window of vulnerability: entries not yet sealed when the insider strikes
    wrows = []
    for epoch in (64, 256, 1024, 4096):
        det = 0
        s = FRSL(epoch=epoch)
        for p in data[: n - 1]:
            s.append(p)
        exposed = s.unsealed()
        for _ in range(trials):
            s2 = FRSL(epoch=epoch)
            for p in data[: n - 1]:
                s2.append(p)
            tamper(s2, "truncate", rng, True)
            det += not s2.verify()
        wrows.append({"epoch": epoch, "unsealed_entries": exposed, "truncate_detection": det / trials})
    pd.DataFrame(wrows).to_csv(RES / "e3_unsealed_window.csv", index=False)

    piv = df.assign(col=df.attack + np.where(df.recompute, "\n+recompute", "")).pivot(
        index="scheme", columns="col", values="detection_rate")
    order = ["Plain central log", "Per-entry hash", "Hash chain", "Blockchain (PoW)", "FRSL (proposed)"]
    cols = [a for a in ATTACKS] + [a + "\n+recompute" for a in ATTACKS]
    piv = piv.loc[order, cols]
    fig, ax = plt.subplots(figsize=(7.0, 2.4))
    ax.grid(False)
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("b", ["#f0efec", "#86b6ef", "#1c5cab"])
    ax.pcolormesh(piv.values, cmap=cmap, vmin=0, vmax=1, edgecolors="#fcfcfb", linewidth=2)
    for i in range(piv.shape[0]):
        for j in range(piv.shape[1]):
            v = piv.values[i, j]
            ax.text(j + 0.5, i + 0.5, f"{v:.0%}", ha="center", va="center", fontsize=7,
                    color="white" if v > 0.6 else INK)
    ax.set_xticks(np.arange(len(cols)) + 0.5, ATTACKS * 2, fontsize=7)
    ax.set_yticks(np.arange(len(order)) + 0.5, order)
    ax.invert_yaxis()
    ax.tick_params(length=0)
    for x0, lab in ((2.5, "store tampered, hashes left as-is"), (7.5, "insider also recomputes stored hashes")):
        ax.text(x0, -0.35, lab, ha="center", va="bottom", fontsize=7.5, color=INK2)
    ax.axvline(5, color="#fcfcfb", lw=6)
    for sp in ax.spines.values():
        sp.set_visible(False)
    save(fig, "e3_tamper_heatmap")
    SUMMARY["E3"] = df.groupby("scheme")["detection_rate"].mean().round(3).to_dict()
    SUMMARY["E3_window"] = wrows


# ---------------------------------------------------------------------- E4/E5
def run_seed(seed, mode="corrected"):
    sim = CloudSimulator(seed=seed)
    recs = sim.run()
    inv = sim.inventory()
    ev = Normalizer(inv, mode).parse_all(recs)
    ev.sort(key=lambda e: e.ts)
    return sim, recs, inv, ev


def e4_e5(seeds):
    tu = BASE_TS + 6 * 3600
    drows, prows, crows, srows = [], [], [], []
    for seed in seeds:
        sim, recs, inv, ev = run_seed(seed)
        by = {e.eid: e for e in ev}
        hyb_alerts = None
        for D in (RuleDetector(), AnomalyDetector(tu, seed=seed), HybridDetector(tu, seed=seed)):
            t0 = time.perf_counter()
            al = D.detect(ev)
            dt = time.perf_counter() - t0
            m = detection_metrics(al, recs, ev)
            m.update(detector=D.name, seed=seed, detect_s=dt)
            drows.append(m)
            # per attack type campaign detection
            camps = defaultdict(set)
            for r in recs:
                if r.campaign:
                    camps[r.label].add(r.campaign)
            hit = {recs[e].campaign for a in al for e in a.eids if recs[e].campaign}
            for atype, cs in camps.items():
                prows.append({"detector": D.name, "seed": seed, "attack": atype,
                              "detected": len(cs & hit) / len(cs)})
            if isinstance(D, HybridDetector):
                hyb_alerts = al
        for cor in (TimeWindowCorrelator(), LeaderFollower(adaptive=False), LeaderFollower(adaptive=True),
                    EntityGraphCorrelator()):
            t0 = time.perf_counter()
            inc = cor.correlate(by, hyb_alerts)
            cm = clustering_metrics(inc, recs)
            seed_rm = reconstruction_metrics(inc, recs, by, seed_only=True)
            inc = reconstruct(inc, ev)
            rm = reconstruction_metrics(inc, recs, by)
            crows.append({"correlator": cor.name, "seed": seed, **cm,
                          "alert_only_recall": seed_rm["timeline_recall"],
                          "timeline_recall": rm["timeline_recall"], "timeline_precision": rm["timeline_precision"],
                          "time_s": time.perf_counter() - t0})
        # time-normalisation ablation
        for mode in ("naive", "corrected"):
            _, recs2, inv2, ev2 = run_seed(seed, mode) if mode == "naive" else (sim, recs, inv, ev)
            by2 = {e.eid: e for e in ev2}
            al = HybridDetector(tu, seed=seed).detect(ev2)
            inc = reconstruct(EntityGraphCorrelator().correlate(by2, al), ev2)
            rm = reconstruction_metrics(inc, recs2, by2)
            dm = detection_metrics(al, recs2, ev2)
            err = np.array([abs(e.ts - recs2[e.eid].true_ts) for e in ev2 if e.source in ("syslog", "hypervisor")])
            per = defaultdict(list)
            for c, v in rm["per_campaign_recall"].items():
                per[c.split("-", 1)[1]].append(v)
            srows.append({"mode": mode, "seed": seed, "timeline_recall": rm["timeline_recall"],
                          "ordering_accuracy": rm["ordering_accuracy"], "f1": dm["f1"],
                          "campaign_detection_rate": dm["campaign_detection_rate"],
                          "mean_abs_ts_error_s": err.mean(),
                          **{f"recall_{k}": float(np.mean(v)) for k, v in per.items()}})
        log(f"E4/E5 seed {seed} done")

    dd, dp, dc, ds = map(pd.DataFrame, (drows, prows, crows, srows))
    dd.to_csv(RES / "e4_detection.csv", index=False)
    dp.to_csv(RES / "e4_detection_per_attack.csv", index=False)
    dc.to_csv(RES / "e5_correlation.csv", index=False)
    ds.to_csv(RES / "e5_time_normalisation.csv", index=False)

    cols = ["precision", "recall", "f1", "fpr", "alert_precision", "false_alerts",
            "campaign_detection_rate", "mttd_s"]
    agg = dd.groupby("detector", sort=False)[cols].agg(["mean", "std"])
    agg.to_csv(RES / "e4_detection_summary.csv")
    SUMMARY["E4"] = {d: {c: [round(agg.loc[d, (c, "mean")], 4), round(agg.loc[d, (c, "std")], 4)] for c in cols}
                     for d in agg.index}
    SUMMARY["E4_per_attack"] = dp.groupby(["detector", "attack"])["detected"].mean().round(3).unstack().to_dict("index")
    ccols = ["ari", "v_measure", "completeness", "homogeneity", "fragmentation", "incidents",
             "alert_only_recall", "timeline_recall", "timeline_precision", "time_s"]
    cagg = dc.groupby("correlator", sort=False)[ccols].agg(["mean", "std"])
    cagg.to_csv(RES / "e5_correlation_summary.csv")
    SUMMARY["E5"] = {d: {c: [round(cagg.loc[d, (c, "mean")], 4), round(cagg.loc[d, (c, "std")], 4)] for c in ccols}
                     for d in cagg.index}
    sagg = ds.groupby("mode").mean(numeric_only=True).drop(columns="seed")
    sagg.to_csv(RES / "e5_time_normalisation_summary.csv")
    SUMMARY["E5_time_norm"] = sagg.round(4).to_dict("index")

    # figure: detection
    det_names = list(agg.index)
    dcol = {"Rules": C[1], "Isolation Forest": C[2], "Hybrid (proposed)": C[0]}
    metrics = [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"),
               ("alert_precision", "Alert\nprecision"), ("campaign_detection_rate", "Campaigns\ndetected")]
    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.5), gridspec_kw={"width_ratios": [3, 1.2]})
    w = 0.26
    x = np.arange(len(metrics))
    for k, d in enumerate(det_names):
        ax[0].bar(x + (k - 1) * w, [agg.loc[d, (m, "mean")] for m, _ in metrics], w * 0.92,
                  yerr=[agg.loc[d, (m, "std")] for m, _ in metrics], color=dcol[d], label=d,
                  error_kw={"elinewidth": 0.8, "ecolor": INK2})
    ax[0].set_xticks(x, [t for _, t in metrics], fontsize=7.5)
    ax[0].set_ylim(0, 1.05)
    ax[0].legend(fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    ax[1].bar(range(len(det_names)), [agg.loc[d, ("false_alerts", "mean")] for d in det_names], 0.6,
              yerr=[agg.loc[d, ("false_alerts", "std")] for d in det_names],
              color=[dcol[d] for d in det_names], error_kw={"elinewidth": 0.8, "ecolor": INK2})
    ax[1].set_xticks(range(len(det_names)), ["Rules", "IForest", "Hybrid"], fontsize=7.5)
    ax[1].set_ylabel("false alerts / 24 h")
    save(fig, "e4_detection")

    # figure: correlation
    cnames = list(cagg.index)
    ccol = dict(zip(cnames, [C[1], C[2], C[3], C[0]]))
    cm_ = [("ari", "ARI"), ("v_measure", "V-measure"), ("alert_only_recall", "Recall\n(alerts only)"),
           ("timeline_recall", "Recall\n(reconstructed)"), ("timeline_precision", "Timeline\nprecision")]
    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.6), gridspec_kw={"width_ratios": [3, 1.2]})
    w = 0.2
    x = np.arange(len(cm_))
    for k, d in enumerate(cnames):
        ax[0].bar(x + (k - 1.5) * w, [cagg.loc[d, (m, "mean")] for m, _ in cm_], w * 0.92,
                  yerr=[cagg.loc[d, (m, "std")] for m, _ in cm_], color=ccol[d], label=d,
                  error_kw={"elinewidth": 0.8, "ecolor": INK2})
    ax[0].set_xticks(x, [t for _, t in cm_], fontsize=7)
    ax[0].set_ylim(0, 1.05)
    ax[0].legend(fontsize=6.5, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.25))
    ax[1].bar(range(len(cnames)), [cagg.loc[d, ("fragmentation", "mean")] for d in cnames], 0.6,
              color=[ccol[d] for d in cnames], yerr=[cagg.loc[d, ("fragmentation", "std")] for d in cnames],
              error_kw={"elinewidth": 0.8, "ecolor": INK2})
    ax[1].axhline(1.0, color=INK2, lw=0.8, ls="--")
    ax[1].set_xticks(range(len(cnames)), ["TW", "LF-s", "LF-a", "EG"], fontsize=7.5)
    ax[1].set_ylabel("incidents per campaign")
    save(fig, "e5_correlation")

    # figure: time normalisation
    keys = ["timeline_recall", "ordering_accuracy", "recall_ssh_lateral", "recall_anti_forensics", "recall_cryptomining"]
    labels = ["Timeline\nrecall", "Ordering\naccuracy", "Recall:\nSSH lateral", "Recall:\nanti-forensics", "Recall:\ncryptomining"]
    fig, ax = plt.subplots(figsize=(4.6, 2.3))
    x = np.arange(len(keys))
    for k, (mode, col, lab) in enumerate([("naive", C[1], "naive (assume UTC)"), ("corrected", C[0], "inventory-corrected")]):
        ax.bar(x + (k - 0.5) * 0.36, [sagg.loc[mode, c] for c in keys], 0.33, color=col, label=lab)
    ax.set_xticks(x, labels, fontsize=7)
    ax.set_ylim(0, 1.08)
    ax.legend(fontsize=7, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.2))
    save(fig, "e5_time_normalisation")


# ----------------------------------------------------------------------- E6
def e6(seeds):
    rows = []
    for seed in seeds:
        sim, recs, inv, ev = run_seed(seed)
        tu = BASE_TS + 6 * 3600
        by = {e.eid: e for e in ev}
        al = HybridDetector(tu, seed=seed).detect(ev)
        incs = reconstruct(EntityGraphCorrelator().correlate(by, al), ev)
        for inc in incs:
            camp = {recs[e].campaign for e in inc.eids if recs[e].campaign}
            if not camp:
                continue
            truth = {e.eid for e in ev if recs[e.eid].campaign in camp}
            lo, hi = inc.start - 1800, inc.end + 4 * 3600
            window = [e for e in ev if lo <= e.ts <= hi]
            naive = naive_collect(ev, lo, hi)
            iso, st = isolate(window, inc.tenant, lo, hi, inv)
            iso_set = set(iso)
            truth_raw = {by[e].raw for e in truth if lo <= by[e].ts <= hi}
            rows.append({"seed": seed, "tenant": inc.tenant, "naive_records": len(naive),
                         "naive_leak": leakage(naive, inc.tenant, inv),
                         "isolated_records": len(iso), "isolated_leak": leakage(iso, inc.tenant, inv),
                         "pseudonymised_records": st["pseudonymised_records"],
                         "evidence_retained": len(truth_raw & iso_set) / max(1, len(truth_raw)),
                         "foreign_records_naive": sum(1 for e in window if e.tenant not in (inc.tenant,)),
                         })
        log(f"E6 seed {seed} done")
    df = pd.DataFrame(rows)
    df.to_csv(RES / "e6_isolation.csv", index=False)
    SUMMARY["E6"] = df.drop(columns=["seed", "tenant"]).mean().round(3).to_dict()
    SUMMARY["E6"]["incidents"] = len(df)

    fig, ax = plt.subplots(1, 2, figsize=(5.6, 2.2))
    ax[0].bar([0, 1], [df.naive_records.mean(), df.isolated_records.mean()], 0.55, color=[C[1], C[0]])
    ax[0].set_xticks([0, 1], ["naive window\ndump", "isolated"])
    ax[0].set_ylabel("records in evidence set")
    ax[1].bar([0, 1], [df.naive_leak.mean(), df.isolated_leak.mean()], 0.55, color=[C[1], C[0]])
    ax[1].set_xticks([0, 1], ["naive window\ndump", "isolated"])
    ax[1].set_ylabel("foreign-tenant identifiers")
    for a, vals in ((ax[0], [df.naive_records.mean(), df.isolated_records.mean()]),
                    (ax[1], [df.naive_leak.mean(), df.isolated_leak.mean()])):
        for i, v in enumerate(vals):
            a.text(i, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=7, color=INK)
    save(fig, "e6_isolation")


# ----------------------------------------------------------------------- E7
def e7():
    rng = np.random.default_rng(7)
    rows, cdf = [], {}
    for atype in ATTACK_TYPES:
        src = SCENARIO_SOURCES[atype]
        for label, ready in (("CSP request (status quo)", set()),
                             ("Forensic-ready (owner-side sources)", {"cloudtrail", "syslog", "vpcflow"}),
                             ("Forensic-ready + FaaS (all sources)", set(src))):
            t = acquisition_time_model(src, ready, rng)
            rows.append({"attack": atype, "setting": label, "cdi": csp_dependency_index(src),
                         "cdi_uncooperative_owner": csp_dependency_index(src, cooperative_owner=False),
                         "eat_median_h": np.median(t), "eat_p90_h": np.percentile(t, 90), "eat_mean_h": t.mean()})
            cdf.setdefault(label, []).append(t)
    df = pd.DataFrame(rows)
    df.to_csv(RES / "e7_acquisition.csv", index=False)
    SUMMARY["E7"] = df.round(3).to_dict("records")
    fig, ax = plt.subplots(figsize=(4.6, 2.3))
    for (label, ts), col in zip(cdf.items(), [C[1], C[3], C[0]]):
        t = np.sort(np.concatenate(ts))
        ax.plot(np.maximum(t, 0.01), np.linspace(0, 1, len(t)), color=col, label=label)
    ax.set_xscale("log")
    ax.set_xlabel("evidence acquisition time (hours, log)")
    ax.set_ylabel("CDF over incidents")
    ax.legend(fontsize=6.5, loc="lower right")
    save(fig, "e7_acquisition_cdf")


# ----------------------------------------------------------------------- E8
def e8(scales):
    rows = []
    for tenants, hours in scales:
        sim = CloudSimulator(seed=11, n_tenants=tenants, hours=hours)
        recs = sim.run()
        pipe = ForensicPipeline(sim.inventory(), train_hours=min(6, hours / 4))
        t0 = time.perf_counter()
        res = pipe.run(recs)
        total = time.perf_counter() - t0
        t1 = time.perf_counter()
        pkgs = [pipe.package(res, inc) for inc in res.incidents[:5]]
        pkg_t = (time.perf_counter() - t1) / max(1, len(pkgs))
        assert all(p.verify()[0] for p in pkgs)
        rows.append({"tenants": tenants, "hours": hours, "records": len(recs), "total_s": total,
                     "eps": len(recs) / total, "package_s_per_incident": pkg_t, **res.timings})
        log(f"E8 {tenants}x{hours}h records={len(recs)} total={total:.1f}s")
    df = pd.DataFrame(rows)
    df.to_csv(RES / "e8_scalability.csv", index=False)
    SUMMARY["E8"] = df.round(3).to_dict("records")
    fig, ax = plt.subplots(figsize=(4.6, 2.3))
    bottom = np.zeros(len(df))
    for col, lab, cc in (("preserve_s", "preserve (FRSL)", C[0]), ("normalise_s", "normalise", C[2]),
                         ("detect_s", "detect", C[3]), ("correlate_s", "correlate + reconstruct", C[1])):
        ax.bar(range(len(df)), df[col], 0.6, bottom=bottom, color=cc, label=lab, edgecolor="#fcfcfb", linewidth=1)
        bottom += df[col].values
    ax.set_xticks(range(len(df)), [f"{r.records / 1000:.0f}k" for r in df.itertuples()])
    ax.set_xlabel("raw log records")
    ax.set_ylabel("pipeline time (s)")
    ax.legend(fontsize=6.5, loc="upper left")
    save(fig, "e8_scalability")


def custody_check():
    pkg = EvidencePackage("CASE-selftest")
    pkg.add("a.log", b"hello")
    pkg.add("b.log", b"world")
    pkg.seal()
    ok1 = pkg.verify()[0]
    pkg.artifacts["a.log"] = b"hell0"
    ok2, probs = pkg.verify()
    SUMMARY["custody"] = {"clean_verifies": ok1, "tampered_detected": not ok2, "problems": probs}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    if a.quick:
        sizes, trials, seeds, scales = [1000, 5000], 20, [1, 2], [(2, 12), (4, 24)]
    else:
        sizes, trials, seeds, scales = [1000, 5000, 20000, 50000], 100, [1, 2, 3, 4, 5], \
            [(2, 24), (4, 24), (8, 24), (8, 48), (16, 48)]
    e1_e2(sizes)
    e3(trials)
    e4_e5(seeds)
    e6(seeds)
    e7()
    e8(scales)
    custody_check()
    SUMMARY["runtime_s"] = round(time.time() - t0, 1)
    SUMMARY["config"] = {"sizes": sizes, "trials": trials, "seeds": seeds, "scales": scales}
    (RES / "summary.json").write_text(json.dumps(SUMMARY, indent=1, default=float))
    log("all experiments done in", SUMMARY["runtime_s"], "s")


if __name__ == "__main__":
    main()
