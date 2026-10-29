"""End-to-end forensic-ready monitoring and incident-response pipeline.

Stages (mapped to the five-stage investigation process used by the survey,
Fig. 1: identification, collection/preservation, examination, analysis,
presentation):

1. **Collection & preservation** - raw logs from all stakeholders are
   appended to the FRSL tamper-evident store as they arrive.
2. **Identification** - parse/normalise to UTC and run the hybrid detector.
3. **Examination & analysis** - correlate alerts into incidents and
   reconstruct full timelines; derive the Table-14 acquisition plan.
4. **Presentation** - per-incident, tenant-isolated evidence package with
   Merkle-sealed manifest, inclusion proofs and custody ledger, plus a
   Markdown incident report.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .artifacts import acquisition_plan, csp_dependency_index
from .correlation import EntityGraphCorrelator, Incident, reconstruct
from .custody import EvidencePackage
from .detector import HybridDetector
from .isolation import isolate, leakage
from .normalizer import Event, Normalizer
from .seclog import FRSL
from .simulator import BASE_TS, Inventory, RawRecord


@dataclass
class PipelineResult:
    events: list[Event]
    alerts: list
    incidents: list[Incident]
    store: FRSL
    timings: dict = field(default_factory=dict)
    packages: list[EvidencePackage] = field(default_factory=list)


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class ForensicPipeline:
    def __init__(self, inventory: Inventory, train_hours: float = 6.0, epoch: int = 1024, seed: int = 0):
        self.inv = inventory
        self.train_until = BASE_TS + train_hours * 3600
        self.epoch = epoch
        self.seed = seed

    def run(self, records: list[RawRecord]) -> PipelineResult:
        T = {}
        t0 = time.perf_counter()
        store = FRSL(epoch=self.epoch)
        for r in records:
            store.append(f"{r.source}|{r.line}".encode())
        store.seal()
        T["preserve_s"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        events = Normalizer(self.inv).parse_all(records)
        events.sort(key=lambda e: e.ts)
        T["normalise_s"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        alerts = HybridDetector(self.train_until, seed=self.seed).detect(events)
        T["detect_s"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        by_id = {e.eid: e for e in events}
        incidents = EntityGraphCorrelator().correlate(by_id, alerts)
        incidents = reconstruct(incidents, events)
        T["correlate_s"] = time.perf_counter() - t0
        return PipelineResult(events, alerts, incidents, store, T)

    # ------------------------------------------------------------- packaging
    def package(self, res: PipelineResult, inc: Incident, outdir: Path | None = None) -> EvidencePackage:
        by_id = {e.eid: e for e in res.events}
        tl = [by_id[i] for i in inc.timeline]
        case = f"CASE-{inc.tenant}-{inc.iid:03d}"
        pkg = EvidencePackage(case)
        pkg.log("forensic-pipeline", "open_case", f"tenant={inc.tenant} alerts={len(inc.alerts)}")
        lines, stats = isolate(tl, inc.tenant, inc.start - 1800, inc.end + 4 * 3600, self.inv)
        sources = sorted({e.source for e in tl})
        plan = acquisition_plan(sources)
        proofs = []
        for e in tl[:50]:
            idx, proof = res.store.prove(e.eid)
            ok = res.store.verify_entry(res.store.store[e.eid], idx, proof)
            proofs.append({"eid": e.eid, "epoch": idx, "proof_len": len(proof), "verified": ok})
        pkg.add("timeline.jsonl", "\n".join(json.dumps(by_id[i].to_dict()) for i in inc.timeline).encode(), "forensic-pipeline")
        pkg.add("raw_isolated.log", "\n".join(lines).encode(), "forensic-pipeline")
        pkg.add("alerts.json", json.dumps([a.__dict__ for a in inc.alerts], default=str, indent=1).encode(), "forensic-pipeline")
        pkg.add("acquisition_plan.json", json.dumps(plan, indent=1).encode(), "forensic-pipeline")
        pkg.add("integrity_proofs.json", json.dumps(proofs, indent=1).encode(), "forensic-pipeline")
        report = self.report(inc, tl, plan, stats, leakage(lines, inc.tenant, self.inv), proofs)
        pkg.add("incident_report.md", report.encode(), "forensic-pipeline")
        pkg.seal("forensic-pipeline")
        pkg.log("forensic-pipeline", "transfer", "to=investigator")
        pkg.log("investigator", "verify", "ok" if pkg.verify()[0] else "FAILED")
        if outdir:
            pkg.write(Path(outdir) / case)
        res.packages.append(pkg)
        return pkg

    def report(self, inc, tl, plan, iso_stats, leak, proofs) -> str:
        rules = Counter(a.rule for a in inc.alerts)
        L = [f"# Incident report CASE-{inc.tenant}-{inc.iid:03d}", "",
             f"* Tenant: `{inc.tenant}`",
             f"* Alert window (UTC): {_fmt(inc.start)} - {_fmt(inc.end)}",
             f"* Reconstructed window (UTC): {_fmt(tl[0].ts)} - {_fmt(tl[-1].ts)}" if tl else "",
             f"* Alerts: {len(inc.alerts)} ({', '.join(f'{k}x{v}' for k, v in rules.items())})",
             f"* Reconstructed timeline: {len(tl)} events from {len({e.source for e in tl})} sources",
             f"* Key entities: {', '.join(sorted(inc.entities)[:12])}",
             f"* CSP Dependency Index: {csp_dependency_index([p['source'] for p in plan]):.2f}",
             f"* Evidence isolation: {iso_stats}, residual foreign identifiers = {leak}",
             f"* Integrity: {sum(p['verified'] for p in proofs)}/{len(proofs)} sampled entries verified by Merkle proof against anchored PPL",
             "", "## Timeline (first 40 events)", "", "| UTC | source | action | principal | src | detail |", "|---|---|---|---|---|---|"]
        for e in tl[:40]:
            L.append(f"| {_fmt(e.ts)} | {e.source} | {e.action} | {e.principal or ''} | {e.src_ip or ''} | {(e.detail or e.resource or '')[:60]} |")
        L += ["", "## Acquisition plan (survey Table 14)", "", "| source | stakeholder | obtain from | dependency |", "|---|---|---|---|"]
        for p in plan:
            L.append(f"| {p['source']} | {p['stakeholder']} | {p['obtain_from']} | {p['dependency']} |")
        return "\n".join(L) + "\n"
