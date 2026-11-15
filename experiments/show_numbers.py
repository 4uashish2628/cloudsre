"""Show where every number in the presentation comes from.

    python experiments/show_numbers.py              # all slides, from saved results (instant)
    python experiments/show_numbers.py 10           # one slide, from saved results
    python experiments/show_numbers.py 10 --live    # recompute that slide's experiment now

Saved results are results/summary.json, written by experiments/run_all.py.
--live re-runs the same experiment code as run_all.py, but writes its files
to a temporary folder, so the committed results and paper figures are not
touched. Accuracy numbers come out identical (the experiments are seeded);
speed numbers vary slightly with machine load.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TITLES = {
    3: "Base paper: a survey of cloud forensics",
    4: "Our idea: guidelines into one working system",
    7: "FRSL design",
    8: "FRSL results: tamper detection and cost",
    9: "Test setup: a simulated multi-tenant cloud",
    10: "Hybrid detection: 67% fewer false alerts",
    11: "Rebuilding the full attack timeline",
    12: "Live demo",
    13: "Evidence isolation",
    14: "Provider dependency and scalability",
    15: "Contributions and limits",
}


def pct(x):
    return f"{100 * x:.0f}%"


def rows_for(slide: int, S: dict) -> list[tuple[str, str, str]]:
    """(value shown, what it means, where it comes from) for one slide."""
    if slide == 3:
        return [("80 papers, 2009-2019", "papers the survey classifies", "base paper Sec. 2.1 and Table 2"),
                ("Table 14", "artifacts held by each stakeholder", "base paper Sec. 8.1, Table 14"),
                ("5 guidelines", "investigation guidelines", "base paper Sec. 8.2.1-8.2.5")]
    if slide == 4:
        return [("R1-R6 table", "our requirements vs surveyed systems",
                 "our analysis of base paper Tables 3-8; same as our paper's Table I")]
    if slide == 7:
        p = S["E2"][-1]
        return [(f"{p['proof_hashes']:.0f} hashes", "Merkle proof length for one record (batch of 1,024)",
                 "summary.json E2[-1].proof_hashes")]
    if slide == 8:
        f, b, h = S["E1"]["FRSL (proposed)"], S["E1"]["Blockchain (PoW)"], S["E1"]["Hash chain"]
        p = S["E2"][-1]
        w = {r["epoch"]: r["truncate_detection"] for r in S["E3_window"]}
        return [
            (pct(S["E3"]["FRSL (proposed)"]), "FRSL tamper detection over all 10 attack settings", "E3 -> summary.json E3"),
            (f"{f['throughput_eps'] / b['throughput_eps']:.1f}x", "FRSL ingest speed / blockchain ingest speed",
             f"E1: {f['throughput_eps']:,.0f} / {b['throughput_eps']:,.0f} entries/s"),
            (f"{1000 * p['single_verify_ms']:.0f} us", "time to verify one record by Merkle proof (50k-entry log)",
             "E2 -> summary.json E2[-1].single_verify_ms"),
            (f"{p['full_verify_ms'] / p['single_verify_ms']:,.0f}x", "full audit time / one-record time",
             f"E2: {p['full_verify_ms']:.1f} ms / {p['single_verify_ms'] * 1000:.1f} us"),
            (f"{h['throughput_eps'] / 1000:,.0f}k / {f['throughput_eps'] / 1000:,.0f}k / {b['throughput_eps'] / 1000:,.0f}k",
             "throughput chart: hash chain / FRSL / blockchain (entries/s)", "E1 at 50k entries"),
            (f"heatmap: Plain {pct(S['E3']['Plain central log'])}, Per-entry {pct(S['E3']['Per-entry hash'])}, "
             f"Chain {pct(S['E3']['Hash chain'])}", "average detection of the weaker schemes", "E3 -> results/e3_tamper_detection.csv"),
            (f"caveat: truncation caught {pct(w[64])} / {pct(w[1024])} / {pct(w[4096])}",
             "if the insider strikes before sealing (batch size 64 / 1024 / 4096)", "E3 window -> summary.json E3_window"),
        ]
    if slide == 9:
        from cloudforensix.simulator import CloudSimulator
        recs = [CloudSimulator(seed=s).run() for s in (1, 2, 3, 4, 5)]
        camps = {len({r.campaign for r in rs if r.campaign}) for rs in recs}
        avg = sum(len(r) for r in recs) / len(recs)
        return [(f"{'/'.join(map(str, sorted(camps)))}", "attack campaigns per 24 h run", "simulator, campaigns_per_type=4 x 5 types"),
                ("5", "random seeds averaged", "run_all.py seeds = [1, 2, 3, 4, 5]"),
                (f"{avg / 1000:.0f}k", "raw log records per run (mean of seeds 1-5)",
                 f"simulator: {', '.join(f'{len(r):,}' for r in recs)}")]
    if slide == 10:
        E = S["E4"]
        r, i, h = E["Rules"], E["Isolation Forest"], E["Hybrid (proposed)"]
        return [
            (f"{r['false_alerts'][0]:.1f} / {i['false_alerts'][0]:.1f} / {h['false_alerts'][0]:.1f}",
             "false alerts per day: rules / Isolation Forest / hybrid (chart)", "E4 -> summary.json E4.*.false_alerts"),
            (f"{100 * (1 - h['false_alerts'][0] / r['false_alerts'][0]):.0f}% fewer", "hybrid vs rules false alerts", "computed from the line above"),
            (pct(h["campaign_detection_rate"][0]), "campaigns detected by hybrid", "E4 campaign_detection_rate"),
            (pct(i["campaign_detection_rate"][0]), "campaigns detected by Isolation Forest alone", "E4 campaign_detection_rate"),
            (f"{h['mttd_s'][0]:.0f} s", "mean time to detect", "E4 mttd_s"),
            (f"{r['precision'][0]:.2f} -> {h['precision'][0]:.2f}", "event precision, rules -> hybrid", "E4 precision"),
        ]
    if slide == 11:
        E, T = S["E5"], S["E5_time_norm"]
        eg = E["Entity graph (proposed)"]
        return [
            (f"{pct(eg['alert_only_recall'][0])} -> {pct(eg['timeline_recall'][0])}",
             "attack events covered: alerts only -> after reconstruction", "E5 alert_only_recall, timeline_recall"),
            (f"ARI {eg['ari'][0]:.4f}", "grouping score of entity graph (1.0 = perfect)", "E5 ari"),
            (f"{eg['fragmentation'][0]:.2f} vs {E['Leader-Follower (static)']['fragmentation'][0]:.2f}-"
             f"{E['Leader-Follower (adaptive)']['fragmentation'][0]:.2f}", "incidents per campaign: ours vs Leader-Follower", "E5 fragmentation"),
            (f"{pct(T['naive']['recall_ssh_lateral'])} / {pct(T['naive']['recall_anti_forensics'])} / {pct(T['naive']['timeline_recall'])}",
             "recall WITHOUT time correction: SSH / anti-forensics / all (red bars)", "E5 ablation -> summary.json E5_time_norm.naive"),
            (f"{pct(T['corrected']['recall_ssh_lateral'])} / {pct(T['corrected']['recall_anti_forensics'])} / {pct(T['corrected']['timeline_recall'])}",
             "recall WITH time correction (green bars)", "E5_time_norm.corrected"),
        ]
    if slide == 12:
        return [("28 passed", "unit tests", "run: .venv/bin/python -m pytest -q"),
                ("116 alerts, 26 incidents, 20/20", "one investigation run, seed 7",
                 "run: .venv/bin/python -m cloudforensix.cli investigate --seed 7 --out cases"),
                ("11 steps from 1 alert", "rebuilt SSH attack",
                 "run: .venv/bin/python experiments/show_timeline.py cases/CASE-tenant-a-021"),
                ("50/50 verified, 0 foreign ids", "from the incident report", "cases/CASE-tenant-a-021/artifacts/incident_report.md")]
    if slide == 13:
        e = S["E6"]
        return [(f"{e['naive_leak']:.0f} -> {e['isolated_leak']:.0f}", "other tenants' identifiers per incident: naive -> isolated",
                 "E6 naive_leak, isolated_leak"),
                (f"{e['incidents']:.0f} incidents", "attack incidents averaged over (5 seeds)", "E6 incidents"),
                (pct(e["evidence_retained"]), "attack records kept after isolation", "E6 evidence_retained"),
                (f"{e['naive_records']:,.0f} -> {e['isolated_records']:,.0f}", "records per evidence set", "E6 naive_records, isolated_records")]
    if slide == 14:
        med = {r["attack"]: r["eat_median_h"] for r in S["E7"] if r["setting"].startswith("CSP request")}
        return [(", ".join(f"{k} {v:.0f} h" for k, v in med.items()), "modelled median wait with CSP request (table)",
                 "E7 model -> results/e7_acquisition.csv (assumed delays)"),
                (" / ".join(f"{r['total_s']:.1f}s" for r in S["E8"]), "pipeline time for 20k/37k/71k/133k/276k records (chart)", "E8"),
                (f"{sum(r['eps'] for r in S['E8']) / len(S['E8']) / 1000:.0f}k records/s", "mean end-to-end throughput", "E8 eps")]
    if slide == 15:
        n = sum(len(p.read_text().splitlines()) for p in (ROOT / "cloudforensix").glob("*.py"))
        return [(f"{n:,} lines", "framework source code", "count of cloudforensix/*.py"),
                ("28 tests", "unit tests", "tests/test_cloudforensix.py"),
                ("8 experiments", "E1-E8", "experiments/run_all.py"),
                ("6 requirements", "R1-R6", "slide 4 / paper Table I")]
    raise SystemExit(f"slide {slide} has no numbers; choose from {sorted(TITLES)}")


LIVE = {8: "e1_e2 + e3", 9: "simulator", 10: "e4_e5", 11: "e4_e5", 13: "e6", 14: "e7 + e8", 7: "e1_e2"}


def live_summary(slide: int) -> dict:
    """Re-run the slide's experiment with run_all.py's own code into a temp folder."""
    import run_all
    tmp = Path(tempfile.mkdtemp(prefix="cfx_live_"))
    run_all.RES, run_all.FIG = tmp, tmp
    run_all.SUMMARY.clear()
    if slide in (7, 8):
        run_all.e1_e2([50000])
        if slide == 8:
            run_all.e3(100)
    elif slide in (10, 11):
        run_all.e4_e5([1, 2, 3, 4, 5])
    elif slide == 13:
        run_all.e6([1, 2, 3, 4, 5])
    elif slide == 14:
        run_all.e7()
        run_all.e8([(2, 24), (4, 24), (8, 24), (8, 48), (16, 48)])
    return dict(run_all.SUMMARY)


def show(slide: int, S: dict, label: str):
    print(f"\n=== Slide {slide}: {TITLES[slide]}  [{label}] ===")
    for value, meaning, source in rows_for(slide, S):
        print(f"  {value:<34} {meaning}\n  {'':<34} source: {source}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("slide", nargs="?", type=int)
    ap.add_argument("--live", action="store_true", help="recompute the slide's experiment now")
    a = ap.parse_args()
    saved = json.loads((ROOT / "results" / "summary.json").read_text())
    slides = [a.slide] if a.slide else sorted(TITLES)
    for sl in slides:
        if a.live and sl in LIVE:
            sys.path.insert(0, str(ROOT / "experiments"))
            t0 = time.time()
            print(f"\nRecomputing slide {sl} ({LIVE[sl]}) ...", flush=True)
            fresh = {**saved, **live_summary(sl)} if sl != 9 else saved
            show(sl, fresh, f"recomputed now in {time.time() - t0:.0f} s")
        elif a.live and sl == 12:
            show(sl, saved, "run the demo commands below")
        else:
            show(sl, saved, "saved results/summary.json")


if __name__ == "__main__":
    main()
