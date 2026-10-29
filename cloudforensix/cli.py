"""Command-line entry point.

    python -m cloudforensix.cli simulate --seed 7 --out data/
    python -m cloudforensix.cli investigate --seed 7 --out cases/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .metrics import detection_metrics, reconstruction_metrics
from .pipeline import ForensicPipeline
from .simulator import CloudSimulator


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cloudforensix")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("simulate", "investigate"):
        p = sub.add_parser(name)
        p.add_argument("--seed", type=int, default=7)
        p.add_argument("--tenants", type=int, default=4)
        p.add_argument("--hours", type=float, default=24)
        p.add_argument("--out", default="out")
    a = ap.parse_args(argv)

    sim = CloudSimulator(seed=a.seed, n_tenants=a.tenants, hours=a.hours)
    recs = sim.run()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    if a.cmd == "simulate":
        for src in sorted({r.source for r in recs}):
            (out / f"{src}.log").write_text("\n".join(r.line for r in recs if r.source == src) + "\n")
        (out / "inventory.json").write_text(json.dumps(sim.inventory().to_dict(), indent=1))
        (out / "ground_truth.jsonl").write_text("\n".join(
            json.dumps({"eid": i, "source": r.source, "true_ts": r.true_ts, "label": r.label,
                        "campaign": r.campaign, "step": r.step}) for i, r in enumerate(recs)) + "\n")
        print(f"wrote {len(recs)} records to {out}/")
        return

    pipe = ForensicPipeline(sim.inventory(), seed=a.seed)
    res = pipe.run(recs)
    by_id = {e.eid: e for e in res.events}
    dm = detection_metrics(res.alerts, recs, res.events)
    rm = reconstruction_metrics(res.incidents, recs, by_id)
    attack_incidents = [i for i in res.incidents if any(recs[e].label != "benign" for e in i.eids)]
    for inc in res.incidents:
        pipe.package(res, inc, out)
    print(json.dumps({"records": len(recs), "events": len(res.events), "alerts": len(res.alerts),
                      "incidents": len(res.incidents), "incidents_true": len(attack_incidents),
                      "store_verified": res.store.verify(), "timings": res.timings,
                      "detection": {k: v for k, v in dm.items() if not isinstance(v, dict)},
                      "reconstruction": {k: v for k, v in rm.items() if k != "per_campaign_recall"}},
                     indent=1, default=float))
    print(f"evidence packages written to {out}/")


if __name__ == "__main__":
    main()
