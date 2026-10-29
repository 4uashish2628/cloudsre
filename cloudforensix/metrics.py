"""Forensic evaluation metrics.

Sec. 7.2 of the survey observes "there's no discussion over metrics in both
digital and cloud forensics" and suggests analysis time, effort, quick alerts
and false positives.  This module defines the metric set used throughout the
evaluation:

Detection           event-level precision / recall / F1 / FPR,
                    campaign detection rate, MTTD (mean time to detect)
Reconstruction      timeline recall (evidence completeness), timeline
                    precision, ordering accuracy (pairwise, vs ground truth),
                    clustering purity / ARI against campaign ids
Integrity           tamper-detection rate per attack class
Privacy             foreign-tenant identifier leakage
Acquisition         CSP Dependency Index, evidence acquisition time (EAT)
"""

from __future__ import annotations

from collections import Counter, defaultdict

import numpy as np
from sklearn.metrics import adjusted_rand_score, homogeneity_completeness_v_measure


def prf(tp: int, fp: int, fn: int, tn: int | None = None) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    d = {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}
    if tn is not None:
        d["fpr"] = fp / (fp + tn) if fp + tn else 0.0
    return d


def detection_metrics(alerts, records, events) -> dict:
    """Event-level and campaign-level detection quality."""
    flagged = {e for a in alerts for e in a.eids}
    present = {e.eid for e in events}
    tp = fp = fn = tn = 0
    for eid in present:
        mal = records[eid].label != "benign"
        if eid in flagged:
            tp += mal
            fp += not mal
        else:
            fn += mal
            tn += not mal
    m = prf(tp, fp, fn, tn)
    # alert-level precision: an alert is true if any of its events is malicious
    true_alerts = sum(any(records[e].label != "benign" for e in a.eids) for a in alerts)
    m["alerts"] = len(alerts)
    m["false_alerts"] = len(alerts) - true_alerts
    m["alert_precision"] = true_alerts / len(alerts) if alerts else 0.0
    # campaigns
    start: dict[str, float] = {}
    for r in records:
        if r.campaign and (r.campaign not in start or r.true_ts < start[r.campaign]):
            start[r.campaign] = r.true_ts
    first_alert: dict[str, float] = {}
    for a in alerts:
        camps = {records[e].campaign for e in a.eids if records[e].campaign}
        for c in camps:
            first_alert[c] = min(first_alert.get(c, 1e30), a.ts)
    det = [c for c in start if c in first_alert]
    m["campaigns"] = len(start)
    m["campaigns_detected"] = len(det)
    m["campaign_detection_rate"] = len(det) / len(start) if start else 0.0
    ttd = [max(0.0, first_alert[c] - start[c]) for c in det]
    m["mttd_s"] = float(np.mean(ttd)) if ttd else float("nan")
    m["mttd_median_s"] = float(np.median(ttd)) if ttd else float("nan")
    return m


def clustering_metrics(incidents, records) -> dict:
    """Agreement between correlator incidents and true campaigns (malicious
    alerted events only)."""
    y_true, y_pred = [], []
    for inc in incidents:
        for e in inc.eids:
            c = records[e].campaign
            if c:
                y_true.append(c)
                y_pred.append(inc.iid)
    if not y_true:
        return {"ari": 0.0, "homogeneity": 0.0, "completeness": 0.0, "v_measure": 0.0, "incidents": len(incidents)}
    h, c, v = homogeneity_completeness_v_measure(y_true, y_pred)
    camp_incidents = sum(1 for inc in incidents if any(records[e].campaign for e in inc.eids))
    return {"ari": adjusted_rand_score(y_true, y_pred), "homogeneity": h, "completeness": c,
            "v_measure": v, "incidents": len(incidents), "incidents_with_attack": camp_incidents,
            "fragmentation": camp_incidents / max(1, len(set(y_true)))}


def reconstruction_metrics(incidents, records, events_by_id, seed_only: bool = False) -> dict:
    """Timeline completeness per campaign: each campaign is matched to the
    incident holding most of its events."""
    camp_events: dict[str, set] = defaultdict(set)
    for eid in events_by_id:
        c = records[eid].campaign
        if c:
            camp_events[c].add(eid)
    recalls, precisions, orderings = [], [], []
    for c, truth in camp_events.items():
        best, overlap = None, 0
        for inc in incidents:
            members = inc.eids if seed_only else set(inc.timeline or inc.eids)
            o = len(members & truth)
            if o > overlap:
                best, overlap = members, o
        if best is None:
            recalls.append(0.0)
            continue
        recalls.append(overlap / len(truth))
        mal = sum(1 for e in best if records[e].label != "benign")
        precisions.append(mal / len(best))
        orderings.append(ordering_accuracy([e for e in best if e in truth], events_by_id, records))
    return {"timeline_recall": float(np.mean(recalls)) if recalls else 0.0,
            "timeline_precision": float(np.mean(precisions)) if precisions else 0.0,
            "ordering_accuracy": float(np.nanmean(orderings)) if orderings else float("nan"),
            "per_campaign_recall": dict(zip(camp_events, recalls))}


def ordering_accuracy(eids, events_by_id, records, max_pairs: int = 20000, seed: int = 0) -> float:
    """Fraction of event pairs whose reconstructed order matches true order
    (pairs closer than 1 s in true time are ignored)."""
    eids = list(eids)
    if len(eids) < 2:
        return float("nan")
    rng = np.random.default_rng(seed)
    n = len(eids)
    m = min(max_pairs, n * (n - 1) // 2)
    i = rng.integers(0, n, m)
    j = rng.integers(0, n, m)
    ok = tot = 0
    for a, b in zip(i, j):
        if a == b:
            continue
        ta, tb = records[eids[a]].true_ts, records[eids[b]].true_ts
        if abs(ta - tb) < 1:
            continue
        ra, rb = events_by_id[eids[a]].ts, events_by_id[eids[b]].ts
        tot += 1
        ok += (ta < tb) == (ra < rb)
    return ok / tot if tot else float("nan")


def label_counts(records) -> Counter:
    return Counter(r.label for r in records)
