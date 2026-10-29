"""Live detection: the trigger of incident-driven forensics.

Sec. 7.2 of the survey argues that live cloud analysis must "generate quick
alerts with minimum false positives".  Three detectors are compared:

``RuleDetector``
    Sigma-style correlation rules derived from the attack techniques and
    artifact locations catalogued in the survey (Table 14).
``AnomalyDetector``
    Isolation Forest over per-entity 10-minute behaviour windows, trained on a
    clean baseline period (forensic readiness assumes a known-good baseline).
``HybridDetector`` (proposed)
    Rule hits are *contextualised* by a behaviour profile learned in the
    baseline period (which principal does what from where) -- alerts that
    match established behaviour are suppressed -- and complemented by
    high-confidence anomalies so that novel behaviour is still caught.

Every alert keeps the ids of the events that triggered it; those ids seed the
correlation / reconstruction stage.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from .normalizer import Event, is_external

MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 45700}
HOME_REGIONS = {"us-east-1"}


@dataclass
class Alert:
    rule: str
    ts: float                    # time the alert could be raised (last evidence)
    tenant: str | None
    key: str                     # entity the alert is about
    eids: list[int]
    severity: str = "high"
    score: float = 1.0
    suppressed: bool = False
    context: dict = field(default_factory=dict)


# ------------------------------------------------------------------ rules
class RuleDetector:
    name = "Rules"

    def __init__(self, bf_threshold=5, bf_window=600, bulk_get=60, bulk_window=600,
                 run_burst=5, run_window=3600, egress_bytes=150_000_000):
        self.p = dict(bf_threshold=bf_threshold, bf_window=bf_window, bulk_get=bulk_get,
                      bulk_window=bulk_window, run_burst=run_burst, run_window=run_window,
                      egress_bytes=egress_bytes)

    def detect(self, events: list[Event]) -> list[Alert]:
        p = self.p
        alerts: list[Alert] = []
        fails: dict[tuple, deque] = defaultdict(deque)
        gets: dict[tuple, deque] = defaultdict(deque)
        runs: dict[tuple, deque] = defaultdict(deque)
        egress: dict[tuple, deque] = defaultdict(deque)
        mining_seen: set = set()
        fired_bulk: dict[tuple, float] = {}
        for ev in events:
            a = ev.action
            # R1 brute force followed by success (console or SSH)
            if a in ("auth.login", "auth.ssh"):
                k = (ev.tenant, ev.src_ip, ev.host if a == "auth.ssh" else ev.principal)
                dq = fails[k]
                while dq and ev.ts - dq[0][0] > p["bf_window"]:
                    dq.popleft()
                if ev.outcome == "failure":
                    dq.append((ev.ts, ev.eid))
                elif len(dq) >= p["bf_threshold"]:
                    alerts.append(Alert("R1_bruteforce_success", ev.ts, ev.tenant, f"ip:{ev.src_ip}",
                                        [e for _, e in dq] + [ev.eid]))
                    dq.clear()
            # R2 privilege escalation to admin / key for another identity
            if a == "iam.attach_policy" and "AdministratorAccess" in ev.detail:
                alerts.append(Alert("R2_admin_policy_attached", ev.ts, ev.tenant, f"user:{ev.principal}", [ev.eid]))
            if a == "iam.create_key" and ev.target and ev.target != ev.principal:
                alerts.append(Alert("R2_key_for_other_user", ev.ts, ev.tenant, f"user:{ev.principal}", [ev.eid], "medium"))
            # R3 audit / logging tampering (anti-forensics)
            if a.startswith("audit.") and a != "audit.describe":
                alerts.append(Alert("R3_audit_tampering", ev.ts, ev.tenant, f"user:{ev.principal or ev.host}", [ev.eid], "critical"))
            if a == "os.sudo" and any(w in ev.detail for w in ("auditd stop", "shred", "/var/log", "history -c")):
                alerts.append(Alert("R3_audit_tampering", ev.ts, ev.tenant, f"host:{ev.host}", [ev.eid], "critical"))
            # R4 cryptomining: mining-pool ports or RunInstances burst / odd region
            if a == "net.flow" and ev.dst_port in MINING_PORTS and is_external(ev.dst_ip):
                k = (ev.src_ip, ev.dst_ip)
                if k not in mining_seen:
                    mining_seen.add(k)
                    alerts.append(Alert("R4_mining_pool_traffic", ev.ts, ev.tenant, f"ip:{ev.dst_ip}", [ev.eid]))
            if a == "compute.run":
                k = (ev.tenant, ev.principal)
                dq = runs[k]
                dq.append((ev.ts, ev.eid))
                while ev.ts - dq[0][0] > p["run_window"]:
                    dq.popleft()
                odd = ev.region not in HOME_REGIONS
                if len(dq) >= p["run_burst"] or (odd and len(dq) >= 2):
                    alerts.append(Alert("R4_instance_burst", ev.ts, ev.tenant, f"user:{ev.principal}", [e for _, e in dq],
                                        context={"region": ev.region}))
                    dq.clear()
            # R5 bulk object collection
            if a == "storage.get":
                k = (ev.tenant, ev.principal)
                dq = gets[k]
                dq.append((ev.ts, ev.eid))
                while ev.ts - dq[0][0] > p["bulk_window"]:
                    dq.popleft()
                if len(dq) >= p["bulk_get"] and ev.ts - fired_bulk.get(k, -1e18) > p["bulk_window"]:
                    fired_bulk[k] = ev.ts
                    alerts.append(Alert("R5_bulk_collection", ev.ts, ev.tenant, f"user:{ev.principal}",
                                        [e for _, e in dq], context={"src_ip": ev.src_ip}))
            # R6 large egress to an external address
            if a == "storage.access" and is_external(ev.src_ip):
                k = (ev.tenant, ev.src_ip)
                dq = egress[k]
                dq.append((ev.ts, ev.eid, ev.nbytes))
                while ev.ts - dq[0][0] > 3600:
                    dq.popleft()
                if sum(x[2] for x in dq) > p["egress_bytes"]:
                    alerts.append(Alert("R6_large_egress", ev.ts, ev.tenant, f"ip:{ev.src_ip}", [x[1] for x in dq]))
                    dq.clear()
        return alerts


# ---------------------------------------------------------------- anomaly
FEATURES = ["n", "fail", "actions", "iam_write", "s_get", "log_bytes", "ext_src",
            "resources", "ports", "ext_dst", "odd_region", "audit"]


def window_features(events: list[Event], width: int = 600):
    """Aggregate events into (tenant, entity, window) behaviour vectors."""
    agg: dict[tuple, dict] = {}
    for ev in events:
        if ev.action in ("hv.heartbeat", "hv.node_stats", "os.cron"):
            continue
        ent = ev.principal or ev.src_ip or ev.host
        if ent is None:
            continue
        k = (ev.tenant, ent, int(ev.ts // width))
        d = agg.get(k)
        if d is None:
            d = agg[k] = {"eids": [], "acts": set(), "res": set(), "ports": set(), "f": defaultdict(float)}
        f = d["f"]
        d["eids"].append(ev.eid)
        f["n"] += 1
        f["fail"] += ev.outcome == "failure"
        d["acts"].add(ev.action)
        f["iam_write"] += ev.action in ("iam.create_user", "iam.attach_policy", "iam.create_key")
        f["s_get"] += ev.action == "storage.get"
        f["log_bytes"] += ev.nbytes if ev.action in ("storage.access", "net.flow") else 0
        f["ext_src"] = max(f["ext_src"], float(is_external(ev.src_ip)))
        if ev.resource:
            d["res"].add(ev.resource)
        if ev.dst_port:
            d["ports"].add(ev.dst_port)
        f["ext_dst"] += is_external(ev.dst_ip)
        f["odd_region"] += bool(ev.region and ev.region not in HOME_REGIONS)
        f["audit"] += ev.action.startswith("audit.") or ev.action == "os.sudo"
    keys = list(agg)
    X = np.zeros((len(keys), len(FEATURES)))
    for i, k in enumerate(keys):
        d = agg[k]
        f = d["f"]
        f["actions"], f["resources"], f["ports"] = len(d["acts"]), len(d["res"]), len(d["ports"])
        f["log_bytes"] = np.log1p(f["log_bytes"])
        X[i] = [f[c] for c in FEATURES]
    X[:, [0, 1, 4, 7]] = np.log1p(X[:, [0, 1, 4, 7]])
    return keys, X, agg


class AnomalyDetector:
    name = "Isolation Forest"

    def __init__(self, train_until: float, quantile: float = 0.995, seed: int = 0, width: int = 600):
        self.train_until = train_until
        self.quantile = quantile
        self.seed = seed
        self.width = width
        self.model = None
        self.threshold = None

    def detect(self, events: list[Event]) -> list[Alert]:
        keys, X, agg = window_features(events, self.width)
        train = np.array([k[2] * self.width < self.train_until for k in keys])
        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=self.seed)
        self.model.fit(X[train])
        s = -self.model.score_samples(X)            # higher = more anomalous
        self.threshold = float(np.quantile(s[train], self.quantile))
        self.scores = dict(zip(keys, s))
        alerts = []
        for k, sc in zip(keys, s):
            if sc > self.threshold and k[2] * self.width >= self.train_until:
                eids = agg[k]["eids"]
                alerts.append(Alert("A1_behaviour_anomaly", (k[2] + 1) * self.width, k[0], f"ent:{k[1]}",
                                    eids, "medium", float(sc)))
        return alerts


# ----------------------------------------------------------------- hybrid
class HybridDetector:
    """Proposed: profile-contextualised rules + high-confidence anomalies."""

    name = "Hybrid (proposed)"

    def __init__(self, train_until: float, seed: int = 0, strong_margin: float = 0.06):
        self.train_until = train_until
        self.rules = RuleDetector()
        self.anom = AnomalyDetector(train_until, quantile=0.999, seed=seed)
        self.strong_margin = strong_margin

    def _profile(self, events: list[Event]):
        prof = {"principal_ip": set(), "principal_action": set(), "ip_action": set()}
        for ev in events:
            if ev.ts >= self.train_until:
                break
            if ev.principal and ev.src_ip:
                prof["principal_ip"].add((ev.tenant, ev.principal, ev.src_ip))
            if ev.principal:
                prof["principal_action"].add((ev.tenant, ev.principal, ev.action, ev.detail[:60]))
            if ev.src_ip:
                prof["ip_action"].add((ev.tenant, ev.src_ip, ev.action))
        return prof

    def detect(self, events: list[Event]) -> list[Alert]:
        by_id = {e.eid: e for e in events}
        prof = self._profile(events)
        out = []
        for a in self.rules.detect(events):
            evs = [by_id[i] for i in a.eids]
            known_ip = all(
                (e.tenant, e.principal, e.src_ip) in prof["principal_ip"] or
                (e.tenant, e.src_ip, e.action) in prof["ip_action"]
                for e in evs if e.src_ip and e.principal)
            src_ips = {e.src_ip for e in evs if e.src_ip}
            corp = all(not is_external(ip) or ip.startswith("192.0.2.") for ip in src_ips)
            if a.rule in ("R5_bulk_collection", "R6_large_egress", "R1_bruteforce_success") and known_ip and src_ips:
                a.suppressed, a.context["why"] = True, "matches baseline principal/IP profile"
            elif a.rule.startswith("R2") and corp and src_ips:
                a.suppressed, a.context["why"] = True, "IAM change from corporate network"
            elif a.rule == "R4_instance_burst" and corp and a.context.get("region") in HOME_REGIONS:
                a.suppressed, a.context["why"] = True, "home-region burst from corporate network"
            if not a.suppressed:
                out.append(a)
        anomalies = self.anom.detect(events)
        thr = self.anom.threshold + self.strong_margin
        for a in anomalies:
            if a.score > thr:
                out.append(a)
        out.sort(key=lambda x: x.ts)
        return out
