"""Incident correlation and event (timeline) reconstruction.

Sec. 4.1 of the survey highlights event reconstruction in the cloud
(CLOSER, Raju et al. [73,74]) based on the Leader-Follower (LF) aggregation
algorithm, and Sec. 8.2.2 calls log correlation "crucial" yet rarely
addressed.  Three correlators group *alerted* events into incidents:

``TimeWindowCorrelator``   baseline - split whenever the gap exceeds Δ.
``LeaderFollower``         re-implementation of LF [73] in its static-leader
                           and adaptive-leader variants.
``EntityGraphCorrelator``  proposed - union-find over shared forensic
                           entities (principal, external IP, created
                           identity, host) under a time constraint, so that
                           multi-stage, multi-source campaigns are linked
                           transitively.

:func:`reconstruct` then expands every incident into a full timeline by
pulling in *all* normalised events (alerted or not) that touch the incident's
entities -- this is what turns a handful of alerts into an evidence set.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from .detector import Alert
from .normalizer import Event, is_external


@dataclass
class Incident:
    iid: int
    tenant: str | None
    eids: set[int]
    alerts: list[Alert] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    start: float = 0.0
    end: float = 0.0
    timeline: list[int] = field(default_factory=list)


def _alerted(events_by_id: dict[int, Event], alerts: list[Alert]):
    eid2alerts: dict[int, list[Alert]] = defaultdict(list)
    for a in alerts:
        for e in a.eids:
            eid2alerts[e].append(a)
    evs = sorted((events_by_id[e] for e in eid2alerts), key=lambda e: e.ts)
    return evs, eid2alerts


def _finish(groups: list[list[Event]], eid2alerts) -> list[Incident]:
    out = []
    for i, g in enumerate(groups):
        als = {id(a): a for e in g for a in eid2alerts[e.eid]}
        ents = set().union(*(e.entities for e in g)) if g else set()
        out.append(Incident(i, g[0].tenant, {e.eid for e in g}, list(als.values()), ents,
                            min(e.ts for e in g), max(e.ts for e in g)))
    return out


class TimeWindowCorrelator:
    name = "Time window"

    def __init__(self, gap: float = 1800):
        self.gap = gap

    def correlate(self, events_by_id, alerts):
        evs, e2a = _alerted(events_by_id, alerts)
        groups = []
        last_by_tenant: dict = {}
        open_by_tenant: dict = {}
        for e in evs:
            g = open_by_tenant.get(e.tenant)
            if g is None or e.ts - last_by_tenant[e.tenant] > self.gap:
                g = []
                groups.append(g)
                open_by_tenant[e.tenant] = g
            g.append(e)
            last_by_tenant[e.tenant] = e.ts
        return _finish(groups, e2a)


def _jaccard(a: frozenset | set, b: frozenset | set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class LeaderFollower:
    """Leader-Follower clustering (Raju et al. [73]).

    similarity = Jaccard(entities) * exp(-Δt / tau); an event joins the most
    similar leader if similarity >= theta, otherwise it becomes a new leader.
    ``adaptive=True`` lets the leader's entity set grow with its followers.
    """

    def __init__(self, theta: float = 0.2, tau: float = 3600, adaptive: bool = False):
        self.theta, self.tau, self.adaptive = theta, tau, adaptive
        self.name = "Leader-Follower" + (" (adaptive)" if adaptive else " (static)")

    def correlate(self, events_by_id, alerts):
        evs, e2a = _alerted(events_by_id, alerts)
        leaders: list[dict] = []
        for e in evs:
            best, bs = None, 0.0
            for L in leaders:
                if L["tenant"] != e.tenant:
                    continue
                s = _jaccard(L["ents"], e.entities) * math.exp(-(e.ts - L["ts"]) / self.tau)
                if s > bs:
                    best, bs = L, s
            if best is not None and bs >= self.theta:
                best["members"].append(e)
                if self.adaptive:
                    best["ents"] = best["ents"] | e.entities
                    best["ts"] = e.ts
            else:
                leaders.append({"tenant": e.tenant, "ents": set(e.entities), "ts": e.ts, "members": [e]})
        return _finish([L["members"] for L in leaders], e2a)


class EntityGraphCorrelator:
    """Proposed: transitive entity linking with union-find.

    Two alerted events of the same tenant are linked when they share an
    entity within that entity's horizon.  Entities are weighted by how
    discriminative they are: *strong* entities (external IPs, identities
    created during the incident) link across ``horizon`` seconds, *weak*
    ones (an existing principal or a host, which several unrelated campaigns
    may hit) only across ``weak_horizon``.  Events of the same alert are
    always linked.
    """

    name = "Entity graph (proposed)"

    def __init__(self, horizon: float = 4 * 3600, weak_horizon: float = 1800):
        self.horizon = horizon
        self.weak_horizon = weak_horizon

    @staticmethod
    def _strong(e: Event) -> set[str]:
        s = {x for x in e.entities if x.startswith("ip:")}
        if e.target:
            s.add(f"user:{e.tenant}/{e.target}")
        return s

    def correlate(self, events_by_id, alerts):
        evs, e2a = _alerted(events_by_id, alerts)
        parent = {e.eid: e.eid for e in evs}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for a in alerts:
            for e in a.eids[1:]:
                union(a.eids[0], e)
        last_seen: dict[tuple, tuple[float, int]] = {}
        for e in evs:
            strong = self._strong(e)
            for ent in e.entities:
                k = (e.tenant, ent)
                h = self.horizon if ent in strong else self.weak_horizon
                if k in last_seen and e.ts - last_seen[k][0] <= h:
                    union(last_seen[k][1], e.eid)
                last_seen[k] = (e.ts, e.eid)
        groups: dict[int, list[Event]] = defaultdict(list)
        for e in evs:
            groups[find(e.eid)].append(e)
        return _finish(sorted(groups.values(), key=lambda g: g[0].ts), e2a)


CORRELATORS = [TimeWindowCorrelator, lambda: LeaderFollower(adaptive=False),
               lambda: LeaderFollower(adaptive=True), EntityGraphCorrelator]


# ------------------------------------------------------------ reconstruction
SECURITY_ACTIONS_ON_HOST = ("auth.ssh", "os.sudo", "audit.daemon_stop", "hv.vm_start")


def _expansion_entities(inc: Incident, events_by_id) -> set[str]:
    ents = set()
    for eid in inc.eids:
        e = events_by_id[eid]
        for x in e.entities:
            if x.startswith(("user:", "ip:")):
                ents.add(x)
            elif x.startswith("host:") and (e.action in SECURITY_ACTIONS_ON_HOST or e.action in ("net.flow", "compute.run")):
                ents.add(x)
    return ents


def reconstruct(incidents: list[Incident], events: list[Event], before: float = 1800,
                after: float = 4 * 3600, hops: int = 2, max_fanout: int = 3) -> list[Incident]:
    """Expand each incident into its full timeline (multi-hop entity pivot).

    Host entities only pull in security-relevant host events (SSH, sudo,
    audit, VM start, and flows that involve an external peer or port 22),
    so routine telemetry such as cron or heartbeats is not dragged in.
    """
    by_id = {e.eid: e for e in events}
    by_ent: dict[tuple, list[Event]] = defaultdict(list)
    users_of_ip: dict[tuple, set] = defaultdict(set)
    for e in events:
        for x in e.entities:
            by_ent[(e.tenant, x)].append(e)
            if x.startswith("ip:") and e.principal:
                users_of_ip[(e.tenant, x)].add(e.principal)
    # supernode pruning: an address used by many identities (corporate NAT,
    # partner gateway) is infrastructure, not an attacker pivot
    hub = {k for k, v in users_of_ip.items() if len(v) > max_fanout}
    for inc in incidents:
        lo, hi = inc.start - before, inc.end + after
        ents = _expansion_entities(inc, by_id)
        members = set(inc.eids)
        frontier = set(ents)
        for _ in range(hops):
            new_ents = set()
            for x in frontier:
                for e in by_ent.get((inc.tenant, x), ()):
                    if not lo <= e.ts <= hi or e.eid in members:
                        continue
                    if x.startswith("host:"):
                        ok = (e.action in SECURITY_ACTIONS_ON_HOST
                              or (e.action == "hv.heartbeat" and e.nbytes >= 90)
                              or (e.action == "net.flow" and (e.dst_port == 22 or
                                                              (is_external(e.dst_ip) and e.dst_port != 443))))
                        if not ok or (e.action == "auth.ssh" and e.outcome == "failure" and
                                      not any(f"ip:{e.src_ip}" == y for y in ents)):
                            continue
                    members.add(e.eid)
                    for y in e.entities:
                        if y.startswith(("user:", "ip:")) and y not in ents and (inc.tenant, y) not in hub:
                            new_ents.add(y)
            ents |= new_ents
            frontier = new_ents
        inc.entities = ents
        inc.timeline = sorted(members, key=lambda i: by_id[i].ts)
    return incidents
