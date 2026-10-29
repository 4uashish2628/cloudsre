"""Stakeholder artifact map and CSP-dependency analysis (survey Sec. 8.1, Table 14).

Table 14 lists, per stakeholder and access mechanism, the forensic artifacts
available and on whom the investigator depends to obtain them
(U = cloud end-user, O = cloud service owner, P = CSP).  The map is encoded
here and used to

* build an acquisition plan for an incident (which artifacts, from whom,
  through which mechanism),
* compute a **CSP Dependency Index** (CDI) - the share of required artifacts
  that can only be obtained with CSP cooperation, and
* estimate evidence-acquisition time with and without forensic readiness
  (experiment E7).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class ArtifactSource:
    stakeholder: str
    mechanisms: tuple[str, ...]
    artifacts: tuple[str, ...]
    dependency: frozenset          # subset of {"U", "O", "P"}
    log_source: str | None = None  # simulator source that realises it


TABLE14 = [
    ArtifactSource("Cloud end-user", ("Browser",), ("browsing history", "cache", "cookies"), frozenset("U")),
    ArtifactSource("Cloud end-user", ("Desktop application",), ("application logs", "database files", "network captures", "registry", "event logs"), frozenset("U")),
    ArtifactSource("Cloud end-user", ("Mobile",), ("log files", "database files"), frozenset("U")),
    ArtifactSource("Cloud end-user", ("APIs",), ("directory listing", "data revision/changelog", "metadata"), frozenset("P")),
    ArtifactSource("Cloud service owner", ("CLI", "Management console", "APIs"), ("account activities", "service logs", "application logs", "data logs"), frozenset("OP"), "cloudtrail"),
    ArtifactSource("Virtual machine", ("CLI", "Management console", "APIs"), ("guest OS logs", "firewall logs", "IDS/IPS logs", "VM snapshots", "application logs", "transaction logs"), frozenset("OP"), "syslog"),
    ArtifactSource("Virtual machine", ("CLI", "Management console", "APIs"), ("network/flow logs",), frozenset("OP"), "vpcflow"),
    ArtifactSource("CSP (hypervisor)", ("CLI", "Management console", "APIs"), ("event logs/syslog", "audit logs", "/var/log", "/proc"), frozenset("P"), "hypervisor"),
    ArtifactSource("CSP (cloud management software)", ("CLI", "Management console", "APIs"), ("component logs (VM, hypervisor, storage, network)",), frozenset("P")),
    ArtifactSource("CSP (cloud storage management)", ("CLI", "Management console", "APIs"), ("backups", "archives", "snapshots", "replicas", "databases", "storage access logs"), frozenset("P"), "s3access"),
    ArtifactSource("CSP (cloud network management)", ("CLI", "Management console", "APIs"), ("router/switch/gateway logs", "SDN controller logs", "northbound/southbound API logs"), frozenset("P")),
]

BY_SOURCE = {a.log_source: a for a in TABLE14 if a.log_source}

# Required log sources per attack scenario (which artifacts reconstruct it).
SCENARIO_SOURCES = {
    "credential_exfil": ["cloudtrail", "s3access"],
    "priv_esc": ["cloudtrail"],
    "cryptomining": ["cloudtrail", "vpcflow", "hypervisor"],
    "ssh_lateral": ["syslog", "vpcflow"],
    "anti_forensics": ["cloudtrail", "syslog"],
}


def acquisition_plan(sources: list[str]) -> list[dict]:
    plan = []
    for s in sources:
        a = BY_SOURCE[s]
        holder = "CSP" if a.dependency == frozenset("P") else (
            "service owner (CSP fallback)" if "O" in a.dependency else "end-user")
        plan.append({"source": s, "stakeholder": a.stakeholder, "obtain_from": holder,
                     "mechanisms": list(a.mechanisms), "artifacts": list(a.artifacts),
                     "dependency": "".join(sorted(a.dependency))})
    return plan


def csp_dependency_index(sources: list[str], cooperative_owner: bool = True) -> float:
    """Share of required artifact sources that need CSP cooperation."""
    if not sources:
        return 0.0
    dep = 0
    for s in sources:
        d = BY_SOURCE[s].dependency
        if d == frozenset("P") or ("O" in d and not cooperative_owner):
            dep += 1
    return dep / len(sources)


def acquisition_time_model(sources: list[str], ready: set[str], rng: np.random.Generator,
                           n: int = 10_000, owner_coop_p: float = 0.8) -> np.ndarray:
    """Monte-Carlo evidence-acquisition time (hours) for one incident.

    Assumed latencies (documented in the paper, Sec. V-G):
      * artifact already captured by the forensic-ready pipeline: retrieval
        is local (measured pipeline time, ~seconds -> 0.01 h);
      * service-owner cooperation: lognormal, median 4 h;
      * CSP request through legal process: lognormal, median 72 h, heavy tail
        (sigma=1.0), cf. jurisdiction/SLA issues in Sec. 5 and 8.2.3;
      * non-cooperative owner falls back to the CSP path.
    Sources are requested in parallel; acquisition completes when the
    slowest source arrives.
    """
    t = np.zeros((n, len(sources)))
    for j, s in enumerate(sources):
        d = BY_SOURCE[s].dependency
        if s in ready:
            t[:, j] = 0.01
            continue
        csp = rng.lognormal(np.log(72), 1.0, n)
        if d == frozenset("P"):
            t[:, j] = csp
        else:
            owner = rng.lognormal(np.log(4), 0.6, n)
            coop = rng.random(n) < owner_coop_p
            t[:, j] = np.where(coop, owner, csp)
    return t.max(axis=1)
