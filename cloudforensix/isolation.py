"""Privacy-preserving evidence isolation for multi-tenant clouds.

Sec. 8.2.4 of the survey: shared resources mean that evidence acquired for
one tenant (memory dumps, hypervisor logs, shared network logs) also contains
data of "non-considerate users", violating their privacy.  ``isolate``
builds a tenant-scoped evidence set:

1. drop events attributable to another tenant;
2. in *shared* records (e.g. hypervisor node statistics listing every
   co-resident VM) replace foreign identifiers with keyed pseudonyms
   (HMAC-SHA256), so the record stays usable for timeline purposes and can
   be re-identified only by a court-authorised key holder.

``naive_collect`` reproduces the common practice of dumping every record in
the incident window from the shared sources and is the comparison baseline.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from .normalizer import Event
from .simulator import Inventory

VM_RE = re.compile(r"\bvm-[a-z]-[x\d]+\b")
TENANT_RE = re.compile(r"\btenant-[a-z]\b")
ACCT_RE = re.compile(r"\b\d{12}\b")
IP_RE = re.compile(r"\b10\.(\d+)\.\d+\.\d+\b")


def _pseudo(key: bytes, s: str) -> str:
    return "anon-" + hmac.new(key, s.encode(), hashlib.sha256).hexdigest()[:10]


def foreign_identifiers(text: str, tenant: str, inv: Inventory) -> set[str]:
    """Identifiers in ``text`` that belong to tenants other than ``tenant``."""
    out = set()
    for vm in VM_RE.findall(text):
        owner = inv.hosts.get(vm, f"tenant-{vm[3]}")
        if owner != tenant:
            out.add(vm)
    for t in TENANT_RE.findall(text):
        if t != tenant:
            out.add(t)
    for a in ACCT_RE.findall(text):
        owner = inv.accounts.get(a)
        if owner and owner != tenant:
            out.add(a)
    for m in IP_RE.finditer(text):
        owner = f"tenant-{chr(ord('a') + int(m.group(1)) - 1)}"
        if owner != tenant:
            out.add(m.group(0))
    return out


def naive_collect(events: list[Event], start: float, end: float) -> list[str]:
    return [e.raw for e in events if start <= e.ts <= end]


def isolate(events: list[Event], tenant: str, start: float, end: float,
            inv: Inventory, key: bytes = b"court-escrow-key") -> tuple[list[str], dict]:
    kept, stats = [], {"dropped_foreign": 0, "pseudonymised_records": 0, "pseudonyms": 0}
    for e in events:
        if not start <= e.ts <= end:
            continue
        if e.tenant is not None and e.tenant != tenant:
            stats["dropped_foreign"] += 1
            continue
        raw = e.raw
        if e.tenant is None:   # shared record: keep only if it concerns this tenant
            if tenant not in raw and not any(inv.hosts.get(v) == tenant for v in VM_RE.findall(raw)):
                stats["dropped_foreign"] += 1
                continue
        foreign = foreign_identifiers(raw, tenant, inv)
        if foreign:
            for f in sorted(foreign, key=len, reverse=True):
                raw = raw.replace(f, _pseudo(key, f))
            stats["pseudonymised_records"] += 1
            stats["pseudonyms"] += len(foreign)
        kept.append(raw)
    return kept, stats


def leakage(lines: list[str], tenant: str, inv: Inventory) -> int:
    """Number of distinct foreign-tenant identifiers exposed in an evidence set."""
    s = set()
    for ln in lines:
        s |= foreign_identifiers(ln, tenant, inv)
    return len(s)
