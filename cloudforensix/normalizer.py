"""Heterogeneous log aggregation: parse five raw formats into one event schema.

Implements the "log aggregation and correlation for forensics" guideline
(Manral et al., Sec. 8.2.2): logs arrive "with different and incompatible
structures" and, as Sec. 7.1.2 notes, "distinct time zones".  Each parser maps
its format onto :class:`Event` and resolves the timestamp to UTC using the
asset inventory:

* RFC 3164 syslog has neither year nor zone -> host zone from the inventory,
  year from the case context;
* hypervisor timestamps carry a zone but the node clock drifts -> subtract the
  NTP-audited skew recorded in the inventory.

``mode="naive"`` disables both corrections (treat every timestamp as UTC and
ignore skew) and is used as the ablation baseline in experiment E5.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .simulator import MONTHS, Inventory

MON = {m: i + 1 for i, m in enumerate(MONTHS)}

SYSLOG_RE = re.compile(r"^(\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) ([\w\-]+)\[\d+\]: (.*)$")
HYPER_RE = re.compile(r"^(\S+) (\S+) libvirtd: (.*)$")
S3_RE = re.compile(r"^(\d+) (\S+) \[([^\]]+)\] (\S+) (\S+) (\S+) (\S+) (\S+) (\d+) (\d+)$")
SSH_RE = re.compile(r"(Accepted|Failed) (password|publickey) for (?:invalid user )?(\S+) from (\S+) port")
SUDO_RE = re.compile(r"^(\S+) : .*COMMAND=(.*)$")
DOMAIN_RE = re.compile(r"domain (\S+) \((tenant-\w+)\)")
CPU_RE = re.compile(r"cpu=(\d+)%")


@dataclass
class Event:
    eid: int
    ts: float
    source: str
    tenant: str | None
    action: str
    principal: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    nbytes: int = 0
    resource: str | None = None
    target: str | None = None
    host: str | None = None
    region: str | None = None
    outcome: str = "success"
    detail: str = ""
    entities: frozenset = field(default_factory=frozenset)
    raw: str = ""

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("entities", "raw")}
        d["entities"] = sorted(self.entities)
        return d


INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def is_external(ip: str | None) -> bool:
    """True for addresses outside the tenant VPC address space (RFC 1918).

    ``ipaddress.is_private`` is deliberately not used: it also flags the
    documentation ranges (192.0.2/24, 203.0.113/24 ...) that stand in for
    public corporate and partner addresses in the simulator."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a in n for n in INTERNAL_NETS)


CT_ACTIONS = {
    "ConsoleLogin": "auth.login", "GetObject": "storage.get", "PutObject": "storage.put",
    "ListBuckets": "storage.list", "GetBucketAcl": "storage.acl_read",
    "DescribeInstances": "compute.describe", "RunInstances": "compute.run",
    "CreateUser": "iam.create_user", "AttachUserPolicy": "iam.attach_policy",
    "CreateAccessKey": "iam.create_key", "ListUsers": "iam.list", "ListRoles": "iam.list",
    "ListAttachedUserPolicies": "iam.list", "GetAccountAuthorizationDetails": "iam.list",
    "GetCallerIdentity": "sts.whoami", "StopLogging": "audit.stop_logging",
    "DeleteTrail": "audit.delete_trail", "DeleteFlowLogs": "audit.delete_flowlogs",
    "DescribeTrails": "audit.describe",
}


class Normalizer:
    def __init__(self, inventory: Inventory, mode: str = "corrected"):
        assert mode in ("corrected", "naive")
        self.inv = inventory
        self.mode = mode
        self.errors = 0
        self.dyn_ip: dict[str, str] = {}   # inventory enrichment learnt from RunInstances

    # ------------------------------------------------------------ dispatch
    def parse(self, eid: int, source: str, line: str) -> Event | None:
        try:
            ev = getattr(self, f"_p_{source}")(eid, line)
        except Exception:
            self.errors += 1
            return None
        if ev is not None:
            ev.raw = line
            ev.entities = self._entities(ev)
        return ev

    def parse_all(self, records) -> list[Event]:
        out = []
        for i, r in enumerate(records):
            ev = self.parse(i, r.source, r.line)
            if ev is not None:
                out.append(ev)
        return out

    @staticmethod
    def _entities(ev: Event) -> frozenset:
        ents = set()
        if ev.principal and ev.principal != "backup-svc":
            ents.add(f"user:{ev.tenant}/{ev.principal}")
        for ip in (ev.src_ip, ev.dst_ip):
            if ip and is_external(ip):
                ents.add(f"ip:{ip}")
        if ev.target:
            ents.add(f"user:{ev.tenant}/{ev.target}")
        if ev.host:
            ents.add(f"host:{ev.host}")
        return frozenset(ents)

    # ------------------------------------------------------------- parsers
    def _p_cloudtrail(self, eid, line):
        j = json.loads(line)
        ts = datetime.strptime(j["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        ui = j.get("userIdentity", {})
        name = j["eventName"]
        action = CT_ACTIONS.get(name, "api." + name)
        outcome = "failure" if "errorCode" in j else "success"
        if name == "ConsoleLogin":
            outcome = "success" if j.get("responseElements", {}).get("ConsoleLogin") == "Success" else "failure"
        rp = j.get("requestParameters") or {}
        resource = rp.get("bucketName") or rp.get("name") or rp.get("instanceType")
        if "key" in rp:
            resource = f"{rp['bucketName']}/{rp['key']}"
        host = None
        if name == "RunInstances":
            host = rp.get("tag")
            for it in (j.get("responseElements") or {}).get("instancesSet", {}).get("items", []):
                self.dyn_ip[it["privateIpAddress"]] = it["instanceId"]
                host = it["instanceId"]
        return Event(eid, ts, "cloudtrail", self.inv.accounts.get(ui.get("accountId")), action,
                     principal=ui.get("userName"), src_ip=j.get("sourceIPAddress"),
                     resource=resource, target=rp.get("userName") if action.startswith("iam.") else None,
                     region=j.get("awsRegion"), outcome=outcome, host=host,
                     detail=rp.get("policyArn", "") or name)

    def _p_vpcflow(self, eid, line):
        f = line.split()
        src, dst = f[3], f[4]
        host = (self.inv.vm_ip.get(src) or self.inv.vm_ip.get(dst)
                or self.dyn_ip.get(src) or self.dyn_ip.get(dst))
        return Event(eid, float(f[10]), "vpcflow", self.inv.accounts.get(f[1]), "net.flow",
                     src_ip=src, dst_ip=dst, dst_port=int(f[6]), nbytes=int(f[9]),
                     host=host if not (is_external(src) and is_external(dst)) else None,
                     outcome="success" if f[12] == "ACCEPT" else "failure", detail=f[2])

    def _p_syslog(self, eid, line):
        m = SYSLOG_RE.match(line)
        if not m:
            return None
        mon, day, hh, mi, ss, host, prog, msg = m.groups()
        local = datetime(self.inv.case_year, MON[mon], int(day), int(hh), int(mi), int(ss), tzinfo=timezone.utc)
        if self.mode == "corrected":
            local -= timedelta(minutes=self.inv.host_tz_min.get(host, 0))
        tenant = self.inv.hosts.get(host)
        ev = Event(eid, local.timestamp(), "syslog", tenant, f"os.{prog.lower()}", host=host, detail=msg)
        if prog == "sshd":
            s = SSH_RE.search(msg)
            if s:
                ev.action = "auth.ssh"
                ev.outcome = "success" if s.group(1) == "Accepted" else "failure"
                ev.principal = s.group(3) if ev.outcome == "success" else None
                ev.src_ip = s.group(4)
        elif prog == "sudo":
            s = SUDO_RE.match(msg)
            ev.action = "os.sudo"
            if s:
                ev.principal, ev.detail = s.group(1), s.group(2)
        elif prog == "auditd":
            ev.action = "audit.daemon_stop" if "exiting" in msg else "os.auditd"
        return ev

    def _p_hypervisor(self, eid, line):
        m = HYPER_RE.match(line)
        stamp, node, msg = m.groups()
        if self.mode == "corrected":
            ts = datetime.fromisoformat(stamp).timestamp() - self.inv.node_clock_offset_s.get(node, 0.0)
        else:
            ts = datetime.fromisoformat(stamp[:23]).replace(tzinfo=timezone.utc).timestamp()
        d = DOMAIN_RE.search(msg)
        ev = Event(eid, ts, "hypervisor", d.group(2) if d else None, "hv.node_stats", resource=node, detail=msg)
        if d:
            ev.host = d.group(1)
            ev.action = "hv.vm_start" if "started" in msg else "hv.heartbeat"
            c = CPU_RE.search(msg)
            ev.nbytes = int(c.group(1)) if c else 0      # reuse numeric slot for cpu%
        return ev

    def _p_s3access(self, eid, line):
        m = S3_RE.match(line)
        owner, bucket, stamp, ip, requester, _rid, op, key, status, nbytes = m.groups()
        ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        return Event(eid, ts, "s3access", self.inv.accounts.get(owner), "storage.access",
                     principal=requester.rsplit("/", 1)[-1], src_ip=ip, resource=f"{bucket}/{key}",
                     nbytes=int(nbytes), outcome="success" if status.startswith("2") else "failure", detail=op)
