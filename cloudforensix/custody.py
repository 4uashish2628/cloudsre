"""Evidence packaging and a hash-linked chain-of-custody ledger.

The survey repeatedly stresses evidence integrity and chain of custody
(Sec. 5, "evidence integrity and reliability and chain of custody") and the
need for verifiable trust (Sec. 8.2.5).  An :class:`EvidencePackage` stores
each artifact with its SHA-256, a Merkle root over all artifacts, and a
custody ledger in which every action (acquire, seal, transfer, analyse,
verify) is chained to the previous one and MAC-ed by the acting party.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .seclog import merkle_root


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class CustodyEntry:
    seq: int
    ts: float
    actor: str
    action: str
    note: str
    prev: str
    mac: str = ""

    def body(self) -> bytes:
        return json.dumps([self.seq, self.ts, self.actor, self.action, self.note, self.prev]).encode()


@dataclass
class EvidencePackage:
    case_id: str
    artifacts: dict[str, bytes] = field(default_factory=dict)
    ledger: list[CustodyEntry] = field(default_factory=list)
    keys: dict[str, bytes] = field(default_factory=dict)

    def log(self, actor: str, action: str, note: str = "", ts: float | None = None):
        prev = sha256(self.ledger[-1].body() + self.ledger[-1].mac.encode()) if self.ledger else "0" * 64
        e = CustodyEntry(len(self.ledger), ts or time.time(), actor, action, note, prev)
        key = self.keys.setdefault(actor, hashlib.sha256(f"key:{actor}".encode()).digest())
        e.mac = hmac.new(key, e.body(), hashlib.sha256).hexdigest()
        self.ledger.append(e)

    def add(self, name: str, data: bytes, actor: str = "investigator"):
        self.artifacts[name] = data
        self.log(actor, "acquire", f"{name} sha256={sha256(data)} bytes={len(data)}")

    def manifest(self) -> dict:
        names = sorted(self.artifacts)
        digests = [bytes.fromhex(sha256(self.artifacts[n])) for n in names]
        return {"case_id": self.case_id,
                "artifacts": {n: sha256(self.artifacts[n]) for n in names},
                "merkle_root": merkle_root(digests).hex() if names else None}

    def seal(self, actor: str = "investigator"):
        self.log(actor, "seal", f"merkle_root={self.manifest()['merkle_root']}")

    def verify(self) -> tuple[bool, list[str]]:
        problems = []
        sealed_root = None
        prev = "0" * 64
        for e in self.ledger:
            if e.prev != prev:
                problems.append(f"ledger link broken at #{e.seq}")
            key = self.keys.get(e.actor)
            if key is None or not hmac.compare_digest(hmac.new(key, e.body(), hashlib.sha256).hexdigest(), e.mac):
                problems.append(f"bad MAC at #{e.seq}")
            if e.action == "acquire":
                name, rest = e.note.split(" sha256=")
                digest = rest.split()[0]
                if name in self.artifacts and sha256(self.artifacts[name]) != digest:
                    problems.append(f"artifact modified: {name}")
                if name not in self.artifacts:
                    problems.append(f"artifact missing: {name}")
            if e.action == "seal":
                sealed_root = e.note.split("=")[1]
            prev = sha256(e.body() + e.mac.encode())
        if sealed_root and sealed_root != self.manifest()["merkle_root"]:
            problems.append("manifest root differs from sealed root")
        return not problems, problems

    def write(self, outdir: str | Path):
        out = Path(outdir)
        (out / "artifacts").mkdir(parents=True, exist_ok=True)
        for n, b in self.artifacts.items():
            (out / "artifacts" / n).write_bytes(b)
        (out / "manifest.json").write_text(json.dumps(self.manifest(), indent=2))
        (out / "custody_ledger.json").write_text(json.dumps([e.__dict__ for e in self.ledger], indent=2))
