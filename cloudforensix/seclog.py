"""Tamper-evident, forensic-ready log storage (continuous forensics).

The survey (Sec. 4.1, Tables 3-4) reviews secure-logging schemes -- SecLaaS
(Proof of Past Logs + Bloom filters), CLASS, BlockSLaaS and blockchain-based
public auditing -- and lists their weaknesses: no protection against a
*malicious CSP*, no log validation before integrity verification, and heavy
computation/storage overhead.  This module implements the scheme proposed in
this work, **FRSL (Forensic-Ready Secure Log)**, together with the baselines it
is compared against, behind one interface.

FRSL
    * every entry is hash-chained to its predecessor (ordering, deletion);
    * every ``epoch`` entries are sealed in a Merkle tree whose root, entry
      count and previous-epoch digest form a *Proof of Past Log* (PPL);
    * the PPL is MAC-ed with a key held by the tenant / auditor -- **not** the
      CSP -- and published to an append-only anchor (Sec. 8.2.3 "CSP proof");
    * each epoch also carries a Bloom filter so an investigator can test
      whether a given record existed without downloading the epoch (SecLaaS);
    * single entries are verifiable with an O(log B) Merkle inclusion proof.

Threat model: the attacker is a privileged CSP insider with full read/write
access to the log store (it may rewrite entries *and* recompute every hash),
but cannot forge the anchor MAC or rewrite already-published anchors.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
from dataclasses import dataclass, field

H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
ZERO = b"\x00" * 32


def entry_digest(seq: int, payload: bytes, prev: bytes) -> bytes:
    return H(struct.pack(">Q", seq) + prev + payload)


# ----------------------------------------------------------------- primitives
def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    level = [H(b"\x00" + x) for x in leaves] or [H(b"")]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [H(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    return merkle_levels(leaves)[-1][0]


def merkle_proof(levels: list[list[bytes]], idx: int) -> list[tuple[bool, bytes]]:
    proof = []
    for level in levels[:-1]:
        if len(level) % 2:
            level = level + [level[-1]]
        sib = idx ^ 1
        proof.append((sib < idx, level[sib]))
        idx //= 2
    return proof


def merkle_verify(leaf: bytes, proof, root: bytes) -> bool:
    h = H(b"\x00" + leaf)
    for left, sib in proof:
        h = H(b"\x01" + sib + h) if left else H(b"\x01" + h + sib)
    return hmac.compare_digest(h, root)


class BloomFilter:
    def __init__(self, n: int, fp: float = 0.001):
        self.m = max(64, int(-n * math.log(fp) / (math.log(2) ** 2)))
        self.k = max(1, round(self.m / max(1, n) * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)

    def _idx(self, item: bytes):
        d = hashlib.sha256(item).digest()
        h1, h2 = int.from_bytes(d[:8], "big"), int.from_bytes(d[8:16], "big")
        return ((h1 + i * h2) % self.m for i in range(self.k))

    def add(self, item: bytes):
        for i in self._idx(item):
            self.bits[i >> 3] |= 1 << (i & 7)

    def __contains__(self, item: bytes) -> bool:
        return all(self.bits[i >> 3] & (1 << (i & 7)) for i in self._idx(item))

    def nbytes(self) -> int:
        return len(self.bits)


# ------------------------------------------------------------------- schemes
@dataclass
class Entry:
    seq: int
    payload: bytes
    prev: bytes = ZERO
    digest: bytes = ZERO


class LogScheme:
    """Common interface. ``store`` is the CSP-controlled (mutable) state;
    ``anchors`` is the externally published, attacker-immutable state."""

    name = "base"
    can_recompute = True     # insider can recompute whatever is stored

    def __init__(self, epoch: int = 1024):
        self.epoch = epoch
        self.store: list[Entry] = []
        self.anchors: list = []

    def append(self, payload: bytes) -> None:
        self.store.append(Entry(len(self.store), payload))

    def seal(self) -> None:
        pass

    def verify(self) -> bool:
        return True

    def overhead_bytes(self) -> int:
        return 0

    def recompute(self) -> None:
        """Insider re-derives all *stored* integrity metadata after tampering."""


class PlainLog(LogScheme):
    name = "Plain central log"


class PerEntryHash(LogScheme):
    name = "Per-entry hash"

    def append(self, payload):
        self.store.append(Entry(len(self.store), payload, digest=H(payload)))

    def verify(self):
        return all(hmac.compare_digest(H(e.payload), e.digest) for e in self.store)

    def recompute(self):
        for e in self.store:
            e.digest = H(e.payload)

    def overhead_bytes(self):
        return 32 * len(self.store)


class HashChain(LogScheme):
    name = "Hash chain"

    def append(self, payload):
        prev = self.store[-1].digest if self.store else ZERO
        seq = len(self.store)
        self.store.append(Entry(seq, payload, prev, entry_digest(seq, payload, prev)))

    def verify(self):
        prev = ZERO
        for i, e in enumerate(self.store):
            if e.seq != i or e.prev != prev or entry_digest(e.seq, e.payload, prev) != e.digest:
                return False
            prev = e.digest
        return True

    def recompute(self):
        prev = ZERO
        for i, e in enumerate(self.store):
            e.seq, e.prev = i, prev
            e.digest = entry_digest(i, e.payload, prev)
            prev = e.digest

    def overhead_bytes(self):
        return 72 * len(self.store)


@dataclass
class PPL:
    """Proof of Past Log for one sealed epoch (published, attacker-immutable)."""

    index: int
    first_seq: int
    count: int
    root: bytes
    chain_tail: bytes
    prev_ppl: bytes
    mac: bytes
    bloom: BloomFilter = field(repr=False, default=None)

    def body(self) -> bytes:
        return struct.pack(">QQQ", self.index, self.first_seq, self.count) + self.root + self.chain_tail + self.prev_ppl


class FRSL(HashChain):
    """Proposed scheme: hash chain + Merkle-sealed epochs + auditor-MAC-ed,
    externally anchored PPLs + per-epoch Bloom filters."""

    name = "FRSL (proposed)"

    def __init__(self, epoch: int = 1024, auditor_key: bytes = b"tenant-auditor-key", bloom_fp: float = 0.001):
        super().__init__(epoch)
        self._key = auditor_key        # held by tenant/auditor, never by CSP
        self.bloom_fp = bloom_fp
        self._sealed = 0
        self._levels: dict[int, list[list[bytes]]] = {}

    def append(self, payload):
        super().append(payload)
        if len(self.store) - self._sealed >= self.epoch:
            self.seal()

    def seal(self):
        if self._sealed >= len(self.store):
            return
        chunk = self.store[self._sealed:]
        leaves = [e.digest for e in chunk]
        levels = merkle_levels(leaves)
        bloom = BloomFilter(len(chunk), self.bloom_fp)
        for e in chunk:
            bloom.add(H(e.payload))
        prev_ppl = H(self.anchors[-1].body()) if self.anchors else ZERO
        p = PPL(len(self.anchors), self._sealed, len(chunk), levels[-1][0], chunk[-1].digest, prev_ppl, b"", bloom)
        p.mac = hmac.new(self._key, p.body(), hashlib.sha256).digest()
        self._levels[p.index] = levels
        self.anchors.append(p)
        self._sealed = len(self.store)

    def verify(self) -> bool:
        if not super().verify():
            return False
        prev = ZERO
        covered = 0
        for p in self.anchors:
            if not hmac.compare_digest(hmac.new(self._key, p.body(), hashlib.sha256).digest(), p.mac):
                return False
            if p.prev_ppl != prev or p.first_seq != covered:
                return False
            chunk = self.store[p.first_seq:p.first_seq + p.count]
            if len(chunk) != p.count or chunk[-1].digest != p.chain_tail:
                return False
            if merkle_root([e.digest for e in chunk]) != p.root:
                return False
            prev = H(p.body())
            covered += p.count
        return True

    # investigator utilities ------------------------------------------------
    def prove(self, seq: int):
        for p in self.anchors:
            if p.first_seq <= seq < p.first_seq + p.count:
                return p.index, merkle_proof(self._levels[p.index], seq - p.first_seq)
        raise KeyError("entry not yet sealed")

    def verify_entry(self, entry: Entry, ppl_index: int, proof) -> bool:
        p = self.anchors[ppl_index]
        ok_mac = hmac.compare_digest(hmac.new(self._key, p.body(), hashlib.sha256).digest(), p.mac)
        return ok_mac and entry_digest(entry.seq, entry.payload, entry.prev) == entry.digest \
            and merkle_verify(entry.digest, proof, p.root)

    def maybe_contains(self, payload: bytes) -> bool:
        h = H(payload)
        return any(h in p.bloom for p in self.anchors)

    def overhead_bytes(self):
        per_ppl = 24 + 32 * 4
        return super().overhead_bytes() + sum(per_ppl + p.bloom.nbytes() for p in self.anchors)

    def unsealed(self) -> int:
        return len(self.store) - self._sealed


class BlockchainLog(LogScheme):
    """BlockSLaaS-style baseline: entries packed into proof-of-work blocks
    whose headers are replicated to consortium nodes outside CSP control."""

    name = "Blockchain (PoW)"

    def __init__(self, epoch: int = 1024, block_size: int = 64, difficulty_bits: int = 12):
        super().__init__(epoch)
        self.block_size = block_size
        self.target = 1 << (256 - difficulty_bits)
        self._pending: list[Entry] = []
        self._first = 0

    def append(self, payload):
        e = Entry(len(self.store), payload, digest=H(payload))
        self.store.append(e)
        self._pending.append(e)
        if len(self._pending) >= self.block_size:
            self.seal()

    def _mine(self, header: bytes) -> tuple[int, bytes]:
        nonce = 0
        while True:
            h = H(header + struct.pack(">Q", nonce))
            if int.from_bytes(h, "big") < self.target:
                return nonce, h
            nonce += 1

    def seal(self):
        if not self._pending:
            return
        prev = self.anchors[-1][4] if self.anchors else ZERO
        root = merkle_root([e.digest for e in self._pending])
        header = prev + root + struct.pack(">QQ", self._first, len(self._pending))
        nonce, bh = self._mine(header)
        self.anchors.append((self._first, len(self._pending), root, nonce, bh, prev))
        self._first += len(self._pending)
        self._pending = []

    def verify(self):
        prev = ZERO
        covered = 0
        for first, n, root, nonce, bh, p in self.anchors:
            chunk = self.store[first:first + n]
            if first != covered or len(chunk) != n or p != prev:
                return False
            if any(H(e.payload) != e.digest for e in chunk):
                return False
            if merkle_root([e.digest for e in chunk]) != root:
                return False
            header = p + root + struct.pack(">QQ", first, n)
            if H(header + struct.pack(">Q", nonce)) != bh or int.from_bytes(bh, "big") >= self.target:
                return False
            prev = bh
            covered += n
        return True

    def recompute(self):
        for e in self.store:
            e.digest = H(e.payload)

    def overhead_bytes(self):
        return 32 * len(self.store) + len(self.anchors) * (32 * 4 + 24)


SCHEMES = [PlainLog, PerEntryHash, HashChain, BlockchainLog, FRSL]


# ------------------------------------------------------------------ attacks
def tamper(scheme: LogScheme, kind: str, rng, recompute: bool) -> None:
    """Apply one insider attack to the CSP-controlled store."""
    st = scheme.store
    n = len(st)
    i = rng.randrange(1, n - 2)
    if kind == "modify":
        st[i].payload = st[i].payload.replace(b"Failure", b"Success") + b" "
    elif kind == "delete":
        del st[i]
    elif kind == "insert":
        st.insert(i, Entry(i, b'{"eventName":"ConsoleLogin","note":"fabricated alibi"}',
                           st[i].prev, st[i].digest))
    elif kind == "reorder":
        st[i], st[i + 1] = st[i + 1], st[i]
    elif kind == "truncate":
        del st[i:]
    else:
        raise ValueError(kind)
    if recompute:
        scheme.recompute()
