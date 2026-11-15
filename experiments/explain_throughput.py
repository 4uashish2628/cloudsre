"""Measure slide 8's ingest throughput step by step (FRSL vs blockchain vs hash chain).

    python experiments/explain_throughput.py

Same method as experiment E1 in run_all.py: write 50,000 real log lines into
each log scheme, time it (best of 3 runs), and divide entries by seconds.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cloudforensix.seclog import FRSL, BlockchainLog, HashChain  # noqa: E402
from run_all import payloads  # noqa: E402

N = 50_000
data = payloads(N)
print(f"Step 1: generated {len(data):,} log lines from the cloud simulator")
print(f"        example: {data[0][:90].decode()}...\n")

results = {}
for cls in (HashChain, FRSL, BlockchainLog):
    times = []
    for _ in range(3):
        log = cls()
        t0 = time.perf_counter()
        for line in data:
            log.append(line)          # hash, chain, and (FRSL) seal every 1,024 entries
        log.seal()                    # seal the last partial batch
        times.append(time.perf_counter() - t0)
    best = min(times)
    results[log.name] = N / best
    print(f"Step 2: {log.name:<18} runs: {', '.join(f'{t:.3f}s' for t in times)}  -> best {best:.3f}s")
    print(f"        throughput = {N:,} entries / {best:.3f} s = {N / best:,.0f} entries/s\n")

f, b = results["FRSL (proposed)"], results["Blockchain (PoW)"]
print(f"Step 3: FRSL / blockchain = {f:,.0f} / {b:,.0f} = {f / b:.1f}x faster")
print("\nSaved result used on the slide: results/e1_logging_overhead.csv (FRSL, n=50000) = 320,703 entries/s")
print("Speed varies 10-20% with laptop load; the ranking and the ~7x gap stay the same.")
