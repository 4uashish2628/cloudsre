"""Print the key steps of an incident's reconstructed timeline (used in the live demo).

    python experiments/show_timeline.py cases/CASE-tenant-a-021
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

case = Path(sys.argv[1])
events = [json.loads(line) for line in (case / "artifacts" / "timeline.jsonl").read_text().splitlines()]

fails = [e for e in events if e["action"] == "auth.ssh" and e["outcome"] == "failure"]
print(f"{case.name}: {len(events)} events in the reconstructed timeline\n")
if fails:
    t = datetime.fromtimestamp(fails[0]["ts"], tz=timezone.utc)
    print(f"{t:%H:%M:%S}  1. BRUTE FORCE   {len(fails)} failed SSH logins from {fails[0]['src_ip']}")

step = 2
for e in events:
    t = datetime.fromtimestamp(e["ts"], tz=timezone.utc)
    if e["action"] == "auth.ssh" and e["outcome"] == "success":
        print(f"{t:%H:%M:%S}  {step}. LOGIN         '{e['principal']}' logged in to {e['host']} from {e['src_ip']}")
    elif e["action"] == "os.sudo":
        print(f"{t:%H:%M:%S}  {step}. RUN AS ROOT   on {e['host']}: {e['detail']}")
    elif e["action"] == "net.flow" and e["dst_port"] == 22 and e["src_ip"].startswith("10."):
        print(f"{t:%H:%M:%S}  {step}. LATERAL MOVE  {e['src_ip']} -> {e['dst_ip']}:22")
    else:
        continue
    step += 1
