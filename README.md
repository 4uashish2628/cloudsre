# CloudForensiX — Forensic-Ready Monitoring & Incident Response for Multi-Tenant Clouds

**Subject:** Cloud and SRE Security · **Track:** Monitoring and Incident Response
**Group:** Aditya Sharma, Atithi Jaiman, Ashish Singh
**Base paper:** B. Manral, G. Somani, K.-K. R. Choo, M. Conti, M. S. Gaur,
*"A Systematic Survey on Cloud Forensics Challenges, Solutions, and Future Directions"*,
ACM Computing Surveys 52(6), Art. 124, 2019. doi:[10.1145/3361216](https://doi.org/10.1145/3361216)

📄 **Research paper:** [`paper/main.pdf`](paper/main.pdf) (LaTeX source: [`paper/main.tex`](paper/main.tex))

---

## 1. What this project does

The survey ends with **cloud forensic investigation guidelines** (Sec. 8.2): live and remote analysis,
log aggregation and correlation, the CSP as a forensic contributor, privacy and evidence isolation, and trusted computing.
It also points out that there are **no metrics** for comparing forensic solutions (Sec. 7.2), and that most surveyed proposals
*"lack implementation and model evaluation"*.

We **implement those guidelines as one end-to-end system** and **evaluate every component** against the baselines the survey discusses:

| Survey guideline / gap | Our implementation | Module |
|---|---|---|
| Continuous forensics, secure logging (3.1, 4.1); CSP must not be trusted (8.2.3) | **FRSL**: hash chain + Merkle-sealed epochs + tenant-MAC'd *Proof of Past Log* anchored outside CSP control + Bloom filters | `seclog.py` |
| Log aggregation; "distinct time zones" (8.2.2, 7.1.2) | 5 raw-format parsers → one schema, UTC via asset inventory, NTP-skew correction, online IP→instance enrichment | `normalizer.py` |
| Live analysis: "quick alerts, minimum false positives" (8.2.1, 7.2) | Sigma-style rules × learnt behaviour profile + Isolation Forest (**hybrid**) | `detector.py` |
| Event reconstruction (CLOSER / Leader-Follower [73]) (4.1, 8.2.2) | **Entity-graph** union-find correlation + multi-hop timeline reconstruction; LF re-implemented as baseline | `correlation.py` |
| Privacy & evidence isolation in multi-tenancy (8.2.4) | Tenant-scoped evidence with HMAC pseudonymisation of co-tenants | `isolation.py` |
| Integrity, chain of custody, trust (5, 8.2.5) | Merkle-sealed evidence manifest + hash-linked, MAC'd custody ledger + FRSL inclusion proofs | `custody.py` |
| Stakeholder artifact map (Table 14) | Encoded Table 14 → acquisition plan, **CSP Dependency Index**, acquisition-time model | `artifacts.py` |
| Missing forensic metrics (7.2) | Detection, reconstruction, integrity, privacy and acquisition metric suite | `metrics.py` |

```
 raw logs (CloudTrail · VPC flow · guest syslog · hypervisor · S3 access)
        │
        ▼
 ┌──────────────┐   PPLs    ┌──────────────────┐
 │  FRSL store  │ ────────▶ │ external anchor  │  (tenant-held MAC key)
 └──────┬───────┘           └──────────────────┘
        ▼
 Normaliser ─▶ Hybrid detector ─▶ Entity-graph correlation ─▶ Reconstruction
                                                                   │
                         Table-14 plan ─▶ Evidence package ◀─ Isolation
                                          (manifest, proofs, custody, report)
```

## 2. Key results (5 seeds, 20 attack campaigns per run, all reproducible)

| Experiment | Headline result |
|---|---|
| E1–E2 secure-logging cost | FRSL ingests **321k entries/s**, **7.2×** faster than a PoW blockchain log; a single-record Merkle proof verifies in **8 µs** (~5,300× faster than a full audit) |
| E3 malicious-CSP tampering | FRSL and the blockchain detect **100%** of modify/delete/insert/reorder/truncate attacks, **even when the insider recomputes hashes**. The hash chain detects **0%** of those. Negative result: truncation of the *unsealed* tail is undetectable, so seal on a timer |
| E4 live detection | Hybrid: **100%** campaigns detected, MTTD **83 s**, false alerts **14.6/day vs 44.2** for rules (−67%), precision 0.78 vs 0.49 |
| E5 correlation & reconstruction | Entity graph ARI **0.9996** (best); reconstruction lifts evidence recall from **34% → 100%** |
| E5 ablation | Without time normalisation, SSH-lateral-movement recall drops to **63%** and anti-forensics recall to **72%** |
| E6 evidence isolation | Foreign-tenant identifiers per incident **51 → 0**, with **100%** of attack evidence retained |
| E7 CSP dependency | Table-14 CDI of 0.5 (exfiltration) and 0.33 (mining); only CSP forensics-as-a-service removes the ~73 h median wait (modelled) |
| E8 scalability | Linear, **~52k records/s** end-to-end on one laptop core (276k records in 5.3 s) |

All numbers are in [`results/summary.json`](results/summary.json) and the per-experiment CSVs in [`results/`](results/).
The figures are in [`paper/figures/`](paper/figures/).

## 3. Repository layout

```
cloudforensix/      framework (simulator, normalizer, seclog, detector, correlation,
                    isolation, custody, artifacts, metrics, pipeline, cli)
experiments/        run_all.py: E1–E8, writes results/ and paper/figures/
tests/              28 pytest unit/integration tests
results/            CSV + summary.json produced by the experiments
paper/              main.tex, main.pdf, figures/
examples/           two real evidence packages produced by the pipeline
                    (SSH lateral movement, cryptomining)
```

## 4. Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
make test          # 28 tests
```

```bash
make experiments   # all 8 experiments, ~65 s, regenerates results/ and figures
```

```bash
make demo          # simulate a 24 h, 4-tenant region and investigate it -> cases/
```

```bash
make paper         # rebuild paper/main.pdf (needs tectonic)
```

CLI:

```bash
.venv/bin/python -m cloudforensix.cli simulate    --seed 7 --tenants 4 --hours 24 --out data
.venv/bin/python -m cloudforensix.cli investigate --seed 7 --out cases
```

`simulate` writes the five raw log files, `inventory.json` and `ground_truth.jsonl`.
`investigate` runs the full pipeline and writes one evidence package per incident:
`timeline.jsonl`, `raw_isolated.log`, `alerts.json`, `acquisition_plan.json`,
`integrity_proofs.json`, `incident_report.md`, `manifest.json` and `custody_ledger.json`.
See [`examples/`](examples/).

Docker: `docker build -t cloudforensix . && docker run --rm cloudforensix`

## 5. Evaluation methodology

Researchers cannot instrument commercial CSP back-ends (survey Sec. 1), so the evaluation uses a **deterministic, seeded
multi-tenant IaaS simulator** that emits *raw text* in five real formats (CloudTrail JSON, VPC Flow Logs v2,
RFC 3164 syslog with local time and no year, libvirt hypervisor logs with node zone and clock drift, and S3 server access logs).
Hidden ground truth (true time, label, campaign, kill-chain step) is used **only for scoring**.

* **Attacks (4 of each type per run, overlapping in time):** credential brute force → S3 exfiltration;
  IAM privilege escalation; cryptomining in an unusual region; SSH brute force → lateral movement;
  anti-forensics (StopLogging, DeleteFlowLogs, auditd stop, log shredding).
* **Benign confounders:** forgotten passwords, travelling users, nightly backups, a DR drill from a new site,
  legitimate admin grants, GPU batch jobs, and Internet SSH scanners.

Limitations (synthetic data, rule thresholds, MAC vs signatures, modelled acquisition latencies) are discussed in the paper, Sec. VII.

## 6. Citation

```bibtex
@article{manral2019survey,
  author  = {Manral, Bharat and Somani, Gaurav and Choo, Kim-Kwang Raymond and Conti, Mauro and Gaur, Manoj Singh},
  title   = {A Systematic Survey on Cloud Forensics Challenges, Solutions, and Future Directions},
  journal = {ACM Computing Surveys}, volume = {52}, number = {6}, articleno = {124}, year = {2019},
  doi     = {10.1145/3361216}
}
```
