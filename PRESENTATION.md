# Presentation Plan: CloudForensiX

**Total time:** about 15 minutes of talk, then 3–5 minutes of Q&A
**Order:** Aditya → Atithi → Ashish → Chiranthan
**Rule of thumb:** one idea per slide, a figure on most slides, and no paragraphs on slides; the speaker says the detail.

The evaluation has two parts, so make both visible:
- **Research paper and technical contribution (20 marks):** what problem, what we proposed, why it is new compared to the survey.
- **Implementation and evaluation (15 marks):** a working system, a live demo, and measured results with baselines.

---

## 1. Aditya Sharma: Problem, base paper and our idea (about 3.5 min, slides 1–4)

| Slide | Content | Source |
|---|---|---|
| 1. Title | Project title, the 4 names, course, track (Monitoring and Incident Response), GitHub link | paper title page |
| 2. Why cloud forensics is hard | Evidence location is unknown; resources are shared between tenants; logs are spread across user, tenant and provider, each with its own format and clock; the investigator must trust the provider | paper Sec. I |
| 3. Base paper | Manral et al., ACM Computing Surveys 2019. Its taxonomy (incident-, provider-, consumer-, resource-driven), its artifact map (Table 14), its 5 guidelines. Its key gaps: most proposals are never implemented, and there are no metrics to compare them | paper Sec. II |
| 4. Our idea and requirements | "We turned the survey's guidelines into one working system and measured it." Show Table I (requirements R1–R6 vs. SecLaaS, BlockSLaaS, FROST, FMP, CLOSER, ours) | paper Table I |

**What to say at the end (handover):** "These six requirements became six components. Atithi will show how the system is built."

---

## 2. Atithi Jaiman: Architecture and secure logging (about 4 min, slides 5–8)

| Slide | Content | Source |
|---|---|---|
| 5. Architecture | Walk the pipeline left to right: raw logs → FRSL store → normaliser → hybrid detector → correlation → isolation → evidence package. Map each block to the survey's 5 investigation stages | paper Fig. 1 |
| 6. Threat model | Three adversaries: the external attacker, the **malicious cloud insider** (can edit logs and recompute every hash), and the curious co-tenant | paper Sec. III |
| 7. FRSL design | Hash chain + Merkle-sealed batches + Proof of Past Log signed with a key only the **tenant** holds and published outside the provider's control + Bloom filter. Key sentence: "the provider can rewrite its disk, but not the tenant's anchor" | paper Sec. IV-A |
| 8. FRSL results (E1–E3) | Tamper heatmap: only FRSL and blockchain catch the insider who recomputes hashes; FRSL is **7.2× faster** than blockchain; one record verifies in **8 µs**. Honest note: entries not yet sealed can be cut off, so seal on a timer | Fig. 3, Table III |

**Handover:** "Now the logs are safe. Ashish will show how we detect attacks and rebuild what happened."

---

## 3. Ashish Singh: Detection, reconstruction and live demo (about 4.5 min, slides 9–12)

| Slide | Content | Source |
|---|---|---|
| 9. Test environment | Simulated multi-tenant cloud with 5 real log formats; 20 attack campaigns per run (exfiltration, privilege escalation, cryptomining, SSH lateral movement, anti-forensics); benign look-alikes; 5 seeds. Say *why* it is simulated: real providers cannot be instrumented | paper Sec. V, Table II |
| 10. Hybrid detection (E4) | Rules + learnt normal behaviour + Isolation Forest. **100%** campaigns found, detection in **83 s**, false alerts **44 → 14.6 per day (−67%)** | Fig. 4, Table IV |
| 11. Correlation and timeline (E5) | Entity graph links alerts that share an attacker IP, user or host. Best clustering (ARI 0.9996). Evidence recall **34% → 100%** after reconstruction. Ablation: without time-zone correction, SSH lateral recall falls to **63%** | Fig. 5, Fig. 6, Table V |
| 12. **Live demo** (about 1.5 min) | Run the commands below and open one evidence package | see demo script |

### Demo script (practise this; keep a screen recording as backup)

```bash
cd cloudsre
```

```bash
.venv/bin/python -m pytest -q
```

```bash
.venv/bin/python -m cloudforensix.cli investigate --seed 7 --out cases
```

Then open `cases/CASE-tenant-a-020/artifacts/incident_report.md`, or the copy in `examples/`, and point at:
- the reconstructed timeline (failed SSH logins → success → `wget` dropper → lateral movement);
- "Integrity: 50/50 entries verified";
- "residual foreign identifiers = 0";
- the acquisition plan from the survey's Table 14.

**Handover:** "Chiranthan will cover privacy, scale, and what we learned."

---

## 4. Chiranthan: Privacy, scale, conclusion and Q&A (about 3 min, slides 13–16)

| Slide | Content | Source |
|---|---|---|
| 13. Evidence isolation (E6) | A naive dump of the incident window leaks **51 identifiers of other tenants** per incident; ours leaks **0**, with **100%** of the attack evidence kept | Fig. 7 |
| 14. Provider dependency and scale (E7, E8) | Survey Table 14 shows which evidence only the provider holds (storage logs, hypervisor). Only a provider "forensics-as-a-service" API removes the long wait; say clearly this part is a *model*. Pipeline handles about **52k records/s** and scales linearly | Fig. 8, Fig. 9 |
| 15. Contributions and limitations | Recap the 5 contributions. Limitations: simulated data, rules written knowing the attack types, MAC instead of public signatures, modelled acquisition delays | paper Sec. VII |
| 16. Conclusion | Three takeaways: (1) external anchoring defeats a malicious provider cheaply; (2) behaviour context removes two thirds of false alerts; (3) correlation plus correct time normalisation turns a third of the evidence into all of it. Future work. "Thank you, questions?" | paper Sec. VIII |

Chiranthan also **moderates Q&A**: repeat the question, then pass it to whoever presented that part.

---

## Likely questions and who answers

| Question | Answer (short) | Who |
|---|---|---|
| The survey has no algorithm; what did you implement? | Its Section 8.2 guidelines and its gaps (no implementation, no metrics), as one system with baselines from the survey | Aditya |
| Why is the data simulated? | Researchers cannot instrument real provider back-ends (the survey says this too); real formats, ground truth, benign look-alikes | Ashish |
| Why not just use blockchain? | Same detection, 7.2× slower; what matters is that the anchor is outside the provider's control | Atithi |
| What can the insider still do? | Cut off entries that are not yet sealed; fix by sealing every few seconds | Atithi |
| Isn't 100% campaign detection suspicious? | The rules were written knowing the attack types; we report it as a limitation. The real gain is fewer false alerts | Ashish |
| How does this help SRE? | The same telemetry that drives alerts becomes court-ready evidence; detection in about 83 s; linear scaling | Chiranthan |
| How do you protect other tenants' privacy? | Drop their records, pseudonymise shared ones with a key a court can unlock | Chiranthan |

---

## Checklist before the day

- [ ] Build the slide deck from the figures in `paper/figures/` (PNG versions are ready to paste).
- [ ] Rehearse once end to end with a timer; each person stays within their slot.
- [ ] Test the demo on the presenting laptop; record it as a fallback video.
- [ ] Have `paper/main.pdf` and the GitHub page open in tabs.
- [ ] Each person knows the one headline number of every other part.
