# CloudForensiX — Presentation Script

**Order:** Aditya → Atithi → Ashish → Chiranthan
**Length:** about 15 minutes of talk, then Q&A
**Deck:** [CloudForensiX_presentation.pptx](CloudForensiX_presentation.pptx)

How to use this script:
- Read it aloud a few times, then speak it in your own words. Do not read from the screen.
- Text in *[brackets]* is an action (click, point, pause), not something to say.
- **Bold** words are the ones to stress.
- Each part ends with a handover line. Say it, then step aside.

---

## Part 1 — Aditya (slides 1–4, about 3.5 minutes)

### Slide 1 — Title (30 s)

Good morning everyone. We are Aditya, Atithi, Ashish and Chiranthan, and our project is **CloudForensiX**: a forensic-ready monitoring and incident-response framework for multi-tenant clouds.

Our project is based on the paper *"A Systematic Survey on Cloud Forensics: Challenges, Solutions, and Future Directions"* by Manral and colleagues, published in ACM Computing Surveys in 2019.

Here is the plan. I will explain the problem and our idea. Atithi will show the architecture and our secure logging. Ashish will cover attack detection, timeline reconstruction and a live demo. Chiranthan will finish with privacy, scalability and our conclusions.

*[Click]*

### Slide 2 — Why investigating a cloud incident is hard (1 min)

When something goes wrong in the cloud, investigating it is much harder than investigating a normal computer. There are four reasons.

*[Point to each card in turn]*

**First, we don't know where the evidence is.** Data is virtualised and spread across data centres, sometimes across countries. You can't just walk in and seize a server.

**Second, resources are shared.** One physical machine runs virtual machines for many customers. So a single hypervisor log or memory dump contains other customers' data too.

**Third, the logs are scattered.** The user, the customer and the cloud provider each keep different logs, in different formats, in different time zones, with clocks that drift.

**And fourth, we have to trust the provider.** The provider controls the infrastructure and the logs. A malicious insider at the provider could quietly edit them.

For SRE and security teams this matters directly: the same logs we use for monitoring and alerting must later serve as **evidence**.

*[Click]*

### Slide 3 — Base paper (1 min)

Our base paper is a **survey**. It doesn't propose one algorithm. Instead, it reviews about 80 research papers from 2009 to 2019.

*[Point to the four boxes]*

It sorts them into four groups. **Incident-driven** solutions react to an incident or prepare for one. **Provider-driven** solutions rely on the cloud provider's logs or agents. **Consumer-driven** solutions work from the customer's side. **Resource-driven** solutions focus on VMs, storage or networks.

*[Point to the dark card]*

The survey also gives a table of which evidence each party holds, and five guidelines for future investigations.

*[Point to the red warning icon]*

Most importantly for us, it points out two **gaps**. First, most proposed solutions **were never implemented or evaluated**. Second, there are **no metrics** to compare forensic solutions with each other.

*[Click]*

### Slide 4 — Our idea (1 min)

So our idea was simple: take the survey's guidelines and turn them into **one working system**, and then **measure** it.

*[Point to the table rows]*

From the guidelines we derived six requirements. R1, tamper-evident logs that are safe even from a malicious provider. R2, combining different logs and fixing time zones. R3, fast detection with few false alarms. R4, correlating alerts and rebuilding the attack timeline. R5, protecting other customers' privacy. And R6, integrity, chain of custody and metrics.

*[Point to the columns]*

The columns are the main systems the survey reviews: SecLaaS, BlockSLaaS, FROST, the forensic monitoring plane, and CLOSER. Each one covers only **part** of the list. Our system, on the right, covers **all six**, and we test every part against these baselines.

**Handover:** Six requirements became six components. Atithi will now show you how the system is built.

---

## Part 2 — Atithi (slides 5–8, about 4 minutes)

### Slide 5 — Architecture (1 min)

Thank you, Aditya.

This is the complete pipeline. *[Point left]* On the left are five kinds of raw logs: API calls, network flows, the guest operating system's logs, hypervisor logs and storage access logs. They use the same formats that real clouds like AWS use.

*[Follow the arrows along the top row]*

Every record first goes into the **FRSL store**, our tamper-evident log, which I'll explain in a moment. From there the **normaliser** reads all five formats and converts every timestamp to one common time. The **hybrid detector** raises alerts. And the **entity graph** groups the alerts into incidents and rebuilds the full timeline.

*[Point to the orange boxes]*

The orange boxes are what the investigator actually receives. Each incident is **isolated** from other customers' data and packed into an **evidence package** with integrity proofs and a chain-of-custody record. It also includes an acquisition plan telling the investigator who holds which evidence.

*[Point to the small grey labels above the boxes]*

These stages follow the five-step investigation process described in the survey.

*[Click]*

### Slide 6 — Who we defend against (1 min)

We designed against three kinds of adversary.

*[Point left]* The **external attacker** steals passwords or breaks into virtual machines. For this one, our goal is to detect them fast and rebuild the full story.

*[Point centre]* The most important is the **malicious cloud insider**. The survey says most earlier solutions ignore this case. This insider has full write access to the log store. They can edit, delete, reorder or cut off records, and they can even **recompute every stored hash** so the log still looks consistent. The only things they cannot do are forge the customer's secret key and rewrite proofs that were already published outside the provider.

*[Point right]* Third, a **curious co-tenant**, or an investigator, who should never see another customer's data in the evidence.

*[Click]*

### Slide 7 — FRSL design (1 min)

FRSL stands for Forensic-Ready Secure Log. It has four layers.

*[Point to each number]*

**One:** every log entry includes the hash of the entry before it. If anyone deletes or reorders an entry, the chain breaks.

**Two:** every batch of entries is sealed under a single **Merkle root**. Thanks to that, any single record can later be proven with only about ten hashes, without re-checking the whole log.

**Three:** the root, the count and the last hash form a **Proof of Past Log**, which is signed with a key that only the **customer** holds, never the provider.

**Four:** that proof is published **outside** the provider. A Bloom filter also lets an investigator quickly check whether a record existed.

*[Point to the quote]*

So the key idea is this: the provider can rewrite its own disk, **but it cannot rewrite the customer's anchor.**

*[Click]*

### Slide 8 — FRSL results (1 min)

Here are the results. *[Point to the heatmap]* We ran five attacks: modify, delete, insert, reorder and cut off, with a hundred trials each. On the right half, the insider also recomputes all the hashes.

A plain log detects **nothing**. A hash chain catches edits, but **nothing** once the insider recomputes the hashes. Only FRSL and blockchain detect **all** of them.

*[Point to the numbers]*

FRSL detects **100 percent** of insider attacks. It is **7.2 times faster** than blockchain logging, and verifying a single record takes only **8 microseconds**.

*[Point to the red caveat]*

One honest limitation: records that are not yet sealed into a batch can be cut off without detection. In practice, you seal batches on a timer, every few seconds.

**Handover:** Now the logs are safe. Ashish will show how we detect attacks and rebuild what happened.

---

## Part 3 — Ashish (slides 9–12, about 4.5 minutes)

### Slide 9 — Test setup (1 min)

Thank you, Atithi.

To test the system we needed attacks with a known ground truth. Researchers cannot instrument a real cloud provider's systems, and the survey itself says this. So we built a **simulated multi-tenant cloud**.

*[Point to the big numbers]*

Every simulated day contains **20 attack campaigns**. We ran it with **5** different random seeds and averaged the results. Each run produces about **37 thousand** raw log records.

*[Point to the middle card]*

There are five attack types: password guessing followed by data theft; privilege escalation to admin; cryptomining on stolen GPUs; an SSH break-in followed by lateral movement; and anti-forensics, where the attacker switches off logging and shreds logs.

*[Point to the right card]*

To make it realistic, we also added **harmless activity that looks like an attack**: people forgetting passwords, nightly backups downloading lots of files, admins creating users, and Internet scanners. The correct answers are hidden from our system and used only for scoring.

*[Click]*

### Slide 10 — Hybrid detection (1 min)

We compared three detectors. *[Point to the chart]*

**Rules alone** find every attack, but they also raise about **44 false alerts a day**, because the harmless look-alikes trigger them.

**Isolation Forest** alone, a machine-learning anomaly detector, is worse: about **79** false alerts, and it finds only **26 percent** of the attacks.

Our **hybrid** starts from the rules, then suppresses alerts that match normal behaviour learnt during a clean period, for example a known user logging in from their usual IP address. It adds only strong anomalies on top.

*[Point to the numbers]*

The result: it still catches **100 percent** of campaigns, on average within **83 seconds**, and false alerts drop by **67 percent**, to 14.6 a day. Precision rises from 0.49 to **0.78**.

*[Click]*

### Slide 11 — Rebuilding the timeline (1 min)

A detector only flags the events that **trigger** an alert. That's only about a third of what the attacker did.

*[Point to 34% → 100%]*

Our **entity graph** links alerts that share an attacker IP address, a user account or a host. It then searches all the logs for everything connected to them. That takes evidence coverage from **34 percent to 100 percent**.

It also groups attacks better than the Leader-Follower method from the CLOSER paper the survey reviews. Our grouping score, the ARI, is 0.9996.

*[Point to the chart]*

This chart shows why the time-zone fix matters. Operating-system logs record **local** time, with no year and no time zone. If we ignore that, recall for SSH lateral movement falls to **63 percent** and for anti-forensics to **72 percent**. With our correction, both are back to 100 percent.

*[Click]*

### Slide 12 — Live demo (1.5 min)

Now let me show it running.

*[Switch to the terminal]*

First I run our tests. *[Run `.venv/bin/python -m pytest -q`]* All **28 tests** pass.

Now I run a full investigation. *[Run `.venv/bin/python -m cloudforensix.cli investigate --seed 7 --out cases`]* This simulates a full day in a four-customer cloud and runs the whole pipeline in under a second. We get 116 alerts grouped into 26 incidents, **all 20 attacks found**, and the log store verifies as untampered.

*[Run `.venv/bin/python experiments/show_timeline.py cases/CASE-tenant-a-021`]*

This is the rebuilt timeline of one SSH attack. *[Point down the list]* First, **42 failed logins** from the attacker's IP. Then a **successful login** as the user "deploy". Then the attacker downloads a script and runs it **as root**. Then they **scan four other machines** on port 22, log in to two of them, and run the same script there. All of that was rebuilt from just **one** alert.

*[Open `cases/CASE-tenant-a-021/artifacts/incident_report.md`]*

This is the evidence report for the same attack.

*[Point to the Integrity line]* 50 out of 50 records verified against the signed proofs.

*[Point to the isolation line]* Zero identifiers from other customers.

*[Scroll to the acquisition plan]* And here is the plan saying who holds each piece of evidence, taken from the survey's table.

*[If the demo fails, say: "Let me show the recorded run instead," and play the video or open the copy in the `examples` folder.]*

**Handover:** Chiranthan will now cover privacy, scale and what we learned.

---

## Part 4 — Chiranthan (slides 13–16, about 3 minutes, then Q&A)

### Slide 13 — Evidence isolation (45 s)

Thank you, Ashish.

The survey highlights a conflict between forensics and privacy. A hypervisor log or a shared network log contains **other customers'** data.

*[Point to the red bar]*

The usual practice is to dump everything from the incident's time window. That leaks on average **51 identifiers of other customers** per incident.

*[Point to the numbers]*

Our isolation removes other customers' records completely. In shared logs, it replaces their names with coded pseudonyms that only a court-authorised key holder can reverse. The result: **zero** leakage, and we still keep **100 percent** of the attack's own records. The evidence set also shrinks from about 7,150 to 2,030 records, which makes it easier to analyse.

*[Click]*

### Slide 14 — Provider dependency and scalability (45 s)

*[Point to the table]*

Using the survey's evidence table, we worked out which evidence **only the cloud provider** holds. For data theft it's the storage access logs. For cryptomining it's the hypervisor logs.

If you have to request those through a legal process, it can take days. Our model gives a median of around **80 to 90 hours**. I want to be clear that these delays are **modelled with assumed values**, not measured.

Our system makes the customer's own evidence ready in seconds. For provider-held logs, the only real fix is the survey's recommendation: the provider offering **forensics as a service**.

*[Point to the chart]*

On the right, the pipeline scales **linearly**. It handles about **52 thousand records per second** on a single laptop core.

*[Click]*

### Slide 15 — Contributions and limitations (45 s)

To summarise what we contributed. *[Point left]* Six requirements derived from the survey. An open-source framework of about 2,300 lines of code with 28 tests. FRSL, a secure log that is safe from a malicious provider. A reproducible simulator with known correct answers. And a set of forensic metrics with eight experiments.

*[Point right]* We are also open about the limits. The data is simulated, not from a real provider. Our rules were written knowing the attack types, so 100 percent detection does not mean we catch unknown attacks. FRSL uses a customer-held key, not public signatures. Unsealed records can be cut off. And the evidence-waiting times are modelled.

*[Click]*

### Slide 16 — Three takeaways (30 s)

Three takeaways.

**One:** anchoring signed proofs **outside the provider** defeats a malicious insider, at a fraction of blockchain's cost.

**Two:** adding **learnt behaviour** to rules cuts false alerts by two thirds, without missing a single attack.

**Three:** correlating alerts with **correct time** turns a third of the evidence into all of it.

In future we'd like to test on real cloud log datasets, use public signatures with hardware-protected keys, run it as a live streaming service, and add container and network-controller logs.

Thank you. We're happy to take your questions.

*[Chiranthan moderates Q&A: repeat each question so everyone hears it, then pass it to whoever presented that part.]*

---

## Q&A — prepared answers

**"The survey has no algorithm. What exactly did you implement?"** → *Aditya*
The survey's Section 8.2 guidelines and the two gaps it names, no implementation and no metrics. We built all of them as one system and compared each part against the systems the survey reviews.

**"Why didn't you use real cloud data?"** → *Ashish*
Researchers can't instrument a real provider's back end; the survey says this too. Our simulator produces logs in the real AWS-style formats and includes harmless look-alikes. Real public datasets are our next step.

**"Why not just use blockchain?"** → *Atithi*
It gives the same detection but is 7.2 times slower. What actually protects the logs is that the proof sits outside the provider's control. Blockchain is one way to do that; a signed anchor is a cheaper way.

**"What can the insider still do?"** → *Atithi*
Cut off records that haven't been sealed yet. The fix is to seal batches on a short timer, every few seconds.

**"Isn't 100 percent detection suspicious?"** → *Ashish*
Yes, which is why we list it as a limitation: the rules were written knowing the attack types. The real result is the false-alert reduction with no loss of coverage.

**"How does this help SRE teams?"** → *Chiranthan*
The same telemetry that drives alerting becomes evidence you can defend, attacks are detected in about 83 seconds, and it scales linearly.

**"How do you protect other customers' privacy?"** → *Chiranthan*
We drop their records, and in shared logs we replace their identifiers with keyed pseudonyms that only a court-authorised key holder can reverse.

**"What is a Merkle tree / Bloom filter?"** → *Atithi*
A Merkle tree hashes records in pairs, up to one root, so one record can be proven with a few hashes. A Bloom filter is a compact structure that answers "was this record ever there?" very quickly.
