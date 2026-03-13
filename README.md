# PRISM — Real-Time APT Attribution Through Behavioral DNA

> *"The next world war won't start with missiles. It already started with packets."*

---

## The World Right Now

The geopolitical landscape of 2024–2025 has fundamentally changed the cyber threat surface. Active conflicts in the Middle East, sustained tensions between nuclear powers, and the fragmentation of global alliances have created the most volatile nation-state cyber environment in history.

When kinetic conflict escalates, cyber operations follow — not after, but alongside and often before. Every major military escalation in the last decade has been preceded or accompanied by a surge in APT (Advanced Persistent Threat) activity:

- **Gaza conflict escalation (2023–2024):** A surge in attacks on Israeli critical infrastructure, water systems, and defense contractors attributed to Iranian-linked groups including MuddyWater and APT35.
- **Ukraine war (2022–present):** Russian APT groups — Sandworm, APT28, Gamaredon — have conducted persistent campaigns targeting energy grids, logistics networks, and government systems.
- **Taiwan Strait tensions:** Chinese APT clusters (APT41, Volt Typhoon) pre-positioned inside US critical infrastructure — not to attack immediately, but to sit and wait.
- **India-Pakistan escalation cycles:** Pakistani threat actors Transparent Tribe and SideCopy run near-continuous spearphishing campaigns against Indian defense and government targets.

The pattern is clear: **as World War III shapes up in proxy form across multiple theaters, APT activity will intensify, accelerate, and expand to secondary targets** — allied nations, supply chains, financial systems, and civilian infrastructure of countries perceived as supporting one side.

The organizations that will be hit hardest are not the ones with no defenses. They are the ones who cannot tell *who* is attacking them until it is already over.

---

## The Problem Nobody Has Actually Solved

### What Exists Today

**VirusTotal** is the de facto standard for malware analysis. Upload a file, get a verdict. Hashes, signatures, sandbox reports. It is excellent at what it does.

What it does is designed for **enterprise security teams defending against commodity threats** — ransomware, infostealer campaigns, mass phishing. A private company getting hit by LockBit ransomware can upload the sample and get answers in seconds.

**That model breaks completely against APTs.**

Nation-state actors do not send a single .exe. They do not trigger signature engines. Their operations look like this:

```
Week 1:  Spearphish lands. Word document opens. No malware drops.
         A macro runs a legitimate Windows binary. Nothing fires.

Week 2:  A scheduled task is quietly registered.
         It calls out to a compromised legitimate website.
         The response is an encoded blob disguised as a JPEG.

Week 3:  The blob decodes to a loader.
         The loader checks: Is this a VM? Is a debugger attached?
         If yes — it deletes itself silently.

Week 5:  The loader pulls a second-stage stager.
         The stager lives in memory only. Never touches disk.
         It opens a C2 channel using DNS over HTTPS.
         Beacon interval: randomized between 4 and 9 hours.

Month 3: The operator is inside. They move laterally using stolen credentials.
         They exfiltrate data in 50KB chunks compressed inside image files.
         Total noise generated: near zero.
```

**None of those steps trigger a VirusTotal alert.** Each artifact in isolation looks clean. A loader that does nothing harmful. A scheduled task that calls a legitimate domain. A JPEG. Normal traffic.

The only way to identify this is to look at the **chain of behaviors** — and recognize that you have seen this chain before.

### What the Current World Offers Instead

Security researchers and threat intelligence firms have documented APT behavior extensively. There are thousands of published reports:

- Mandiant/FireEye's APT group profiles
- MITRE ATT&CK's technique library
- Recorded Future, CrowdStrike, and Secureworks campaign reports
- Government advisories from CISA, NCSC, and BIS

These are **blogs and PDFs.**

When an organization is actively being compromised right now — at 2am, during a live incident — no analyst has time to cross-reference a campaign report from 2021. No tool takes the artifacts they are seeing and tells them: *"This behavioral sequence matches Lazarus Group's 2023 financial sector campaign with 84% confidence, based on these five overlapping indicators."*

**That tool does not exist publicly. PRISM builds it.**

---

## What PRISM Does

PRISM is a real-time behavioral attribution platform. It does not ask: *"Is this file malicious?"*

It asks: *"Who operates like this?"*

The distinction matters enormously. A file can be cleaned, recompiled, repacked, or replaced. Behavior — the way a group thinks, moves, sequences their actions, times their operations, selects their targets — is far harder to change. It is the operational DNA of a threat actor.

### Core Concept: Behavioral DNA Fingerprinting

Every APT group leaves fingerprints across three layers:

| Layer | Examples | Persistence |
|---|---|---|
| **Artifacts** | File hashes, malware samples, C2 IPs | Days to weeks — easily rotated |
| **Techniques** | Persistence methods, lateral movement, exfil patterns | Months to years — slow to change |
| **Behavioral DNA** | Dev environment artifacts, working hours, target logic, code style | Years — almost never changes |

VirusTotal operates entirely at Layer 1. Threat intel blogs document Layer 2 and 3 but provide no query interface. PRISM operates across all three layers with weighted scoring — placing the least trust in artifacts and the most trust in behavioral DNA.

---

## Technical Architecture

### Input Layer

PRISM accepts multiple artifact types as input — reflecting how real incidents surface:

- **Log files** (Windows Event Logs, Sysmon, EDR telemetry)
- **Network captures** (PCAP files, DNS logs, proxy logs)
- **Malware samples** (PE files, scripts, documents with macros)
- **Indicator lists** (IOC feeds, manual analyst observations)
- **Behavioral descriptions** (free text mapped to ATT&CK techniques)

### Feature Extraction Engine

Each input is parsed to extract behavioral signals:

**Static Features**
- Import tables and API call patterns
- String artifacts (language markers, path conventions, error messages)
- Compiler artifacts and build environment traces
- Code structure and control flow signatures

**Behavioral Features**
- MITRE ATT&CK technique mapping (Tactics → Techniques → Sub-techniques)
- Persistence mechanism type and implementation
- Lateral movement method selection
- Command and control communication pattern (protocol, timing, encoding)
- Exfiltration technique and volume pattern
- Operational timing (active hours mapped to timezone inference)

**Infrastructure Features**
- Certificate reuse across campaigns
- ASN and hosting provider clustering
- Domain registration patterns and naming conventions
- IP overlap with known infrastructure

### Attribution Database

The knowledge base is built from structured, public sources:

- **MITRE ATT&CK Enterprise** — technique-to-group mappings for 130+ documented threat groups
- **MalwareBazaar** — open malware sample repository with family tags
- **MISP Threat Sharing** — community-contributed campaign intelligence
- **Public APT Reports** — structured extraction from Mandiant, CrowdStrike, CISA advisories
- **Malpedia** — malware family reference database

Each APT group is represented as a weighted behavioral vector — a numerical signature of their known operational patterns across all three layers.

### Similarity and Scoring Engine

Attribution is computed as weighted cosine similarity between the observed behavioral vector and each group's known profile:

```
Attribution Score = Σ (weight_i × similarity_i) across all feature dimensions

Where:
  Behavioral DNA features   → weight 0.45
  Technique features        → weight 0.35
  Artifact features         → weight 0.20
```

The weighting reflects the real-world stability of each layer. Artifacts change fast. Behavioral DNA persists for years.

**TTP Drift Handling:** APT groups evolve. A group that scores 60% similarity on current TTPs but shows strong behavioral DNA overlap still surfaces in results — with a confidence interval and a drift annotation explaining which elements changed versus which remained consistent.

### Output

For each analysis, PRISM produces:

1. **Top Attribution Candidates** — ranked list of APT groups with similarity scores
2. **Confidence Score** — adjusted for data completeness and TTP drift probability
3. **Matched Indicators** — specific behavioral features that drove the attribution
4. **Campaign Context** — known historical campaigns the current activity resembles
5. **Risk Assessment** — likely targets, probable next steps, recommended defensive actions
6. **MITRE ATT&CK Navigator Layer** — exportable visualization of matched techniques

---

## Why This Matters In The Current Threat Climate

### The Targeting Logic of Nation-State APTs

Nation-state cyber operations are not random. They follow geopolitical logic:

- **Iran-linked groups** (APT35, MuddyWater, Charming Kitten) target Israel, Saudi Arabia, US defense contractors, and dissidents
- **Russian groups** (APT28, Sandworm, Cozy Bear) target NATO members, Ukraine, election infrastructure, energy grids
- **Chinese groups** (APT41, Volt Typhoon, Salt Typhoon) target critical infrastructure pre-positioning, intellectual property, telecom
- **North Korean groups** (Lazarus, APT38, Kimsuky) target financial systems, cryptocurrency, defense research

As Middle East conflict intensifies, organizations in allied nations become secondary targets. A logistics company supplying military goods. A hospital treating military personnel. A bank processing sanctions-related transactions. None of these organizations think of themselves as targets. APTs do not make that distinction.

### The Attribution Gap Is a Strategic Gap

When you cannot attribute an attack, you cannot:

- Understand the true objective (espionage vs disruption vs pre-positioning)
- Predict what comes next in the campaign
- Share actionable intelligence with peers and government
- Inform leadership of the business and national security implications
- Respond proportionately

PRISM closes that gap — not with perfect certainty, but with structured, explainable, evidence-backed attribution that gives analysts a starting point within minutes instead of weeks.

---

## What Makes PRISM Different

| Capability | VirusTotal | Threat Intel Blogs | MISP/OpenCTI | PRISM |
|---|---|---|---|---|
| Single file analysis | ✅ | ❌ | ❌ | ✅ |
| Multi-artifact campaign correlation | ❌ | ❌ | Partial | ✅ |
| Real-time attribution during incident | ❌ | ❌ | ❌ | ✅ |
| TTP-chain behavioral matching | ❌ | Documented only | Partial | ✅ |
| Confidence scoring with evidence | ❌ | ❌ | ❌ | ✅ |
| TTP drift tolerance | ❌ | ❌ | ❌ | ✅ |
| Open, queryable, not proprietary | ✅ | N/A | ✅ | ✅ |

---

## Tech Stack

| Component | Technology |
|---|---|
| Core engine | Python 3.11 |
| Feature extraction | YARA, pefile, python-evtx, scapy |
| ATT&CK integration | mitreattack-python |
| Similarity scoring | scikit-learn, numpy |
| Database | SQLite (local), optional PostgreSQL |
| Dashboard | Streamlit |
| Visualization | Plotly, NetworkX |
| Data sources | MITRE ATT&CK API, MalwareBazaar API, MISP |

---

## Project Status

This project is being developed as part of a cybersecurity hackathon, with a focused MVP targeting:

- MITRE ATT&CK technique extraction and matching
- Top 20 documented APT groups with full behavioral profiles
- Multi-artifact input support
- Streamlit dashboard with scored attribution output
- Campaign visualization using network graphs

---

## Operational Hardening (Low False Positives)

### 1) Use AI as an extraction assistant, not an attribution decision maker

If you are limited to local **Llama 8B** class models, this is still useful for:

- Normalizing free-text incident notes into structured fields
- Suggesting ATT&CK techniques (with explicit evidence snippets)
- Summarizing long advisories into candidate IOCs/TTPs

Do **not** let AI directly assign actor attribution. Keep attribution in deterministic scoring rules and gated thresholds.

### 2) Real-time intel ingestion without auto-poisoning profiles

For constant news flow, use a 3-stage pipeline:

1. **Ingest to queue**: collect advisories/news into a raw `intel_queue` (never update profiles directly).
2. **Extract candidates**: parse each item into proposed TTP/context indicators with source metadata.
3. **Human-reviewed promotion**: review candidate diffs, then merge approved updates into `apt_profiles.json`.

This prevents one noisy article from permanently polluting attribution logic.

Automatic mode (real data, no manual review loop):

```bash
python intel_pipeline.py autopilot-once
```

Continuous automatic updates every 2 hours:

```bash
python intel_pipeline.py autopilot-watch --interval-min 120
```

`autopilot` also performs periodic MITRE ATT&CK sync (cached, default every 24h) to refresh group-technique mappings.

If you want aggressive direct updates, lower thresholds:

```bash
python intel_pipeline.py autopilot-once --min-support 1 --min-evidence 0.45 --force
```

Optional: set `NVD_API_KEY` env var for higher NVD API throughput.

Status command:

```bash
python intel_pipeline.py status
```

Artifacts produced:

- Queue: `intel/raw_queue.jsonl`
- Candidate diffs: `intel/candidate_updates.json`
- Human decisions: `intel/review_sheet.json`
- Change log: `intel/change_log.jsonl`
- Profile backups: `backups/apt_profiles.<timestamp>.json`

Accuracy note:
- Real-time ingestion and auto-updates are implemented, but no production attribution system can guarantee 100% accuracy.
- Keep regression guards enabled (`--max-changed-hyp`) and monitor `intel/change_log.jsonl`.

### 3) Confidence gates before attribution

PRISM now enforces:

- Minimum evidence breadth (technique count + tactic coverage)
- Minimum top score and lead over runner-up
- Emerging-cluster fallback when evidence is weak or novel

Weak cases are shown as **hypotheses**, not confirmed actor labels.

### 4) Emerging cluster memory

Unattributed novel incidents are persisted to `emerging_clusters.json` with:

- `cluster_id`
- `first_seen`, `last_seen`
- `sightings`
- rolling techniques/context and top hypotheses

This lets you track repeat campaigns before naming an actor.

---

## The Bigger Picture

This is not just a hackathon project. The infrastructure being built here — a behavioral attribution layer above raw detection — is what national CERTs, SOC teams, and incident responders need as the cyber dimension of geopolitical conflict intensifies.

VirusTotal solved yesterday's problem. PRISM is built for the threat environment that is already here.

---

*Built during a period when knowing your adversary is no longer optional.*
