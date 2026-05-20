# Threat Intel on a Ramen Budget — A Technical Whitepaper

**Project:** ramen-cve / threat-intel-hunter
**Author:** Danny Page ([@cesiumskater](https://github.com/cesiumskater))
**Companion to:** the BSidesSLC 2026 talk *"Threat Intel on a Ramen Budget"*
**Document version:** 1.0 — 2026-05-12

---

## Abstract

Most organizations cannot afford a commercial Threat Intelligence Platform
(TIP) or a staffed CTI team. They *can* afford an analyst, a laptop, and a
handful of free APIs. `ramen-cve` (invoked as `threat_intel_hunter.py`) is a
single-package Python CLI that delivers the working core of a CTI / threat-
hunting program on that budget: it collects vulnerability and indicator data
from open feeds, enriches it against authoritative free sources, frames it
using the industry-standard analytical models (MITRE ATT&CK, the Diamond
Model, the Cyber Kill Chain), prioritizes it with a transparent decision
model, and disseminates it in every format a downstream tool can consume.

This paper documents the project's purpose, architecture, threat-intelligence
methodology, technical implementation, security posture, and roadmap.

---

## 1. Problem statement

The intelligence cycle — *direction → collection → processing → analysis →
dissemination → feedback* — does not require a platform. It requires a
repeatable process. The barriers a small team actually hits are:

1. **Volume.** Hundreds of CVEs disclosed weekly; only a fraction matter to
   any given environment.
2. **Fragmentation.** CVSS lives at NVD, exploitation probability at
   FIRST.org EPSS, known-exploited status at CISA, exploit code at
   Exploit-DB / Nuclei / GitHub, attribution at MITRE ATT&CK. Stitching
   these by hand is the job no one has time for.
3. **Actionability.** "CVE-2021-44228 is CVSS 10.0" is not an action. "This
   affects `web-prod-03`, is KEV-listed with a past-due remediation date, is
   used by APT41 against the financial sector, and a Metasploit module
   exists" *is*.
4. **Continuity.** Intelligence that depends on an analyst remembering to
   run a script is not a program.

`ramen-cve` collapses all four into one command.

---

## 2. Design principles

- **Correctness over cleverness.** Every external call degrades gracefully;
  a failed enrichment never aborts the run.
- **Transparent prioritization.** The bucket model is a flat decision table
  an analyst can hold in their head and defend to leadership.
- **Minimal, auditable dependencies.** Five runtime packages, all permissive-
  licensed (see `docs/SBOM.md`). Stdlib-heavy.
- **Single-artifact friendliness.** The implementation is one importable
  package; the root is one entry-point file. It runs from a checkout with no
  install, or installs as a console script.
- **Provenance everywhere.** TLP and NATO Admiralty grades flow from source
  to output; secrets are redacted from every log and artefact.
- **Cross-platform first.** Windows path quirks (quoted paths, `~`) are
  handled at the boundary; scheduling generates native Task Scheduler XML
  *and* cron lines.

---

## 3. Architecture

```
                 ┌─────────────────────────────────────────────┐
   Inputs  ──►   │  COLLECTION                                  │
   OPML / dir    │  parse_opml · extract_cves · extract_iocs    │
   URL           │  parse_stix_bundle · pull_taxii              │
   CVE list      └───────────────────┬─────────────────────────┘
   STIX/TAXII                        │
                 ┌───────────────────▼─────────────────────────┐
                 │  ENRICHMENT (cached, rate-limited, gated)    │
                 │  NVD CVSS+CWE+CPE · EPSS · CISA KEV ·         │
                 │  Exploit-DB / Nuclei / GitHub PoC ·           │
                 │  VirusTotal/AbuseIPDB/OTX/MalwareBazaar ·     │
                 │  associations.json (actors/campaigns/malware) │
                 └───────────────────┬─────────────────────────┘
                 ┌───────────────────▼─────────────────────────┐
                 │  ANALYSIS                                    │
                 │  CWE→ATT&CK · CWE→Kill-Chain · Diamond Model │
                 │  bucket_and_suggest · TLP/Admiralty merge ·  │
                 │  IOC confidence decay · inventory correlation│
                 │  sector filter                               │
                 └───────────────────┬─────────────────────────┘
                 ┌───────────────────▼─────────────────────────┐
                 │  DISSEMINATION                               │
                 │  CSV · Markdown · STIX 2.1 · Sigma · YARA ·  │
                 │  Slack · generic webhook · email digest      │
                 └───────────────────┬─────────────────────────┘
                 ┌───────────────────▼─────────────────────────┐
                 │  WORKFLOW & OPERATIONS                        │
                 │  hunts/ · pirs/ · trend · audit log ·        │
                 │  YAML presets · schedule (Task Sched / cron) │
                 └─────────────────────────────────────────────┘
```

State lives in a single SQLite database (`.ramen-cache.db`): per-source TTL
caches, a non-purged `runs` history (for trending), and an append-only
`audit_log`. Bundled lookup data ships inside the package
(`src/ramen_cve/data/`); YAML presets ship under `src/ramen_cve/config/`.

The codebase is a ~30-module package under `src/ramen_cve/`, refactored from
the original single-file design on 2026-05-18 → 2026-05-20 (see
`docs/REFACTOR_PLAN.md` Execution Log, steps 0–33). The package layers
(constants → models → cache → extract → … → output / dispatch / config →
cli → façade) preserve the flat `from ramen_cve import X` contract via a
re-export `__init__.py`. The 463-test suite and a golden byte-oracle
proved the refactor is zero-behaviour-change end-to-end (regenerated
CSV/Markdown are byte-identical to the pre-refactor baseline).

---

## 4. Threat-intelligence methodology

### 4.1 Prioritization model

Every CVE lands in exactly one bucket, evaluated top-to-bottom:

| Bucket | Condition | Rationale |
| --- | --- | --- |
| **KEV Override** | CISA KEV listed | Exploitation is *confirmed in the wild*. CVSS/EPSS are moot. |
| **Patch Now** | CVSS ≥ τ_cvss **and** EPSS ≥ τ_epss | Severe **and** statistically likely to be exploited. |
| **Plan & Patch** | CVSS ≥ τ_cvss **and** EPSS < τ_epss | Severe, exploitation not yet probable — schedule it. |
| **Watch Closely** | CVSS < τ_cvss **and** EPSS ≥ τ_epss | Lower impact but actively exploited — monitor. |
| **Deprioritize** | otherwise | Low impact, low probability. |

CVSS answers *how bad if exploited*; EPSS answers *how likely to be
exploited in the next 30 days*; KEV answers *is it being exploited now*.
Using all three avoids the classic failure mode of CVSS-only programs
(patching a CVSS 9.8 nobody is exploiting while ignoring a CVSS 6.5 in every
exploit kit).

### 4.2 Analytical framing

- **MITRE ATT&CK** — each CVE's CWE list is mapped to likely ATT&CK
  techniques, so the report ties vulnerabilities to adversary behavior and
  detection coverage rather than leaving them as abstract scores.
- **Diamond Model** — the four vertices (adversary / capability /
  infrastructure / victim) are populated from associations + inventory, so
  a finding reads as an event, not a row.
- **Cyber Kill Chain** — CWE → kill-chain phase mapping situates each CVE in
  the intrusion lifecycle.
- **Admiralty Code + TLP** — every record carries source-reliability and
  sharing-restriction metadata, merged conservatively (worst TLP, best
  Admiralty) when multiple sources corroborate.

### 4.3 Indicator lifecycle

IOCs are not eternal. Confidence decays on a per-type exponential half-life
(IPv4 30 d, URL 30 d, domain 90 d, e-mail 90 d; file hashes never decay).
`--ioc-confidence-floor` drops indicators below a threshold so stale noise
doesn't accumulate run over run.

### 4.4 Direction & feedback

The intelligence cycle's bookends are first-class: **PIRs**
(`pirs/*.json`, `pir` subcommand) capture the leadership-blessed questions
the program exists to answer; **hunts** (`hunts/*.json`, `hunt` subcommand)
track hypothesis-driven investigations through to a true/false-positive
disposition; **trend** shows a CVE's bucket/score trajectory across runs;
the **audit log** records who ran what, when, and with what outcome.

---

## 5. Technical implementation highlights

- **Caching & rate-limiting.** SQLite tables with per-source TTL; NVD calls
  back off to the unauthenticated 5-req/30 s budget when no key is present.
- **Graceful degradation.** Every fetcher is wrapped: a 4xx/5xx/timeout
  logs a warning and yields an empty result; the pipeline continues.
- **Deterministic identifiers.** STIX SDO IDs and Sigma/YARA rule IDs are
  SHA-256-derived UUIDv4-shaped strings, so re-runs produce stable IDs that
  downstream platforms can diff/dedupe.
- **Path robustness.** A single normalization pipeline strips ASCII/curly
  quotes, trims whitespace, and expands `~` for *every* user-supplied path,
  fixing the Windows "Copy as path" footgun.
- **YAML preset system.** `--save-config NAME` snapshots an invocation;
  `--config NAME` replays it (CLI flags still win). The email block
  populates SMTP env vars; the logging block sets verbosity. This is what
  makes unattended scheduled runs trivial.
- **Native scheduling.** `schedule windows-task` emits importable Task
  Scheduler 2.0 XML; `schedule cron` emits a crontab line. The safer OS
  scheduler is generated rather than a fragile long-running daemon.
- **Defensive output.** TLP:RED records are stripped unless
  `--allow-tlp-red`; secrets never reach an artefact; generated detection
  content is inert *stubs*, never executable.

---

## 6. Security considerations

- **Secret handling.** API keys and SMTP credentials are sourced only from
  environment / `.env`; `_redact_key` and `_redact_audit_args` keep them out
  of logs and the audit table. The YAML template explicitly warns against
  storing SMTP passwords in plaintext YAML and recommends `.env`.
- **Path traversal.** Hunt/PIR ids are rejected if they contain separators
  or leading dots; output basenames are sanitized of shell/glob/path
  metacharacters; traversal artefacts collapse to a clean stem.
- **Supply chain.** Five permissive-licensed runtime deps, all from PyPI
  over TLS, no vendored binaries (see `docs/SBOM.md`). No copyleft.
- **Egress transparency.** Every network endpoint the tool may contact is
  enumerated in the SBOM; all third-party enrichment is opt-in/gated.
- **No code execution.** The tool emits data and inert rule stubs only; the
  scheduled-task XML it generates is the only thing that causes future
  execution, and the operator imports it explicitly.

---

## 7. Limitations

- Heuristic CWE→ATT&CK and CWE→Kill-Chain maps; a curated mapping per CVE
  would be more precise.
- `associations.json` is a seeded sample (12 CVEs), not a live attribution
  feed.
- EPSS captures internet-wide probability, not environment-specific risk;
  inventory correlation narrows but does not replace it.
- Bucketing is deliberately flat — it is a triage aid, not a quantitative
  risk model (see roadmap: SSVC).

---

## 8. Roadmap

Prioritized in `docs/cti-capability-gap-analysis-v2.md`:

1. **SSVC decision tree** (CISA/CMU) alongside the existing buckets.
2. **Native SIEM query generation** (KQL / SPL / Elastic EQL) beside Sigma.
3. **MISP-native push/pull** via PyMISP.
4. **Bucket-transition delta alerting** — page only when a CVE *moves* up.
5. **Vulnerability-scanner imports** (Nessus / Qualys).
6. **Risk-weighted prioritization** (CVE × asset criticality × exploit).
7. **Backtesting / replay mode** for evaluating model changes safely.
8. Completion of the fine-grained `core/parsers/outputs` module split.

---

## 9. Conclusion

A CTI program is a process, not a purchase. `ramen-cve` proves that the
working core — collection, multi-source enrichment, framework-aligned
analysis, transparent prioritization, multi-format dissemination, and the
direction/feedback bookends — fits in one auditable Python package a single
analyst can run, schedule, and defend. Threat intelligence on a ramen
budget is not a compromise; for most teams it is the pragmatic 80%.
