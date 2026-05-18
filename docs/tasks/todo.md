# Project status & backlog

**Last updated:** 2026-05-12
**Branch:** `claude/cti-capability-gap-analysis-fPqgm`
**Tests:** 450+ passing · ruff clean · entry point `threat_intel_hunter.py`

This file replaced the original v1 implementation plan, which had been
fully delivered and was no longer an accurate description of the project.
Every v1 acceptance criterion (OPML/URL/CVE triage → CVSS+EPSS → bucket →
CSV/MD, SQLite cache, `.env` keys, ruff+pytest, README) is **met** and has
been for many commits. See `git log` for the full history. Note: the
project deliberately grew well past the original "single-file, 3-dep, ~400
line" v1 envelope at explicit user direction across subsequent sessions;
the relevant CLAUDE.md constraints are superseded for this branch and the
deeper structural follow-up is tracked under "Deferred by design" below.

---

## Shipped (done)

Foundation: OPML / URL / CVE / STIX-bundle / TAXII ingestion · NVD CVSS +
CWE + CPE · EPSS (batched, historical) · authoritative CISA KEV catalog ·
SQLite cache with per-source TTL + non-purged `runs` history + append-only
`audit_log` · graceful API degradation · rate-limit awareness · NVD key
bootstrap + redaction.

Analysis: 5-bucket triage (KEV override + CVSS×EPSS quadrant) ·
CWE→MITRE ATT&CK · CWE→Cyber Kill-Chain phase · Diamond Model quadrants ·
threat-actor / campaign / malware attribution · TLP + NATO Admiralty
provenance (worst/best merge) · IOC confidence decay (per-type
half-life) · sector filter · asset/inventory correlation.

Collection: multi-IOC extraction (IPv4 / URL / domain / email / MD5 /
SHA-1 / SHA-256, defang-aware) · exploit/PoC tracking (Exploit-DB /
Nuclei / GitHub) · pluggable IOC enrichers (VirusTotal / AbuseIPDB /
OTX / MalwareBazaar).

Dissemination: CSV · IOC CSV · Markdown (ATT&CK / Adversary /
Affected-Hosts cross-tabs) · STIX 2.1 bundle · Sigma stubs · YARA
stubs · Slack + generic-webhook dispatch · per-owner email digest.

Workflow & ops: hunts library + `hunt` subcommand · PIRs library +
`pir` subcommand · `trend` sparkline history · `audit` subcommand ·
interactive wizard · robust path normalization (quote-strip + `~`) ·
custom output basename with smart extension handling · directory-OPML
support · YAML preset system (`--config` / `--save-config` /
`--list-configs` / `--reset-config`) · OPML persistence
(`--remember-opml` / `remember_opml:` YAML / `--reset-opml`) ·
scheduling (`schedule windows-task` / `schedule cron`).

Packaging & docs: `src/` layout (`src/ramen_cve/`) · `pyproject.toml`
full `[project]` metadata + `ramen-cve` console script · bundled data
& config under the package · refreshed `README.md` · `docs/whitepaper.md`
· `docs/SBOM.md` · `docs/cti-capability-gap-analysis*.md` ·
`docs/REFACTOR_PLAN.md` · regenerated `examples/sample-output.csv` +
`examples/sample-report.md` (current 31-column schema).

---

## Backlog (prioritized — see docs/cti-capability-gap-analysis-v2.md)

1. SSVC (Stakeholder-Specific Vulnerability Categorization) decision
   tree, run in parallel with the existing buckets.
2. Native SIEM query generation (KQL / SPL / Elastic EQL) beside Sigma.
3. MISP-native push / pull via PyMISP.
4. Bucket-transition delta alerting — page only when a CVE *moves* up.
5. Vulnerability-scanner imports (Nessus / Qualys / Rapid7).
6. Hunt analytics library (reusable per-ATT&CK-technique queries).
7. Risk-weighted prioritization (CVE × asset criticality × exploit).
8. Backtesting / replay mode for safe model-change evaluation.

## Deferred by design (documented, not a regression)

- The fine-grained `src/core/ parsers/ utils/ outputs/` module split.
  Rationale, exact execution plan, and the test-rewrite cost are recorded
  in `docs/REFACTOR_PLAN.md`. The src/ layout is in place; the deeper
  split is deferred because a blind one-pass move would break the
  patch-target semantics of ~150 `patch("ramen_cve.X")` call sites
  across the test suite and must be its own dedicated, test-rewriting
  cycle.

## Process

- PR #6 is a draft. Mark ready for review when the maintainer is
  satisfied with the branch.
