# CTI / Threat Hunting Capability Gap Analysis — v2

**Repository:** `cesiumskater/cti-cth-ramen-budget`
**Analysis date:** 2026-05-06
**Scope:** All `.py` files in the repository — at the time of this analysis, the implementation lived in a single ~4,120-line `ramen_cve.py` plus `tests/` (5,400 lines across `test_ramen_cve.py`, `test_smoke.py`, `test_wizard.py`, `test_api_key_prompt.py`).

> **Status (as of 2026-05-20):** this analysis was conducted against the
> pre-refactor monolith. The monolith was split into a ~30-module
> package under `src/ramen_cve/` between 2026-05-18 and 2026-05-20
> (see `docs/REFACTOR_PLAN.md` Execution Log, steps 0–33). All
> capabilities catalogued below remain present and behave identically;
> file/line references in this document point at pre-refactor paths
> (`ramen_cve.py:NNNN`) and are preserved for historical traceability.
> Current test count: **463 passing** (was 302 at the time of writing).

This is the **second-pass audit** following the v1 gap analysis (`cti-capability-gap-analysis.md`). Since v1, fourteen features have shipped (CISA KEV catalog, multi-IOC extraction, MITRE ATT&CK mapping, exploit/PoC tracking, STIX/TAXII I/O, threat-actor modeling, Sigma rule generation, multi-source IOC enrichment, TLP+Admiralty tagging, threat-hunt workflow, asset/inventory correlation, Slack/webhook dispatchers, Diamond Model + Kill Chain, historical trending). The gaps below are the next layer the project would need to grow into to reach the level of a fully-staffed enterprise CTI program.

---

## Executive Summary

`ramen-cve` has graduated decisively past the v1 "vulnerability triage utility" classification. The codebase now spans CVE enrichment, multi-IOC collection, STIX 2.1 / TAXII 2.x bidirectional interoperability, MITRE ATT&CK technique mapping, Diamond Model + Cyber Kill Chain framing, threat-actor / campaign / malware attribution, asset-exposure correlation against an inventory CSV, four pluggable IOC enrichers (VirusTotal / AbuseIPDB / OTX / MalwareBazaar), a hunt-hypothesis JSON workflow, Sigma detection-rule scaffolding, Slack + webhook dispatch, and historical trending with sparkline rendering. Maturity is now best described as **Intermediate — broad-coverage CTI/TH platform**: it produces analyst-actionable artifacts in formats every downstream platform (MISP, OpenCTI, SIEM, ticketing) can consume, with provenance (TLP / Admiralty), kill-chain framing, and detection scaffolds. The remaining gaps are no longer foundational; they are the second-stage features that distinguish a working CTI tool from a fully-instrumented program — SSVC-style decision frameworks, native SIEM query languages, MISP-platform integration, indicator decay, audit logging, a delta-on-bucket-change alert path, and a more sophisticated risk-weighted prioritization model that takes asset criticality into account. Operationally, the single-file design had reached ~4,100 lines at the time of this analysis (≈8× the project's stated 500-line refactor threshold). The package split was executed between 2026-05-18 and 2026-05-20 (see `docs/REFACTOR_PLAN.md`) and has cleared the maintenance cliff — `src/ramen_cve/__init__.py` is now a 526-LOC pure re-export façade with implementation distributed across ~30 focused modules.

---

## Current Capability Inventory

The features below are present today in `.py` files. Filenames and function names are referenced so each item can be located directly. Line counts compared to v1: `ramen_cve.py` grew from ~1,400 → 4,120 (+193%) before the May-2026 package refactor; test count grew from ~115 (v1) → ~302 (at the time of this analysis) → **463 passing** (post-refactor, current).

### Collection
- **OPML feed ingestion with TLP / Admiralty inheritance.** `ramen_cve.py:parse_opml` walks `<outline>` elements recursively and reads `data-tlp` / `data-admiralty` extension attributes (with parent-outline inheritance).
- **Single-URL ingestion** with HTML publication-date sniffing. `ramen_cve.py:_run_url`.
- **Manual / file-based CVE list ingestion.** `ramen_cve.py:_run_cve` (with `--from-file`).
- **STIX 2.1 bundle ingestion** from a local JSON file. `ramen_cve.py:parse_stix_bundle` + `_stix_objects_to_records`.
- **TAXII 2.1 collection pull.** `ramen_cve.py:pull_taxii` (HTTP Basic auth supported, single page in v1).
- **CVE ID extraction** via regex with case-normalization and dedup. `ramen_cve.py:extract_cves`.
- **Multi-IOC extraction** for IPv4, URL, domain, email, MD5, SHA-1, SHA-256 with defang-aware refanging (hxxp / `[.]` / `(at)` / etc.). `ramen_cve.py:extract_iocs` (+ `_defang_text`, `_DEFANG_MAP`, `_DEFANG_DETECT`).

### Enrichment
- **NVD CVSS enrichment** — CVSS v3.1/v3.0 base score + severity + vector + version, CWE list, NVD published date, `cisaExploitAdd` flag, **CPE 2.3 strings** (including nested `children` nodes). `ramen_cve.py:fetch_nvd`, `_parse_nvd_response`.
- **EPSS enrichment** with batched 100-CVE-per-call requests and historical-date support. `ramen_cve.py:fetch_epss`.
- **CISA KEV catalog ingestion** — authoritative due-date, required-action, ransomware-use, vendor/product, short-description. `ramen_cve.py:fetch_kev_catalog`, `_parse_kev_due_date`.
- **MITRE ATT&CK technique mapping** from CWE via a curated 36-entry table. `ramen_cve.py:CWE_TO_ATTACK`, `ATTACK_TECHNIQUE_NAMES`, `map_cwes_to_attack_techniques`.
- **Cyber Kill Chain phase derivation** from CWE (default `exploitation`; overrides for recon / install / delivery / actions-on-objectives). `ramen_cve.py:CWE_TO_KILL_CHAIN`, `map_cwes_to_kill_chain`.
- **Threat-actor / campaign / malware attribution** loaded from `associations.json` (12 seeded CVEs from MITRE Groups). `ramen_cve.py:load_associations`, `_build_actor`, `_build_campaign`, `_build_malware`.
- **Public-exploit-availability tracking** — Exploit-DB CSV mirror, Nuclei templates index, GitHub repo search (gated on `GITHUB_TOKEN`). `ramen_cve.py:fetch_exploitdb_cve_set`, `fetch_nuclei_cve_set`, `search_github_for_cve`, `enrich_with_exploit_status`.
- **Pluggable IOC enrichment registry** (VirusTotal, AbuseIPDB, OTX, MalwareBazaar) with per-source API keys + per-(enricher, ioc_type, value) cache. `ramen_cve.py:_EnricherBase`, `VirusTotalEnricher`, `AbuseIPDBEnricher`, `OtxEnricher`, `MalwareBazaarEnricher`, `enrich_iocs`, `_build_default_enrichers`.
- **Asset / inventory correlation** — pulls CPE from NVD; `--inventory` CSV (host,product,version OR host,cpe) joined to each CVE. `ramen_cve.py:load_inventory`, `_cpe_matches_inventory`, `correlate_inventory`.

### Analysis
- **Diamond Model quadrant population** — capability auto-derived from CWE+technique; adversary auto-derived from first linked actor; infrastructure / victim left for future feeds. `ramen_cve.py:EnrichedCve` (`diamond_*` fields).
- **TLP + Admiralty source confidence**, with `_worst_tlp` (most-restrictive wins) and `_best_admiralty` (highest-confidence wins) merged across duplicate-CVE sources. `ramen_cve.py:TLP_LEVELS`, `_normalize_tlp`, `_worst_tlp`, `_admiralty_score`, `_best_admiralty`.
- **Severity bucketing** — KEV override + CVSS×EPSS quadrant logic. `ramen_cve.py:bucket_and_suggest`, `BUCKET_ACTIONS`, `BUCKET_ORDER`.
- **Date-bounded filtering** across `feed` / `disclosure` / `epss` modes. `ramen_cve.py:filter_by_date`.
- **CVE deduplication with provenance merging** — earliest first_seen wins, worst-TLP propagates, best-Admiralty propagates. `ramen_cve.py:enrich_cves` (merge logic).
- **IOC deduplication** with the same provenance-merge semantics across feeds. `ramen_cve.py:_dedupe_iocs`.

### Detection Engineering
- **Sigma rule stub generation** — `--format sigma` writes one YAML per `kev_override` / `patch_now` CVE with deterministic UUID id, level mapping, ATT&CK / CISA-KEV / ransomware tags, and TODO `logsource` / `detection` blocks. `ramen_cve.py:_sigma_level_for`, `_build_sigma_stub`, `write_sigma_stubs`, `SIGMA_ELIGIBLE_BUCKETS`.

### Hunting Workflow
- **Hunt hypothesis library** — `hunts/` directory of one-JSON-per-hunt records (id / hypothesis / data_sources / attack_techniques / linked_cves / status / created / findings). `ramen_cve.py:Hunt` dataclass + `load_hunt`, `load_all_hunts`, `save_hunt`, `_hunt_path`.
- **`hunt` subcommand** with `list / show / link / log / status` actions and path-traversal protection. `ramen_cve.py:_run_hunt`, `HUNT_STATUSES`.

### Dissemination
- **CSV report** (CVE) with 26 columns. `ramen_cve.py:CSV_COLUMNS`, `write_csv`.
- **CSV report** (IOC) — separate file with 9 columns including JSON-encoded `enrichments`. `ramen_cve.py:IOC_CSV_COLUMNS`, `write_iocs_csv`.
- **Markdown triage report** — bucket sections, per-CVE Diamond / ATT&CK / Provenance / Affected-Hosts lines, IOC section grouped by type with per-source enrichment summaries, and three cross-tab roll-ups (By ATT&CK Technique, Linked Adversaries, Affected in Your Environment). `ramen_cve.py:write_markdown`, `IOC_TYPE_DISPLAY`, `IOC_TYPE_ORDER`, `_summarize_enrichment`.
- **STIX 2.1 bundle output** with deterministic UUIDs, Identity / Vulnerability / Note / Indicator SDOs and an NVD external_reference per CVE. `ramen_cve.py:write_stix`, `_stix_uuid`, `_ioc_to_stix_pattern`.
- **Slack webhook dispatcher** — Block-Kit summary with header / body / NVD context link. `ramen_cve.py:SlackWebhookDispatcher`.
- **Generic JSON webhook dispatcher** — POSTs every actionable EnrichedCve field. `ramen_cve.py:GenericWebhookDispatcher`, `dispatch_records`, `DISPATCH_DEFAULT_BUCKETS`.

### Operations / Plumbing
- **SQLite cache** with per-table TTL — `nvd_cache`, `epss_cache`, `kev_cache`, `exploit_cache`, `enrichment_cache`, plus a non-purged `runs` history table. `ramen_cve.py:Cache` (`_SCHEMA`, `_is_fresh`, all `get_*` / `set_*` / `record_run` / `purge`).
- **Historical trending** — `ramen_cve trend <CVE>` prints unicode sparklines (`_sparkline`) and a Markdown table of recorded runs. `ramen_cve.py:_run_trend`, `_record_runs`.
- **Interactive setup wizard** with quote-stripping path inputs. `ramen_cve.py:_run_wizard`, `_strip_path_quotes`, `_path_arg`, `_wizard_validate_date`, `_wizard_validate_float`.
- **NVD API key bootstrap** — in-line prompt, `.env` write with newline-injection rejection, expired-key re-prompt-and-retry. `ramen_cve.py:_prompt_for_api_key`, `_save_api_key_to_env`.
- **Defensive logging** — `_redact_key` strips `apiKey=...`; `_safe_url_for_log` strips query string + fragment.
- **Sample CI workflow** — `examples/github-actions-daily-triage.yml` for scheduled execution (out of scope for `.py` review but documented in trend rationale).
- **Test coverage**: 302 passing, 0 failing across pure-logic (regexes, mappers, defang, TLP math), I/O (cache schema, fixtures), HTTP-mock (NVD / EPSS / KEV / EDB / Nuclei / GitHub / VirusTotal / AbuseIPDB / OTX / MalwareBazaar / TAXII / Slack / webhook), CLI (every subcommand, every flag), wizard (every prompt branch), end-to-end smoke against `examples/sample.opml`. `tests/test_ramen_cve.py`, `tests/test_smoke.py`, `tests/test_wizard.py`, `tests/test_api_key_prompt.py`.

---

## Identified Capability Gaps

The gaps below assume the v1 list is closed. They are the next layer of features a mature program would expect.

### SSVC (Stakeholder-Specific Vulnerability Categorization) Decision Tree

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** CVSS×EPSS is a heuristic; SSVC (published by CISA / CMU SEI in 2021) is a formal decision tree that resolves a CVE into one of four actions — `track / track* / attend / act` — given an organization-specific set of decision points (exploitation status, automatable, technical impact, mission prevalence, public well-being impact). It's the framework CISA uses internally and increasingly the language regulated industries reference. The current bucket logic produces five outputs but isn't traceable to a published model that auditors / auditees recognize.
**Example Implementation Approach:** Add `ssvc_action: str` + `ssvc_decision_points: dict` fields to `EnrichedCve`. Implement a `compute_ssvc(rec, organizational_profile)` function that walks the published 2023 v2 decision tree using exploit_status, KEV listing, EPSS, CWE-derived technical impact, and an `--organization-profile` JSON file (mission-prevalence + public-well-being-impact). Surface the action in CSV / Markdown / Slack alongside the existing bucket. Don't replace bucketing — run them in parallel so consumers see both signals.

---

### Native SIEM Query Generation (KQL / SPL / Elastic EQL)

**Category:** Detection Engineering
**Maturity Tier:** Intermediate
**Why It Matters:** Sigma is the lingua franca but every SOC ultimately runs a native query language — Microsoft Sentinel / Defender (KQL), Splunk (SPL), Elastic (Lucene + EQL), CrowdStrike (CQL), Chronicle (UDM). A SOC analyst staring at a Sigma stub still has to convert it manually. Producing a parallel native query stub for the most common platforms saves the conversion step and dramatically lifts adoption rates.
**Example Implementation Approach:** Extend `--format` to accept `kql`, `spl`, `eql`. Reuse `_build_sigma_stub`'s skeleton — same per-CVE eligibility filter — and emit one platform-flavored template per CVE into a `ramen-cve-<ts>-<lang>/` directory. The `selection` block stays a TODO; the value-add is the pre-tagged title / level / CVE / ATT&CK / KEV references in each platform's idiom.

---

### MISP-Platform Native Integration

**Category:** Collection / Dissemination
**Maturity Tier:** Intermediate
**Why It Matters:** STIX 2.1 / TAXII covers the standardized exchange path, but MISP is the de-facto open-source CTI platform that thousands of SOCs run today. MISP has its own JSON event schema, Galaxy taxonomy (which extends MITRE ATT&CK with industry context), and PyMISP API. A direct MISP push / pull is a different integration from generic STIX — consumers want an event with the right MISP-specific tags and Galaxy clusters, not a raw STIX bundle they have to import-and-translate.
**Example Implementation Approach:** Add `pymisp` as an optional dependency (gated on a `--misp-url` flag so `pip install ramen-cve` stays minimal). New `misp` subcommand modeled on `stix`: `ramen_cve misp push --misp-url ... --misp-key ...` builds a MISP `MISPEvent` per CVE with attributes (`vulnerability`, `text`, `link`), tags (`tlp:`, `admiralty:`, `attack:Txxxx`), and Galaxy references (`misp-galaxy:threat-actor=` for each linked actor). `misp pull` reads events back and feeds them through the same enrichment pipeline.

---

### YARA Rule Generation for Linked Malware

**Category:** Detection Engineering
**Maturity Tier:** Intermediate
**Why It Matters:** Sigma covers log-based detection; YARA covers file / memory matching and is the workhorse for malware-family identification. For every CVE that has linked malware in `associations.json`, the tool already knows the malware family name — it could emit a YARA stub keyed on that family and let the analyst fill in the strings/condition. Currently that step is manual every time.
**Example Implementation Approach:** Add `--format yara` (or extend `--format all`) that, for each linked Malware in an EnrichedCve, writes a YARA rule stub `ramen-cve-<ts>-yara/<malware-name>.yar` with the rule name `Ramen_<MalwareName>`, metadata (CVE list, ATT&CK techniques, CISA-KEV flag, MITRE software ID if URL was provided), and TODO `strings:` + `condition:` blocks. Reuse `_stix_uuid` for the `id` metadata field.

---

### Indicator Confidence Decay / Aging

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** IOCs are not forever — a malicious IP today may be a CDN tomorrow; a hash that defines yesterday's campaign is unique-to-that-campaign forever. Mature platforms decay confidence on a curve (e.g., GreyNoise's "first seen / last seen" aging, MISP's `decaying-models`). The current pipeline records `first_seen` but never down-weights or expires an indicator, so a stale IOC stays in the report indefinitely.
**Example Implementation Approach:** Add `confidence: float` (0.0–1.0) and `last_seen: date` to `IocRecord`. Define one or two decay curves per indicator type (IPs decay fast — half-life ~30 days; SHA-256 hashes effectively don't decay; domains in between — half-life ~90 days). At each run, compute `confidence = exp(-ln(2) * age_days / half_life)`. Surface the confidence in CSV + MD + STIX; suppress IOCs below `--ioc-confidence-floor=0.10` from output.

---

### Bucket-Transition Delta Detection / Alerting

**Category:** Analysis / Dissemination
**Maturity Tier:** Intermediate
**Why It Matters:** The `runs` table already records every CVE's bucket per run. The high-value signal isn't the current bucket — it's the **transition** ("CVE-X moved from `watch_closely` to `kev_override` overnight"). That's exactly what an SOC needs to be paged on. Today, the dispatcher fires every run for every patch_now / kev_override record, which produces alert fatigue rather than triage signal.
**Example Implementation Approach:** Add a `compute_bucket_deltas(cache, enriched)` function that joins each EnrichedCve to its previous run's bucket via `Cache.get_runs` and yields `(cve_id, old_bucket, new_bucket)` for upgrades only (downgrades are noise). Add a `--dispatch-on-delta-only` flag that gates `dispatch_records` on the delta result. Slack / webhook payloads should include the transition (`"⬆️ CVE-X-Y promoted: watch_closely → kev_override"`), not just the snapshot.

---

### PIR (Priority Intelligence Requirements) Tracking

**Category:** Hunting Workflow / Analysis
**Maturity Tier:** Advanced
**Why It Matters:** PIRs are the foundation of programmatic CTI direction — they are the leadership-blessed questions the program exists to answer ("Who is targeting our financial-services customers?", "Are any of our crown-jewel applications mentioned in adversary chatter?"). Modern programs explicitly tag every collected indicator and every generated report with the PIR(s) it satisfies, then report PIR coverage to leadership. Without PIRs, the tool is reactive only.
**Example Implementation Approach:** Mirror the `hunts/` directory pattern — add a `pirs/` directory with one JSON per PIR (id, name, question, owner, status, tagged_cves, tagged_iocs, tagged_actors). Add `pir` subcommand with `list / show / link / coverage` actions. The `coverage` action prints a tabular report: for each PIR, count of linked CVEs / IOCs / actors and what fraction of recent runs touched it.

---

### Audit Logging

**Category:** Operations
**Maturity Tier:** Intermediate
**Why It Matters:** Every action in a CTI program is, in principle, auditable: who ran what triage when, who linked which CVE to which hunt, who pushed a finding to which Slack channel. Today the tool emits operational logs to stderr but doesn't persist them, and there's no accountability trail. For regulated industries (SOX / PCI / FedRAMP) this is table-stakes; for any team with more than one analyst it's a daylight-saving issue.
**Example Implementation Approach:** Add an `audit_log` table to the SQLite cache: `(timestamp, actor, command, args_redacted, outcome)`. Wrap every subcommand entry in a context-manager that records start + end. `actor` defaults to `getpass.getuser()`. Add a `ramen_cve audit` subcommand that prints a paginated, filterable log. Treat the log as append-only — no UPDATE / DELETE on the table. Document that the cache file is now sensitive (it was already, since it caches API responses).

---

### Risk-Weighted Prioritization (Asset Criticality + Business Context)

**Category:** Analysis
**Maturity Tier:** Advanced
**Why It Matters:** Inventory correlation today says "this CVE affects host `web-1`" — but `web-1` could be a public-facing payments host (page everyone) or a developer's spare laptop (file a low-priority ticket). Mature VM programs consume an asset criticality tier alongside the host list and weight every prioritization decision by it. This is the single biggest remaining blind spot in the prioritization pipeline.
**Example Implementation Approach:** Extend `--inventory` CSV to accept an optional `criticality` column with values `tier1` / `tier2` / `tier3` (or numeric 1–5). Compute a per-CVE `risk_score = max_inventory_criticality(cve) × cvss_weight × (1 + 2*epss_score) × (10 if kev_listed else 1)`. Surface `risk_score` and the tier of the most-critical affected host in CSV / Markdown / Slack. Re-rank CVEs in each bucket by risk_score in the Markdown report.

---

### Vulnerability-Scanner Integration (Nessus / Rapid7 / Qualys / OpenVAS Imports)

**Category:** Collection
**Maturity Tier:** Intermediate
**Why It Matters:** The CSV `--inventory` is a useful scaffold but real organizations already have richer asset+vulnerability data in their VM scanner. A direct import from Nessus `.nessus` XML or Qualys `findings.csv` would replace dozens of fields (host name, OS, CPE, scan timestamp, severity per scanner) without manual prep. It also closes the loop: the same vulnerabilities the scanner found and the CTI tool prioritized would be visible side-by-side.
**Example Implementation Approach:** Add `import` subcommand with format flags: `ramen_cve import nessus <file>` parses the Nessus XML format (lxml or stdlib `xml.etree`) into the existing inventory shape. Each plugin's CVE list joins to ramen-cve's CSV / Markdown output. Same pattern for Qualys CSV (`ramen_cve import qualys <file>`). The output keeps every scanner-reported field as an extra column (passed through, not interpreted).

---

### Hunt Analytics Library (Reusable Detection Queries Per Technique)

**Category:** Hunting Workflow / Detection Engineering
**Maturity Tier:** Intermediate
**Why It Matters:** The current Hunt dataclass tracks a hypothesis and findings — but the *query* the analyst runs against their SIEM during the hunt is left implicit. PEAK-style hunts come with a reusable analytic library: per-ATT&CK-technique queries that any analyst can drop into their data lake to test the hypothesis. Today every hunt re-derives its queries from scratch.
**Example Implementation Approach:** Add an `analytics/` directory of one-JSON-per-analytic records (id, name, attack_techniques, data_sources, queries: {kql, spl, eql, sigma}, false_positives, references). New `analytic list / show / suggest` subcommand; `analytic suggest <hunt-id>` prints the analytics whose `attack_techniques` overlap the hunt's. Seed with five analytics covering T1059 / T1190 / T1078 / T1110 / T1566 to demonstrate the convention.

---

### Email / Daily-Digest Dispatcher

**Category:** Dissemination
**Maturity Tier:** Foundation
**Why It Matters:** Slack and generic webhooks fire per-finding — that's the right shape for "page someone now" but the wrong shape for "give the asset owner their morning patch list." Mature programs ship a daily digest: one email per asset owner / product line summarizing what's new in their bucket, with the actionable items at the top. Email is also the only dispatch channel that survives the analyst's vacation.
**Example Implementation Approach:** Add `EmailDispatcher` next to `SlackWebhookDispatcher` / `GenericWebhookDispatcher`. Configure via `RAMEN_SMTP_HOST` / `RAMEN_SMTP_PORT` / `RAMEN_SMTP_USER` / `RAMEN_SMTP_PASS` / `RAMEN_SMTP_FROM` env vars. Add a `--digest` mode (separate from `--dispatch`) that batches the day's KEV+patch_now records into one Markdown-rendered email per recipient (recipients keyed by inventory `owner` column — see Risk-Weighted Prioritization above for the inventory schema growth). Use stdlib `email.mime` so no new dependency.

---

### Backtesting / Replay Mode

**Category:** Operations / Analysis
**Maturity Tier:** Advanced
**Why It Matters:** Every change to bucket logic, threshold, or association lookup raises the question "would this have changed yesterday's report?" Without a replay mode the only way to answer it is to actually wait for tomorrow's run. Backtesting is the only honest way to evaluate a prioritization change before shipping it.
**Example Implementation Approach:** Add a `replay` subcommand: `ramen_cve replay --as-of YYYY-MM-DD` reads from cache only (no network), reconstructs the EnrichedCve set from cached NVD / EPSS / KEV snapshots at that date, and re-runs `bucket_and_suggest` + the rest of the pipeline. Compare the produced bucket assignment to what was historically recorded in the `runs` table for that day. Print a diff table (CVEs that would now be in a different bucket, with old vs new). Cache rows would need a soft-versioning column (`as_of_date`) for this to work cleanly — biggest implementation cost.

---

### Sector / Geopolitical Threat Context

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** A CVE actively exploited against the financial sector is a different priority for a financial-sector defender than a CVE actively exploited against energy. Today the report is sector-agnostic. ENISA, the FBI, and CISA publish sector-specific advisories; threat actors have known sector preferences (FIN groups → financial; APT41 → broad espionage; Sandworm → energy + government). Tagging CVEs and actors with sector context lets a defender filter to "what matters for **us**".
**Example Implementation Approach:** Extend `associations.json` actor entries with a `sectors_targeted: list[str]` field (drawn from ENISA / MITRE Groups). Add a `--sector financial` CLI flag that filters output to CVEs linked to actors targeting the named sector, OR that aren't sector-attributed at all. Surface the sector list in the Markdown adversary cross-tab.

---

### Refactor `ramen_cve.py` Into a Package

**Category:** Operations
**Maturity Tier:** Foundation (deferred-from-v1, now urgent)
**Why It Matters:** The project's own `CLAUDE.md` says "If the file passes 500 lines, that's the signal to refactor into a small package — not before." The file is now **4,120 lines**, more than 8× that threshold. Every new feature now requires a longer scroll, and every test imports the same monolith. The maintenance velocity will hit a wall before the next quarter of features lands. This isn't a CTI capability gap per se — it's an enabler for *every* gap above.
**Example Implementation Approach:** Split into a small package: `ramen_cve/__init__.py` (re-exports), `models.py` (dataclasses), `cache.py`, `extract.py` (regexes + extract_cves + extract_iocs + defang), `enrich/` package (one module per source: nvd, epss, kev, exploits, virustotal, abuseipdb, otx, malwarebazaar), `analyze.py` (bucket, kill-chain, attack mapping, diamond, TLP), `output/` package (csv, markdown, stix, sigma), `dispatch/` package (slack, webhook), `cli.py` (argparse + main + runners), `wizard.py`, `hunt.py`, `trend.py`. Keep the entry point `ramen_cve.py` as a 5-line shim that calls `from ramen_cve.cli import main; main()`. Tests should import from the new module paths; the public API stays compatible because the re-exports in `__init__.py` cover every name the tests touch today.

---

## Prioritized Recommendations

The five gaps below are ranked by **impact-to-effort ratio**, given the project's "ramen budget" constraint and current state.

1. **Bucket-Transition Delta Detection / Alerting** — Highest ratio. The infrastructure (`runs` table + dispatcher pipeline) is already shipped; this is one ~50-line function plus a flag and dramatically reduces alert fatigue, which is the single biggest reason mature SOCs ignore this tool's outputs.
2. **SSVC Decision Tree** — Modest implementation cost (a decision tree + one config file) but produces a CISA-recognized output that auditors / regulators actively look for. Runs in parallel with the existing bucketing so it's purely additive.
3. **Risk-Weighted Prioritization (Asset Criticality)** — One new optional inventory column + one weighted score function transforms the inventory feature from "informational" to "operational." High lift for low effort because the inventory plumbing is already there.
4. **Refactor into a Package** — Not a feature, but the prerequisite that unlocks every subsequent feature without further increasing the maintenance cost curve. Deferring it again will compound the cost of every future change.
5. **Native SIEM Query Generation (KQL / SPL)** — Higher implementation cost than the four above (one template per language, careful escaping), but it's the change that finally takes the detection-engineering output from "useful scaffold" to "deployable in production." Sigma is great in principle; native is what actually gets pushed.

---

*Analysis scope: `.py` files only. Shell scripts, CI workflows, config files, JSON data files, sample artifacts, and documentation were intentionally excluded per the task constraints. The v1 gap analysis (`cti-capability-gap-analysis.md`) is preserved verbatim alongside this v2 report for diff purposes.*
