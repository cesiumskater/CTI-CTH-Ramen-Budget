# CTI / Threat Hunting Capability Gap Analysis

**Repository:** `cesiumskater/cti-cth-ramen-budget`
**Analysis date:** 2026-05-05
**Scope:** All `.py` files in the repository — at the time of this analysis, the implementation lived in a single `ramen_cve.py` plus `tests/*.py`.

> **Status (as of 2026-05-20):** this analysis predates the package
> refactor (2026-05-18 → 2026-05-20). The implementation now lives in
> a ~30-module package under `src/ramen_cve/` behind a re-export
> façade (see `docs/REFACTOR_PLAN.md`); file/line references like
> `ramen_cve.py:NNNN` are preserved as pre-refactor traceability.
> The capability inventory below remains accurate (zero behaviour
> change). The companion second-pass audit is
> `cti-capability-gap-analysis-v2.md`.

---

## Executive Summary

`ramen-cve` is a single-purpose CVE triage utility — its job is to extract CVE identifiers from RSS feeds, URLs, or hand-supplied lists; enrich them with NVD CVSS data, EPSS exploitation probability, and the CISA KEV flag; and emit a prioritized "patch now / plan / watch / deprioritize" decision in CSV and Markdown. It implements that narrow vulnerability-prioritization slice cleanly (≈1,400 lines, well-tested, defensive about secrets and rate limits) but does not attempt the broader work of a Cyber Threat Intelligence or Threat Hunting program. Against the standard CTI/CTH reference set (MITRE ATT&CK, the Diamond Model, the Cyber Kill Chain, STIX/TAXII, CISA KEV catalog, SANS/F3EAD, PEAK), the maturity level is best described as **Foundation — Vulnerability Triage Only**: there is no IOC handling beyond CVE IDs, no adversary or campaign modeling, no detection-rule output, no hunt workflow primitives, no dissemination integrations, and no STIX/TAXII interoperability. The gaps below are not flaws in v1; they are the natural directions the project would have to grow if the goal expanded from "patch-priority bucketing" toward an end-to-end intelligence pipeline.

---

## Current Capability Inventory

The features below are present today in `.py` files. Filenames and function names are referenced so each item can be located directly.

- **CVE ID extraction from arbitrary text** — regex-based, deduplicating, case-normalizing. `ramen_cve.py:extract_cves`
- **OPML feed list ingestion** — recursive walk of `<outline>` elements, capturing per-feed category. `ramen_cve.py:parse_opml`
- **Single-URL ingestion** with HTML publication-date sniffing. `ramen_cve.py:_run_url`
- **Manual / file-based CVE list ingestion**. `ramen_cve.py:_run_cve`
- **NVD CVSS enrichment** — CVSS v3.1/v3.0 base score, severity, vector, version; CWE list; NVD published date; CISA `cisaExploitAdd` flag. `ramen_cve.py:fetch_nvd`, `_parse_nvd_response`
- **EPSS enrichment** — current and historical batch lookup (up to 100 CVEs/call). `ramen_cve.py:fetch_epss`
- **SQLite-backed local cache** with TTL and corrupt-row tolerance. `ramen_cve.py:Cache`
- **Severity bucketing** — KEV override, then a CVSS×EPSS quadrant (`patch_now`, `plan_and_patch`, `watch_closely`, `deprioritize`, `unknown`). `ramen_cve.py:bucket_and_suggest`
- **Date-bounded filtering** across `feed` / `disclosure` / `epss` modes. `ramen_cve.py:filter_by_date`
- **CSV and Markdown report generation**, with a per-bucket summary table. `ramen_cve.py:write_csv`, `write_markdown`
- **NVD API key bootstrap** with in-line prompt for missing/expired keys and safe `.env` writes. `ramen_cve.py:_prompt_for_api_key`, `_save_api_key_to_env`
- **Defensive logging** that strips API keys, query strings, and fragments before any URL hits the log. `ramen_cve.py:_redact_key`, `_safe_url_for_log`
- **Interactive setup wizard** for first-time users. `ramen_cve.py:_run_wizard`
- **Test coverage** for OPML parsing, regex, cache TTL/corruption, NVD/EPSS fetch behavior, bucketing precedence, date filtering, CSV/MD writers, CLI/argparse, the wizard, and the API-key prompt flow. `tests/test_ramen_cve.py`, `tests/test_smoke.py`, `tests/test_wizard.py`, `tests/test_api_key_prompt.py`

---

## Identified Capability Gaps

### Multi-IOC Type Support (Beyond CVE IDs)

**Category:** Collection / Analysis
**Maturity Tier:** Foundation
**Why It Matters:** A CTI program tracks far more than CVEs. The standard indicator types are IP addresses, domains/FQDNs, URLs, file hashes (MD5 / SHA-1 / SHA-256), email senders, mutex names, registry keys, JA3/JA4 TLS fingerprints, and YARA-rule names. Restricting collection to CVE IDs means an adversary's command-and-control domain mentioned in the same feed item is silently discarded — even though it is the more actionable indicator for blocking and hunting.
**Example Implementation Approach:** Add a sibling extractor module to the existing `extract_cves` function that runs the same feed/URL text through a small set of additional regexes (RFC-5321 emails, RFC-3986 URLs, IPv4/IPv6, hex-hash patterns) plus a defang-aware step (`hxxp` → `http`, `[.]` → `.`, `(at)` → `@`). Persist each indicator as a new dataclass alongside `CveRecord` and let the existing pipeline carry it through to enrichment, bucketing, and output.

---

### STIX 2.1 / TAXII 2.x Interoperability

**Category:** Collection / Dissemination
**Maturity Tier:** Foundation
**Why It Matters:** STIX 2.1 is the de facto serialization for structured CTI; TAXII 2.x is the matching transport. Mature CTI tooling can both **consume** STIX bundles from TAXII feeds (CISA AIS, MITRE CTI repo, Mandiant, MISP exports) and **emit** STIX so that downstream SIEMs, SOARs, and threat-intelligence platforms can ingest the output. This project today reads only OPML/RSS and HTML, and emits only CSV/Markdown — it cannot exchange data with any other CTI tool in either direction.
**Example Implementation Approach:** Add a `stix2` runtime dependency (well-maintained, BSD-licensed). On the input side, write a `parse_stix_bundle(path)` and a `pull_taxii(server, collection)` adapter that yield `CveRecord` objects (plus the multi-IOC objects from the gap above). On the output side, add `write_stix(enriched, path)` that maps each `EnrichedCve` to a `Vulnerability` SDO with `external_references` to NVD/EPSS and a `Note` SDO carrying the bucket and suggested action.

---

### MITRE ATT&CK Technique Mapping

**Category:** Analysis / Detection Engineering
**Maturity Tier:** Foundation
**Why It Matters:** ATT&CK is the lingua franca for describing what an adversary actually *does* — Initial Access via T1190 Exploit Public-Facing Application, Execution via T1059 Command and Scripting Interpreter, etc. CVSS tells you how bad a vulnerability is in the abstract; ATT&CK technique tags tell you which detection coverage in your SOC is relevant. Mapping each enriched CVE to one or more ATT&CK techniques unlocks coverage-gap analysis ("we have 12 patch-now CVEs that all enable T1190; how is our T1190 detection?") and is a routine ask of any CTI consumer.
**Example Implementation Approach:** Pull the MITRE CTI ATT&CK STIX bundle (open data, Apache-2.0) into a small lookup table keyed on CWE → likely techniques, plus a manual override table for known mappings (e.g., CWE-502 deserialization → T1059, T1190). Add `attack_techniques: list[str]` to `EnrichedCve`, populate it in `enrich_cves`, and surface it in both CSV and Markdown output. The Markdown summary can grow a "By ATT&CK Technique" cross-tab.

---

### Authoritative CISA KEV Catalog Ingestion

**Category:** Collection / Analysis
**Maturity Tier:** Foundation
**Why It Matters:** Today the tool relies on NVD's `cisaExploitAdd` field as a proxy for KEV membership. NVD does carry that field, but it does not carry the **due date** (`dueDate`), the **required action**, the **vendor/product** narrative, or the **ransomware use** flag — all of which CISA publishes directly in its KEV JSON and which Federal Civilian Executive Branch agencies (and most regulated industries) have to track. A CTI program that drives patching decisions should consume the authoritative catalog and surface the due date, not just the boolean.
**Example Implementation Approach:** Fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` once per run (cache for 24h alongside NVD/EPSS), build an in-memory `dict[cve_id, kev_record]`, and join it to each `EnrichedCve`. Extend the `kev_override` bucket to display the CISA due date and short description, and raise a louder warning when a CVE's due date is past or imminent.

---

### Threat Actor and Campaign Modeling

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** Useful CTI answers questions like "is this CVE being used by APT29?" or "is this part of the *Volt Typhoon* campaign?" That requires first-class concepts for threat actors, malware families, and campaigns, plus the ability to associate indicators (CVEs, IOCs, TTPs) with them. Without these, every report is a flat list of vulnerabilities with no narrative — hard to brief to leadership, hard to tie to risk decisions.
**Example Implementation Approach:** Introduce three new dataclasses (`ThreatActor`, `Campaign`, `Malware`) and a separate `associations.json` lookup file that maps CVE → actor/campaign/malware (seeded from the MITRE Groups dataset, which is open). At enrichment time, attach matching associations to each `EnrichedCve`. Add a "Linked Adversaries" section per bucket in the Markdown report.

---

### Detection Rule Generation (Sigma / YARA)

**Category:** Detection Engineering
**Maturity Tier:** Intermediate
**Why It Matters:** A standard CTI deliverable is a detection artifact — typically a Sigma rule for log-based detection or a YARA rule for file/memory matching — that an SOC can deploy immediately. Today this tool produces a CSV and a human-readable report; it does not produce anything a SOAR or SIEM can ingest as a rule.
**Example Implementation Approach:** Add a third output format alongside CSV/MD: a `--format sigma` flag that writes one Sigma YAML stub per `patch_now`/`kev_override` CVE, populated with the CVE ID, CVSS score, ATT&CK technique tags (from the gap above), and a `TODO` placeholder for the actual log-source-specific selection block. The point is not to auto-write a perfect detection — it is to give the detection engineer a pre-tagged, pre-prioritized stub to start from.

---

### Multi-Source Enrichment (VirusTotal, OTX, AbuseIPDB, MalwareBazaar)

**Category:** Collection / Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** NVD + EPSS tells you about the vulnerability; it does not tell you whether **this specific** indicator is currently being seen in the wild. A CTI program normally enriches each indicator across multiple commercial and community sources to triangulate confidence: VirusTotal for hashes/URLs/domains, AlienVault OTX for community pulse hits, AbuseIPDB for IP reputation, MalwareBazaar for sample availability, GreyNoise for internet-scan vs targeted-attack distinction.
**Example Implementation Approach:** Once multi-IOC support is in place (above), add a pluggable `enrichers/` registry where each enricher exposes `supports(ioc_type) → bool` and `enrich(ioc, cache) → dict`. Ship one enricher per source, each gated on its own optional API key (using the same `.env` bootstrap pattern as `NVD_API_KEY`). Cache responses in new SQLite tables keyed on `(source, ioc_value)`.

---

### Source Confidence and TLP Tagging (Admiralty Code)

**Category:** Analysis / Dissemination
**Maturity Tier:** Intermediate
**Why It Matters:** Not every source is equally trustworthy and not every report is equally distributable. The NATO Admiralty Code rates sources A-F (reliability) and 1-6 (information credibility); TLP (Traffic Light Protocol) governs sharing — RED, AMBER, AMBER+STRICT, GREEN, CLEAR. Without these, downstream consumers can't decide whether to act on a finding or how widely to share it. Today every CVE in the report is presented as if it has identical provenance and identical sharing rules.
**Example Implementation Approach:** Add an `OPML extension` convention — e.g., an `xmlUrl`-sibling attribute `data-admiralty="B2"` and `data-tlp="green"` — that the OPML parser reads and stamps onto every `FeedEntry`, then onto every CVE pulled from that feed. Surface the worst (most-restrictive) TLP across all sources for a given CVE in both CSV and Markdown. Optionally, refuse to write a TLP:RED finding to a path that isn't explicitly opt-in.

---

### Exploit / PoC Availability Tracking

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** EPSS estimates exploitation *probability*; it does not tell you whether weaponized exploit code is publicly available right now. A working PoC on GitHub or a Metasploit module changes the urgency of patching considerably even at the same EPSS score. Mature CTI tooling tracks PoC presence in Exploit-DB, Metasploit modules, the Nuclei templates repo, and trending GitHub repos that match the CVE ID.
**Example Implementation Approach:** Add an `exploit_status` field to `EnrichedCve` plus a small set of zero-cost lookups: GitHub Search API for `CVE-YYYY-NNNNN` in repo names/descriptions (gated on a `GITHUB_TOKEN`), the Exploit-DB CSV mirror (downloadable, refreshed weekly), and the `nuclei-templates` repo file listing. Populate `exploit_status` with one of `none`, `metasploit`, `github_poc`, `nuclei_template`, `exploit_db`. Promote any CVE with confirmed exploit code one bucket up the urgency ladder.

---

### Threat Hunting Hypothesis Workflow

**Category:** Hunting Workflow
**Maturity Tier:** Advanced
**Why It Matters:** Threat hunting (PEAK, F3EAD, hypothesis-driven hunting) is a workflow, not a list — analysts file a hypothesis, gather supporting data, run hunts, record findings, and either confirm a true positive or feed the hunt back into detection engineering. This repository has no concept of a hunt: there is no hypothesis store, no hunt log, no link between a CVE and a hypothesis, no place to record "we hunted for exploitation evidence and found none." For a "Threat Hunting" tool the absence of any hunt primitives is the largest single gap.
**Example Implementation Approach:** Introduce a `hunts/` directory of YAML files, each describing one hypothesis (`name`, `hypothesis`, `data_sources`, `attack_techniques`, `linked_cves`, `status`, `findings`). Add a `ramen_cve hunt` subcommand that lists hunts, links a CVE to one (`hunt link <hunt-id> <cve-id>`), and records outcomes (`hunt log <hunt-id> --finding "..."`). Render an `examples/sample-hunt.yaml` so the convention is discoverable.

---

### Asset / Vulnerability Exposure Correlation

**Category:** Analysis
**Maturity Tier:** Advanced
**Why It Matters:** A "Patch Now" recommendation is only actionable if you know **what you have** and **whether the affected product runs in your environment**. Mature CTI/VM programs correlate CVE → CPE (Common Platform Enumeration) → asset inventory, so the report can say "Patch CVE-2024-1234 — affects 47 of your hosts running Apache 2.4.x." Today every CVE is treated as equally relevant to the user, even if it targets a product they do not run.
**Example Implementation Approach:** Read the CPE (`cpeMatch`) entries already returned by NVD (the data is in the v2 API response, currently discarded by `_parse_nvd_response`) into a list on `EnrichedCve`. Accept an optional `--inventory inventory.csv` flag whose CSV columns are `host,product,version` (or, if available, full CPE strings). Compute the intersection and emit a "Hosts Affected" column in CSV and a "Likely affected in your environment" subsection in Markdown. Records with no inventory match are still reported but visually deprioritized.

---

### Dissemination Integrations (SIEM / SOAR / Ticketing / Chat / Email)

**Category:** Dissemination
**Maturity Tier:** Intermediate
**Why It Matters:** A CTI report that ends as a CSV on disk is a report only if a human reads it. Mature programs push high-priority findings into the systems people already watch — Jira/ServiceNow tickets for KEV-listed CVEs, Slack/Teams messages for Patch-Now bucket changes, SIEM enrichment lookups for SOC analysts, email digests for asset owners. Without these the tool's findings are gated on someone remembering to run it and read the output.
**Example Implementation Approach:** Add a small `dispatchers/` registry following the same pattern proposed for enrichers. Each dispatcher subscribes to a bucket transition (`enters kev_override`, `enters patch_now`, etc.) and posts to a configured target. Ship two minimal dispatchers (Slack-via-webhook, generic-HTTP-webhook) and document the contract clearly enough that users can write their own without changing core code. Gate everything on an explicit `--dispatch` flag so default behavior remains "write files, do not phone home."

---

### Diamond Model / Cyber Kill Chain Mapping

**Category:** Analysis
**Maturity Tier:** Intermediate
**Why It Matters:** Two of the three classic CTI analytical frameworks — the Diamond Model (adversary, capability, infrastructure, victim) and the Lockheed Martin Cyber Kill Chain (recon, weaponization, delivery, exploitation, installation, C2, actions on objectives) — are how analysts structure the *story* of an incident or a campaign. The CVSS+EPSS quadrant in this tool sits roughly at the "Exploitation" stage of the Kill Chain but does not say so, and provides no place to record the other six. The result is that a CTI consumer cannot use this output to build a kill-chain or Diamond writeup without manual enrichment.
**Example Implementation Approach:** Add an optional `kill_chain_phase` and `diamond_capability` field to `EnrichedCve`, defaulting to `"exploitation"` and `"capability"` respectively (which is what every enriched CVE record describes by definition). Once threat-actor associations exist (gap above), the corresponding `diamond_adversary` and `diamond_infrastructure` fields can also be filled in. The Markdown report grows a one-line Diamond Model header per kev/patch-now CVE.

---

### Historical Trending and Scheduled Runs

**Category:** Analysis / Operations
**Maturity Tier:** Intermediate
**Why It Matters:** A point-in-time triage is half a picture. A CTI program watches the **trajectory** of EPSS over a window ("this CVE jumped from 0.05 to 0.78 in two weeks — exploitation is ramping"), tracks the rate of new feed mentions as a leading indicator, and runs the whole pipeline on a cadence so the dashboard reflects today's threat picture, not last month's. The current `--date-mode epss` mode supports a single historical day; there is no notion of a window, a delta, or a scheduled re-run.
**Example Implementation Approach:** Add a `runs` table to the existing SQLite cache that stores each enriched CVE's bucket and EPSS score per run timestamp. Introduce a `ramen_cve trend <CVE>` subcommand that plots (in Markdown — sparkline characters or a small ASCII chart) the score trajectory across stored runs. Document a sample cron / GitHub Actions invocation in the README so users have a discoverable path to scheduled execution.

---

## Prioritized Recommendations

The five gaps below are ranked by **impact-to-effort ratio** — how much CTI/CTH value the change unlocks per unit of implementation work, given this project's "ramen budget" constraint of staying small and readable.

1. **Authoritative CISA KEV Catalog Ingestion** — Highest ratio. One additional HTTP fetch and one join produces the missing due-date and ransomware-use signal that every regulated patching program needs, while reusing the existing cache and bucket plumbing.
2. **Multi-IOC Type Support** — Doubles or triples the actionable output of every single feed read for an additional ~50 lines of regex and one new dataclass; unblocks half the other gaps in this list (enrichment, dispatch, STIX) which all need indicators richer than CVE IDs.
3. **MITRE ATT&CK Technique Mapping** — Modest implementation cost (a static mapping plus a new field) but transforms the report from a vulnerability list into a coverage-driving artifact that detection engineering and threat-hunting teams can consume directly.
4. **Authoritative Exploit / PoC Availability Tracking** — Cheap to add (GitHub search + Exploit-DB CSV are both free) and meaningfully changes the bucket assignment for the small but important set of CVEs where weaponized code lands before the EPSS model catches up.
5. **STIX 2.1 / TAXII 2.x Output** — Higher implementation cost than the four above, but it is the single change that takes this tool out of "personal CSV pipeline" and into "node in a real CTI ecosystem" — once the output is STIX, every downstream platform (MISP, OpenCTI, ThreatConnect, OpenSearch Security Analytics) can consume it without a custom adapter.

---

*Analysis scope: `.py` files only. Shell scripts, configuration files, examples, and documentation were intentionally excluded per the task constraints.*
