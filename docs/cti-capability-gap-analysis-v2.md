# CTI / Threat-Hunting Capability Roadmap

> **Scope.** Forward-looking analysis of what `ramen-cve` would need to
> grow into to reach a fully-instrumented enterprise CTI program. The
> live shipped feature set is described in
> [`README.md`](../README.md) — refer there for *what the tool does
> today*; this document is the *what's next*.
>
> The v1 single-file gap analysis (2026-05-05) and the v2 monolith-era
> audit (2026-05-06) have been distilled into the prioritized backlog
> below. Items that were on those lists and have since shipped (CISA
> KEV catalog, multi-IOC extraction, MITRE ATT&CK mapping, STIX/TAXII
> I/O, threat-actor modeling, Sigma rule generation, multi-source IOC
> enrichment, TLP+Admiralty tagging, threat-hunt workflow, asset/
> inventory correlation, Slack/webhook dispatchers, Diamond Model +
> Kill Chain, historical trending, EPSS trajectory mode, depth-1 URL
> crawl, daemon mode, configurable bucket policy, static-HTML Web UI,
> bucket-transition delta alerting) have been removed.

---

## Maturity snapshot

`ramen-cve` sits at **intermediate broad-coverage CTI/CTH tooling**.
It produces analyst-actionable artefacts in formats every downstream
platform (MISP, OpenCTI, SIEMs, ticketing) can consume, with
provenance (TLP / Admiralty), framework framing (ATT&CK / Kill Chain /
Diamond), and detection scaffolds. The remaining gaps are the
second-stage features that distinguish a working CTI tool from a
fully-instrumented program.

---

## Prioritized backlog

Ranked by **impact-to-effort ratio**, given the project's ramen-budget
constraint of staying small and readable.

### 1. SSVC (Stakeholder-Specific Vulnerability Categorization)

**Category:** Analysis. **Maturity tier:** Intermediate.

CVSS × EPSS is a heuristic; SSVC (CISA / CMU SEI, 2021) is a formal
decision tree that resolves a CVE into one of four actions —
`track / track* / attend / act` — given an org-specific set of
decision points. It's the framework CISA uses internally and
increasingly the language regulated industries reference.

*Approach:* Add `ssvc_action: str` + `ssvc_decision_points: dict` to
`EnrichedCve`. Implement `compute_ssvc(rec, organizational_profile)`
walking the 2023 v2 decision tree using exploit_status, KEV listing,
EPSS, CWE-derived technical impact, and an `--organization-profile`
JSON file. Surface alongside the existing bucket — don't replace.

### 2. Risk-weighted prioritization (asset criticality)

**Category:** Analysis. **Maturity tier:** Advanced.

Inventory correlation today says "this CVE affects host `web-1`" — but
`web-1` could be a public-facing payments host or a developer's spare
laptop. Mature VM programs weight every prioritization decision by
asset criticality.

*Approach:* Extend `--inventory` CSV to accept an optional
`criticality` column (`tier1` / `tier2` / `tier3`). Compute
`risk_score = max_inventory_criticality(cve) × cvss_weight ×
(1 + 2×epss_score) × (10 if kev_listed else 1)`. Surface
`risk_score` + the most-critical affected tier in CSV / Markdown /
Slack. Re-rank CVEs in each bucket by `risk_score` in the Markdown.

### 3. Native SIEM query generation (KQL / SPL / Elastic EQL)

**Category:** Detection Engineering. **Maturity tier:** Intermediate.

Sigma is the lingua franca, but every SOC ultimately runs a native
query language. Producing parallel native stubs saves the conversion
step and dramatically lifts adoption rates.

*Approach:* Extend `--format` to accept `kql`, `spl`, `eql`. Reuse
`_build_sigma_stub`'s skeleton — same per-CVE eligibility filter —
and emit one platform-flavoured template per CVE into a
`ramen-cve-<ts>-<lang>/` directory. The `selection` block stays a
TODO; the value-add is the pre-tagged title / level / CVE / ATT&CK /
KEV references in each platform's idiom.

### 4. MISP-platform native integration

**Category:** Collection / Dissemination. **Maturity tier:** Intermediate.

STIX 2.1 / TAXII covers the standardized exchange path, but MISP is
the de-facto open-source CTI platform thousands of SOCs run today.
A direct MISP push / pull is a different integration from generic
STIX — consumers want an event with the right MISP-specific tags and
Galaxy clusters.

*Approach:* `pymisp` as an *optional* dependency (gated on
`--misp-url`). New `misp` subcommand modeled on `stix`:
`misp push --misp-url … --misp-key …` builds a `MISPEvent` per CVE
with attributes / tags / Galaxy references. `misp pull` reads events
back through the enrichment pipeline.

### 5. Vulnerability-scanner imports (Nessus / Qualys / Rapid7 / OpenVAS)

**Category:** Collection. **Maturity tier:** Intermediate.

The CSV `--inventory` is a useful scaffold but real organizations
already have richer asset + vulnerability data in their VM scanner.
A direct import replaces dozens of fields without manual prep.

*Approach:* `import` subcommand with format flags:
`ramen-cve import nessus <file>` parses Nessus XML into the existing
inventory shape; same for Qualys CSV. Each plugin's CVE list joins to
ramen-cve's CSV / Markdown output. Scanner-reported fields pass
through as extra columns.

### 6. Hunt analytics library (reusable per-technique queries)

**Category:** Hunting Workflow / Detection Engineering. **Maturity tier:** Intermediate.

The current `Hunt` dataclass tracks a hypothesis and findings, but
the *query* the analyst runs against their SIEM is left implicit.
PEAK-style hunts come with a reusable analytic library.

*Approach:* `analytics/` directory of one-JSON-per-analytic records
(id, name, attack_techniques, data_sources, queries: {kql, spl, eql,
sigma}, false_positives, references). New `analytic list / show /
suggest` subcommand; `analytic suggest <hunt-id>` prints the
analytics whose `attack_techniques` overlap the hunt's. Seed with
five analytics covering T1059 / T1190 / T1078 / T1110 / T1566.

### 7. Backtesting / replay mode

**Category:** Operations / Analysis. **Maturity tier:** Advanced.

Every change to bucket logic, threshold, or association lookup
raises the question "would this have changed yesterday's report?"
Backtesting is the only honest way to evaluate a prioritization
change before shipping it.

*Approach:* `replay --as-of YYYY-MM-DD` reads from cache only (no
network), reconstructs the EnrichedCve set from cached NVD / EPSS /
KEV snapshots at that date, re-runs `bucket_and_suggest`, and
diff-tables the produced bucket assignment against what was
historically recorded in the `runs` table for that day. Biggest cost
is a soft-versioning column (`as_of_date`) on cache rows.

### 8. Sector / geopolitical threat context (deeper than today's filter)

**Category:** Analysis. **Maturity tier:** Intermediate.

A `--sector financial` filter ships today and narrows output by linked
actor's targeted-sectors. The next step is *contextual* sector
tagging — surfacing the sector list in adversary cross-tabs and
weighting prioritization by sector-relevance to the operator.

*Approach:* Surface the actor sector list in the Markdown adversary
cross-tab (already in the data, not yet rendered). Optionally weight
`risk_score` (item 2 above) by sector match.

---

## Pointers

- The live backlog with slice plans, acceptance criteria, and effort
  estimates lives at [`tasks/todo.md`](../tasks/todo.md).
- The user-facing feature inventory lives in
  [`README.md`](../README.md).
- The historical 2026-05 single-file gap analysis (v1) has been
  removed from `docs/` — its content has been folded into this file
  and `README.md` plus the relevant items have shipped.
