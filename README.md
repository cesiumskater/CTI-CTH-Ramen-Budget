# ramen-cve

**CVE triage on a ramen budget** — a Python CTI / threat-hunting pipeline
for teams who need a *working* process before they can afford a *working
platform*.

Give it an OPML feed list, an article URL, a CVE list, or a STIX 2.1
bundle. It extracts CVE identifiers and enriches each one with CVSS (NVD),
exploitation probability (EPSS), CISA KEV context, MITRE ATT&CK mappings,
threat-actor attribution, public-exploit availability, and per-host
inventory correlation. It then drops every CVE into one of five action
buckets — KEV-listed CVEs always surface first — and writes analyst-friendly
artefacts (CSV, Markdown, STIX 2.1, Sigma/YARA stubs, an inline-SVG quadrant,
a static Web UI) and optionally pushes Slack / webhook alerts or batched
email digests to asset owners.

Companion code for the BSidesSLC 2026 talk **"Threat Intel on a Ramen
Budget"** by Danny Page ([@cesiumskater](https://github.com/cesiumskater)).

> **This README is the single source of truth.** Everything you need to
> install, run, configure, and extend the tool lives here. The files under
> [`docs/`](docs/) are supplementary — see [Documentation](#documentation).

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Quick start](#quick-start)
- [Installation](#installation)
- [API keys](#api-keys)
- [Usage](#usage)
- [Configuration & presets](#configuration--presets)
- [Scheduled runs](#scheduled-runs)
- [Daemon mode](#daemon-mode)
- [Web UI](#web-ui)
- [Bucket logic](#bucket-logic)
- [Outputs](#outputs)
- [What's bundled](#whats-bundled)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The intelligence cycle — *direction → collection → processing → analysis →
dissemination → feedback* — doesn't require a commercial platform. It
requires a repeatable process. `ramen-cve` is that process in one auditable
Python package:

- **Collect** CVEs and IOCs from feeds, articles, CVE lists, or STIX/TAXII.
- **Enrich** them against free, authoritative sources (NVD, EPSS, CISA KEV,
  Exploit-DB / Nuclei / GitHub, VirusTotal / AbuseIPDB / OTX / MalwareBazaar).
- **Analyse** with industry-standard frames (MITRE ATT&CK, Cyber Kill Chain,
  Diamond Model) plus TLP + NATO Admiralty provenance.
- **Prioritize** with a flat, defensible five-bucket decision table.
- **Disseminate** in every format a downstream tool can consume.

It runs from a fresh checkout with **no install and no API keys** — every
key you add and every enrichment you enable simply unlocks more. The whole
thing is small enough for one analyst to run, schedule, read, and defend to
leadership. That's the ramen budget.

**Who it's for:** small security teams, solo analysts, and anyone who wants
the working core of a CTI / CTH program without a TIP licence. MIT-licensed
and meant to be forked.

---

## Features

- **Inputs** — OPML feed lists (single file or a directory of `*.opml`),
  single-URL crawl (`--depth 0|1`), hand-supplied CVE lists, STIX 2.1 bundle
  import, and TAXII 2.x pull.
- **Enrichment** — NVD (CVSS, CWE, CPE), EPSS (including multi-day
  trajectory mode), CISA KEV (due date + ransomware-use flag), public-exploit
  signals (Exploit-DB, Nuclei, GitHub PoC), IOC reputation (VirusTotal,
  AbuseIPDB, OTX, MalwareBazaar), bundled threat-actor / campaign / malware
  associations, and CPE↔asset inventory correlation.
- **Analysis frames** — MITRE ATT&CK technique tagging, Cyber Kill Chain
  phase, Diamond Model (adversary / capability / infrastructure / victim),
  TLP + NATO Admiralty source-confidence merging, IOC confidence decay, and
  an optional sector filter.
- **Outputs** — CVE CSV (UTF-8 BOM so Excel renders it correctly, with
  spreadsheet formula-injection neutralised), IOC CSV sidecar, Markdown
  triage report, STIX 2.1 bundle, Sigma rule stubs, YARA rule stubs, an
  inline-SVG CVSS×EPSS quadrant, and a deterministic static-HTML Web UI.
- **Dispatch** — Slack Block-Kit webhooks, generic JSON webhook, and
  per-owner email digests. `--dispatch-on-delta-only` pushes only CVEs whose
  bucket *upgraded* since the previous run (the bucket transition is surfaced
  in the payload either way).
- **Workflow primitives** — threat-hunt hypothesis tracker (`hunt`),
  Priority Intelligence Requirements (`pir`), historical trend (`trend`), and
  a tamper-evident audit log (`audit`).
- **Operations** — YAML preset system (`--save-config` / `--config`), native
  scheduler emitters (Windows Task Scheduler XML + cron), and a long-running
  `daemon` subcommand with timestamped per-iteration output and optional
  history pruning.
- **Five runtime dependencies** (`requests`, `feedparser`, `python-dotenv`,
  `questionary`, `PyYAML`) — see [`docs/SBOM.md`](docs/SBOM.md).

---

## Quick start

```bash
git clone https://github.com/cesiumskater/cti-cth-ramen-budget
cd cti-cth-ramen-budget
./scripts/setup.sh                 # Linux / macOS
# .\scripts\setup.ps1              # Windows PowerShell

# No-args wizard — interactive prompts for every option.
python threat_intel_hunter.py

# Or jump straight to an OPML run.
python threat_intel_hunter.py opml examples/sample.opml
```

The bootstrap creates `.venv`, does an editable install (so the `ramen-cve`
console script lands on your `PATH`), and copies `config/env.example` to
`.env` at the repo root on first run.

---

## Installation

The fast path is `scripts/setup.sh` / `scripts/setup.ps1` above. Manual:

```bash
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell
pip install -e ".[dev]"            # installs the ramen-cve console script
cp config/env.example .env         # then fill in any keys you want
```

Three equivalent entry points after install:

- `ramen-cve …` — console script (recommended)
- `python -m ramen_cve …`
- `python threat_intel_hunter.py …` — no-install shim that prints a friendly
  hint if dependencies aren't on the path yet

**Python 3.10+.** Runtime deps are pinned in
[`config/requirements.txt`](config/requirements.txt); dev deps in
[`config/requirements-dev.txt`](config/requirements-dev.txt). The
authoritative dependency manifest is
[`pyproject.toml`](pyproject.toml).

### Docker

If you'd rather not manage a Python toolchain, a multi-stage
[`Dockerfile`](Dockerfile) ships in the repo. The image runs as a non-root
user, mounts `/data` for the cache + per-run output, and exposes the
`ramen-cve` console script as its entry-point.

```bash
docker build -t ramen-cve .                         # ~1 minute, one-off
docker run --rm -v $PWD/data:/data ramen-cve --version

# Run a triage straight from the image:
docker run --rm -v $PWD/data:/data ramen-cve \
    opml /data/feeds.opml --out-dir /data/out --format csv,html
```

`docker-compose.yml` provides one-shot and `--profile daemon` services with
all API-key env-vars wired from a host-side `.env`. CI builds and
smoke-tests the image on every push.

---

## API keys

The tool runs with **zero** keys. Each key you set unlocks more.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | every run | Lifts the NVD rate limit from 5/30s → 50/30s |
| `GITHUB_TOKEN` | exploit tracker | Lifts the GitHub Search rate limit from 10/min → 30/min |
| `VT_API_KEY` | IOC enrichment | VirusTotal lookups for IPs / URLs / domains / hashes |
| `ABUSEIPDB_API_KEY` | IOC enrichment | AbuseIPDB IP reputation |
| `OTX_API_KEY` | IOC enrichment | AlienVault OTX indicator pulses |
| `SLACK_WEBHOOK_URL` | `--dispatch` | Per-finding Block-Kit alerts |
| `RAMEN_DISPATCH_WEBHOOK` | `--dispatch` | Generic JSON webhook alerts |
| `RAMEN_SMTP_HOST` (+ `_FROM`, `_USER`, `_PASS`, `_USE_TLS`) | `--digest` | Daily-digest email |
| `RAMEN_DIGEST_TO` | `--digest` | Catch-all recipient for un-owned hosts |

Copy [`config/env.example`](config/env.example) → `.env` at the repo root and
paste your keys after each `=`. `.env` is gitignored; keys are redacted from
logs and are never serialized into outputs or the cache. The full network
trust surface is enumerated in [`docs/SBOM.md`](docs/SBOM.md) §6.

---

## Usage

The fastest way in is the no-args **wizard** — `python threat_intel_hunter.py`
walks you through every prompt, accepts quoted Windows paths and `~`, and
lets you pick the output basename before any files are written. Output
formats are a **checkbox list** (space toggles, enter confirms; green =
selected, red = unselected), so you can pick any combination — csv + md
start ticked.

**Made a mistake? Go back.** Every prompt is back-navigable: choose the
`← back` row on a menu, or type **`select ..`** at a text/path prompt, to
return to the previous question. Going back **hard-clears** that answer, so
the prompt is re-asked fresh — no stale default to accidentally re-accept.
`Ctrl-C` aborts the whole wizard.

Eleven subcommands are available: `opml`, `url`, `cve`, `stix`, `hunt`,
`pir`, `trend`, `audit`, `web`, `schedule`, and `daemon`.

### OPML feeds

```bash
python threat_intel_hunter.py opml examples/sample.opml
python threat_intel_hunter.py opml ~/feeds              # directory of *.opml
```

### Single URL (optionally crawl one hop)

```bash
python threat_intel_hunter.py url https://krebsonsecurity.com/2024/04/some-article/
python threat_intel_hunter.py url https://example.com/seed --depth 1 \
    --max-crawl-links 25 --crawl-delay-ms 500
```

### Named CVEs

```bash
python threat_intel_hunter.py cve CVE-2021-44228 CVE-2021-26855
python threat_intel_hunter.py cve --from-file my-cves.txt
```

### STIX / TAXII

```bash
python threat_intel_hunter.py stix bundle.json
python threat_intel_hunter.py stix --taxii-url https://taxii.example/api1 \
    --taxii-collection 00000000-0000-4000-8000-000000000001
```

### Threat hunts (PEAK / F3EAD)

```bash
python threat_intel_hunter.py hunt list
python threat_intel_hunter.py hunt show   log4shell-evidence
python threat_intel_hunter.py hunt link   log4shell-evidence CVE-2021-45046
python threat_intel_hunter.py hunt log    log4shell-evidence "Nothing in proxy logs."
python threat_intel_hunter.py hunt status log4shell-evidence closed_true_positive
```

### Priority Intelligence Requirements

```bash
python threat_intel_hunter.py pir list
python threat_intel_hunter.py pir coverage
python threat_intel_hunter.py pir link log4j-exposure CVE-2021-44228
```

### Trend, audit, web

```bash
python threat_intel_hunter.py trend CVE-2021-44228     # sparkline across cached runs
python threat_intel_hunter.py audit --tail 100         # who ran what, when
python threat_intel_hunter.py web --site-dir ./_site   # static, browseable HTML
```

### Common flags (analysis subcommands)

| Flag | Default | What it does |
| --- | --- | --- |
| `--start YYYY-MM-DD` / `--end YYYY-MM-DD` | none | Date window |
| `--date-mode {feed,disclosure,epss}` | `feed` | Which date the window applies to (`epss` accepts a range for trajectory mode) |
| `--cvss-threshold N` | `7.0` | CVSS cutoff for "high severity" |
| `--epss-threshold N` | `0.10` | EPSS cutoff for "likely exploited" |
| `--out-dir PATH` | cwd | Output directory (quote-stripped, `~`-expanded) |
| `--basename NAME` | timestamped | Output filename stem |
| `--format SPEC` | `both` | One or more output formats, comma-separated: `csv`, `md`, `stix`, `sigma`, `yara`, `html`, `navigator` (e.g. `--format csv,navigator`). Aliases: `both` = csv,md; `all` = everything |
| `--no-cache` | off | Skip the SQLite cache (always re-fetch) |
| `--no-exploit-lookup` | off | Skip Exploit-DB / Nuclei / GitHub PoC lookups |
| `--no-enrich-iocs` | off | Skip VT / AbuseIPDB / OTX / MalwareBazaar enrichment |
| `--ioc-confidence-floor F` | `0.0` | Drop IOCs whose decayed confidence < `F` |
| `--inventory PATH` | none | CSV of `host,product,version,[cpe],[owner],[criticality]` for asset correlation. The optional `criticality` column (`tier1`/`tier2`/`tier3`) feeds the **risk_score** that re-ranks CVEs *within* each bucket in the Markdown report |
| `--sector NAME` | none | Drop CVEs whose only attribution targets a *different* sector |
| `--associations-file PATH` | bundled | Override the CVE→actor/malware lookup |
| `--ssvc-profile PATH` | off | Activate **SSVC v2** (Stakeholder-Specific Vulnerability Categorization) Deployer-tree scoring alongside the existing buckets. JSON profile sets the org-specific decision points (mission_impact, safety_impact, value_density, exposure_default); see [`src/ramen_cve/ssvc.py`](src/ramen_cve/ssvc.py). Emits `ssvc_action` ∈ {`defer`, `scheduled`, `out-of-cycle`, `immediate`} in CSV + Markdown |
| `--allow-tlp-red` | off | Permit writing TLP:RED records (otherwise stripped) |
| `--dispatch` | off | Push per-finding alerts to Slack / generic webhook |
| `--dispatch-on-delta-only` | off | With `--dispatch`, only push CVEs whose bucket *upgraded* since the previous run (first-seen included); suppresses every-run repeats |
| `--digest` | off | Batch-mail a daily digest per asset owner (SMTP via env) |
| `--quiet` / `--verbose` | off | Logging level |
| `--log-format {text,json}` | `text` | Stderr log shape. `text` keeps the human-readable `LEVEL message` format; `json` emits one JSON line per record (`ts`, `level`, `logger`, `message`, plus any extras) for SIEM ingestion |

Three top-level flags are valid before any subcommand: `--config NAME`,
`--save-config NAME`, and `--list-configs`. See the next section.

---

## Configuration & presets

Every flag above can be captured in a YAML file, so a complex invocation
becomes a one-word command. The fully commented schema lives at
**[`src/ramen_cve/config/config.yaml`](src/ramen_cve/config/config.yaml)** —
that file is the authoritative reference for every supported key (`output`,
`filters`, `enrichment`, `cache`, `dispatch`, `email`, `logging`,
`inventory_path`, `remember_opml`, plus the nested `buckets:` block for
custom bucket labels / thresholds / action text).

```bash
# Save the current invocation as a named preset:
python threat_intel_hunter.py --save-config daily-hunt \
    opml ~/feeds --format all --cvss-threshold 8.0 --sector financial

# Replay it. CLI flags still override individual YAML values.
python threat_intel_hunter.py --config daily-hunt
python threat_intel_hunter.py --config daily-hunt --format csv    # override one key
python threat_intel_hunter.py --config /abs/path/custom.yaml      # explicit file

python threat_intel_hunter.py --list-configs
```

**Precedence: CLI flag > YAML value > built-in default.** A YAML key left
blank is ignored. The preset records the subcommand too, so `--config
daily-hunt` with no positional subcommand runs exactly what was saved.

A showcase preset that tightens the bucket thresholds and rewrites the
suggested-action text with concrete SLAs ships at
[`src/ramen_cve/config/presets/aggressive.yaml`](src/ramen_cve/config/presets/aggressive.yaml).

**Email digests via YAML.** When the `email:` block has `enabled: true`, the
preset's SMTP settings populate the `RAMEN_SMTP_*` environment variables and
`--digest` is implicitly enabled. A real `.env` always wins over the YAML
value, so production deployments keep secrets out of the preset file.

---

## Scheduled runs

The `schedule` subcommand turns a saved preset into a recurring run by
emitting an **OS-native scheduler artefact** — no fragile long-lived process
to keep alive.

**Windows Task Scheduler:**

```bash
python threat_intel_hunter.py schedule windows-task \
    --for-config daily-hunt --time 06:15 \
    --task-name ramen-cve-daily --output task.xml
# then, in an elevated prompt:
schtasks /Create /TN ramen-cve-daily /XML task.xml
```

**Linux / macOS cron:**

```bash
python threat_intel_hunter.py schedule cron --for-config daily-hunt --time 06:15
# → 15 6 * * * /path/to/python /path/to/threat_intel_hunter.py --config daily-hunt
crontab -e   # paste the line
```

A bundled GitHub-Actions equivalent lives at
[`examples/github-actions-daily-triage.yml`](examples/github-actions-daily-triage.yml).

---

## Daemon mode

When you'd rather run **one long-lived process** than wire up an external
scheduler, the `daemon` subcommand loops a saved preset at a fixed interval.
It complements `schedule` (use `schedule` if you already have systemd / cron /
Task Scheduler; reach for `daemon` inside a container).

```bash
# 1. Save the recurring invocation once.
ramen-cve --save-config daily-opml opml ~/feeds --format all

# 2. Loop it every 6 hours, keep 30 days of history.
ramen-cve daemon --for-config daily-opml --interval 21600 \
    --out-dir ~/ramen-history --prune-after-days 30
```

`--for-config` is required and must name a preset whose subcommand is `opml`,
`url`, `cve`, or `stix`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--for-config NAME` | *(required)* | Preset (or YAML path) to loop each iteration |
| `--interval SECONDS` | `21600` (6 h) | Sleep between iterations |
| `--jitter SECONDS` | `0` | Uniform ±jitter (spreads load across hosts) |
| `--max-runs N` | `-1` (unbounded) | Iteration cap; mainly for testing |
| `--out-dir DIR` | cwd | Each iteration writes to `<DIR>/ramen-cve-<UTC timestamp>/` |
| `--prune-after-days N` | `0` (off) | Delete iteration subdirs older than `N` days |

SIGTERM / SIGINT finish the in-flight iteration, then exit cleanly. The
inter-iteration wait is interruptible, so shutdown latency stays sub-second
even on a 6-hour interval.

> **Security — long-lived secrets.** A daemon keeps `NVD_API_KEY`,
> `RAMEN_SMTP_PASS`, and `SLACK_WEBHOOK_URL` resident for its lifetime. Prefer
> a systemd `EnvironmentFile`, a launchd `EnvironmentVariables` block, or
> container/orchestrator secrets over a committed `.env`. Run **one daemon per
> cache file** — the SQLite cache isn't built for concurrent writers (use
> `Restart=on-failure`, not `always`).

---

## Web UI

`ramen-cve web --site-dir ./_site` generates a fully static HTML tree
covering every run in the cache:

- `index.html` — bucket breakdown + CVSS×EPSS quadrant + a run-history strip
  linking to per-run and per-CVE pages.
- `runs/<ts>.html` — per-run bucket counts, quadrant, and an "added /
  removed / reclassified since previous run" diff block.
- `cve/<CVE-ID>.html` — header + NVD summary + EPSS trajectory (SVG above 2
  snapshots, sparkline below) + exploit status + linked actors / campaigns /
  malware + IOCs from the most recent run's sidecar + affected hosts.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--site-dir DIR` | *(required)* | Where the site is written — no default, explicit by design |
| `--out-dir DIR` | from cache | Override the per-run artefact directory recorded in `run_artefacts`; useful when CSV/MD/STIX files have moved since the original run |

Zero JavaScript, zero new runtime dependency, no server. Open `index.html`
directly in a browser, or rsync `_site/` behind any static host. A committed
showcase bundle lives at [`examples/_web-sample/`](examples/_web-sample/) —
clone the repo and open `examples/_web-sample/index.html` for a first look.

---

## Bucket logic

Every CVE lands in exactly one bucket, checked top to bottom:

| Bucket | Condition | Action |
| --- | --- | --- |
| **KEV Override** | CISA KEV listed | Patch immediately — exploitation confirmed |
| **Patch Now** | CVSS ≥ τ_cvss **and** EPSS ≥ τ_epss | High severity *and* likely exploited |
| **Plan and Patch** | CVSS ≥ τ_cvss **and** EPSS < τ_epss | High severity, exploit unlikely so far |
| **Watch Closely** | CVSS < τ_cvss **and** EPSS ≥ τ_epss | Low severity but actively exploited |
| **Deprioritize** | everything else | Low severity + low exploitation probability |

CVSS answers *how bad if exploited*; EPSS answers *how likely in the next 30
days*; KEV answers *is it being exploited right now*. Using all three avoids
the classic CVSS-only failure mode (patching a 9.8 nobody exploits while
ignoring a 6.5 in every exploit kit).

The decision tree is flat by design — it fits in the analyst's head. Labels,
thresholds, and action text are customisable per-bucket via the YAML
`buckets:` block (see `config.yaml`). **KEV precedence is non-configurable.**

---

## Plugins

Third-party output writers can extend `--format` without modifying core
code. Authors publish a separate package whose `pyproject.toml` declares:

```toml
[project.entry-points."ramen_cve.writers"]
jsonl = "my_ramen_writer:write_jsonl"
```

`ramen-cve` discovers installed plugins on the next invocation; the new
token (`jsonl`) becomes a valid `--format` value (alone or in combos:
`--format csv,jsonl`). A broken plugin logs a WARNING and is skipped —
the rest of the pipeline runs unaffected.

A reference plugin lives at
[`examples/plugins/jsonl_writer/`](examples/plugins/jsonl_writer/) —
install editable with `pip install -e examples/plugins/jsonl_writer`,
then `ramen-cve cve CVE-2021-44228 --format jsonl --out-dir ./out`
writes line-delimited JSON to `./out/ramen-cve-<ts>-jsonl.jsonl`. The
[contract](src/ramen_cve/plugins.py) (`WRITER_CONTRACT`) is the
stability boundary — see the plugin's README for the authoring walkthrough.

Other extension points (parsers, enrichers, dispatchers, bucket
policies) are tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Outputs

A single run can produce up to eight artefact types. Pick what you want with
`--format` — a single value or any comma-separated combination
(`--format csv,html,navigator`); `both` (= csv,md) and `all` work as aliases:

| Artefact | Trigger | Shape |
| --- | --- | --- |
| CVE CSV | `csv` / `both` / `all` | One row per CVE, 35 columns; UTF-8 BOM for Excel, formula-injection neutralised |
| IOC CSV | (when IOCs found) | One row per non-CVE indicator |
| EPSS trajectory CSV | (when `--date-mode epss` spans >1 day) | One row per `(cve_id, date)` |
| Markdown report | `md` / `both` / `all` | Bucket sections + ATT&CK cross-tab + Linked Adversaries + Affected Hosts + sparklines |
| STIX 2.1 bundle | `stix` / `all` | Vulnerability + Note + Indicator + Identity SDOs (deterministic IDs) |
| Sigma stubs | `sigma` / `all` | One YAML stub per KEV / Patch-Now CVE, pre-tagged |
| YARA stubs | `yara` / `all` | One YARA rule scaffold per linked-malware family |
| Inline-SVG quadrant HTML | `html` / `all` | Single-file CVSS×EPSS scatter |
| ATT&CK Navigator layer | `navigator` / `all` | `*.attack-layer.json` — drop into [Navigator](https://mitre-attack.github.io/attack-navigator/); CVE-touched techniques heat-mapped by worst bucket |

`--basename my-report` writes `my-report.csv` / `my-report.md` /
`my-report-iocs.csv` / `my-report.stix.json` / `my-report-sigma/` /
`my-report-yara/` / `my-report.html`. **Existing files are never
overwritten** — a `-1`, `-2`, … suffix is appended on collision. A redundant
extension on `--basename` is stripped before the right one is re-applied, so
you never get `my-report.csv.csv`.

Reference artefacts ship under [`examples/`](examples/): a Markdown report at
[`examples/sample-report.md`](examples/sample-report.md), its CSV counterpart
at [`examples/sample-output.csv`](examples/sample-output.csv), and a quadrant
at [`examples/sample-quadrant.html`](examples/sample-quadrant.html).

---

## What's bundled

`src/ramen_cve/data/` ships a working lookup set. **None of it is required**
— every default path can be overridden — but the bundled values let
`python threat_intel_hunter.py` work out of the box:

- **`associations.json`** — 12 well-known CVEs (Log4Shell, ProxyLogon,
  PrintNightmare, ZeroLogon, Equation Editor, EternalBlue, Fortinet SSL VPN,
  Pulse Secure, Sandworm PowerPoint, Follina, Outlook NTLM, Barracuda ESG)
  mapped to MITRE ATT&CK Groups, ransomware operators, malware families,
  named campaigns, and per-actor sector targeting.
- **`hunts/log4shell-evidence.json`** — a sample threat-hunt hypothesis.
- **`pirs/log4j-exposure.json`** — a sample Priority Intelligence Requirement.

Add or correct entries directly in those JSON files; the package reads them
on every run. Provenance for the bundled data is documented in
[`docs/SBOM.md`](docs/SBOM.md) §1.

---

## Repository layout

```
.
├── README.md                  # this file (single source of truth)
├── LICENSE                    # MIT
├── pyproject.toml             # project metadata + ruff + pytest config
├── conftest.py                # pytest src/ bootstrap
├── threat_intel_hunter.py     # entry-point shim → ramen_cve.cli:main
│
├── src/ramen_cve/             # installable package (src layout)
│   ├── __init__.py            #   pure re-export façade with a locked __all__
│   ├── __main__.py            #   python -m ramen_cve
│   ├── cli.py                 #   argparse tree + main + per-subcommand runners
│   ├── config/                #   YAML config system
│   │   ├── config.yaml        #     fully-commented schema / template
│   │   └── presets/           #     bundled + user-saved presets
│   ├── data/                  #   bundled lookup data (associations, hunts, pirs)
│   ├── enrich/                #   nvd · epss · kev · exploits · iocs · inventory · orchestrator
│   ├── output/                #   csv_writer · markdown · stix · sigma · yara · html_quadrant
│   ├── dispatch/              #   slack · webhook · email sinks + per-owner digest
│   └── web/                   #   static-HTML Web UI generator
│
├── config/                    # dependency manifests + env template
│   ├── env.example            #   copy to .env at the repo root
│   ├── requirements.txt
│   └── requirements-dev.txt
│
├── docs/                      # supplementary docs (this README is primary)
│   ├── CLAUDE.md              #   AI-contributor project rules
│   ├── SBOM.md                #   software bill of materials
│   ├── whitepaper.md          #   technical whitepaper (BSidesSLC 2026)
│   └── cti-capability-gap-analysis-v2.md   # forward-looking CTI/CTH roadmap
│
├── examples/                  # sample inputs + outputs + showcase bundle
│   ├── sample.opml
│   ├── sample-inventory.csv
│   ├── sample-output.csv
│   ├── sample-report.md
│   ├── sample-quadrant.html
│   ├── github-actions-daily-triage.yml
│   └── _web-sample/           #   committed static-site showcase
│
├── scripts/
│   ├── setup.sh               # bootstrap on Linux / macOS
│   ├── setup.ps1              # bootstrap on Windows PowerShell
│   └── regen_examples.py      # deterministic showcase regenerator (byte-oracle)
│
├── tasks/
│   ├── todo.md                # forward-looking backlog + templates
│   └── lessons.md             # recurring failure modes + prevention rules
│
└── tests/                     # 809 pytest cases + fixtures
```

---

## Documentation

This README is the primary reference. The supplementary docs each have a
single, distinct job and defer back here for anything user-facing:

| Doc | Purpose |
| --- | --- |
| `README.md` (this file) | **Primary source of truth** — install, usage, config, outputs |
| [`docs/whitepaper.md`](docs/whitepaper.md) | BSidesSLC 2026 technical whitepaper — problem statement, methodology, security posture |
| [`docs/SBOM.md`](docs/SBOM.md) | Software bill of materials — runtime + dev deps, transitive, licenses, network endpoints |
| [`docs/CLAUDE.md`](docs/CLAUDE.md) | AI-contributor project rules — operating principles, layered architecture, dependency budget |
| [`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md) | Forward-looking CTI/CTH capability roadmap (the "why + approach" behind the backlog) |
| [`tasks/todo.md`](tasks/todo.md) | Forward-looking backlog and planning templates |
| [`tasks/lessons.md`](tasks/lessons.md) | Recurring failure modes + prevention rules captured during development |
| [`src/ramen_cve/config/config.yaml`](src/ramen_cve/config/config.yaml) | Fully-commented YAML config schema — authoritative for every configuration key |
| [`config/env.example`](config/env.example) | Environment-variable template (copy to `.env`) |

Skimming for the first time? This README + `docs/whitepaper.md` + the
`config.yaml` template are the three documents you actually need.

---

## Roadmap

Next-up directions, in priority order. The "why it matters + suggested
implementation approach" for each lives in
[`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md);
the operational picking surface is [`tasks/todo.md`](tasks/todo.md).

1. **SSVC** (Stakeholder-Specific Vulnerability Categorization) decision
   tree — run in parallel with today's bucketing, additive.
2. **Risk-weighted prioritization** — CVE × asset criticality × exploit
   availability (one new optional `criticality` inventory column).
3. **Native SIEM query generation** (KQL / SPL / Elastic EQL) alongside the
   Sigma stubs.
4. **MISP-native push / pull** via PyMISP.
5. **Vulnerability-scanner imports** (Nessus / Qualys / Rapid7).
6. **Hunt analytics library** — reusable, per-ATT&CK-technique queries.
7. **Backtesting / replay mode** to evaluate model changes safely.

*(Bucket-transition delta alerting has already shipped — see
`--dispatch-on-delta-only` above.)*

---

## Contributing

The project is intentionally small enough that one person can hold it in
their head. PRs that respect that spirit are welcome.

**Before opening a PR**, run the full verification gate:

```bash
pip install -e ".[dev]"                              # if you haven't already
pytest tests/ -q                                     # must stay green (809 cases)
ruff check threat_intel_hunter.py conftest.py src/ tests/ scripts/
python scripts/regen_examples.py --check             # byte-oracle on the showcase bundle
```

All three are part of the per-commit gate documented in
[`docs/CLAUDE.md`](docs/CLAUDE.md). The byte-oracle catches accidental drift
in the bundled `examples/sample-output.csv` / `examples/sample-report.md` /
`examples/_web-sample/` artefacts.

**Conventions worth knowing:**

- **Five-runtime-dep budget.** Adding a sixth needs a written justification
  in [`tasks/todo.md`](tasks/todo.md). The current set is `requests`,
  `feedparser`, `python-dotenv`, `questionary`, `PyYAML` — see
  [`docs/SBOM.md`](docs/SBOM.md).
- **Layered package.** Modules sit on layers L0–L5; imports point downward
  only. New modules should pick the lowest layer that fits.
  [`src/ramen_cve/__init__.py`](src/ramen_cve/__init__.py) is a pure
  re-export façade with a locked `__all__`; both halves of the contract are
  gated by `tests/test_facade.py` — never remove a re-export without updating
  that test.
- **Thin vertical slices.** Land features in small, reviewable steps, each
  with its own tests and verification story (see
  [`docs/CLAUDE.md`](docs/CLAUDE.md)).
- **Per-failure-mode lessons.** When you hit a recurring failure pattern,
  capture it in [`tasks/lessons.md`](tasks/lessons.md) so the next
  contributor doesn't repeat it.

**Reporting issues:** open a GitHub issue with the command you ran, the
observed output, and the expected output. Redact any real API keys before
pasting logs (the tool redacts at write time, but manually captured terminal
scrollback may not have been).

**Picking a task:** the backlog in
[`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md)
is sorted by impact-to-effort ratio. Item 1 (the SSVC decision tree) is a
strong starter — it's additive, has a modest implementation cost, and
produces an auditor-recognized output.

---

## License

MIT — see [`LICENSE`](LICENSE). The repo is meant to be forked and adapted by
anyone who watches the talk.
