# ramen-cve

**CVE triage on a ramen budget** — a Python CTI / threat-hunting pipeline
behind a flat re-export façade, for teams who need a working pipeline before
they have a working platform.

Give it an OPML feed list, an article URL, a CVE list, or a STIX 2.1 bundle.
It extracts CVE identifiers, enriches each with CVSS (NVD), exploitation
probability (EPSS), CISA KEV context, MITRE ATT&CK mappings, threat-actor
attribution, public-exploit availability, and per-host inventory correlation.
It buckets every CVE into one of five action categories — KEV-listed CVEs
always surface first — then writes analyst-friendly artefacts (CSV, Markdown,
STIX 2.1, Sigma stubs, YARA stubs, inline-SVG quadrant, static Web UI) and
optionally pushes Slack / webhook alerts or batched email digests to asset
owners.

Companion to the BSidesSLC 2026 talk **"Threat Intel on a Ramen Budget"** by
Danny Page ([@cesiumskater](https://github.com/cesiumskater)).

This README is the single source of truth for the project. Supplementary
material lives under [`docs/`](docs/) — see [Documentation](#documentation)
at the bottom.

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Installation](#installation)
- [API keys](#api-keys)
- [Usage](#usage)
- [YAML configuration & presets](#yaml-configuration--presets)
- [Scheduled runs](#scheduled-runs)
- [Daemon mode](#daemon-mode)
- [Web UI](#web-ui)
- [Bucket logic](#bucket-logic)
- [Outputs](#outputs)
- [Repository layout](#repository-layout)
- [What's bundled](#whats-bundled)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- **Inputs:** OPML feed lists (single file or directory), single-URL crawl
  (`--depth 0|1`), hand-supplied CVE lists, STIX 2.1 bundle import, TAXII 2.x
  pull.
- **Enrichment:** NVD (CVSS, CWE, CPE), EPSS (including multi-day trajectory
  mode), CISA KEV catalogue (due date + ransomware-use flag), public-exploit
  signals (Exploit-DB, Nuclei, GitHub PoC), IOC reputation (VirusTotal,
  AbuseIPDB, OTX, MalwareBazaar), bundled threat-actor / campaign / malware
  associations, and CPE↔asset inventory correlation.
- **Analysis frames:** MITRE ATT&CK technique tagging, Cyber Kill Chain
  phase, Diamond Model (adversary / capability / infrastructure / victim),
  TLP + NATO Admiralty source-confidence merging, IOC confidence decay,
  optional sector filter.
- **Outputs:** CVE CSV (UTF-8 with BOM so Excel renders correctly), IOC CSV
  sidecar, Markdown triage report, STIX 2.1 bundle, Sigma rule stubs, YARA
  rule stubs, inline-SVG CVSS×EPSS quadrant HTML, and a deterministic
  static-HTML Web UI generator.
- **Dispatch:** Slack Block-Kit webhooks, generic JSON webhook, per-owner
  email digests.
- **Workflow primitives:** threat-hunt hypothesis tracker (`hunt`), Priority
  Intelligence Requirements (`pir`), historical trend (`trend`), and a
  tamper-evident audit log (`audit`).
- **Operations:** YAML preset system (`--save-config` / `--config`), native
  scheduler emitters (Windows Task Scheduler XML + cron), long-running
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
console script is on your `PATH`), and copies `config/env.example` to `.env`
at the repo root on first run.

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

- `ramen-cve …` (console script, recommended)
- `python -m ramen_cve …`
- `python threat_intel_hunter.py …` (no-install shim — prints a friendly
  hint if dependencies aren't on the path yet)

Python 3.10+. Runtime deps pinned in `config/requirements.txt`; dev deps in
`config/requirements-dev.txt`.

---

## API keys

The tool runs without any keys. Each key you set unlocks more.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | every run | Lifts NVD rate-limit from 5/30s → 50/30s |
| `GITHUB_TOKEN` | exploit tracker | Lifts GitHub Search rate-limit from 10/min → 30/min |
| `VT_API_KEY` | IOC enrichment | VirusTotal lookups for IPs / URLs / domains / hashes |
| `ABUSEIPDB_API_KEY` | IOC enrichment | AbuseIPDB IP reputation |
| `OTX_API_KEY` | IOC enrichment | AlienVault OTX indicator pulses |
| `SLACK_WEBHOOK_URL` | `--dispatch` | Per-finding Block-Kit alerts |
| `RAMEN_DISPATCH_WEBHOOK` | `--dispatch` | Generic JSON webhook alerts |
| `RAMEN_SMTP_HOST` (+ `_FROM`, `_USER`, `_PASS`, `_USE_TLS`) | `--digest` | Daily-digest email |
| `RAMEN_DIGEST_TO` | `--digest` | Catch-all recipient for un-owned hosts |

Copy `config/env.example` → `.env` at the repo root and paste your keys
after each `=`. `.env` is gitignored; keys are redacted from logs and never
serialized into outputs or the cache.

---

## Usage

The fastest way in is the no-args **wizard** — `python threat_intel_hunter.py`
walks you through every prompt, accepts quoted Windows paths and `~`, and
lets you pick the output basename before files are written.

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
python threat_intel_hunter.py web --site-dir ./_site   # static HTML browseable view
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
| `--format {csv,md,both,stix,sigma,yara,html,all}` | `both` | Output formats |
| `--no-cache` | off | Skip SQLite cache (always re-fetch) |
| `--no-exploit-lookup` | off | Skip Exploit-DB / Nuclei / GitHub PoC lookups |
| `--no-enrich-iocs` | off | Skip VT / AbuseIPDB / OTX / MalwareBazaar enrichment |
| `--ioc-confidence-floor F` | `0.0` | Drop IOCs whose decayed confidence < `F` |
| `--inventory PATH` | none | CSV of `host,product,version,[cpe],[owner]` for asset correlation |
| `--sector NAME` | none | Drop CVEs whose only attribution targets a *different* sector |
| `--associations-file PATH` | bundled | Override the CVE→actor/malware lookup |
| `--allow-tlp-red` | off | Permit writing TLP:RED records (otherwise stripped) |
| `--dispatch` | off | Push per-finding alerts to Slack / generic webhook |
| `--digest` | off | Batch-mail a daily digest per asset owner (SMTP via env) |
| `--quiet` / `--verbose` | off | Logging level |

Three top-level flags (valid before any subcommand): `--config NAME`,
`--save-config NAME`, `--list-configs`. See the next section.

---

## YAML configuration & presets

Every flag above can be captured in a YAML file so a complex invocation
becomes a one-word command. The fully commented schema lives at
**[`src/ramen_cve/config/config.yaml`](src/ramen_cve/config/config.yaml)** —
that file is the authoritative reference for every supported key (`output`,
`filters`, `enrichment`, `cache`, `dispatch`, `email`, `logging`,
`inventory_path`, `remember_opml`, plus the nested `buckets:` block for
custom bucket labels / thresholds).

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

Precedence: **CLI flag > YAML value > built-in default**. A YAML key left
blank is ignored. The preset records the subcommand too, so `--config
daily-hunt` with no positional subcommand runs exactly what was saved.

A showcase preset that tightens the bucket thresholds and rewrites the
suggested-action text with concrete SLAs ships at
[`src/ramen_cve/config/presets/aggressive.yaml`](src/ramen_cve/config/presets/aggressive.yaml).

### Email digests via YAML

When the YAML `email:` block has `enabled: true`, the preset's SMTP settings
populate the `RAMEN_SMTP_*` environment variables and `--digest` is
implicitly enabled. A real `.env` always wins over the YAML value, so
production deployments keep secrets out of the preset file. Schema in the
`config.yaml` template above.

---

## Scheduled runs

The `schedule` subcommand turns a saved preset into a recurring run by
emitting an **OS-native scheduler artefact** — there's no fragile
long-lived process to keep alive.

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
scheduler, the `daemon` subcommand loops a saved preset at a fixed
interval. It complements `schedule` (use `schedule` if you already have
systemd / cron / Task Scheduler; reach for `daemon` inside a container).

```bash
# 1. Save the recurring invocation once.
ramen-cve --save-config daily-opml opml ~/feeds --format all

# 2. Loop it every 6 hours, keep 30 days of history.
ramen-cve daemon --for-config daily-opml --interval 21600 \
    --out-dir ~/ramen-history --prune-after-days 30
```

`--for-config` is required and must name a preset whose subcommand is
`opml`, `url`, `cve`, or `stix`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--for-config NAME` | *(required)* | Preset (or YAML path) to loop each iteration |
| `--interval SECONDS` | `21600` (6 h) | Sleep between iterations |
| `--jitter SECONDS` | `0` | Uniform ±jitter (spreads load across hosts) |
| `--max-runs N` | `-1` (unbounded) | Iteration cap; mainly for testing |
| `--out-dir DIR` | cwd | Each iteration writes to `<DIR>/ramen-cve-<UTC timestamp>/` |
| `--prune-after-days N` | `0` (off) | Delete iteration subdirs older than `N` days |

SIGTERM / SIGINT finish the in-flight iteration then exit cleanly. The
inter-iteration wait is interruptible, so shutdown latency stays sub-second
even on a 6-hour interval.

> **Security — long-lived secrets.** A daemon keeps `NVD_API_KEY`,
> `RAMEN_SMTP_PASS`, and `SLACK_WEBHOOK_URL` resident for its lifetime.
> Prefer a systemd `EnvironmentFile`, a launchd `EnvironmentVariables`
> block, or container/orchestrator secrets over a committed `.env`. Run
> **one daemon per cache file** — the SQLite cache isn't built for
> concurrent writers (use `Restart=on-failure`, not `always`).

Bundled service templates are summarised in the `daemon --help` text and
in the [Operations](#operations) docs cell below.

### Operations

- **systemd unit, launchd plist, GitHub-Actions workflow** — see
  [`examples/github-actions-daily-triage.yml`](examples/github-actions-daily-triage.yml)
  for the Actions form. systemd / launchd snippets sit in the previous
  README revision (git history: `git log -p README.md`) and will rejoin a
  dedicated `docs/operations.md` if a future PR requests them.

---

## Web UI

`ramen-cve web --site-dir ./_site` generates a fully static HTML tree
covering every run in the cache:

- `index.html` — bucket breakdown + Task-6 CVSS×EPSS quadrant + run-history
  strip linking to per-run pages and per-CVE detail pages.
- `runs/<ts>.html` — per-run bucket counts, quadrant, and an "added /
  removed / reclassified since previous run" diff block.
- `cve/<CVE-ID>.html` — header + NVD summary + EPSS trajectory (SVG above 2
  snapshots, sparkline below) + exploit status + linked actors / campaigns
  / malware + IOCs from the most recent run's sidecar + affected hosts.

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--site-dir DIR` | *(required)* | Where the site is written. No default — explicit by design |
| `--out-dir DIR` | from cache | Override the per-run artefact directory recorded in `run_artefacts`; useful when CSV/MD/STIX files have been moved since the original pipeline run |

Zero JavaScript, zero new runtime dependency, no server. Open
`index.html` directly in a browser, or rsync `_site/` behind any static
host. A committed showcase bundle lives at
[`examples/_web-sample/`](examples/_web-sample/) — clone the repo and open
`examples/_web-sample/index.html` for a first look.

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

Thresholds and decision tree are flat by design — they fit in the analyst's
head. Labels / thresholds / action text can be customised per-bucket via
the YAML `buckets:` block (see `config.yaml`). KEV precedence is
non-configurable.

---

## Outputs

A single run can produce up to seven artefacts. Pick what you want with
`--format`:

| Artefact | Trigger | Shape |
| --- | --- | --- |
| CVE CSV | `csv` / `both` / `all` | One row per CVE, 30 columns; UTF-8 BOM for Excel |
| IOC CSV | (when IOCs found) | One row per non-CVE indicator |
| EPSS trajectory CSV | (when `--date-mode epss` spans >1 day) | One row per `(cve_id, date)` |
| Markdown report | `md` / `both` / `all` | Bucket sections + ATT&CK cross-tab + Linked Adversaries + Affected Hosts + sparklines |
| STIX 2.1 bundle | `stix` / `all` | Vulnerability + Note + Indicator + Identity SDOs (deterministic UUIDv4) |
| Sigma stubs | `sigma` / `all` | One YAML stub per KEV / Patch-Now CVE, pre-tagged |
| YARA stubs | `yara` / `all` | One YARA rule scaffold per linked-malware family |
| Inline-SVG quadrant HTML | `html` / `all` | Single-file CVSS×EPSS scatter |

`--basename my-report` writes `my-report.csv` / `my-report.md` /
`my-report-iocs.csv` / `my-report.stix.json` / `my-report-sigma/` /
`my-report-yara/` / `my-report.html`. Existing files are never
overwritten; a `-1`, `-2`, … suffix is appended on collision. A redundant
extension on `--basename` is stripped before re-applying the right one, so
you never get `my-report.csv.csv`.

A reference Markdown report lives at
[`examples/sample-report.md`](examples/sample-report.md); its CSV
counterpart at [`examples/sample-output.csv`](examples/sample-output.csv).

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
│   ├── __init__.py            #   pure re-export façade with locked __all__
│   ├── __main__.py            #   python -m ramen_cve
│   ├── cli.py                 #   argparse tree + main + per-subcommand runners
│   ├── config/                #   YAML config system
│   │   ├── config.yaml        #     fully-commented schema / template
│   │   └── presets/           #     bundled + user-saved presets
│   ├── data/                  #   bundled lookup data (associations, hunts, pirs)
│   ├── enrich/                #   nvd / epss / kev / exploits / iocs / inventory
│   ├── output/                #   csv_writer / markdown / stix / sigma / yara / html_quadrant
│   ├── dispatch/              #   slack / webhook / email sinks + per-owner digest
│   └── web/                   #   static-HTML Web UI generator
│
├── config/                    # dep manifests + env template
│   ├── env.example            #   copy to .env at the repo root
│   ├── requirements.txt
│   └── requirements-dev.txt
│
├── docs/                      # supplementary docs (this README is primary)
│   ├── CLAUDE.md              #   AI-contributor project rules
│   ├── SBOM.md                #   software bill of materials
│   ├── whitepaper.md          #   technical whitepaper (BSidesSLC 2026)
│   ├── REFACTOR_PLAN.md       #   historical (monolith → package, complete)
│   ├── web_ui_design.md       #   historical (Web UI design, slices shipped)
│   └── cti-capability-gap-analysis-v2.md   # forward-looking roadmap
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
│   └── regen_examples.py      # deterministic showcase regenerator
│
├── tasks/
│   ├── todo.md                # forward-looking backlog
│   └── lessons.md             # recurring failure modes + prevention
│
├── tests/                     # 778+ pytest cases + fixtures
└── .claude/                   # Claude Code project settings (gitkept)
```

---

## What's bundled

`src/ramen_cve/data/` ships a working lookup set. None of it is required —
every default path can be overridden — but the bundled values let
`python threat_intel_hunter.py` work out of the box:

- **`associations.json`** — 12 well-known CVEs (Log4Shell, ProxyLogon,
  PrintNightmare, ZeroLogon, EternalBlue, Follina, Pulse Secure, Fortinet,
  Sandworm PowerPoint, Outlook NTLM, Barracuda ESG) mapped to MITRE Groups
  threat actors, ransomware operators, malware families, named campaigns,
  and per-actor sector targeting.
- **`hunts/log4shell-evidence.json`** — sample threat-hunt hypothesis.
- **`pirs/log4j-exposure.json`** — sample Priority Intelligence Requirement.

Add or correct entries directly in those JSON files; the package reads them
on every run.

---

## Documentation

| Doc | Purpose |
| --- | --- |
| `README.md` (this file) | Primary source of truth — install, usage, config, outputs |
| [`docs/whitepaper.md`](docs/whitepaper.md) | BSidesSLC 2026 technical whitepaper — problem statement, methodology, security posture |
| [`docs/SBOM.md`](docs/SBOM.md) | Software bill of materials (runtime + dev deps, transitive, licenses, network endpoints) |
| [`docs/CLAUDE.md`](docs/CLAUDE.md) | AI-contributor project rules (operating principles, layered architecture, dependency budget) |
| [`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md) | Forward-looking CTI/CTH capability roadmap |
| [`docs/REFACTOR_PLAN.md`](docs/REFACTOR_PLAN.md) | Historical — monolith → package refactor (complete) |
| [`docs/web_ui_design.md`](docs/web_ui_design.md) | Historical — Web UI design doc (all slices shipped) |
| [`tasks/todo.md`](tasks/todo.md) | Forward-looking backlog and templates |
| [`tasks/lessons.md`](tasks/lessons.md) | Recurring failure modes + prevention rules captured during development |
| [`src/ramen_cve/config/config.yaml`](src/ramen_cve/config/config.yaml) | Fully-commented YAML config schema — authoritative for every configuration key |
| [`config/env.example`](config/env.example) | Environment-variable template (copy to `.env`) |

If you're skimming for the first time: this README + `docs/whitepaper.md`
+ the `config.yaml` template are the three documents you actually need.

---

## Roadmap

The features below are next-up directions, prioritized in
[`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md):

1. **SSVC** (Stakeholder-Specific Vulnerability Categorization) decision
   tree, run in parallel with today's bucketing.
2. **Native SIEM query generation** (KQL / SPL / Elastic EQL) alongside
   Sigma stubs.
3. **MISP-native push / pull** via PyMISP.
4. **Bucket-transition delta alerting** — page only when a CVE *moves up*
   (the `runs` table already has the data).
5. **Vulnerability-scanner imports** (Nessus / Qualys / Rapid7 native).
6. **Risk-weighted prioritization** (CVE × asset criticality × exploit
   availability).
7. **Backtesting / replay mode** to evaluate model changes safely.

The active backlog with slice plans, acceptance criteria, and effort
estimates lives at [`tasks/todo.md`](tasks/todo.md).

---

## Contributing

The project is intentionally small enough that one person can hold it
in their head. PRs that respect that spirit are welcome.

**Before opening a PR:**

```bash
pip install -e ".[dev]"           # if you haven't already
pytest tests/ -q                  # must stay green (778 cases as of this writing)
ruff check threat_intel_hunter.py conftest.py src/ tests/ scripts/
python scripts/regen_examples.py --check   # byte-oracle on the showcase bundle
```

All three are part of the per-commit verification gate documented in
[`docs/CLAUDE.md`](docs/CLAUDE.md). The byte-oracle catches accidental
drift in the bundled `examples/sample-output.csv` /
`examples/sample-report.md` / `examples/_web-sample/` artefacts.

**Conventions worth knowing:**

- **Five-runtime-dep budget.** Adding a sixth needs a written
  justification in `tasks/todo.md`. The current set is `requests`,
  `feedparser`, `python-dotenv`, `questionary`, `PyYAML` — see
  [`docs/SBOM.md`](docs/SBOM.md).
- **Layered package.** Modules sit on layers L0–L5; imports point
  downward only. New modules should pick the lowest layer that fits.
  [`src/ramen_cve/__init__.py`](src/ramen_cve/__init__.py) is a pure
  re-export façade with a locked `__all__`; both halves of the
  contract are gated by `tests/test_facade.py`.
- **Thin vertical slices.** Land features in small reviewable steps,
  each with its own tests + verification story. See
  [`docs/CLAUDE.md`](docs/CLAUDE.md) §3.
- **Per-failure-mode lessons.** When you hit a recurring failure
  pattern, capture it in [`tasks/lessons.md`](tasks/lessons.md) so
  the next contributor doesn't repeat it.

**Reporting issues:** open a GitHub issue with the command you ran,
the observed output, and the expected output. Redact any real API
keys before pasting logs (the tool redacts at write time, but
manually-captured terminal scrollback may not have been).

**Picking a task:** the prioritized backlog in
[`docs/cti-capability-gap-analysis-v2.md`](docs/cti-capability-gap-analysis-v2.md)
is sorted by impact-to-effort ratio. Item 1 (bucket-transition delta
alerting) is the highest-leverage starter task — the infrastructure
is already in place.

---

## License

MIT — see [`LICENSE`](LICENSE).
