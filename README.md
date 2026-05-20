# ramen-cve

CVE triage on a ramen budget — a ~30-module Python package (CTI / threat-hunting
pipeline behind a flat re-export façade) for teams who need a working pipeline
before they have a working platform.

Give it an OPML feed list (or a directory of them), a single article URL, a list of CVE IDs,
or a STIX 2.1 bundle. It extracts CVE identifiers, enriches each with CVSS (NVD), exploitation
probability (EPSS), KEV-catalogue context (CISA), MITRE ATT&CK mappings, threat-actor
attribution, exploit / PoC availability, and per-host inventory correlation. It buckets every
CVE into one of five action categories (KEV-listed CVEs always surface first), then writes
analyst-friendly artefacts — CSV, Markdown, STIX 2.1 bundle, Sigma rule stubs, YARA rule stubs
— and optionally pushes Slack / webhook alerts or batched email digests to asset owners.

Companion code for the BSidesSLC 2026 talk **"Threat Intel on a Ramen Budget"** by Danny Page
([@cesiumskater](https://github.com/cesiumskater)).

---

## Repository layout

```
.
├── threat_intel_hunter.py   # entry-point shim → ramen_cve.cli:main() (façade-re-exported)
├── README.md                # this file
├── LICENSE                  # MIT
├── pyproject.toml           # project metadata + ruff + pytest config
├── conftest.py              # tells pytest to import the package from src/
├── .gitignore
├── .gitattributes
│
├── src/
│   └── ramen_cve/           # the installable package (src layout)
│       ├── __init__.py      # pure re-export façade + locked __all__; implementation in submodules (see docs/REFACTOR_PLAN.md)
│       ├── __main__.py      # python -m ramen_cve entry
│       ├── config/          # YAML config system
│       │   ├── config.yaml  #   fully-commented schema / template
│       │   └── presets/     #   saved named presets (--save-config)
│       └── data/            # bundled lookup data, loaded at runtime
│           ├── associations.json
│           ├── hunts/
│           └── pirs/
│
├── config/                  # dependency manifests + env template
│   ├── env.example          # copy to .env at the repo root and fill in API keys
│   ├── requirements.txt
│   └── requirements-dev.txt
│
├── docs/                    # contributor docs, gap analyses, whitepaper
│   ├── CLAUDE.md            # AI-contributor project rules
│   ├── whitepaper.md        # full technical whitepaper
│   ├── SBOM.md              # software bill of materials
│   ├── REFACTOR_PLAN.md
│   ├── cti-capability-gap-analysis*.md
│   └── tasks/               # lessons.md + todo.md
│
├── examples/                # sample OPML, sample CSV / MD outputs,
│                            #   GitHub-Actions scheduled-triage workflow
├── scripts/
│   ├── setup.sh             # bootstrap on Linux / macOS
│   └── setup.ps1            # bootstrap on Windows PowerShell
├── tests/                   # 420+ pytest cases + fixtures
└── .claude/                 # Claude Code project settings (gitkept)
```

---

## Install

The fast path is the bundled bootstrap; it builds a virtualenv, does an
editable install of the package (so the `ramen-cve` console script is on
your `PATH`), and copies `config/env.example` to `.env` on first run.

```bash
./scripts/setup.sh                 # Linux / macOS
.\scripts\setup.ps1                # Windows PowerShell
```

Manual install:

```bash
git clone https://github.com/cesiumskater/cti-cth-ramen-budget
cd cti-cth-ramen-budget
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell
pip install -e ".[dev]"            # installs `ramen-cve` console script
cp config/env.example .env         # then fill in the keys you want
```

---

## API key setup

The tool runs without any keys, but every key you set unlocks a feature.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | every run | Lifts NVD rate-limit from 5/30s → 50/30s |
| `GITHUB_TOKEN` | exploit/PoC tracker | Lifts GitHub Search rate-limit from 10/min → 30/min |
| `VT_API_KEY` | IOC enrichment | VirusTotal lookups for IPs / URLs / domains / hashes |
| `ABUSEIPDB_API_KEY` | IOC enrichment | AbuseIPDB IP reputation |
| `OTX_API_KEY` | IOC enrichment | AlienVault OTX indicator pulses |
| `SLACK_WEBHOOK_URL` | `--dispatch` | Per-finding Block-Kit alerts |
| `RAMEN_DISPATCH_WEBHOOK` | `--dispatch` | Generic JSON webhook alerts |
| `RAMEN_SMTP_HOST` + `..._FROM` + (`..._USER`, `..._PASS`, `..._USE_TLS`) | `--digest` | Daily-digest email |
| `RAMEN_DIGEST_TO` | `--digest` | Catch-all recipient for un-owned hosts |

1. Copy `config/env.example` to `.env` at the repo root.
2. Paste each key after its `=`.
3. The `.env` file is gitignored. Keys are redacted from logs and never serialized.

---

## Usage

The fastest way to try it is the interactive wizard — just run `python threat_intel_hunter.py` with no
arguments. It walks you through every prompt, lets you paste Windows or POSIX paths with quotes
or `~`, and lets you choose the output basename before files are written.

### Process an OPML feed list (or a directory of them)

```bash
python threat_intel_hunter.py opml examples/sample.opml
python threat_intel_hunter.py opml ~/feeds          # a directory of *.opml files
```

The OPML mode fetches every RSS/Atom feed listed in the file (or all `.opml` files in the
directory), extracts CVE IDs from each item, enriches them, and writes
`ramen-cve-<timestamp>.csv` and `ramen-cve-<timestamp>.md` to the current directory (override
with `--out-dir` and `--basename`).

### Scan a single URL

```bash
python threat_intel_hunter.py url https://krebsonsecurity.com/2024/04/some-article/
```

### Enrich named CVEs directly

```bash
python threat_intel_hunter.py cve CVE-2021-44228 CVE-2021-26855
python threat_intel_hunter.py cve --from-file my-cves.txt
```

### Ingest a STIX 2.1 bundle or TAXII collection

```bash
python threat_intel_hunter.py stix bundle.json
python threat_intel_hunter.py stix --taxii-url https://taxii.example/api1 \
                         --taxii-collection 00000000-0000-4000-8000-000000000001
```

### Threat-hunt workflow (PEAK / F3EAD style)

```bash
python threat_intel_hunter.py hunt list
python threat_intel_hunter.py hunt show log4shell-evidence
python threat_intel_hunter.py hunt link log4shell-evidence CVE-2021-45046
python threat_intel_hunter.py hunt log  log4shell-evidence "Saw nothing in proxy logs."
python threat_intel_hunter.py hunt status log4shell-evidence closed_true_positive
```

### Priority Intelligence Requirements

```bash
python threat_intel_hunter.py pir list
python threat_intel_hunter.py pir coverage
python threat_intel_hunter.py pir link log4j-exposure CVE-2021-44228
```

### Historical trend for a single CVE

```bash
python threat_intel_hunter.py trend CVE-2021-44228
```

Renders a Unicode sparkline of CVSS / EPSS over every cached run plus a Markdown table of
bucket-by-date.

### Audit log

```bash
python threat_intel_hunter.py audit
python threat_intel_hunter.py audit --tail 100
```

Every invocation of an analysis or workflow subcommand is recorded with the actor (from
`getpass.getuser()`), the redacted CLI args, and the return code — append-only, in the SQLite
cache file.

### Common flags

These apply to the analysis subcommands (`opml`, `url`, `cve`, `stix`):

| Flag | Default | What it does |
| --- | --- | --- |
| `--start YYYY-MM-DD` | none | Drop CVEs outside the date window |
| `--end   YYYY-MM-DD` | none | (paired with `--start`) |
| `--date-mode {feed,disclosure,epss}` | `feed` | Which date the window applies to |
| `--cvss-threshold N` | `7.0` | CVSS cutoff for "high severity" |
| `--epss-threshold N` | `0.10` | EPSS cutoff for "likely exploited" |
| `--out-dir PATH` | cwd | Output directory (quote-stripped, `~`-expanded) |
| `--basename NAME` | timestamped | Output filename stem (extension auto-handled) |
| `--format {csv,md,both,stix,sigma,yara,all}` | `both` | Output formats |
| `--no-cache` | false | Skip SQLite cache (always re-fetch) |
| `--no-exploit-lookup` | false | Skip Exploit-DB / Nuclei / GitHub PoC lookups |
| `--no-enrich-iocs` | false | Skip VT / AbuseIPDB / OTX / MalwareBazaar enrichment |
| `--ioc-confidence-floor F` | `0.0` | Drop IOCs whose decayed confidence < `F` (0.0–1.0) |
| `--inventory PATH` | none | CSV of `host,product,version,[cpe],[owner]` for asset correlation |
| `--sector NAME` | none | Drop CVEs whose only attribution targets a *different* sector |
| `--associations-file PATH` | bundled | Override the CVE→actor/malware lookup file |
| `--allow-tlp-red` | false | Permit writing TLP:RED records (otherwise stripped) |
| `--dispatch` | false | Push per-finding alerts to Slack / generic webhook |
| `--digest` | false | Batch-mail a daily digest per asset owner (SMTP via env) |
| `--quiet` | false | Suppress INFO logs |
| `--verbose` | false | Show DEBUG logs |

Three top-level flags (valid before any subcommand): `--config NAME`,
`--save-config NAME`, `--list-configs` (see below).

---

## YAML configuration & presets

Every flag above can be captured in a YAML file so a complex invocation
becomes a one-word command. The fully-commented schema lives at
`src/ramen_cve/config/config.yaml`; named presets live in
`src/ramen_cve/config/presets/<name>.yaml`.

**Save the current invocation as a preset:**

```bash
python threat_intel_hunter.py --save-config daily-hunt \
    opml ~/feeds --format all --cvss-threshold 8.0 --sector financial
# → writes src/ramen_cve/config/presets/daily-hunt.yaml
```

**Replay it later — CLI flags still override individual YAML values:**

```bash
python threat_intel_hunter.py --config daily-hunt
python threat_intel_hunter.py --config daily-hunt --format csv   # override one key
python threat_intel_hunter.py --config /abs/path/to/custom.yaml   # explicit file
```

**List every saved preset:**

```bash
python threat_intel_hunter.py --list-configs
```

Precedence is always **CLI flag > YAML value > built-in default**. A YAML
key left blank is ignored (it never clobbers a real CLI argument). The
config carries the subcommand too, so `--config daily-hunt` with no
positional subcommand runs exactly what was saved. See the template's
inline comments for every recognized key (`output`, `filters`,
`enrichment`, `cache`, `dispatch`, `email`, `logging`, `inventory_path`,
`remember_opml`, …).

### Email reports via YAML

Set the `email:` block in a preset to mail the day's findings as
attachments. When `email.enabled: true`, the preset's SMTP settings
populate the `RAMEN_SMTP_*` environment variables that the digest
dispatcher reads, and `--digest` is implicitly enabled:

```yaml
email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  smtp_user: alerts@example.com
  smtp_pass: ""                 # PREFER .env / keyring over plaintext YAML
  smtp_from: alerts@example.com
  smtp_use_tls: true
  fallback_recipient: soc@example.com
```

A real `.env` always wins over the YAML value (the loader uses
`os.environ.setdefault`), so production deployments keep secrets out of
the preset file.

---

## Scheduled / recurring runs

The `schedule` subcommand turns a saved preset into a recurring daily run.
It generates the **OS-native scheduler artefact** rather than running a
fragile long-lived daemon.

**Windows Task Scheduler:**

```bash
python threat_intel_hunter.py schedule windows-task \
    --for-config daily-hunt --time 06:15 \
    --task-name ramen-cve-daily --output task.xml
# then, in an elevated prompt:
schtasks /Create /TN ramen-cve-daily /XML task.xml
```

The emitted XML is a valid Task Scheduler 2.0 document with a daily
`CalendarTrigger` at `--time` and an `Exec` action that runs
`python threat_intel_hunter.py --config daily-hunt`.

**Linux / macOS cron:**

```bash
python threat_intel_hunter.py schedule cron --for-config daily-hunt --time 06:15
# → 15 6 * * * /path/to/python /path/to/threat_intel_hunter.py --config daily-hunt
crontab -e   # paste the line
```

Both forms accept `--python PATH` to pin the interpreter and `--output
FILE` to write to disk instead of stdout. A bundled GitHub-Actions
equivalent lives in `examples/github-actions-daily-triage.yml`.

---

## Bucket logic

Every CVE lands in exactly one bucket, checked top to bottom:

| Bucket | Condition | Action |
| --- | --- | --- |
| **KEV Override** | CISA KEV listed | Patch immediately — exploitation confirmed |
| **Patch Now** | CVSS ≥ threshold **and** EPSS ≥ threshold | High severity *and* likely exploited |
| **Plan and Patch** | CVSS ≥ threshold **and** EPSS < threshold | High severity, exploit unlikely so far |
| **Watch Closely** | CVSS < threshold **and** EPSS ≥ threshold | Low severity but actively exploited |
| **Deprioritize** | Everything else | Low severity + low exploitation probability |

The thresholds and decision tree are flat by design — they fit in the analyst's head.

---

## Outputs

A single run can produce up to six artefacts. Pick what you want with `--format`:

| Artefact | Trigger | Shape |
| --- | --- | --- |
| CVE CSV | `csv` / `both` / `all` | One row per CVE, 26 columns. |
| IOC CSV | `csv` / `both` / `all` (when IOCs found) | One row per non-CVE indicator. |
| Markdown report | `md` / `both` / `all` | Bucket sections + ATT&CK cross-tab + Linked Adversaries + Affected Hosts. |
| STIX 2.1 bundle | `stix` / `all` | Vulnerability + Note + Indicator + Identity SDOs. Deterministic UUIDv4 ids. |
| Sigma stubs | `sigma` / `all` | One YAML stub per KEV / Patch-Now CVE, pre-tagged. |
| YARA stubs | `yara` / `all` | One YARA rule scaffold per linked-malware family. |

`--basename my-report` writes `my-report.csv` / `my-report.md` / `my-report-iocs.csv` /
`my-report.stix.json` / `my-report-sigma/` / `my-report-yara/`. Existing files are never
overwritten; a `-1`, `-2`, … suffix is appended on collision. The user-supplied basename can
include a redundant extension (`my-report.csv`) — the writer strips it before re-applying the
right one, so you never end up with `my-report.csv.csv`.

---

## What's bundled

The repository ships with a working set of lookup data under
`src/ramen_cve/data/`. None of it is required — every default path can be overridden — but
the bundled values let `python threat_intel_hunter.py` work out of the box.

- `src/ramen_cve/data/associations.json` — 12 well-known CVEs (Log4Shell, ProxyLogon,
  PrintNightmare, ZeroLogon, EternalBlue, Follina, Pulse Secure, Fortinet, Sandworm
  PowerPoint, Outlook NTLM, Barracuda ESG) mapped to MITRE-Groups threat actors,
  ransomware operators, malware families, named campaigns, and per-actor sector targeting.
- `src/ramen_cve/data/hunts/log4shell-evidence.json` — sample threat-hunt hypothesis.
- `src/ramen_cve/data/pirs/log4j-exposure.json` — sample Priority Intelligence Requirement.

Add or correct entries directly in those JSON files; the package reads them on every run (paths resolve relative to `src/ramen_cve/data/`).

---

## What this is not (yet)

These would all fit cleanly but aren't shipped yet — see `docs/whitepaper.md` §8,
`docs/REFACTOR_PLAN.md`, and the two gap-analysis documents for the prioritized backlog:

- SSVC (Stakeholder-Specific Vulnerability Categorization) decision tree
- Native SIEM query generation (KQL / SPL / Elastic EQL)
- MISP-platform-native push / pull (via PyMISP)
- Bucket-transition delta detection (alert only when bucket *changes*)
- Vulnerability-scanner imports (Nessus / Qualys / Rapid7 native)
- Hunt analytics library (reusable per-ATT&CK-technique queries)
- Risk-weighted prioritization (CVE × asset criticality × exploit availability)
- Backtesting / replay mode

---

## License

MIT — see `LICENSE`.
