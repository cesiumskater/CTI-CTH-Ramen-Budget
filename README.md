# ramen-cve

CVE triage on a ramen budget — a single-file Python CLI for threat intelligence and threat
hunting teams who need a working pipeline before they have a working platform.

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
├── ramen_cve.py             # the implementation
├── README.md                # this file
├── LICENSE                  # MIT
├── CLAUDE.md                # project rules (for AI-assisted contributors)
├── pyproject.toml           # ruff config + project metadata
├── requirements.txt         # runtime deps (requests, feedparser, python-dotenv, questionary)
├── requirements-dev.txt     # dev deps (pytest, ruff)
├── .env.example             # copy to .env and fill in optional API keys
│
├── data/                    # bundled lookup data ramen_cve.py reads at runtime
│   ├── associations.json    #   CVE → threat-actor / campaign / malware (MITRE Groups)
│   ├── hunts/               #   one JSON per threat-hunt hypothesis
│   └── pirs/                #   one JSON per Priority Intelligence Requirement
│
├── docs/                    # design notes and gap analyses
├── examples/                # sample OPML feed list, sample CSV / Markdown outputs,
│                            #   GitHub-Actions scheduled-triage workflow
├── scripts/                 # one-line venv-and-install bootstrap for both shells
│   ├── setup.sh             #   Linux / macOS
│   └── setup.ps1            #   Windows PowerShell
├── tasks/                   # in-flight engineering plan + lessons.md
└── tests/                   # 400+ pytest cases + fixtures
```

---

## Install

```bash
git clone https://github.com/cesiumskater/cti-cth-ramen-budget
cd cti-cth-ramen-budget
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows PowerShell
pip install -r requirements.txt
```

Or run the bundled bootstrap:

```bash
./scripts/setup.sh                 # Linux / macOS
.\scripts\setup.ps1                # Windows PowerShell
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

1. Copy `.env.example` to `.env`.
2. Paste each key after its `=`.
3. The `.env` file is gitignored. Keys are redacted from logs and never serialized.

---

## Usage

The fastest way to try it is the interactive wizard — just run `python ramen_cve.py` with no
arguments. It walks you through every prompt, lets you paste Windows or POSIX paths with quotes
or `~`, and lets you choose the output basename before files are written.

### Process an OPML feed list (or a directory of them)

```bash
python ramen_cve.py opml examples/sample.opml
python ramen_cve.py opml ~/feeds          # a directory of *.opml files
```

The OPML mode fetches every RSS/Atom feed listed in the file (or all `.opml` files in the
directory), extracts CVE IDs from each item, enriches them, and writes
`ramen-cve-<timestamp>.csv` and `ramen-cve-<timestamp>.md` to the current directory (override
with `--out-dir` and `--basename`).

### Scan a single URL

```bash
python ramen_cve.py url https://krebsonsecurity.com/2024/04/some-article/
```

### Enrich named CVEs directly

```bash
python ramen_cve.py cve CVE-2021-44228 CVE-2021-26855
python ramen_cve.py cve --from-file my-cves.txt
```

### Ingest a STIX 2.1 bundle or TAXII collection

```bash
python ramen_cve.py stix bundle.json
python ramen_cve.py stix --taxii-url https://taxii.example/api1 \
                         --taxii-collection 00000000-0000-4000-8000-000000000001
```

### Threat-hunt workflow (PEAK / F3EAD style)

```bash
python ramen_cve.py hunt list
python ramen_cve.py hunt show log4shell-evidence
python ramen_cve.py hunt link log4shell-evidence CVE-2021-45046
python ramen_cve.py hunt log  log4shell-evidence "Saw nothing in proxy logs."
python ramen_cve.py hunt status log4shell-evidence closed_true_positive
```

### Priority Intelligence Requirements

```bash
python ramen_cve.py pir list
python ramen_cve.py pir coverage
python ramen_cve.py pir link log4j-exposure CVE-2021-44228
```

### Historical trend for a single CVE

```bash
python ramen_cve.py trend CVE-2021-44228
```

Renders a Unicode sparkline of CVSS / EPSS over every cached run plus a Markdown table of
bucket-by-date.

### Audit log

```bash
python ramen_cve.py audit
python ramen_cve.py audit --tail 100
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

The repository ships with a working set of lookup data under `data/`. None of it is required —
every default path can be overridden — but the bundled values let `python ramen_cve.py` work
out of the box.

- `data/associations.json` — 12 well-known CVEs (Log4Shell, ProxyLogon, PrintNightmare,
  ZeroLogon, EternalBlue, Follina, Pulse Secure, Fortinet, Sandworm PowerPoint, Outlook NTLM,
  Barracuda ESG) mapped to MITRE-Groups threat actors, ransomware operators, malware
  families, named campaigns, and per-actor sector targeting.
- `data/hunts/log4shell-evidence.json` — sample threat-hunt hypothesis.
- `data/pirs/log4j-exposure.json` — sample Priority Intelligence Requirement.

Add or correct entries directly in those JSON files; `ramen_cve.py` reads them on every run.

---

## Scheduled / batched usage

`examples/github-actions-daily-triage.yml` is a copy-and-paste-ready GitHub Actions workflow
that runs the OPML pipeline on a cron schedule and uploads the resulting artefacts. Same
shape works for cron / systemd timers / Azure DevOps / Jenkins / Bamboo.

---

## What this is not (yet)

These would all fit cleanly but aren't shipped in this branch — see `docs/REFACTOR_PLAN.md`
and the two gap-analysis documents for the prioritized backlog:

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
