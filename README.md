# ramen-cve

A single-file Python CLI for threat intel triage on a ramen budget.

Give it an OPML feed list, a single article URL, or a list of CVE IDs. It extracts CVE
identifiers, enriches each with CVSS data from NVD and exploitation probability from EPSS
(FIRST.org), buckets every CVE into one of five action categories, and writes a CSV (for
tracker import) and a Markdown report (for human review). CISA KEV-listed CVEs are always
surfaced first, regardless of CVSS or EPSS scores.

Companion code for the BSidesSLC 2026 talk **"Threat Intel on a Ramen Budget"** by Danny Page
([@cesiumskater](https://github.com/cesiumskater)).

---

## Install

```bash
git clone https://github.com/cesiumskater/cti-cth-ramen-budget
cd cti-cth-ramen-budget
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows PowerShell
pip install -r requirements.txt
```

Or run the included setup script:

```bash
./setup.sh          # Linux/macOS
.\setup.ps1         # Windows PowerShell
```

---

## NVD API key setup

An NVD API key is optional but **strongly recommended** — without one you get 5 requests per
30 seconds (6-second pauses between CVEs). With a free key you get 50 requests per 30 seconds.

1. Request a free key at <https://nvd.nist.gov/developers/request-an-api-key>
2. Copy `.env.example` to `.env`
3. Paste your key after `NVD_API_KEY=`

The key is never printed, logged, or committed.

---

## Usage

### Process an OPML feed list

```bash
python ramen_cve.py opml examples/sample.opml
```

This fetches every RSS/Atom feed in the OPML file, extracts CVE IDs from item titles and
summaries, enriches them, and writes `ramen-cve-<timestamp>.csv` and
`ramen-cve-<timestamp>.md` to the current directory.

### Scan a single URL

```bash
python ramen_cve.py url https://krebsonsecurity.com/2024/04/some-article/
```

Fetches the page, extracts CVE IDs from the HTML, enriches them, and writes output files.

### Enrich named CVEs directly

```bash
python ramen_cve.py cve CVE-2021-44228 CVE-2021-26855
```

No feed fetching needed — just pass CVE IDs and get a triage report back.

### Common flags (all subcommands)

| Flag | Default | Description |
| --- | --- | --- |
| `--start YYYY-MM-DD` | none | Drop CVEs first seen before this date |
| `--end YYYY-MM-DD` | none | Drop CVEs first seen after this date |
| `--date-mode {feed,disclosure,epss}` | `feed` | Which date to filter on |
| `--cvss-threshold N` | `7.0` | CVSS score cutoff for "high severity" |
| `--epss-threshold N` | `0.10` | EPSS score cutoff for "likely exploited" |
| `--out-dir PATH` | `.` | Where to write output files |
| `--format {csv,md,both}` | `both` | Output format |
| `--no-cache` | false | Skip SQLite cache (always re-fetch) |
| `--quiet` | false | Suppress INFO logs |
| `--verbose` | false | Show DEBUG logs |

---

## Bucket logic

Every CVE lands in exactly one bucket, checked in this order:

| Bucket | Condition | Action |
| --- | --- | --- |
| **KEV Override** | CISA KEV listed | Patch immediately — exploitation confirmed |
| **Patch Now** | CVSS ≥ threshold AND EPSS ≥ threshold | High severity + likely exploited |
| **Plan and Patch** | CVSS ≥ threshold AND EPSS < threshold | High severity, exploit unlikely so far |
| **Watch Closely** | CVSS < threshold AND EPSS ≥ threshold | Lower severity but actively exploited |
| **Deprioritize** | Everything else | Low severity + low exploitation probability |

---

## What this is not

These features are good ideas but out of scope for v1. File an issue if you need them — they
may appear in a future release:

- HTML quadrant chart or dashboard output
- Multi-day EPSS trajectory plots
- Recursive URL crawling (`--depth 1`)
- Custom bucket labels or thresholds beyond CVSS/EPSS
- Output formats beyond CSV and Markdown (JSON, STIX 2.1, MISP)
- Slack/email/webhook delivery
- Scheduled/daemon mode
- A web UI

---

## License

MIT — see `LICENSE`.
