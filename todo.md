# tasks/todo.md — Ramen CVE v1

This is the implementation plan for `ramen_cve.py`, the OPML/URL/CVE → CVSS+EPSS triage tool described in the project design conversation. It follows the claude.md plan template: each slice is a thin vertical increment with explicit acceptance criteria and verification steps. Work top to bottom. Keep one task "in progress" at a time.

---

## Goal

Ship a single-file Python CLI (`ramen_cve.py`) that takes an OPML file, a single URL, or a list of CVE IDs as input; extracts CVE identifiers via regex; enriches each CVE with CVSS data from NVD and EPSS data from FIRST.org; buckets each CVE by exploitation likelihood and impact (with CISA KEV as a hard override); and produces both a CSV (tracker-ready) and a Markdown report (human-readable) as output.

---

## Acceptance criteria (whole project)

The v1 is done when all of the following are true:

- [ ] `python ramen_cve.py opml examples/sample.opml` produces a CSV and a Markdown report in the working directory without errors.
- [ ] `python ramen_cve.py url <url>` extracts CVEs from a single page and produces the same output formats.
- [ ] `python ramen_cve.py cve CVE-2021-44228 CVE-2021-26855` enriches the named CVEs and produces the same output formats.
- [ ] `--start` and `--end` flags filter the CVE set by the active date mode.
- [ ] `--date-mode {feed,disclosure,epss}` switches which date the filter applies to.
- [ ] All four base buckets and the KEV override bucket are correctly assigned per the design.
- [ ] CVSS and EPSS API calls are cached in SQLite with a 24-hour default TTL.
- [ ] No secrets are hardcoded; the NVD API key loads from `.env`.
- [ ] `ruff check .` passes with the project's configured rule set.
- [ ] `pytest` passes against the test suite.
- [ ] `README.md` covers install, key setup, three example invocations, and out-of-scope notes.

---

## Working notes (update as you go)

- Single file, target ~400 lines, hard ceiling 500 before considering refactor.
- Three runtime deps only: `requests`, `feedparser`, `python-dotenv`. Stdlib for everything else.
- Ruff for lint and format. Pytest for tests. No mypy in v1.
- All API calls fail soft. One bad CVE or one dead feed must never crash the run.
- Logging to stderr; CSV/MD paths are the only stdout output.

---

# Phase 0 — Repo scaffolding

## Slice 0.1: Repo structure and metadata

- [ ] Create the directory layout from `claude.md`:
  - `ramen_cve.py` (empty stub for now: shebang, module docstring, `if __name__ == "__main__": pass`)
  - `requirements.txt` with `requests`, `feedparser`, `python-dotenv` (pinned to caret/compatible-release ranges)
  - `requirements-dev.txt` with `pytest`, `ruff`
  - `.env.example` with `NVD_API_KEY=` placeholder and a comment pointing at the request-an-api-key URL
  - `.gitignore` covering `.env`, `*.db`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `*.egg-info/`, output files (`ramen-cve-*.csv`, `ramen-cve-*.md`)
  - `LICENSE` (MIT, copyright Danny Page)
  - `pyproject.toml` with the ruff config (line length 100, rules `E,F,W,I,UP,B,SIM`)
  - `tests/` directory with empty `__init__.py` and `test_ramen_cve.py` stub
  - `examples/` directory (empty for now)
  - `tasks/todo.md` (this file) and `tasks/lessons.md` (empty header only)

**Acceptance:** Repo opens cleanly in an editor. `ruff check .` runs against the empty stub and exits 0. `pytest` runs and reports zero tests collected.

**Verification:**
```
ruff check .
pytest
```

## Slice 0.2: Constants and module skeleton

- [ ] Open `ramen_cve.py` and add the top-of-file constants block:
  - `CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")`
  - `NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"`
  - `EPSS_API_BASE = "https://api.first.org/data/v1/epss"`
  - `DEFAULT_CVSS_THRESHOLD = 7.0`
  - `DEFAULT_EPSS_THRESHOLD = 0.10`
  - `DEFAULT_CACHE_PATH = ".ramen-cache.db"`
  - `DEFAULT_CACHE_TTL_HOURS = 24`
  - `USER_AGENT = "ramen-cve/0.1 (+https://github.com/cesiumskater)"`
- [ ] Add `from __future__ import annotations` at the top.
- [ ] Add the imports block (stdlib first, then third-party, alphabetical within each group).
- [ ] Add a module docstring summarizing what the tool does in 3-5 lines.
- [ ] Stub the dataclasses that will carry data through the pipeline:
  - `@dataclass class CveRecord` with fields for the input-side data (`cve_id`, `source`, `first_seen`, `first_seen_type`).
  - `@dataclass class EnrichedCve` extending CveRecord conceptually with NVD and EPSS fields plus the bucket and suggested action.
- [ ] Stub the four functions that will be the pipeline backbone, with docstrings only and `raise NotImplementedError` bodies:
  - `parse_opml(path: Path) -> list[FeedEntry]`
  - `extract_cves(text: str, source: str, first_seen: date) -> list[CveRecord]`
  - `enrich_cves(records: list[CveRecord], cache: Cache) -> list[EnrichedCve]`
  - `bucket_and_suggest(enriched: list[EnrichedCve], cvss_thr: float, epss_thr: float) -> list[EnrichedCve]`

**Acceptance:** File imports cleanly (`python -c "import ramen_cve"`). Ruff still passes. No runtime behavior yet.

**Verification:**
```
python -c "import ramen_cve"
ruff check .
```

---

# Phase 1 — CVE extraction (the cheapest, most testable layer)

## Slice 1.1: The CVE regex and extractor function

- [ ] Implement `extract_cves(text, source, first_seen)`:
  - Use the module-level `CVE_REGEX`.
  - `findall` across the text, deduplicate within the result, normalize to upper-case (`CVE-2024-1234` not `cve-2024-1234`).
  - Return `[CveRecord(cve_id=..., source=source, first_seen=first_seen, first_seen_type=...)]`.
  - The `first_seen_type` is determined by the caller and passed via the function signature; extractor does not decide it.
- [ ] Write unit tests in `tests/test_ramen_cve.py`:
  - Plain match: `"CVE-2021-44228 was bad"` → one record.
  - Multiple matches in one string → deduplicated.
  - Mixed case → normalized to upper-case.
  - No match → empty list.
  - Adjacent text doesn't break it: `"...CVE-2024-1234.See more..."` → one record.
  - Won't false-match on `CVE-` without digits or with too few digits.
  - Doesn't match seven-digit-plus IDs incorrectly: `CVE-2024-1234567` valid, `CVE-2024-12345678` should not match (regex caps at 7).

**Acceptance:** All extractor tests pass. The regex behavior is locked in by tests.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

## Slice 1.2: OPML parser (stdlib only)

- [ ] Implement `parse_opml(path: Path) -> list[FeedEntry]`:
  - Use `xml.etree.ElementTree`.
  - Walk `<outline>` elements recursively. Capture any element with an `xmlUrl` attribute.
  - Return `[FeedEntry(title=..., url=..., category=...)]` where category is the parent outline's `text` attribute (or empty string if at the root).
  - Skip elements without `xmlUrl` (those are folders/categories, not feeds).
  - Handle missing files and malformed XML by raising a clean `OpmlError` with a useful message.
- [ ] Add a tiny `examples/sample.opml` with 3-4 real feeds (Krebs RSS, CISA KEV RSS, Abuse.ch blog RSS, one nested under a category) for the smoke test in Phase 6.
- [ ] Tests:
  - Flat OPML with 2 feeds → 2 entries.
  - Nested OPML with categories → categories captured, feeds at all depths returned.
  - Outline elements without `xmlUrl` are skipped, not returned.
  - Malformed XML raises `OpmlError`, not a raw `ParseError`.

**Acceptance:** Both happy-path and error-path tests pass. `examples/sample.opml` validates as well-formed XML.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
python -c "import xml.etree.ElementTree as ET; ET.parse('examples/sample.opml')"
```

---

# Phase 2 — Caching layer (offline before online)

## Slice 2.1: SQLite cache wrapper

- [ ] Implement a small `Cache` class wrapping `sqlite3.connect()`:
  - `__init__(self, path: Path, ttl_hours: int)` creates the DB file if missing and runs the schema migration.
  - Two tables: `nvd_cache(cve_id TEXT PRIMARY KEY, payload_json TEXT, fetched_at TEXT)` and `epss_cache(cve_id TEXT, score_date TEXT, payload_json TEXT, fetched_at TEXT, PRIMARY KEY(cve_id, score_date))`.
  - `get_nvd(cve_id) -> dict | None` returns parsed JSON if cached and within TTL; otherwise `None`.
  - `set_nvd(cve_id, payload: dict)` upserts.
  - Parallel `get_epss(cve_id, score_date)` and `set_epss(cve_id, score_date, payload)`.
  - `purge()` clears entries older than TTL, used by `--no-cache` (which still writes to a fresh in-memory DB).
- [ ] Tests:
  - Round-trip: set then get returns the same payload.
  - Stale entry past TTL returns `None`.
  - In-memory mode (path = `:memory:`) works for the `--no-cache` flag.
  - Schema is idempotent (re-running `__init__` doesn't drop data).

**Acceptance:** Cache tests pass. The class is the only path for SQLite work; no raw `sqlite3` calls elsewhere in the file.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

---

# Phase 3 — Enrichment (the network layer, with mocks)

## Slice 3.1: NVD CVSS lookup

- [ ] Implement `fetch_nvd(cve_id: str, cache: Cache, api_key: str | None) -> dict`:
  - Cache hit short-circuits the network call.
  - On miss: GET `NVD_API_BASE?cveId={cve_id}` with `apiKey` header if key is provided, `User-Agent: USER_AGENT` always.
  - Sleep 0.6 seconds with key, 6.0 seconds without key, before each network call.
  - Parse the response: extract `cvssMetricV31` (preferred) or `cvssMetricV30` (fallback), capture `baseScore`, `baseSeverity`, `vectorString`. Capture `cisaExploitAdd` if present (KEV flag). Capture CWE list. Capture `published` date.
  - Return a normalized dict, not the raw NVD payload, so the cache layer is forward-compatible if NVD changes their schema.
  - On 4xx/5xx: log a warning, return a record with empty CVSS fields and `nvd_status="error"`. Do not raise.
- [ ] Tests with mocked HTTP (use `unittest.mock.patch` on `requests.get`):
  - Successful response with v3.1 metric → fields populated.
  - Successful response with only v3.0 metric → fields populated, version recorded.
  - Successful response with no CVSS metric (some old CVEs) → empty CVSS, no crash.
  - KEV-listed CVE → `kev_listed=True`.
  - 404 response → record with `nvd_status="error"`, empty CVSS.
  - Cache hit avoids the `requests.get` call (assert mock was not called).

**Acceptance:** All NVD tests pass. The function is the only place in the file that touches NVD HTTP.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

## Slice 3.2: EPSS lookup with batching

- [ ] Implement `fetch_epss(cve_ids: list[str], cache: Cache, score_date: str | None = None) -> dict[str, dict]`:
  - For each cached CVE, short-circuit. Collect the misses into a list.
  - Batch the misses in groups of 100. For each batch, GET `EPSS_API_BASE?cve=A,B,C[&date=YYYY-MM-DD]`.
  - Parse the `data` array; populate cache with `(cve_id, score_date or "current", payload)`.
  - Return `{cve_id: {"epss": float, "percentile": float, "date": str}}`.
  - On error: return an empty dict for that batch's CVEs, log warning.
- [ ] Tests with mocked HTTP:
  - 5 CVEs, all uncached → one batched request.
  - 105 CVEs, all uncached → two batched requests (100 + 5).
  - 50 CVEs with 30 cached → one request for 20.
  - All cached → zero requests.
  - Historical date passed → URL includes `&date=...`.
  - Empty input → empty output, no requests.

**Acceptance:** All EPSS tests pass. Batching behavior is verified by mock call count.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

## Slice 3.3: Combined enricher

- [ ] Implement `enrich_cves(records: list[CveRecord], cache: Cache, api_key: str | None) -> list[EnrichedCve]`:
  - For each unique CVE ID across the records, call `fetch_nvd`.
  - Call `fetch_epss` once with the deduplicated CVE list (uses the batching).
  - Merge NVD and EPSS data back onto each `CveRecord` (one CVE may appear multiple times across sources; preserve the source/first_seen of the earliest occurrence per the active date mode).
  - Return the merged `EnrichedCve` list.
- [ ] Test:
  - 3 records covering 2 unique CVEs (one duplicate) → 2 enriched records, with the source/first_seen merged correctly.

**Acceptance:** Combined enricher test passes. NVD and EPSS data is merged onto records without duplication.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

---

# Phase 4 — Scoring and bucket logic

## Slice 4.1: Bucket assignment

- [ ] Implement `bucket_and_suggest(enriched, cvss_thr, epss_thr)`:
  - For each record, compute the bucket using this exact precedence:
    1. If `kev_listed=True` → `kev_override`.
    2. Else if `cvss_score >= cvss_thr` and `epss_score >= epss_thr` → `patch_now`.
    3. Else if `cvss_score >= cvss_thr` and `epss_score < epss_thr` → `plan_and_patch`.
    4. Else if `cvss_score < cvss_thr` and `epss_score >= epss_thr` → `watch_closely`.
    5. Else → `deprioritize`.
  - Records missing CVSS or EPSS data: bucket is `unknown`, action is "Insufficient data; manual review."
  - For each bucket, attach a one-line `suggested_action` from a constant dict at module scope. The five strings are written down in `claude.md` and should match exactly.
  - Return the list with bucket and action populated.
- [ ] Tests covering every branch of the precedence:
  - KEV true + low scores → `kev_override` (KEV wins).
  - KEV false + high CVSS + high EPSS → `patch_now`.
  - KEV false + high CVSS + low EPSS → `plan_and_patch`.
  - KEV false + low CVSS + high EPSS → `watch_closely`.
  - KEV false + low CVSS + low EPSS → `deprioritize`.
  - Missing CVSS → `unknown`.
  - Missing EPSS → `unknown`.
  - Threshold edge cases: exactly at threshold counts as "high" (use `>=`).
  - Custom thresholds passed via flag actually change the bucket assignment.

**Acceptance:** All bucket tests pass. The precedence is locked in by tests, including edge cases.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

---

# Phase 5 — Date filtering

## Slice 5.1: Date filter

- [ ] Implement `filter_by_date(enriched, start, end, date_mode)`:
  - For `date_mode="feed"`: filter on `record.first_seen` where `first_seen_type == "feed_pub"`. Records with other types are kept (manual_input, url) only if their `first_seen` falls in range; explicitly note in the test that this is the intended behavior.
  - For `date_mode="disclosure"`: filter on `record.nvd_published`.
  - For `date_mode="epss"`: only allow `start == end` (single-day) in v1; raise a `ValueError` with a helpful message otherwise.
  - Records that fall outside the range are dropped, not flagged.
  - Records with a missing relevant date are logged and dropped (do not silently re-filter on a different date type).
  - `start` and `end` are both inclusive.
- [ ] Tests:
  - Feed mode with date in range → kept.
  - Feed mode with date outside range → dropped.
  - Feed mode with missing date → dropped, warning logged.
  - Disclosure mode uses NVD published date, not feed date.
  - EPSS mode with start != end raises.
  - Empty result set (zero matches) returns empty list, no crash.

**Acceptance:** All date filter tests pass. The "which date are we filtering on" decision is auditable from the tests.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

---

# Phase 6 — Output writers

## Slice 6.1: CSV writer

- [ ] Implement `write_csv(enriched, path)`:
  - Use the `csv` module with `quoting=csv.QUOTE_MINIMAL`.
  - 13 columns in the order specified in the design: `cve_id, source, first_seen, first_seen_type, cvss_score, cvss_severity, epss_score, epss_percentile, kev_listed, bucket, suggested_action, cwe, nvd_published, enriched_at`.
  - Empty values written as empty strings, not the literal `None`.
  - Numeric formatting: CVSS to one decimal, EPSS to four decimals, percentile to four decimals.
- [ ] Test:
  - Round-trip: write a list of EnrichedCve, read the CSV back, assert column count and a sampled value.
  - Suggested-action containing a comma is properly quoted.
  - Empty CVSS field round-trips as empty string.

**Acceptance:** CSV tests pass. File is openable in Excel and Google Sheets without column drift.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

## Slice 6.2: Markdown writer

- [ ] Implement `write_markdown(enriched, path, run_metadata)`:
  - Header block: title, generated timestamp, filter description, sources list, thresholds, total count.
  - Summary table: one row per bucket, count and action template.
  - Bucket sections in priority order: `kev_override`, `patch_now`, `watch_closely`, `plan_and_patch`, `deprioritize`, `unknown`.
  - Each CVE within a bucket renders as: H3 with the CVE ID, bold "Action:" line, then a bullet block with CVSS, EPSS, CWE, NVD published date, source(s).
  - Footer: tool version, command-line arguments used (with secrets redacted), API source citations.
- [ ] Test:
  - Empty input renders a valid Markdown report with "0 CVEs found" notice.
  - One CVE per bucket renders the expected section count.
  - The CVE ID appears exactly once per occurrence in the report.

**Acceptance:** Markdown tests pass. Report opens cleanly in any Markdown viewer.

**Verification:**
```
pytest tests/test_ramen_cve.py -v
```

---

# Phase 7 — CLI and end-to-end wiring

## Slice 7.1: argparse skeleton

- [ ] Build the `argparse.ArgumentParser` with three subcommands: `opml`, `url`, `cve`.
  - `opml` takes a positional path.
  - `url` takes a positional URL.
  - `cve` takes one or more positional CVE IDs, plus `--from-file` for a text-file list.
- [ ] Shared flags on all three subcommands: `--start`, `--end`, `--date-mode`, `--cvss-threshold`, `--epss-threshold`, `--out-dir`, `--format`, `--no-cache`, `--quiet`, `--verbose`.
- [ ] Validation:
  - Dates parse as ISO YYYY-MM-DD; reject anything else.
  - `--date-mode epss` requires `--start == --end`; reject otherwise with a clear message.
  - CVE positional arguments must match the regex; otherwise reject with the corrected format suggestion.
- [ ] Logging configured per `--quiet`/`--verbose` to stderr.
- [ ] Tests:
  - Each subcommand parses its own positional argument.
  - Invalid date format is rejected before any work runs.
  - Invalid CVE format is rejected before any work runs.

**Acceptance:** `python ramen_cve.py --help` shows all three subcommands cleanly. CLI argument validation has test coverage.

**Verification:**
```
python ramen_cve.py --help
python ramen_cve.py opml --help
pytest tests/test_ramen_cve.py -v
```

## Slice 7.2: Wire the pipeline together for `opml` mode

- [ ] In `main()`, dispatch on the subcommand.
- [ ] For `opml`:
  - Parse OPML → list of FeedEntry.
  - For each feed, fetch with `feedparser`, iterate items, run `extract_cves` on title+summary+content.
  - Build the deduplicated CveRecord list with `first_seen_type="feed_pub"`.
  - Filter by date.
  - Enrich.
  - Bucket.
  - Write CSV and/or Markdown per `--format`.
  - Print the output paths to stdout.

**Acceptance:** Running against `examples/sample.opml` with mocked APIs (network disabled) produces both output files. Smoke test in Phase 8 verifies end-to-end.

**Verification:**
```
python ramen_cve.py opml examples/sample.opml --start 2024-01-01 --end 2025-12-31
ls -la *.csv *.md
```

## Slice 7.3: Wire `url` mode

- [ ] For `url`:
  - GET the URL with `requests`, respecting the User-Agent header.
  - Extract publication date from `<meta property="article:published_time">`, `<time datetime=...>`, or `og:published_time` (in that order). Fall back to today's date with a logged warning if none found.
  - Run `extract_cves` on the response body.
  - Build CveRecord list with `first_seen_type="feed_pub"` (treat URL articles as feed-equivalent).
  - Same filter / enrich / bucket / write pipeline.

**Acceptance:** Running against a real CVE-bearing article produces output with the expected CVEs.

**Verification:** Manual integration run with one real URL.

## Slice 7.4: Wire `cve` mode

- [ ] For `cve`:
  - Validate input CVE IDs via the regex.
  - Build CveRecord list with `source="manual_input"`, `first_seen=today`, `first_seen_type="manual_input"`.
  - When `--date-mode` is `feed` (default) and inputs are manual, switch to `disclosure` automatically and log the switch.
  - Filter / enrich / bucket / write.

**Acceptance:** `python ramen_cve.py cve CVE-2021-44228` enriches one CVE and produces non-empty output.

**Verification:** Manual integration run with one or two real CVEs.

---

# Phase 8 — Smoke test, lint, and docs

## Slice 8.1: End-to-end smoke test

- [ ] Add `tests/test_smoke.py`:
  - Mock `requests.get` to return fixture JSON for NVD and EPSS for a known CVE set.
  - Run the full `opml` pipeline against `examples/sample.opml`.
  - Assert the CSV has at least one row, the Markdown has at least one bucket section, and both files exist at the expected paths.
- [ ] Add `tests/fixtures/` with a few mocked NVD and EPSS payloads for stable CVEs (Log4Shell, ProxyLogon, etc.).

**Acceptance:** `pytest` runs the smoke test offline in under 2 seconds.

**Verification:**
```
pytest -v
```

## Slice 8.2: Lint and format pass

- [ ] Run `ruff check . --fix` and review any auto-fixes.
- [ ] Run `ruff format .` to normalize style.
- [ ] Resolve any remaining lint warnings; suppress only with documented inline reasons.

**Acceptance:** `ruff check .` exits 0. `ruff format --check .` exits 0.

**Verification:**
```
ruff check .
ruff format --check .
```

## Slice 8.3: README

- [ ] Write `README.md` covering:
  - One-paragraph "what this is" pitched at a beginner-to-intermediate audience.
  - Install: `pip install -r requirements.txt`.
  - NVD key setup: copy `.env.example` to `.env`, paste key, link to the request page.
  - Three example invocations (one per subcommand) with expected output snippets.
  - The bucket logic explained in 5-7 lines with the same metaphor as the talk.
  - "What this is not" section listing the v2 future items from `claude.md` so users don't file issues for them.
  - Talk credit: "Companion code for the BSidesSLC 2026 talk 'Threat Intel on a Ramen Budget' by Danny Page (@cesiumskater)."

**Acceptance:** README renders correctly on GitHub. All commands in it actually work when executed.

**Verification:** Manual review against a fresh clone.

## Slice 8.4: Final integration run

- [ ] Run the tool live against:
  - The bundled `examples/sample.opml` with no date filter.
  - One real recent URL (a Krebs or BleepingComputer article).
  - Two manually specified CVEs (one KEV-listed, one not).
- [ ] Inspect the CSV and Markdown outputs by hand. Look for:
  - Bucket assignments make sense.
  - Suggested actions are appropriate.
  - No raw API errors or stack traces.
  - No secrets leaked in the report footer.
- [ ] Save one of the runs into `examples/sample-output.csv` and `examples/sample-report.md`.

**Acceptance:** All three runs succeed. Output files match what a reasonable analyst would expect. Bundled examples are committed.

**Verification:** Manual review of the three outputs.

---

# Future (out of scope for v1, do not start without explicit approval)

These are good ideas. They live here so we don't forget them, not because they're shipping in v1.

- HTML quadrant chart output (`--format html`).
- EPSS trajectory mode (`--trajectory` flag, time-series plot per CVE).
- One-level URL crawling (`--depth 1` for index pages and newsletters).
- Configurable bucket labels (rename `patch_now` → custom string for org-specific severity language).
- Output formats beyond CSV and Markdown (JSON, STIX 2.1, MISP event format).
- Slack / email / webhook delivery.
- A `--watch` mode that re-runs on a cron.
- Web UI.
- Refactor into a small package layout when the file passes 500 lines.

---

# Lessons (mirror to tasks/lessons.md as they're discovered)

This section captures things learned during build. After every user correction or postmortem, append an entry here AND to `tasks/lessons.md`.

(Empty until something is learned.)

---

# Results (fill in when v1 ships)

(To be completed at the end of Phase 8.)
