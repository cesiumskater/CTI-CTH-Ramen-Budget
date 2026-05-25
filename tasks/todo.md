# Todo

The operational ledger for ongoing and future work, paired with
[`tasks/lessons.md`](lessons.md) (failure modes captured during work).
See `docs/CLAUDE.md` (Task Management + Templates) for conventions
and `docs/REFACTOR_PLAN.md` for completed refactor history.

> **Status (May 20, 2026):** monolith-split refactor closed (PRs #20
> + #21 + #22 on `main`). Below: 8 priority-ordered task plans, each
> spec-ready for a fresh engineer to pick up — goal, acceptance
> criteria, leveraged seams, design, implementation slices, test
> strategy, verification gate, risks, effort estimate.

---

## In progress

### Task 7 — Configurable bucket labels / thresholds (Slice A in progress)

- [ ] **Slice A — `BucketPolicy` leaf + façade lock.** New
      `src/ramen_cve/bucket_policy.py` (L1, depends only on
      `constants`): `BucketSpec` (frozen dataclass: id, label, action,
      order, optional per-bucket cvss/epss thresholds), `BucketPolicy`
      (frozen dataclass with `default_cvss_threshold`,
      `default_epss_threshold`, `buckets: dict[str, BucketSpec]`),
      `DEFAULT_BUCKET_POLICY` mirroring today's hardcoded
      `BUCKET_ACTIONS`/`BUCKET_DISPLAY`/`BUCKET_ORDER`, and
      `BucketPolicy.from_yaml(dict)` (merges user overrides over
      defaults; degrades to defaults when block absent). Re-export via
      `__init__.py`; `test_facade.py` PUBLIC_API extended; new
      `tests/test_bucket_policy.py` covering default identity, partial
      YAML overrides, KEV-bucket immutability, unknown-bucket rejection,
      per-bucket threshold fallback. No integration change yet — golden
      byte-oracle must remain identical.
- [ ] **Slice B — `bucket_and_suggest(policy=…)` backward-compat.**
      `analyze.bucket_and_suggest` gains an optional `policy:
      BucketPolicy | None = None` kw arg. When None, construct an
      ad-hoc policy from the existing `cvss_thr`/`epss_thr` args
      (preserves byte-identical fallback). When a policy is supplied,
      use its per-bucket thresholds. Four existing CLI call sites
      unchanged. Golden oracle must remain identical.
- [ ] **Slice C — YAML loader integration.** `apply_yaml_config`
      reads the optional `buckets:` block and stamps
      `args.bucket_policy: BucketPolicy`. New tests for a preset with
      custom buckets.
- [ ] **Slice D — output integration.** `write_markdown` accepts
      optional `policy: BucketPolicy | None`; when supplied, iterates
      `policy.display_order()` for sectioning and uses `spec.label` /
      `spec.action`. CLI threads `args.bucket_policy` through. CSV
      unchanged (bucket id is what's serialised, not the label).
      Golden oracle remains identical when no `buckets:` block is
      present.
- [ ] **Slice E — `aggressive.yaml` showcase preset.** Under
      `src/ramen_cve/config/presets/`: stricter per-bucket thresholds
      and rewritten action prose, demonstrating end-to-end
      customisation. Loaded via `--config aggressive`.

### Task 1 — EPSS trajectory mode (Slice A landed; B/C/D pending)

- [x] **Slice A — model + per-date fetch loop + CLI plumbing.** Added
      `EnrichedCve.epss_trajectory: dict[str, dict]` (defaults empty,
      preserves byte-identical contract for single-date / no-range runs).
      `enrich_cves` gains `epss_date_range: tuple[date, date] | None`;
      when start != end it loops `fetch_epss(score_date=d)` per day in
      the inclusive range and accumulates the time-series, pinning the
      scalar `epss_*` fields to the END-date value. Relaxed the
      `_validate_args` and `filter_by_date` `start == end` constraint
      for `--date-mode epss`. New `cli._epss_date_range_for(args)`
      helper threads the range into the four `enrich_cves` call sites.
      Verification: 470 passed (was 463 + 7 new trajectory tests in
      `tests/test_epss_trajectory.py`), ruff clean, golden byte-oracle
      byte-identical to anchor (`CSV 3fd1ac95`, `MD e9779ffc`).
- [x] **Slice B — sidecar CSV.** `EPSS_TRAJECTORY_COLUMNS` +
      `write_epss_trajectory_csv` added to `output/csv_writer.py`;
      one row per `(cve_id, date, epss, percentile)`, rows sorted for
      byte-stable output. `pipeline._output` emits
      `<basename>-epss-trajectory.csv` whenever any record has a
      non-empty trajectory dict. L3 façade re-export updated;
      test_facade contract list updated. +4 tests (writer-direct
      basic / skip-empty / sort, plus pipeline-level emit-iff-present
      integration). Verification: 474 passed, ruff clean, golden
      byte-identical (sidecar suppressed when no trajectory).
- [x] **Slice C — Markdown sparkline + table; `_sparkline` lift.**
      Lifted `_SPARKLINE_CHARS` + `_sparkline` from `trend.py` (L4)
      into a new `render.py` L1 leaf so `output/markdown.py` (L3) can
      reuse them without an upward import. `trend.py` re-imports the
      symbols (back-compat; `ramen_cve.trend._sparkline` and the
      façade re-export keep resolving). `write_markdown` now appends a
      `**EPSS trajectory:** \`<sparkline>\` (start → end, N samples)`
      bullet for any record with a non-empty trajectory dict, plus a
      compact inline date/EPSS/percentile table when N ≤ 10 (above
      that, the sparkline alone — the full series lives in the
      Slice-B sidecar CSV). +4 tests (sparkline-lift identity,
      trajectory section emitted, omitted when no trajectory, table
      suppressed when long). Verification: 478 passed, ruff clean,
      golden CSV+MD byte-identical to the post-Step-18 anchor (no
      trajectory in the smoke fixture → markdown unchanged).
- [x] **Slice D — volume guard.** Added the constants
      `EPSS_TRAJECTORY_WARN_THRESHOLD=200` and
      `EPSS_TRAJECTORY_ABUSE_THRESHOLD=500` to
      `enrich/orchestrator.py`. Pre-loop, `enrich_cves` computes
      `projected = days × ceil(N_cves / 100)`; ≥ WARN logs a WARNING
      and proceeds, ≥ ABUSE raises `ValueError` unless the new
      `confirm_large_trajectory: bool = False` parameter is True.
      The CLI side adds a `--allow-large-epss-trajectory` flag
      (shared across all four runners). +5 tests (error at abuse,
      bypass with flag, warn-band logging, silent below warn, and
      end-to-end CLI flag threading via a spy on `enrich_cves`).
      Verification: 483 passed (20 trajectory tests total across
      Slices A–D), ruff clean, golden CSV+MD byte-identical to anchor.

**Task 1 status: COMPLETE.** EPSS trajectory mode is shipped end-to-
end (model + per-date fetch + sidecar CSV + Markdown sparkline/table
+ volume guard). PR #24 carries all four slices; opt-in via
`--date-mode epss` with a multi-day `--start`/`--end`.

---

## Planned (priority-ordered)

Picking order set by the project owner. Within each task, slices are
sequenced for thin-vertical delivery (CLAUDE.md §3): smallest safe
end-to-end slice first, then expand. Verification gates per slice.

---

### 1. EPSS trajectory mode

**Goal.** Extend `--date-mode epss` to accept a date range and return
**time-series EPSS scores** per CVE across that range (vs. today's
single-date support). Enables exploitation-likelihood trend analysis
during triage.

**Acceptance.**
- `ramen-cve opml feed.opml --date-mode epss --start 2024-01-01 --end 2024-06-01`
  enriches every CVE with EPSS scores for every date in the range
  (existing single-date invocation — `--start == --end` — still works
  byte-identically; this is the backwards-compat gate).
- A new optional sidecar CSV `<basename>-epss-trajectory.csv`
  (one row per CVE-date) is emitted when the range spans > 1 day.
- The Markdown report shows a compact sparkline + a small table per
  CVE in the trajectory window, mirroring the existing `trend.py`
  sparkline aesthetic.
- Offline reproducible via the mocked-pipeline harness (extended
  fixture).

**Leveraged seams (post-refactor).**
- Fetch: `src/ramen_cve/enrich/epss.py` — `fetch_epss(cve_ids, cache,
  score_date=None)` already accepts an optional `score_date`. Batches
  ≤100 CVEs per call; rate-limit handled inside.
- Cache: `src/ramen_cve/cache.py` — `epss_cache(cve_id, score_date)`
  PRIMARY KEY **already supports per-date entries**. No schema
  migration.
- CLI parse: `cli.py` `build_parser()` defines `--date-mode` with
  choices `feed|disclosure|epss`; the `start == end` constraint for
  EPSS mode lives in `_validate_args` and `analyze.filter_by_date`.
- Output: `output/csv_writer.py` `CSV_COLUMNS` (the contract); the
  sparkline pattern lives in `trend.py` (`_SPARKLINE_CHARS`,
  `_sparkline`).
- Sparkline rendering exists in `src/ramen_cve/trend.py:_sparkline`
  — reuse, don't duplicate.
- Test fixtures: `tests/fixtures/epss_batch.json` (current);
  extend with `epss_trajectory.json` (multi-date payload).

**Design — key decisions.**

1. **Storage on the model.** Add `epss_trajectory: dict[str, dict] =
   field(default_factory=dict)` to `EnrichedCve`
   (`src/ramen_cve/models.py`) — keyed by ISO date string, value
   `{"epss": float, "percentile": float}`. Empty dict when the run is
   single-date (preserves current shape). The existing scalar
   `epss_score` / `epss_percentile` / `epss_date` fields keep
   pointing at the most-recent date in the trajectory.
2. **CLI shape.** **Reuse `--date-mode epss` with a range.** Don't
   invent a new flag. The current `start == end` constraint becomes:
   if `date_mode == "epss"` and `start != end`, trigger trajectory
   mode (fetch per day in the range); if `start == end`, behaviour is
   bit-for-bit identical to today.
3. **Output.** Sidecar CSV `<basename>-epss-trajectory.csv` only when
   the trajectory has > 1 entry. Markdown adds a 1-line sparkline +
   3-line table directly under the EPSS line per CVE. Main
   `<basename>.csv` schema unchanged (compatibility win for
   downstream consumers).
4. **Fetch strategy.** Iterate dates ascending; for each date, batch
   the full CVE list (≤100 per call). Cache hits per `(cve_id,
   score_date)` skip the API; only misses go over the wire.
5. **Volume guard.** `(end - start).days × ceil(len(cves) / 100)` API
   calls. Warn at `>= 200` projected calls; error out at `>= 500`
   unless `--epss-trajectory-yes` flag is also passed (foot-gun
   protection; FIRST.org rate-limits aggressively).
6. **Filtering semantics.** `filter_by_date` continues to gate
   inclusion using the *most recent* (end-date) EPSS score, so the
   selected CVEs are the same as a single-date `--end` run. The
   trajectory is *additional* context, not a different filter.

**Implementation slices.**

1. **Slice A — model + fetch loop (smallest end-to-end).**
   - Add `epss_trajectory` field to `EnrichedCve`.
   - In `enrich/orchestrator.py`, when `args.date_mode == "epss"` and
     `args.start != args.end`, loop `fetch_epss(..., score_date=d)`
     for each `d` in `daterange(start, end)`, populating the
     trajectory dict and setting the scalar fields to the `end` value.
   - Relax `_validate_args` / `filter_by_date` to allow the range.
   - Verify: single-date run still byte-identical to anchor (golden
     oracle); a 2-date range populates the trajectory dict.
2. **Slice B — sidecar CSV.**
   - New writer in `output/csv_writer.py`: `write_epss_trajectory_csv`
     (one row per `(cve_id, date, epss, percentile)`).
   - `pipeline._output` invokes it whenever any record has a
     non-empty trajectory dict.
   - CSV columns locked in a new `EPSS_TRAJECTORY_COLUMNS` tuple
     (consumer contract).
3. **Slice C — Markdown enhancement.**
   - In `output/markdown.py`, after the existing EPSS line, when a
     trajectory exists: emit `<sparkline>  <first-date>→<last-date>
     (<n> samples)` then a compact 3-column inline table.
   - Reuse `trend._sparkline` (import as a sibling — `output` → `trend`
     is L3→L4 sibling; if that's awkward, **lift `_sparkline` into a
     new `ramen_cve/util/render.py`** as L1 leaf and have both
     consumers import from there).
4. **Slice D — volume guard + UX.**
   - Pre-flight count, log a warning at the threshold, hard error
     above the abuse-protection threshold.
   - Document in `--help` of `--date-mode`.

**Test strategy.**
- Extend `tests/fixtures/` with `epss_trajectory.json` (multi-date,
  4 records).
- New `tests/test_epss_trajectory.py`:
  - `test_trajectory_disabled_when_start_equals_end` — byte-identical
    output to single-date (golden oracle).
  - `test_trajectory_populates_dict` — 3-date range, 2 CVEs, mock
    branches by `params["date"]`, assert `epss_trajectory` keys.
  - `test_trajectory_csv_sidecar_emitted_only_when_multi_date`.
  - `test_trajectory_volume_guard_warns_above_threshold`.
  - `test_trajectory_volume_guard_errors_above_abuse_threshold`.
- Mock branch in `test_smoke.py`'s `_epss_side_effect`: return a
  date-keyed subset.

**Verification gate (per slice + final).**
- `pytest tests/ -q` → 463 (existing) + new tests.
- `ruff check threat_intel_hunter.py conftest.py src/ tests/` → clean.
- Golden byte-oracle on single-date invocation → byte-identical to
  anchor.
- Manual smoke: `ramen-cve opml examples/sample.opml --date-mode epss
  --start 2024-01-01 --end 2024-01-03 --no-cache` (mocked or live)
  produces both files.

**Risks & flags.**
- EPSS API rate limits on FIRST.org (mitigated by the volume guard).
- Trajectory dict serialised through the Cache run-history table is
  large per record — keep it out of the runs table; only persist
  scalars there.
- Multi-day historical data in EPSS sometimes has gaps (model dates,
  not calendar dates) — fail-soft per missing date; trajectory entry
  becomes `{date: null}` markers in the sidecar.

**Effort.** **8–12 focused hours** for the full implementation
(8 h MVP through Slice B; +2 h Markdown; +1–2 h guard/UX).

---

### 2. Multi-page URL crawling (`--depth 1`) — DONE (PR #25, merged)

**Goal.** When the `url` input mode is given `--depth 1`, follow
**same-host links one hop** from the seed page and extract CVEs/IOCs
from all collected pages, not just the seed.

**Acceptance.**
- `ramen-cve url https://example.com/post --depth 0` is **byte-
  identical** to today's `url` mode (no behaviour change at the
  default).
- `... --depth 1` fetches the seed, extracts every same-host
  `<a href>`, deduplicates + sorts (deterministic), caps at a safety
  budget (default 25 followed links), rate-limits per host, and
  feeds all collected text through `extract_cves` / `extract_iocs`.
- Failures on a followed link are fail-soft (log a WARNING, skip,
  continue).
- New `--max-crawl-links N` (default 25) and `--crawl-delay-ms M`
  (default 500) flags.

**Leveraged seams (post-refactor).**
- `cli._run_url` (`src/ramen_cve/cli.py:724-786`) — the entire URL
  flow: fetch → date extraction → `extract_cves` / `extract_iocs` →
  enrich → output. Single page; no loop today.
- `extract.extract_cves(text, source, …)` is text-agnostic; can be
  invoked per page.
- The proven rate-limit pattern: `enrich/nvd.py:31-36` uses
  `time.monotonic()` tracked via a function attribute. Mirror it.
- Patch seam: `patch("ramen_cve.requests.get", side_effect=_fake_get)`
  + `patch("ramen_cve.time.sleep")` (existing tests use this).
- `keyring._safe_url_for_log` — already redacts query-string secrets;
  log followed URLs through it.

**Design — key decisions.**

1. **Link extraction strategy.** **Stdlib only — tight `re` for
   `<a\s+[^>]*href=["\']?([^"\'>\s]+)` + `urllib.parse.urljoin`.**
   Do NOT add `beautifulsoup4`. Rationale: 4 runtime deps today
   (`requests`, `feedparser`, `python-dotenv`, `questionary`,
   `PyYAML`) — adding a 6th for one regex is contra to the
   ramen-budget ethos. The regex catches ≥95 % of real-world `<a>`
   tags; the remaining 5 % (computed-href JavaScript, exotic
   attribute orderings) is not worth a dep.
2. **Same-host filter.** `urlparse(...).netloc.lower().lstrip("www.")`
   on both URLs. Port mismatch is treated as different host
   (intentional — different service). Unparseable URLs are rejected.
3. **Budget.** Default 25 links/seed; configurable via
   `--max-crawl-links`. Hard ceiling 200 (prevent foot-gun).
4. **Ordering.** Sorted, lowercased URLs → deterministic test
   output, deterministic dedupe.
5. **Per-host rate limit.** Mirror the `_last_call`
   function-attribute pattern from `fetch_nvd`. Default 500 ms
   between fetches (configurable). All followed links are
   same-host by definition, so one global per-host bucket suffices.
6. **CSV/Markdown impact.** Each extracted CVE keeps its **seed**
   URL as `source` (existing field) so downstream consumers don't
   see schema churn. The Markdown report's "Sources" section lists
   *all crawled URLs* (seed + followed), so users can see what
   was visited.
7. **CLI flag.** `--depth {0,1}` (default 0, max 1 in v1; choices
   restricts user foot-gun). Promote to `--depth N` later if a real
   need emerges.

**Implementation slices.**

- [x] **Slice A — pure helpers, no integration (testable in
  isolation).** Added `_HREF_RE`, `_extract_links(html, base_url)`,
  `_same_host(url1, url2)`, `_filter_and_cap_links(seed, html, cap)`
  to `src/ramen_cve/extract.py` (~80 LOC), plus
  `DEFAULT_MAX_CRAWL_LINKS=25` and `MAX_CRAWL_LINKS_CEILING=200`
  constants. Pure stdlib (`re` + `urllib.parse`); no new dep. New
  `tests/test_url_crawl.py` with 19 cases covering link extraction,
  same-host edge cases (www-stripping, port mismatch, case, blank /
  unparseable), dedupe + sort, cap argument, ceiling clamp, default
  cap, and negative-cap → empty. Verification: 482 passed (463 + 19
  new), ruff clean, golden byte-identical to anchor.
- [x] **Slice B — rate-limited fetch helper.** Added
   `_fetch_url_with_rate_limit(url, delay_ms=500)` to `cli.py`,
   mirroring `enrich/nvd.py:fetch_nvd`'s `_last_call`
   function-attribute pattern. Uses `time.monotonic()` for elapsed
   timing and `time.sleep()` for the throttle — resolved through the
   shared `time` module so `patch("ramen_cve.time.sleep")` continues
   to work. Raises `OpmlError` with a `_safe_url_for_log`-redacted
   URL on any HTTP-level failure so callers can fail-soft per
   followed link via a single except clause. Added `import time` to
   `cli.py`. +5 tests (returns text, raises on HTTP error, throttles
   second call, zero delay skips sleep, secret-redaction in error).
   Verification: 487 passed (482 + 5), ruff clean, golden
   byte-identical.
- [x] **Slice C — wire into `_run_url`.** Added `--depth {0,1}`
   (default 0), `--max-crawl-links` (default 25, hard ceiling 200),
   and `--crawl-delay-ms` (default 500) to the `url` subparser.
   Refactored `_run_url`: fetches the seed via the
   `_fetch_url_with_rate_limit` helper from Slice B; on `--depth 1`,
   feeds the seed HTML through `_filter_and_cap_links` then loops
   per-link fetches (same throttle); CVE/IOC extraction runs over
   the union of every visited page with that page's URL stamped as
   `source` so downstream attribution stays per-page-correct. +7
   integration tests (depth-0 byte-identical seed-only path; depth-1
   follows same-host links; depth-1 skips off-host links; depth-1
   fail-soft on followed 4xx/5xx; depth-1 respects --max-crawl-links
   cap; depth-0 `sources` metadata = [seed]; depth-1 `sources`
   metadata = every visited URL).
- [x] **Slice D — error robustness + UX** (folded into Slice C; same
   integration site). Per-link failure raises `OpmlError` inside the
   fetch helper; the loop catches it, logs a WARNING via the
   `_safe_url_for_log`-redacted message, and continues with the next
   link. The run metadata's `sources` list now enumerates every
   visited URL (seed + followed), so the Markdown report's
   "## Sources" section is a faithful per-run audit trail. At
   `--depth 0` this is exactly `[args.url]` — byte-identical to
   pre-feature output. Verification: 494 passed (487 + 7 new), ruff
   clean, golden byte-identical.

**Task 2 status: COMPLETE.** Multi-page URL crawl is shipped
end-to-end (link extraction primitives + rate-limited fetch helper +
`_run_url` integration + per-link fail-soft + Sources enumeration).
PR #25 carries Slices A–D; opt-in via `--depth 1` on the `url`
subcommand.

**Test strategy.**
- `tests/test_url_crawl.py`:
  - `test_depth_0_is_byte_identical` — same as today.
  - `test_depth_1_follows_same_host_links` — fake_get branches on
    URL, seed has 2 same-host links, expect both CVEs.
  - `test_depth_1_skips_other_hosts` — seed links go off-host;
    none are followed.
  - `test_depth_1_caps_at_max_crawl_links`.
  - `test_depth_1_rate_limits_via_sleep` — assert `time.sleep` was
    invoked between fetches (mocked).
  - `test_depth_1_failsoft_on_404` — one followed link 404s; run
    still exits 0.

**Verification gate.**
- `pytest tests/ -q` → existing 463 + ~6 new tests.
- `ruff` clean.
- Manual: against a fixed mock-page bundle.

**Risks & flags.**
- A poorly-chosen seed can still generate 25 outbound HTTP requests.
  Default safer than today (1 request); cap protects against
  malicious / runaway seeds.
- Tight-regex link extraction misses computed-href JS; acceptable.
- No `robots.txt` check in v1; documented as a future enhancement
  (rare on triage-target news sites, but flag in `--help`).

**Effort.** **~8 focused hours** (2 helpers + tests; 1.5 integration;
1 rate-limit; 2.5 test suite; 1 polish).

---

### 3. Long-running daemon mode — DONE (PR #26, merged)

**Goal.** Add a `daemon` subcommand that runs the pipeline at fixed
intervals (e.g., every 6 h) in a single long-lived process. Today
the `schedule` subcommand only **emits** a cron line / Windows Task
XML for an external scheduler; this complements (does not replace)
that.

**Acceptance.**
- `ramen-cve daemon --for-config daily-opml --interval 21600` runs
  the pipeline (loading the preset), sleeps, repeats, and stops
  gracefully on SIGTERM/SIGINT after finishing the in-flight run.
- `--max-runs N` (default `-1` = infinite) bounds iterations
  (critical for testing).
- Per-run outputs go to a **timestamped subdirectory**
  (`<out-dir>/ramen-cve-<iso-ts>/...`) so history is preserved.
- Optional `--prune-after-days N` deletes timestamped output
  directories older than N days (default off).
- Optional `--jitter SECONDS` adds ±jitter to the interval.

**Leveraged seams (post-refactor).**
- `src/ramen_cve/schedule.py` — existing `_emit_cron_line`,
  `_emit_windows_task_xml`, `_run_schedule`, `_build_schedule_command`.
  The daemon code mirrors the function-naming style.
- `src/ramen_cve/cli.py:main` dispatches subcommands via
  `_audit_dispatch(cache, "<name>", args, lambda: _run_<name>(...))`.
- `_run_opml` / `_run_url` / `_run_cve` are already designed to be
  one-shot; the daemon invokes whichever the preset selects.
- `Cache(path)` (`src/ramen_cve/cache.py`) — re-openable; safe to
  hold one instance across iterations.
- Façade-level `import ramen_cve` deferred-import seam in `main()`
  (§5.2) — daemon must respect it (no module-top facade ref).

**Design — key decisions.**

1. **Scheduler choice.** **Pure stdlib `while + sleep + signal`**
   (≈30 LOC). No `apscheduler` for v1 — that's a 6th runtime dep
   for a feature that doesn't need cron expressions yet. If cron
   expressions become a hard requirement, revisit in v2.
2. **In-process safety considerations (every iteration).**
   - **Logging:** call `_configure_logging` ONCE at daemon start,
     not per iteration (`basicConfig` after-first-call is a no-op
     but explicit is better).
   - **Cache:** keep ONE `Cache(path)` across all iterations (don't
     re-instantiate — avoids fd churn).
   - **Args namespace:** the pipeline stashes `args._inventory_rows`
     as a side-effect (`pipeline.py:117/131`). Reset this on every
     iteration to avoid carry-over. Document the contract.
   - **Env vars:** `load_dotenv()` once at start. NVD_API_KEY,
     SLACK_WEBHOOK_URL, SMTP_PASSWORD live in `os.environ` for the
     daemon's lifetime — document this as a known long-life
     secret-exposure risk; recommend containerised secrets in prod.
3. **Lifecycle.** SIGTERM/SIGINT set a `_daemon_should_stop = True`
   flag inside the handler; the loop checks the flag **after each
   pipeline run completes** (don't interrupt mid-enrichment — partial
   outputs are worse than a delayed shutdown). Audit-log the
   shutdown as a graceful event via the existing audit machinery.
4. **State.** Each iteration writes to `<out-dir>/ramen-cve-<iso-ts>/`
   (the existing microsecond stamp from `_output` makes this
   deterministic). `--prune-after-days` walks `out-dir` and removes
   old subdirs by mtime.
5. **Foreground only in v1.** No forking, no pidfile. Users
   wire systemd / supervisord / Docker if they want true daemonisation.
   This avoids platform-specific `os.fork` / Windows incompat.
6. **CLI flag set.**
   - `--for-config NAME` (required — the YAML preset that defines
     opml/url/cve invocation).
   - `--interval SECONDS` (default 21600).
   - `--jitter SECONDS` (default 0).
   - `--max-runs N` (default -1).
   - `--prune-after-days N` (default 0 = off).

**Implementation slices.**

- [x] **Slice A — subcommand scaffolding.** New
   `src/ramen_cve/daemon.py` (L4, mirrors `schedule.py` style) with
   `_build_iteration_argv(preset_name)` and `_run_daemon(args, cache,
   api_key)`. The argv builder reads a YAML preset's `subcommand`
   (opml/url/cve/stix) + positional and emits the argv that
   `ramen_cve.main(...)` would parse, plus `--config <preset>` so the
   preset's other flags flow through `apply_yaml_config`.
   `_run_daemon` validates `--for-config`, resolves the iteration
   argv, and runs the pipeline once via a deferred `import ramen_cve;
   ramen_cve.main(iter_argv)` (avoids the cli<->daemon module-level
   circular import; matches the §5.2 deferred-lookup pattern). The
   daemon's own exit code is 0 once an iteration has executed —
   inner-iteration failures log a WARNING but don't crash the
   daemon (Slice B will retry on the next interval). Wired the
   `daemon` subparser into `cli.build_parser` with `--for-config`
   (required), `--interval`, `--jitter`, `--max-runs`,
   `--prune-after-days`. Dispatch via `_audit_dispatch(cache,
   "daemon", args, lambda: _run_daemon(args, cache, None))` —
   `api_key=None` because the recursive inner `main()` resolves its
   own. Façade re-exports `_build_iteration_argv` and `_run_daemon`;
   `tests/test_facade.py` contract updated. +15 tests: 9 covering
   `_build_iteration_argv` (each subcommand happy path + 4 error
   paths), 5 covering `_run_daemon` (requires-for-config, invokes
   main exactly once with resolved argv, returns 0 even when inner
   main fails, unsupported `--max-runs` logs WARN but still runs,
   bad preset → rc=2 without calling main), and 1 end-to-end via
   `ramen_cve.main` proving the subparser routes through
   `_audit_dispatch`. Verification: 529 passed (was 514 + 15), ruff
   clean, golden byte-identical.
- [x] **Slice B — the loop + signal handling.** Replaced Slice A's
   single-shot call with a `while True` loop terminated by either
   `--max-runs N` (iteration cap) or a SIGTERM/SIGINT-driven
   `threading.Event`. The loop uses `_should_stop.wait(timeout=
   interval + jitter)` so the daemon wakes immediately on signal
   rather than after the full interval (sub-second shutdown
   latency on a 6 h interval). `_install_signal_handlers()` saves
   the prior handlers and the daemon's `finally` clause restores
   them, so embedders don't lose their signal handling. Fixed an
   `X or default` short-circuit bug surfaced during testing —
   `interval=0` / `jitter=0` / `max_runs=0` are now honoured
   verbatim instead of being silently coerced to defaults
   (captured as `tasks/lessons.md` L8). +6 Slice-B tests
   (max-runs N actually loops N times, unbounded run exits on
   `_should_stop`, failed iterations don't abort the loop, signal
   handler flips the event, restore-handlers works, jitter
   modulates sleep, negative jitter clamps to zero). One Slice-A
   test (`logs_warning_for_unsupported_max_runs`) rewritten as
   `honours_max_runs_positive` since the loop now supports it.
   Verification: 535 passed (515 + 21 daemon tests, run in 0.20s),
   ruff clean, golden byte-identical.
- [x] **Slice C — timestamped output dirs.** New
   `_iteration_output_subdir(base)` creates a fresh
   `<base>/ramen-cve-<UTC microsecond ts>/` per iteration (probing
   `-N` suffixes for the rare same-microsecond collision), and the
   loop appends `--out-dir <subdir>` to each iteration's argv. Because
   the injected `--out-dir` comes after `--config`, it overrides any
   `out_dir` the preset declares (explicit CLI arg beats
   apply_yaml_config). New `--out-dir` daemon flag sets the base
   (default = cwd). +3 tests (distinct subdir per iteration created on
   disk + passed as --out-dir; default-to-cwd; preset out_dir
   override). An autouse `_isolate_cwd` test fixture chdirs into
   tmp_path so default-cwd subdir creation never pollutes the repo;
   the three exact-argv asserts use a `_strip_out_dir` helper.
   Verification: 538 passed (535 + 3), ruff clean, golden
   byte-identical.
- [x] **Slice D — `--prune-after-days` history pruning.** New
   `_prune_old_iterations(base, days)` helper walks the base output dir
   and `shutil.rmtree`s any direct child whose name starts with the
   shared `ramen-cve-` iteration prefix (hoisted to a
   `_ITERATION_DIR_PREFIX` constant so create-side and prune-side can't
   drift) AND whose mtime is older than `days`. Age is compared in the
   POSIX clock domain (`time.time()` vs. `st_mtime`) — deliberately NOT
   `_utcnow().timestamp()`, which is a *naive* UTC datetime and would
   mis-convert in a non-UTC locale. `days <= 0` is a no-op (pruning is
   opt-in). Fail-soft: an un-stat'able / un-removable child logs a
   WARNING and is skipped, never crashing the daemon; only `ramen-cve-*`
   *directories* are candidates so a user can safely point `--out-dir`
   at a populated directory. `_run_daemon` calls it once on startup
   (clears stale history from earlier daemon lifetimes) and once after
   every iteration. Decision: **no debounce** — the directory walk is
   O(#subdirs) and trivially cheap next to a real pipeline iteration, so
   even at `--interval 0` per-iteration pruning is fine; the plan's
   "behind a debounce" optimisation guards a sub-second-interval scenario
   that doesn't exist in practice. +9 tests (prune removes only
   over-threshold dirs, zero/negative days = no-op, non-iteration
   entries + prefix-matching files ignored, nonexistent base, fail-soft
   on rmtree OSError, plus three e2e via `_run_daemon`: stale dir pruned
   while fresh survives, opt-in default leaves ancient dirs, and
   startup+per-iteration invocation count). Verification: 547 passed
   (538 + 9), ruff + F821/F822 clean, golden CSV+MD byte-identical to
   anchor (`CSV 3fd1ac95`, `MD e9779ffc`).
- [x] **Slice E — docs.** Added a `## Running as a daemon` section to
   `README.md` (placed right after `## Scheduled / recurring runs`, which
   it complements): when to choose `daemon` vs `schedule`, a two-step
   save-preset-then-loop example, a full flag table (`--for-config`,
   `--interval`, `--jitter`, `--max-runs`, `--out-dir`,
   `--prune-after-days` with their real defaults), the graceful-shutdown
   contract (SIGTERM/SIGINT finish the in-flight iteration; sub-second
   latency via the interruptible wait), a copy-paste **systemd** unit
   (with `Restart=on-failure` rationale), a **launchd** plist for macOS,
   and a security callout: a long-lived daemon keeps `NVD_API_KEY` /
   `RAMEN_SMTP_PASSWORD` / `SLACK_WEBHOOK_URL` resident for its whole
   lifetime, so prefer an `EnvironmentFile` / launchd `EnvironmentVariables`
   / container secret over a committed `.env`, `chmod 600` it, run as a
   dedicated unprivileged user, and run one daemon per SQLite cache file.
   Docs-only; no code/test change, gate unaffected.

**Task 3 status: COMPLETE.** Long-running daemon mode is shipped
end-to-end (subcommand scaffolding + `while/sleep/signal` loop with
graceful SIGTERM/SIGINT shutdown + timestamped per-iteration output
subdirs + `--prune-after-days` history pruning + README operator docs).
PR #26 carries Slices A–E; opt-in via `ramen-cve daemon --for-config
NAME`.

**Test strategy.**
- `tests/test_daemon.py`:
  - `test_daemon_max_runs_1_returns_0` — run-once mode, mocked
    pipeline runner, exit code 0.
  - `test_daemon_runs_n_times_then_exits` — `--max-runs 3`, assert
    pipeline invoked thrice; `time.sleep` patched.
  - `test_daemon_sigterm_finishes_current_run` — simulate signal
    via the handler directly; assert the in-flight run completes
    and the next iteration is skipped.
  - `test_daemon_per_run_output_subdir` — each iteration writes to
    a fresh timestamped subdir.
  - `test_daemon_prune_after_days` — pre-create old dirs; verify
    deletion behaviour.

**Verification gate.**
- `pytest tests/ -q` → existing + new.
- `ruff` clean.
- Manual: `ramen-cve daemon --for-config <test> --max-runs 2
  --interval 2` returns within ~4 s and writes two subdirs.

**Risks & flags.**
- **Crash recovery:** a mid-pipeline crash leaves a partial subdir.
  The atomic-write-then-rename pattern in `pipeline._output` already
  mitigates most output corruption; document the case.
- **Log rotation:** stderr accumulates indefinitely. v1 punts to
  systemd/journal/logrotate; v1.1 may add `RotatingFileHandler`.
- **API rate limits:** running every 6 h against a large preset can
  saturate NVD/EPSS. Cache TTL helps; document expected request
  counts per cycle.
- **Disk space:** pruning is opt-in; without it, history grows
  unbounded. Default `--prune-after-days 30` is tempting but
  destructive; opt-in is safer.
- **SQLite lock contention** if two daemon instances run in
  parallel. Document: run one daemon per host; use systemd's
  `Restart=on-failure` not `Restart=always` to avoid races.

**Effort.** **7–9 focused hours** (Slice A: 1; B: 2; C: 1; D: 0.5;
E: 1; tests: 2–3; docs: 1).

---

### 4. Housekeeping — DONE (with one permission caveat)

**Goal.** Delete merged feature branches. They are 100 % merged into
`main`; safe to recreate from main if ever needed.

**Outcome (2026-05-22).**
- **Local:** all six merged feature branches deleted with `git branch
  -d` (refuses unmerged, so this is safe): `claude/daemon-mode`,
  `claude/epss-trajectory-slice-a`, `claude/init-tasks-todo`,
  `claude/post-refactor-plans-and-docs`,
  `claude/refactor-monolith-split`, `claude/url-crawl-depth-1`. Only
  `main` and the active working branch remain locally.
- **Remote:** the two originally-named refs
  (`claude/refactor-monolith-split`, `claude/init-tasks-todo`) are
  **already absent** from `origin` (cleaned up earlier / on merge), so
  nothing to do there. `origin/claude/daemon-mode` (merged via PR #26)
  still exists, but `git push origin --delete claude/daemon-mode`
  returns **HTTP 403** — this session's credential is scoped to the
  designated working branch only and cannot mutate other remote refs.
  Left in place; harmless (merged). A maintainer can delete it from the
  GitHub UI, or enable "automatically delete head branches" on the repo.

**Acceptance.** Local clutter gone; `main` history unchanged. The
remaining `origin/claude/daemon-mode` is a known, harmless leftover
outside this session's push scope.

**Effort.** ~1 minute (as estimated).

---

### 5. Regenerate `examples/sample-output.csv` + `sample-report.md` — DONE

**Outcome (2026-05-23).** Shipped `scripts/regen_examples.py`: a
self-documented, deterministic regenerator that rebuilds the bundle from
a fully self-contained inline fixture set. Investigation found the
previously committed examples were **stale on multiple axes** (sources
like "SANS ISC"/"Vendor Blog" that are absent from `examples/sample.opml`;
fewer threat actors than the current bundled `associations.json` carries),
so a faithful byte-reproduction from current inputs was impossible —
Phase 1 option (b) ("design a new showcase set") was the only viable path.

The regenerated showcase is **richer** than the previous file, not
narrower: five CVEs spanning **every bucket** (one per bucket), two
defanged IOCs (URL + SHA-256, refanged in render), a four-row inventory
correlating three CVEs to hosts, and threat-actor links that reflect the
*current* bundled associations (APT41 + HAFNIUM + Aquatic Panda for
Log4Shell; HAFNIUM + APT27 for ProxyLogon). The two real CVEs
(CVE-2021-44228, CVE-2021-26855) pick up actor / malware context from
the bundle; the three `CVE-2024-000x` ids are deliberately synthetic
placeholders so no real advisory is misrepresented.

**Determinism details.**
- All network is mocked: NVD, EPSS, and CISA-KEV via inline payloads in
  the script; RSS feeds via a per-host fake `feedparser.parse`; exploit
  + IOC enrichment disabled by flag so no un-mocked call is ever made.
- The two live-clock fields — CSV `enriched_at` and Markdown
  `Generated:` — are normalised to a frozen instant after the run, and
  the Markdown `Command:` line's absolute OPML path is rewritten to
  `examples/sample.opml`, so the bundle is portable across machines.
- `scripts/regen_examples.py --check` regenerates into a temp dir and
  diffs against the committed files (exit 1 on drift) — CI-friendly.

**Files touched.** Added `scripts/regen_examples.py` (~250 LOC, fully
documented), `examples/sample-inventory.csv` (new — committed example
input). Replaced `examples/sample-output.csv` and `examples/sample-report.md`
with the regenerator's output.

**Verification.** ruff + F821/F822 clean; `pytest tests/ -q` 547 passed;
golden byte-oracle byte-identical to anchor (CSV `3fd1ac95`, MD
`e9779ffc`, 1069 B / 79 lines — the regen examples are independent of
the smoke fixtures, so the oracle is unaffected); `regen --check`
returns rc=0 after a fresh regen (idempotent).

**Original goal + plan retained below for reference.**

**Goal.** Refresh the bundled example bundle so it reflects a current
post-refactor pipeline run. Today's committed files (1,426 B CSV
+ 3,859 B MD, 3 CVEs) are correct-but-pre-refactor; the golden
byte-oracle proves end-to-end pipeline behaviour is byte-identical
to the pre-refactor baseline, so the committed files **are** still
faithful examples — but the user-facing artifacts should still be
representative of the current package.

**Important caveat discovered in planning.** The committed examples
were generated from a **richer fixture set than `tests/test_smoke.py`**
(3 CVEs incl. a third one beyond Log4Shell + ProxyLogon; CSV is
1,426 B vs. smoke's ~1,069 B output). The original generation
recipe is not currently documented. A naive "regenerate from
test_smoke" would **shrink** the examples, not refresh them.

**Acceptance.**
- A scripted regenerator (`scripts/regen_examples.py`) produces the
  bundled `examples/*.csv` + `examples/*.md` byte-identically on
  every run (frozen `_utcnow`, frozen fixture bundle).
- The first commit of the regenerated files documents the exact
  fixture inputs used (so the next regen reproduces them).
- Running the regen twice in a row → no diff.

**Plan (two-phase).**

1. **Phase 1 — recover or recreate the richer fixture set.**
   - Search `git log --all -- examples/sample-output.csv` for the
     commit that introduced the current bundle; inspect the diff
     to identify the third CVE + any non-default flags used.
   - Either (a) recover the original fixtures, or (b) build a new
     fixture set that's richer than `test_smoke`'s (e.g., include a
     CVE without a KEV entry, a non-CVE noise IOC, etc.) — design a
     "showcase" set rather than a minimal-smoke set.
2. **Phase 2 — write the regen script.**
   - `scripts/regen_examples.py`: imports `ramen_cve`, patches
     `requests.get` / `time.sleep` / `feedparser.parse` like
     `test_smoke`, **patches `_utcnow`** to a frozen instant
     (so MD `Generated:` line and CSV `enriched_at` column are
     deterministic), runs the pipeline against `examples/sample.opml`,
     copies output into `examples/sample-output.csv` and
     `examples/sample-report.md` (rename the `.md` to match the
     current filename convention).
   - Lock the regen with a `make examples` target or top-of-file
     usage docstring.

**Verification gate.**
- `python scripts/regen_examples.py` → exit 0, file diffs are
  exactly the contents that just changed (i.e., second run is a
  no-op).
- `git diff examples/` shows only the expected content delta.
- `pytest tests/ -q` (suite uses fixtures, not examples) → 463.

**Risks & flags.**
- If the original richer fixtures are lost to history, Phase 1
  becomes a judgment call (build a representative showcase). Note
  in the regen-script docstring which fixture set was chosen and
  why.
- Renaming `sample-output.md` → `sample-report.md` (or vice versa)
  is a doc-style decision; current convention is `sample-report.md`,
  so the regen script honours that.

**Effort.** **3–5 hours** (Phase 1 investigation: 1–2 h; Phase 2
script + commit: 2–3 h).

---

### 6. HTML quadrant chart output — DONE

**Goal.** Add `--format html` (or `--format quadrant`) that emits a
self-contained HTML file with a CVSS-by-EPSS scatter, points
coloured by bucket, hoverable for CVE id + suggested action.

**Acceptance.**
- `ramen-cve opml … --format html` writes `<basename>.html` with an
  inline SVG scatter (no external assets, no JS frameworks).
- Each point: CVSS on x-axis (0–10), EPSS on y-axis (0–1), colour
  by `bucket`, `<title>` tooltip = CVE id + score summary.
- File is human-readable when opened directly in a browser;
  printable.

**Design — key decisions.**

1. **Pure inline SVG, no JS framework.** A single `<svg>` block
   with `<circle>` per CVE, embedded in a minimal HTML wrapper.
   Tooltips via SVG `<title>`. No D3, no Chart.js — that would
   blow up the dep budget.
2. **Bucket colour palette** documented as a small constant in
   `output/html_quadrant.py`. Colour-blind-safe (use
   "viridis"-style steps).
3. **Threshold guides.** Render the CVSS/EPSS threshold lines as
   light grey gridlines, labelled with the threshold values used.
4. **Self-contained.** Inline CSS in `<style>`; no external links.

**Implementation slices.**

1. **Slice A — SVG renderer pure-function.** `_render_quadrant_svg(
   enriched: list[EnrichedCve], cvss_thr: float, epss_thr: float) ->
   str` returning SVG markup. Pure, easy to unit-test.
2. **Slice B — HTML wrapper.** `write_quadrant_html(enriched, path,
   ...)` writes the SVG inside a minimal HTML5 doc with embedded
   CSS.
3. **Slice C — wire to `--format`.** Extend the existing
   `--format` choices in `cli.build_parser`; route via
   `pipeline._output`.

**Test strategy.**
- `tests/test_html_quadrant.py`:
  - `test_renders_one_circle_per_record`.
  - `test_kev_override_records_get_kev_colour`.
  - `test_thresholds_drawn_as_gridlines`.
  - `test_html_is_self_contained` — no `<link>`/`<script src=…>`
    references.
- Snapshot test (frozen SVG output for a fixed input) as the byte
  oracle.

**Effort.** **4–6 focused hours.**

---

### 7. Configurable bucket labels / thresholds

**Goal.** Let a YAML preset define bucket labels, per-bucket
thresholds, suggested-action text, and display order, replacing
today's hardcoded `BUCKET_DISPLAY` / `BUCKET_ACTIONS` constants.
Existing presets without a `buckets:` block must produce
**byte-identical** output (default policy = current behaviour).

**Acceptance.**
- A preset can include a `buckets:` block (nested YAML) overriding
  per-bucket label / cvss_threshold / epss_threshold / action /
  order.
- KEV override remains hard-precedence (non-configurable).
- Empty/missing `buckets:` → defaults; output byte-identical to
  today on existing presets.
- All existing tests pass unchanged.

**Leveraged seams.**
- `src/ramen_cve/analyze.py:bucket_and_suggest` — current bucket
  decision tree (KEV → patch_now → plan_and_patch → watch_closely
  → deprioritize → unknown).
- `src/ramen_cve/constants.py:BUCKET_ACTIONS` — current action
  prose.
- `src/ramen_cve/output/markdown.py:BUCKET_ORDER, BUCKET_DISPLAY` —
  current rendering tables.
- `src/ramen_cve/config.py:_YAML_FLAT_KEY_MAP` /
  `apply_yaml_config` — YAML loader (we'll add a nested-key path
  alongside the existing flat-key path).

**Design — key decisions.**

1. **New leaf module `bucket_policy.py`** with a `BucketPolicy`
   dataclass:
   - `buckets: dict[str, tuple[str, str, int]]` (id → (label,
     action, order))
   - `thresholds: dict[str, tuple[float, float]]` (id → (cvss, epss))
   - `default_cvss_threshold: float = 7.0`
   - `default_epss_threshold: float = 0.10`
   - `from_yaml(dict) -> BucketPolicy` (degrades to defaults if
     absent; merges per-bucket overrides over defaults)
   - `assign(record: EnrichedCve) -> str` (sets `record.bucket` and
     `record.suggested_action` in place, returns bucket id).
2. **`DEFAULT_BUCKET_POLICY`** hardcoded to today's behaviour —
   referenced as the fallback everywhere.
3. **Refactor surface (smallest possible).**
   - `bucket_and_suggest` gains an optional `policy:
     BucketPolicy | None = None` parameter; when None, it
     constructs a policy from the existing `cvss_thr`/`epss_thr`
     args (backwards-compat).
   - `write_markdown` gains optional `policy` (used to iterate
     `policy.buckets` for display order/labels).
   - `apply_yaml_config` reads the optional `buckets:` block,
     stamps `args.bucket_policy` (a `BucketPolicy`); call sites
     read from there.
4. **YAML schema (example).**
   ```yaml
   buckets:
     patch_now:
       label: "Critical - Patch Now"
       cvss_threshold: 8.0
       epss_threshold: 0.15
       action: "Patch within 24 hours"
       order: 1
   ```
5. **Bucket IDs remain reserved** — users can only override
   metadata of the six existing bucket ids; they cannot define new
   bucket ids in v1.

**Implementation slices.**

1. **Slice A — BucketPolicy dataclass + tests.** Pure data, no
   integration.
2. **Slice B — `bucket_and_suggest(policy=…)` backward-compat
   path.** Existing callers don't pass policy; default behaviour
   preserved. Suite stays at 463.
3. **Slice C — YAML loader integration.** `apply_yaml_config` reads
   `buckets:`; new tests for a preset with custom buckets.
4. **Slice D — output integration.** `write_markdown` iterates
   `policy.buckets` for order/labels. CSV columns unchanged (bucket
   id is what's serialised, not the label).
5. **Slice E — ship a `aggressive.yaml` showcase preset** under
   `src/ramen_cve/config/presets/` demonstrating customisation.

**Test strategy.**
- `tests/test_bucket_policy.py` (per the recon report — full set,
  including `test_kev_always_wins`, `from_yaml_custom_thresholds`,
  `from_yaml_custom_labels`, end-to-end with a custom preset).
- Golden byte-oracle on a non-`buckets:` preset → byte-identical to
  anchor (the **must-not-regress** gate).

**Verification gate.** 463 + new tests; ruff clean; golden
byte-oracle.

**Risks & flags.**
- `tests/test_facade.py` locks the `BUCKET_*` re-exports; keep
  them in `__init__.py` even after the refactor (they remain the
  default-policy mirror).
- Subtle: today `bucket_and_suggest` reads the *global thresholds*;
  the policy refactor inverts this so the policy carries
  thresholds. Make sure the backwards-compat constructor (when
  policy=None) reproduces today's exact decision tree (not "a
  per-bucket-threshold tree that happens to use the same numbers").

**Effort.** **7–9 focused hours.**

---

### 8. Web UI

**Goal.** A browseable triage view over the SQLite cache,
associations, and historical runs (`runs` table). The largest
remaining item by scope.

**Acceptance.** _To be defined alongside an explicit design doc
before implementation._ Suggested MVP:
- A read-only static HTML generator (no server, no auth) that emits
  an `index.html` summarising the latest run + linking to per-run
  reports.
- Per-CVE detail pages showing trajectory (if available) + linked
  IOCs + associations.

**Design notes (decisions deferred).**
- **No server in v1.** Static HTML keeps the dep set unchanged; can
  be served by any web host (or opened locally). Defer FastAPI /
  Streamlit to a v2 design doc that explicitly justifies the
  dep/operational cost.
- Reuse the inline-SVG quadrant from task 6 as the index visual.
- The Markdown report effectively *is* the per-run view; this task
  extends to a cross-run timeline view.

**Effort.** **TBD by spec.** Plan: one design doc + one MVP slice
(static index page) = **probably ~20–30 hours** end-to-end, but the
design doc must come first.

**Risks & flags.**
- Scope creep is the biggest risk. Time-box the design doc to a
  half-day; if MVP can't be cut to one screen, defer further.

---

## Templates

### Plan template — paste under "In progress" when starting a new task

- [ ] Restate goal + acceptance criteria
- [ ] Locate existing implementation / patterns
- [ ] Design: minimal approach + key decisions
- [ ] Implement smallest safe slice
- [ ] Add / adjust tests
- [ ] Run verification (lint / tests / build / manual repro)
- [ ] Summarize changes + verification story
- [ ] Record lessons (if any) in `tasks/lessons.md`

### Bugfix template — paste under "In progress" for a bug report

- Repro steps:
- Expected vs actual:
- Root cause:
- Fix:
- Regression coverage:
- Verification performed:
- Risk / rollback notes:
