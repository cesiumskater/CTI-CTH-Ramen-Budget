# Web UI — Design Doc (Task 8)

**Status:** Draft — design only, no code yet.
**Time-box for this doc:** half a day's worth of decisions.
**Author note:** the per-task backlog in `tasks/todo.md` flags Task 8 as
"design doc first; one MVP slice ≈ 20-30 h end-to-end". This doc
discharges the design half. An accompanying implementation plan with
slice boundaries lands at the bottom.

Every design call below was explicitly confirmed with the project owner
in the design-doc review session (see §11 Decision log).

---

## 1. Goal

A browseable triage view over data the tool already produces — without
introducing a server, a JS framework, a database migration, or a new
runtime dependency. The user opens a single HTML file in any browser
and can:

1. See the **latest run at a glance**: total CVE count, bucket
   breakdown, the Task-6 inline-SVG CVSS×EPSS quadrant.
2. Drill into a **per-run summary** to inspect what changed run-over-
   run (added / removed / reclassified CVEs).
3. Drill into a **per-CVE detail page** showing the historical
   trajectory (from the cache's never-purged `runs` table), linked
   threat actors + campaigns + malware, exploit-status + nuclei-template
   + GitHub-PoC signals, and any IOCs that came in alongside the CVE.

What this is **not**: a real-time dashboard, a multi-tenant portal, a
shared search interface, or a JS-driven SPA. Those belong in a future
v2 once we have evidence the static-HTML version is too thin for real
operators.

---

## 2. Constraints (binding, not aspirational)

These come from the project's ramen-budget ethos and the explicit
spec in `tasks/todo.md` Task 8. The implementation **must** honour
all five:

| # | Constraint | Why it's binding |
|---|------------|------------------|
| 1 | No new runtime dependency. | The project's dep set is 5 (`requests`, `feedparser`, `python-dotenv`, `questionary`, `PyYAML`); a Web UI must not push it to 6. Stdlib only. |
| 2 | No server in v1 (static HTML). | A Flask/FastAPI/Streamlit MVP brings a process to keep alive, an auth story, and a deployment story. Out of scope. |
| 3 | No JS framework, no NPM. | Inline `<style>`/external `static/style.css` only. Tiny inline `<script>` is fine if and only if it is the only way to deliver the feature; default to zero JS. |
| 4 | Read-only. | Mutations (re-running enrichment, editing a hunt, etc.) require a server. Out of scope. |
| 5 | Determinism preserved. | Pages are byte-stable for a fixed `_utcnow` mock + a fixed cache snapshot — same standard as the existing CSV/MD/STIX writers. |

---

## 3. Data sources (what we already have)

The Web UI is a **renderer over existing data**, not a new pipeline.
Every fact it shows is already on disk:

### 3.1 The `runs` table (SQLite — canonical run truth)

`src/ramen_cve/cache.py` keeps a never-purged history:

```sql
CREATE TABLE IF NOT EXISTS runs (
    cve_id     TEXT NOT NULL,
    ts_iso     TEXT NOT NULL,       -- second-precision: "2026-05-25T13:25:01+00:00"
    bucket     TEXT NOT NULL,
    cvss_score REAL,
    epss_score REAL,
    PRIMARY KEY (cve_id, ts_iso)
);
```

The Web UI treats `SELECT DISTINCT ts_iso FROM runs ORDER BY ts_iso DESC`
as the **canonical list of runs**. `Cache.get_runs(cve_id)` already
returns the per-CVE time-ordered series. This is the natural feed for
both the home-page run-history strip and the per-CVE trajectory page.

### 3.2 The disk-artefact ↔ SQLite-ts wrinkle, resolved by a new table

`Cache.record_run` writes `_utcnow().isoformat(timespec="seconds")` →
e.g. `2026-05-25T13:25:01+00:00`. `pipeline._output` names files via
`_utcnow().strftime("%Y%m%dT%H%M%S%f")` → e.g.
`ramen-cve-20260525T132501478665.html`. Same call, **different
precision**, and naive second-truncation matching false-positives on
two pipeline calls within the same second (rare but plausible under
daemon mode at sub-second intervals).

Resolution: **a new SQLite table** added to `cache.py`'s `_SCHEMA`,
populated by `pipeline._output` on every write:

```sql
CREATE TABLE IF NOT EXISTS run_artefacts (
    ts_iso     TEXT PRIMARY KEY,        -- matches runs.ts_iso (second precision)
    disk_stamp TEXT NOT NULL,           -- the microsecond filename stamp
    out_dir    TEXT NOT NULL            -- absolute path that _output wrote into
);
```

The Web UI's discovery step:

1. `SELECT DISTINCT ts_iso FROM runs ORDER BY ts_iso DESC` → canonical
   run list.
2. `LEFT JOIN run_artefacts USING (ts_iso)` → exact disk stamp + dir
   for each run that produced files. NULLs are runs with no on-disk
   artefacts (cache wiped, files archived, etc.) — render "—".
3. For each linked artefact, probe specifically `<out_dir>/ramen-cve-<disk_stamp>.{html,md,csv,stix.json}`
   and the daemon-iteration variant `<out_dir>/ramen-cve-<disk_stamp>/`.

Why a new table, not an extra column on `runs`:
- `runs` is the public per-CVE timeline; one row per `(cve_id,
  ts_iso)`. Stamping the same `disk_stamp` on every CVE row in a run
  duplicates data N times.
- `run_artefacts` is per-invocation (one row per pipeline call) —
  cleaner separation of concerns + a 1:1 to `_output` writes.
- Backwards compatible: `CREATE TABLE IF NOT EXISTS` runs on every
  `Cache.__init__`, so existing cache files pick up the new table on
  first open. No migration logic, no destructive ALTER.

The Web UI tolerates an empty `run_artefacts` table (a freshly
upgraded cache with prior `runs` history but no recorded artefacts):
all rows render "—" until a fresh pipeline run repopulates.

### 3.3 Per-source caches (rich per-CVE detail)

`nvd_cache`, `epss_cache` (per-date), `kev_cache`, `exploit_cache`,
`enrichment_cache` — used to render the per-CVE detail page without
re-fetching from the API. The Web UI runs against a cache snapshot,
never the network.

### 3.4 On-disk run artefacts (linked, never re-emitted)

Both single-shot runs and daemon iterations already write:

```
<out-dir>/
  ramen-cve-<ts>.csv                  # single-shot
  ramen-cve-<ts>.md
  ramen-cve-<ts>.html                 # Task 6 quadrant
  ramen-cve-<ts>/                     # daemon iteration (Task 3 Slice C)
    ramen-cve-<ts>.csv
    ramen-cve-<ts>.md
    ramen-cve-<ts>.html
```

The Web UI does **not** need to re-emit these — it links to them.
Crucially, the Task-6 inline-SVG quadrant is reusable as-is and is the
visual anchor for the index + per-run pages.

### 3.5 Bundled associations + IOC sidecars

- `src/ramen_cve/data/associations.json` — threat-actor + campaign +
  malware lookups (loaded by `associations.load_associations`).
- Per-run IOC CSV sidecars: `<out-dir>/ramen-cve-<ts>-iocs.csv`
  (written by `pipeline._output` whenever IOCs were extracted).

### 3.6 What we do NOT touch

The `audit_log` table carries arguments that — while redacted at write
time — are still operationally sensitive. The MVP does not surface
it. A future operator-only view is a separate spec.

---

## 4. Architecture — static HTML, deterministic generator

### 4.1 New entry point: `ramen-cve web`

A new subcommand. Argparse skeleton:

```
ramen-cve web --site-dir PATH         # REQUIRED — no default
              [--cache PATH]          # defaults to .ramen-cache.db
              [--out-dir PATH]        # for disk-artefact lookup
              [--config NAME]         # threads args.bucket_policy through
              [--max-runs-on-home N]  # default 30
```

`--site-dir` is **required** by design — no default. Generating into
an implicit location is the kind of write-shape surprise the project's
existing `_safe_basename` / `_unique_output_path` machinery
specifically avoids; this matches the precedent and removes any "did
I just overwrite something?" foot-gun.

Implementation lives in a new L4 module
`src/ramen_cve/web/builder.py` (consistent with `output/` and
`enrich/` layering — depends on L1-L3 leaves, depended on by
`cli.py`).

### 4.2 File layout written

```
<site-dir>/
  index.html                          # cross-run summary + latest quadrant
  static/
    style.css                         # single shared stylesheet
  runs/
    <ts>.html                         # per-run summary (one per discovered iteration)
  cve/
    CVE-2021-44228.html               # per-CVE detail (one per CVE in the runs table)
```

`<ts>` in the URL is the SQLite-canonical second-precision stamp with
the colons stripped (`20260525T132501Z`), so filenames are
filesystem-safe on every OS and sort lexicographically by time.

### 4.3 Shared stylesheet

A single `static/style.css` linked from every page. Pages stay light
(structural HTML only); cosmetic tweaks land in one place; the
**snapshot oracle freezes structural HTML, not the stylesheet** —
which lets a future CSS revision land without rewriting every
snapshot.

### 4.4 Bucket-policy aware

The builder accepts `--config NAME` and threads `args.bucket_policy`
(Task 7) through to label-rendering so the home/run/CVE pages use the
user's custom labels and action prose. The default (no `--config`)
reproduces today's hardcoded `BUCKET_DISPLAY` / `BUCKET_ACTIONS`
byte-for-byte via `DEFAULT_BUCKET_POLICY`.

### 4.5 HTML safety contract

Every interpolated string passes through `html.escape(..., quote=True)`
**unconditionally** — no allowlist, no light-markup preservation. A
description containing literal `<i>foo</i>` renders as
`&lt;i&gt;foo&lt;/i&gt;`. A description containing `<script>` is
neutralised. This is a Slice-A invariant locked by
`test_html_escapes_cve_description` + `test_html_escapes_actor_name`
+ `test_html_escapes_attribute_values`.

---

## 5. Page-by-page spec

### 5.1 `index.html` — the home page

**Above the fold:**
- H1: "Ramen CVE Triage".
- Generated timestamp (from `_utcnow()`).
- Cache path + total-runs count (from `runs` table).

**Latest run summary:**
- Bucket breakdown table using the active `BucketPolicy`'s labels and
  display order (defaults to `BUCKET_DISPLAY` / `BUCKET_ORDER`).
- The Task-6 quadrant `<svg>` **inlined verbatim** from the latest
  run's quadrant HTML file (extract the `<svg>...</svg>` block via a
  tight regex — no full HTML parser, no new dep). Falls back to a
  "—" placeholder when the disk artefact is absent.

**Run history strip:**
- A reverse-chronological table: timestamp → total CVEs → KEV count
  → links to `runs/<ts>.html` + best-effort links to the on-disk MD /
  CSV / STIX / HTML quadrant for this run.
- Default cap: last 30 runs (overridable via `--max-runs-on-home`).
- Older runs accessible by direct URL `runs/<ts>.html`.

**Out of scope on the index:** filtering, search, sorting controls
(would need JS). Documented in §10.

### 5.2 `runs/<ts>.html` — per-run summary

- H1: the run's UTC timestamp.
- The same bucket breakdown table for THIS run.
- The Task-6 quadrant for THIS run, again inlined (or "—" placeholder).
- "What changed since the previous run" diff block: added / removed /
  bucket-reclassified CVEs. Computed by `Cache.get_runs(cve_id)`
  windows around this `ts`.
- Best-effort footer links to the on-disk MD + CSV + STIX for this run.

**Constraint:** generating this page touches the per-CVE history but
not the live cache caches (NVD/EPSS) — it's strictly a renderer over
data already captured into `runs`.

### 5.3 `cve/<CVE-ID>.html` — per-CVE detail (RICH)

The "rich" mode confirmed in the design review. Sections, top to
bottom:

1. **Header.** CVE id + most recent bucket (using the active
   `BucketPolicy`'s label) + linked NVD URL.
2. **Summary.** Description, CVSS score + severity, CVSS vector, EPSS
   score + percentile, KEV-listed (Y/N) + KEV due date when listed
   (from `nvd_cache` + `epss_cache` + `kev_cache`).
3. **Trajectory chart.** A Task-6-style inline-SVG scatter, one point
   per `runs` row (oldest to newest, most recent highlighted). Below
   2 snapshots → fall back to a Task-1-style ASCII sparkline from
   `render.py`. Above 200 snapshots → cap at the 200 most recent +
   a "+N earlier" footer note.
4. **Exploit status (NEW vs §5.3 lean version).** Inline lines from
   `exploit_cache`: ExploitDB ID + URL, Nuclei template path,
   GitHub-PoC repo names (deduplicated).
5. **Linked actors / campaigns / malware.** From `associations.json`,
   each linked to its NVD/MITRE reference.
6. **Linked IOCs (NEW vs §5.3 lean version).** Up to 50 IOCs from the
   most recent run's `<basename>-iocs.csv` sidecar where the IOC's
   `linked_cves` contains this CVE id. Above 50 → "+N more" footer
   linking to the full CSV.
7. **Affected hosts.** From the most-recent run's `affected_hosts`
   list (already in `EnrichedCve`).
8. **Footer.** "Seen in N runs since `<first_seen_iso>`".

The detail page is the "rich" view; it is the **navigator equivalent
of the Markdown report**, not a strict subset of it. The Markdown
still wins for offline / printable / scriptable use.

---

## 6. Determinism contract (the byte-oracle gate)

This is the lever that makes the Web UI testable in the same way as
CSV/MD/STIX:

1. **Frozen `_utcnow()`** — the test harness mocks the module-level
   clock (the existing pattern from `tests/test_smoke.py` and
   `scripts/regen_examples.py`).
2. **Sorted iteration** over the `runs` table by `(ts_iso, cve_id)`
   and over discovered run directories by `<ts>` — `os.listdir`
   ordering is not stable across filesystems.
3. **No randomness** in the generator (no `uuid4()`; if a per-page
   anchor id is needed, hash a deterministic input).
4. **Locale-stable formatting** — every numeric format string is
   `f"{x:.4f}"`-style with an explicit precision; never `repr(float)`.
5. **LF line endings** explicitly (`Path.write_text(text,
   encoding="utf-8")` and `\n` joiners; no `os.linesep`).
6. **Stylesheet decoupling** — the byte-oracle freezes structural
   HTML (the `<body>`); cosmetic CSS edits do not invalidate it.

A frozen `examples/_web-sample/` snapshot fixture (see §9) anchors a
`tests/test_web_ui.py` oracle.

---

## 7. Tests (the gate)

`tests/test_web_ui.py` (new file) covers, at minimum:

| Test | What it locks |
|------|---------------|
| `test_index_renders_latest_run_summary` | bucket counts on the home page match the most-recent `runs` rows |
| `test_index_includes_inlined_quadrant_svg` | the `<svg>...</svg>` from the latest quadrant HTML appears verbatim in `index.html` |
| `test_index_link_paths_are_relative` | no `file://`, no protocol-prefixed `href` / `src` |
| `test_run_page_emitted_per_distinct_ts_iso` | each distinct `ts_iso` in `runs` produces a `runs/<ts>.html` |
| `test_run_page_artefact_links_best_effort` | a run with no disk MD shows "—" in the MD column, doesn't error |
| `test_run_artefacts_table_created_idempotent` | `CREATE TABLE IF NOT EXISTS run_artefacts` adds the table to an existing cache file without disturbing other tables |
| `test_pipeline_output_writes_run_artefacts_row` | a successful `_output` invocation inserts one row keyed by the second-precision `ts_iso` with the microsecond `disk_stamp` and absolute `out_dir` |
| `test_discover_runs_left_join_handles_missing_artefact_row` | a `runs` ts with no matching `run_artefacts` row renders artefact links as "—" instead of erroring |
| `test_cve_page_trajectory_uses_runs_table` | a 3-snapshot fixture renders 3 points |
| `test_cve_page_links_associations` | a Log4Shell fixture lists APT41 + HAFNIUM + Aquatic Panda |
| `test_cve_page_renders_exploit_status` | ExploitDB id + Nuclei template + GitHub-PoC names appear inline |
| `test_cve_page_renders_iocs_from_sidecar` | IOCs whose `linked_cves` contains the CVE id appear inline |
| `test_cve_page_ioc_cap_at_50` | above 50 IOCs → "+N more" footer |
| `test_bucket_policy_threaded_through_pages` | `--config aggressive` propagates custom labels into home + run + CVE pages |
| `test_html_escapes_cve_description` | `<script>` in a description renders as `&lt;script&gt;` |
| `test_no_external_assets` | no `<link rel="stylesheet" href="http…">`, no `<script src="http…">` |
| `test_no_javascript` | no `<script>` tag at all |
| `test_site_is_byte_stable` | second build → no diff (analogous to `regen --check` rc=0) |
| `test_site_dir_required` | `ramen-cve web` without `--site-dir` exits non-zero with usage |

Plus the frozen-bundle oracle (`examples/_web-sample/`) regenerated by
`scripts/regen_examples.py --check`.

---

## 8. Implementation slices (post-design, not in this PR)

Same thin-vertical-delivery cadence as Tasks 1-3 + 6 + 7. Each slice
ends with `pytest tests/ -q`, ruff clean, and the byte-oracle still
matching the anchor.

| Slice | Scope | LOC est. |
|------:|-------|---------:|
| A | `web/builder.py` skeleton + `ramen-cve web --site-dir` subcommand + facade lock + HTML-escape invariant + single `static/style.css`. Emits a minimal `<site-dir>/index.html` with the H1 and a "N runs" placeholder pulled from the `runs` table. Tests: subcommand parses; `--site-dir` is required; empty `runs` table → 1 file; CSS shipped; unconditional `html.escape`. | ~250 |
| B | **New `run_artefacts` SQLite table.** Schema in `cache.py`; `Cache.record_artefacts(ts_iso, disk_stamp, out_dir)` writer; `pipeline._output` call-site update (stamps the artefacts row after every successful write). Tests: schema upgrade idempotent on existing cache files; `_output` populates the table; multi-write per run captured once. | ~150 |
| C | `_discover_runs(cache, out_dir)` helper. SQLite is canonical; the artefacts table supplies the exact disk stamp via `LEFT JOIN`. The home-page run-history strip renders with best-effort artefact links. Per-run summary page (`runs/<ts>.html`) with the bucket breakdown + the Task-6 quadrant inlined. Tests: discovery returns SQLite ts; missing artefacts row → "—"; daemon-iteration subdir variant linked correctly. | ~350 |
| D | Per-CVE detail page sections 1-3 (header, summary, trajectory). The trajectory chart reuses Task-6's `_render_quadrant_svg` in a single-CVE multi-snapshot mode (one point per `runs` row). Tests: 3-snapshot fixture; sparkline-fallback below 2 points; cap at 200. | ~350 |
| E | Per-CVE detail page sections 4-7 (exploit status, associations, IOCs, affected hosts) — the "rich" content the design owner asked for. Tests: ExploitDB + Nuclei + GitHub-PoC rendering; IOC cap at 50; Log4Shell association fixture. | ~300 |
| F | Diff block on `runs/<ts>.html` ("added / removed / reclassified since previous run"). Tests: a 3-CVE / 2-run fixture; reclassification surfaces. | ~200 |
| G | Bucket-policy threading (`--config NAME` → `args.bucket_policy` → every label in every page) + showcase regen extension. `scripts/regen_examples.py` also emits `examples/_web-sample/`; `regen --check` validates the bundle. Tests: byte-stable second build; `regen --check` rc=0 includes the web bundle; `--config aggressive` propagates labels into home + run + CVE pages. | ~250 |

Total ≈ 1850 LOC + tests. The `run_artefacts` table (Slice B) + the
"rich" CVE page (Slice E) + the diff block (Slice F) + bucket-policy
threading (Slice G) push the original 20-30 h estimate to **26-34 h**
end-to-end.

---

## 9. Showcase: committed `examples/_web-sample/`

`scripts/regen_examples.py` (already shipping the CSV / MD / inventory
/ quadrant showcase) gets a fourth pass that runs `ramen-cve web`
against the same inline fixture set, with `--site-dir` pointed at a
temp dir, and copies the output into `examples/_web-sample/`. The
existing live-clock normalisation (`Generated:` line, absolute paths)
is extended to the new `index.html` / `runs/<ts>.html` / `cve/<id>.html`
files. `regen --check` rc=0 includes the bundle in the byte-diff gate.

The committed `_web-sample/` becomes a user's first-look at the Web
UI: `git clone && open examples/_web-sample/index.html`.

---

## 10. Explicit deferrals (out of scope for v1)

- **Search.** No client-side or server-side search in v1. CVE-id
  navigation is by direct URL: `cve/CVE-2021-44228.html`.
- **Filtering.** No bucket filter, no CVSS-range slider, no
  free-text filter. The Markdown report is still the rich view.
- **`--latest-only`.** Defer to v1.1 — the full-site write is fast
  enough that this is premature optimisation. Each `ramen-cve web`
  invocation rewrites the entire `<site-dir>`.
- **Authentication / multi-tenant.** No login. Anyone with file
  access has full access.
- **Real-time updates.** A static site doesn't refresh. Re-running
  `ramen-cve web` rewrites the bundle.
- **Mobile-first responsive design.** Page renders fine at 800-1200
  px wide. Mobile is a stretch goal for v1.1.
- **Internationalisation.** English only.
- **Export.** No "export to PDF" — print-friendly CSS only.
- **`audit_log` surfacing.** Operationally sensitive; a future
  operator-only view is a separate spec.

---

## 11. Decision log

Every design call below was confirmed with the project owner before
this doc was committed:

| # | Decision | Choice | Alternative weighed |
|---|----------|--------|---------------------|
| D1 | Subcommand name | `ramen-cve web` | `report` (ambiguous with the MD report), `site`, `--format web` (awkward for a directory tree) |
| D2 | Run source of truth | **Both**: SQLite `runs` table is canonical; disk artefacts are best-effort linked | Disk-only (loses runs without HTML); SQLite-only (no artefact links) |
| D3 | Per-CVE page scope | **Rich**: trajectory + actors + exploit-status + IOCs + affected hosts inline | "Lean" (link to MD for everything beyond NVD summary + trajectory); lean v1 + rich v1.1 |
| D4 | Bucket policy | **Honoured**: `--config NAME` threads `args.bucket_policy` through; custom labels propagate to every page | Always render DEFAULT_BUCKET_POLICY labels (label-mismatch vs MD report) |
| D5 | `--site-dir` default | **No default — required** | `<out-dir>/_web/` (overwrite risk); `<cwd>/_web/` |
| D6 | CSS strategy | **Single shared `static/style.css`** linked from every page | Inline `<style>` block per page (decouples cosmetics from oracle, but tripled payload) |
| D7 | Showcase bundle | **Yes**: extend `scripts/regen_examples.py` to commit `examples/_web-sample/` | Generator only, no committed bundle |
| D8 | `--latest-only` flag | **Defer to v1.1** | Ship in v1 as a fast-incremental path |
| D9 | ts-precision matching | **New `run_artefacts` SQLite table** (`ts_iso PK`, `disk_stamp`, `out_dir`), populated by `pipeline._output` | Second-truncate + glob (false-positive risk under daemon mode); augment `runs` schema (data duplication N×) |
| D10 | HTML escape policy | **Defang everything**: `html.escape(..., quote=True)` unconditionally | Preserve a known-safe HTML allowlist (`<i>`, `<b>`, `<code>`, `<br>`) — new attack surface |
| D11 | Diff block on `runs/<ts>.html` | **v1**: ship Slice F as drafted | Defer to v1.1 — per-run pages become bucket-table-only |
| D12 | When to commit this doc | **Commit + push + draft PR** | Hold for further iteration |

---

## 12. Decision summary (the part to argue with)

The narrowest interpretation of "Web UI" that's still useful is a
**deterministic static HTML generator** that turns the never-purged
`runs` table (canonical) + the per-run on-disk artefacts (best-effort
linked) into a navigable tree of
`<site-dir>/{index.html, runs/, cve/, static/}` pages with the Task-6
quadrant as the visual anchor, and the per-CVE detail page rich
enough to be the navigator equivalent of the Markdown report.

It adds **zero runtime dependencies**, **zero ongoing operational
cost**, **zero new attack surface** (no network listener), respects
**Task 7's `BucketPolicy`** for label customisation, and slots into
the existing `ramen-cve <subcommand>` shape via a new `web` verb.

If the design holds up under review, Slice A is the natural first
implementation PR.
