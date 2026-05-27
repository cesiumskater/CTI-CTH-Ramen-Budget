# Web UI — Design Doc (HISTORICAL)

> **Status: SHIPPED.** All seven slices (A → G) landed; the `ramen-cve web`
> subcommand and `src/ramen_cve/web/builder.py` are the live
> implementation. This document is preserved because `cli.py`,
> `web/__init__.py`, and `web/builder.py` reference it for design
> rationale. For **user-facing** Web UI docs, see the
> [`Web UI` section in `README.md`](../README.md#web-ui).

---

## What shipped

A read-only static-HTML generator over the SQLite `runs` table and
on-disk run artefacts. Zero new runtime dependency, no server, no JS
framework.

Invocation:

```bash
ramen-cve web --site-dir ./_site
```

Generated tree:

```
<site-dir>/
  index.html                # bucket breakdown + quadrant + run-history strip
  static/style.css          # single shared stylesheet
  runs/<ts>.html            # per-run summary + "added/removed/reclassified" diff
  cve/<CVE-ID>.html         # header + summary + trajectory + exploit + associations + IOCs + hosts
```

A committed showcase bundle lives at `examples/_web-sample/` — clone the
repo and open `examples/_web-sample/index.html` for a first look.

## Key invariants (still locked by tests)

- **Zero new runtime dep.** Stdlib only.
- **Zero JavaScript.** Inline `<style>` / external `static/style.css` only.
  No `<script>` tag anywhere.
- **Read-only.** Mutations would require a server; out of scope.
- **Deterministic.** Pages are byte-stable for a fixed `_utcnow` mock and
  a fixed cache snapshot. Same standard as the existing CSV / MD / STIX
  writers; gated by `tests/test_web_ui.py`.
- **HTML-escape everywhere.** `html.escape(..., quote=True)`
  unconditionally on every interpolated string. No allowlist.
- **`--site-dir` is required.** No default — matches the
  `_safe_basename` / `_unique_output_path` precedent and removes any
  "did I just overwrite something?" foot-gun.
- **Bucket-policy aware.** `--config NAME` threads `args.bucket_policy`
  through to every page so custom labels propagate from home → run →
  per-CVE.

## Schema addition

The Web UI introduced one new SQLite table to bridge the canonical
second-precision `runs.ts_iso` and the microsecond on-disk artefact
stamps:

```sql
CREATE TABLE IF NOT EXISTS run_artefacts (
    ts_iso     TEXT PRIMARY KEY,        -- matches runs.ts_iso (second precision)
    disk_stamp TEXT NOT NULL,           -- microsecond filename stamp
    out_dir    TEXT NOT NULL            -- absolute path that _output wrote into
);
```

`CREATE TABLE IF NOT EXISTS` runs on every `Cache.__init__`, so existing
cache files pick the table up on first open with no migration.

## Explicit deferrals (still out of scope)

- Search / filtering / sort controls (would need JS).
- `--latest-only` incremental builds.
- Authentication / multi-tenant.
- Real-time updates (re-run `ramen-cve web` to refresh).
- Mobile-first responsive design.
- Internationalisation; English only.
- `audit_log` surfacing — operationally sensitive; a future
  operator-only view would be a separate spec.

## Where to look next

- User docs → `README.md` (`Web UI` section).
- Implementation → `src/ramen_cve/web/builder.py`.
- Test contract → `tests/test_web_ui.py`.
- Backlog for future slices → `tasks/todo.md` (`Web UI` task entry).
