"""Tests for `ramen_cve.web.builder` — Task 8 Slice A.

Locks the minimal-shell contract: `--site-dir` is required, an empty
`runs` table raises WebUiError (`_run_web` → rc=1, no files written),
a populated `runs` table produces `index.html` + `static/style.css`
with the design-doc §5.1 invariants (HTML5 doctype, UTF-8 charset,
linked stylesheet, generator meta tag, H1, N-runs paragraph).
Byte-stable second build. No JavaScript. No external assets.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pytest

from ramen_cve.bucket_policy import DEFAULT_BUCKET_POLICY
from ramen_cve.cache import Cache
from ramen_cve.cli import VERSION, _run_web
from ramen_cve.models import WebUiError
from ramen_cve.web.builder import (
    WEB_DEFAULT_MAX_RUNS_ON_HOME,
    _render_index,
    build_site,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cache_with_runs(tmp_path, n: int) -> Cache:
    """Build a Cache backed by `tmp_path/.cache.db` with `n` distinct runs."""
    cache = Cache(tmp_path / ".cache.db")
    for i in range(n):
        # Mutate the ts to force distinct ts_iso. record_run uses _utcnow()
        # at second precision; a single per-row insert during the same
        # second collapses to one row, so we INSERT directly.
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            (f"CVE-2024-{i:04d}", f"2024-01-01T00:00:{i:02d}+00:00",
             "patch_now", 9.0, 0.5),
        )
    cache._conn.commit()
    return cache


def _site_args(site_dir):
    return argparse.Namespace(site_dir=site_dir, quiet=False, verbose=False)


# ---------------------------------------------------------------------------
# Pure-function tests for `_render_index` (no I/O).
# ---------------------------------------------------------------------------


def test_render_index_html5_doctype():
    assert _render_index(1, VERSION).startswith("<!doctype html>")


def test_render_index_includes_lang_attribute():
    assert '<html lang="en">' in _render_index(1, VERSION)


def test_render_index_includes_utf8_charset():
    assert '<meta charset="utf-8">' in _render_index(1, VERSION)


def test_render_index_includes_generator_meta():
    body = _render_index(1, "0.1")
    assert '<meta name="generator" content="ramen-cve 0.1">' in body


def test_render_index_links_stylesheet():
    assert '<link rel="stylesheet" href="static/style.css">' in _render_index(1, VERSION)


def test_render_index_includes_h1():
    assert "<h1>Ramen CVE Triage</h1>" in _render_index(1, VERSION)


def test_render_index_pluralises_n_runs_correctly():
    """English plural: 0 runs / 1 run / 2 runs."""
    assert "<p>0 runs recorded.</p>" in _render_index(0, VERSION)
    assert "<p>1 run recorded.</p>" in _render_index(1, VERSION)
    assert "<p>2 runs recorded.</p>" in _render_index(2, VERSION)


def test_render_index_escapes_a_poisoned_version_string():
    """A `<script>`-laced VERSION must not smuggle markup into the page."""
    body = _render_index(1, "1.0<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_render_index_has_no_javascript_tag():
    """Slice A ships zero JS. The doc §4.5 + §10 invariant."""
    assert "<script>" not in _render_index(5, VERSION)
    assert "<script " not in _render_index(5, VERSION)


# ---------------------------------------------------------------------------
# `build_site` integration tests (touches disk).
# ---------------------------------------------------------------------------


def test_build_site_writes_index_html_and_css_with_one_run(tmp_path):
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    paths = build_site(cache, site_dir)

    assert paths["index"] == site_dir / "index.html"
    assert paths["css"] == site_dir / "static" / "style.css"
    assert paths["index"].is_file()
    assert paths["css"].is_file()


def test_build_site_index_reports_runs_count_from_runs_table(tmp_path):
    cache = _cache_with_runs(tmp_path, n=3)
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "<p>3 runs recorded.</p>" in body


def test_build_site_empty_runs_table_raises_web_ui_error(tmp_path):
    """An empty runs table is fail-fast (design-doc §D11)."""
    cache = Cache(tmp_path / ".cache.db")  # no runs inserted
    site_dir = tmp_path / "site"
    with pytest.raises(WebUiError, match="No runs recorded"):
        build_site(cache, site_dir)


def test_build_site_does_not_write_anything_when_runs_empty(tmp_path):
    """A failed build leaves the filesystem unchanged."""
    cache = Cache(tmp_path / ".cache.db")
    site_dir = tmp_path / "site"
    with pytest.raises(WebUiError):
        build_site(cache, site_dir)
    assert not site_dir.exists()


def test_build_site_creates_nested_static_dir(tmp_path):
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "deeply" / "nested" / "site"
    build_site(cache, site_dir)
    assert (site_dir / "static").is_dir()


def test_build_site_css_is_a_placeholder_in_slice_a(tmp_path):
    """Slice A's CSS is the file-with-a-comment that Slice G replaces."""
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    css = (site_dir / "static" / "style.css").read_text(encoding="utf-8")
    assert "populated in Slice G" in css


def test_build_site_is_byte_stable_across_two_runs(tmp_path):
    """Second build → identical bytes (design-doc §6 determinism gate)."""
    cache = _cache_with_runs(tmp_path, n=4)
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    first = (site_dir / "index.html").read_bytes()
    second_css = (site_dir / "static" / "style.css").read_bytes()
    build_site(cache, site_dir)
    assert (site_dir / "index.html").read_bytes() == first
    assert (site_dir / "static" / "style.css").read_bytes() == second_css


def test_build_site_accepts_policy_kwarg_without_consuming_it(tmp_path):
    """Slice A reserves the `policy` kwarg for Slice G — must be accepted now."""
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    paths = build_site(cache, site_dir, policy=DEFAULT_BUCKET_POLICY)
    assert paths["index"].is_file()


def test_build_site_accepts_max_runs_on_home_kwarg_without_consuming_it(tmp_path):
    """Slice A reserves the `max_runs_on_home` kwarg for Slice C — must be accepted now."""
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    paths = build_site(cache, site_dir, max_runs_on_home=5)
    assert paths["index"].is_file()


def test_web_default_max_runs_on_home_is_30():
    """Lock the design-doc §5.1 default."""
    assert WEB_DEFAULT_MAX_RUNS_ON_HOME == 30


# ---------------------------------------------------------------------------
# `_run_web` (CLI handler) — rc semantics + audit-log-friendly logging.
# ---------------------------------------------------------------------------


def test_run_web_returns_0_when_runs_present_and_prints_paths(tmp_path, capsys):
    cache = _cache_with_runs(tmp_path, n=2)
    rc = _run_web(_site_args(tmp_path / "site"), cache, None)
    assert rc == 0
    stdout = capsys.readouterr().out.splitlines()
    assert any(line.endswith("index.html") for line in stdout)
    assert any(line.endswith("style.css") for line in stdout)


def test_run_web_returns_1_when_runs_empty(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    rc = _run_web(_site_args(tmp_path / "site"), cache, None)
    assert rc == 1


def test_run_web_logs_warning_when_runs_empty(tmp_path, caplog):
    cache = Cache(tmp_path / ".cache.db")
    # _run_web re-emits the WebUiError as a WARNING under the cli logger;
    # capture broadly so either logger name matches.
    with caplog.at_level(logging.WARNING):
        _run_web(_site_args(tmp_path / "site"), cache, None)
    messages = [rec.message for rec in caplog.records]
    assert any("No runs recorded" in m for m in messages)


def test_run_web_no_files_written_when_runs_empty(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    site_dir = tmp_path / "site"
    _run_web(_site_args(site_dir), cache, None)
    assert not site_dir.exists()


# ---------------------------------------------------------------------------
# Argparse — `--site-dir` is required.
# ---------------------------------------------------------------------------


def test_web_subcommand_requires_site_dir(capsys):
    """`ramen-cve web` without --site-dir exits non-zero with usage."""
    from ramen_cve.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["web"])
    err = capsys.readouterr().err
    assert "--site-dir" in err


def test_web_subcommand_parses_with_site_dir(tmp_path):
    from ramen_cve.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["web", "--site-dir", str(tmp_path / "site")])
    assert args.subcommand == "web"
    assert str(args.site_dir) == str(tmp_path / "site")


# ---------------------------------------------------------------------------
# "No external assets" + "no JS" invariants on a real build.
# ---------------------------------------------------------------------------


def test_built_index_has_no_protocol_prefixed_assets(tmp_path):
    """No `<link href="http…">` / `<script src="http…">` / etc."""
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "http://" not in body
    assert "https://" not in body
    assert "file://" not in body


def test_built_index_has_no_script_tag(tmp_path):
    cache = _cache_with_runs(tmp_path, n=1)
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "<script" not in body


# ---------------------------------------------------------------------------
# Slice B — `run_artefacts` table + `Cache.record_artefacts` writer
# + `pipeline._output(cache=...)` integration.
# ---------------------------------------------------------------------------


def test_record_artefacts_inserts_a_row(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    cache.record_artefacts(
        "2026-05-25T13:25:01", "20260525T132501478665", "/tmp/out"
    )
    row = cache.get_artefacts("2026-05-25T13:25:01")
    assert row == {
        "ts_iso": "2026-05-25T13:25:01",
        "disk_stamp": "20260525T132501478665",
        "out_dir": "/tmp/out",
    }


def test_get_artefacts_returns_none_when_absent(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    assert cache.get_artefacts("never-recorded") is None


def test_record_artefacts_insert_or_ignore_skips_collision(tmp_path):
    """Second insert with same ts_iso must NOT overwrite the first (design-doc §D25)."""
    cache = Cache(tmp_path / ".cache.db")
    cache.record_artefacts("2026-05-25T13:25:01", "first-stamp", "/tmp/A")
    cache.record_artefacts("2026-05-25T13:25:01", "second-stamp", "/tmp/B")
    row = cache.get_artefacts("2026-05-25T13:25:01")
    assert row["disk_stamp"] == "first-stamp"
    assert row["out_dir"] == "/tmp/A"


def test_run_artefacts_schema_upgrade_idempotent_on_existing_cache(tmp_path):
    """Opening an existing cache file twice keeps the run_artefacts table intact."""
    db = tmp_path / ".cache.db"
    cache1 = Cache(db)
    cache1.record_artefacts("2026-05-25T13:25:01", "stamp", "/tmp/out")
    # Drop the connection; re-open. CREATE TABLE IF NOT EXISTS must
    # leave the existing row intact rather than recreating empty.
    cache1._conn.close()
    cache2 = Cache(db)
    row = cache2.get_artefacts("2026-05-25T13:25:01")
    assert row is not None
    assert row["disk_stamp"] == "stamp"


def _output_args(tmp_path, fmt="csv"):
    """Minimal argparse.Namespace accepted by pipeline._output."""
    import argparse

    return argparse.Namespace(
        format=fmt, out_dir=tmp_path, basename="run-x",
        allow_tlp_red=False,
    )


def _patch_record(rec_cls, **fields):
    """Helper to build an EnrichedCve with cve_id 'CVE-2024-0001' by default."""
    from datetime import date

    defaults = {
        "cve_id": "CVE-2024-0001", "source": "test",
        "first_seen": date(2024, 1, 1), "first_seen_type": "feed_pub",
        "cvss_score": 9.0, "epss_score": 0.5, "bucket": "patch_now",
    }
    defaults.update(fields)
    return rec_cls(**defaults)


def test_output_no_cache_kwarg_skips_artefacts_write(tmp_path):
    """Back-compat path: cache=None must not touch any table."""
    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    rec = _patch_record(EnrichedCve)
    paths = _output([rec], _output_args(tmp_path), {"version": "0.1"})
    # Sanity: file was written.
    assert paths["csv"] is not None
    # The point of the test: no exception (no cache provided), no row
    # could possibly have been written. Nothing to assert beyond clean
    # completion.


def test_output_with_cache_writes_run_artefacts_row(tmp_path):
    """When cache is plumbed through, _output stamps an artefacts row."""
    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    cache = Cache(tmp_path / ".cache.db")
    rec = _patch_record(EnrichedCve)
    paths = _output([rec], _output_args(tmp_path), {"version": "0.1"}, cache=cache)
    assert paths["csv"] is not None

    rows = cache._conn.execute(
        "SELECT ts_iso, disk_stamp, out_dir FROM run_artefacts"
    ).fetchall()
    assert len(rows) == 1
    ts_iso, disk_stamp, out_dir = rows[0]
    assert ts_iso  # naive ISO seconds, format "YYYY-MM-DDTHH:MM:SS"
    assert "T" in ts_iso and ts_iso.count(":") == 2
    assert "+" not in ts_iso  # naive, per design-doc §D27
    assert len(disk_stamp) == 21  # YYYYMMDDTHHMMSS + 6 microseconds
    assert disk_stamp.startswith(ts_iso[:4])  # year prefix matches
    assert str(tmp_path) in out_dir


def test_output_with_cache_skips_artefacts_row_when_no_files_written(tmp_path):
    """When TLP:RED stripping leaves no records and no format produces a file,
    _output must NOT stamp a row (design-doc §D26: conditional record)."""
    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    cache = Cache(tmp_path / ".cache.db")
    # Sigma-only format + a record with no kev_override / patch_now ↔
    # write_sigma_stubs returns empty → paths["sigma_dir"] stays None.
    rec = _patch_record(EnrichedCve, bucket="deprioritize")
    paths = _output([rec], _output_args(tmp_path, fmt="sigma"), {"version": "0.1"},
                    cache=cache)
    assert all(p is None for p in paths.values())
    row_count = cache._conn.execute(
        "SELECT COUNT(*) FROM run_artefacts"
    ).fetchone()[0]
    assert row_count == 0


def test_output_ts_iso_format_matches_record_run(tmp_path):
    """Slice B's run_artefacts.ts_iso must literal-equal what Cache.record_run
    writes today, so the Web UI's LEFT JOIN finds the row (design-doc §D27)."""
    from datetime import datetime
    from unittest.mock import patch

    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    cache = Cache(tmp_path / ".cache.db")
    rec = _patch_record(EnrichedCve)

    # Freeze the clock to a fixed naive UTC instant so both writers
    # produce identical second-precision strings.
    frozen = datetime(2026, 5, 25, 13, 25, 1, 478665)
    with patch("ramen_cve.models._utcnow", return_value=frozen), \
         patch("ramen_cve.cache._utcnow", return_value=frozen), \
         patch("ramen_cve.pipeline._utcnow", return_value=frozen):
        cache.record_run("CVE-2024-0001", "patch_now", 9.0, 0.5)
        _output([rec], _output_args(tmp_path), {"version": "0.1"}, cache=cache)

    runs_ts = cache._conn.execute("SELECT DISTINCT ts_iso FROM runs").fetchone()[0]
    artefacts_ts = cache._conn.execute(
        "SELECT ts_iso FROM run_artefacts"
    ).fetchone()[0]
    assert runs_ts == artefacts_ts == "2026-05-25T13:25:01"


def test_output_stamps_one_row_per_invocation(tmp_path):
    """Multi-file format (csv+md+stix+sigma+yara+html via --format all) →
    still exactly one run_artefacts row per _output call."""
    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    cache = Cache(tmp_path / ".cache.db")
    rec = _patch_record(EnrichedCve, bucket="kev_override", kev_listed=True)
    args = _output_args(tmp_path, fmt="all")
    _output([rec], args, {"version": "0.1"}, cache=cache)
    row_count = cache._conn.execute(
        "SELECT COUNT(*) FROM run_artefacts"
    ).fetchone()[0]
    assert row_count == 1


def test_output_out_dir_stored_absolute(tmp_path):
    """Stored `out_dir` should be the resolved absolute path so the Web UI
    can locate artefacts regardless of cwd at render time."""
    from ramen_cve.models import EnrichedCve
    from ramen_cve.pipeline import _output

    cache = Cache(tmp_path / ".cache.db")
    rec = _patch_record(EnrichedCve)
    _output([rec], _output_args(tmp_path), {"version": "0.1"}, cache=cache)
    row = cache._conn.execute(
        "SELECT out_dir FROM run_artefacts"
    ).fetchone()
    # _resolve_out_dir on an explicit absolute tmp_path returns it
    # unchanged; the value stamped should equal tmp_path verbatim.
    assert row[0] == str(tmp_path)


# ---------------------------------------------------------------------------
# Slice C — `_discover_runs` + per-run summary pages + index strip.
# ---------------------------------------------------------------------------


def _seed_run(cache, ts_iso, *, cve_ids, artefacts=None):
    """Seed `runs` rows for one ts_iso, plus optional `run_artefacts` row.

    `artefacts` is `(disk_stamp, out_dir)` when present, None otherwise
    (the LEFT-JOIN-miss case the discovery helper has to handle).
    """
    for cve_id in cve_ids:
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            (cve_id, ts_iso, "patch_now", 9.0, 0.5),
        )
    if artefacts is not None:
        disk_stamp, out_dir = artefacts
        cache._conn.execute(
            "INSERT OR IGNORE INTO run_artefacts (ts_iso, disk_stamp, out_dir) "
            "VALUES (?, ?, ?)",
            (ts_iso, disk_stamp, str(out_dir)),
        )
    cache._conn.commit()


def _make_artefact_files(out_dir, disk_stamp, *, kinds=("csv", "md", "stix", "html")):
    """Create empty placeholder artefact files for the given kinds.

    Filenames mirror what `pipeline._output` writes. Used to exercise
    the best-effort link branch (file present → `<a>`; absent → "—").
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix_for = {
        "csv": ".csv", "md": ".md", "stix": ".stix.json", "html": ".html",
    }
    dir_for = {"sigma": "-sigma", "yara": "-yara"}
    for kind in kinds:
        if kind in suffix_for:
            (out_dir / f"ramen-cve-{disk_stamp}{suffix_for[kind]}").write_text("")
        elif kind in dir_for:
            (out_dir / f"ramen-cve-{disk_stamp}{dir_for[kind]}").mkdir()


# ---- `_slugify_ts` --------------------------------------------------------


def test_slugify_ts_replaces_colons_with_dashes():
    from ramen_cve.web.builder import _slugify_ts

    assert _slugify_ts("2026-05-26T14:03:11") == "2026-05-26T14-03-11"


def test_slugify_ts_handles_tz_suffix():
    """The direct-insert path in test helpers carries a `+00:00` tail —
    must remain filesystem-safe after slugification."""
    from ramen_cve.web.builder import _slugify_ts

    assert _slugify_ts("2024-01-01T00:00:00+00:00") == "2024-01-01T00-00-00+00-00"


# ---- `_discover_runs` ----------------------------------------------------


def test_discover_runs_returns_empty_list_when_runs_table_empty(tmp_path):
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    assert _discover_runs(cache) == []


def test_discover_runs_one_row_per_distinct_ts_iso(tmp_path):
    """Three runs with 1, 2, 1 CVEs respectively → three rows."""
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-2024-0001"])
    _seed_run(cache, "2026-05-25T11:00:00",
              cve_ids=["CVE-2024-0002", "CVE-2024-0003"])
    _seed_run(cache, "2026-05-25T12:00:00", cve_ids=["CVE-2024-0004"])

    rows = _discover_runs(cache)
    assert len(rows) == 3


def test_discover_runs_is_descending_by_ts_iso(tmp_path):
    """Newest first — matches `Cache.list_run_timestamps` ordering."""
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    _seed_run(cache, "2026-05-25T12:00:00", cve_ids=["CVE-B"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-C"])

    rows = _discover_runs(cache)
    assert [r.ts_iso for r in rows] == [
        "2026-05-25T12:00:00",
        "2026-05-25T11:00:00",
        "2026-05-25T10:00:00",
    ]


def test_discover_runs_counts_distinct_cves_per_run(tmp_path):
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00",
              cve_ids=["CVE-A", "CVE-B", "CVE-C"])
    rows = _discover_runs(cache)
    assert rows[0].cve_count == 3


def test_discover_runs_attaches_artefacts_when_row_present(tmp_path):
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"],
              artefacts=("20260525T100000123456", "/tmp/out"))
    row = _discover_runs(cache)[0]
    assert row.disk_stamp == "20260525T100000123456"
    assert row.out_dir == "/tmp/out"


def test_discover_runs_left_join_miss_returns_none_for_disk_stamp(tmp_path):
    """A `runs` ts with no matching `run_artefacts` row → None disk_stamp + out_dir."""
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])  # no artefacts
    row = _discover_runs(cache)[0]
    assert row.disk_stamp is None
    assert row.out_dir is None


def test_discover_runs_mixes_with_and_without_artefacts(tmp_path):
    """Real-world: some runs predate Slice B (no artefacts row), some have one."""
    from ramen_cve.web.builder import _discover_runs

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])  # missing
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-B"],
              artefacts=("20260525T110000222222", "/tmp/out"))
    rows = _discover_runs(cache)
    # Newest first.
    assert rows[0].disk_stamp == "20260525T110000222222"
    assert rows[1].disk_stamp is None


# ---- Per-run page emission -----------------------------------------------


def test_build_site_emits_one_run_page_per_ts_iso(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-B"])
    _seed_run(cache, "2026-05-25T12:00:00", cve_ids=["CVE-C"])

    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    pages = sorted(p.name for p in (site_dir / "runs").iterdir())
    assert pages == [
        "2026-05-25T10-00-00.html",
        "2026-05-25T11-00-00.html",
        "2026-05-25T12-00-00.html",
    ]


def test_build_site_run_page_filename_uses_slugified_ts(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    assert (site_dir / "runs" / "2026-05-26T14-03-11.html").is_file()


def test_run_page_contains_h1_with_ts_iso(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "<h1>Run 2026-05-26T14:03:11</h1>" in body


def test_run_page_reports_cve_count_singular(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "<p>1 CVE in this run.</p>" in body


def test_run_page_reports_cve_count_plural(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X", "CVE-Y", "CVE-Z"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "<p>3 CVEs in this run.</p>" in body


def test_run_page_lists_all_six_artefact_kinds(tmp_path):
    """The 6 mainline artefact kinds appear as labels regardless of presence."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    for label in ("CSV", "MD", "STIX", "HTML", "Sigma", "YARA"):
        assert f"<th>{label}</th>" in body


def test_run_page_renders_dash_when_artefacts_row_missing(tmp_path):
    """No `run_artefacts` row → all 6 cells render "—"."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])  # no artefacts
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    # 6 dashes — once per artefact row.
    assert body.count("<td>—</td>") == 6


def test_run_page_links_present_artefacts(tmp_path):
    """When the row + the files exist, the page renders `<a href>` links."""
    out_dir = tmp_path / "run-out"
    _make_artefact_files(out_dir, "20260526T140311000000",
                         kinds=("csv", "md", "stix", "html", "sigma", "yara"))
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"],
              artefacts=("20260526T140311000000", out_dir))
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "ramen-cve-20260526T140311000000.csv" in body
    assert "ramen-cve-20260526T140311000000.md" in body
    assert "ramen-cve-20260526T140311000000.stix.json" in body
    assert "ramen-cve-20260526T140311000000.html" in body
    assert "ramen-cve-20260526T140311000000-sigma" in body
    assert "ramen-cve-20260526T140311000000-yara" in body


def test_run_page_renders_dash_for_missing_files_when_row_present(tmp_path):
    """A row exists, but only CSV + MD files actually exist on disk —
    the other four cells must render "—" without erroring."""
    out_dir = tmp_path / "run-out"
    _make_artefact_files(out_dir, "20260526T140311000000", kinds=("csv", "md"))
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"],
              artefacts=("20260526T140311000000", out_dir))
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    # csv + md cells contain hrefs; stix + html + sigma + yara → 4 dashes.
    assert body.count("<td>—</td>") == 4


def test_run_page_uses_relative_artefact_hrefs(tmp_path):
    """Artefact `href`s never carry protocol prefixes (file://, http://)."""
    out_dir = tmp_path / "run-out"
    _make_artefact_files(out_dir, "20260526T140311000000", kinds=("csv",))
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"],
              artefacts=("20260526T140311000000", out_dir))
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "file://" not in body
    assert "http://" not in body
    assert "https://" not in body


def test_run_page_css_link_is_relative_to_parent(tmp_path):
    """Per-run pages live one level deeper than `static/`."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert '<link rel="stylesheet" href="../static/style.css">' in body


def test_run_page_has_no_javascript(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "runs" / "2026-05-26T14-03-11.html").read_text("utf-8")
    assert "<script" not in body


# ---- Index run-history strip ---------------------------------------------


def test_index_includes_run_history_strip(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    assert "<h2>Run history</h2>" in body


def test_index_strip_is_reverse_chronological(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    _seed_run(cache, "2026-05-25T12:00:00", cve_ids=["CVE-B"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-C"])

    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    pos_newest = body.find("2026-05-25T12:00:00")
    pos_middle = body.find("2026-05-25T11:00:00")
    pos_oldest = body.find("2026-05-25T10:00:00")
    assert 0 < pos_newest < pos_middle < pos_oldest


def test_index_strip_caps_at_max_runs_on_home(tmp_path):
    """5 runs with max_runs_on_home=2 → only the 2 newest appear in the strip."""
    cache = Cache(tmp_path / ".cache.db")
    for i in range(5):
        _seed_run(cache, f"2026-05-25T1{i}:00:00", cve_ids=[f"CVE-{i}"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir, max_runs_on_home=2)
    body = (site_dir / "index.html").read_text("utf-8")
    # Newest two present.
    assert "2026-05-25T14:00:00" in body
    assert "2026-05-25T13:00:00" in body
    # Older three absent from the index (still reachable via runs/<slug>.html).
    assert "2026-05-25T12:00:00" not in body
    assert "2026-05-25T11:00:00" not in body
    assert "2026-05-25T10:00:00" not in body


def test_index_strip_links_to_per_run_page(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    assert 'href="runs/2026-05-26T14-03-11.html"' in body


def test_index_strip_renders_dash_when_artefacts_missing(tmp_path):
    """A run with no `run_artefacts` row → 6 dashes on its strip row."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    assert body.count("<td>—</td>") == 6


def test_index_strip_links_present_artefacts_relatively(tmp_path):
    """Index lives at the site root, so its artefact links use `../<out_dir>/…`
    rather than `runs/../<out_dir>/…`."""
    out_dir = tmp_path / "run-out"
    _make_artefact_files(out_dir, "20260526T140311000000", kinds=("csv",))
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"],
              artefacts=("20260526T140311000000", out_dir))
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    # The link text is the filename; the href is a relative path.
    assert "ramen-cve-20260526T140311000000.csv" in body
    assert "file://" not in body
    assert "https://" not in body


def test_empty_strip_when_runs_is_empty_does_not_emit_h2(tmp_path):
    """Defensive: the strip renderer returns "" for an empty list, so the
    index has no orphan `<h2>Run history</h2>` if every run got filtered out.
    (Cannot reach via `build_site` — empty runs raises — but the helper is
    independently callable.)"""
    from ramen_cve.web.builder import _render_strip

    out = _render_strip([], tmp_path / "site", cap=30)
    assert out == ""


def test_strip_row_includes_cve_count(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11",
              cve_ids=["CVE-A", "CVE-B", "CVE-C", "CVE-D"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "index.html").read_text("utf-8")
    # The strip's second column for this run holds the count.
    assert "<td>4</td>" in body


# ---- `build_site` return + byte stability with Slice C additions ---------


def test_build_site_returns_run_page_paths_in_dict(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-B"])
    site_dir = tmp_path / "site"
    paths = build_site(cache, site_dir)
    # Per-run page keys are surfaced (Slice D additionally writes per-CVE
    # pages — `len(paths)` is left unconstrained so future slices can
    # extend without churning this test).
    assert paths["run/2026-05-25T10-00-00"] == (
        site_dir / "runs" / "2026-05-25T10-00-00.html"
    )
    assert paths["run/2026-05-25T11-00-00"] == (
        site_dir / "runs" / "2026-05-25T11-00-00.html"
    )


def test_build_site_byte_stable_with_strip_and_run_pages(tmp_path):
    """The Slice C additions don't break the design-doc §6 byte-stability gate."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-B"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    first_index = (site_dir / "index.html").read_bytes()
    first_run1 = (site_dir / "runs" / "2026-05-25T10-00-00.html").read_bytes()
    first_run2 = (site_dir / "runs" / "2026-05-25T11-00-00.html").read_bytes()
    build_site(cache, site_dir)
    assert (site_dir / "index.html").read_bytes() == first_index
    assert (site_dir / "runs" / "2026-05-25T10-00-00.html").read_bytes() == first_run1
    assert (site_dir / "runs" / "2026-05-25T11-00-00.html").read_bytes() == first_run2


def test_run_web_prints_run_page_paths(tmp_path, capsys):
    """`_run_web`'s path-printing now surfaces per-run page paths too."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-26T14:03:11", cve_ids=["CVE-X"])
    rc = _run_web(_site_args(tmp_path / "site"), cache, None)
    assert rc == 0
    stdout = capsys.readouterr().out.splitlines()
    assert any(line.endswith("2026-05-26T14-03-11.html") for line in stdout)


# ---------------------------------------------------------------------------
# Slice D — per-CVE detail pages §§1-3 (header, summary, trajectory).
# Includes: refactored `_render_quadrant_svg_from_points` (one new caller),
# per-source raw cache readers, and `_render_cve_page`.
# ---------------------------------------------------------------------------


def _set_nvd_raw(cache, cve_id, payload):
    """Insert an `nvd_cache` row directly (TTL-irrelevant for raw reader)."""
    cache._conn.execute(
        "INSERT OR REPLACE INTO nvd_cache VALUES (?, ?, ?)",
        (cve_id, __import__("json").dumps(payload), "2020-01-01T00:00:00"),
    )
    cache._conn.commit()


def _set_epss_raw(cache, cve_id, score_date, payload):
    cache._conn.execute(
        "INSERT OR REPLACE INTO epss_cache VALUES (?, ?, ?, ?)",
        (cve_id, score_date, __import__("json").dumps(payload), "2020-01-01T00:00:00"),
    )
    cache._conn.commit()


def _set_kev_catalog_raw(cache, catalog):
    cache._conn.execute(
        "INSERT OR REPLACE INTO kev_cache VALUES (?, ?, ?)",
        ("catalog", __import__("json").dumps(catalog), "2020-01-01T00:00:00"),
    )
    cache._conn.commit()


# ---- Refactor invariant: existing `_render_quadrant_svg` is byte-stable --


def test_render_quadrant_svg_from_points_zero_points_still_renders_frame():
    """The points-list helper must render the chart frame even with no points."""
    from ramen_cve.output.html_quadrant import _render_quadrant_svg_from_points

    svg = _render_quadrant_svg_from_points([])
    assert svg.startswith("<svg")
    assert "</svg>" in svg
    assert "<circle" not in svg  # no data points


def test_render_quadrant_svg_from_points_is_latest_thickens_stroke():
    """`is_latest=True` adds the `cve-latest` class + a 2px stroke."""
    from ramen_cve.output.html_quadrant import _render_quadrant_svg_from_points

    svg = _render_quadrant_svg_from_points(
        [(9.0, 0.5, "tip", "patch_now", True)],
    )
    assert "cve-latest" in svg
    assert 'stroke-width="2"' in svg


def test_render_quadrant_svg_from_points_not_latest_uses_default_stroke():
    """Default `is_latest=False` stays bit-identical to pre-refactor output."""
    from ramen_cve.output.html_quadrant import _render_quadrant_svg_from_points

    svg = _render_quadrant_svg_from_points(
        [(9.0, 0.5, "tip", "patch_now", False)],
    )
    assert "cve-latest" not in svg
    assert 'stroke-width="0.5"' in svg


# ---- Cache raw readers ----------------------------------------------------


def test_get_nvd_raw_returns_payload_regardless_of_ttl(tmp_path):
    """An ancient `fetched_at` no longer hides the payload."""
    cache = Cache(tmp_path / ".cache.db", ttl_hours=1)
    _set_nvd_raw(cache, "CVE-2021-44228", {"cve_id": "CVE-2021-44228",
                                            "cvss_score": 10.0})
    # `get_nvd` would return None for this stale row.
    assert cache.get_nvd("CVE-2021-44228") is None
    # `get_nvd_raw` must bypass the freshness gate.
    raw = cache.get_nvd_raw("CVE-2021-44228")
    assert raw == {"cve_id": "CVE-2021-44228", "cvss_score": 10.0}


def test_get_nvd_raw_returns_none_when_absent(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    assert cache.get_nvd_raw("CVE-never-fetched") is None


def test_get_epss_raw_returns_latest_score_date(tmp_path):
    """Two rows for the same CVE → reader returns the newer `score_date`."""
    cache = Cache(tmp_path / ".cache.db", ttl_hours=1)
    _set_epss_raw(cache, "CVE-2021-44228", "2024-01-01",
                  {"epss": 0.50, "percentile": 0.95, "date": "2024-01-01"})
    _set_epss_raw(cache, "CVE-2021-44228", "2024-02-15",
                  {"epss": 0.55, "percentile": 0.96, "date": "2024-02-15"})
    raw = cache.get_epss_raw("CVE-2021-44228")
    assert raw["date"] == "2024-02-15"
    assert raw["epss"] == 0.55


def test_get_epss_raw_returns_none_when_absent(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    assert cache.get_epss_raw("CVE-no-rows") is None


def test_get_kev_catalog_raw_returns_payload_regardless_of_ttl(tmp_path):
    cache = Cache(tmp_path / ".cache.db", ttl_hours=1)
    _set_kev_catalog_raw(cache,
                         {"CVE-2021-44228": {"dueDate": "2021-12-24"}})
    assert cache.get_kev_catalog() is None  # stale via TTL gate
    raw = cache.get_kev_catalog_raw()
    assert raw == {"CVE-2021-44228": {"dueDate": "2021-12-24"}}


def test_get_kev_catalog_raw_returns_none_when_absent(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    assert cache.get_kev_catalog_raw() is None


# ---- Per-CVE page emission -----------------------------------------------


def test_build_site_emits_one_cve_page_per_distinct_cve(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A", "CVE-B"])
    _seed_run(cache, "2026-05-25T11:00:00", cve_ids=["CVE-A", "CVE-C"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    pages = sorted(p.name for p in (site_dir / "cve").iterdir())
    assert pages == ["CVE-A.html", "CVE-B.html", "CVE-C.html"]


def test_cve_page_contains_h1_with_cve_id(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-2021-44228"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-2021-44228.html").read_text("utf-8")
    assert "<h1>CVE-2021-44228" in body
    # `<h1>CVE-2021-44228 <span class="bucket">[Patch now]</span></h1>`-shape
    assert 'class="bucket"' in body


def test_cve_page_header_uses_most_recent_bucket(tmp_path):
    """A CVE that was reclassified between runs renders the final bucket."""
    cache = Cache(tmp_path / ".cache.db")
    cache._conn.execute(
        "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
        "VALUES (?, ?, ?, ?, ?)",
        ("CVE-X", "2026-05-25T10:00:00", "watch_closely", 7.0, 0.2),
    )
    cache._conn.execute(
        "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
        "VALUES (?, ?, ?, ?, ?)",
        ("CVE-X", "2026-05-26T10:00:00", "patch_now", 9.0, 0.5),
    )
    cache._conn.commit()
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    # DEFAULT_BUCKET_POLICY's label for "patch_now".
    assert "Patch Now" in body


def test_cve_page_links_nvd_url(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-2021-44228"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-2021-44228.html").read_text("utf-8")
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in body


def test_cve_page_renders_dash_when_summary_data_absent(tmp_path):
    """No NVD / EPSS / KEV cache rows → every §2 field renders "—"."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    # Description, CVSS score, severity, vector, EPSS, percentile all "—".
    assert "<dd>—</dd>" in body
    assert body.count("<dd>—</dd>") >= 5
    # KEV listed renders "No" rather than "—" (it's a boolean).
    assert "<dt>KEV listed</dt><dd>No</dd>" in body


def test_cve_page_renders_nvd_summary_fields(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    _set_nvd_raw(cache, "CVE-X", {
        "description": "Remote code execution in Foo before 1.2.",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    })
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "Remote code execution in Foo before 1.2." in body
    assert "9.8 (CRITICAL)" in body
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in body


def test_cve_page_renders_epss_score_and_percentile(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    _set_epss_raw(cache, "CVE-X", "2024-01-15",
                  {"epss": 0.9421, "percentile": 0.9876, "date": "2024-01-15"})
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "0.9421" in body
    assert "98.8%" in body


def test_cve_page_renders_kev_listed_and_due_date(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-2021-44228"])
    _set_kev_catalog_raw(cache, {
        "CVE-2021-44228": {"dueDate": "2021-12-24",
                           "knownRansomwareCampaignUse": "Known"}
    })
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-2021-44228.html").read_text("utf-8")
    assert "<dt>KEV listed</dt><dd>Yes</dd>" in body
    assert "<dt>KEV due date</dt><dd>2021-12-24</dd>" in body


def test_cve_page_escapes_poisoned_description(tmp_path):
    """An NVD payload with `<script>` in the description must be defanged."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    _set_nvd_raw(cache, "CVE-X", {
        "description": "Hi <script>alert(1)</script>",
    })
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


# ---- Trajectory chart ----------------------------------------------------


def test_cve_page_trajectory_zero_snapshots_shows_no_data(tmp_path):
    """A CVE with one snapshot but no scores → no plottable points."""
    cache = Cache(tmp_path / ".cache.db")
    cache._conn.execute(
        "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
        "VALUES (?, ?, ?, ?, ?)",
        ("CVE-X", "2026-05-25T10:00:00", "unknown", None, None),
    )
    cache._conn.commit()
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "no trajectory data" in body
    assert "<svg" not in body  # no SVG when no plottable points


def test_cve_page_trajectory_one_snapshot_uses_sparkline(tmp_path):
    """Below 2 snapshots → ASCII sparkline fallback (design-doc §5.3 §3)."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])  # 1 plottable snapshot
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "Single snapshot" in body
    # The sparkline character is one of the unicode block-eighths.
    assert any(ch in body for ch in "▁▂▃▄▅▆▇█")
    assert "<svg" not in body  # SVG path is only taken at 2+ snapshots


def test_cve_page_trajectory_two_plus_snapshots_renders_svg(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    for i, ts in enumerate(("2026-05-25T10:00:00", "2026-05-26T10:00:00",
                            "2026-05-27T10:00:00")):
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            ("CVE-X", ts, "patch_now", 9.0 + i * 0.1, 0.5 + i * 0.05),
        )
    cache._conn.commit()
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "<svg" in body
    # 3 circles — one per snapshot.
    assert body.count("<circle") == 3
    # The most-recent snapshot is highlighted.
    assert "cve-latest" in body


def test_cve_page_trajectory_caps_at_200_with_footer_note(tmp_path):
    """251 snapshots → 200 plotted + a '+51 earlier' footer."""
    cache = Cache(tmp_path / ".cache.db")
    for i in range(251):
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            ("CVE-X", f"2026-01-{(i % 30) + 1:02d}T{(i // 30) % 24:02d}:00:{i % 60:02d}",
             "patch_now", 9.0, 0.5),
        )
    cache._conn.commit()
    # Note: deduped via PRIMARY KEY (cve_id, ts_iso) — collisions possible
    # with our index arithmetic; pick distinct ts_iso explicitly instead.
    site_dir = tmp_path / "site"
    cache._conn.execute("DELETE FROM runs WHERE cve_id = 'CVE-X'")
    for i in range(251):
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            ("CVE-X", f"2020-01-01T00:00:{i:04d}",  # unique ts via long suffix
             "patch_now", 9.0, 0.5),
        )
    cache._conn.commit()
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    # 200 circles plotted; the other 51 are referenced by the footer.
    assert body.count("<circle") == 200
    assert "+51 earlier snapshots" in body


def test_cve_page_css_link_is_relative_to_parent(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert '<link rel="stylesheet" href="../static/style.css">' in body


def test_cve_page_has_no_javascript(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "<script" not in body


# ---- `build_site` integration ---------------------------------------------


def test_build_site_byte_stable_with_cve_pages(tmp_path):
    """Slice D's per-CVE pages must respect the design-doc §6 byte-stability gate."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A", "CVE-B"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    first_a = (site_dir / "cve" / "CVE-A.html").read_bytes()
    first_b = (site_dir / "cve" / "CVE-B.html").read_bytes()
    build_site(cache, site_dir)
    assert (site_dir / "cve" / "CVE-A.html").read_bytes() == first_a
    assert (site_dir / "cve" / "CVE-B.html").read_bytes() == first_b


def test_build_site_returns_cve_page_paths_in_dict(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-A", "CVE-B"])
    site_dir = tmp_path / "site"
    paths = build_site(cache, site_dir)
    assert paths["cve/CVE-A"] == site_dir / "cve" / "CVE-A.html"
    assert paths["cve/CVE-B"] == site_dir / "cve" / "CVE-B.html"


def test_run_web_prints_cve_page_paths(tmp_path, capsys):
    """`_run_web`'s path-printing also surfaces per-CVE page paths."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-2021-44228"])
    rc = _run_web(_site_args(tmp_path / "site"), cache, None)
    assert rc == 0
    stdout = capsys.readouterr().out.splitlines()
    assert any(line.endswith("CVE-2021-44228.html") for line in stdout)


# ---- Constants and re-exports --------------------------------------------


def test_web_trajectory_cap_is_200():
    """Lock the design-doc §5.3 §3 cap."""
    from ramen_cve.web.builder import WEB_TRAJECTORY_CAP

    assert WEB_TRAJECTORY_CAP == 200


# ---------------------------------------------------------------------------
# Slice E — per-CVE detail page §§4-5, 7 (exploit status, associations,
# affected hosts). All three read from the most-recent run's main CVE CSV
# on disk. §6 (IOCs) is deferred until `IOC_CSV_COLUMNS` gains a `cve_id`
# column for per-CVE filtering.
# ---------------------------------------------------------------------------


_CSV_HEADER = (
    "cve_id,source,first_seen,first_seen_type,cvss_score,cvss_severity,"
    "epss_score,epss_percentile,kev_listed,kev_due_date,"
    "kev_known_ransomware_use,kev_vendor_project,kev_product,bucket,"
    "suggested_action,cwe,attack_techniques,exploit_status,linked_actors,"
    "linked_campaigns,linked_malware,tlp,admiralty,affected_hosts,"
    "kill_chain_phase,diamond_capability,diamond_adversary,"
    "diamond_infrastructure,diamond_victim,nvd_published,enriched_at"
)


def _write_run_csv(out_dir, disk_stamp, rows):
    """Write a `ramen-cve-<stamp>.csv` with the header + supplied rows.

    `rows` is `[(cve_id, exploit_status, linked_actors, linked_campaigns,
    linked_malware, affected_hosts), ...]` — only the columns Slice E
    reads are populated; the rest are blank to mirror real-world thin
    runs.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"ramen-cve-{disk_stamp}.csv"
    lines = [_CSV_HEADER]
    for cve_id, exploit, actors, campaigns, malware, hosts in rows:
        # Quote any field that contains a comma. csv-correct quoting via
        # the stdlib would be nicer but the test fixtures stay free of
        # commas, so this minimal join is enough.
        lines.append(
            f"{cve_id},,,,,,,,,,,,,,,,,{exploit},{actors},{campaigns},"
            f"{malware},,,{hosts},,,,,,,"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _seed_run_with_csv(cache, ts_iso, disk_stamp, out_dir, csv_rows):
    """Insert runs+run_artefacts pointers + write a real CSV on disk.

    Mirrors what Slice B's `_output(cache=…)` does at the end of a real
    pipeline run, so the Web UI's reader exercises the live shape.
    """
    for cve_id, *_ in csv_rows:
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            (cve_id, ts_iso, "patch_now", 9.0, 0.5),
        )
    cache._conn.commit()
    cache.record_artefacts(ts_iso, disk_stamp, str(out_dir))
    _write_run_csv(out_dir, disk_stamp, csv_rows)


# ---- `_find_run_csv_for_cve` ---------------------------------------------


def test_find_run_csv_for_cve_returns_none_when_no_artefacts(tmp_path):
    """A run exists but `run_artefacts` is empty (pre-Slice-B history)."""
    from ramen_cve.web.builder import _find_run_csv_for_cve

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    assert _find_run_csv_for_cve(cache, "CVE-X") is None


def test_find_run_csv_for_cve_returns_none_when_file_missing(tmp_path):
    """Artefacts row points at a path that's been deleted from disk."""
    from ramen_cve.web.builder import _find_run_csv_for_cve

    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    cache.record_artefacts(
        "2026-05-25T10:00:00", "20260525T100000000000", str(tmp_path / "gone"),
    )
    assert _find_run_csv_for_cve(cache, "CVE-X") is None


def test_find_run_csv_for_cve_returns_path_when_file_exists(tmp_path):
    from ramen_cve.web.builder import _find_run_csv_for_cve

    cache = Cache(tmp_path / ".cache.db")
    _seed_run_with_csv(
        cache,
        "2026-05-25T10:00:00",
        "20260525T100000000000",
        tmp_path / "out",
        [("CVE-X", "none", "", "", "", "")],
    )
    csv_path = _find_run_csv_for_cve(cache, "CVE-X")
    assert csv_path == tmp_path / "out" / "ramen-cve-20260525T100000000000.csv"


def test_find_run_csv_for_cve_picks_most_recent_with_artefacts(tmp_path):
    """A more-recent run lacking artefacts is skipped — the older artefacted
    run wins (INNER JOIN semantics)."""
    from ramen_cve.web.builder import _find_run_csv_for_cve

    cache = Cache(tmp_path / ".cache.db")
    _seed_run_with_csv(
        cache,
        "2026-05-25T10:00:00",
        "20260525T100000000000",
        tmp_path / "out",
        [("CVE-X", "exploit_db", "", "", "", "")],
    )
    _seed_run(cache, "2026-05-26T10:00:00", cve_ids=["CVE-X"])  # newer, no artefacts
    csv_path = _find_run_csv_for_cve(cache, "CVE-X")
    assert csv_path.name == "ramen-cve-20260525T100000000000.csv"


# ---- `_read_cve_csv_row` -------------------------------------------------


def test_read_cve_csv_row_returns_dict_for_match(tmp_path):
    from ramen_cve.web.builder import _read_cve_csv_row

    path = _write_run_csv(tmp_path, "x", [("CVE-X", "github_poc", "", "", "", "")])
    row = _read_cve_csv_row(path, "CVE-X")
    assert row is not None
    assert row["exploit_status"] == "github_poc"


def test_read_cve_csv_row_returns_none_for_missing_cve(tmp_path):
    from ramen_cve.web.builder import _read_cve_csv_row

    path = _write_run_csv(tmp_path, "x", [("CVE-A", "none", "", "", "", "")])
    assert _read_cve_csv_row(path, "CVE-B") is None


def test_read_cve_csv_row_returns_none_when_file_missing(tmp_path):
    from ramen_cve.web.builder import _read_cve_csv_row

    assert _read_cve_csv_row(tmp_path / "nope.csv", "CVE-X") is None


# ---- `_render_exploit_status` (§4) --------------------------------------


def test_render_exploit_status_dash_when_no_row():
    from ramen_cve.web.builder import _render_exploit_status

    out = _render_exploit_status(None)
    assert "<h2>Exploit status</h2>" in out
    assert "—" in out


def test_render_exploit_status_humanizes_each_known_value():
    from ramen_cve.web.builder import _render_exploit_status

    for raw, label in [
        ("exploit_db", "Public exploit (ExploitDB)"),
        ("nuclei_template", "Nuclei detection template"),
        ("github_poc", "GitHub PoC"),
        ("none", "None observed"),
    ]:
        out = _render_exploit_status({"exploit_status": raw})
        assert label in out


def test_render_exploit_status_empty_string_renders_none_observed():
    from ramen_cve.web.builder import _render_exploit_status

    out = _render_exploit_status({"exploit_status": ""})
    assert "None observed" in out


def test_render_exploit_status_escapes_unexpected_value():
    """An unrecognised status falls through escaped — never raw."""
    from ramen_cve.web.builder import _render_exploit_status

    out = _render_exploit_status({"exploit_status": "<script>"})
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


# ---- `_render_associations_list` helper ----------------------------------


def test_render_associations_list_dash_when_empty():
    from ramen_cve.web.builder import _render_associations_list

    assert _render_associations_list("") == "—"
    assert _render_associations_list(";  ;  ") == "—"


def test_render_associations_list_renders_bulleted_list():
    from ramen_cve.web.builder import _render_associations_list

    out = _render_associations_list("APT41;Aquatic Panda")
    assert "<ul>" in out
    assert "<li>APT41</li>" in out
    assert "<li>Aquatic Panda</li>" in out


def test_render_associations_list_escapes_each_name():
    """A semicolon-injected `<script>` must be defanged item-by-item."""
    from ramen_cve.web.builder import _render_associations_list

    out = _render_associations_list("Hi;<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


# ---- `_render_associations` (§5) ----------------------------------------


def test_render_associations_dash_everywhere_when_no_row():
    from ramen_cve.web.builder import _render_associations

    out = _render_associations(None)
    assert "<h2>Associations</h2>" in out
    assert "<dt>Threat actors</dt><dd>—</dd>" in out
    assert "<dt>Campaigns</dt><dd>—</dd>" in out
    assert "<dt>Malware</dt><dd>—</dd>" in out


def test_render_associations_full_row():
    from ramen_cve.web.builder import _render_associations

    out = _render_associations({
        "linked_actors": "APT41;Aquatic Panda",
        "linked_campaigns": "Operation CuckooBees",
        "linked_malware": "ShadowPad;PlugX",
    })
    assert "<li>APT41</li>" in out
    assert "<li>Aquatic Panda</li>" in out
    assert "<li>Operation CuckooBees</li>" in out
    assert "<li>ShadowPad</li>" in out
    assert "<li>PlugX</li>" in out


def test_render_associations_mixed_populated_and_empty():
    """Actors populated, campaigns + malware blank → exactly one list, two dashes."""
    from ramen_cve.web.builder import _render_associations

    out = _render_associations({
        "linked_actors": "APT41",
        "linked_campaigns": "",
        "linked_malware": "",
    })
    assert "<li>APT41</li>" in out
    # Two of three sub-blocks remain "—".
    assert out.count("<dd>—</dd>") == 2


# ---- `_render_affected_hosts` (§7) --------------------------------------


def test_render_affected_hosts_dash_when_no_row():
    from ramen_cve.web.builder import _render_affected_hosts

    out = _render_affected_hosts(None)
    assert "<h2>Affected hosts</h2>" in out
    assert "—" in out


def test_render_affected_hosts_renders_list():
    from ramen_cve.web.builder import _render_affected_hosts

    out = _render_affected_hosts({
        "affected_hosts": "web-01.example;db-prod-04.example",
    })
    assert "<li>web-01.example</li>" in out
    assert "<li>db-prod-04.example</li>" in out


def test_render_affected_hosts_empty_column_renders_dash():
    from ramen_cve.web.builder import _render_affected_hosts

    out = _render_affected_hosts({"affected_hosts": ""})
    assert "<h2>Affected hosts</h2>" in out
    assert "—" in out


# ---- End-to-end per-CVE page integration ---------------------------------


def test_cve_page_renders_all_three_section_headers(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "<h2>Exploit status</h2>" in body
    assert "<h2>Associations</h2>" in body
    assert "<h2>Affected hosts</h2>" in body


def test_cve_page_section_4_5_7_dash_when_no_csv_artefact(tmp_path):
    """Slice C-style fixtures (no on-disk CSV) → all three sections "—"."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run(cache, "2026-05-25T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    # §4: "—". §5: three dashes in the dl. §7: "—".
    assert body.count("<dd>—</dd>") >= 3  # §5 sub-blocks


def test_cve_page_renders_sections_from_csv_when_present(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run_with_csv(
        cache,
        "2026-05-25T10:00:00",
        "20260525T100000000000",
        tmp_path / "out",
        [("CVE-X", "exploit_db", "APT41", "Operation CuckooBees", "ShadowPad",
          "web-01.example")],
    )
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    assert "Public exploit (ExploitDB)" in body
    assert "<li>APT41</li>" in body
    assert "<li>Operation CuckooBees</li>" in body
    assert "<li>ShadowPad</li>" in body
    assert "<li>web-01.example</li>" in body


def test_cve_page_byte_stable_with_full_sections(tmp_path):
    cache = Cache(tmp_path / ".cache.db")
    _seed_run_with_csv(
        cache,
        "2026-05-25T10:00:00",
        "20260525T100000000000",
        tmp_path / "out",
        [("CVE-X", "nuclei_template", "APT41", "", "PlugX",
          "web-01;web-02")],
    )
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    first = (site_dir / "cve" / "CVE-X.html").read_bytes()
    build_site(cache, site_dir)
    assert (site_dir / "cve" / "CVE-X.html").read_bytes() == first


def test_cve_page_picks_most_recent_artefacted_run(tmp_path):
    """Newer run with no artefacts is skipped; older run with CSV wins."""
    cache = Cache(tmp_path / ".cache.db")
    _seed_run_with_csv(
        cache,
        "2026-05-25T10:00:00",
        "20260525T100000000000",
        tmp_path / "out",
        [("CVE-X", "exploit_db", "APT41", "", "", "")],
    )
    _seed_run(cache, "2026-05-26T10:00:00", cve_ids=["CVE-X"])
    site_dir = tmp_path / "site"
    build_site(cache, site_dir)
    body = (site_dir / "cve" / "CVE-X.html").read_text("utf-8")
    # The older run's exploit status flows through, not "—".
    assert "Public exploit (ExploitDB)" in body
