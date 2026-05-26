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
