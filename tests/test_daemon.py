"""Long-running daemon mode — Slice A coverage.

Single-shot wiring: verifies the new `daemon` subcommand parses,
audit-dispatches, resolves a YAML preset to an argv, and invokes
`ramen_cve.main(argv)` exactly once before returning 0.

Slices B (the actual `while + sleep + signal` loop), C (timestamped
per-iteration output subdirs), and D (`--prune-after-days` history
pruning) live in `tasks/todo.md` task 3 and add their own coverage
when they land.
"""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest
import yaml

import ramen_cve
from ramen_cve.daemon import _build_iteration_argv, _run_daemon
from ramen_cve.models import OpmlError

# ---------------------------------------------------------------------------
# Preset fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def preset_dir(tmp_path, monkeypatch):
    """Redirect the preset loader at a tmp dir and yield (dir, write_preset_fn).

    `monkeypatch.setattr(ramen_cve.config, ...)` per the Amendment
    monkeypatch protocol: config functions read their own bound name.
    """
    monkeypatch.setattr(ramen_cve.config, "DEFAULT_PRESETS_DIR", tmp_path)

    def _write(name: str, payload: dict) -> None:
        (tmp_path / f"{name}.yaml").write_text(yaml.safe_dump(payload))

    return tmp_path, _write


def _ns(**kw):
    base = {"for_config": None, "max_runs": -1, "no_cache": True}
    base.update(kw)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# _build_iteration_argv
# ---------------------------------------------------------------------------


def test_build_iteration_argv_opml(preset_dir):
    _, write = preset_dir
    write("daily-opml", {"subcommand": "opml", "opml_path": "examples/sample.opml"})
    argv = _build_iteration_argv("daily-opml")
    assert argv == ["opml", "examples/sample.opml", "--config", "daily-opml"]


def test_build_iteration_argv_url(preset_dir):
    _, write = preset_dir
    write("daily-url", {"subcommand": "url", "url": "https://example.com/post"})
    argv = _build_iteration_argv("daily-url")
    assert argv == ["url", "https://example.com/post", "--config", "daily-url"]


def test_build_iteration_argv_cve_list(preset_dir):
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001", "CVE-2024-0002"]})
    argv = _build_iteration_argv("daily-cve")
    assert argv == ["cve", "CVE-2024-0001", "CVE-2024-0002", "--config", "daily-cve"]


def test_build_iteration_argv_cve_single_string_coerced_to_list(preset_dir):
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": "CVE-2024-9999"})
    argv = _build_iteration_argv("daily-cve")
    assert argv == ["cve", "CVE-2024-9999", "--config", "daily-cve"]


def test_build_iteration_argv_stix(preset_dir):
    _, write = preset_dir
    write("daily-stix", {"subcommand": "stix", "stix_path": "/tmp/bundle.json"})
    argv = _build_iteration_argv("daily-stix")
    assert argv == ["stix", "/tmp/bundle.json", "--config", "daily-stix"]


def test_build_iteration_argv_rejects_unsupported_subcommand(preset_dir):
    _, write = preset_dir
    write("bad", {"subcommand": "hunt", "hunt_dir": "hunts/"})
    with pytest.raises(OpmlError, match="'subcommand' must be one of"):
        _build_iteration_argv("bad")


def test_build_iteration_argv_rejects_missing_subcommand(preset_dir):
    _, write = preset_dir
    write("nosub", {"opml_path": "x.opml"})
    with pytest.raises(OpmlError, match="'subcommand' must be one of"):
        _build_iteration_argv("nosub")


def test_build_iteration_argv_rejects_opml_without_path(preset_dir):
    _, write = preset_dir
    write("opml-empty", {"subcommand": "opml"})
    with pytest.raises(OpmlError, match="requires `opml_path`"):
        _build_iteration_argv("opml-empty")


def test_build_iteration_argv_rejects_cve_without_list(preset_dir):
    _, write = preset_dir
    write("cve-empty", {"subcommand": "cve"})
    with pytest.raises(OpmlError, match="requires a non-empty `cves`"):
        _build_iteration_argv("cve-empty")


# ---------------------------------------------------------------------------
# _run_daemon (Slice A: single-shot)
# ---------------------------------------------------------------------------


def test_run_daemon_requires_for_config(preset_dir):
    args = _ns(for_config=None)
    # Cache is unused on the early-out path; can be any sentinel.
    rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 2


def test_run_daemon_invokes_main_once_with_resolved_argv(preset_dir):
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    calls: list[list[str]] = []

    def _spy_main(argv):
        calls.append(list(argv))
        return 0

    args = _ns(for_config="daily-cve", max_runs=1)
    with patch("ramen_cve.main", _spy_main):
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0
    assert calls == [["cve", "CVE-2024-0001", "--config", "daily-cve"]]


def test_run_daemon_returns_0_even_if_inner_main_failed(preset_dir):
    """A failing inner iteration logs a warning but does not abort the daemon
    (Slice B will retry on the next interval; the daemon's own rc is 0 once
    it has run an iteration)."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    args = _ns(for_config="daily-cve", max_runs=1)
    with patch("ramen_cve.main", return_value=2):
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0


def test_run_daemon_logs_warning_for_unsupported_max_runs(preset_dir, caplog):
    """Slice A only honours --max-runs 1 (or -1); other values log a WARN
    and still run exactly once."""
    import logging as _logging

    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    args = _ns(for_config="daily-cve", max_runs=3)
    with (
        patch("ramen_cve.main", return_value=0),
        caplog.at_level(_logging.WARNING, logger="ramen_cve.daemon"),
    ):
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0
    assert any("Slice A only supports --max-runs 1" in r.message for r in caplog.records)


def test_run_daemon_surfaces_bad_preset_as_rc_2(preset_dir):
    """A malformed preset (missing subcommand) produces rc=2 with an error log,
    not a crash."""
    _, write = preset_dir
    write("broken", {"opml_path": "x.opml"})  # no subcommand

    args = _ns(for_config="broken", max_runs=1)
    # main should NOT be called when preset resolution fails.
    with patch("ramen_cve.main") as m:
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 2
    m.assert_not_called()


# ---------------------------------------------------------------------------
# End-to-end CLI dispatch (parser -> _audit_dispatch -> _run_daemon)
# ---------------------------------------------------------------------------


def test_cli_daemon_subcommand_dispatches_through_audit(preset_dir, tmp_path, monkeypatch):
    """`ramen-cve daemon --for-config ... --max-runs 1` reaches _run_daemon
    via _audit_dispatch and returns the daemon's exit code (0)."""
    _, write = preset_dir
    write(
        "test-preset",
        {"subcommand": "cve", "cves": ["CVE-2024-0001"]},
    )
    # Avoid touching the real cache file in the user's home directory.
    monkeypatch.setattr(
        "ramen_cve.constants.DEFAULT_CACHE_PATH", str(tmp_path / "cache.db")
    )

    calls: list[list[str]] = []

    def _spy_inner(argv):
        calls.append(list(argv))
        return 0

    # Patch main as the inner pipeline driver. Patching here is safe because
    # the outer main() that the CLI dispatch enters is the same module
    # attribute we're replacing — but the daemon module imports `ramen_cve`
    # lazily, so its bound `main` resolves through that attribute at call
    # time AFTER patch takes effect.
    #
    # The outer dispatch (which calls _run_daemon) is itself inside
    # ramen_cve.main, so we can't simply replace `ramen_cve.main` for both
    # roles. Instead, drive the inner via patch on `ramen_cve.cli.main`
    # (the attribute the deferred-import lookup ultimately resolves to is
    # `ramen_cve.main`, which IS `ramen_cve.cli.main`; rebinding the
    # façade attribute keeps the outer call intact).
    real_main = ramen_cve.main

    def _outer_then_inner(argv):
        # First call (from the test): run the real outer dispatch.
        if not calls:
            calls.append("OUTER-PLACEHOLDER")
            return real_main(argv)
        # Subsequent calls (from _run_daemon): record + short-circuit.
        calls.append(list(argv))
        return 0

    with patch("ramen_cve.main", _outer_then_inner):
        rc = ramen_cve.main(
            ["daemon", "--for-config", "test-preset", "--max-runs", "1"]
        )
    assert rc == 0
    # The inner main was invoked exactly once with the resolved argv.
    inner_argvs = [c for c in calls if c != "OUTER-PLACEHOLDER"]
    assert inner_argvs == [["cve", "CVE-2024-0001", "--config", "test-preset"]]
