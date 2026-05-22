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
import pathlib
from unittest.mock import patch

import pytest
import yaml

import ramen_cve
from ramen_cve.daemon import _build_iteration_argv, _run_daemon
from ramen_cve.models import OpmlError

# ---------------------------------------------------------------------------
# Preset fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path, monkeypatch):
    """chdir into the per-test tmp dir so the daemon's default
    `--out-dir` (= cwd) creates its `ramen-cve-<ts>/` iteration subdirs
    under tmp, never polluting the repo working tree."""
    monkeypatch.chdir(tmp_path)


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


def _strip_out_dir(argv: list[str]) -> list[str]:
    """Drop the daemon-injected `--out-dir <subdir>` tail for argv asserts.

    Slice C appends a fresh `--out-dir <timestamped-subdir>` to every
    iteration's argv; tests that assert the *resolved preset* argv strip
    it so they stay focused on the preset-resolution contract.
    """
    if "--out-dir" in argv:
        i = argv.index("--out-dir")
        return argv[:i]
    return list(argv)


def _ns(**kw):
    # interval=0/jitter=0 means back-to-back iterations with no real sleep —
    # essential for tests because the loop's `Event.wait(timeout)` blocks
    # otherwise (real-time intervals are minutes-to-hours in production).
    base = {
        "for_config": None,
        "max_runs": -1,
        "no_cache": True,
        "interval": 0,
        "jitter": 0,
    }
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
    assert [_strip_out_dir(c) for c in calls] == [
        ["cve", "CVE-2024-0001", "--config", "daily-cve"]
    ]


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


def test_run_daemon_honours_max_runs_positive(preset_dir):
    """Slice B: `--max-runs N` (N>0) actually loops N iterations and exits."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    calls: list[list[str]] = []
    with patch("ramen_cve.main", side_effect=lambda argv: calls.append(list(argv)) or 0):
        args = _ns(for_config="daily-cve", max_runs=3)
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0
    assert len(calls) == 3, calls
    # Every iteration sees the same resolved preset argv (the preset doesn't
    # change mid-run); only the appended --out-dir subdir differs.
    assert all(
        _strip_out_dir(c) == ["cve", "CVE-2024-0001", "--config", "daily-cve"]
        for c in calls
    )


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
    # The inner main was invoked exactly once with the resolved argv
    # (modulo the daemon-injected --out-dir tail).
    inner_argvs = [c for c in calls if c != "OUTER-PLACEHOLDER"]
    assert [_strip_out_dir(c) for c in inner_argvs] == [
        ["cve", "CVE-2024-0001", "--config", "test-preset"]
    ]


# ---------------------------------------------------------------------------
# Slice B — loop + signal handling
# ---------------------------------------------------------------------------


def test_daemon_unbounded_exits_on_stop_event(preset_dir):
    """`--max-runs -1` is unbounded; setting `_should_stop` from inside a
    mocked iteration drops out of the loop after that iteration finishes."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    from ramen_cve import daemon as d_mod

    calls: list[list[str]] = []

    def _trip_after_two(argv):
        calls.append(list(argv))
        if len(calls) == 2:
            d_mod._should_stop.set()
        return 0

    with patch("ramen_cve.main", side_effect=_trip_after_two):
        args = _ns(for_config="daily-cve", max_runs=-1)
        rc = _run_daemon(args, cache=object(), api_key=None)
    # Iteration 1 → no stop, sleep(0); iteration 2 → trip stop → break BEFORE
    # iteration 3 even though max_runs is unbounded.
    assert rc == 0
    assert len(calls) == 2


def test_daemon_failed_inner_iterations_keep_running(preset_dir, caplog):
    """A failing iteration logs a WARN but the loop continues to the next
    iteration; the daemon's own rc is 0 once it exits cleanly."""
    import logging as _logging

    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    return_codes = iter([2, 1, 0])  # fail, fail, succeed — all three loop.
    with (
        patch("ramen_cve.main", side_effect=lambda argv: next(return_codes)),
        caplog.at_level(_logging.WARNING, logger="ramen_cve.daemon"),
    ):
        args = _ns(for_config="daily-cve", max_runs=3)
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0
    # Two WARN lines for the two failing iterations (rc=2 then rc=1); the
    # successful third iteration produces none.
    warn_msgs = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert sum(1 for m in warn_msgs if "returned rc=" in m) == 2


def test_daemon_signal_handler_sets_stop_event(preset_dir):
    """The handler installed by `_install_signal_handlers` flips
    `_should_stop` when invoked (we don't rely on real SIGTERM delivery
    in tests — too platform-/scheduler-dependent)."""
    import signal as _signal

    from ramen_cve import daemon as d_mod

    d_mod._should_stop.clear()
    restore = d_mod._install_signal_handlers()
    try:
        # The just-installed SIGTERM handler is what we want to invoke.
        handler = _signal.getsignal(_signal.SIGTERM)
        assert callable(handler), "SIGTERM should have a callable handler now"
        handler(_signal.SIGTERM, None)
        assert d_mod._should_stop.is_set()
    finally:
        restore()


def test_daemon_restores_previous_signal_handlers(preset_dir):
    """After the daemon exits, SIGTERM/SIGINT go back to whatever was set
    before — embedders don't lose their signal handling."""
    import signal as _signal


    sentinel = lambda *a, **kw: None  # noqa: E731  — distinguishable handler

    prev_term = _signal.signal(_signal.SIGTERM, sentinel)
    prev_int = _signal.signal(_signal.SIGINT, sentinel)
    try:
        _, write = preset_dir
        write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

        with patch("ramen_cve.main", return_value=0):
            args = _ns(for_config="daily-cve", max_runs=1)
            _run_daemon(args, cache=object(), api_key=None)

        # After daemon exit, our sentinel should be restored.
        assert _signal.getsignal(_signal.SIGTERM) is sentinel
        assert _signal.getsignal(_signal.SIGINT) is sentinel
    finally:
        _signal.signal(_signal.SIGTERM, prev_term)
        _signal.signal(_signal.SIGINT, prev_int)


def test_daemon_jitter_modulates_sleep(preset_dir):
    """`--jitter N` adds uniform ±N seconds to the base interval. We
    patch `random.uniform` to capture the argument range and confirm
    the loop calls Event.wait with the jittered value."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    from ramen_cve import daemon as d_mod

    sleep_calls: list[float] = []

    class _SpyEvent:
        def __init__(self):
            self._set = False
            self._real = d_mod._should_stop

        def is_set(self):
            return self._real.is_set()

        def clear(self):
            self._real.clear()

        def set(self):
            self._real.set()

        def wait(self, timeout):  # noqa: ARG002
            sleep_calls.append(timeout)
            # After the first sleep, flip the real event so the loop exits.
            self._real.set()
            return True

    fake = _SpyEvent()
    with (
        patch("ramen_cve.main", return_value=0),
        patch.object(d_mod, "_should_stop", fake),
        # Lock the random component so the assertion is deterministic.
        patch("ramen_cve.daemon.random.uniform", return_value=4.0),
    ):
        args = _ns(for_config="daily-cve", max_runs=-1, interval=10, jitter=5)
        rc = _run_daemon(args, cache=object(), api_key=None)
    assert rc == 0
    # One sleep call before the early-exit; jittered = 10 + 4.0 = 14.0.
    assert sleep_calls == [14.0]


def test_daemon_negative_jitter_clamps_to_zero(preset_dir):
    """Sleep duration is clamped at zero; a wild negative jitter can't make
    `Event.wait` choke on a negative timeout."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    from ramen_cve import daemon as d_mod

    sleep_calls: list[float] = []

    class _SpyEvent:
        def __init__(self):
            self._real = d_mod._should_stop

        def is_set(self):
            return self._real.is_set()

        def clear(self):
            self._real.clear()

        def set(self):
            self._real.set()

        def wait(self, timeout):  # noqa: ARG002
            sleep_calls.append(timeout)
            self._real.set()
            return True

    fake = _SpyEvent()
    with (
        patch("ramen_cve.main", return_value=0),
        patch.object(d_mod, "_should_stop", fake),
        patch("ramen_cve.daemon.random.uniform", return_value=-100.0),
    ):
        args = _ns(for_config="daily-cve", max_runs=-1, interval=10, jitter=5)
        _run_daemon(args, cache=object(), api_key=None)
    # 10 + (-100) would be -90, but the clamp pins it at 0.0.
    assert sleep_calls == [0.0]


# ---------------------------------------------------------------------------
# Slice C — timestamped per-iteration output subdirs
# ---------------------------------------------------------------------------


def _out_dir_of(argv: list[str]) -> str | None:
    """Extract the --out-dir value the daemon injected into an iteration argv."""
    if "--out-dir" in argv:
        return argv[argv.index("--out-dir") + 1]
    return None


def test_daemon_each_iteration_gets_distinct_output_subdir(preset_dir, tmp_path):
    """Three iterations → three distinct `<base>/ramen-cve-<ts>` subdirs,
    each created on disk and passed to the inner main as --out-dir."""
    base, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    seen_dirs: list[str] = []
    with patch(
        "ramen_cve.main",
        side_effect=lambda argv: seen_dirs.append(_out_dir_of(argv)) or 0,
    ):
        args = _ns(for_config="daily-cve", max_runs=3, out_dir=str(base))
        rc = _run_daemon(args, cache=object(), api_key=None)

    assert rc == 0
    assert len(seen_dirs) == 3
    # All three are distinct and were actually created under the base dir.
    assert len(set(seen_dirs)) == 3, seen_dirs
    for d in seen_dirs:
        p = pathlib.Path(d)
        assert p.is_dir(), f"iteration subdir not created: {d}"
        assert p.parent == base
        assert p.name.startswith("ramen-cve-")


def test_daemon_out_dir_defaults_to_cwd(preset_dir, tmp_path):
    """With no --out-dir, the base is the current working directory
    (the autouse fixture chdir'd us into tmp_path)."""
    _, write = preset_dir
    write("daily-cve", {"subcommand": "cve", "cves": ["CVE-2024-0001"]})

    seen_dirs: list[str] = []
    with patch(
        "ramen_cve.main",
        side_effect=lambda argv: seen_dirs.append(_out_dir_of(argv)) or 0,
    ):
        args = _ns(for_config="daily-cve", max_runs=1, out_dir=None)
        rc = _run_daemon(args, cache=object(), api_key=None)

    assert rc == 0
    assert len(seen_dirs) == 1
    subdir = pathlib.Path(seen_dirs[0])
    # cwd is tmp_path (autouse _isolate_cwd); subdir lives directly under it.
    assert subdir.parent == tmp_path
    assert subdir.is_dir()


def test_daemon_out_dir_overrides_preset_via_explicit_cli_arg(preset_dir, tmp_path):
    """The injected --out-dir is appended AFTER --config, so it wins over any
    out_dir the preset declares (explicit CLI arg beats apply_yaml_config)."""
    base, write = preset_dir
    # Preset declares its own output dir; the daemon must override it.
    write(
        "daily-cve",
        {"subcommand": "cve", "cves": ["CVE-2024-0001"],
         "output": {"out_dir": "/preset/declared/path"}},
    )

    captured: list[list[str]] = []
    with patch("ramen_cve.main", side_effect=lambda argv: captured.append(list(argv)) or 0):
        args = _ns(for_config="daily-cve", max_runs=1, out_dir=str(base))
        _run_daemon(args, cache=object(), api_key=None)

    argv = captured[0]
    # --config precedes --out-dir in the argv, and the --out-dir points under
    # the daemon's base, NOT the preset's declared path.
    assert "--config" in argv and "--out-dir" in argv
    assert argv.index("--out-dir") > argv.index("--config")
    injected = _out_dir_of(argv)
    assert pathlib.Path(injected).parent == base
    assert "/preset/declared/path" not in injected
