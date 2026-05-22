"""ramen_cve.daemon — long-running daemon subcommand (Layer-4).

Loops a configured pipeline preset at a fixed interval in one
long-lived process, with SIGTERM/SIGINT graceful shutdown, timestamped
per-iteration output subdirs, and optional `--prune-after-days` history
pruning. Slice E (the systemd / launchd documentation) is the only
remaining piece. See `tasks/todo.md` task 3 for the full plan.
"""

from __future__ import annotations

import argparse
import logging
import random
import shutil
import signal
import threading
import time
from pathlib import Path

from .cache import Cache
from .config import load_yaml_config
from .models import OpmlError, _utcnow

_log = logging.getLogger(__name__)


# Shared prefix for every per-iteration output subdir. The pruner only ever
# removes directories matching this prefix, so the create-side and prune-side
# MUST agree — keeping the literal in one place prevents drift that would let
# `_prune_old_iterations` either miss real iteration dirs or (worse) delete an
# unrelated directory a user keeps under the same `--out-dir` base.
_ITERATION_DIR_PREFIX = "ramen-cve-"


def _iteration_output_subdir(base: Path) -> Path:
    """Return a fresh timestamped subdir under `base`, creating it.

    Each daemon iteration writes into its own
    ``<base>/ramen-cve-<UTC microsecond ts>/`` so history accumulates
    instead of each run overwriting the last. Microsecond resolution
    makes collisions essentially impossible, but we still probe `-N`
    suffixes so two iterations within the same microsecond (e.g. a
    `--interval 0` test loop) get distinct directories.
    """
    ts = _utcnow().strftime("%Y%m%dT%H%M%S%f")
    subdir = base / f"{_ITERATION_DIR_PREFIX}{ts}"
    n = 1
    while subdir.exists():
        subdir = base / f"{_ITERATION_DIR_PREFIX}{ts}-{n}"
        n += 1
    subdir.mkdir(parents=True)
    return subdir


def _prune_old_iterations(base: Path, days: int) -> int:
    """Remove iteration output subdirs older than `days` under `base`.

    Walks `base` and ``shutil.rmtree``s every direct child directory whose
    name starts with ``ramen-cve-`` (the iteration prefix) and whose mtime is
    more than `days` days in the past. Returns the count removed.

    Safety:
      * Only ``ramen-cve-*`` directories are candidates, so pointing
        ``--out-dir`` at a directory that also holds unrelated files never
        deletes them.
      * Age is compared in the POSIX clock domain (``time.time()`` vs.
        ``st_mtime``) — deliberately NOT ``_utcnow().timestamp()``, which is a
        *naive* UTC datetime and would be mis-converted in a non-UTC locale.
      * Fail-soft: a child that can't be stat'd or removed (a race with
        another process, a permission error) logs a WARNING and is skipped
        rather than aborting the daemon.

    ``days <= 0`` disables pruning (the default) and returns 0 without
    touching the filesystem.
    """
    if days <= 0 or not base.is_dir():
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    # Sorted for deterministic prune/log ordering across platforms.
    for child in sorted(base.iterdir()):
        if not child.name.startswith(_ITERATION_DIR_PREFIX) or not child.is_dir():
            continue
        try:
            if child.stat().st_mtime >= cutoff:
                continue
            shutil.rmtree(child)
        except OSError as exc:
            _log.warning("daemon: could not prune %s: %s", child, exc)
            continue
        removed += 1
        _log.info(
            "daemon: pruned output dir %s (older than %d day(s)).", child, days,
        )
    return removed

# The four pipeline subcommands a daemon iteration may dispatch to.
# (hunt / pir / trend / audit / schedule are deliberately out of
# scope — looping those doesn't make sense for an ongoing triage
# pipeline.)
_DAEMON_VALID_SUBCOMMANDS = ("opml", "url", "cve", "stix")

# Module-level stop signal shared between the SIGTERM/SIGINT handlers
# and the daemon loop. A `threading.Event` lets the loop block on
# `wait(timeout=interval)` and wake immediately when a signal lands,
# without the per-syscall flakiness of `time.sleep` interruption.
# Cleared at the top of every `_run_daemon` call so test invocations
# in the same process don't bleed state.
_should_stop: threading.Event = threading.Event()


def _install_signal_handlers():
    """Install SIGTERM/SIGINT handlers; return a restore-callable.

    Both signals set the module-level `_should_stop` event, which the
    loop checks after every iteration. We don't interrupt mid-pipeline
    — partial output files are worse than a one-iteration delay on
    shutdown. The previous handlers are saved + restored so embedders
    don't lose their signal handling when the daemon exits.

    Note: `signal.signal` only works on the main thread. The daemon is
    always invoked from the main thread (it's the top-of-process CLI
    runner), so this is safe in production. Tests that need to skip
    the install can monkeypatch the function.
    """

    def _handler(signum, frame):  # noqa: ARG001 — signal API contract
        _log.info(
            "daemon: received signal %d; will finish current iteration and exit.",
            signum,
        )
        _should_stop.set()

    prev_term = signal.signal(signal.SIGTERM, _handler)
    prev_int = signal.signal(signal.SIGINT, _handler)

    def _restore() -> None:
        signal.signal(signal.SIGTERM, prev_term)
        signal.signal(signal.SIGINT, prev_int)

    return _restore


def _build_iteration_argv(preset_name: str) -> list[str]:
    """Build the argv for one daemon iteration from a YAML preset.

    Reads the preset's ``subcommand`` (opml/url/cve/stix) plus the
    relevant positional argument and writes them as the argv list that
    ``ramen_cve.main`` would parse. The preset's other settings
    (filters, output flags, dispatch, etc.) flow through to the inner
    runner automatically because we append ``--config <preset>`` and
    main() then re-applies the preset via ``apply_yaml_config``.

    Raises ``OpmlError`` if the preset is missing, unparseable, or
    declares an unsupported ``subcommand`` value. Re-raises the
    loader's ``FileNotFoundError`` / ``ValueError`` unchanged so
    callers can distinguish a missing preset from a malformed one.
    """
    config = load_yaml_config(preset_name)
    subcommand = (config.get("subcommand") or "").strip()
    if subcommand not in _DAEMON_VALID_SUBCOMMANDS:
        raise OpmlError(
            f"daemon preset {preset_name!r}: 'subcommand' must be one of "
            f"{', '.join(_DAEMON_VALID_SUBCOMMANDS)} (got {subcommand!r})."
        )

    if subcommand == "opml":
        # opml's positional is a path; preset key is `opml_path` per
        # config._YAML_FLAT_KEY_MAP.
        path = config.get("opml_path")
        if not path:
            raise OpmlError(
                f"daemon preset {preset_name!r}: subcommand=opml requires "
                f"`opml_path` in the YAML."
            )
        argv = ["opml", str(path)]
    elif subcommand == "url":
        url = config.get("url")
        if not url:
            raise OpmlError(
                f"daemon preset {preset_name!r}: subcommand=url requires "
                f"`url` in the YAML."
            )
        argv = ["url", str(url)]
    elif subcommand == "cve":
        cves = config.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]
        if not cves:
            raise OpmlError(
                f"daemon preset {preset_name!r}: subcommand=cve requires a "
                f"non-empty `cves` list in the YAML."
            )
        argv = ["cve", *[str(c) for c in cves]]
    else:  # stix
        path = config.get("stix_path")
        if not path:
            raise OpmlError(
                f"daemon preset {preset_name!r}: subcommand=stix requires "
                f"`stix_path` in the YAML."
            )
        argv = ["stix", str(path)]

    # Tell main() to apply the same preset for the rest of the flags.
    argv += ["--config", preset_name]
    return argv


def _run_daemon(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Loop the configured pipeline at fixed intervals until stopped.

    Before the first iteration ``_prune_old_iterations`` runs once so a
    freshly (re)started daemon clears stale history immediately, then:

    Loop body per iteration:
      1. ``ramen_cve.main(iter_argv)`` runs the inner pipeline once.
         Inner failures log a WARNING but don't abort the daemon —
         the next iteration retries.
      2. ``_prune_old_iterations`` removes output subdirs older than
         ``--prune-after-days`` (a no-op when the flag is 0/unset).
      3. If `--max-runs` is positive and we've hit it, exit.
      4. If a SIGTERM/SIGINT has flipped `_should_stop`, exit.
      5. ``_should_stop.wait(interval + jitter)`` — sleep until the
         next iteration OR until a signal wakes us, whichever comes
         first. This is what gives the daemon sub-second shutdown
         latency on a long interval.

    `--max-runs -1` (the default) means "unbounded — exit only on
    signal". `--max-runs 1` is the Slice-A single-shot mode and is
    still honoured. `--interval 0` makes the daemon run iterations
    back-to-back (useful for tests).
    """
    preset = getattr(args, "for_config", None)
    if not preset:
        _log.error("daemon: --for-config NAME is required.")
        return 2

    try:
        iter_argv = _build_iteration_argv(preset)
    except OpmlError as exc:
        _log.error("%s", exc)
        return 2

    # Use ``X if X is not None else default`` rather than ``X or default``
    # so an explicit zero (e.g. --interval 0 in tests) is honoured, not
    # silently coerced back to the default.
    raw_max = getattr(args, "max_runs", -1)
    max_runs = int(raw_max if raw_max is not None else -1)
    raw_int = getattr(args, "interval", 21600)
    interval = max(0, int(raw_int if raw_int is not None else 21600))
    raw_jit = getattr(args, "jitter", 0)
    jitter = max(0, int(raw_jit if raw_jit is not None else 0))
    raw_prune = getattr(args, "prune_after_days", 0)
    prune_after_days = max(0, int(raw_prune if raw_prune is not None else 0))

    # Base output directory: each iteration gets a fresh timestamped subdir
    # underneath it so successive runs accumulate instead of overwriting.
    raw_out = getattr(args, "out_dir", None)
    base_out_dir = Path(raw_out) if raw_out is not None else Path.cwd()

    # Fresh state per call: tests rely on starting with a clear event.
    _should_stop.clear()
    restore_signals = _install_signal_handlers()
    iterations = 0
    try:
        # Deferred import: cli imports daemon at module load, so
        # importing ramen_cve (which re-exports cli.main) at module-
        # level would create a circular import. Function-local lookup
        # goes through the package namespace and resolves whatever
        # `main` is in scope at call time — tests patch via
        # `patch("ramen_cve.main", ...)` (Amendment 2026-05-18
        # monkeypatch protocol).
        import ramen_cve

        # Startup housekeeping: clear out history left by earlier daemon
        # lifetimes before we begin writing fresh iteration dirs.
        _prune_old_iterations(base_out_dir, prune_after_days)

        while True:
            iterations += 1
            # Fresh timestamped output dir per iteration; appended as an
            # explicit --out-dir so it overrides any out_dir the preset
            # set (an explicit CLI arg beats apply_yaml_config).
            subdir = _iteration_output_subdir(base_out_dir)
            this_argv = [*iter_argv, "--out-dir", str(subdir)]
            _log.info("daemon: iteration %d via %s", iterations, this_argv)
            rc = ramen_cve.main(this_argv)
            if rc != 0:
                _log.warning(
                    "daemon: iteration %d returned rc=%d (will retry on the next interval).",
                    iterations, rc,
                )

            # Post-iteration housekeeping: keep a long-lived daemon from
            # accumulating output beyond the retention window over its
            # lifetime. The just-written subdir has a current mtime so it is
            # never a prune candidate. The walk is O(#subdirs) and trivially
            # cheap next to a real pipeline iteration, so no debounce is
            # needed even at --interval 0.
            _prune_old_iterations(base_out_dir, prune_after_days)

            if max_runs > 0 and iterations >= max_runs:
                _log.info(
                    "daemon: reached --max-runs %d, exiting cleanly.", max_runs,
                )
                break
            if _should_stop.is_set():
                _log.info("daemon: stop signal received, exiting after iteration %d.", iterations)
                break

            # Jitter is ±N seconds added to the base interval (uniform).
            # Clamped at zero so a wild jitter setting can't make us
            # busy-loop with a negative sleep.
            jittered = float(interval)
            if jitter:
                jittered += random.uniform(-jitter, jitter)
            jittered = max(0.0, jittered)
            _log.info("daemon: sleeping %.1fs before next iteration.", jittered)
            # `Event.wait(timeout)` returns True iff the event was set
            # during the wait — that's our signal-driven early exit.
            if _should_stop.wait(timeout=jittered):
                _log.info(
                    "daemon: stop signal received during sleep, exiting after iteration %d.",
                    iterations,
                )
                break
    finally:
        restore_signals()

    _log.info("daemon: clean exit after %d iteration(s).", iterations)
    return 0
