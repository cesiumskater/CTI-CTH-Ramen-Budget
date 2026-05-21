"""ramen_cve.daemon — long-running daemon subcommand (Layer-4).

Slice A: single-shot wiring. Verifies the `daemon` subcommand is
parsed, audit-dispatched, and resolves a YAML preset into a recursive
`ramen_cve.main(...)` invocation that runs the configured pipeline
once and exits.

Slice B will add the actual `while + sleep + signal` loop with
SIGTERM/SIGINT graceful shutdown; Slice C the timestamped per-iteration
output subdirs; Slice D `--prune-after-days` history pruning; Slice E
the documentation (systemd / launchd examples). See `tasks/todo.md`
task 3 for the full plan.
"""

from __future__ import annotations

import argparse
import logging

from .cache import Cache
from .config import load_yaml_config
from .models import OpmlError

_log = logging.getLogger(__name__)

# The four pipeline subcommands a daemon iteration may dispatch to.
# (hunt / pir / trend / audit / schedule are deliberately out of
# scope — looping those doesn't make sense for an ongoing triage
# pipeline.)
_DAEMON_VALID_SUBCOMMANDS = ("opml", "url", "cve", "stix")


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
    """Run the configured pipeline once (Slice A wiring; no loop yet).

    Slice A intentionally supports only a single iteration so the
    subcommand dispatch, preset resolution, and recursive ``main()``
    plumbing can be tested end-to-end without committing to the
    long-lived-process surface. Slice B replaces the single call with
    a ``while not _stop: run(); jittered_sleep()`` loop and adds the
    signal handlers.
    """
    preset = getattr(args, "for_config", None)
    if not preset:
        _log.error("daemon: --for-config NAME is required.")
        return 2

    max_runs = int(getattr(args, "max_runs", -1) or -1)
    if max_runs not in (-1, 1):
        _log.warning(
            "daemon Slice A only supports --max-runs 1 (or -1 = unbounded "
            "with the Slice-B loop, not yet implemented); got %s. Running "
            "exactly one iteration.",
            max_runs,
        )

    try:
        iter_argv = _build_iteration_argv(preset)
    except OpmlError as exc:
        _log.error("%s", exc)
        return 2

    # Deferred import: cli imports daemon at module load, so importing
    # ramen_cve (which re-exports cli.main) at module-level would create
    # a circular import. Function-local lookup goes through the package
    # namespace and resolves whatever main is in scope at call time —
    # also the documented seam tests can patch via
    # `patch("ramen_cve.main", ...)` (Amendment 2026-05-18 monkeypatch
    # protocol).
    import ramen_cve

    _log.info("daemon: running iteration via %s", iter_argv)
    rc = ramen_cve.main(iter_argv)
    if rc != 0:
        _log.warning("daemon: iteration returned rc=%d", rc)
    # The daemon itself exits 0 once it successfully ran an iteration —
    # downstream-pipeline failures don't terminate the daemon (they'll
    # be retried on the next interval once Slice B lands the loop).
    return 0
