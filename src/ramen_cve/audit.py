"""ramen_cve.audit — tamper-evident run audit log: actor capture,
argument redaction, dispatch wrapper, and the `audit` subcommand
runner (Layer-4). See README.md and src/ramen_cve/__init__.py."""
from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import logging
from datetime import date
from pathlib import Path

from .cache import Cache
from .models import _utcnow

_log = logging.getLogger(__name__)


_AUDIT_SENSITIVE_KEYS = ("key", "pass", "token", "secret")


def _audit_actor() -> str:
    """Return the current OS user for audit attribution.

    `getpass.getuser()` consults LOGNAME / USER / LNAME / USERNAME (per the
    Python stdlib) and raises OSError on platforms that have none of them.
    Fall back to 'unknown' rather than aborting the run.
    """

    try:
        return getpass.getuser() or "unknown"
    except OSError:
        return "unknown"


def _redact_audit_args(args: argparse.Namespace) -> str:
    """JSON-serialize argparse Namespace with sensitive values masked.

    Any field whose name contains 'key', 'pass', 'token', or 'secret' is
    replaced with '***'. Paths / dates / non-JSON-native types are stringified.
    """
    out: dict[str, object] = {}
    for k, v in vars(args).items():
        if v is None:
            out[k] = None
            continue
        if any(s in k.lower() for s in _AUDIT_SENSITIVE_KEYS):
            out[k] = "***" if v else None
            continue
        if isinstance(v, Path):
            out[k] = str(v)
        elif isinstance(v, date):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return json.dumps(out, default=str, sort_keys=True)


def _audit_dispatch(
    cache: Cache | None,
    command: str,
    args: argparse.Namespace,
    runner,
) -> int:
    """Run `runner`, persist an audit row, and return the runner's exit code.

    `runner` is a zero-arg callable that returns the subcommand's rc. We
    capture exceptions, record the outcome, and re-raise so the user-facing
    behavior is unchanged. A None `cache` (interactive bootstrap before the
    cache is opened) skips logging silently — never abort a real run for an
    audit-write failure.
    """
    actor = _audit_actor()
    args_redacted = _redact_audit_args(args)
    ts_iso = _utcnow().isoformat(timespec="seconds")
    try:
        rc = runner()
    except Exception as exc:
        if cache is not None:
            with contextlib.suppress(Exception):
                cache.log_audit(
                    actor, command, args_redacted,
                    outcome=f"error: {type(exc).__name__}",
                    ts_iso=ts_iso,
                )
        raise
    if cache is not None:
        with contextlib.suppress(Exception):
            cache.log_audit(
                actor, command, args_redacted,
                outcome=f"rc={rc}",
                ts_iso=ts_iso,
            )
    return rc


def _run_audit(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Print the tail of the append-only audit log as a Markdown table."""
    limit = max(1, int(getattr(args, "tail", 20)))
    rows = cache.get_audit(limit)
    if not rows:
        _log.info("Audit log is empty.")
        return 0
    print(f"# Audit log — last {len(rows)} entries")
    print()
    print("| Timestamp (UTC) | Actor | Command | Outcome | Args |")
    print("| --- | --- | --- | --- | --- |")
    for r in rows:
        # Backticks around args so JSON commas don't break the markdown column.
        print(
            f"| {r['ts_iso']} | {r['actor']} | {r['command']} | "
            f"{r['outcome']} | `{r['args_redacted']}` |"
        )
    return 0

