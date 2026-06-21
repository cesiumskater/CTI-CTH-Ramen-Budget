"""ramen_cve.plugins — entry-point–discovered third-party extensions.

Layer-4 leaf. Discovers community-maintained plugins via
``importlib.metadata`` so a contributor can publish a separate PyPI
package (or a local editable install) that ramen-cve picks up without any
core change.

The v1 surface is intentionally minimal: only **output writers** are
pluggable. The four other hook points the roadmap envisions (parsers,
enrichers, dispatchers, bucket policies) ship as follow-up slices once the
writer contract has settled in the wild.

Plugin authoring (writers)
--------------------------
Publish a separate package whose ``pyproject.toml`` declares::

    [project.entry-points."ramen_cve.writers"]
    jsonl = "my_ramen_writer:write_jsonl"

…and exposes a callable matching :data:`WRITER_CONTRACT`. ramen-cve picks
the plugin up on the next run; ``--format jsonl`` becomes a valid token.

Discovery is **opt-in by import**: nothing fetches plugins at startup
unless ``--format`` references a non-builtin token. A broken plugin (load
error, runtime exception, wrong signature) logs a warning and is skipped —
it never aborts a triage.

Stability
---------
The :data:`WRITER_CONTRACT` callable signature is the stability boundary.
Adding optional keyword arguments to it is a non-breaking change; renaming
or removing one is breaking and goes through CHANGELOG + a deprecation
release.
"""
from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

#: The group name plugin authors declare under ``[project.entry-points.…]``.
WRITER_ENTRY_POINT_GROUP = "ramen_cve.writers"

#: Writer plugins are called with this signature::
#:
#:     write(records, path, *, run_metadata=None, iocs=None, policy=None) -> Path | None
#:
#: ``records`` is the post-enrichment list[EnrichedCve] the built-in
#: writers receive. ``path`` is a *suggested* base path the host
#: constructed (out_dir / ``<basename>-<token>``); the plugin may return a
#: different path (e.g. with its preferred extension), or ``None`` if it
#: chose to write nothing this run. Returning the actual path lets the
#: host announce it on stdout and record it in the run-artefacts table.
WRITER_CONTRACT = "(records, path, *, run_metadata, iocs, policy) -> Path | None"


def discover_writers() -> dict[str, Callable[..., Path | None]]:
    """Return ``{token: callable}`` for every successfully-loaded writer plugin.

    A plugin whose ``ep.load()`` raises is logged at WARNING level and
    omitted from the result — a single bad plugin must never crash the
    pipeline. Built-in writers are *not* included here; they're called
    directly from :mod:`ramen_cve.pipeline`.
    """
    out: dict[str, Callable[..., Path | None]] = {}
    # importlib.metadata.entry_points(group=…) is available on every
    # supported interpreter (pyproject requires Python >=3.10, which
    # introduced the kwarg). No legacy fallback needed.
    eps = importlib.metadata.entry_points(group=WRITER_ENTRY_POINT_GROUP)
    for ep in eps:
        try:
            out[ep.name] = ep.load()
        except Exception as exc:  # noqa: BLE001 — fail-soft is the design
            _log.warning(
                "Skipping writer plugin %r (group %s) — load failed: %s",
                ep.name,
                WRITER_ENTRY_POINT_GROUP,
                exc,
            )
    return out


def writer_tokens() -> set[str]:
    """Return the set of writer tokens currently exposed by installed plugins.

    Surfaced separately from :func:`discover_writers` so the
    ``--format`` validator can accept plugin tokens without paying the
    cost of loading every plugin's module just to parse argv.
    """
    return set(discover_writers().keys())


def invoke_writer(
    token: str,
    writer: Callable[..., Path | None],
    records: list,
    path: Path,
    *,
    run_metadata: dict[str, Any] | None = None,
    iocs: list | None = None,
    policy: Any | None = None,
) -> Path | None:
    """Call ``writer(records, path, …)`` defensively.

    A plugin that raises is logged at WARNING and skipped; the caller
    gets back ``None``. This mirrors the failure semantics of every
    network fetcher in the codebase.
    """
    try:
        result = writer(records, path, run_metadata=run_metadata, iocs=iocs, policy=policy)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Writer plugin %r raised %s: %s", token, type(exc).__name__, exc)
        return None
    if result is None:
        return None
    return Path(result)
