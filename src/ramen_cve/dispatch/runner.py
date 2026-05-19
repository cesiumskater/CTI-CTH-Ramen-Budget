"""ramen_cve.dispatch.runner — dispatch orchestrator: fan records out
to every enabled dispatcher, count successful posts (Layer-3).

See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import logging

from ..models import EnrichedCve
from .sinks import (
    DISPATCH_DEFAULT_BUCKETS,
    _build_default_dispatchers,
    _DispatcherBase,
)

_log = logging.getLogger(__name__)


def dispatch_records(
    enriched: list[EnrichedCve],
    *,
    dispatch_on: tuple[str, ...] = DISPATCH_DEFAULT_BUCKETS,
    dispatchers: list[_DispatcherBase] | None = None,
) -> int:
    """Push records whose bucket is in `dispatch_on` to every enabled dispatcher.

    Returns the count of successful (record, dispatcher) posts. Failures are
    logged but do not abort the run.
    """
    if dispatchers is None:
        dispatchers = _build_default_dispatchers()
    enabled = [d for d in dispatchers if d.enabled()]
    if not enabled:
        _log.info(
            "Dispatch enabled but no dispatchers configured "
            "(set SLACK_WEBHOOK_URL or RAMEN_DISPATCH_WEBHOOK)."
        )
        return 0
    successes = 0
    for rec in enriched:
        if rec.bucket not in dispatch_on:
            continue
        for d in enabled:
            if d.dispatch(rec):
                successes += 1
    return successes

