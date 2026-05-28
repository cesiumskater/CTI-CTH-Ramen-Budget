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
    deltas: dict[str, tuple[str | None, str]] | None = None,
    delta_only: bool = False,
) -> int:
    """Push records whose bucket is in `dispatch_on` to every enabled dispatcher.

    `deltas` maps `cve_id -> (old_bucket, new_bucket)` for records whose
    bucket upgraded since the previous run (see `ramen_cve.deltas`). When
    `delta_only` is True, records absent from `deltas` are skipped — this
    is the `--dispatch-on-delta-only` mode. When a record IS in `deltas`,
    the transition tuple is passed as a `transition=` kwarg to each
    dispatcher so the payload can surface it; dispatchers without a
    `transition` parameter are called positionally (back-compat).

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
    deltas = deltas or {}
    successes = 0
    for rec in enriched:
        if rec.bucket not in dispatch_on:
            continue
        if delta_only and rec.cve_id not in deltas:
            continue
        transition = deltas.get(rec.cve_id)
        extra = {"transition": transition} if transition is not None else {}
        for d in enabled:
            if d.dispatch(rec, **extra):
                successes += 1
    return successes

