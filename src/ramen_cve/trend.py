"""ramen_cve.trend — run-history sparkline + the `trend` subcommand
runner (Layer-4). See README.md and src/ramen_cve/__init__.py."""
from __future__ import annotations

import argparse
import logging

from .bucket_policy import DEFAULT_BUCKET_POLICY, BucketPolicy
from .cache import Cache
from .constants import CVE_REGEX
from .deltas import compute_bucket_deltas
from .models import EnrichedCve

# Lifted to the L1 `render` leaf so output/markdown.py can reuse the
# sparkline without an upward L3 -> L4 import (see render.py docstring).
# Re-imported here so `ramen_cve.trend._sparkline` (and the façade
# re-export) keep resolving for back-compat.
from .render import _SPARKLINE_CHARS, _sparkline  # noqa: F401

_log = logging.getLogger(__name__)


def _record_runs(
    cache: Cache,
    enriched: list[EnrichedCve],
    policy: BucketPolicy | None = None,
) -> dict[str, tuple[str | None, str]]:
    """Append a snapshot row per enriched CVE so `trend` has history to draw.

    Returns bucket-transition deltas computed against the *previous*
    recorded run (i.e. before this run is inserted). Callers thread the
    return value into `_maybe_dispatch` so `--dispatch-on-delta-only`
    can suppress unchanged-bucket repeats.
    """
    deltas = compute_bucket_deltas(cache, enriched, policy or DEFAULT_BUCKET_POLICY)
    for rec in enriched:
        cache.record_run(rec.cve_id, rec.bucket, rec.cvss_score, rec.epss_score)
    return deltas


def _run_trend(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Print a Markdown-friendly historical trend for one CVE."""
    cve_id = (args.cve_id or "").upper()
    if not CVE_REGEX.fullmatch(cve_id):
        _log.error("trend: %r is not a valid CVE ID", args.cve_id)
        return 1
    runs = cache.get_runs(cve_id)
    if not runs:
        _log.info(
            "No historical runs recorded for %s. Run a triage with the same "
            "cache file (default: .ramen-cache.db) to seed history.",
            cve_id,
        )
        return 0
    epss_values = [r["epss_score"] for r in runs]
    cvss_values = [r["cvss_score"] for r in runs]
    print(f"# {cve_id} — {len(runs)} historical run(s)")
    print()
    print(f"EPSS: {_sparkline(epss_values)}")
    print(f"CVSS: {_sparkline(cvss_values)}")
    print()
    print("| Run timestamp (UTC) | Bucket | CVSS | EPSS |")
    print("| --- | --- | --- | --- |")
    for r in runs:
        cv = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "N/A"
        ep = f"{r['epss_score']:.4f}" if r["epss_score"] is not None else "N/A"
        print(f"| {r['ts_iso']} | {r['bucket']} | {cv} | {ep} |")
    return 0

