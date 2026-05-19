"""ramen_cve.trend — run-history sparkline + the `trend` subcommand
runner (Layer-4). See docs/REFACTOR_PLAN.md."""
from __future__ import annotations

import argparse
import logging

from .cache import Cache
from .constants import CVE_REGEX
from .models import EnrichedCve

_log = logging.getLogger(__name__)


_SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[float | None]) -> str:
    """Render a list of numbers as a unicode sparkline; None renders as a space."""
    real = [v for v in values if v is not None]
    if not real:
        return ""
    lo, hi = min(real), max(real)
    span = hi - lo if hi > lo else 1.0
    out: list[str] = []
    for v in values:
        if v is None:
            out.append(" ")
            continue
        idx = int(((v - lo) / span) * (len(_SPARKLINE_CHARS) - 1))
        out.append(_SPARKLINE_CHARS[max(0, min(idx, len(_SPARKLINE_CHARS) - 1))])
    return "".join(out)


def _record_runs(cache: Cache, enriched: list[EnrichedCve]) -> None:
    """Append a snapshot row per enriched CVE so `trend` has history to draw."""
    for rec in enriched:
        cache.record_run(rec.cve_id, rec.bucket, rec.cvss_score, rec.epss_score)


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

