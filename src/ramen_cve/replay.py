"""ramen_cve.replay — point-in-time replay / backtesting over run history.

Layer-4 subcommand, a pure read of the non-purged ``runs`` table (no network,
no re-fetch, no schema change). ``replay --as-of YYYY-MM-DD [--to YYYY-MM-DD]``
reconstructs each CVE's last-known bucket at two points in time and diffs
them, so an analyst can answer "how did our exposure change between then and
now?" — the bucket distribution at each point, which CVEs moved bucket, and
which are new.

Seeded automatically: every triage run appends a snapshot per CVE (see
``trend._record_runs``), so replay works against whatever history the shared
cache file already holds. Re-exported on the façade.
"""
from __future__ import annotations

import argparse
import logging
from datetime import date

from .cache import Cache
from .constants import BUCKET_ACTIONS
from .models import _utcnow

_log = logging.getLogger(__name__)


def _end_of_day(d: date) -> str:
    """Inclusive end-of-day ISO bound for a `runs.ts_iso` comparison.

    ``runs.ts_iso`` is second-precision naive-UTC ISO ("YYYY-MM-DDThh:mm:ss");
    appending T23:59:59 makes ``<= bound`` include every run on that calendar
    day. Lexical string comparison is correct for this fixed-width format.
    """
    return f"{d.isoformat()}T23:59:59"


def bucket_counts(snapshot: dict[str, dict]) -> dict[str, int]:
    """Count CVEs per bucket in a `snapshot_as_of` result."""
    counts: dict[str, int] = {}
    for state in snapshot.values():
        counts[state["bucket"]] = counts.get(state["bucket"], 0) + 1
    return counts


def diff_snapshots(before: dict[str, dict], after: dict[str, dict]) -> dict:
    """Diff two run-history snapshots (each ``{cve_id: state}``).

    Returns ``{"added", "removed", "changed", "unchanged"}`` where:
      * ``added``    — CVE ids in ``after`` but not ``before`` (sorted);
      * ``removed``  — in ``before`` but not ``after`` (sorted; usually empty
        for a forward as-of→now diff since run history is append-only);
      * ``changed``  — ``[(cve_id, before_bucket, after_bucket), ...]`` where
        the bucket moved, sorted by cve_id;
      * ``unchanged``— count of shared CVEs whose bucket held.
    Deterministic ordering throughout.
    """
    before_ids, after_ids = set(before), set(after)
    changed: list[tuple[str, str, str]] = []
    unchanged = 0
    for cve_id in sorted(before_ids & after_ids):
        b, a = before[cve_id]["bucket"], after[cve_id]["bucket"]
        if b != a:
            changed.append((cve_id, b, a))
        else:
            unchanged += 1
    return {
        "added": sorted(after_ids - before_ids),
        "removed": sorted(before_ids - after_ids),
        "changed": changed,
        "unchanged": unchanged,
    }


def _run_replay(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute `replay`: diff the run-history snapshot at --as-of against --to."""
    as_of: date = args.as_of
    to: date | None = args.to
    if to is not None and to < as_of:
        _log.error("replay: --to (%s) is before --as-of (%s).", to, as_of)
        return 1

    before = cache.snapshot_as_of(_end_of_day(as_of))
    to_bound = _end_of_day(to) if to else _utcnow().isoformat(timespec="seconds")
    after = cache.snapshot_as_of(to_bound)
    to_label = to.isoformat() if to else "now"

    if not before and not after:
        _log.info(
            "No historical runs recorded on or before %s. Seed history by "
            "running a triage with the same cache file (default: "
            ".ramen-cache.db).",
            to_label,
        )
        return 0

    d = diff_snapshots(before, after)
    before_counts, after_counts = bucket_counts(before), bucket_counts(after)

    print(f"# Replay: {as_of.isoformat()} → {to_label}")
    print()
    print(
        f"- {len(before)} CVE(s) tracked as of {as_of.isoformat()}; "
        f"{len(after)} as of {to_label}."
    )
    print(
        f"- {len(d['changed'])} bucket change(s), {len(d['added'])} new, "
        f"{len(d['removed'])} dropped, {d['unchanged']} unchanged."
    )
    print()

    # Bucket distribution across both points. Canonical buckets first (in
    # BUCKET_ACTIONS order), then any non-canonical bucket present in either
    # snapshot (e.g. from an older policy) so no count is silently dropped.
    present = set(before_counts) | set(after_counts)
    ordered = [b for b in BUCKET_ACTIONS if b in present]
    ordered += sorted(present - set(BUCKET_ACTIONS))
    print("## Bucket distribution\n")
    print(f"| Bucket | as of {as_of.isoformat()} | as of {to_label} |")
    print("| --- | --- | --- |")
    for bucket in ordered:
        print(f"| {bucket} | {before_counts.get(bucket, 0)} | {after_counts.get(bucket, 0)} |")
    print()

    if d["changed"]:
        print("## Bucket transitions\n")
        print("| CVE | as-of bucket | → | to bucket |")
        print("| --- | --- | --- | --- |")
        for cve_id, b, a in d["changed"]:
            print(f"| {cve_id} | {b} | → | {a} |")
        print()

    if d["added"]:
        print(f"**New since {as_of.isoformat()}:** {', '.join(d['added'])}\n")
    if d["removed"]:
        print(f"**Dropped by {to_label}:** {', '.join(d['removed'])}\n")
    return 0
