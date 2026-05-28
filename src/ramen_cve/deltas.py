"""ramen_cve.deltas — bucket-transition delta detection (Layer-3).

A *delta* here is a CVE whose triage bucket has *upgraded* (moved to a
higher-priority bucket per the `BucketPolicy` ordering) between the
previously recorded run and the current `EnrichedCve`. First-seen CVEs
count as upgrades (`None -> bucket`). Downgrades and unchanged buckets
are excluded — they are noise for alerting.

`--dispatch-on-delta-only` uses this to suppress the every-run repeat-
dispatch of CVEs that have not changed state, which is the dominant
source of alert fatigue in the default dispatch pipeline.

Layer-3: reads from the `runs` table via `Cache.get_runs`; no network
I/O. Must be called *before* the current run is recorded so that the
most recent history entry is the *previous* bucket.
"""
from __future__ import annotations

from .bucket_policy import DEFAULT_BUCKET_POLICY, BucketPolicy
from .cache import Cache
from .models import EnrichedCve


def compute_bucket_deltas(
    cache: Cache,
    enriched: list[EnrichedCve],
    policy: BucketPolicy = DEFAULT_BUCKET_POLICY,
) -> dict[str, tuple[str | None, str]]:
    """Return `{cve_id: (old_bucket, new_bucket)}` for upgrades only.

    Semantics:
      * First-seen CVE (no history): `(None, current_bucket)` — counted
        as an upgrade so newly-discovered CVEs always dispatch.
      * Bucket upgraded (strictly lower `order` int per the policy):
        included.
      * Bucket unchanged or downgraded: excluded.
      * Current bucket unknown to the policy: excluded (we can't rank
        it, so we can't claim an upgrade).
      * Previous bucket unknown to the policy: included — treat the
        transition into a known bucket as worth dispatching.
    """
    deltas: dict[str, tuple[str | None, str]] = {}
    for rec in enriched:
        new_rank = _rank_or_none(policy, rec.bucket)
        if new_rank is None:
            continue
        history = cache.get_runs(rec.cve_id)
        if not history:
            deltas[rec.cve_id] = (None, rec.bucket)
            continue
        old_bucket = history[-1]["bucket"]
        old_rank = _rank_or_none(policy, old_bucket)
        if old_rank is None or new_rank < old_rank:
            deltas[rec.cve_id] = (old_bucket, rec.bucket)
    return deltas


def _rank_or_none(policy: BucketPolicy, bucket_id: str) -> int | None:
    """Return the policy's order int for `bucket_id`, or None if unknown."""
    try:
        return policy.spec(bucket_id).order
    except KeyError:
        return None
