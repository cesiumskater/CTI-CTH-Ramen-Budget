"""ramen_cve.bucket_policy — configurable bucket labels / thresholds (L1).

A `BucketPolicy` carries the per-bucket display label, suggested-action
prose, ordering, and (optionally) per-bucket CVSS/EPSS thresholds that
today live as hardcoded constants spread across `constants.BUCKET_ACTIONS`,
`output.markdown.BUCKET_DISPLAY`, and `output.markdown.BUCKET_ORDER`.

`DEFAULT_BUCKET_POLICY` mirrors today's hardcoded behaviour byte-for-byte;
slices B-D will thread it through `bucket_and_suggest` and `write_markdown`
so the existing CLI flow remains byte-identical when no YAML `buckets:`
block is present. Slice A is the leaf only — no integration yet.

Layer-1 invariant: depends only on `constants`. No I/O, no logging.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .constants import (
    BUCKET_ACTIONS,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_EPSS_THRESHOLD,
)

BUCKET_IDS: tuple[str, ...] = (
    "kev_override",
    "patch_now",
    "plan_and_patch",
    "watch_closely",
    "deprioritize",
    "unknown",
)

# KEV always wins (the precedence rule in bucket_and_suggest is
# non-configurable in v1). Users may relabel/restyle the KEV bucket but
# cannot change the rule that makes a record land in it.
KEV_BUCKET_ID = "kev_override"

# Default display label per bucket — mirrors output.markdown.BUCKET_DISPLAY
# byte-for-byte. Kept here in the L1 leaf so a policy can be constructed
# without importing L3 modules.
_DEFAULT_LABELS: dict[str, str] = {
    "kev_override": "KEV Override (Patch Immediately)",
    "patch_now": "Patch Now",
    "watch_closely": "Watch Closely",
    "plan_and_patch": "Plan and Patch",
    "deprioritize": "Deprioritize",
    "unknown": "Unknown / Insufficient Data",
}

# Default ordering — mirrors output.markdown.BUCKET_ORDER exactly:
#   kev_override → patch_now → watch_closely → plan_and_patch →
#   deprioritize → unknown.
_DEFAULT_ORDER: dict[str, int] = {
    "kev_override": 0,
    "patch_now": 1,
    "watch_closely": 2,
    "plan_and_patch": 3,
    "deprioritize": 4,
    "unknown": 5,
}


@dataclass(frozen=True)
class BucketSpec:
    """Per-bucket configuration (immutable).

    `cvss_threshold` / `epss_threshold` are *per-bucket* overrides; when
    None, the enclosing `BucketPolicy`'s default thresholds apply (i.e.
    today's single-threshold behaviour).
    """

    id: str
    label: str
    action: str
    order: int
    cvss_threshold: float | None = None
    epss_threshold: float | None = None


@dataclass(frozen=True)
class BucketPolicy:
    """A complete bucket configuration.

    `buckets` is keyed by bucket id; only the six reserved ids in
    BUCKET_IDS are recognised in v1 (users cannot define new buckets).
    `default_cvss_threshold` / `default_epss_threshold` are the
    fallbacks when a bucket spec doesn't set its own override —
    equivalent to today's single-threshold pair.
    """

    default_cvss_threshold: float = DEFAULT_CVSS_THRESHOLD
    default_epss_threshold: float = DEFAULT_EPSS_THRESHOLD
    buckets: dict[str, BucketSpec] = field(default_factory=dict)

    def spec(self, bucket_id: str) -> BucketSpec:
        """Return the spec for a bucket id. Raises KeyError if unknown."""
        return self.buckets[bucket_id]

    def label(self, bucket_id: str) -> str:
        """Display label for a bucket id (used by Markdown headings)."""
        return self.buckets[bucket_id].label

    def action(self, bucket_id: str) -> str:
        """Suggested-action prose for a bucket id (stamped onto records)."""
        return self.buckets[bucket_id].action

    def display_order(self) -> list[str]:
        """Bucket ids sorted by their `order` field (ascending).

        Mirrors today's `output.markdown.BUCKET_ORDER` when the policy is
        DEFAULT_BUCKET_POLICY.
        """
        return sorted(self.buckets, key=lambda b: self.buckets[b].order)

    def cvss_threshold_for(self, bucket_id: str) -> float:
        """Per-bucket CVSS threshold; falls back to the policy default."""
        s = self.buckets.get(bucket_id)
        if s is not None and s.cvss_threshold is not None:
            return s.cvss_threshold
        return self.default_cvss_threshold

    def epss_threshold_for(self, bucket_id: str) -> float:
        """Per-bucket EPSS threshold; falls back to the policy default."""
        s = self.buckets.get(bucket_id)
        if s is not None and s.epss_threshold is not None:
            return s.epss_threshold
        return self.default_epss_threshold

    @classmethod
    def from_yaml(cls, data: dict | None) -> BucketPolicy:
        """Build a policy from a parsed YAML `buckets:` block.

        Accepts the relaxed schema documented in the task spec:

            buckets:
              patch_now:
                label: "Critical - Patch Now"
                cvss_threshold: 8.0
                epss_threshold: 0.15
                action: "Patch within 24 hours"
                order: 1

        Missing keys per bucket fall back to the default spec; the entire
        block being absent (`data` is None or `{}`) returns
        DEFAULT_BUCKET_POLICY. Unknown bucket ids raise ValueError so
        typos don't silently no-op. v1 reserves the six BUCKET_IDS.
        """
        if not data:
            return DEFAULT_BUCKET_POLICY

        if not isinstance(data, dict):
            raise ValueError(
                f"buckets: block must be a YAML mapping, got {type(data).__name__}"
            )

        unknown = sorted(set(data) - set(BUCKET_IDS))
        if unknown:
            raise ValueError(
                f"Unknown bucket id(s): {unknown}. Reserved ids are {list(BUCKET_IDS)}."
            )

        merged: dict[str, BucketSpec] = {}
        for bid in BUCKET_IDS:
            default_spec = _DEFAULT_SPECS[bid]
            override = data.get(bid)
            if not override:
                merged[bid] = default_spec
                continue
            if not isinstance(override, dict):
                raise ValueError(
                    f"buckets.{bid} must be a YAML mapping, got "
                    f"{type(override).__name__}"
                )
            merged[bid] = BucketSpec(
                id=bid,
                label=str(override.get("label", default_spec.label)),
                action=str(override.get("action", default_spec.action)),
                order=int(override.get("order", default_spec.order)),
                cvss_threshold=_float_or_none(override.get("cvss_threshold")),
                epss_threshold=_float_or_none(override.get("epss_threshold")),
            )
        return cls(
            default_cvss_threshold=DEFAULT_CVSS_THRESHOLD,
            default_epss_threshold=DEFAULT_EPSS_THRESHOLD,
            buckets=merged,
        )


def _float_or_none(value) -> float | None:
    """Coerce a YAML-derived value to float, treating None/'' as 'no override'."""
    if value is None or value == "":
        return None
    return float(value)


def _default_specs() -> dict[str, BucketSpec]:
    """Factory mirroring today's hardcoded behaviour byte-for-byte."""
    return {
        bid: BucketSpec(
            id=bid,
            label=_DEFAULT_LABELS[bid],
            action=BUCKET_ACTIONS[bid],
            order=_DEFAULT_ORDER[bid],
        )
        for bid in BUCKET_IDS
    }


_DEFAULT_SPECS: dict[str, BucketSpec] = _default_specs()


DEFAULT_BUCKET_POLICY: BucketPolicy = BucketPolicy(
    default_cvss_threshold=DEFAULT_CVSS_THRESHOLD,
    default_epss_threshold=DEFAULT_EPSS_THRESHOLD,
    buckets=_DEFAULT_SPECS,
)
