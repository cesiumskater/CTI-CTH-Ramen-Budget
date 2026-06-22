"""ramen_cve.risk — risk-weighted CVE prioritization.

Transforms the existing ``--inventory`` flag from informational to
operational. When the inventory CSV carries an optional ``criticality``
column (``tier1`` / ``tier2`` / ``tier3``), this module computes a
per-CVE ``risk_score`` from four signals analysts already trust:

  * **Asset criticality** — the most-critical tier among the CVE's
    affected hosts (tier1 = crown jewels, tier3 = background fleet).
  * **CVSS score** — vulnerability severity.
  * **EPSS score** — internet-wide exploit probability.
  * **KEV listed** — confirmed exploitation in the wild.

The formula::

    risk_score = host_criticality_weight
               * cvss_weight
               * (1 + 2*epss_score)
               * (10 if kev_listed else 1)

Where:

* ``host_criticality_weight`` = 3 (tier1) / 2 (tier2) / 1 (tier3) / 1 (no
  inventory data → don't penalise CVEs we lack visibility into).
* ``cvss_weight`` = the CVSS score (0–10), or 1.0 when unknown.
* ``epss_score`` is the raw EPSS probability (0–1).
* The KEV multiplier is multiplicative on purpose: it shoves
  KEV-listed findings to the top regardless of CVSS / EPSS.

Pure module — no I/O, no network. Stdlib only. Re-exported on the
façade. The CSV writer surfaces ``risk_score`` + ``affected_host_criticality``
as new columns; the Markdown writer re-ranks CVEs within each bucket by
score so the "which one should I patch first?" answer is visible at a
glance without changing the bucket boundaries themselves.
"""
from __future__ import annotations

from .models import EnrichedCve

#: Criticality tiers ordered worst-to-best (tier1 is the most critical).
CRITICALITY_TIERS: tuple[str, ...] = ("tier1", "tier2", "tier3")

#: Per-tier multiplier on the risk score. Tier-1 hosts triple the weight
#: vs. a host with no recorded criticality, tier-2 doubles it, tier-3 is
#: neutral (no penalty for the "background fleet" cells), and no-data is
#: also neutral so CVEs without inventory matches aren't suppressed.
_TIER_WEIGHT: dict[str, float] = {"tier1": 3.0, "tier2": 2.0, "tier3": 1.0}

_NO_HOST_WEIGHT = 1.0
_DEFAULT_CVSS_WEIGHT = 1.0
_KEV_MULTIPLIER = 10.0


def _tier_rank(tier: str | None) -> int:
    """Lower index = more critical. Unknown / missing falls to the bottom."""
    if not tier:
        return len(CRITICALITY_TIERS)
    try:
        return CRITICALITY_TIERS.index(tier.lower())
    except ValueError:
        return len(CRITICALITY_TIERS)


def worst_criticality(tiers: list[str | None]) -> str | None:
    """Return the most-critical tier label from a list, or None if none known.

    Used by :func:`correlate_inventory` (in ``enrich.inventory``) to pick a
    single tier for the EnrichedCve from the per-affected-host tiers — the
    "worst host wins" rule that an analyst would apply by reflex.
    """
    best: str | None = None
    best_rank = len(CRITICALITY_TIERS)
    for tier in tiers:
        rank = _tier_rank(tier)
        if rank < best_rank:
            best_rank = rank
            best = tier.lower() if tier else None
    return best


def compute_risk_score(rec: EnrichedCve) -> float:
    """Return the risk score for one EnrichedCve.

    Pure; reads ``cvss_score``, ``epss_score``, ``kev_listed``, and
    ``affected_host_criticality``. Missing inputs degrade gracefully:
    no CVSS → 1.0 weight; no EPSS → 0; no host criticality → 1.0 weight.
    Always returns a non-negative float.
    """
    host_weight = _TIER_WEIGHT.get(
        (rec.affected_host_criticality or "").lower(), _NO_HOST_WEIGHT
    )
    cvss_weight = rec.cvss_score if rec.cvss_score is not None else _DEFAULT_CVSS_WEIGHT
    epss = rec.epss_score if rec.epss_score is not None else 0.0
    kev = _KEV_MULTIPLIER if rec.kev_listed else 1.0
    return float(host_weight) * float(cvss_weight) * (1.0 + 2.0 * float(epss)) * kev


def apply_risk_scores(records: list[EnrichedCve]) -> None:
    """In-place: populate ``risk_score`` on each record.

    Idempotent — calling twice with the same inputs yields the same scores.
    No-op on an empty list. Safe to call when no inventory criticality data
    is present (the host-weight collapses to 1.0 and the score still
    differentiates CVEs by CVSS / EPSS / KEV).
    """
    for rec in records:
        rec.risk_score = compute_risk_score(rec)
