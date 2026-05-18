"""ramen_cve.decay — IOC confidence decay + floor filter (Layer-1).

Half-life exponential decay over IOC age and the confidence-floor
filter. Pure; depends only on the models leaf. See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import math
from datetime import date

from .models import IocRecord

IOC_HALF_LIFE_DAYS: dict[str, int] = {
    "ipv4": 30,
    "domain": 90,
    "url": 30,
    "email": 90,
    "md5": 0,
    "sha1": 0,
    "sha256": 0,
}


def _ioc_confidence(
    ioc_type: str,
    last_seen: date | None,
    today: date | None = None,
) -> float:
    """Return a 0..1 confidence score for an indicator given when it was last seen.

    confidence = exp(-ln(2) * age_days / half_life)
    age_days < 0 (clock skew) is clamped to 0 → 1.0.
    half_life = 0 in IOC_HALF_LIFE_DAYS means "no decay" → 1.0.
    A missing last_seen returns 1.0 (the IOC was just observed by definition
    of being in the current run); callers that want stricter behavior should
    pass an explicit last_seen.
    """
    if last_seen is None:
        return 1.0
    half_life = IOC_HALF_LIFE_DAYS.get(ioc_type, 30)
    if half_life <= 0:
        return 1.0
    today = today or date.today()
    age_days = max(0, (today - last_seen).days)
    return math.exp(-math.log(2) * age_days / half_life)


def apply_ioc_decay(iocs: list[IocRecord], today: date | None = None) -> list[IocRecord]:
    """Set rec.confidence on every IOC using the exponential half-life model.

    Mutates and returns the same list for chaining. `last_seen` falls back to
    `first_seen` when not set, so a freshly-extracted IOC defaults to 1.0.
    """
    today = today or date.today()
    for ioc in iocs:
        anchor = ioc.last_seen or ioc.first_seen
        ioc.confidence = _ioc_confidence(ioc.ioc_type, anchor, today)
    return iocs


def filter_iocs_by_confidence(iocs: list[IocRecord], floor: float) -> list[IocRecord]:
    """Drop IOCs whose confidence is below the floor. A floor of 0 keeps every IOC."""
    if floor <= 0:
        return list(iocs)
    return [i for i in iocs if (i.confidence or 0.0) >= floor]

