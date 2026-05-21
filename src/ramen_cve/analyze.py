"""ramen_cve.analyze — pure scoring/classification (Layer-1).

CWE→ATT&CK / →Kill-Chain mappers, TLP + NATO-Admiralty math, the
5-bucket triage and the date-window filter. No I/O. Depends only on
the constants/models leaves. See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import logging
from datetime import date

from .constants import (
    BUCKET_ACTIONS,
    CWE_TO_ATTACK,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_EPSS_THRESHOLD,
    TLP_LEVELS,
)
from .models import EnrichedCve

_log = logging.getLogger(__name__)


def map_cwes_to_attack_techniques(cwes: list[str]) -> list[str]:
    """Return a deduplicated, sorted list of ATT&CK technique IDs for the CWEs.

    Empty input or unmapped CWEs return an empty list. Sorting keeps CSV and
    Markdown output deterministic across runs.
    """
    techniques: set[str] = set()
    for cwe in cwes:
        techniques.update(CWE_TO_ATTACK.get(cwe.upper(), []))
    return sorted(techniques)


# Lockheed Martin Cyber Kill Chain phases. The default phase for a CVE is
# 'exploitation' — that's what every vulnerability description reduces to.
# Specific CWEs that reliably indicate a different phase override.
KILL_CHAIN_PHASES = (
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
)

# CWE → likely Kill Chain phase override. Anything not listed defaults to
# 'exploitation' since that's how the vast majority of CVEs map.
CWE_TO_KILL_CHAIN: dict[str, str] = {
    "CWE-200": "reconnaissance",        # Information Disclosure
    "CWE-22": "reconnaissance",         # Path Traversal (often pre-exploit recon)
    "CWE-269": "installation",          # Improper Privilege Management → PrivEsc
    "CWE-426": "installation",          # Untrusted Search Path → DLL Hijack
    "CWE-732": "installation",          # Incorrect Permission Assignment
    "CWE-552": "actions_on_objectives", # Files accessible to unauthorized parties
    "CWE-319": "actions_on_objectives", # Cleartext Transmission of sensitive data
    "CWE-601": "delivery",              # Open Redirect → phishing delivery aid
    "CWE-1021": "delivery",             # UI Restriction Bypass / Clickjacking
    "CWE-400": "actions_on_objectives", # DoS impact
}


def map_cwes_to_kill_chain(cwes: list[str]) -> str:
    """Return the most specific Kill Chain phase for the given CWE list.

    If any CWE has an override entry, return its phase (first match wins; the
    CWE_TO_KILL_CHAIN dict is small and deterministic). Otherwise default to
    'exploitation'.
    """
    for cwe in cwes:
        phase = CWE_TO_KILL_CHAIN.get(cwe.upper())
        if phase:
            return phase
    return "exploitation"



def _normalize_tlp(value: str | None) -> str:
    """Coerce a raw TLP attribute value into our canonical UPPER form, defaulting to CLEAR."""
    if not value:
        return "CLEAR"
    v = value.strip().upper()
    # Accept legacy "WHITE" → CLEAR mapping (TLP v1.0 used "WHITE").
    if v == "WHITE":
        return "CLEAR"
    return v if v in TLP_LEVELS else "CLEAR"


def _worst_tlp(a: str | None, b: str | None) -> str:
    """Return the more-restrictive TLP between two values.

    Order: RED > AMBER+STRICT > AMBER > GREEN > CLEAR.
    """
    na, nb = _normalize_tlp(a), _normalize_tlp(b)
    return TLP_LEVELS[max(TLP_LEVELS.index(na), TLP_LEVELS.index(nb))]


def _admiralty_score(grade: str | None) -> tuple[int, int]:
    """Return a sortable tuple where (0,0) = best (A1) and (99,99) = no rating."""
    if not grade or len(grade) != 2:
        return (99, 99)
    letter, digit = grade[0].upper(), grade[1]
    if letter not in "ABCDEF" or not digit.isdigit():
        return (99, 99)
    return (ord(letter) - ord("A"), int(digit))


def _best_admiralty(a: str | None, b: str | None) -> str:
    """Return the higher-confidence (lower-tuple) Admiralty grade between two values."""
    sa = _admiralty_score(a)
    sb = _admiralty_score(b)
    if sa <= sb:
        return (a or "").upper()
    return (b or "").upper()



def bucket_and_suggest(
    enriched: list[EnrichedCve],
    cvss_thr: float = DEFAULT_CVSS_THRESHOLD,
    epss_thr: float = DEFAULT_EPSS_THRESHOLD,
) -> list[EnrichedCve]:
    """Assign a bucket and suggested action to each enriched CVE.

    NOTE: this function MUTATES the records in `enriched` in place
    (setting `rec.bucket` and `rec.suggested_action`) and returns the
    same list for chaining. Callers should not rely on the input being
    untouched.

    Precedence:
      1. kev_listed=True → kev_override (always wins)
      2. CVSS >= thr AND EPSS >= thr → patch_now
      3. CVSS >= thr AND EPSS < thr  → plan_and_patch
      4. CVSS < thr  AND EPSS >= thr → watch_closely
      5. CVSS < thr  AND EPSS < thr  → deprioritize
      Missing CVSS or EPSS           → unknown
    """
    for rec in enriched:
        if rec.kev_listed:
            rec.bucket = "kev_override"
        elif rec.cvss_score is None or rec.epss_score is None:
            rec.bucket = "unknown"
        elif rec.cvss_score >= cvss_thr and rec.epss_score >= epss_thr:
            rec.bucket = "patch_now"
        elif rec.cvss_score >= cvss_thr:
            rec.bucket = "plan_and_patch"
        elif rec.epss_score >= epss_thr:
            rec.bucket = "watch_closely"
        else:
            rec.bucket = "deprioritize"
        rec.suggested_action = BUCKET_ACTIONS[rec.bucket]
    return enriched


def filter_by_date(
    enriched: list[EnrichedCve],
    start: date | None,
    end: date | None,
    date_mode: str,
) -> list[EnrichedCve]:
    """Filter enriched CVEs by date range according to the active date mode.

    date_mode:
      "feed"        — filter on record.first_seen (publication date from the feed).
      "disclosure"  — filter on record.nvd_published (NVD published date).
      "epss"        — only start==end (single day) is supported in v1.

    Records missing the relevant date are logged and dropped.
    Both start and end are inclusive. None means no bound on that side.
    """
    # `--date-mode epss` with start != end is now valid (EPSS trajectory mode:
    # historical EPSS is fetched once per day in the inclusive range; the
    # filter below still uses nvd_published as the inclusion criterion).
    result: list[EnrichedCve] = []
    for rec in enriched:
        if date_mode == "feed":
            rec_date = rec.first_seen
        elif date_mode == "disclosure":
            rec_date = rec.nvd_published
        else:  # epss — date was already used for the API call; filter on nvd_published
            rec_date = rec.nvd_published

        if rec_date is None:
            _log.warning("CVE %s has no date for date_mode=%s; skipping.", rec.cve_id, date_mode)
            continue

        if start and rec_date < start:
            continue
        if end and rec_date > end:
            continue
        result.append(rec)

    return result

