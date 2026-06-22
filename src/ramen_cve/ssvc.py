"""ramen_cve.ssvc — Stakeholder-Specific Vulnerability Categorization.

Adapted from CISA / CMU SEI's SSVC v2 (2023) "Deployer" decision tree, which
is the role analysts running ``ramen-cve`` play. SSVC sits *alongside* the
existing CVSS×EPSS bucket policy — it doesn't replace it — and produces an
auditor-recognised action label (``defer`` / ``scheduled`` / ``out-of-cycle``
/ ``immediate``) plus the four decision-point values the label was derived
from. Both surface in CSV and the Markdown report; consumers free to ignore
either model.

The full Deployer tree is too large to embed verbatim. The implementation
here makes the conservative choices CISA's reference docs document, and
parameterises the org-specific values via an optional **profile** JSON:

  {
    "mission_impact":  "low" | "medium" | "high" | "very_high",
    "safety_impact":   "negligible" | "minor" | "major" | "hazardous" | "catastrophic",
    "value_density":   "diffuse" | "concentrated",
    "exposure_default":"small" | "controlled" | "open"
  }

Anything omitted defaults to *medium / minor / diffuse / small* — the
"average enterprise host" position. Pass ``--ssvc-profile path.json`` on
the CLI; without it, SSVC stays inert (no new columns populated).

Pure module — no I/O, no network. Stdlib only. Re-exported on the façade
for plugin / library use.
"""
from __future__ import annotations

from typing import Any

from .models import EnrichedCve

# ---------------------------------------------------------------------------
# Decision-point value sets (per SSVC v2 / Deployer tree)
# ---------------------------------------------------------------------------

EXPLOITATION_VALUES = ("none", "public_poc", "active")
EXPOSURE_VALUES = ("small", "controlled", "open")
UTILITY_VALUES = ("laborious", "efficient", "super_effective")
HUMAN_IMPACT_VALUES = ("low", "medium", "high", "very_high")

#: The SSVC outcome labels, in the order CISA prints them
#: (least urgent → most urgent — same direction as the bucket policy).
SSVC_ACTIONS = ("defer", "scheduled", "out-of-cycle", "immediate")

#: Default profile values when ``--ssvc-profile`` is omitted or partial.
_DEFAULT_PROFILE: dict[str, str] = {
    "mission_impact": "medium",       # average enterprise function
    "safety_impact": "minor",         # no safety-of-life implication
    "value_density": "diffuse",       # the host doesn't aggregate value
    "exposure_default": "small",      # not internet-facing by default
}


def _exploitation(rec: EnrichedCve) -> str:
    """Derive the SSVC ``Exploitation`` value from existing signals.

    KEV listed → ``active`` (CISA's definition of "exploitation observed in
    the wild" matches their own KEV catalogue). Any other public exploit
    signal (Exploit-DB, Nuclei, GitHub PoC, Metasploit) → ``public_poc``.
    Otherwise → ``none``.
    """
    if rec.kev_listed:
        return "active"
    if rec.exploit_status and rec.exploit_status != "none":
        return "public_poc"
    return "none"


def _exposure(rec: EnrichedCve, profile: dict[str, str]) -> str:
    """Derive the SSVC ``Exposure`` value.

    The profile carries the org's *default* exposure assumption (most hosts
    are not internet-facing). A CVE that affects no known inventory host
    falls back to that default; any CVE with at least one affected host
    inherits the default until per-host data is wired through. The CISA
    tree treats ``open`` as the worst level — explicitly tagging a host as
    open-exposure is something a future inventory schema change can lift
    in.
    """
    return profile.get("exposure_default", "small")


def _utility(rec: EnrichedCve, profile: dict[str, str]) -> str:
    """Derive the SSVC ``Utility`` value (Automatable + Value Density).

    *Automatable* is approximated from ``cwe``: classic remote-RCE / SQLi
    /command-injection patterns are highly automatable; everything else is
    treated as not-automatable. *Value Density* comes from the profile.
    The CISA table maps (automatable, value-density) → utility tier.
    """
    automatable = _is_automatable(rec.cwe)
    value_density = profile.get("value_density", "diffuse")
    table = {
        (False, "diffuse"): "laborious",
        (False, "concentrated"): "efficient",
        (True, "diffuse"): "efficient",
        (True, "concentrated"): "super_effective",
    }
    return table[(automatable, value_density)]


#: CWE families CISA considers "automatable" in the Utility table.
_AUTOMATABLE_CWES = frozenset({
    "CWE-20",    # improper input validation
    "CWE-77", "CWE-78", "CWE-89",       # injection (command/sql)
    "CWE-94",    # improper control of generation of code
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",  # buffer-related memory safety
    "CWE-125", "CWE-787",                # OOB read/write
    "CWE-190", "CWE-191",                # integer overflow/underflow
    "CWE-287", "CWE-306",                # broken auth
    "CWE-352",                            # CSRF
    "CWE-416",                            # use-after-free
    "CWE-434",                            # unrestricted file upload
    "CWE-502",                            # unsafe deserialisation
    "CWE-611", "CWE-918",                # SSRF / XXE
})


def _is_automatable(cwes: list[str]) -> bool:
    """True when at least one CWE points at an automatable exploit pattern."""
    return any(cwe.upper().strip() in _AUTOMATABLE_CWES for cwe in (cwes or []))


def _human_impact(profile: dict[str, str]) -> str:
    """Derive the SSVC ``Human Impact`` value (Mission Impact × Safety Impact).

    Pure look-up against the CISA cross-table. The two inputs are both
    organization-specific and so live entirely in the profile — there is
    no signal in the per-CVE data that lets us derive them.
    """
    mission = profile.get("mission_impact", "medium")
    safety = profile.get("safety_impact", "minor")
    # CISA's Mission × Safety table, collapsed to the four Human Impact tiers.
    table: dict[tuple[str, str], str] = {
        ("low", "negligible"): "low",
        ("low", "minor"): "low",
        ("low", "major"): "medium",
        ("low", "hazardous"): "high",
        ("low", "catastrophic"): "very_high",
        ("medium", "negligible"): "medium",
        ("medium", "minor"): "medium",
        ("medium", "major"): "high",
        ("medium", "hazardous"): "high",
        ("medium", "catastrophic"): "very_high",
        ("high", "negligible"): "high",
        ("high", "minor"): "high",
        ("high", "major"): "very_high",
        ("high", "hazardous"): "very_high",
        ("high", "catastrophic"): "very_high",
        ("very_high", "negligible"): "very_high",
        ("very_high", "minor"): "very_high",
        ("very_high", "major"): "very_high",
        ("very_high", "hazardous"): "very_high",
        ("very_high", "catastrophic"): "very_high",
    }
    return table.get((mission, safety), "medium")


def _decision(exposure: str, utility: str, human_impact: str, exploitation: str) -> str:
    """The Deployer decision tree's terminal node.

    Compact form of CISA's published tree. The full 3×3×4×3 table has 108
    leaves; many collapse to the same action. We score the four inputs as
    integers, sum them, and bucket — chosen so the result matches CISA's
    published outcomes for the cases their public documentation shows.
    Tested against every documented example in `tests/test_ssvc.py`.
    """
    score = 0
    score += {"none": 0, "public_poc": 2, "active": 4}[exploitation]
    score += {"small": 0, "controlled": 1, "open": 3}[exposure]
    score += {"laborious": 0, "efficient": 2, "super_effective": 4}[utility]
    score += {"low": 0, "medium": 1, "high": 3, "very_high": 5}[human_impact]
    if score >= 11:
        return "immediate"
    if score >= 7:
        return "out-of-cycle"
    if score >= 4:
        return "scheduled"
    return "defer"


def normalize_profile(raw: dict[str, Any] | None) -> dict[str, str]:
    """Fill in defaults for any keys missing from a user-supplied profile.

    Unknown keys are kept (forward-compatibility), but invalid values for
    known keys fall back to the default — a typo in the profile JSON
    shouldn't crash a triage. Returns a fresh dict; never mutates input.
    """
    out = dict(_DEFAULT_PROFILE)
    if not raw:
        return out
    if not isinstance(raw, dict):
        return out
    valid: dict[str, tuple[str, ...]] = {
        "mission_impact": HUMAN_IMPACT_VALUES,
        "safety_impact": ("negligible", "minor", "major", "hazardous", "catastrophic"),
        "value_density": ("diffuse", "concentrated"),
        "exposure_default": EXPOSURE_VALUES,
    }
    for key, values in valid.items():
        candidate = raw.get(key)
        if isinstance(candidate, str) and candidate in values:
            out[key] = candidate
    # Forward-compat: keep any extra keys the user shipped, untouched.
    for key, value in raw.items():
        if key not in valid and isinstance(value, str):
            out[key] = value
    return out


def compute_ssvc(
    rec: EnrichedCve,
    profile: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Return ``(action, decision_points)`` for one EnrichedCve.

    ``decision_points`` is the dict that records WHY the action was chosen,
    so a downstream auditor can replay the call. Both fields are emitted
    in the CSV and called out under each CVE in the Markdown report.

    Pure function: no I/O, no logging, no mutation of ``rec``. Tested in
    ``tests/test_ssvc.py``.
    """
    profile = profile if profile is not None else _DEFAULT_PROFILE
    exp = _exploitation(rec)
    expos = _exposure(rec, profile)
    util = _utility(rec, profile)
    hi = _human_impact(profile)
    action = _decision(expos, util, hi, exp)
    points = {
        "exploitation": exp,
        "exposure": expos,
        "utility": util,
        "human_impact": hi,
    }
    return action, points


def apply_ssvc(
    records: list[EnrichedCve],
    profile: dict[str, str] | None = None,
) -> None:
    """In-place: populate ``ssvc_action`` / ``ssvc_decision_points`` on each rec.

    No-op when records is empty. Idempotent: running twice with the same
    profile produces the same fields. When the analyst doesn't pass
    ``--ssvc-profile`` the pipeline simply doesn't call this function and
    both fields stay at their dataclass defaults (``None`` / ``{}``).
    """
    normalised = normalize_profile(profile)
    for rec in records:
        action, points = compute_ssvc(rec, normalised)
        rec.ssvc_action = action
        rec.ssvc_decision_points = points
