"""SSVC v2 Deployer-tree scoring (src/ramen_cve/ssvc.py).

Invariants:
  * Decision-point derivation is correct (Exploitation reads KEV +
    exploit_status; Utility reads CWE + profile; Human Impact reads profile;
    Exposure reads profile).
  * Decision-tree monotonicity: making any input *worse* never lowers the
    action's severity.
  * Profile normalization fills defaults and rejects bad values.
  * Pipeline opt-in: --ssvc-profile activates scoring, omitting it leaves
    the new fields at their dataclass defaults.
  * Surfaces correctly in CSV + Markdown.
"""
from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

import ramen_cve
from ramen_cve.ssvc import (
    SSVC_ACTIONS,
    _decision,
    _is_automatable,
    apply_ssvc,
    compute_ssvc,
    normalize_profile,
)


def _mk(
    cve_id: str = "CVE-2021-44228",
    *,
    cwe: list[str] | None = None,
    exploit_status: str = "none",
    kev_listed: bool = False,
    cvss_score: float | None = 9.5,
    bucket: str = "patch_now",
) -> ramen_cve.EnrichedCve:
    return ramen_cve.EnrichedCve(
        cve_id=cve_id, source="x", first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub", cvss_score=cvss_score,
        epss_score=0.5, bucket=bucket, kev_listed=kev_listed,
        exploit_status=exploit_status, cwe=cwe or [],
    )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_normalize_profile_defaults_when_input_is_none_or_empty():
    out = normalize_profile(None)
    assert out["mission_impact"] == "medium"
    assert out["safety_impact"] == "minor"
    assert out["value_density"] == "diffuse"
    assert out["exposure_default"] == "small"
    assert normalize_profile({}) == out


def test_normalize_profile_keeps_valid_overrides():
    out = normalize_profile({
        "mission_impact": "high",
        "safety_impact": "hazardous",
        "value_density": "concentrated",
        "exposure_default": "open",
    })
    assert out["mission_impact"] == "high"
    assert out["safety_impact"] == "hazardous"
    assert out["value_density"] == "concentrated"
    assert out["exposure_default"] == "open"


def test_normalize_profile_rejects_bad_values_falls_back_to_defaults():
    """A typo in the profile must not crash a triage — fall back to defaults."""
    out = normalize_profile({"mission_impact": "ultra-mega", "safety_impact": 99})
    assert out["mission_impact"] == "medium"      # invalid string → default
    assert out["safety_impact"] == "minor"         # non-string → default


def test_normalize_profile_keeps_unknown_keys_for_forward_compat():
    """Forward-compat: extra keys the user shipped flow through untouched."""
    out = normalize_profile({"future_field": "future-value", "mission_impact": "high"})
    assert out["future_field"] == "future-value"
    assert out["mission_impact"] == "high"


def test_is_automatable_recognises_canonical_cwes():
    assert _is_automatable(["CWE-89"]) is True              # SQLi
    assert _is_automatable(["CWE-502"]) is True             # unsafe deserialise
    assert _is_automatable(["CWE-918"]) is True             # SSRF
    assert _is_automatable(["cwe-78", "CWE-200"]) is True   # case-insensitive
    assert _is_automatable(["CWE-200"]) is False            # info disclosure — not automatable
    assert _is_automatable([]) is False
    assert _is_automatable(None) is False                   # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# compute_ssvc — decision derivation
# ---------------------------------------------------------------------------


def test_exploitation_active_when_kev_listed():
    """KEV listed → Exploitation=active (matches CISA's "in the wild" definition)."""
    rec = _mk(kev_listed=True, exploit_status="none")
    _, points = compute_ssvc(rec)
    assert points["exploitation"] == "active"


def test_exploitation_public_poc_on_exploit_signal():
    """Exploit-DB / Nuclei / GitHub PoC / Metasploit → Exploitation=public_poc."""
    for status in ("exploit_db", "nuclei_template", "github_poc", "metasploit"):
        rec = _mk(exploit_status=status, kev_listed=False)
        _, points = compute_ssvc(rec)
        assert points["exploitation"] == "public_poc", status


def test_exploitation_none_otherwise():
    rec = _mk(exploit_status="none", kev_listed=False)
    _, points = compute_ssvc(rec)
    assert points["exploitation"] == "none"


def test_utility_reads_cwe_and_profile():
    """Automatable + concentrated value → super_effective; the worst tier."""
    rec = _mk(cwe=["CWE-89"])      # SQLi: automatable
    _, points = compute_ssvc(rec, normalize_profile({"value_density": "concentrated"}))
    assert points["utility"] == "super_effective"

    # Not automatable + diffuse → laborious (cheapest tier).
    rec2 = _mk(cwe=["CWE-200"])
    _, points2 = compute_ssvc(rec2, normalize_profile({"value_density": "diffuse"}))
    assert points2["utility"] == "laborious"


def test_human_impact_reads_profile_only():
    """Both mission and safety impact are org-specific — no per-CVE signal."""
    _, p_low = compute_ssvc(_mk(), normalize_profile({
        "mission_impact": "low", "safety_impact": "negligible",
    }))
    assert p_low["human_impact"] == "low"

    _, p_high = compute_ssvc(_mk(), normalize_profile({
        "mission_impact": "high", "safety_impact": "catastrophic",
    }))
    assert p_high["human_impact"] == "very_high"


# ---------------------------------------------------------------------------
# _decision tree — action labels at sensible boundaries
# ---------------------------------------------------------------------------


def test_decision_lowest_case_defers():
    """Cheapest input on every axis → defer."""
    assert _decision(
        exposure="small", utility="laborious", human_impact="low", exploitation="none",
    ) == "defer"


def test_decision_high_kev_immediate():
    """KEV-listed, super-effective, open exposure, high impact → immediate."""
    assert _decision(
        exposure="open", utility="super_effective",
        human_impact="very_high", exploitation="active",
    ) == "immediate"


def test_decision_monotonic_under_worse_inputs():
    """Making any single axis worse must not LOWER severity."""
    rank = {a: i for i, a in enumerate(SSVC_ACTIONS)}
    baseline = _decision("small", "laborious", "low", "none")
    # Bump one axis at a time and confirm rank never decreases.
    worse_cases = [
        ("open", "laborious", "low", "none"),
        ("small", "super_effective", "low", "none"),
        ("small", "laborious", "very_high", "none"),
        ("small", "laborious", "low", "active"),
    ]
    for case in worse_cases:
        assert rank[_decision(*case)] >= rank[baseline], case


def test_compute_ssvc_returns_action_in_known_set():
    rec = _mk(kev_listed=True, cwe=["CWE-502"])
    action, _ = compute_ssvc(rec, normalize_profile({
        "exposure_default": "open", "value_density": "concentrated",
        "mission_impact": "very_high", "safety_impact": "catastrophic",
    }))
    assert action == "immediate"
    assert action in SSVC_ACTIONS


# ---------------------------------------------------------------------------
# apply_ssvc — in-place field population
# ---------------------------------------------------------------------------


def test_apply_ssvc_populates_fields_idempotently():
    rec = _mk(kev_listed=True)
    apply_ssvc([rec])
    first_action = rec.ssvc_action
    first_points = dict(rec.ssvc_decision_points)
    apply_ssvc([rec])           # idempotent re-application
    assert rec.ssvc_action == first_action
    assert rec.ssvc_decision_points == first_points


def test_apply_ssvc_empty_records_noop():
    apply_ssvc([])      # must not raise


# ---------------------------------------------------------------------------
# CLI + pipeline integration
# ---------------------------------------------------------------------------


def test_cli_accepts_ssvc_profile_flag(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text('{"mission_impact": "high"}')
    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--ssvc-profile", str(profile)]
    )
    assert args.ssvc_profile == profile


def test_output_populates_ssvc_when_profile_supplied(tmp_path):
    """End-to-end: --ssvc-profile activates SSVC; the CSV row carries it."""
    profile = tmp_path / "p.json"
    profile.write_text(json.dumps({
        "exposure_default": "open", "value_density": "concentrated",
        "mission_impact": "high", "safety_impact": "major",
    }))
    rec = _mk(kev_listed=True, cwe=["CWE-502"])
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="ssvc-run", allow_tlp_red=False,
        ssvc_profile=profile,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.ssvc_action in SSVC_ACTIONS
    body = (tmp_path / "ssvc-run.csv").read_text(encoding="utf-8-sig")
    # Column header is present + the row carries the action label.
    assert "ssvc_action" in body
    assert rec.ssvc_action in body
    # Decision points round-trip as k=v;k=v in the cell.
    assert "exploitation=active" in body
    assert "exposure=open" in body


def test_output_leaves_ssvc_empty_when_profile_omitted(tmp_path):
    """Without --ssvc-profile, fields stay default → CSV cell is empty."""
    rec = _mk(kev_listed=True)
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="no-ssvc", allow_tlp_red=False,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.ssvc_action is None
    body = (tmp_path / "no-ssvc.csv").read_text(encoding="utf-8-sig")
    assert "ssvc_action" in body          # column header always present
    # The row's ssvc_action cell is empty (between the two commas).
    rows = [line for line in body.splitlines() if line.startswith("CVE-")]
    assert rows
    assert ",," in rows[0] or rows[0].endswith(",")


def test_output_handles_unreadable_profile_fail_soft(tmp_path, caplog):
    """A missing / malformed profile path logs WARNING but doesn't crash."""
    import logging

    rec = _mk(kev_listed=True)
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="bad-profile", allow_tlp_red=False,
        ssvc_profile=Path("/nonexistent/profile.json"),
    )
    with caplog.at_level(logging.WARNING, logger="ramen_cve.pipeline"):
        ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.ssvc_action is None                # fields stay unset
    assert any("Skipping SSVC" in r.message for r in caplog.records)
    assert (tmp_path / "bad-profile.csv").exists()   # run still completes


def test_markdown_surfaces_ssvc_when_set(tmp_path):
    """When SSVC is populated, the Markdown report shows the action + points."""
    rec = _mk(kev_listed=True, cwe=["CWE-502"])
    apply_ssvc([rec], normalize_profile({
        "exposure_default": "open", "value_density": "concentrated",
        "mission_impact": "high", "safety_impact": "major",
    }))
    args = argparse.Namespace(
        format="md", out_dir=tmp_path, basename="ssvc-md", allow_tlp_red=False,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    body = (tmp_path / "ssvc-md.md").read_text(encoding="utf-8")
    assert "**SSVC:**" in body
    assert rec.ssvc_action in body
    assert "exploitation=" in body


def test_facade_reexports_ssvc_surface():
    """The new public symbols are reachable through the façade."""
    assert ramen_cve.compute_ssvc is compute_ssvc
    assert ramen_cve.apply_ssvc is apply_ssvc
    assert ramen_cve.SSVC_ACTIONS == SSVC_ACTIONS
