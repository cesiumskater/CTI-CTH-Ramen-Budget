"""Risk-weighted prioritization (src/ramen_cve/risk.py + the inventory +
pipeline + CSV + Markdown wiring).

Invariants under test:
  * Formula maths is correct for every component (host crit, CVSS, EPSS,
    KEV); inputs that are None degrade gracefully.
  * KEV multiplier dominates — a KEV-listed CVE outranks any non-KEV one
    at equal CVSS/EPSS/host.
  * worst_criticality picks the most-critical tier from a mixed list.
  * The inventory loader reads the optional `criticality` column
    case-insensitively; missing column is fine.
  * correlate_inventory populates affected_host_criticality with the
    worst host tier among matches.
  * Pipeline always populates risk_score (even without inventory crit).
  * CSV adds the two new columns; Markdown surfaces the line and
    re-ranks CVEs within a bucket by risk_score descending.
  * Facade re-exports the public surface.
"""
from __future__ import annotations

import argparse
from datetime import date

import ramen_cve
from ramen_cve.enrich.inventory import correlate_inventory, load_inventory
from ramen_cve.models import ThreatActor
from ramen_cve.risk import (
    CRITICALITY_TIERS,
    apply_risk_scores,
    apply_sector_weight,
    compute_risk_score,
    sector_matches,
    worst_criticality,
)


def _mk_actor_cve(sector: str, *, cvss_score: float = 8.0) -> ramen_cve.EnrichedCve:
    """An EnrichedCve linked to one actor targeting `sector`."""
    return ramen_cve.EnrichedCve(
        cve_id="CVE-2024-0001", source="x", first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub", cvss_score=cvss_score, epss_score=0.0,
        bucket="patch_now",
        linked_actors=[ThreatActor(name="Grp", sectors_targeted=[sector])],
    )


def _mk(
    cve_id: str = "CVE-2021-44228",
    *,
    cvss_score: float | None = 9.5,
    epss_score: float | None = 0.5,
    kev_listed: bool = False,
    affected_host_criticality: str | None = None,
    bucket: str = "patch_now",
    cpes: list[str] | None = None,
) -> ramen_cve.EnrichedCve:
    return ramen_cve.EnrichedCve(
        cve_id=cve_id, source="x", first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=cvss_score, epss_score=epss_score, kev_listed=kev_listed,
        bucket=bucket, cpes=cpes or [],
        affected_host_criticality=affected_host_criticality,
    )


# ---------------------------------------------------------------------------
# worst_criticality
# ---------------------------------------------------------------------------


def test_worst_criticality_picks_most_critical_tier():
    assert worst_criticality(["tier3", "tier1", "tier2"]) == "tier1"
    assert worst_criticality(["tier3", "tier2"]) == "tier2"
    assert worst_criticality(["tier3"]) == "tier3"


def test_worst_criticality_is_case_insensitive():
    assert worst_criticality(["TIER2", "Tier1"]) == "tier1"


def test_worst_criticality_ignores_none_and_unknown_tiers():
    assert worst_criticality([None, "tier3", "garbage"]) == "tier3"
    assert worst_criticality([None, None]) is None
    assert worst_criticality([]) is None


def test_criticality_tiers_ordered_worst_to_best():
    """Public constant ordering matches the rank function."""
    assert CRITICALITY_TIERS == ("tier1", "tier2", "tier3")


# ---------------------------------------------------------------------------
# compute_risk_score — formula
# ---------------------------------------------------------------------------


def test_risk_score_baseline_one_when_everything_is_zero():
    """No KEV, no EPSS, no CVSS, no inventory → 1.0 baseline."""
    rec = _mk(cvss_score=None, epss_score=None, kev_listed=False,
              affected_host_criticality=None)
    assert compute_risk_score(rec) == 1.0


def test_risk_score_scales_with_cvss():
    """Score doubles when CVSS doubles, holding all else equal."""
    a = compute_risk_score(_mk(cvss_score=4.0, epss_score=0.0, kev_listed=False))
    b = compute_risk_score(_mk(cvss_score=8.0, epss_score=0.0, kev_listed=False))
    assert b == 2 * a


def test_risk_score_scales_with_epss():
    """EPSS=0 → factor 1.0; EPSS=0.5 → factor 2.0; EPSS=1.0 → factor 3.0."""
    base = compute_risk_score(_mk(cvss_score=10.0, epss_score=0.0))
    mid = compute_risk_score(_mk(cvss_score=10.0, epss_score=0.5))
    high = compute_risk_score(_mk(cvss_score=10.0, epss_score=1.0))
    assert mid == 2 * base
    assert high == 3 * base


def test_kev_multiplier_dominates():
    """KEV pushes a low-CVSS finding ahead of a high-CVSS non-KEV finding."""
    low_kev = compute_risk_score(_mk(cvss_score=4.0, epss_score=0.1, kev_listed=True))
    high_clean = compute_risk_score(_mk(cvss_score=10.0, epss_score=0.5, kev_listed=False))
    assert low_kev > high_clean


def test_host_criticality_weights_apply_correctly():
    """tier1 triples, tier2 doubles, tier3 / None are neutral."""
    s_none = compute_risk_score(_mk(affected_host_criticality=None))
    s_tier3 = compute_risk_score(_mk(affected_host_criticality="tier3"))
    s_tier2 = compute_risk_score(_mk(affected_host_criticality="tier2"))
    s_tier1 = compute_risk_score(_mk(affected_host_criticality="tier1"))
    assert s_none == s_tier3
    assert s_tier2 == 2 * s_tier3
    assert s_tier1 == 3 * s_tier3


def test_apply_risk_scores_in_place_and_idempotent():
    rec = _mk(kev_listed=True, affected_host_criticality="tier1")
    apply_risk_scores([rec])
    first = rec.risk_score
    apply_risk_scores([rec])
    assert rec.risk_score == first


def test_apply_risk_scores_empty_is_noop():
    apply_risk_scores([])


# ---------------------------------------------------------------------------
# Inventory loader + correlate_inventory
# ---------------------------------------------------------------------------


def test_inventory_loader_reads_criticality_case_insensitively(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text(
        "host,product,version,criticality\n"
        "web-1,log4j,2.14.1,TIER1\n"
        "db-1,postgres,15.2,tier2\n"
        "dev-1,python,3.11,\n"
    )
    rows = load_inventory(inv)
    assert rows[0]["criticality"] == "tier1"
    assert rows[1]["criticality"] == "tier2"
    assert rows[2]["criticality"] == ""              # empty column tolerated


def test_inventory_loader_tolerates_missing_criticality_column(tmp_path):
    """Inventories without the column still parse and `criticality` is empty."""
    inv = tmp_path / "old.csv"
    inv.write_text("host,product,version\nweb-1,log4j,2.14.1\n")
    rows = load_inventory(inv)
    assert rows == [{
        "host": "web-1", "product": "log4j", "version": "2.14.1",
        "cpe": "", "owner": "", "criticality": "",
    }]


def test_correlate_inventory_records_worst_host_criticality(tmp_path):
    """When two affected hosts have different tiers, the worst wins."""
    rec = _mk(cpes=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"])
    inv = [
        {"host": "web-1", "product": "log4j", "version": "2.14.1",
         "cpe": "", "owner": "", "criticality": "tier2"},
        {"host": "prod-1", "product": "log4j", "version": "2.14.1",
         "cpe": "", "owner": "", "criticality": "tier1"},
        {"host": "dev-1", "product": "log4j", "version": "2.14.1",
         "cpe": "", "owner": "", "criticality": ""},
    ]
    correlate_inventory([rec], inv)
    assert set(rec.affected_hosts) == {"web-1", "prod-1", "dev-1"}
    assert rec.affected_host_criticality == "tier1"          # the worst wins


def test_correlate_inventory_leaves_criticality_none_when_unset(tmp_path):
    """Inventory with no criticality column → field stays None."""
    rec = _mk(cpes=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"])
    inv = [{
        "host": "web-1", "product": "log4j", "version": "2.14.1",
        "cpe": "", "owner": "", "criticality": "",
    }]
    correlate_inventory([rec], inv)
    assert rec.affected_hosts == ["web-1"]
    assert rec.affected_host_criticality is None


# ---------------------------------------------------------------------------
# Pipeline + CSV + Markdown wiring
# ---------------------------------------------------------------------------


def test_output_always_populates_risk_score(tmp_path):
    """risk_score is computed unconditionally — no inventory needed."""
    rec = _mk(kev_listed=True, cvss_score=10.0, epss_score=0.9)
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="rs-run", allow_tlp_red=False,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.risk_score is not None
    body = (tmp_path / "rs-run.csv").read_text(encoding="utf-8-sig")
    assert "risk_score" in body
    assert "affected_host_criticality" in body


def test_markdown_re_ranks_within_bucket_by_risk_score(tmp_path):
    """Two CVEs in the SAME bucket — the higher risk_score appears first."""
    low = _mk("CVE-LOW", cvss_score=7.0, epss_score=0.1, kev_listed=False,
              affected_host_criticality=None, bucket="patch_now")
    high = _mk("CVE-HIGH", cvss_score=7.0, epss_score=0.1, kev_listed=True,
               affected_host_criticality="tier1", bucket="patch_now")
    args = argparse.Namespace(
        format="md", out_dir=tmp_path, basename="rerank", allow_tlp_red=False,
    )
    ramen_cve._output([low, high], args, {"version": "0.2.0"})
    body = (tmp_path / "rerank.md").read_text(encoding="utf-8")
    # The CVE-HIGH header must appear before CVE-LOW within the report.
    assert body.index("CVE-HIGH") < body.index("CVE-LOW")


def test_markdown_surfaces_risk_score_line(tmp_path):
    rec = _mk(kev_listed=True, affected_host_criticality="tier1")
    args = argparse.Namespace(
        format="md", out_dir=tmp_path, basename="risk-md", allow_tlp_red=False,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    body = (tmp_path / "risk-md.md").read_text(encoding="utf-8")
    assert "**Risk score:**" in body
    assert "tier1" in body


# ---------------------------------------------------------------------------
# Sector weighting (--sector-weight)
# ---------------------------------------------------------------------------


def test_sector_matches_true_false_and_case_insensitive():
    rec = _mk_actor_cve("energy")
    assert sector_matches(rec, "energy") is True
    assert sector_matches(rec, "ENERGY") is True          # case-insensitive
    assert sector_matches(rec, "financial") is False


def test_sector_matches_blank_and_no_actors():
    assert sector_matches(_mk_actor_cve("energy"), "") is False
    no_actors = _mk(bucket="patch_now")
    assert sector_matches(no_actors, "energy") is False


def test_apply_sector_weight_boosts_only_matching_records():
    match = _mk_actor_cve("energy")
    miss = _mk_actor_cve("financial")
    apply_risk_scores([match, miss])
    base_match, base_miss = match.risk_score, miss.risk_score
    scaled = apply_sector_weight([match, miss], "energy", 2.0)
    assert scaled == 1
    assert match.risk_score == 2 * base_match      # matched → x2
    assert miss.risk_score == base_miss            # unmatched → untouched


def test_apply_sector_weight_returns_count_scaled():
    recs = [_mk_actor_cve("energy"), _mk_actor_cve("energy"), _mk_actor_cve("retail")]
    apply_risk_scores(recs)
    assert apply_sector_weight(recs, "energy", 1.5) == 2


def test_apply_sector_weight_noop_cases():
    """Blank sector, weight of exactly 1.0, or None weight → no-op (returns 0)."""
    recs = [_mk_actor_cve("energy")]
    apply_risk_scores(recs)
    base = recs[0].risk_score
    assert apply_sector_weight(recs, "", 2.0) == 0
    assert apply_sector_weight(recs, "energy", 1.0) == 0
    assert apply_sector_weight(recs, "energy", None) == 0
    assert recs[0].risk_score == base              # unchanged in every no-op


def test_apply_sector_weight_below_one_deprioritizes():
    """A weight < 1.0 is allowed and de-emphasizes matched CVEs."""
    recs = [_mk_actor_cve("energy")]
    apply_risk_scores(recs)
    base = recs[0].risk_score
    apply_sector_weight(recs, "energy", 0.5)
    assert recs[0].risk_score == 0.5 * base


def test_apply_sector_weight_skips_records_without_score():
    """A record whose risk_score was never computed is left alone."""
    rec = _mk_actor_cve("energy")            # risk_score still None
    assert rec.risk_score is None
    assert apply_sector_weight([rec], "energy", 2.0) == 0
    assert rec.risk_score is None


def test_output_wiring_applies_sector_weight(tmp_path):
    """End-to-end through _output: --sector + --sector-weight scales the score."""
    rec = _mk_actor_cve("energy")
    expected = compute_risk_score(rec) * 3.0
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="sw", allow_tlp_red=False,
        sector="energy", sector_weight=3.0,
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.risk_score == expected


def test_output_wiring_sector_weight_default_is_noop(tmp_path):
    """Without --sector-weight (default 1.0) the score equals the base."""
    rec = _mk_actor_cve("energy")
    expected = compute_risk_score(rec)
    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="sw0", allow_tlp_red=False,
        sector="energy",  # no sector_weight attr → getattr default 1.0
    )
    ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert rec.risk_score == expected


def test_facade_reexports_risk_surface():
    assert ramen_cve.compute_risk_score is compute_risk_score
    assert ramen_cve.apply_risk_scores is apply_risk_scores
    assert ramen_cve.apply_sector_weight is apply_sector_weight
    assert ramen_cve.sector_matches is sector_matches
    assert ramen_cve.worst_criticality is worst_criticality
    assert ramen_cve.CRITICALITY_TIERS == CRITICALITY_TIERS
