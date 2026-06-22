"""ATT&CK Navigator layer writer (output/navigator.py).

Invariants under test:
  * Parent + sub-technique split (Navigator's layer schema expects parent
    in techniqueID and a separate row per sub).
  * Bucket → score mapping (KEV hottest, deprioritize coldest).
  * Worst-bucket aggregation per technique when multiple CVEs share one.
  * Stable byte output (deterministic JSON for fixed input).
  * Empty CVE list still produces a valid (empty-techniques) layer.
  * Malformed technique tokens are silently dropped (fail-soft).
  * --format navigator parses + the pipeline writes the right artefact.
"""
from __future__ import annotations

import argparse
import json
from datetime import date

import pytest

import ramen_cve
from ramen_cve.output.navigator import (
    _BUCKET_SCORE,
    _technique_id,
    _worst_bucket,
    build_navigator_layer,
    write_navigator,
)

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_technique_id_splits_parent_and_sub():
    assert _technique_id("T1190") == ("T1190", None)
    assert _technique_id("T1059.001") == ("T1059", "T1059.001")
    assert _technique_id("t1190") == ("T1190", None)        # case-insensitive
    assert _technique_id("  T1190  ") == ("T1190", None)    # trimmed
    # Anything that isn't a recognisable technique drops silently.
    assert _technique_id("CWE-79") == ("", None)
    assert _technique_id("") == ("", None)
    assert _technique_id(None) == ("", None)                # type: ignore[arg-type]
    assert _technique_id("garbage") == ("", None)


def test_worst_bucket_picks_highest_priority():
    """KEV (rank 0) beats patch_now (rank 1) beats deprioritize (rank 4)."""
    assert _worst_bucket(["deprioritize", "patch_now", "kev_override"]) == "kev_override"
    assert _worst_bucket(["watch_closely", "patch_now"]) == "patch_now"
    assert _worst_bucket(["unknown", "deprioritize"]) == "deprioritize"
    assert _worst_bucket(["deprioritize"]) == "deprioritize"


# ---------------------------------------------------------------------------
# build_navigator_layer — the pure converter
# ---------------------------------------------------------------------------


def _mk(cve_id: str, bucket: str, techniques: list[str]) -> ramen_cve.EnrichedCve:
    return ramen_cve.EnrichedCve(
        cve_id=cve_id, source="x", first_seen=date(2024, 1, 1), first_seen_type="feed_pub",
        cvss_score=8.0, epss_score=0.5, bucket=bucket, attack_techniques=techniques,
    )


def test_build_layer_shape_is_navigator_schema_compatible():
    rec = _mk("CVE-2021-44228", "kev_override", ["T1190"])
    layer = build_navigator_layer([rec], run_metadata={"version": "0.2.0"})
    # Minimum keys the Navigator UI requires to render.
    assert layer["domain"] == "enterprise-attack"
    assert "versions" in layer and "layer" in layer["versions"]
    assert "gradient" in layer
    assert "techniques" in layer
    # legendItems aren't required by the schema but are how the user reads
    # the colour mapping in the Navigator sidebar.
    assert any(item["label"] == "KEV override" for item in layer["legendItems"])


def test_build_layer_aggregates_cves_per_technique_with_worst_bucket():
    """Two CVEs sharing T1190 → one entry, score = worst bucket, comment lists both."""
    recs = [
        _mk("CVE-A", "patch_now", ["T1190"]),
        _mk("CVE-B", "kev_override", ["T1190"]),    # the hotter contributor
    ]
    layer = build_navigator_layer(recs)
    t1190 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1190")
    assert t1190["score"] == _BUCKET_SCORE["kev_override"]   # worst wins
    assert "CVE-A" in t1190["comment"] and "CVE-B" in t1190["comment"]
    assert "worst bucket: kev_override" in t1190["comment"]


def test_build_layer_emits_parent_and_sub_rows():
    """A CVE with a sub-technique produces BOTH the parent row and a sub row,
    each at the same score (Navigator renders them on separate matrix cells)."""
    rec = _mk("CVE-X", "patch_now", ["T1059.001"])
    layer = build_navigator_layer([rec])
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1059", "T1059.001"]                      # parent first, then sub
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1059"] == scores["T1059.001"] == _BUCKET_SCORE["patch_now"]


def test_build_layer_drops_invalid_technique_tokens():
    """Heuristic CWE→ATT&CK mappings can yield junk; the writer must not crash."""
    rec = _mk("CVE-Y", "patch_now", ["T1190", "CWE-79", "", "garbage"])
    layer = build_navigator_layer([rec])
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1190"]


def test_build_layer_empty_input_is_valid_layer():
    """No CVEs in scope → still a valid (empty-techniques) Navigator file —
    the analyst gets a blank matrix rather than an error."""
    layer = build_navigator_layer([])
    assert layer["techniques"] == []
    assert "gradient" in layer                                # still a complete schema


def test_build_layer_score_ordering_matches_bucket_priority():
    """Hotter bucket → higher score on the heatmap."""
    assert _BUCKET_SCORE["kev_override"] > _BUCKET_SCORE["patch_now"]
    assert _BUCKET_SCORE["patch_now"] > _BUCKET_SCORE["plan_and_patch"]
    assert _BUCKET_SCORE["plan_and_patch"] > _BUCKET_SCORE["watch_closely"]
    assert _BUCKET_SCORE["watch_closely"] > _BUCKET_SCORE["deprioritize"]


# ---------------------------------------------------------------------------
# write_navigator — disk + determinism
# ---------------------------------------------------------------------------


def test_write_navigator_produces_valid_json(tmp_path):
    rec = _mk("CVE-2021-44228", "kev_override", ["T1190", "T1059.001"])
    out = tmp_path / "run.attack-layer.json"
    write_navigator([rec], out, run_metadata={"version": "0.2.0"})
    assert out.exists()
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["domain"] == "enterprise-attack"
    # Final newline (POSIX convention; helps `diff`).
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_write_navigator_is_byte_deterministic(tmp_path):
    """Same enriched input + same metadata → identical bytes across runs.
    Determinism is the contract every output writer obeys; this is the test
    that proves it for the new one."""
    recs = [
        _mk("CVE-B", "patch_now", ["T1059.001", "T1190"]),
        _mk("CVE-A", "kev_override", ["T1190"]),
    ]
    p1 = tmp_path / "a.attack-layer.json"
    p2 = tmp_path / "b.attack-layer.json"
    write_navigator(recs, p1, run_metadata={"version": "0.2.0"})
    write_navigator(recs, p2, run_metadata={"version": "0.2.0"})
    assert p1.read_bytes() == p2.read_bytes()


# ---------------------------------------------------------------------------
# CLI / pipeline wiring
# ---------------------------------------------------------------------------


def test_format_navigator_parses_and_combines():
    """--format navigator is a recognised single token and combines with builtins."""
    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", "navigator"]
    )
    assert args.format == "navigator"
    combo = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", "csv,navigator"]
    )
    assert combo.format == "csv,navigator"
    # `--format all` includes the new token (every concrete format).
    all_args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", "all"]
    )
    assert all_args.format == "all"


def test_format_unknown_navigator_typo_rejected(capsys):
    """A typo like 'navagator' is rejected at parse time (rc 2)."""
    with pytest.raises(SystemExit) as exc:
        ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", "navagator"]
        )
    assert exc.value.code == 2
    assert "navagator" in capsys.readouterr().err


def test_output_writes_navigator_layer_alongside_builtins(tmp_path):
    """End-to-end: --format csv,navigator writes the CSV AND the layer file,
    and recordeds the layer under `paths["navigator"]`."""
    rec = _mk("CVE-2021-44228", "kev_override", ["T1190", "T1059.001"])
    args = argparse.Namespace(
        format="csv,navigator", out_dir=tmp_path, basename="nav-run", allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert (tmp_path / "nav-run.csv").exists()
    nav = tmp_path / "nav-run.attack-layer.json"
    assert nav.exists() and paths["navigator"] == nav
    layer = json.loads(nav.read_text(encoding="utf-8"))
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1190" in ids and "T1059" in ids and "T1059.001" in ids


def test_output_skips_navigator_when_format_omits_it(tmp_path):
    """--format both (csv,md) must NOT write the navigator file."""
    rec = _mk("CVE-2021-44228", "kev_override", ["T1190"])
    args = argparse.Namespace(
        format="both", out_dir=tmp_path, basename="nav-skip", allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert paths.get("navigator") is None
    assert not (tmp_path / "nav-skip.attack-layer.json").exists()
