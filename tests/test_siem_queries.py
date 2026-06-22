"""Native SIEM query stub writers (src/ramen_cve/output/siem_queries.py).

Invariants:
  * Eligibility matches Sigma — KEV-listed + patch-now CVEs only.
  * Each platform's comment syntax is honoured (`//` for KQL/EQL,
    triple-backtick for SPL).
  * Header lines carry CVE metadata (bucket, CVSS, EPSS, KEV, ATT&CK, NVD URL).
  * Output is byte-deterministic for a fixed enriched set.
  * --format {kql,spl,eql} parses, combines with builtins, and `all` includes them.
  * Pipeline writes the per-platform directory and records it under
    paths["<platform>_dir"].
  * Empty/eligible-empty input produces an empty result without crashing.
"""
from __future__ import annotations

import argparse
from datetime import date

import pytest

import ramen_cve
from ramen_cve.output.siem_queries import (
    SIEM_QUERY_ELIGIBLE_BUCKETS,
    SIEM_QUERY_PLATFORMS,
    _build_eql_stub,
    _build_kql_stub,
    _build_spl_stub,
    _safe_filename_stem,
    write_siem_query_stubs,
)


def _mk(
    cve_id: str = "CVE-2021-44228",
    *,
    bucket: str = "patch_now",
    kev_listed: bool = False,
    techniques: list[str] | None = None,
) -> ramen_cve.EnrichedCve:
    return ramen_cve.EnrichedCve(
        cve_id=cve_id, source="x", first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub", cvss_score=9.8, cvss_severity="CRITICAL",
        epss_score=0.5421, bucket=bucket, kev_listed=kev_listed,
        # `is None` (not `or`) so `techniques=[]` actually passes through
        # — we use that to test the "no ATT&CK line" code path.
        attack_techniques=["T1190"] if techniques is None else techniques,
    )


# ---------------------------------------------------------------------------
# Eligibility + public surface
# ---------------------------------------------------------------------------


def test_eligibility_matches_sigma():
    """Same buckets sigma fires on — KEV + patch_now only."""
    assert SIEM_QUERY_ELIGIBLE_BUCKETS == ("kev_override", "patch_now")


def test_platforms_list_is_stable_canonical_order():
    assert SIEM_QUERY_PLATFORMS == ("kql", "spl", "eql")


def test_unknown_platform_raises(tmp_path):
    with pytest.raises(ValueError, match="Unknown SIEM platform"):
        write_siem_query_stubs([_mk()], tmp_path, "yaml-but-not-sigma")


# ---------------------------------------------------------------------------
# Stub content per platform
# ---------------------------------------------------------------------------


def test_kql_stub_uses_double_slash_comments_and_relative_window():
    rec = _mk(kev_listed=True)
    out = _build_kql_stub(rec)
    # Header comments
    assert out.startswith("// Detection scaffold for CVE-2021-44228")
    assert "// Bucket: patch_now" in out
    assert "// CISA KEV: listed" in out
    assert "// ATT&CK: T1190" in out
    assert "// Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in out
    # Body shape
    assert 'let cve_id = "CVE-2021-44228";' in out
    assert "ago(7d)" in out                    # deterministic relative window
    assert "<TableName>" in out                # analyst placeholder


def test_spl_stub_uses_triple_backtick_comments():
    rec = _mk(kev_listed=True)
    out = _build_spl_stub(rec)
    assert "``` Detection scaffold for CVE-2021-44228 ```" in out
    assert "``` Bucket: patch_now" in out
    assert "``` CISA KEV: listed" in out
    assert "``` ATT&CK: T1190 ```" in out
    assert "index=<index> earliest=-7d@d" in out   # deterministic window
    assert 'eval cve_id="CVE-2021-44228"' in out


def test_eql_stub_uses_double_slash_and_any_where_form():
    rec = _mk()
    out = _build_eql_stub(rec)
    assert out.startswith("// Detection scaffold for CVE-2021-44228")
    assert 'any where event.category in ("process", "file", "network")' in out
    assert "@timestamp >= now() - 7d" in out


def test_stub_omits_kev_line_when_not_listed():
    """No KEV signal → no KEV comment line in any platform's header."""
    rec = _mk(kev_listed=False)
    for builder in (_build_kql_stub, _build_spl_stub, _build_eql_stub):
        assert "CISA KEV" not in builder(rec)


def test_stub_omits_attack_line_when_techniques_empty():
    rec = _mk(techniques=[])
    for builder in (_build_kql_stub, _build_spl_stub, _build_eql_stub):
        assert "ATT&CK" not in builder(rec)


# ---------------------------------------------------------------------------
# Determinism + filenames
# ---------------------------------------------------------------------------


def test_safe_filename_stem_passthrough_and_sanitisation():
    assert _safe_filename_stem("CVE-2021-44228") == "CVE-2021-44228"
    assert _safe_filename_stem("CVE-2021-44228/../etc") == "CVE-2021-44228_.._etc"
    assert _safe_filename_stem("") == "unknown"
    assert _safe_filename_stem(None) == "unknown"   # type: ignore[arg-type]


@pytest.mark.parametrize("platform", SIEM_QUERY_PLATFORMS)
def test_write_stubs_byte_deterministic(tmp_path, platform):
    """Same enriched input → identical file bytes across two writes."""
    recs = [_mk("CVE-2021-44228", kev_listed=True), _mk("CVE-2021-26855")]
    d1 = tmp_path / f"{platform}-1"
    d2 = tmp_path / f"{platform}-2"
    write_siem_query_stubs(recs, d1, platform)
    write_siem_query_stubs(recs, d2, platform)
    for f1, f2 in zip(sorted(d1.iterdir()), sorted(d2.iterdir()), strict=True):
        assert f1.name == f2.name
        assert f1.read_bytes() == f2.read_bytes()


@pytest.mark.parametrize("platform,ext", [("kql", ".kql"), ("spl", ".spl"), ("eql", ".eql")])
def test_write_stubs_uses_platform_extension_per_eligible_cve(tmp_path, platform, ext):
    recs = [
        _mk("CVE-PATCH-NOW", bucket="patch_now"),
        _mk("CVE-KEV", bucket="kev_override", kev_listed=True),
        _mk("CVE-DEFER", bucket="deprioritize"),        # NOT eligible → skipped
        _mk("CVE-WATCH", bucket="watch_closely"),       # NOT eligible → skipped
    ]
    out = tmp_path / f"{platform}-out"
    written = write_siem_query_stubs(recs, out, platform)
    names = sorted(p.name for p in written)
    assert names == [f"CVE-KEV{ext}", f"CVE-PATCH-NOW{ext}"]
    assert all(p.suffix == ext for p in written)


def test_write_stubs_empty_input_returns_empty_no_dir_created(tmp_path):
    """No eligible records → no files written, no dir created."""
    target = tmp_path / "siem-empty"
    written = write_siem_query_stubs([], target, "kql")
    assert written == []
    assert not target.exists()


def test_write_stubs_all_ineligible_returns_empty(tmp_path):
    target = tmp_path / "siem-ineligible"
    rec = _mk(bucket="watch_closely")        # not eligible
    written = write_siem_query_stubs([rec], target, "kql")
    assert written == []


# ---------------------------------------------------------------------------
# CLI / pipeline / façade wiring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token", ["kql", "spl", "eql"])
def test_format_token_parses_alone_and_in_combo(token):
    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", token]
    )
    assert args.format == token
    combo = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", f"csv,{token}"]
    )
    assert combo.format == f"csv,{token}"


def test_format_all_includes_kql_spl_eql():
    args = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format", "all"]
    )
    assert args.format == "all"
    # The expansion accepts an explicit listing too — locks in canonical order.
    explicit = ramen_cve.build_parser().parse_args(
        ["cve", "CVE-2021-44228", "--format",
         "csv,md,stix,sigma,yara,html,navigator,kql,spl,eql"]
    )
    assert explicit.format == "all"


@pytest.mark.parametrize("platform", SIEM_QUERY_PLATFORMS)
def test_output_writes_platform_dir_alongside_builtins(tmp_path, platform):
    rec = _mk(kev_listed=True)
    args = argparse.Namespace(
        format=f"csv,{platform}", out_dir=tmp_path, basename="siem-run",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.2.0"})
    target = tmp_path / f"siem-run-{platform}"
    assert paths[f"{platform}_dir"] == target
    assert target.is_dir()
    files = list(target.iterdir())
    assert len(files) == 1
    assert files[0].suffix == f".{platform}"


def test_output_skips_platform_dir_when_no_eligible_records(tmp_path, caplog):
    """Watch-closely bucket → no stubs, no dir, an INFO line, but rc OK."""
    import logging

    rec = _mk(bucket="watch_closely")
    args = argparse.Namespace(
        format="kql", out_dir=tmp_path, basename="empty-kql", allow_tlp_red=False,
    )
    with caplog.at_level(logging.INFO, logger="ramen_cve.pipeline"):
        paths = ramen_cve._output([rec], args, {"version": "0.2.0"})
    assert paths["kql_dir"] is None
    assert not (tmp_path / "empty-kql-kql").exists()
    assert any("KQL stubs" in r.message for r in caplog.records)


def test_facade_reexports_siem_surface():
    assert ramen_cve.write_siem_query_stubs is write_siem_query_stubs
    assert ramen_cve.SIEM_QUERY_ELIGIBLE_BUCKETS == SIEM_QUERY_ELIGIBLE_BUCKETS
    assert ramen_cve.SIEM_QUERY_PLATFORMS == SIEM_QUERY_PLATFORMS


def test_wizard_format_choices_include_new_siem_platforms():
    """The wizard checkbox now offers all 10 concrete formats."""
    import inspect

    from ramen_cve import wizard

    src = inspect.getsource(wizard._ask_format)
    for token in ("navigator", "kql", "spl", "eql"):
        assert f'value="{token}"' in src
