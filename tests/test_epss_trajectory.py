"""EPSS trajectory mode — Slice A coverage.

Covers the new behaviour added when `--date-mode epss` is given a multi-day
range: the orchestrator fetches historical EPSS once per day in the range
and stores the time-series on each `EnrichedCve.epss_trajectory`, with the
scalar `epss_*` fields pinned to the end-date value. Single-date and
no-range invocations remain byte-identical to pre-feature behaviour.

See `docs/REFACTOR_PLAN.md`-era plans in `tasks/todo.md` (task 1).
"""

from __future__ import annotations

import argparse
from datetime import date

import pytest

import ramen_cve
from ramen_cve import enrich_cves
from ramen_cve.cache import Cache
from ramen_cve.cli import _epss_date_range_for, _validate_args
from ramen_cve.models import CveRecord

# ---------------------------------------------------------------------------
# Helpers: stub the three upstream fetchers via the orchestrator's local
# bindings (per the plan's Amendment: tests patch symbols at the module
# where the function-under-test resolves them, not at the façade).
# ---------------------------------------------------------------------------


def _stub_nvd_kev(monkeypatch):
    """Make NVD + KEV no-ops so we can isolate the EPSS trajectory path."""
    monkeypatch.setattr(
        "ramen_cve.enrich.orchestrator.fetch_nvd",
        lambda cve_id, cache, api_key: {"nvd_status": "ok"},
    )
    monkeypatch.setattr(
        "ramen_cve.enrich.orchestrator.fetch_kev_catalog",
        lambda cache: {},
    )


def _epss_by_date_factory(per_date_scores):
    """Return a fetch_epss stub keyed on the score_date param."""

    def _stub(cve_ids, cache, score_date=None):
        scores = per_date_scores.get(score_date, {})
        return {
            cid: {"epss": e, "percentile": p, "date": score_date}
            for cid, (e, p) in scores.items()
        }

    return _stub


def _single_record():
    return CveRecord("CVE-2024-0001", "test", date(2024, 6, 1), "manual_input")


# ---------------------------------------------------------------------------
# Orchestrator behaviour
# ---------------------------------------------------------------------------


def test_trajectory_populated_for_multi_date_range(monkeypatch, tmp_path):
    """`epss_date_range=(start, end)` with start != end loops per day."""
    _stub_nvd_kev(monkeypatch)
    monkeypatch.setattr(
        "ramen_cve.enrich.orchestrator.fetch_epss",
        _epss_by_date_factory(
            {
                "2024-06-01": {"CVE-2024-0001": (0.10, 0.50)},
                "2024-06-02": {"CVE-2024-0001": (0.15, 0.75)},
                "2024-06-03": {"CVE-2024-0001": (0.20, 0.99)},
            }
        ),
    )
    cache = Cache(str(tmp_path / "cache.db"))

    [r] = enrich_cves(
        [_single_record()],
        cache,
        None,
        epss_date_range=(date(2024, 6, 1), date(2024, 6, 3)),
    )

    assert r.epss_trajectory == {
        "2024-06-01": {"epss": 0.10, "percentile": 0.50},
        "2024-06-02": {"epss": 0.15, "percentile": 0.75},
        "2024-06-03": {"epss": 0.20, "percentile": 0.99},
    }
    # Scalar fields are pinned to the END date so existing CSV/MD output
    # stays compatible (downstream consumers see the most recent score).
    assert r.epss_score == 0.20
    assert r.epss_percentile == 0.99
    assert r.epss_date == "2024-06-03"


def test_trajectory_empty_when_range_is_single_date(monkeypatch, tmp_path):
    """start == end is NOT trajectory mode — keeps today's single-shot path."""
    _stub_nvd_kev(monkeypatch)

    calls: list[str | None] = []

    def _fetch_epss(cve_ids, cache, score_date=None):
        calls.append(score_date)
        return {
            "CVE-2024-0001": {
                "epss": 0.42,
                "percentile": 0.84,
                "date": score_date or "current",
            }
        }

    monkeypatch.setattr("ramen_cve.enrich.orchestrator.fetch_epss", _fetch_epss)
    cache = Cache(str(tmp_path / "cache.db"))

    [r] = enrich_cves(
        [_single_record()],
        cache,
        None,
        epss_date_range=(date(2024, 6, 1), date(2024, 6, 1)),
    )

    # Single fetch call (no per-day loop) and an empty trajectory dict.
    assert calls == [None]  # falls through to the no-score-date branch
    assert r.epss_trajectory == {}
    assert r.epss_score == 0.42


def test_trajectory_empty_when_no_range(monkeypatch, tmp_path):
    """`epss_date_range=None` is byte-identical to today's single-shot fetch."""
    _stub_nvd_kev(monkeypatch)

    monkeypatch.setattr(
        "ramen_cve.enrich.orchestrator.fetch_epss",
        lambda ids, c, score_date=None: {
            "CVE-2024-0001": {"epss": 0.33, "percentile": 0.66, "date": "current"}
        },
    )
    cache = Cache(str(tmp_path / "cache.db"))

    [r] = enrich_cves([_single_record()], cache, None)

    assert r.epss_trajectory == {}
    assert r.epss_score == 0.33


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def _ns(**kw):
    """Minimal Namespace builder for the validator / helper."""
    base = {"start": None, "end": None, "date_mode": None}
    base.update(kw)
    return argparse.Namespace(**base)


def test_validate_args_allows_epss_range():
    """`--date-mode epss --start X --end Y` (X != Y) is no longer an error."""
    parser = argparse.ArgumentParser()
    args = _ns(date_mode="epss", start=date(2024, 1, 1), end=date(2024, 6, 1))
    _validate_args(args, parser)  # must not raise / call parser.error


def test_validate_args_still_requires_both_bounds_for_epss():
    """Even in trajectory mode, both --start and --end remain mandatory."""
    parser = argparse.ArgumentParser()
    args = _ns(date_mode="epss", start=date(2024, 1, 1), end=None)
    with pytest.raises(SystemExit):
        _validate_args(args, parser)  # parser.error raises SystemExit


def test_epss_date_range_for_returns_tuple_only_in_epss_mode():
    """Helper threads (start, end) into enrich_cves only for epss mode."""
    assert _epss_date_range_for(
        _ns(date_mode="epss", start=date(2024, 1, 1), end=date(2024, 6, 1))
    ) == (date(2024, 1, 1), date(2024, 6, 1))
    assert _epss_date_range_for(
        _ns(date_mode="feed", start=date(2024, 1, 1), end=date(2024, 6, 1))
    ) is None
    assert _epss_date_range_for(_ns(date_mode="epss", start=None, end=None)) is None


# ---------------------------------------------------------------------------
# Facade re-export sanity (the new field doesn't break L3)
# ---------------------------------------------------------------------------


def test_epss_trajectory_field_is_default_empty():
    """A freshly-constructed EnrichedCve has an empty trajectory dict."""
    r = ramen_cve.EnrichedCve(
        cve_id="CVE-2024-9999",
        source="t",
        first_seen=date(2024, 6, 1),
        first_seen_type="manual_input",
    )
    assert r.epss_trajectory == {}


# ---------------------------------------------------------------------------
# Slice B — sidecar CSV writer + pipeline integration
# ---------------------------------------------------------------------------


def _enriched(cve_id: str, trajectory: dict[str, dict] | None = None):
    from ramen_cve import EnrichedCve
    return EnrichedCve(
        cve_id=cve_id,
        source="t",
        first_seen=date(2024, 6, 1),
        first_seen_type="manual_input",
        epss_trajectory=trajectory or {},
    )


def test_write_epss_trajectory_csv_writes_one_row_per_date(tmp_path):
    """A record with N trajectory entries produces N data rows + 1 header."""
    from ramen_cve import write_epss_trajectory_csv

    rec = _enriched(
        "CVE-2024-0001",
        {
            "2024-06-01": {"epss": 0.10, "percentile": 0.50},
            "2024-06-02": {"epss": 0.15, "percentile": 0.75},
            "2024-06-03": {"epss": 0.20, "percentile": 0.99},
        },
    )
    out = tmp_path / "traj.csv"
    write_epss_trajectory_csv([rec], out)

    lines = out.read_text().splitlines()
    assert lines[0] == "cve_id,date,epss,percentile"
    assert lines[1:] == [
        "CVE-2024-0001,2024-06-01,0.1000,0.5000",
        "CVE-2024-0001,2024-06-02,0.1500,0.7500",
        "CVE-2024-0001,2024-06-03,0.2000,0.9900",
    ]


def test_write_epss_trajectory_csv_skips_records_with_empty_trajectory(tmp_path):
    """Records without a trajectory contribute zero data rows (just the header)."""
    from ramen_cve import write_epss_trajectory_csv

    out = tmp_path / "traj.csv"
    write_epss_trajectory_csv(
        [_enriched("CVE-2024-AAAA"), _enriched("CVE-2024-BBBB")], out
    )

    assert out.read_text().splitlines() == ["cve_id,date,epss,percentile"]


def test_write_epss_trajectory_csv_rows_are_sorted(tmp_path):
    """Rows are sorted by (cve_id, date) for byte-stable output."""
    from ramen_cve import write_epss_trajectory_csv

    a = _enriched(
        "CVE-2024-ZZZZ",
        {"2024-06-03": {"epss": 0.3, "percentile": 0.9}},
    )
    b = _enriched(
        "CVE-2024-AAAA",
        {
            "2024-06-02": {"epss": 0.2, "percentile": 0.8},
            "2024-06-01": {"epss": 0.1, "percentile": 0.5},
        },
    )
    out = tmp_path / "traj.csv"
    # Pass in shuffled order; output must still be sorted.
    write_epss_trajectory_csv([a, b], out)

    assert out.read_text().splitlines()[1:] == [
        "CVE-2024-AAAA,2024-06-01,0.1000,0.5000",
        "CVE-2024-AAAA,2024-06-02,0.2000,0.8000",
        "CVE-2024-ZZZZ,2024-06-03,0.3000,0.9000",
    ]


def test_pipeline_output_emits_sidecar_only_when_trajectory_present(tmp_path):
    """_output writes <basename>-epss-trajectory.csv iff any record has trajectory.

    Exercises the conditional emission inside pipeline._output: an
    enriched run with no trajectory must NOT create the sidecar; one
    with at least one trajectory entry must.
    """
    from ramen_cve import _output

    args = argparse.Namespace(
        format="csv", out_dir=tmp_path, basename="run",
        allow_tlp_red=True,  # avoid stripping
    )
    md = {"version": "test"}

    # Run 1: no trajectory anywhere -> no sidecar
    out_dir_1 = tmp_path / "run1"
    out_dir_1.mkdir()
    args.out_dir = out_dir_1
    _output([_enriched("CVE-2024-AAAA")], args, md, iocs=None)
    assert not list(out_dir_1.glob("*epss-trajectory*"))

    # Run 2: one record has a trajectory -> sidecar appears
    out_dir_2 = tmp_path / "run2"
    out_dir_2.mkdir()
    args.out_dir = out_dir_2
    rec = _enriched(
        "CVE-2024-AAAA",
        {"2024-06-01": {"epss": 0.1, "percentile": 0.5}},
    )
    _output([rec], args, md, iocs=None)
    sidecars = list(out_dir_2.glob("*epss-trajectory*"))
    assert len(sidecars) == 1, sidecars
    assert sidecars[0].name == "run-epss-trajectory.csv"


# ---------------------------------------------------------------------------
# Slice C — Markdown sparkline + inline table; render.py lift
# ---------------------------------------------------------------------------


def test_render_sparkline_identical_to_trend_facade():
    """The `ramen_cve.render._sparkline` lift preserves `_sparkline` behaviour;
    the `ramen_cve.trend` re-import and the façade keep resolving."""
    import ramen_cve
    from ramen_cve.render import _SPARKLINE_CHARS as char_set
    from ramen_cve.render import _sparkline as render_sparkline
    from ramen_cve.trend import _sparkline as trend_sparkline

    assert ramen_cve._sparkline is render_sparkline
    assert ramen_cve._sparkline is trend_sparkline  # trend re-imports it
    assert char_set == ramen_cve._SPARKLINE_CHARS

    # Smoke: known mappings.
    assert render_sparkline([0.0, 1.0]) == "▁█"
    assert render_sparkline([0.5, None, 0.5]) == "▁ ▁"
    assert render_sparkline([]) == ""


def _enriched_for_markdown(cve_id, trajectory=None):
    """An EnrichedCve with the minimum metadata write_markdown needs."""
    rec = _enriched(cve_id, trajectory=trajectory)
    rec.bucket = "patch_now"  # routes into a real section, not "## No CVEs found"
    rec.cvss_score = 9.0
    rec.cvss_severity = "CRITICAL"
    rec.epss_score = 0.5
    rec.epss_percentile = 0.8
    return rec


def test_markdown_emits_trajectory_section_for_records_with_trajectory(tmp_path):
    """A record with `epss_trajectory` gets a sparkline line + inline table."""
    from ramen_cve import write_markdown

    rec = _enriched_for_markdown(
        "CVE-2024-0001",
        trajectory={
            "2024-06-01": {"epss": 0.10, "percentile": 0.50},
            "2024-06-02": {"epss": 0.15, "percentile": 0.75},
            "2024-06-03": {"epss": 0.20, "percentile": 0.99},
        },
    )
    out = tmp_path / "report.md"
    write_markdown([rec], out, {"version": "test"})
    text = out.read_text()

    assert "- **EPSS trajectory:**" in text
    assert "2024-06-01 → 2024-06-03, 3 samples" in text
    # Inline table (<=10 samples threshold)
    assert "| Date | EPSS | Percentile |" in text
    assert "| 2024-06-01 | 0.1000 | 0.5000 |" in text
    assert "| 2024-06-03 | 0.2000 | 0.9900 |" in text


def test_markdown_omits_trajectory_section_when_dict_empty(tmp_path):
    """No trajectory key → no extra lines (byte-identical to pre-feature path)."""
    from ramen_cve import write_markdown

    rec = _enriched_for_markdown("CVE-2024-0001", trajectory=None)
    out = tmp_path / "report.md"
    write_markdown([rec], out, {"version": "test"})
    text = out.read_text()

    assert "EPSS trajectory" not in text
    assert "| Date | EPSS | Percentile |" not in text


def test_markdown_omits_table_when_trajectory_is_long(tmp_path):
    """> 10 samples: sparkline summary line only; table is suppressed
    (the full series is in the sidecar CSV from Slice B)."""
    from ramen_cve import write_markdown

    trajectory = {
        f"2024-06-{day:02d}": {"epss": 0.1 + day * 0.01, "percentile": 0.5}
        for day in range(1, 13)  # 12 samples
    }
    rec = _enriched_for_markdown("CVE-2024-0001", trajectory=trajectory)
    out = tmp_path / "report.md"
    write_markdown([rec], out, {"version": "test"})
    text = out.read_text()

    assert "- **EPSS trajectory:**" in text
    assert "12 samples" in text
    assert "| Date | EPSS | Percentile |" not in text  # table suppressed
