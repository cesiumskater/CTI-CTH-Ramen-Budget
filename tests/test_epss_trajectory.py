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
