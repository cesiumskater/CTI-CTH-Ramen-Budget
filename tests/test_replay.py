"""Backtesting / replay (src/ramen_cve/replay.py + cache.snapshot_as_of + the
`replay` subcommand).

Invariants under test:
  * snapshot_as_of reconstructs each CVE's most-recent state at/before the
    cutoff; CVEs first seen after the cutoff are excluded; empty → {}.
  * diff_snapshots classifies added / removed / changed / unchanged with
    deterministic ordering.
  * bucket_counts tallies per bucket; _end_of_day bounds a calendar day.
  * _run_replay: prints distribution + transitions + new; --to before
    --as-of → rc 1; empty history → rc 0 + info; a non-canonical bucket in
    history is still shown (regression lock).
  * Parser wiring + façade re-exports.
"""
from __future__ import annotations

import argparse
from datetime import date

import ramen_cve
from ramen_cve.cache import Cache
from ramen_cve.replay import _end_of_day, bucket_counts, diff_snapshots

_ROWS = [
    ("CVE-2021-44228", "2024-01-10T09:00:00", "watch_closely", 7.0, 0.10),
    ("CVE-2021-44228", "2024-06-10T09:00:00", "patch_now", 10.0, 0.90),  # escalated
    ("CVE-2021-26855", "2024-01-10T09:00:00", "patch_now", 9.8, 0.80),   # steady
    ("CVE-2021-26855", "2024-06-10T09:00:00", "patch_now", 9.8, 0.85),
    ("CVE-2024-9999",  "2024-06-10T09:00:00", "patch_now", 9.0, 0.95),   # new in June
]


def _seeded_cache(rows=_ROWS) -> Cache:
    c = Cache(":memory:")
    for row in rows:
        c._conn.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?)", row)
    c._conn.commit()
    return c


# ---------------------------------------------------------------------------
# cache.snapshot_as_of
# ---------------------------------------------------------------------------


def test_snapshot_as_of_picks_latest_state_on_or_before_cutoff():
    c = _seeded_cache()
    jan = c.snapshot_as_of("2024-01-31T23:59:59")
    assert set(jan) == {"CVE-2021-44228", "CVE-2021-26855"}  # 2024-9999 not yet seen
    assert jan["CVE-2021-44228"]["bucket"] == "watch_closely"


def test_snapshot_as_of_reflects_later_state():
    c = _seeded_cache()
    jun = c.snapshot_as_of("2024-06-30T23:59:59")
    assert set(jun) == {"CVE-2021-44228", "CVE-2021-26855", "CVE-2024-9999"}
    assert jun["CVE-2021-44228"]["bucket"] == "patch_now"  # escalated by June


def test_snapshot_as_of_before_any_run_is_empty():
    assert _seeded_cache().snapshot_as_of("2023-01-01T23:59:59") == {}


# ---------------------------------------------------------------------------
# diff_snapshots / bucket_counts / _end_of_day
# ---------------------------------------------------------------------------


def test_diff_snapshots_classifies_transitions():
    c = _seeded_cache()
    d = diff_snapshots(
        c.snapshot_as_of("2024-01-31T23:59:59"),
        c.snapshot_as_of("2024-06-30T23:59:59"),
    )
    assert d["added"] == ["CVE-2024-9999"]
    assert d["removed"] == []
    assert d["changed"] == [("CVE-2021-44228", "watch_closely", "patch_now")]
    assert d["unchanged"] == 1  # CVE-2021-26855 held at patch_now


def test_diff_snapshots_detects_removed_when_reversed():
    """A backward diff (later → earlier) surfaces CVEs not yet tracked then."""
    before = {"A": {"bucket": "patch_now"}, "B": {"bucket": "patch_now"}}
    after = {"A": {"bucket": "patch_now"}}
    assert diff_snapshots(before, after)["removed"] == ["B"]


def test_bucket_counts_tallies_per_bucket():
    c = _seeded_cache()
    assert bucket_counts(c.snapshot_as_of("2024-06-30T23:59:59")) == {"patch_now": 3}


def test_end_of_day_bounds_the_day():
    assert _end_of_day(date(2024, 1, 15)) == "2024-01-15T23:59:59"


# ---------------------------------------------------------------------------
# _run_replay
# ---------------------------------------------------------------------------


def test_run_replay_prints_distribution_and_transitions(capsys):
    args = argparse.Namespace(as_of=date(2024, 1, 31), to=date(2024, 6, 30))
    rc = ramen_cve._run_replay(args, _seeded_cache(), None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "## Bucket distribution" in out
    assert "## Bucket transitions" in out
    assert "CVE-2021-44228 | watch_closely | → | patch_now" in out
    assert "New since 2024-01-31:" in out and "CVE-2024-9999" in out


def test_run_replay_to_before_as_of_is_error(capsys):
    args = argparse.Namespace(as_of=date(2024, 6, 30), to=date(2024, 1, 1))
    assert ramen_cve._run_replay(args, _seeded_cache(), None) == 1


def test_run_replay_empty_history_is_ok(caplog):
    args = argparse.Namespace(as_of=date(2024, 1, 1), to=date(2024, 2, 1))
    with caplog.at_level("INFO"):
        rc = ramen_cve._run_replay(args, Cache(":memory:"), None)
    assert rc == 0
    assert any("No historical runs" in r.message for r in caplog.records)


def test_run_replay_shows_non_canonical_bucket(capsys):
    """A bucket present in history but absent from BUCKET_ACTIONS must still
    appear in the distribution (guards the count-reconciliation fix)."""
    c = _seeded_cache([("CVE-2020-0001", "2024-03-01T09:00:00", "legacy_bucket", 5.0, 0.1)])
    args = argparse.Namespace(as_of=date(2024, 3, 31), to=date(2024, 4, 30))
    ramen_cve._run_replay(args, c, None)
    assert "legacy_bucket" in capsys.readouterr().out


def test_run_replay_to_none_uses_now(capsys):
    """--to omitted diffs against 'now'; all seeded 2024 rows precede now."""
    args = argparse.Namespace(as_of=date(2024, 1, 31), to=None)
    rc = ramen_cve._run_replay(args, _seeded_cache(), None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "→ now" in out


# ---------------------------------------------------------------------------
# Parser wiring + façade
# ---------------------------------------------------------------------------


def test_parser_wires_replay_subcommand():
    args = ramen_cve.build_parser().parse_args(["replay", "--as-of", "2024-01-01"])
    assert args.subcommand == "replay"
    assert args.as_of == date(2024, 1, 1)
    assert args.to is None


def test_parser_replay_accepts_to():
    args = ramen_cve.build_parser().parse_args(
        ["replay", "--as-of", "2024-01-01", "--to", "2024-06-01"]
    )
    assert args.to == date(2024, 6, 1)


def test_facade_reexports_replay_surface():
    assert ramen_cve.diff_snapshots is diff_snapshots
    assert ramen_cve.bucket_counts is bucket_counts
    assert ramen_cve._run_replay.__name__ == "_run_replay"
