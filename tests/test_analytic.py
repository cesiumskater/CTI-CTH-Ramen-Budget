"""Detection-analytic library (src/ramen_cve/analytic.py + models.Analytic +
the `analytic` subcommand + data/analytics.json).

Invariants under test:
  * The bundled catalog loads, is sorted by id, has unique ids, and every
    entry carries id + name + technique_ids.
  * The bundled catalog covers the techniques of the bundled log4shell hunt
    (T1190, T1059), so `analytic suggest` is useful out of the box.
  * Technique ids are upper-cased/trimmed; overlap is parent/sub-technique
    aware (T1059 matches T1059.001) via _base_technique.
  * load_analytics degrades gracefully: missing / malformed / wrong-shape
    file → [] ; duplicate ids dropped; a bare top-level list is accepted.
  * suggest_analytics ranks by distinct shared base techniques (then id),
    reports only the overlapping techniques, and is empty when the hunt has
    no techniques or nothing overlaps.
  * CLI wiring: list / show / suggest exit codes + output; unknown ids and
    missing hunts fail cleanly.
  * Facade re-exports the public surface.
"""
from __future__ import annotations

import json

import pytest

import ramen_cve
from ramen_cve.analytic import (
    _base_technique,
    load_analytics,
    suggest_analytics,
)
from ramen_cve.models import Analytic, Hunt

BUNDLED = ramen_cve.DEFAULT_ANALYTICS_PATH


def _write_catalog(path, entries: list[dict]):
    path.write_text(json.dumps({"analytics": entries}), encoding="utf-8")
    return path


def _hunt(techniques: list[str], hid: str = "h1") -> Hunt:
    return Hunt(id=hid, name="H", hypothesis="", attack_techniques=list(techniques))


# ---------------------------------------------------------------------------
# Bundled catalog
# ---------------------------------------------------------------------------


def test_bundled_catalog_loads_sorted_unique_and_well_formed():
    analytics = load_analytics()
    assert analytics, "bundled analytics.json should be non-empty"
    ids = [a.id for a in analytics]
    assert ids == sorted(ids), "catalog must be returned sorted by id"
    assert len(ids) == len(set(ids)), "catalog ids must be unique"
    for a in analytics:
        assert a.id and a.name, f"{a.id!r} missing id/name"
        assert a.technique_ids, f"{a.id!r} has no technique_ids"


def test_bundled_catalog_covers_log4shell_hunt_techniques():
    """The bundled hunt is tagged T1190 + T1059; the catalog must overlap both
    so `analytic suggest log4shell-evidence` is useful with zero setup."""
    bases = {_base_technique(t) for a in load_analytics() for t in a.technique_ids}
    assert "T1190" in bases
    assert "T1059" in bases


def test_bundled_json_is_valid_and_has_analytics_list():
    raw = json.loads(BUNDLED.read_text(encoding="utf-8"))
    assert isinstance(raw, dict) and isinstance(raw["analytics"], list)


# ---------------------------------------------------------------------------
# Analytic.from_dict + _base_technique
# ---------------------------------------------------------------------------


def test_from_dict_uppercases_and_trims_technique_ids():
    a = Analytic.from_dict({"id": "x", "name": "X", "technique_ids": [" t1059.001 ", "T1190", ""]})
    assert a.technique_ids == ["T1059.001", "T1190"]     # trimmed, upper, blanks dropped


@pytest.mark.parametrize("raw,expected", [
    ("T1059.001", "T1059"), ("T1190", "T1190"),
    (" t1059.007 ", "T1059"), ("", ""),
])
def test_base_technique_reduces_to_parent(raw, expected):
    assert _base_technique(raw) == expected


# ---------------------------------------------------------------------------
# load_analytics — degradation
# ---------------------------------------------------------------------------


def test_load_analytics_missing_file_returns_empty(tmp_path):
    assert load_analytics(tmp_path / "nope.json") == []


def test_load_analytics_malformed_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_analytics(p) == []


def test_load_analytics_wrong_shape_returns_empty(tmp_path):
    p = tmp_path / "noanalytics.json"
    p.write_text(json.dumps({"stuff": 1}), encoding="utf-8")
    assert load_analytics(p) == []


def test_load_analytics_accepts_bare_list(tmp_path):
    p = tmp_path / "bare.json"
    p.write_text(json.dumps([{"id": "a", "name": "A", "technique_ids": ["T1"]}]), encoding="utf-8")
    out = load_analytics(p)
    assert [a.id for a in out] == ["a"]


def test_load_analytics_drops_duplicate_ids(tmp_path):
    p = _write_catalog(tmp_path / "dup.json", [
        {"id": "dup", "name": "first", "technique_ids": ["T1190"]},
        {"id": "dup", "name": "second", "technique_ids": ["T1059"]},
    ])
    out = load_analytics(p)
    assert len(out) == 1 and out[0].name == "first"      # first wins


def test_load_analytics_skips_entries_without_id(tmp_path):
    p = _write_catalog(tmp_path / "noid.json", [
        {"name": "no id", "technique_ids": ["T1190"]},
        {"id": "keep", "name": "keep", "technique_ids": ["T1059"]},
    ])
    assert [a.id for a in load_analytics(p)] == ["keep"]


# ---------------------------------------------------------------------------
# suggest_analytics
# ---------------------------------------------------------------------------


def test_suggest_matches_parent_and_subtechnique(tmp_path):
    """A hunt tagged with the parent T1059 matches an analytic tagged T1059.001."""
    p = _write_catalog(tmp_path / "c.json", [
        {"id": "sub", "name": "sub", "technique_ids": ["T1059.001"]},
    ])
    out = suggest_analytics(_hunt(["T1059"]), load_analytics(p))
    assert [a.id for a, _ in out] == ["sub"]


def test_suggest_ranks_by_shared_base_count_then_id(tmp_path):
    p = _write_catalog(tmp_path / "c.json", [
        {"id": "a-two", "name": "two", "technique_ids": ["T1190", "T1059"]},
        {"id": "b-one", "name": "one-b", "technique_ids": ["T1190"]},
        {"id": "c-one", "name": "one-c", "technique_ids": ["T1059.001"]},
        {"id": "z-none", "name": "none", "technique_ids": ["T9999"]},
    ])
    out = suggest_analytics(_hunt(["T1190", "T1059"]), load_analytics(p))
    # a-two shares 2 bases → first; b-one & c-one share 1 → id order; z-none excluded.
    assert [a.id for a, _ in out] == ["a-two", "b-one", "c-one"]


def test_suggest_matched_lists_only_overlapping_techniques(tmp_path):
    p = _write_catalog(tmp_path / "c.json", [
        {"id": "m", "name": "m", "technique_ids": ["T1059", "T1059.001", "T9999"]},
    ])
    out = suggest_analytics(_hunt(["T1059"]), load_analytics(p))
    _, matched = out[0]
    assert matched == ["T1059", "T1059.001"]             # sorted, T9999 excluded


def test_suggest_empty_when_hunt_has_no_techniques():
    assert suggest_analytics(_hunt([]), load_analytics()) == []


def test_suggest_empty_when_no_overlap(tmp_path):
    p = _write_catalog(tmp_path / "c.json", [
        {"id": "x", "name": "x", "technique_ids": ["T9999"]},
    ])
    assert suggest_analytics(_hunt(["T1190"]), load_analytics(p)) == []


# ---------------------------------------------------------------------------
# CLI wiring (through main; cache pinned to tmp so no real-DB side effects)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _pin_cache(tmp_path, monkeypatch):
    monkeypatch.setattr("ramen_cve.DEFAULT_CACHE_PATH", str(tmp_path / "cache.db"))


def test_parser_wires_analytic_subcommand():
    args = ramen_cve.build_parser().parse_args(["analytic", "suggest", "h1"])
    assert args.subcommand == "analytic"
    assert args.action == "suggest"
    assert args.ident == "h1"


def test_cli_analytic_list(_pin_cache, capsys):
    rc = ramen_cve.main(["analytic", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    # every bundled id should show up in the listing
    for a in load_analytics():
        assert f"[{a.id}]" in out


def test_cli_analytic_show(_pin_cache, capsys):
    first_id = load_analytics()[0].id
    rc = ramen_cve.main(["analytic", "show", first_id])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["id"] == first_id


def test_cli_analytic_show_unknown_id_returns_1(_pin_cache, caplog):
    assert ramen_cve.main(["analytic", "show", "does-not-exist"]) == 1


def test_cli_analytic_suggest_bundled_hunt(_pin_cache, capsys):
    """Suggest against the bundled log4shell hunt (uses bundled --hunt-dir)."""
    rc = ramen_cve.main(["analytic", "suggest", "log4shell-evidence"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "overlap hunt log4shell-evidence" in out


def test_cli_analytic_suggest_missing_hunt_returns_1(_pin_cache, tmp_path):
    rc = ramen_cve.main([
        "analytic", "suggest", "ghost", "--hunt-dir", str(tmp_path),
    ])
    assert rc == 1


def test_cli_analytic_suggest_hunt_without_techniques(_pin_cache, tmp_path, caplog):
    """A hunt with no attack_techniques → rc 0 and an explanatory INFO line."""
    ramen_cve.save_hunt(_hunt([], hid="empty"), tmp_path / "empty.json")
    with caplog.at_level("INFO"):
        rc = ramen_cve.main([
            "analytic", "suggest", "empty", "--hunt-dir", str(tmp_path),
        ])
    assert rc == 0
    assert any("no attack_techniques" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


def test_facade_reexports_analytic_surface():
    assert ramen_cve.load_analytics is load_analytics
    assert ramen_cve.suggest_analytics is suggest_analytics
    assert ramen_cve._base_technique is _base_technique
    assert ramen_cve.Analytic is Analytic
    assert ramen_cve.DEFAULT_ANALYTICS_PATH == BUNDLED
