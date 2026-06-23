"""scripts/validate_feeds.py — structural OPML validator.

Invariants under test:
  * The bundled examples/*.opml files pass clean (lock against regression
    in the bundled feed set).
  * Each enforcement rule fires on a constructed-bad input: non-HTTPS feed,
    missing `text`, missing `xmlUrl`, malformed XML, wrong root element,
    missing <body>, zero feeds, host-less URL.
  * Outlines without `type=rss`/`type=atom` are treated as grouping nodes
    and skipped (false-positive guard).
  * `main([target])` returns 0 on clean and 1 on any violation.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_feeds.py"


@pytest.fixture(scope="module")
def vf():
    """Load scripts/validate_feeds.py as an importable module for direct calls."""
    spec = importlib.util.spec_from_file_location("validate_feeds", SCRIPT_PATH)
    assert spec and spec.loader, "could not locate scripts/validate_feeds.py"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["validate_feeds"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Lock the bundled OPML files
# ---------------------------------------------------------------------------


def test_bundled_sample_opml_passes(vf):
    assert vf._violations_for(REPO_ROOT / "examples" / "sample.opml") == []


def test_bundled_community_feeds_opml_passes(vf):
    assert vf._violations_for(REPO_ROOT / "examples" / "community-feeds.opml") == []


def test_community_feed_bundle_has_at_least_eight_feeds(vf):
    """Cheap regression lock: a community bundle that drops to a handful of
    feeds without warning is almost certainly an accident. 8 is the floor."""
    import xml.etree.ElementTree as ET

    tree = ET.parse(REPO_ROOT / "examples" / "community-feeds.opml")
    feeds = [
        o for o in tree.getroot().iter("outline")
        if (o.get("type") or "").lower() in ("rss", "atom")
    ]
    assert len(feeds) >= 8


# ---------------------------------------------------------------------------
# Each enforcement rule on a constructed input
# ---------------------------------------------------------------------------


def _write_opml(path: Path, body: str, head: str = "<title>x</title>") -> None:
    path.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<opml version="2.0"><head>{head}</head><body>{body}</body></opml>\n',
        encoding="utf-8",
    )


def test_rejects_non_https_feed_url(vf, tmp_path):
    p = tmp_path / "bad.opml"
    _write_opml(p, '<outline type="rss" text="HTTP feed" xmlUrl="http://example.com/feed"/>')
    violations = vf._violations_for(p)
    assert any("HTTPS required" in v for v in violations)


def test_rejects_missing_text_attribute(vf, tmp_path):
    p = tmp_path / "no-text.opml"
    _write_opml(p, '<outline type="rss" xmlUrl="https://example.com/feed"/>')
    violations = vf._violations_for(p)
    assert any("missing required `text`" in v for v in violations)


def test_rejects_missing_xml_url(vf, tmp_path):
    p = tmp_path / "no-url.opml"
    _write_opml(p, '<outline type="rss" text="Empty"/>')
    violations = vf._violations_for(p)
    assert any("missing required `xmlUrl`" in v for v in violations)


def test_rejects_url_without_host(vf, tmp_path):
    p = tmp_path / "no-host.opml"
    _write_opml(p, '<outline type="rss" text="x" xmlUrl="https:///path"/>')
    violations = vf._violations_for(p)
    assert any("xmlUrl has no host" in v for v in violations)


def test_rejects_malformed_xml(vf, tmp_path):
    p = tmp_path / "malformed.opml"
    p.write_text('<?xml version="1.0"?><opml><body><outline></body></opml>', encoding="utf-8")
    assert any("not well-formed XML" in v for v in vf._violations_for(p))


def test_rejects_wrong_root_element(vf, tmp_path):
    p = tmp_path / "wrong-root.opml"
    p.write_text(
        '<?xml version="1.0"?><feeds><outline type="rss" text="x" '
        'xmlUrl="https://example.com/feed"/></feeds>',
        encoding="utf-8",
    )
    assert any("root element is" in v for v in vf._violations_for(p))


def test_rejects_missing_body_element(vf, tmp_path):
    p = tmp_path / "no-body.opml"
    p.write_text('<?xml version="1.0"?><opml version="2.0"><head/></opml>', encoding="utf-8")
    assert any("missing <body>" in v for v in vf._violations_for(p))


def test_rejects_file_with_zero_feeds(vf, tmp_path):
    """A body with only grouping outlines and no rss/atom feeds is suspect."""
    p = tmp_path / "no-feeds.opml"
    _write_opml(p, '<outline text="grouping only"><outline text="still no feeds"/></outline>')
    violations = vf._violations_for(p)
    assert any("no rss / atom feed outlines" in v for v in violations)


def test_grouping_outlines_without_type_are_skipped(vf, tmp_path):
    """A folder-style outline must not falsely demand `xmlUrl`."""
    p = tmp_path / "groups.opml"
    _write_opml(
        p,
        '<outline text="Group A">'
        '<outline type="rss" text="Feed" xmlUrl="https://example.com/feed"/>'
        '</outline>',
    )
    assert vf._violations_for(p) == []


def test_atom_feeds_are_accepted_alongside_rss(vf, tmp_path):
    p = tmp_path / "atom.opml"
    _write_opml(p, '<outline type="atom" text="Atom feed" xmlUrl="https://example.com/atom"/>')
    assert vf._violations_for(p) == []


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def test_main_returns_zero_on_clean(vf, capsys):
    assert vf.main([str(REPO_ROOT / "examples" / "sample.opml")]) == 0


def test_main_returns_one_on_violation(vf, tmp_path, capsys):
    p = tmp_path / "bad.opml"
    _write_opml(p, '<outline type="rss" text="x" xmlUrl="http://example.com/feed"/>')
    assert vf.main([str(p)]) == 1
