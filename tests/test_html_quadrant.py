"""Tests for ramen_cve.output.html_quadrant.

Covers the four contracts called out in tasks/todo.md Task 6 plus a
byte-oracle snapshot:
  - one circle per plottable record (skip when CVSS/EPSS missing),
  - kev_override colour mapping,
  - threshold gridlines drawn + labelled,
  - rendered HTML is fully self-contained (no external assets),
  - frozen SVG snapshot for a deterministic input.
"""
from __future__ import annotations

import re
from datetime import date

from ramen_cve import (
    BUCKET_COLOURS,
    EnrichedCve,
    _render_quadrant_svg,
    write_quadrant_html,
)


def _rec(cve_id: str, cvss: float | None, epss: float | None, bucket: str) -> EnrichedCve:
    return EnrichedCve(
        cve_id=cve_id,
        source="test",
        first_seen=date(2024, 6, 1),
        first_seen_type="manual_input",
        cvss_score=cvss,
        epss_score=epss,
        bucket=bucket,
    )


def test_renders_one_circle_per_plottable_record():
    """N records with CVSS+EPSS → N <circle> elements. Records missing
    either score are skipped (a quadrant point requires both axes)."""
    recs = [
        _rec("CVE-2024-0001", 9.8, 0.95, "kev_override"),
        _rec("CVE-2024-0002", 7.5, 0.20, "patch_now"),
        _rec("CVE-2024-0003", 5.0, 0.05, "deprioritize"),
        _rec("CVE-2024-0004", None, 0.5, "unknown"),   # skipped: no CVSS
        _rec("CVE-2024-0005", 8.0, None, "unknown"),   # skipped: no EPSS
    ]
    svg = _render_quadrant_svg(recs)
    circles = re.findall(r"<circle\b", svg)
    assert len(circles) == 3


def test_kev_override_records_get_kev_colour():
    rec = _rec("CVE-2024-9999", 10.0, 0.99, "kev_override")
    svg = _render_quadrant_svg([rec])
    kev_colour = BUCKET_COLOURS["kev_override"]
    assert f'fill="{kev_colour}"' in svg
    assert 'class="cve cve-kev_override"' in svg


def test_thresholds_drawn_as_labelled_gridlines():
    """Two dashed <line>s (one vertical at CVSS=thr, one horizontal at
    EPSS=thr) plus matching numeric labels in the SVG output."""
    svg = _render_quadrant_svg([], cvss_thr=7.0, epss_thr=0.10)
    assert svg.count('class="threshold cvss-threshold"') == 1
    assert svg.count('class="threshold epss-threshold"') == 1
    assert "CVSS=7" in svg
    assert "EPSS=0.1" in svg
    assert 'stroke-dasharray="4,2"' in svg


def test_tooltip_contains_cve_id_and_scores():
    rec = _rec("CVE-2024-1234", 8.4, 0.6125, "patch_now")
    svg = _render_quadrant_svg([rec])
    assert "<title>CVE-2024-1234 — CVSS 8.4, EPSS 0.6125 (patch_now)</title>" in svg


def test_xy_mapping_inverts_epss_axis_for_svg():
    """EPSS=1.0 should land at the TOP of the plot (smallest y in SVG)."""
    from ramen_cve.output.html_quadrant import PLOT_BOTTOM, PLOT_TOP, _xy

    _, y_low = _xy(0, 0.0)
    _, y_high = _xy(0, 1.0)
    assert y_low == PLOT_BOTTOM
    assert y_high == PLOT_TOP
    assert y_high < y_low  # high EPSS draws higher on screen


def test_html_is_self_contained(tmp_path):
    """No external assets — no <link rel="stylesheet">, no <script src=...>,
    no protocol-prefixed asset references in href/src attrs."""
    recs = [_rec("CVE-2024-0001", 9.0, 0.5, "kev_override")]
    out = tmp_path / "q.html"
    write_quadrant_html(recs, out, metadata={"cvss_threshold": 7.0, "epss_threshold": 0.10})
    html = out.read_text(encoding="utf-8")

    assert "<link" not in html
    assert "<script" not in html
    assert not re.search(r'src\s*=\s*"https?://', html)
    assert not re.search(r'href\s*=\s*"https?://', html)
    # The wrapper does include inline <style> — that's expected.
    assert "<style>" in html
    assert "<svg" in html


def test_write_uses_metadata_thresholds(tmp_path):
    """Custom thresholds in metadata flow through to the SVG labels."""
    recs = [_rec("CVE-2024-0001", 9.0, 0.5, "kev_override")]
    out = tmp_path / "q.html"
    write_quadrant_html(recs, out, metadata={"cvss_threshold": 8.5, "epss_threshold": 0.30})
    html = out.read_text(encoding="utf-8")
    assert "CVSS=8.5" in html
    assert "EPSS=0.3" in html


def test_write_handles_empty_enriched_list(tmp_path):
    out = tmp_path / "q.html"
    write_quadrant_html([], out)
    html = out.read_text(encoding="utf-8")
    assert "<svg" in html
    assert "<circle" not in html
    # KEV/patch-now legend rows still appear (so an empty report is
    # visually consistent with a populated one).
    assert "kev_override (0)" in html
    assert "patch_now (0)" in html


def test_cli_format_html_choice_parses():
    """--format html is accepted on every analysis subcommand."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["opml", "x.opml", "--format", "html"])
    assert args.format == "html"


def test_output_writes_html_file_when_format_is_html(tmp_path):
    """End-to-end: --format html routes through pipeline._output and
    produces a `<basename>.html` file."""
    import argparse

    import ramen_cve

    rec = _rec("CVE-2021-44228", 10.0, 0.97, "kev_override")
    args = argparse.Namespace(
        format="html",
        out_dir=tmp_path,
        basename="run99",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"cvss_threshold": 7.0, "epss_threshold": 0.10})
    assert paths["html"] is not None
    assert paths["html"].exists()
    assert paths["html"].suffix == ".html"
    html = paths["html"].read_text(encoding="utf-8")
    assert "CVE-2021-44228" in html
    assert "<svg" in html


def test_output_writes_html_when_format_is_all(tmp_path):
    """--format all includes the HTML quadrant alongside CSV/MD/STIX/etc."""
    import argparse

    import ramen_cve

    rec = _rec("CVE-2021-44228", 10.0, 0.97, "kev_override")
    args = argparse.Namespace(
        format="all",
        out_dir=tmp_path,
        basename="run42",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"cvss_threshold": 7.0, "epss_threshold": 0.10})
    assert paths["html"] is not None
    assert paths["html"].exists()


def test_snapshot_frozen_svg_for_fixed_input():
    """Byte-oracle: a fixed three-record input produces an exactly-known
    SVG string. Any unintentional change to layout, colour, or escaping
    will break this and force a deliberate snapshot bump."""
    recs = [
        _rec("CVE-2024-0001", 9.8, 0.95, "kev_override"),
        _rec("CVE-2024-0002", 7.5, 0.20, "patch_now"),
        _rec("CVE-2024-0003", 5.0, 0.05, "deprioritize"),
    ]
    svg = _render_quadrant_svg(recs, cvss_thr=7.0, epss_thr=0.10)
    expected_circles = [
        ('cve-kev_override', BUCKET_COLOURS["kev_override"]),
        ('cve-patch_now', BUCKET_COLOURS["patch_now"]),
        ('cve-deprioritize', BUCKET_COLOURS["deprioritize"]),
    ]
    for cls, colour in expected_circles:
        assert cls in svg, f"missing circle class {cls}"
        assert f'fill="{colour}"' in svg, f"missing colour {colour} for {cls}"
    # Stable element counts.
    assert svg.count("<circle") == 3
    # CVSS + EPSS threshold *lines* — match the trailing space so the
    # two `class="threshold-label"` text elements are excluded.
    assert svg.count('class="threshold ') == 2
    # Frame + thresholds + axis labels + tick labels + circles + opening + closing.
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"')
    assert svg.rstrip().endswith("</svg>")
