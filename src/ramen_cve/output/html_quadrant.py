"""ramen_cve.output.html_quadrant — self-contained HTML report with an
inline-SVG CVSS×EPSS quadrant scatter (Layer-3 serialization).

No external assets, no JS frameworks: a single `<svg>` block wrapped in
a minimal HTML5 doc with inline `<style>`. Tooltips via SVG `<title>`.

See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

from pathlib import Path

from ..constants import DEFAULT_CVSS_THRESHOLD, DEFAULT_EPSS_THRESHOLD
from ..models import EnrichedCve

# Colour-blind-safe viridis-style steps, ordered by triage urgency
# (darkest = most urgent). Grey reserved for "unknown" (no data).
BUCKET_COLOURS: dict[str, str] = {
    "kev_override":   "#440154",
    "patch_now":      "#3b528b",
    "watch_closely":  "#21918c",
    "plan_and_patch": "#5ec962",
    "deprioritize":   "#fde725",
    "unknown":        "#9e9e9e",
}

# Display order mirrors output/markdown.py:BUCKET_ORDER so the legend
# and the report tell the same story.
BUCKET_ORDER: tuple[str, ...] = (
    "kev_override",
    "patch_now",
    "watch_closely",
    "plan_and_patch",
    "deprioritize",
    "unknown",
)

# SVG layout (pixel coords).
SVG_WIDTH = 720
SVG_HEIGHT = 540
PLOT_LEFT = 70
PLOT_RIGHT = 660
PLOT_TOP = 40
PLOT_BOTTOM = 480
POINT_RADIUS = 6


def _xy(cvss: float, epss: float) -> tuple[float, float]:
    """Map (CVSS in [0,10], EPSS in [0,1]) to SVG pixel coords.

    SVG y-axis points down, so high EPSS values map to small y.
    """
    x = PLOT_LEFT + (cvss / 10.0) * (PLOT_RIGHT - PLOT_LEFT)
    y = PLOT_BOTTOM - epss * (PLOT_BOTTOM - PLOT_TOP)
    return (x, y)


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _render_quadrant_svg_from_points(
    points: list[tuple[float, float, str, str, bool]],
    cvss_thr: float = DEFAULT_CVSS_THRESHOLD,
    epss_thr: float = DEFAULT_EPSS_THRESHOLD,
) -> str:
    """Return an inline-SVG CVSS×EPSS quadrant scatter from raw points.

    `points` is `[(cvss, epss, tooltip, bucket_id, is_latest), ...]`. The
    caller is responsible for filtering out None coordinates. `is_latest`
    enlarges the point and thickens its stroke — used by Task 8 Slice D's
    per-CVE trajectory page to mark the most-recent snapshot. Stable
    iteration order preserves byte-snapshottable output (no sort here).
    """
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
        f'role="img" aria-label="CVSS by EPSS quadrant chart">'
    )
    # Plot frame.
    parts.append(
        f'<rect class="plot-frame" x="{PLOT_LEFT}" y="{PLOT_TOP}" '
        f'width="{PLOT_RIGHT - PLOT_LEFT}" height="{PLOT_BOTTOM - PLOT_TOP}" '
        f'fill="none" stroke="#cccccc" stroke-width="1"/>'
    )
    # Threshold gridlines (dashed) + labels.
    thr_x, _ = _xy(cvss_thr, 0)
    _, thr_y = _xy(0, epss_thr)
    parts.append(
        f'<line class="threshold cvss-threshold" x1="{thr_x:.1f}" y1="{PLOT_TOP}" '
        f'x2="{thr_x:.1f}" y2="{PLOT_BOTTOM}" '
        f'stroke="#cccccc" stroke-dasharray="4,2" stroke-width="1"/>'
    )
    parts.append(
        f'<line class="threshold epss-threshold" x1="{PLOT_LEFT}" y1="{thr_y:.1f}" '
        f'x2="{PLOT_RIGHT}" y2="{thr_y:.1f}" '
        f'stroke="#cccccc" stroke-dasharray="4,2" stroke-width="1"/>'
    )
    parts.append(
        f'<text class="threshold-label" x="{thr_x:.1f}" y="{PLOT_TOP - 6}" '
        f'text-anchor="middle" font-size="10" fill="#666666">'
        f'CVSS={cvss_thr:g}</text>'
    )
    parts.append(
        f'<text class="threshold-label" x="{PLOT_RIGHT + 4}" y="{thr_y:.1f}" '
        f'text-anchor="start" font-size="10" fill="#666666" dy="0.35em">'
        f'EPSS={epss_thr:g}</text>'
    )
    # Axis labels.
    parts.append(
        f'<text class="axis-label x-axis" x="{(PLOT_LEFT + PLOT_RIGHT) / 2:.1f}" '
        f'y="{PLOT_BOTTOM + 30}" text-anchor="middle" font-size="12" '
        f'fill="#333333">CVSS</text>'
    )
    y_label_cx = PLOT_LEFT - 40
    y_label_cy = (PLOT_TOP + PLOT_BOTTOM) / 2
    parts.append(
        f'<text class="axis-label y-axis" x="{y_label_cx:.1f}" y="{y_label_cy:.1f}" '
        f'text-anchor="middle" font-size="12" fill="#333333" '
        f'transform="rotate(-90 {y_label_cx:.1f} {y_label_cy:.1f})">EPSS</text>'
    )
    # CVSS x-axis ticks.
    for v in (0, 2, 4, 6, 8, 10):
        tx, _ = _xy(v, 0)
        parts.append(
            f'<text class="tick x-tick" x="{tx:.1f}" y="{PLOT_BOTTOM + 14}" '
            f'text-anchor="middle" font-size="9" fill="#666666">{v}</text>'
        )
    # EPSS y-axis ticks.
    for v in (0.0, 0.25, 0.5, 0.75, 1.0):
        _, ty = _xy(0, v)
        parts.append(
            f'<text class="tick y-tick" x="{PLOT_LEFT - 6}" y="{ty:.1f}" '
            f'text-anchor="end" font-size="9" fill="#666666" dy="0.35em">{v:g}</text>'
        )
    # Data points. Stable order = input order, so snapshot tests are
    # reproducible. `is_latest` thickens the stroke + enlarges the point
    # so the most-recent snapshot in a trajectory pops without changing
    # any pre-existing snapshots (all wrapper callers pass is_latest=False).
    for cvss, epss, tooltip, bucket_id, is_latest in points:
        cx, cy = _xy(cvss, epss)
        colour = BUCKET_COLOURS.get(bucket_id, BUCKET_COLOURS["unknown"])
        radius = POINT_RADIUS + 2 if is_latest else POINT_RADIUS
        stroke_width = "2" if is_latest else "0.5"
        latest_cls = " cve-latest" if is_latest else ""
        parts.append(
            f'<circle class="cve cve-{bucket_id}{latest_cls}" '
            f'cx="{cx:.1f}" cy="{cy:.1f}" r="{radius}" '
            f'fill="{colour}" fill-opacity="0.75" '
            f'stroke="#333333" stroke-width="{stroke_width}">'
            f'<title>{_xml_escape(tooltip)}</title>'
            f'</circle>'
        )
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def _render_quadrant_svg(
    enriched: list[EnrichedCve],
    cvss_thr: float = DEFAULT_CVSS_THRESHOLD,
    epss_thr: float = DEFAULT_EPSS_THRESHOLD,
) -> str:
    """Return an inline-SVG CVSS×EPSS quadrant scatter as a markup string.

    Pure function; easy to unit-test and snapshot. Records with a missing
    CVSS or EPSS score are skipped (no point can be plotted for them).
    """
    points: list[tuple[float, float, str, str, bool]] = []
    for rec in enriched:
        if rec.cvss_score is None or rec.epss_score is None:
            continue
        bucket = rec.bucket or "unknown"
        tooltip = (
            f"{rec.cve_id} — CVSS {rec.cvss_score:.1f}, "
            f"EPSS {rec.epss_score:.4f} ({bucket})"
        )
        points.append((rec.cvss_score, rec.epss_score, tooltip, bucket, False))
    return _render_quadrant_svg_from_points(points, cvss_thr, epss_thr)


def write_quadrant_html(
    enriched: list[EnrichedCve],
    path: Path,
    metadata: dict | None = None,
) -> None:
    """Write a self-contained HTML5 doc wrapping the quadrant SVG.

    `metadata` is the run-metadata dict produced by the pipeline; the
    `cvss_threshold` / `epss_threshold` keys (if present) drive the
    threshold gridlines. No external assets, no JS — opens cleanly in
    any modern browser and prints to a single page.
    """
    metadata = metadata or {}
    cvss_thr = float(metadata.get("cvss_threshold", DEFAULT_CVSS_THRESHOLD))
    epss_thr = float(metadata.get("epss_threshold", DEFAULT_EPSS_THRESHOLD))
    svg = _render_quadrant_svg(enriched, cvss_thr, epss_thr)

    # Per-bucket counts for the legend.
    legend_rows = []
    for bid in BUCKET_ORDER:
        count = sum(1 for r in enriched if (r.bucket or "unknown") == bid)
        if count == 0 and bid not in {"kev_override", "patch_now"}:
            continue
        legend_rows.append(
            f'<li><span class="swatch" style="background:{BUCKET_COLOURS[bid]}">'
            f'</span>{bid} ({count})</li>'
        )
    legend_html = "\n        ".join(legend_rows)

    plotted = sum(
        1 for r in enriched
        if r.cvss_score is not None and r.epss_score is not None
    )
    skipped = len(enriched) - plotted
    skipped_note = (
        f" ({skipped} record(s) had no CVSS/EPSS score and were not plotted)"
        if skipped
        else ""
    )

    html = (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="utf-8">\n'
        '<title>ramen-cve quadrant report</title>\n'
        '<style>\n'
        'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", '
        'Helvetica, Arial, sans-serif; margin: 24px; color: #222; }\n'
        'h1 { font-size: 18px; margin: 0 0 8px; }\n'
        '.meta { color: #666; font-size: 12px; margin: 0 0 16px; }\n'
        '.chart { max-width: 720px; }\n'
        '.legend { list-style: none; padding: 0; margin: 12px 0 0; '
        'font-size: 12px; }\n'
        '.legend li { display: inline-block; margin-right: 16px; '
        'margin-bottom: 4px; }\n'
        '.swatch { display: inline-block; width: 12px; height: 12px; '
        'margin-right: 4px; vertical-align: middle; border: 1px solid #333; }\n'
        'svg circle { cursor: default; }\n'
        'svg circle:hover { stroke-width: 2; }\n'
        '@media print { body { margin: 0; } }\n'
        '</style>\n'
        '</head>\n'
        '<body>\n'
        '<h1>ramen-cve quadrant report</h1>\n'
        '<p class="meta">CVSS (severity) × EPSS (30-day exploitation probability). '
        f'Points coloured by triage bucket; hover for CVE id.{skipped_note}</p>\n'
        '<div class="chart">\n'
        f'{svg}'
        '</div>\n'
        '<ul class="legend">\n'
        f'        {legend_html}\n'
        '</ul>\n'
        '</body>\n'
        '</html>\n'
    )
    path.write_text(html, encoding="utf-8")
