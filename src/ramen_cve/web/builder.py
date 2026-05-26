"""ramen_cve.web.builder — static-HTML Web UI generator (Task 8, L4).

Slice A: emits a minimal `<site-dir>/index.html` (H1 + "N runs recorded.")
and an empty `<site-dir>/static/style.css`. Raises `WebUiError` when the
`runs` table is empty (design-doc §D11).

Slice C: adds `_discover_runs` (LEFT JOIN against `run_artefacts`),
per-run summary pages at `<site-dir>/runs/<slug>.html`, and a run-history
strip on the index. The slug is `ts_iso` with colons replaced by hyphens.

Slice D (this update): per-CVE detail pages at `<site-dir>/cve/<CVE-ID>.html`
with §§1-3 of design-doc §5.3 — header (CVE id + most-recent bucket +
linked NVD URL), summary (description + CVSS + EPSS + KEV), and a
trajectory chart that reuses Task-6's `_render_quadrant_svg_from_points`
in single-CVE multi-snapshot mode (sparkline fallback below 2 snapshots,
200-snapshot cap with "+N earlier" footer).

Slices E-G extend per `docs/web_ui_design.md`:
  - E: per-CVE detail page §§4-7 (exploit-status, actors, IOCs, hosts)
  - F: "what changed" diff block on per-run pages
  - G: bucket-policy threading + showcase regen extension
"""
from __future__ import annotations

import html
import logging
import os.path
from pathlib import Path
from typing import NamedTuple

from ..bucket_policy import DEFAULT_BUCKET_POLICY, BucketPolicy
from ..cache import Cache
from ..constants import DEFAULT_CVSS_THRESHOLD, DEFAULT_EPSS_THRESHOLD
from ..models import WebUiError
from ..output.html_quadrant import _render_quadrant_svg_from_points
from ..render import _sparkline

_log = logging.getLogger(__name__)

WEB_DEFAULT_MAX_RUNS_ON_HOME = 30
WEB_TRAJECTORY_CAP = 200
_NVD_URL_TEMPLATE = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# The 6 artefact kinds we link to from per-run pages + the index strip.
# Order is the display order (CSV first, YARA last — mirrors --format
# argparse choices). Each entry: (key, display_label, filename_template).
# `{stamp}` interpolates the microsecond disk stamp from run_artefacts.
_ARTEFACT_KINDS: tuple[tuple[str, str, str], ...] = (
    ("csv", "CSV", "ramen-cve-{stamp}.csv"),
    ("md", "MD", "ramen-cve-{stamp}.md"),
    ("stix", "STIX", "ramen-cve-{stamp}.stix.json"),
    ("html", "HTML", "ramen-cve-{stamp}.html"),
    ("sigma", "Sigma", "ramen-cve-{stamp}-sigma"),
    ("yara", "YARA", "ramen-cve-{stamp}-yara"),
)

# Slice A's CSS is a placeholder — real styling lands in Slice G alongside
# the showcase regen. The file is shipped (linked from every page) so the
# link-from-every-page contract is locked from day one.
_CSS_PLACEHOLDER = "/* ramen-cve web ui — styling populated in Slice G. */\n"


class _DiscoveredRun(NamedTuple):
    """One row from the `runs LEFT JOIN run_artefacts` discovery query.

    `disk_stamp` and `out_dir` are None for runs that exist in `runs`
    but have no matching `run_artefacts` row (cache wiped, files
    archived, or pre-Slice-B history). The Web UI renders those as "—".
    """

    ts_iso: str
    cve_count: int
    disk_stamp: str | None
    out_dir: str | None


def _slugify_ts(ts_iso: str) -> str:
    """Filesystem-safe + lexicographically-sortable filename slug.

    `ts_iso` is a naive ISO-second-precision stamp ("2026-05-26T14:03:11")
    OR the same with a `+00:00` suffix from legacy / direct-insert paths.
    Replacing `:` with `-` keeps the format reversible (positionally) and
    cross-OS-safe.
    """
    return ts_iso.replace(":", "-")


def _discover_runs(cache: Cache) -> list[_DiscoveredRun]:
    """Enumerate every run in the cache, newest first, with artefact data.

    `runs.ts_iso` is the canonical run list (never purged). The LEFT JOIN
    onto `run_artefacts` attaches the microsecond `disk_stamp` + `out_dir`
    when present, NULL otherwise. The CVE count comes from a GROUP BY
    against distinct cve_ids per ts_iso (one row in `runs` per CVE).
    """
    rows = cache._conn.execute(
        "SELECT runs.ts_iso, COUNT(DISTINCT runs.cve_id), "
        "run_artefacts.disk_stamp, run_artefacts.out_dir "
        "FROM runs LEFT JOIN run_artefacts USING (ts_iso) "
        "GROUP BY runs.ts_iso "
        "ORDER BY runs.ts_iso DESC"
    ).fetchall()
    return [_DiscoveredRun(*r) for r in rows]


def _artefact_paths(disk_stamp: str, out_dir: str) -> dict[str, Path]:
    """Compose the 6 absolute artefact paths for a run with artefacts data."""
    base = Path(out_dir)
    return {
        key: base / template.format(stamp=disk_stamp)
        for key, _label, template in _ARTEFACT_KINDS
    }


def _rel_href(target: Path, page_dir: Path) -> str | None:
    """Compute a relative href from `page_dir` to `target`.

    Returns None on Windows cross-drive paths (`os.path.relpath` raises
    `ValueError`); callers render "—" in that case rather than emitting
    an unreachable link.
    """
    try:
        return os.path.relpath(target, page_dir)
    except ValueError:
        return None


def _artefact_link_cell(
    run: _DiscoveredRun,
    kind: str,
    page_dir: Path,
) -> str:
    """Return the HTML cell content for one artefact column on one row.

    Renders "—" when:
    - the run has no `run_artefacts` row (LEFT JOIN miss), OR
    - the artefact's filename doesn't exist on disk (best-effort link), OR
    - the relative href can't be computed (Windows cross-drive).

    Otherwise returns an `<a href="…">filename</a>` with both attribute
    and text passed through `html.escape(..., quote=True)`.
    """
    if run.disk_stamp is None or run.out_dir is None:
        return "—"
    paths = _artefact_paths(run.disk_stamp, run.out_dir)
    target = paths[kind]
    if not target.exists():
        return "—"
    href = _rel_href(target, page_dir)
    if href is None:
        return "—"
    return (
        f'<a href="{html.escape(href, quote=True)}">'
        f"{html.escape(target.name, quote=True)}</a>"
    )


def _render_index(run_count: int, version: str, strip_html: str = "") -> str:
    """Render the `index.html` body.

    Strict-minimum layout (design-doc D14 + D20):
    - HTML5 doctype + `<html lang="en">`
    - UTF-8 charset declaration
    - `<meta name="generator" content="ramen-cve <version>">` for traceability
    - linked `static/style.css`
    - `<h1>Ramen CVE Triage</h1>`
    - `<p>N run(s) recorded.</p>` (English-correct singular/plural)
    - Slice C: the run-history strip rendered by `_render_strip` (empty
      string when called from a pre-Slice-C caller; the strip is the
      only Slice C addition to this page).

    Every interpolated string passes through `html.escape(..., quote=True)`
    (design-doc D10) so a poisoned VERSION constant can't smuggle markup
    onto the page. Slice A's surface is small enough that this is more
    of an invariant lock than a real defence — the real value lands in
    Slices D-E when NVD descriptions / actor names get rendered.
    """
    plural = "" if run_count == 1 else "s"
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta name="generator" content="ramen-cve {html.escape(version, quote=True)}">\n'
        "<title>Ramen CVE Triage</title>\n"
        '<link rel="stylesheet" href="static/style.css">\n'
        "</head>\n"
        "<body>\n"
        "<h1>Ramen CVE Triage</h1>\n"
        f"<p>{run_count} run{plural} recorded.</p>\n"
        f"{strip_html}"
        "</body>\n"
        "</html>\n"
    )


def _render_strip(
    runs: list[_DiscoveredRun],
    site_dir: Path,
    cap: int,
) -> str:
    """Render the run-history strip embedded on `index.html`.

    Reverse-chronological table, capped at `cap` rows. Columns:
    Run (linked to `runs/<slug>.html`), CVEs, then one column per
    artefact kind. Rows beyond `cap` are reachable by direct URL only —
    documented in design-doc §5.1.
    """
    if not runs:
        return ""
    capped = runs[:cap]
    header_cols = "".join(f"<th>{label}</th>" for _key, label, _t in _ARTEFACT_KINDS)
    header = f"<tr><th>Run</th><th>CVEs</th>{header_cols}</tr>"
    body_rows: list[str] = []
    for run in capped:
        slug = _slugify_ts(run.ts_iso)
        ts_escaped = html.escape(run.ts_iso, quote=True)
        run_link = (
            f'<a href="runs/{html.escape(slug, quote=True)}.html">{ts_escaped}</a>'
        )
        cells = "".join(
            f"<td>{_artefact_link_cell(run, key, site_dir)}</td>"
            for key, _label, _t in _ARTEFACT_KINDS
        )
        body_rows.append(
            f"<tr><td>{run_link}</td><td>{run.cve_count}</td>{cells}</tr>"
        )
    return (
        "<h2>Run history</h2>\n"
        "<table>\n"
        f"{header}\n"
        + "\n".join(body_rows)
        + "\n</table>\n"
    )


def _render_run_page(
    run: _DiscoveredRun,
    version: str,
    runs_dir: Path,
) -> str:
    """Render one `runs/<slug>.html` per-run summary page.

    Slice C scope (locked): header (ts_iso + CVE count) plus a 6-row
    table of artefact-file links — each row renders "—" when the file
    is absent. The page is standalone (no run-history strip back-link).
    Slice F adds the diff block; Slice G threads bucket-policy labels.
    """
    ts_escaped = html.escape(run.ts_iso, quote=True)
    plural = "" if run.cve_count == 1 else "s"
    artefact_rows = "\n".join(
        f"<tr><th>{html.escape(label, quote=True)}</th>"
        f"<td>{_artefact_link_cell(run, key, runs_dir)}</td></tr>"
        for key, label, _t in _ARTEFACT_KINDS
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta name="generator" content="ramen-cve {html.escape(version, quote=True)}">\n'
        f"<title>Run {ts_escaped} — Ramen CVE Triage</title>\n"
        '<link rel="stylesheet" href="../static/style.css">\n'
        "</head>\n"
        "<body>\n"
        f"<h1>Run {ts_escaped}</h1>\n"
        f"<p>{run.cve_count} CVE{plural} in this run.</p>\n"
        "<h2>Artefacts</h2>\n"
        "<table>\n"
        f"{artefact_rows}\n"
        "</table>\n"
        "</body>\n"
        "</html>\n"
    )


def _fmt_or_dash(value, fmt: str = "{}") -> str:
    """HTML-escaped value via `fmt`, or "—" when value is None / empty.

    Used by the per-CVE summary to keep "best-effort" rendering uniform:
    a missing field never errors, just shows the em-dash placeholder.
    """
    if value is None or value == "":
        return "—"
    return html.escape(fmt.format(value), quote=True)


def _render_cve_summary(
    nvd: dict | None,
    epss: dict | None,
    kev_row: dict | None,
) -> str:
    """Render the §5.3 §2 summary block — description + CVSS + EPSS + KEV.

    Every field renders independently: a missing `nvd_cache` row drops
    description / CVSS / vector to "—" without affecting EPSS / KEV.
    `kev_row` is the per-CVE record from `get_kev_catalog_raw()` (or
    None when this CVE isn't on the KEV catalog).
    """
    nvd = nvd or {}
    epss = epss or {}

    description = _fmt_or_dash(nvd.get("description"))
    cvss_score = _fmt_or_dash(nvd.get("cvss_score"), "{:.1f}")
    cvss_severity = _fmt_or_dash(nvd.get("cvss_severity"))
    cvss_vector = _fmt_or_dash(nvd.get("cvss_vector"))
    epss_score = _fmt_or_dash(epss.get("epss"), "{:.4f}")
    epss_percentile_raw = epss.get("percentile")
    if epss_percentile_raw is None:
        epss_percentile = "—"
    else:
        epss_percentile = html.escape(f"{float(epss_percentile_raw) * 100:.1f}%")
    kev_listed = "Yes" if kev_row else "No"
    kev_due = _fmt_or_dash((kev_row or {}).get("dueDate"))

    return (
        "<h2>Summary</h2>\n"
        "<dl class=\"cve-summary\">\n"
        f"<dt>Description</dt><dd>{description}</dd>\n"
        f"<dt>CVSS score</dt><dd>{cvss_score} ({cvss_severity})</dd>\n"
        f"<dt>CVSS vector</dt><dd>{cvss_vector}</dd>\n"
        f"<dt>EPSS score</dt><dd>{epss_score}</dd>\n"
        f"<dt>EPSS percentile</dt><dd>{epss_percentile}</dd>\n"
        f"<dt>KEV listed</dt><dd>{kev_listed}</dd>\n"
        f"<dt>KEV due date</dt><dd>{kev_due}</dd>\n"
        "</dl>\n"
    )


def _render_cve_trajectory(runs_history: list[dict]) -> str:
    """Render the §5.3 §3 trajectory chart for a CVE's `runs` rows.

    Branches per design-doc §5.3 §3:
    - 0 plottable snapshots → "(no trajectory data available)".
    - 1 plottable snapshot → unicode sparkline (EPSS over time, 1 bar).
    - 2-200 plottable snapshots → SVG scatter with the most-recent
      snapshot highlighted (is_latest=True on the final point).
    - 200+ plottable snapshots → cap at the 200 most-recent + "+N earlier
      snapshots not shown" footer.

    `runs_history` is `Cache.get_runs(cve_id)` output — list[dict] with
    `ts_iso`, `bucket`, `cvss_score`, `epss_score`, sorted chronologically.
    """
    plottable = [
        r for r in runs_history
        if r.get("cvss_score") is not None and r.get("epss_score") is not None
    ]
    n_total = len(plottable)
    if n_total == 0:
        return "<h2>Trajectory</h2>\n<p>(no trajectory data available)</p>\n"

    if n_total == 1:
        # Design §5.3 §3: "Below 2 snapshots → fall back to a Task-1-style
        # ASCII sparkline from render.py".
        spark = _sparkline([float(plottable[0]["epss_score"])])
        return (
            "<h2>Trajectory</h2>\n"
            f"<p>Single snapshot. EPSS sparkline: {html.escape(spark)}</p>\n"
        )

    # 2+ snapshots: SVG scatter. Cap at the 200 most recent.
    truncated = n_total > WEB_TRAJECTORY_CAP
    capped = plottable[-WEB_TRAJECTORY_CAP:] if truncated else plottable
    last_idx = len(capped) - 1
    points: list[tuple[float, float, str, str, bool]] = []
    for i, r in enumerate(capped):
        bucket = r.get("bucket") or "unknown"
        tooltip = (
            f"{r['ts_iso']} — CVSS {r['cvss_score']:.1f}, "
            f"EPSS {r['epss_score']:.4f} ({bucket})"
        )
        points.append(
            (float(r["cvss_score"]), float(r["epss_score"]),
             tooltip, bucket, i == last_idx)
        )
    svg = _render_quadrant_svg_from_points(
        points, DEFAULT_CVSS_THRESHOLD, DEFAULT_EPSS_THRESHOLD,
    )
    footer = (
        f"<p class=\"trajectory-footer\">+{n_total - WEB_TRAJECTORY_CAP} earlier "
        "snapshots not shown</p>\n"
        if truncated
        else ""
    )
    return f"<h2>Trajectory</h2>\n{svg}{footer}"


def _render_cve_page(
    cve_id: str,
    cache: Cache,
    version: str,
    policy: BucketPolicy,
) -> str:
    """Render one `cve/<CVE-ID>.html` per-CVE detail page (§§1-3).

    §1 Header: H1 with the CVE id + most-recent bucket label + linked
    NVD URL. The most-recent bucket comes from the final `runs` row
    (chronologically). Unknown buckets fall back to the raw id.

    §2 Summary: delegated to `_render_cve_summary`.

    §3 Trajectory: delegated to `_render_cve_trajectory`.

    Slice E adds §§4-7 (exploit status, actors, IOCs, hosts) onto the
    same page below the trajectory chart.
    """
    runs_history = cache.get_runs(cve_id)
    latest_bucket = (
        runs_history[-1].get("bucket") or "unknown" if runs_history else "unknown"
    )
    try:
        bucket_label = policy.label(latest_bucket)
    except KeyError:
        bucket_label = latest_bucket

    nvd = cache.get_nvd_raw(cve_id)
    epss = cache.get_epss_raw(cve_id)
    kev_catalog = cache.get_kev_catalog_raw() or {}
    kev_row = kev_catalog.get(cve_id)

    cve_escaped = html.escape(cve_id, quote=True)
    bucket_label_escaped = html.escape(bucket_label, quote=True)
    nvd_url = _NVD_URL_TEMPLATE.format(cve_id=cve_id)
    nvd_url_escaped = html.escape(nvd_url, quote=True)

    summary = _render_cve_summary(nvd, epss, kev_row)
    trajectory = _render_cve_trajectory(runs_history)

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta name="generator" content="ramen-cve {html.escape(version, quote=True)}">\n'
        f"<title>{cve_escaped} — Ramen CVE Triage</title>\n"
        '<link rel="stylesheet" href="../static/style.css">\n'
        "</head>\n"
        "<body>\n"
        f'<h1>{cve_escaped} <span class="bucket">[{bucket_label_escaped}]</span></h1>\n'
        f'<p><a href="{nvd_url_escaped}">{nvd_url_escaped}</a></p>\n'
        f"{summary}"
        f"{trajectory}"
        "</body>\n"
        "</html>\n"
    )


def _list_distinct_cve_ids(cache: Cache) -> list[str]:
    """Distinct CVE ids across the entire `runs` history, sorted ASC.

    Sorted alphabetically so the per-CVE page write order (and hence
    any second-build byte comparison) is deterministic.
    """
    rows = cache._conn.execute(
        "SELECT DISTINCT cve_id FROM runs ORDER BY cve_id ASC"
    ).fetchall()
    return [r[0] for r in rows]


def build_site(
    cache: Cache,
    site_dir: Path,
    *,
    policy: BucketPolicy | None = None,
    max_runs_on_home: int = WEB_DEFAULT_MAX_RUNS_ON_HOME,
) -> dict[str, Path]:
    """Render the static site rooted at `site_dir`.

    Returns a dict of {kind: Path} for every file written, matching
    `pipeline._output`'s shape so callers can `print(...)` each path
    or attach the bundle to a downstream dispatch.

    Raises `WebUiError` if the cache's `runs` table is empty — there's
    nothing to render and shipping a "no runs yet" landing page would
    obscure the misconfiguration that led here.

    `max_runs_on_home` caps the strip at the most-recent N runs (older
    runs reachable by direct `runs/<slug>.html` URL). `policy` is
    reserved for Slice G — label propagation to per-run + per-CVE pages.
    """
    # Lazy import — `cli.VERSION` is L4, importing it at module load
    # creates a cli ↔ web cycle (cli imports from web; web would import
    # from cli). The deferred-lookup pattern documented in
    # docs/REFACTOR_PLAN.md §5.2 resolves the cycle at call time.
    from ..cli import VERSION

    # Slice G will thread a user-supplied policy through every label;
    # until then, Slice D uses DEFAULT_BUCKET_POLICY for per-CVE header
    # labels so the page renders with the correct prose today.
    active_policy = policy or DEFAULT_BUCKET_POLICY

    runs = _discover_runs(cache)
    if not runs:
        raise WebUiError(
            "No runs recorded in cache — nothing to render. "
            "Run `ramen-cve opml/url/cve ...` first to populate the runs table."
        )

    site_dir.mkdir(parents=True, exist_ok=True)
    static_dir = site_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = site_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    cve_dir = site_dir / "cve"
    cve_dir.mkdir(parents=True, exist_ok=True)

    css_path = static_dir / "style.css"
    css_path.write_text(_CSS_PLACEHOLDER, encoding="utf-8")

    paths: dict[str, Path] = {"index": site_dir / "index.html", "css": css_path}
    for run in runs:
        slug = _slugify_ts(run.ts_iso)
        page_path = runs_dir / f"{slug}.html"
        page_path.write_text(_render_run_page(run, VERSION, runs_dir), encoding="utf-8")
        paths[f"run/{slug}"] = page_path

    for cve_id in _list_distinct_cve_ids(cache):
        page_path = cve_dir / f"{cve_id}.html"
        page_path.write_text(
            _render_cve_page(cve_id, cache, VERSION, active_policy),
            encoding="utf-8",
        )
        paths[f"cve/{cve_id}"] = page_path

    strip = _render_strip(runs, site_dir, max_runs_on_home)
    paths["index"].write_text(
        _render_index(len(runs), VERSION, strip),
        encoding="utf-8",
    )

    _log.info("Wrote Web UI site to %s (%d runs)", site_dir, len(runs))
    return paths
