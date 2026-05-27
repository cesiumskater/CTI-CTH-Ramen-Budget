"""ramen_cve.web.builder — static-HTML Web UI generator (Task 8, L4).

Slice A: emits a minimal `<site-dir>/index.html` (H1 + "N runs recorded.")
and an empty `<site-dir>/static/style.css`. Raises `WebUiError` when the
`runs` table is empty (design-doc §D11).

Slice C: adds `_discover_runs` (LEFT JOIN against `run_artefacts`),
per-run summary pages at `<site-dir>/runs/<slug>.html`, and a run-history
strip on the index. The slug is `ts_iso` with colons replaced by hyphens.

Slice D: per-CVE detail pages at `<site-dir>/cve/<CVE-ID>.html` with
§§1-3 of design-doc §5.3 — header (CVE id + most-recent bucket + linked
NVD URL), summary (description + CVSS + EPSS + KEV), and a trajectory
chart that reuses Task-6's `_render_quadrant_svg_from_points` in single-
CVE multi-snapshot mode (sparkline fallback below 2 snapshots, 200-
snapshot cap with "+N earlier" footer).

Slice E: per-CVE detail page §§4, 5, 7 — exploit status, associations,
affected hosts. All three read from the most-recent run's main CVE CSV
on disk (snapshot-consistent with §§1-3).

Slice E.5: per-CVE detail page §6 — IOCs. Threads CVE attribution
through the IOC pipeline (extract → dedupe → CSV) by adding
`IocRecord.cve_ids: list[str]`. The Web UI's `_render_iocs` reads the
sidecar, filters where `cve_id` is in the row's `cve_ids` list, caps
at 50, sorts by `first_seen` DESC, and renders an HTML-escaped
`<table>` with no clickable `<a>` tags.

Slice F (this update): per-run "Changes since previous run" diff block
on `runs/<slug>.html`. Compares each run against the immediately-prior
`ts_iso` and lists added / removed / reclassified CVEs. The oldest run
gets a "First recorded run" placeholder. All CVE links resolve to
`../cve/<CVE-ID>.html` (Slice D-emitted pages).

Slice G extends per `docs/web_ui_design.md`:
  - G: bucket-policy threading + showcase regen extension
"""
from __future__ import annotations

import csv
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
WEB_IOC_CAP = 50
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


def _previous_ts_iso(cache: Cache, ts_iso: str) -> str | None:
    """The immediately-prior distinct `ts_iso` in `runs`, or None.

    Used by Slice F to pair each run with its predecessor for the diff
    block. None means the supplied run is the oldest recorded.
    """
    row = cache._conn.execute(
        "SELECT ts_iso FROM runs WHERE ts_iso < ? "
        "ORDER BY ts_iso DESC LIMIT 1",
        (ts_iso,),
    ).fetchone()
    return row[0] if row else None


def _bucket_map_for_run(cache: Cache, ts_iso: str) -> dict[str, str]:
    """`{cve_id: bucket}` snapshot for one run."""
    rows = cache._conn.execute(
        "SELECT cve_id, bucket FROM runs WHERE ts_iso = ?",
        (ts_iso,),
    ).fetchall()
    return dict(rows)


def _diff_runs(
    cache: Cache, this_ts_iso: str,
) -> tuple[list[str], list[str], list[tuple[str, str, str]]]:
    """Return `(added, removed, reclassified)` lists vs. the prior run.

    `reclassified` entries are `(cve_id, old_bucket, new_bucket)`.
    Sorted alphabetically by CVE id for deterministic, byte-stable
    output. When no prior run exists, all three lists are empty —
    `_render_diff_block` then emits the "First recorded run" placeholder.
    """
    prev_ts = _previous_ts_iso(cache, this_ts_iso)
    if prev_ts is None:
        return ([], [], [])
    this_map = _bucket_map_for_run(cache, this_ts_iso)
    prev_map = _bucket_map_for_run(cache, prev_ts)
    this_ids = set(this_map)
    prev_ids = set(prev_map)
    added = sorted(this_ids - prev_ids)
    removed = sorted(prev_ids - this_ids)
    reclassified: list[tuple[str, str, str]] = []
    for cve_id in sorted(this_ids & prev_ids):
        if prev_map[cve_id] != this_map[cve_id]:
            reclassified.append((cve_id, prev_map[cve_id], this_map[cve_id]))
    return added, removed, reclassified


def _cve_link(cve_id: str) -> str:
    """Per-run-page-relative `<a>` to the Slice-D-emitted per-CVE page."""
    escaped = html.escape(cve_id, quote=True)
    return f'<a href="../cve/{escaped}.html">{escaped}</a>'


def _render_diff_block(
    cache: Cache,
    this_ts_iso: str,
    policy: BucketPolicy,
) -> str:
    """Render the §5.2 "Changes since previous run" block.

    Layout:
    - Oldest run (no predecessor) → "First recorded run — no diff
      available" placeholder.
    - Empty diff (CVE set + buckets identical) → "No changes."
    - Otherwise → three sub-sections (Added / Removed / Reclassified),
      each rendered only when non-empty. Reclassified entries show
      "<CVE> · <old label> → <new label>" with policy-resolved labels.
    """
    if _previous_ts_iso(cache, this_ts_iso) is None:
        return (
            "<h2>Changes since previous run</h2>\n"
            "<p>First recorded run — no diff available.</p>\n"
        )

    added, removed, reclassified = _diff_runs(cache, this_ts_iso)
    if not (added or removed or reclassified):
        return (
            "<h2>Changes since previous run</h2>\n"
            "<p>No changes.</p>\n"
        )

    parts = ["<h2>Changes since previous run</h2>\n"]
    if added:
        items = "".join(f"<li>{_cve_link(c)}</li>" for c in added)
        parts.append(f"<h3>Added ({len(added)})</h3>\n<ul>{items}</ul>\n")
    if removed:
        # Removed CVEs no longer have a per-run-bucket here, but Slice D
        # may still emit a CVE page (any prior run keeps it in
        # `_list_distinct_cve_ids`). Link defensively.
        items = "".join(f"<li>{_cve_link(c)}</li>" for c in removed)
        parts.append(f"<h3>Removed ({len(removed)})</h3>\n<ul>{items}</ul>\n")
    if reclassified:
        rows = []
        for cve_id, old, new in reclassified:
            try:
                old_label = policy.label(old)
            except KeyError:
                old_label = old
            try:
                new_label = policy.label(new)
            except KeyError:
                new_label = new
            rows.append(
                f"<li>{_cve_link(cve_id)} · "
                f"{html.escape(old_label, quote=True)} → "
                f"{html.escape(new_label, quote=True)}</li>"
            )
        parts.append(
            f"<h3>Reclassified ({len(reclassified)})</h3>\n"
            f"<ul>{''.join(rows)}</ul>\n"
        )
    return "".join(parts)


def _render_run_page(
    run: _DiscoveredRun,
    version: str,
    runs_dir: Path,
    cache: Cache,
    policy: BucketPolicy,
) -> str:
    """Render one `runs/<slug>.html` per-run summary page.

    Slice C: header (ts_iso + CVE count) + 6-row artefact-link table.
    Slice F: appends a "Changes since previous run" diff block computed
    from the prior `ts_iso` (added / removed / reclassified CVEs). The
    oldest run gets a "First recorded run" placeholder.
    """
    ts_escaped = html.escape(run.ts_iso, quote=True)
    plural = "" if run.cve_count == 1 else "s"
    artefact_rows = "\n".join(
        f"<tr><th>{html.escape(label, quote=True)}</th>"
        f"<td>{_artefact_link_cell(run, key, runs_dir)}</td></tr>"
        for key, label, _t in _ARTEFACT_KINDS
    )
    diff_block = _render_diff_block(cache, run.ts_iso, policy)
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
        f"{diff_block}"
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


_EXPLOIT_STATUS_LABELS: dict[str, str] = {
    "exploit_db": "Public exploit (ExploitDB)",
    "nuclei_template": "Nuclei detection template",
    "github_poc": "GitHub PoC",
    "none": "None observed",
    "": "None observed",
}


def _find_run_csv_for_cve(cache: Cache, cve_id: str) -> Path | None:
    """Path to the most-recent run's main CVE CSV that contains `cve_id`.

    Joins `runs` to `run_artefacts` so pre-Slice-B runs (LEFT JOIN miss)
    are silently skipped — they have no on-disk sidecar to read. Returns
    None when no qualifying row exists or the file is missing on disk
    (best-effort §3.2 contract).
    """
    row = cache._conn.execute(
        "SELECT run_artefacts.disk_stamp, run_artefacts.out_dir "
        "FROM runs JOIN run_artefacts USING (ts_iso) "
        "WHERE runs.cve_id = ? "
        "ORDER BY runs.ts_iso DESC LIMIT 1",
        (cve_id,),
    ).fetchone()
    if not row:
        return None
    disk_stamp, out_dir = row
    csv_path = Path(out_dir) / f"ramen-cve-{disk_stamp}.csv"
    return csv_path if csv_path.exists() else None


def _read_cve_csv_row(csv_path: Path, cve_id: str) -> dict | None:
    """Return the row dict for `cve_id` from the run's main CVE CSV, or None.

    Defensive: missing/malformed files just return None and the caller
    renders "—" for §§4-5-7. Never raises — the offline Web UI shouldn't
    crash because an artefact got mangled.
    """
    try:
        with csv_path.open(newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                if row.get("cve_id") == cve_id:
                    return row
    except OSError:
        return None
    return None


def _render_exploit_status(row: dict | None) -> str:
    """§4: render the exploit_status column as a humanized one-liner."""
    if row is None:
        body = "—"
    else:
        raw = (row.get("exploit_status") or "").strip()
        label = _EXPLOIT_STATUS_LABELS.get(raw, raw or "—")
        body = html.escape(label, quote=True)
    return f"<h2>Exploit status</h2>\n<p>{body}</p>\n"


def _render_associations_list(joined: str) -> str:
    """Helper for §5 sub-blocks: semicolon-joined names → `<ul>` or "—"."""
    names = [n.strip() for n in (joined or "").split(";") if n.strip()]
    if not names:
        return "—"
    items = "".join(
        f"<li>{html.escape(n, quote=True)}</li>" for n in names
    )
    return f"<ul>{items}</ul>"


def _render_associations(row: dict | None) -> str:
    """§5: actor / campaign / malware names from the run's CSV row.

    Names only (semicolon-split) — rich linking (URLs, ATT&CK IDs) is
    a deliberate v1 omission documented in the design-doc lockdown.
    """
    if row is None:
        actors = campaigns = malware = "—"
    else:
        actors = _render_associations_list(row.get("linked_actors", ""))
        campaigns = _render_associations_list(row.get("linked_campaigns", ""))
        malware = _render_associations_list(row.get("linked_malware", ""))
    return (
        "<h2>Associations</h2>\n"
        "<dl class=\"cve-associations\">\n"
        f"<dt>Threat actors</dt><dd>{actors}</dd>\n"
        f"<dt>Campaigns</dt><dd>{campaigns}</dd>\n"
        f"<dt>Malware</dt><dd>{malware}</dd>\n"
        "</dl>\n"
    )


def _render_affected_hosts(row: dict | None) -> str:
    """§7: affected_hosts from the run's CSV row, semicolon-split into a list."""
    body = "—" if row is None else _render_associations_list(
        row.get("affected_hosts", "")
    )
    return f"<h2>Affected hosts</h2>\n{body}\n"


def _find_iocs_csv_for_cve(cache: Cache, cve_id: str) -> Path | None:
    """Path to the most-recent run's IOC sidecar CSV for `cve_id`, or None.

    Mirrors `_find_run_csv_for_cve` but for the `-iocs.csv` sidecar. Returns
    None when the join misses, the file is absent, or the run wasn't the
    one that produced an IOC artefact (sidecar may legitimately be absent
    for some runs).
    """
    row = cache._conn.execute(
        "SELECT run_artefacts.disk_stamp, run_artefacts.out_dir "
        "FROM runs JOIN run_artefacts USING (ts_iso) "
        "WHERE runs.cve_id = ? "
        "ORDER BY runs.ts_iso DESC LIMIT 1",
        (cve_id,),
    ).fetchone()
    if not row:
        return None
    disk_stamp, out_dir = row
    iocs_path = Path(out_dir) / f"ramen-cve-{disk_stamp}-iocs.csv"
    return iocs_path if iocs_path.exists() else None


def _read_iocs_for_cve(
    iocs_path: Path | None,
    cve_id: str,
    cap: int = WEB_IOC_CAP,
) -> list[dict]:
    """IOC rows from the sidecar whose `cve_ids` column lists `cve_id`.

    Empty list when the file is missing, malformed, or no row matches.
    Rows are sorted by `first_seen` DESC (most-recent first); ties broken
    by insertion order. Caps at `cap` rows (design-doc §5.3 §6).
    """
    if iocs_path is None:
        return []
    matches: list[dict] = []
    try:
        with iocs_path.open(newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                linked = [c.strip() for c in (row.get("cve_ids") or "").split(";")]
                if cve_id in linked:
                    matches.append(row)
    except OSError:
        return []
    matches.sort(key=lambda r: r.get("first_seen") or "", reverse=True)
    return matches[:cap]


def _render_iocs(rows: list[dict], total: int | None = None) -> str:
    """§6: render an IOC `<table>` for the per-CVE detail page.

    `rows` is the already-capped + filtered output of `_read_iocs_for_cve`.
    `total` (when set) is the pre-cap count — used to show "+N more not
    shown" when truncated. Empty list → "—". Every cell is HTML-escaped;
    IOC values are NOT wrapped in `<a>` tags (a malicious URL must not be
    clickable on an analyst's machine).
    """
    if not rows:
        return "<h2>IOCs</h2>\n<p>—</p>\n"
    header = (
        "<tr><th>Type</th><th>Value</th><th>Source</th>"
        "<th>First seen</th><th>Confidence</th></tr>"
    )
    body_rows: list[str] = []
    for row in rows:
        cells = [
            html.escape(row.get("ioc_type", ""), quote=True),
            html.escape(row.get("value", ""), quote=True),
            html.escape(row.get("source", ""), quote=True),
            html.escape(row.get("first_seen", ""), quote=True),
            html.escape(row.get("confidence", ""), quote=True),
        ]
        body_rows.append(
            "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"
        )
    truncated = ""
    if total is not None and total > len(rows):
        truncated = (
            f'<p class="iocs-footer">+{total - len(rows)} more IOCs '
            "not shown</p>\n"
        )
    return (
        "<h2>IOCs</h2>\n"
        '<table class="cve-iocs">\n'
        f"{header}\n"
        + "\n".join(body_rows)
        + "\n</table>\n"
        + truncated
    )


def _render_cve_page(
    cve_id: str,
    cache: Cache,
    version: str,
    policy: BucketPolicy,
) -> str:
    """Render one `cve/<CVE-ID>.html` per-CVE detail page (§§1-7).

    §1 Header: H1 with the CVE id + most-recent bucket label + linked
    NVD URL. The most-recent bucket comes from the final `runs` row
    (chronologically). Unknown buckets fall back to the raw id.

    §2 Summary: delegated to `_render_cve_summary`.
    §3 Trajectory: delegated to `_render_cve_trajectory`.
    §4 Exploit status / §5 Associations / §7 Affected hosts: read the
    most-recent run's main CVE CSV from disk (snapshot-consistent with
    §§1-3). Missing artefacts or rows → "—" per the best-effort contract.
    §6 IOCs: read the run's `-iocs.csv` sidecar, filter by `cve_ids`,
    cap at `WEB_IOC_CAP` rows with a "+N more" footer when truncated.
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

    csv_path = _find_run_csv_for_cve(cache, cve_id)
    csv_row = _read_cve_csv_row(csv_path, cve_id) if csv_path else None
    iocs_path = _find_iocs_csv_for_cve(cache, cve_id)
    # Pre-cap count is used to render the "+N more" footer when the IOC
    # set exceeds WEB_IOC_CAP. Compute by reading once with cap=very_high.
    all_iocs = _read_iocs_for_cve(iocs_path, cve_id, cap=10_000)
    capped_iocs = all_iocs[:WEB_IOC_CAP]

    cve_escaped = html.escape(cve_id, quote=True)
    bucket_label_escaped = html.escape(bucket_label, quote=True)
    nvd_url = _NVD_URL_TEMPLATE.format(cve_id=cve_id)
    nvd_url_escaped = html.escape(nvd_url, quote=True)

    summary = _render_cve_summary(nvd, epss, kev_row)
    trajectory = _render_cve_trajectory(runs_history)
    exploit = _render_exploit_status(csv_row)
    associations = _render_associations(csv_row)
    iocs = _render_iocs(capped_iocs, total=len(all_iocs))
    hosts = _render_affected_hosts(csv_row)

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
        f"{exploit}"
        f"{associations}"
        f"{iocs}"
        f"{hosts}"
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
    out_dir: Path | None = None,
) -> dict[str, Path]:
    """Render the static site rooted at `site_dir`.

    Returns a dict of {kind: Path} for every file written, matching
    `pipeline._output`'s shape so callers can `print(...)` each path
    or attach the bundle to a downstream dispatch.

    Raises `WebUiError` if the cache's `runs` table is empty — there's
    nothing to render and shipping a "no runs yet" landing page would
    obscure the misconfiguration that led here.

    `max_runs_on_home` caps the strip at the most-recent N runs (older
    runs reachable by direct `runs/<slug>.html` URL). `policy` is the
    `BucketPolicy` whose labels render in every page heading; defaults
    to `DEFAULT_BUCKET_POLICY`.

    `out_dir` overrides the per-run artefact directory recorded in
    `run_artefacts` for every run. Useful when the files have been
    moved since the original pipeline run wrote them (the cache still
    holds the original absolute path). Runs with no `run_artefacts`
    row stay "—" — the override doesn't fabricate a `disk_stamp`.
    """
    # Lazy import — `cli.VERSION` is L4, importing it at module load
    # creates a cli ↔ web cycle (cli imports from web; web would import
    # from cli). The deferred-lookup pattern documented in
    # docs/REFACTOR_PLAN.md §5.2 resolves the cycle at call time.
    from ..cli import VERSION

    active_policy = policy or DEFAULT_BUCKET_POLICY

    runs = _discover_runs(cache)
    if not runs:
        raise WebUiError(
            "No runs recorded in cache — nothing to render. "
            "Run `ramen-cve opml/url/cve ...` first to populate the runs table."
        )

    if out_dir is not None:
        override = str(out_dir)
        runs = [
            run._replace(out_dir=override) if run.disk_stamp is not None else run
            for run in runs
        ]

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
        page_path.write_text(
            _render_run_page(run, VERSION, runs_dir, cache, active_policy),
            encoding="utf-8",
        )
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
