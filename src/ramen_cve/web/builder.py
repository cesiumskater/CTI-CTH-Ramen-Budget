"""ramen_cve.web.builder — static-HTML Web UI generator (Task 8, L4).

Slice A (this module): emits a minimal `<site-dir>/index.html` (H1 +
"N runs recorded.") and an empty `<site-dir>/static/style.css`. The
runs count comes from the SQLite `runs` table via
`Cache.list_run_timestamps()`. Raises `WebUiError` when the table is
empty (the design-doc D11 contract — fail-fast rather than ship an
empty site).

Slices B-G extend this module per `docs/web_ui_design.md`:
  - B: new `run_artefacts` SQLite table + `pipeline._output` wiring
  - C: `_discover_runs` + run-history strip + per-run summary pages
  - D-E: per-CVE detail pages (RICH content)
  - F: "what changed" diff block on per-run pages
  - G: bucket-policy threading + showcase regen extension
"""
from __future__ import annotations

import html
import logging
from pathlib import Path

from ..bucket_policy import BucketPolicy
from ..cache import Cache
from ..models import WebUiError

_log = logging.getLogger(__name__)

WEB_DEFAULT_MAX_RUNS_ON_HOME = 30

# Slice A's CSS is a placeholder — real styling lands in Slice G alongside
# the showcase regen. The file is shipped (linked from every page) so the
# link-from-every-page contract is locked from day one.
_CSS_PLACEHOLDER = "/* ramen-cve web ui — styling populated in Slice G. */\n"


def _render_index(run_count: int, version: str) -> str:
    """Render the Slice A `index.html` body.

    Strict-minimum layout (design-doc D14 + D20):
    - HTML5 doctype + `<html lang="en">`
    - UTF-8 charset declaration
    - `<meta name="generator" content="ramen-cve <version>">` for traceability
    - linked `static/style.css`
    - `<h1>Ramen CVE Triage</h1>`
    - `<p>N run(s) recorded.</p>` (English-correct singular/plural)

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
        "</body>\n"
        "</html>\n"
    )


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

    `policy` and `max_runs_on_home` are accepted in Slice A but not
    consumed until Slices C (run-history strip cap) and G (bucket-policy
    label propagation). They're in the signature now so the call site
    in `_run_web` doesn't churn between slices.
    """
    # Lazy import — `cli.VERSION` is L4, importing it at module load
    # creates a cli ↔ web cycle (cli imports from web; web would import
    # from cli). The deferred-lookup pattern documented in
    # docs/REFACTOR_PLAN.md §5.2 resolves the cycle at call time.
    from ..cli import VERSION

    del policy, max_runs_on_home  # reserved for slices C / G; intentional Slice A no-op

    run_timestamps = cache.list_run_timestamps()
    if not run_timestamps:
        raise WebUiError(
            "No runs recorded in cache — nothing to render. "
            "Run `ramen-cve opml/url/cve ...` first to populate the runs table."
        )

    site_dir.mkdir(parents=True, exist_ok=True)
    static_dir = site_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    css_path = static_dir / "style.css"
    css_path.write_text(_CSS_PLACEHOLDER, encoding="utf-8")

    index_path = site_dir / "index.html"
    index_path.write_text(
        _render_index(len(run_timestamps), VERSION),
        encoding="utf-8",
    )

    _log.info("Wrote Web UI site to %s (%d runs)", site_dir, len(run_timestamps))
    return {"index": index_path, "css": css_path}
