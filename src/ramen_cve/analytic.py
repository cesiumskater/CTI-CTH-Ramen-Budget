"""ramen_cve.analytic — detection-analytic template library + the `analytic`
subcommand runner.

Layer-1.5, mirroring ``associations`` (local JSON → typed models, no network)
and ``hunt`` (subcommand runner). The bundled catalog at
``data/analytics.json`` holds platform-neutral detection skeletons keyed to
MITRE ATT&CK technique IDs. ``analytic suggest <hunt-id>`` reads a hunt's
``attack_techniques`` and surfaces the templates whose techniques overlap —
turning a hunt hypothesis into a starting set of detections.

Overlap is **parent/sub-technique aware**: a hunt tagged ``T1059`` matches an
analytic tagged ``T1059.001`` (and vice versa), because they share the base
technique ``T1059``. This mirrors how an analyst reasons about ATT&CK — the
sub-technique is a specialization of the parent, not an unrelated behaviour.

Stdlib only. Re-exported on the façade.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .cache import Cache
from .constants import DEFAULT_ANALYTICS_PATH
from .hunt import _hunt_path, load_hunt
from .models import Analytic, Hunt, OpmlError

_log = logging.getLogger(__name__)


def _base_technique(tid: str) -> str:
    """Reduce an ATT&CK technique id to its base: ``T1059.001`` -> ``T1059``.

    Upper-cases and trims first so matching is case/whitespace-insensitive.
    A bare technique returns itself; a sub-technique returns its parent.
    """
    tid = (tid or "").strip().upper()
    return tid.split(".", 1)[0]


def load_analytics(path: Path | None = None) -> list[Analytic]:
    """Load the detection-analytic catalog from a JSON file.

    Returns the analytics sorted by id. Falls back to the bundled
    DEFAULT_ANALYTICS_PATH when ``path`` is None; a missing or malformed file
    yields an empty list and a logged warning, so the subcommand degrades to
    "no suggestions" rather than crashing (same contract as load_associations).
    Entries without an id are skipped; ids must be unique — a later duplicate
    is dropped with a warning so ``show`` stays unambiguous.
    """
    target = path or DEFAULT_ANALYTICS_PATH
    if not target.exists():
        _log.warning("Analytics catalog not found: %s; no suggestions available.", target)
        return []
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning("Could not parse analytics catalog %s: %s", target, exc)
        return []

    entries = raw.get("analytics") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        _log.warning("Analytics catalog %s has no 'analytics' list; ignoring.", target)
        return []

    out: list[Analytic] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        analytic = Analytic.from_dict(item)
        if not analytic.id:
            continue
        if analytic.id in seen:
            _log.warning("Duplicate analytic id %r in %s; keeping the first.", analytic.id, target)
            continue
        seen.add(analytic.id)
        out.append(analytic)
    out.sort(key=lambda a: a.id)
    return out


def suggest_analytics(
    hunt: Hunt, analytics: list[Analytic]
) -> list[tuple[Analytic, list[str]]]:
    """Return analytics whose techniques overlap the hunt's, ranked best-first.

    Each result is ``(analytic, matched_techniques)`` where matched_techniques
    are the analytic's own technique strings that share a base technique with
    the hunt (sorted, de-duplicated). Ranking: more distinct shared base
    techniques first, then analytic id for a stable, deterministic order.

    A hunt with no ``attack_techniques`` yields an empty list (nothing to
    overlap against) — the runner turns that into an explanatory INFO line.
    """
    hunt_bases = {_base_technique(t) for t in hunt.attack_techniques if t.strip()}
    if not hunt_bases:
        return []

    scored: list[tuple[int, str, Analytic, list[str]]] = []
    for analytic in analytics:
        shared_bases = {
            _base_technique(t) for t in analytic.technique_ids
        } & hunt_bases
        if not shared_bases:
            continue
        matched = sorted(
            {t for t in analytic.technique_ids if _base_technique(t) in shared_bases}
        )
        scored.append((len(shared_bases), analytic.id, analytic, matched))

    # Rank: most distinct shared base techniques first (negate for descending),
    # then analytic id ascending for determinism.
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [(analytic, matched) for _, _, analytic, matched in scored]


def _print_analytic(analytic: Analytic, matched: list[str] | None = None) -> None:
    """Human-readable one-block print of an analytic (used by list + suggest)."""
    techniques = ", ".join(analytic.technique_ids) if analytic.technique_ids else "—"
    print(f"[{analytic.id}] {analytic.name}")
    print(f"    techniques: {techniques}")
    if matched:
        print(f"    matched:    {', '.join(matched)}")
    if analytic.data_sources:
        print(f"    data:       {', '.join(analytic.data_sources)}")
    if analytic.description:
        print(f"    {analytic.description}")


def _run_analytic(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the analytic subcommand (list / show / suggest).

    ``list``               — print every template in the catalog.
    ``show <analytic-id>`` — print one template as JSON.
    ``suggest <hunt-id>``  — print templates overlapping the hunt's techniques.
    """
    analytics = load_analytics(getattr(args, "analytics_file", None))
    action = args.action

    if action == "list":
        if not analytics:
            _log.info("No analytics in the catalog.")
            return 0
        for analytic in analytics:
            _print_analytic(analytic)
        return 0

    if action == "show":
        if not args.ident:
            _log.error("analytic show: an analytic id is required")
            return 1
        match = next((a for a in analytics if a.id == args.ident), None)
        if match is None:
            _log.error("analytic show: no analytic with id %r", args.ident)
            return 1
        print(json.dumps(match.to_dict(), indent=2))
        return 0

    if action == "suggest":
        if not args.ident:
            _log.error("analytic suggest: a hunt id is required")
            return 1
        try:
            hunt = load_hunt(_hunt_path(args.hunt_dir, args.ident))
        except OpmlError as exc:
            _log.error(str(exc))
            return 1
        if not hunt.attack_techniques:
            _log.info(
                "Hunt %s has no attack_techniques; nothing to suggest against.",
                hunt.id,
            )
            return 0
        suggestions = suggest_analytics(hunt, analytics)
        if not suggestions:
            _log.info(
                "No analytics overlap hunt %s techniques (%s).",
                hunt.id, ", ".join(hunt.attack_techniques),
            )
            return 0
        print(
            f"{len(suggestions)} analytic(s) overlap hunt {hunt.id} "
            f"techniques ({', '.join(hunt.attack_techniques)}):\n"
        )
        for analytic, matched in suggestions:
            _print_analytic(analytic, matched)
            print()
        return 0

    _log.error("Unknown analytic action: %r", action)
    return 1
