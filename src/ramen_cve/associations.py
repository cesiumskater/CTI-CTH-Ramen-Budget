"""ramen_cve.associations — threat-actor/campaign/malware assoc loader.

Layer-1.5: local JSON association file → typed models. No network.
See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path

from .constants import CVE_REGEX, DEFAULT_ASSOCIATIONS_PATH
from .models import Campaign, Malware, ThreatActor

_log = logging.getLogger(__name__)


def _build_actor(d: dict) -> ThreatActor:
    raw_sectors = d.get("sectors_targeted") or []
    sectors = [str(s).strip().lower() for s in raw_sectors if str(s).strip()]
    return ThreatActor(
        name=d.get("name", ""),
        aliases=list(d.get("aliases") or []),
        url=d.get("url"),
        sectors_targeted=sectors,
    )


def _build_campaign(d: dict) -> Campaign:
    return Campaign(name=d.get("name", ""), aliases=list(d.get("aliases") or []),
                    url=d.get("url"))


def _build_malware(d: dict) -> Malware:
    return Malware(name=d.get("name", ""), aliases=list(d.get("aliases") or []),
                   url=d.get("url"))


def load_associations(
    path: Path | None = None,
) -> dict[str, dict[str, list]]:
    """Load CVE → adversary associations from a JSON file.

    Returns a dict keyed on upper-case CVE ID. Each value has the shape:
        {"actors": [ThreatActor], "campaigns": [Campaign], "malware": [Malware]}

    If `path` is None we fall back to the bundled DEFAULT_ASSOCIATIONS_PATH;
    if that file is missing or malformed we return an empty dict and log a
    warning so the rest of the pipeline keeps working with empty linked_*
    fields.
    """
    target = path or DEFAULT_ASSOCIATIONS_PATH
    if not target.exists():
        _log.warning("Associations file not found: %s; skipping adversary join.", target)
        return {}
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning("Could not parse associations file %s: %s", target, exc)
        return {}

    out: dict[str, dict[str, list]] = {}
    for cve_id, payload in raw.items():
        if not isinstance(payload, dict) or not CVE_REGEX.fullmatch(cve_id.upper()):
            continue
        actors_in = payload.get("actors") or []
        campaigns_in = payload.get("campaigns") or []
        malware_in = payload.get("malware") or []
        out[cve_id.upper()] = {
            "actors": [_build_actor(a) for a in actors_in if isinstance(a, dict)],
            "campaigns": [_build_campaign(c) for c in campaigns_in if isinstance(c, dict)],
            "malware": [_build_malware(m) for m in malware_in if isinstance(m, dict)],
        }
    return out


def _parse_kev_due_date(value: str | None) -> date | None:
    """Parse a KEV dueDate string (YYYY-MM-DD) tolerating malformed input."""
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        _log.warning("KEV catalog returned an unparseable dueDate %r; ignoring.", value)
        return None

