"""ramen_cve.hunt — threat-hunt definition I/O (load/save) and the
`hunt` subcommand runner (Layer-4). See docs/REFACTOR_PLAN.md."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .cache import Cache
from .constants import CVE_REGEX, HUNT_STATUSES
from .models import Hunt, OpmlError, _utcnow

_log = logging.getLogger(__name__)


def load_hunt(path: Path) -> Hunt:
    """Load a single hunt JSON file. Raises OpmlError on missing/malformed file."""
    if not path.exists():
        raise OpmlError(f"Hunt file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise OpmlError(f"Could not parse hunt file {path}: {exc}") from exc
    return Hunt.from_dict(data)


def load_all_hunts(dir_path: Path) -> list[Hunt]:
    """Return every well-formed *.json hunt under `dir_path` (sorted by id)."""
    if not dir_path.exists():
        return []
    out: list[Hunt] = []
    for p in sorted(dir_path.glob("*.json")):
        try:
            out.append(load_hunt(p))
        except OpmlError as exc:
            _log.warning("Skipping malformed hunt file %s: %s", p, exc)
    out.sort(key=lambda h: h.id)
    return out


def save_hunt(hunt: Hunt, path: Path) -> None:
    """Persist a Hunt to disk as pretty-printed JSON; creates parent dir if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(hunt.to_dict(), indent=2), encoding="utf-8")


def _hunt_path(hunt_dir: Path, hunt_id: str) -> Path:
    """Resolve the on-disk path for a hunt id (no slash characters allowed)."""
    if "/" in hunt_id or "\\" in hunt_id or hunt_id.startswith("."):
        raise OpmlError(f"Invalid hunt id: {hunt_id!r}")
    return hunt_dir / f"{hunt_id}.json"


def _run_hunt(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the hunt subcommand (list / show / link / log / status)."""
    hunt_dir: Path = args.hunt_dir
    action = args.action

    if action == "list":
        hunts = load_all_hunts(hunt_dir)
        if not hunts:
            _log.info("No hunts in %s.", hunt_dir)
            return 0
        for h in hunts:
            print(f"{h.id}\t{h.status}\t{len(h.linked_cves)} CVEs\t{h.name}")
        return 0

    if not args.hunt_id:
        _log.error("hunt %s: hunt_id is required", action)
        return 1

    if action == "show":
        try:
            hunt = load_hunt(_hunt_path(hunt_dir, args.hunt_id))
        except OpmlError as exc:
            _log.error(str(exc))
            return 1
        print(json.dumps(hunt.to_dict(), indent=2))
        return 0

    # All write actions need to load the hunt first.
    try:
        hunt_path = _hunt_path(hunt_dir, args.hunt_id)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1
    try:
        hunt = load_hunt(hunt_path)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    if action == "link":
        if not args.value:
            _log.error("hunt link: a CVE-ID value is required")
            return 1
        cve = args.value.upper()
        if not CVE_REGEX.fullmatch(cve):
            _log.error("hunt link: %r is not a valid CVE ID", args.value)
            return 1
        if cve in hunt.linked_cves:
            _log.info("CVE %s already linked to hunt %s.", cve, hunt.id)
            return 0
        hunt.linked_cves.append(cve)
        save_hunt(hunt, hunt_path)
        print(f"Linked {cve} to {hunt.id}")
        return 0

    if action == "log":
        if not args.value:
            _log.error("hunt log: a finding text is required")
            return 1
        hunt.findings.append({
            "timestamp": _utcnow().isoformat(timespec="seconds"),
            "text": args.value,
        })
        save_hunt(hunt, hunt_path)
        print(f"Logged finding on {hunt.id}")
        return 0

    if action == "status":
        if not args.value:
            _log.error("hunt status: a new status value is required (one of %s)",
                       ", ".join(HUNT_STATUSES))
            return 1
        new_status = args.value.lower()
        if new_status not in HUNT_STATUSES:
            _log.error("hunt status: %r is not a valid status (use %s)",
                       args.value, ", ".join(HUNT_STATUSES))
            return 1
        hunt.status = new_status
        save_hunt(hunt, hunt_path)
        print(f"Set {hunt.id} status → {new_status}")
        return 0

    _log.error("Unknown hunt action: %r", action)
    return 1

