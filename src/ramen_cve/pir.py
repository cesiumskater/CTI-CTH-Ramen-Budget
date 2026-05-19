"""ramen_cve.pir — Priority Intelligence Requirement (PIR) definition
I/O and the `pir` subcommand runner (Layer-4). See docs/REFACTOR_PLAN.md."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .cache import Cache
from .constants import CVE_REGEX
from .models import OpmlError, Pir

_log = logging.getLogger(__name__)


def load_pir(path: Path) -> Pir:
    """Load a single PIR JSON file. Raises OpmlError on missing / malformed file."""
    if not path.exists():
        raise OpmlError(f"PIR file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise OpmlError(f"Could not parse PIR file {path}: {exc}") from exc
    return Pir.from_dict(data)


def load_all_pirs(dir_path: Path) -> list[Pir]:
    """Return every well-formed *.json PIR under `dir_path` (sorted by id)."""
    if not dir_path.exists():
        return []
    out: list[Pir] = []
    for p in sorted(dir_path.glob("*.json")):
        try:
            out.append(load_pir(p))
        except OpmlError as exc:
            _log.warning("Skipping malformed PIR file %s: %s", p, exc)
    out.sort(key=lambda x: x.id)
    return out


def save_pir(pir: Pir, path: Path) -> None:
    """Persist a Pir to disk as pretty-printed JSON; creates parent dir if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pir.to_dict(), indent=2), encoding="utf-8")


def _pir_path(pir_dir: Path, pir_id: str) -> Path:
    """Resolve the on-disk path for a PIR id (no slash characters allowed)."""
    if "/" in pir_id or "\\" in pir_id or pir_id.startswith("."):
        raise OpmlError(f"Invalid PIR id: {pir_id!r}")
    return pir_dir / f"{pir_id}.json"


def _run_pir(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the pir subcommand (list / show / link / coverage).

    - list:     tab-delimited table of all PIRs.
    - show:     pretty-printed JSON for one PIR.
    - link:     append a CVE id (uppercase, regex-checked) to tagged_cves.
    - coverage: roll-up table of every PIR's tagged-CVE / IOC / actor counts.
    """
    pir_dir: Path = args.pir_dir
    action = args.action

    if action == "list":
        pirs = load_all_pirs(pir_dir)
        if not pirs:
            _log.info("No PIRs in %s.", pir_dir)
            return 0
        for p in pirs:
            print(
                f"{p.id}\t{p.status}\t{len(p.tagged_cves)} CVEs"
                f"\t{len(p.tagged_actors)} actors\t{p.name}"
            )
        return 0

    if action == "coverage":
        pirs = load_all_pirs(pir_dir)
        if not pirs:
            _log.info("No PIRs in %s — nothing to report.", pir_dir)
            return 0
        print("# PIR Coverage")
        print()
        print("| PIR | Status | Tagged CVEs | Tagged IOCs | Tagged Actors |")
        print("| --- | --- | --- | --- | --- |")
        for p in pirs:
            print(
                f"| {p.id} | {p.status} | {len(p.tagged_cves)} | "
                f"{len(p.tagged_iocs)} | {len(p.tagged_actors)} |"
            )
        return 0

    if not args.pir_id:
        _log.error("pir %s: pir_id is required", action)
        return 1

    if action == "show":
        try:
            pir = load_pir(_pir_path(pir_dir, args.pir_id))
        except OpmlError as exc:
            _log.error(str(exc))
            return 1
        print(json.dumps(pir.to_dict(), indent=2))
        return 0

    # All write actions need to load the PIR first.
    try:
        pir_path = _pir_path(pir_dir, args.pir_id)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1
    try:
        pir = load_pir(pir_path)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    if action == "link":
        if not args.value:
            _log.error("pir link: a CVE-ID value is required")
            return 1
        cve = args.value.upper()
        if not CVE_REGEX.fullmatch(cve):
            _log.error("pir link: %r is not a valid CVE ID", args.value)
            return 1
        if cve in pir.tagged_cves:
            _log.info("CVE %s already tagged on PIR %s.", cve, pir.id)
            return 0
        pir.tagged_cves.append(cve)
        save_pir(pir, pir_path)
        print(f"Linked {cve} to {pir.id}")
        return 0

    _log.error("Unknown pir action: %r", action)
    return 1

