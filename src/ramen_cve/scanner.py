"""ramen_cve.scanner — vulnerability-scanner export → inventory CSV shape.

Layer-1.5 (local file → inventory rows, no network), mirroring
``enrich.inventory`` in reverse: that module *reads* the inventory CSV, this
one *writes* it from a scanner export so `--inventory` can consume it.

    ramen-cve import --scanner nessus scan.nessus --out inventory.csv
    ramen-cve opml feeds.opml --inventory inventory.csv   # now correlated

Currently supports **Nessus** (`.nessus`, `NessusClientData_v2`), whose
per-host CPE detections (plugin 45590's `HostProperties` `cpe*` tags plus
`ReportItem/cpe` elements) map cleanly onto the inventory's `cpe` column.
The dispatcher and `SCANNER_FORMATS` are structured so Qualys / Rapid7 —
which are CVE-centric and need a different mapping — can be added without
touching the CLI wiring. Stdlib only (`xml.etree`). Re-exported on the façade.
"""
from __future__ import annotations

import csv
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TextIO

from .cache import Cache
from .models import OpmlError

_log = logging.getLogger(__name__)

#: Scanner export formats `import --scanner` accepts. Nessus first (default).
SCANNER_FORMATS: tuple[str, ...] = ("nessus",)

#: Inventory CSV header — must match the keys enrich.inventory.load_inventory
#: reads, so a written file round-trips straight back through `--inventory`.
INVENTORY_COLUMNS: tuple[str, ...] = (
    "host", "product", "version", "cpe", "owner", "criticality",
)


def _cpe_product_version(cpe: str) -> tuple[str, str]:
    """Best-effort (product, version) from a CPE 2.2 or 2.3 URI.

    ``cpe:/a:apache:http_server:2.4.49``          -> ("http_server", "2.4.49")
    ``cpe:2.3:a:apache:http_server:2.4.49:*:...`` -> ("http_server", "2.4.49")
    A wildcard / NA version slot (``*`` or ``-``) becomes "" so the inventory
    row means "any version" — matching enrich.inventory's version rule. Fills
    the product/version columns for human readability and the non-CPE match
    fallback; the explicit ``cpe`` column is the primary correlation key.
    """
    c = (cpe or "").strip()
    product = version = ""
    if c.lower().startswith("cpe:2.3:"):
        parts = c.split(":")
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""
    elif c.lower().startswith("cpe:/"):
        parts = c[len("cpe:/"):].split(":")
        product = parts[2] if len(parts) > 2 else ""
        version = parts[3] if len(parts) > 3 else ""
    if version in ("*", "-"):
        version = ""
    if product in ("*", "-"):
        product = ""
    return product, version


def _host_label(report_host: ET.Element) -> str:
    """Pick the most useful host identifier from a Nessus ReportHost.

    Prefers the FQDN, then reverse-DNS, then the ``name`` attribute (usually
    the IP). Nessus records these as ``<tag name="host-fqdn">`` etc. inside
    ``<HostProperties>``.
    """
    tags = {
        t.get("name"): (t.text or "").strip()
        for t in report_host.findall("./HostProperties/tag")
        if t.get("name")
    }
    for key in ("host-fqdn", "host-rdns"):
        if tags.get(key):
            return tags[key]
    return (report_host.get("name") or "").strip()


def _host_cpes(report_host: ET.Element) -> list[str]:
    """Collect every distinct CPE advertised for one Nessus ReportHost.

    Two sources: ``HostProperties`` tags whose name is ``cpe`` or ``cpe-N``
    (plugin 45590's OS/software detection), and ``<cpe>`` elements on any
    ``ReportItem``. Order-preserving de-dupe so output is stable.
    """
    seen: dict[str, None] = {}
    for tag in report_host.findall("./HostProperties/tag"):
        name = tag.get("name") or ""
        if name == "cpe" or name.startswith("cpe-"):
            val = (tag.text or "").strip()
            if val.lower().startswith("cpe:"):
                seen.setdefault(val, None)
    for item in report_host.findall("./ReportItem"):
        for cpe_el in item.findall("./cpe"):
            val = (cpe_el.text or "").strip()
            if val.lower().startswith("cpe:"):
                seen.setdefault(val, None)
    return list(seen)


def import_nessus(path: Path) -> list[dict[str, str]]:
    """Parse a ``.nessus`` (NessusClientData_v2) export into inventory rows.

    One row per distinct (host, CPE) pair, with product/version parsed from
    the CPE and ``owner`` / ``criticality`` left blank for the analyst to fill.
    Rows are sorted by (host, cpe) for deterministic output. Raises OpmlError
    on a missing or malformed file (the project's file-input error, as used by
    the hunt loader).
    """
    if not path.exists():
        raise OpmlError(f"Scanner file not found: {path}")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise OpmlError(f"Could not parse Nessus file {path}: {exc}") from exc
    except OSError as exc:
        raise OpmlError(f"Could not read Nessus file {path}: {exc}") from exc

    rows: list[dict[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for report_host in root.iter("ReportHost"):
        host = _host_label(report_host)
        if not host:
            continue
        for cpe in _host_cpes(report_host):
            pair = (host, cpe)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            product, version = _cpe_product_version(cpe)
            rows.append({
                "host": host, "product": product, "version": version,
                "cpe": cpe, "owner": "", "criticality": "",
            })
    rows.sort(key=lambda r: (r["host"], r["cpe"]))
    return rows


#: Format name -> parser. Adding Qualys/Rapid7 is a new entry here + SCANNER_FORMATS.
_IMPORTERS = {"nessus": import_nessus}


def import_scan(path: Path, scanner: str) -> list[dict[str, str]]:
    """Dispatch to the importer for ``scanner`` and return inventory rows.

    Raises OpmlError on an unknown format (argparse normally constrains the
    choice, but the guard keeps the function safe to call directly).
    """
    fn = _IMPORTERS.get((scanner or "").lower())
    if fn is None:
        raise OpmlError(
            f"Unknown scanner format {scanner!r}; supported: {', '.join(SCANNER_FORMATS)}"
        )
    return fn(path)


def write_inventory_rows(rows: list[dict[str, str]], stream: TextIO) -> None:
    """Write inventory rows as CSV (with header) to an open text stream."""
    writer = csv.DictWriter(stream, fieldnames=INVENTORY_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col, "") for col in INVENTORY_COLUMNS})


def write_inventory_csv(rows: list[dict[str, str]], path: Path) -> None:
    """Write inventory rows to a CSV file at ``path`` (creates parent dirs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        write_inventory_rows(rows, fh)


def _run_import(args, cache: Cache, api_key: str | None) -> int:
    """Execute the `import` subcommand: scanner export → inventory CSV.

    Writes to ``--out`` when given, else to stdout so it can be piped into a
    subsequent `--inventory` run. Returns rc 0 on success, 1 on a bad file /
    unknown format.
    """
    import sys

    try:
        rows = import_scan(args.input, args.scanner)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1
    if args.out:
        write_inventory_csv(rows, args.out)
        _log.info(
            "Imported %d inventory row(s) from %s → %s.",
            len(rows), args.input, args.out,
        )
    else:
        write_inventory_rows(rows, sys.stdout)
        _log.info("Imported %d inventory row(s) from %s.", len(rows), args.input)
    return 0
