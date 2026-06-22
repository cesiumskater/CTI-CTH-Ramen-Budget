"""ramen_cve.enrich.inventory — local asset inventory / CPE match (L1.5).

Loads an inventory CSV and correlates CPEs to owned products. No net.
See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..models import EnrichedCve, OpmlError
from ..risk import worst_criticality


def load_inventory(path: Path) -> list[dict[str, str]]:
    """Load an inventory CSV with columns host, product, version (case-insensitive).

    Returns a list of dicts. Optional columns:
      - `cpe`: explicit CPE 2.3 string (skips product/version inference).
      - `owner`: an email address used by the --digest dispatcher to route
        per-asset patch summaries to the right recipient.
      - `criticality`: tier1 / tier2 / tier3 (case-insensitive). Drives the
        risk-weighted prioritization score (see src/ramen_cve/risk.py).
        Empty / missing → treated as "no criticality data" (neutral weight).
    Raises OpmlError on missing or unreadable files.
    """
    if not path.exists():
        raise OpmlError(f"Inventory file not found: {path}")
    rows: list[dict[str, str]] = []
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                rows.append(
                    {
                        "host": (r.get("host") or "").strip(),
                        "product": (r.get("product") or "").strip(),
                        "version": (r.get("version") or "").strip(),
                        "cpe": (r.get("cpe") or "").strip(),
                        "owner": (r.get("owner") or "").strip(),
                        "criticality": (r.get("criticality") or "").strip().lower(),
                    }
                )
    except OSError as exc:
        raise OpmlError(f"Could not read inventory file {path}: {exc}") from exc
    return rows


def _cpe_matches_inventory(cpe: str, product: str, version: str) -> bool:
    """Return True if a CPE 2.3 string plausibly matches a (product, version) pair.

    A match requires:
      - The product token appears in the CPE's vendor or product slot.
      - The CPE's version slot is '*' (any version vulnerable) OR exactly equals
        the inventory version.

    Both comparisons are lowercase.
    """
    if not cpe.startswith("cpe:2.3:") and not cpe.startswith("cpe:/"):
        return False
    parts = cpe.lower().split(":")
    if len(parts) < 6:
        return False
    cpe_vendor = parts[3]
    cpe_product = parts[4]
    cpe_version = parts[5]
    pl = (product or "").lower()
    if not pl:
        return False
    if pl not in cpe_vendor and pl not in cpe_product:
        return False
    return not (cpe_version != "*" and version and cpe_version != version.lower())


def correlate_inventory(
    enriched: list[EnrichedCve],
    inventory: list[dict[str, str]],
) -> list[EnrichedCve]:
    """Annotate each EnrichedCve with hosts whose inventory row matches a CPE.

    For each (cve, host) pair: if any of the CVE's CPEs matches the host's
    product+version (or its explicit cpe column), the host is added to
    rec.affected_hosts. When the inventory carries a ``criticality`` column,
    the most-critical tier across the matched hosts is recorded on
    ``rec.affected_host_criticality`` (tier1 > tier2 > tier3); missing /
    empty criticality cells contribute nothing to that pick. Returns the
    same list for chaining.
    """
    for rec in enriched:
        hits: list[str] = []
        host_tiers: list[str | None] = []
        for inv in inventory:
            host = inv["host"]
            if not host or host in hits:
                continue
            matched = False
            inv_cpe = inv.get("cpe") or ""
            if inv_cpe:
                inv_cpe_l = inv_cpe.lower()
                matched = any(inv_cpe_l in c.lower() or c.lower() in inv_cpe_l for c in rec.cpes)
            else:
                for cpe in rec.cpes:
                    if _cpe_matches_inventory(cpe, inv["product"], inv["version"]):
                        matched = True
                        break
            if matched:
                hits.append(host)
                host_tiers.append(inv.get("criticality") or None)
        rec.affected_hosts = hits
        rec.affected_host_criticality = worst_criticality(host_tiers)
    return enriched
