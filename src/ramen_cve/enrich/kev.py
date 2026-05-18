"""ramen_cve.enrich.kev — CISA KEV catalog fetch (Layer-2, network)."""
from __future__ import annotations

import logging

import requests

from ..cache import Cache
from ..constants import CISA_KEV_URL, USER_AGENT

_log = logging.getLogger(__name__)


def fetch_kev_catalog(cache: Cache) -> dict[str, dict]:
    """Fetch the CISA Known Exploited Vulnerabilities catalog.

    Returns a dict keyed by upper-case CVE ID, where each value is the raw
    KEV record (dueDate, requiredAction, knownRansomwareCampaignUse,
    vendorProject, product, shortDescription, etc.). The catalog is cached
    as a single blob for the cache TTL (24h by default).

    Never raises: on network/parse failure, returns an empty dict and logs a
    warning so the rest of the pipeline can fall back to the NVD-derived
    kev_listed flag without the authoritative metadata.
    """
    cached = cache.get_kev_catalog()
    if cached is not None:
        return cached

    try:
        resp = requests.get(CISA_KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        _log.warning("CISA KEV catalog fetch failed: %s", exc)
        return {}

    catalog: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = (entry.get("cveID") or "").upper()
        if cve_id:
            catalog[cve_id] = entry

    cache.set_kev_catalog(catalog)
    _log.info("Loaded CISA KEV catalog: %d entries.", len(catalog))
    return catalog

