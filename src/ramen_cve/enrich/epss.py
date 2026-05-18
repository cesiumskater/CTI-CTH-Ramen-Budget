"""ramen_cve.enrich.epss — EPSS score fetch (Layer-2, network)."""
from __future__ import annotations

import logging

import requests

from ..cache import Cache
from ..constants import EPSS_API_BASE, USER_AGENT

_log = logging.getLogger(__name__)


def fetch_epss(
    cve_ids: list[str],
    cache: Cache,
    score_date: str | None = None,
) -> dict[str, dict]:
    """Fetch EPSS scores for a list of CVE IDs, batching up to 100 per request.

    score_date is 'YYYY-MM-DD' for historical lookup or None for current.
    Returns {cve_id: {"epss": float, "percentile": float, "date": str}}.
    Never raises — on error the affected batch's CVEs are absent from the result.
    """
    if not cve_ids:
        return {}

    cache_key_date = score_date or "current"
    result: dict[str, dict] = {}
    misses: list[str] = []

    for cve_id in cve_ids:
        cached = cache.get_epss(cve_id, cache_key_date)
        if cached is not None:
            result[cve_id] = cached
        else:
            misses.append(cve_id)

    batch_size = 100
    for i in range(0, len(misses), batch_size):
        batch = misses[i : i + batch_size]
        params: dict[str, str] = {"cve": ",".join(batch)}
        if score_date:
            params["date"] = score_date
        try:
            resp = requests.get(
                EPSS_API_BASE, params=params, headers={"User-Agent": USER_AGENT}, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            _log.warning("EPSS fetch failed for batch starting %s: %s", batch[0], exc)
            continue

        for entry in data.get("data", []):
            cve_id = entry.get("cve", "").upper()
            if not cve_id:
                continue
            payload = {
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
                "date": entry.get("date", score_date or ""),
            }
            cache.set_epss(cve_id, cache_key_date, payload)
            result[cve_id] = payload

    return result

