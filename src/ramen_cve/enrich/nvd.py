"""ramen_cve.enrich.nvd — NVD CVE fetch + parse (Layer-2, network)."""
from __future__ import annotations

import logging
import time

import requests

from ..cache import Cache
from ..constants import NVD_API_BASE, USER_AGENT
from ..keyring import _redact_key

_log = logging.getLogger(__name__)


def fetch_nvd(cve_id: str, cache: Cache, api_key: str | None) -> dict:
    """Fetch NVD CVSS data for a single CVE, using the cache when possible.

    Returns a normalized dict with keys: cvss_score, cvss_severity,
    cvss_vector, cvss_version, kev_listed, cwe, nvd_published, nvd_status.
    Never raises — on HTTP error returns a record with nvd_status='error'.

    Rate limit: sleeps just enough to keep us under the NVD per-window
    limit, but only if a previous call was made recently. The first call
    in a run does not pay the full delay.
    """
    cached = cache.get_nvd(cve_id)
    if cached is not None:
        return cached

    delay = 0.6 if api_key else 6.0
    last = getattr(fetch_nvd, "_last_call", 0.0)
    elapsed = time.monotonic() - last
    if elapsed < delay:
        time.sleep(delay - elapsed)
    fetch_nvd._last_call = time.monotonic()

    headers = {"User-Agent": USER_AGENT}
    params: dict[str, str] = {"cveId": cve_id}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
        if resp.status_code in (401, 403):
            safe_url = _redact_key(f"{NVD_API_BASE}?cveId={cve_id}")
            _log.warning(
                "NVD rejected the API key for %s (%s status %s)",
                cve_id,
                safe_url,
                resp.status_code,
            )
            # Auth errors are NOT cached: a fresh key should be retried immediately.
            return _empty_nvd(cve_id, status="auth_error")
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        safe_url = _redact_key(f"{NVD_API_BASE}?cveId={cve_id}")
        _log.warning("NVD fetch failed for %s (%s): %s", cve_id, safe_url, exc)
        result = _empty_nvd(cve_id, status="error")
        cache.set_nvd(cve_id, result)
        return result

    result = _parse_nvd_response(data)
    cache.set_nvd(cve_id, result)
    return result


def _empty_nvd(cve_id: str, status: str = "ok") -> dict:
    """Return an empty NVD result dict."""
    return {
        "cve_id": cve_id,
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "cvss_version": None,
        "kev_listed": False,
        "cwe": [],
        "nvd_published": None,
        "nvd_status": status,
    }


def _parse_nvd_response(data: dict) -> dict:
    """Extract normalized fields from a raw NVD API v2.0 response."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return _empty_nvd("", status="not_found")

    cve_data = vulns[0].get("cve", {})
    cve_id = cve_data.get("id", "")

    metrics = cve_data.get("metrics", {})
    cvss_score = cvss_severity = cvss_vector = cvss_version = None

    for metric_key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(metric_key, [])
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cv = primary.get("cvssData", {})
            cvss_score = cv.get("baseScore")
            cvss_severity = cv.get("baseSeverity")
            cvss_vector = cv.get("vectorString")
            cvss_version = version
            break

    kev_listed = bool(cve_data.get("cisaExploitAdd"))

    cwe: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-noinfo":
                cwe.append(val)

    published_str = cve_data.get("published")
    nvd_published = published_str[:10] if published_str else None

    # Walk configurations[].nodes[].cpeMatch[] for CPE 2.3 strings. NVD
    # responses sometimes nest cpeMatch under children; iterate defensively.
    cpes: list[str] = []
    seen_cpes: set[str] = set()

    def _collect_cpes(nodes: list) -> None:
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                if criteria and criteria not in seen_cpes:
                    seen_cpes.add(criteria)
                    cpes.append(criteria)
            _collect_cpes(node.get("children") or [])

    for cfg in cve_data.get("configurations") or []:
        _collect_cpes(cfg.get("nodes") or [])

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "kev_listed": kev_listed,
        "cwe": cwe,
        "cpes": cpes,
        "nvd_published": nvd_published,
        "nvd_status": "ok",
    }

