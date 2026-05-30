"""ramen_cve.enrich.iocs — IOC reputation enrichers (Layer-2).

VirusTotal / AbuseIPDB / OTX / MalwareBazaar lookups. Network.
See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import logging
import urllib.parse

import requests

from ..cache import Cache
from ..constants import USER_AGENT
from ..models import IocRecord

_log = logging.getLogger(__name__)


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
OTX_API_BASE = "https://otx.alienvault.com/api/v1"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


class _EnricherBase:
    """Abstract base for IOC enrichers.

    Subclasses set `name`, declare which IOC types they support via
    `supports()`, and implement `_fetch()` to do the actual HTTP call. The
    base class wraps `_fetch` with cache lookup + write so subclasses don't
    repeat that boilerplate.
    """

    name: str = ""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return False

    def enrich(self, ioc_type: str, value: str, cache: Cache) -> dict | None:
        cached = cache.get_enrichment(self.name, ioc_type, value)
        if cached is not None:
            return cached
        try:
            payload = self._fetch(ioc_type, value)
        except Exception as exc:
            _log.warning("%s enrichment failed for %s=%s: %s", self.name, ioc_type, value, exc)
            return None
        if payload is None:
            return None
        cache.set_enrichment(self.name, ioc_type, value, payload)
        return payload

    def _fetch(self, ioc_type: str, value: str) -> dict | None:
        raise NotImplementedError


class VirusTotalEnricher(_EnricherBase):
    """VirusTotal v3 — IPs, domains, URLs, file hashes (gated on VT_API_KEY)."""

    name = "virustotal"
    SUPPORTED = frozenset({"ipv4", "domain", "url", "md5", "sha1", "sha256"})

    def supports(self, ioc_type: str) -> bool:
        return bool(self.api_key) and ioc_type in self.SUPPORTED

    def _fetch(self, ioc_type: str, value: str) -> dict | None:
        import base64

        if ioc_type == "ipv4":
            url = f"{VIRUSTOTAL_API_BASE}/ip_addresses/{value}"
        elif ioc_type == "domain":
            url = f"{VIRUSTOTAL_API_BASE}/domains/{value}"
        elif ioc_type == "url":
            # VT requires URL → base64url(no padding) for the path id.
            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")
            url = f"{VIRUSTOTAL_API_BASE}/urls/{url_id}"
        else:  # md5 / sha1 / sha256
            url = f"{VIRUSTOTAL_API_BASE}/files/{value}"

        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "x-apikey": self.api_key or ""},
            timeout=30,
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        data = resp.json().get("data") or {}
        attrs = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "found": True,
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "reputation": attrs.get("reputation"),
            "url": f"https://www.virustotal.com/gui/search/{value}",
        }


class AbuseIPDBEnricher(_EnricherBase):
    """AbuseIPDB — IP reputation only (gated on ABUSEIPDB_API_KEY)."""

    name = "abuseipdb"
    SUPPORTED = frozenset({"ipv4"})

    def supports(self, ioc_type: str) -> bool:
        return bool(self.api_key) and ioc_type in self.SUPPORTED

    def _fetch(self, ioc_type: str, value: str) -> dict | None:
        resp = requests.get(
            f"{ABUSEIPDB_API_BASE}/check",
            headers={
                "User-Agent": USER_AGENT,
                "Key": self.api_key or "",
                "Accept": "application/json",
            },
            params={"ipAddress": value, "maxAgeInDays": "90"},
            timeout=30,
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
        return {
            "found": True,
            "abuse_confidence": int(data.get("abuseConfidenceScore") or 0),
            "total_reports": int(data.get("totalReports") or 0),
            "country_code": data.get("countryCode"),
            "url": f"https://www.abuseipdb.com/check/{value}",
        }


class OtxEnricher(_EnricherBase):
    """AlienVault OTX — IPs, domains, URLs, file hashes (gated on OTX_API_KEY)."""

    name = "otx"
    SUPPORTED = frozenset({"ipv4", "domain", "url", "md5", "sha1", "sha256"})

    _OTX_TYPE_MAP = {
        "ipv4": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    def supports(self, ioc_type: str) -> bool:
        return bool(self.api_key) and ioc_type in self.SUPPORTED

    def _fetch(self, ioc_type: str, value: str) -> dict | None:
        otx_type = self._OTX_TYPE_MAP[ioc_type]
        # OTX requires URL-encoding the value; urllib.parse.quote handles it.
        encoded = urllib.parse.quote(value, safe="")
        url = f"{OTX_API_BASE}/indicators/{otx_type}/{encoded}/general"
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "X-OTX-API-KEY": self.api_key or ""},
            timeout=30,
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        data = resp.json() or {}
        pulses = (data.get("pulse_info") or {}).get("count")
        return {
            "found": True,
            "pulse_count": int(pulses or 0),
            "reputation": data.get("reputation"),
            "url": f"https://otx.alienvault.com/indicator/{otx_type}/{encoded}",
        }


class MalwareBazaarEnricher(_EnricherBase):
    """MalwareBazaar (abuse.ch) — file hashes only, no API key required."""

    name = "malwarebazaar"
    SUPPORTED = frozenset({"md5", "sha1", "sha256"})

    def __init__(self, api_key: str | None = None) -> None:
        # MalwareBazaar is open; we still pass api_key to satisfy the base class
        # signature, but supports() doesn't gate on it.
        super().__init__(api_key=api_key)

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.SUPPORTED

    def _fetch(self, ioc_type: str, value: str) -> dict | None:
        resp = requests.post(
            MALWAREBAZAAR_API,
            data={"query": "get_info", "hash": value},
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        if (body.get("query_status") or "").lower() != "ok":
            return {"found": False}
        rows = body.get("data") or []
        if not rows:
            return {"found": False}
        first = rows[0]
        return {
            "found": True,
            "file_name": first.get("file_name"),
            "file_type": first.get("file_type"),
            "signature": first.get("signature"),
            "tags": list(first.get("tags") or []),
            "url": f"https://bazaar.abuse.ch/sample/{first.get('sha256_hash', '')}",
        }


def _build_default_enrichers() -> list[_EnricherBase]:
    """Return the default ordered list of enrichers, gated by environment keys."""
    import os

    return [
        VirusTotalEnricher(os.getenv("VT_API_KEY") or None),
        AbuseIPDBEnricher(os.getenv("ABUSEIPDB_API_KEY") or None),
        OtxEnricher(os.getenv("OTX_API_KEY") or None),
        MalwareBazaarEnricher(),
    ]


def enrich_iocs(
    iocs: list[IocRecord],
    cache: Cache,
    enrichers: list[_EnricherBase] | None = None,
) -> list[IocRecord]:
    """Run each enricher against each IOC it supports; mutate iocs in place.

    Per-(enricher, ioc_type, value) results are cached for the cache TTL so
    re-runs don't re-hit the upstream APIs. Returns the same list for chaining.
    """
    if enrichers is None:
        enrichers = _build_default_enrichers()
    for ioc in iocs:
        for enricher in enrichers:
            if not enricher.supports(ioc.ioc_type):
                continue
            payload = enricher.enrich(ioc.ioc_type, ioc.value, cache)
            if payload is not None:
                ioc.enrichments[enricher.name] = payload
    return iocs

