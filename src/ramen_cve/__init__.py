#!/usr/bin/env python3
"""ramen_cve — Threat intel triage on a ramen budget.

Reads an OPML file, a single URL, or a list of CVE IDs; extracts CVE
identifiers via regex; enriches each with CVSS (NVD) and EPSS (FIRST.org)
data; buckets by exploitation likelihood and impact (CISA KEV as a hard
override); and writes a CSV and a Markdown report.

Navigation index — see REFACTOR_PLAN.md for the target ramen_cve/ package
layout these sections will map to when the single-file design is split up.
Use the section names with grep / your editor's outline view; line numbers
will drift.

  Section                                                Future module
  --------------------------------------------------     -----------------------
  Imports + module constants                             cli.py (top of)
  ATT&CK / Kill-Chain mappers                            analyze.py
  _utcnow + TLP / Admiralty math                         analyze.py
  Exceptions (OpmlError)                                 models.py
  Dataclasses (FeedEntry .. EnrichedCve)                 models.py
  Cache (SQLite + every *_cache + runs + audit_log)      cache.py
  parse_opml + extract_cves + extract_iocs + defang      extract.py
  IOC confidence decay (_ioc_confidence, apply_*)        decay.py
  API-key bootstrap                                      cli.py / wizard.py
  fetch_nvd / _parse_nvd_response                        enrich/nvd.py
  fetch_epss                                             enrich/epss.py
  fetch_kev_catalog                                      enrich/kev.py
  load_associations + _build_*                           associations.py
  enrich_cves                                            enrich/orchestrator.py
  exploit/PoC tracker                                    enrich/exploits.py
  _EnricherBase + VT/AbuseIPDB/OTX/MalwareBazaar         enrich/iocs.py
  load_inventory + correlate_inventory                   enrich/inventory.py
  Dispatchers (Slack / Webhook / Email)                  dispatch/*.py
  bucket_and_suggest + filter_by_date                    analyze.py
  CSV / STIX / Sigma / YARA / Markdown writers           output/*.py
  CLI parser + main + _audit_dispatch + _maybe_* helpers cli.py
  _run_opml / _run_url / _run_cve / _run_stix            cli.py
  _run_hunt + Hunt I/O                                   hunt.py
  _run_pir + PIR I/O                                     pir.py
  _run_trend + _sparkline + _record_runs                 trend.py
  _run_audit + _redact_audit_args                        audit.py
  _run_wizard + path validators                          wizard.py
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import logging
import math
import re
import sys
import time
import urllib.parse
from datetime import date
from pathlib import Path

import requests

from .analyze import (  # noqa: F401
    CWE_TO_KILL_CHAIN,
    KILL_CHAIN_PHASES,
    _admiralty_score,
    _best_admiralty,
    _normalize_tlp,
    _worst_tlp,
    bucket_and_suggest,
    filter_by_date,
    map_cwes_to_attack_techniques,
    map_cwes_to_kill_chain,
)
from .cache import Cache  # noqa: F401

# Constants moved to the Layer-0 `constants` leaf; re-exported so
# `from ramen_cve import X` / `ramen_cve.X` keep working (facade).
from .constants import (  # noqa: F401
    _DEFANG_DETECT,
    _DEFANG_MAP,
    _FILE_EXT_TLDS,
    ATTACK_TECHNIQUE_NAMES,
    BUCKET_ACTIONS,
    CISA_KEV_URL,
    CVE_REGEX,
    CWE_TO_ATTACK,
    DEFAULT_ASSOCIATIONS_PATH,
    DEFAULT_CACHE_PATH,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_TEMPLATE,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_DATA_DIR,
    DEFAULT_EPSS_THRESHOLD,
    DEFAULT_HUNT_DIR,
    DEFAULT_LAST_OPML_PATH,
    DEFAULT_PIR_DIR,
    DEFAULT_PRESETS_DIR,
    DOMAIN_REGEX,
    EMAIL_REGEX,
    EPSS_API_BASE,
    EXPLOIT_STATUS_VALUES,
    EXPLOITDB_CSV_URL,
    GITHUB_SEARCH_URL,
    HUNT_STATUSES,
    IPV4_REGEX,
    MD5_REGEX,
    NUCLEI_TEMPLATES_TREE_URL,
    NVD_API_BASE,
    PIR_STATUSES,
    SHA1_REGEX,
    SHA256_REGEX,
    TLP_LEVELS,
    URL_REGEX,
    USER_AGENT,
)
from .extract import (  # noqa: F401
    _defang_text,
    _is_likely_filename,
    _is_public_ip,
    extract_cves,
    extract_iocs,
    parse_opml,
)
from .models import (  # noqa: F401
    Campaign,
    CveRecord,
    EnrichedCve,
    FeedEntry,
    Hunt,
    IocRecord,
    Malware,
    OpmlError,
    Pir,
    ThreatActor,
    _utcnow,
)

_log = logging.getLogger(__name__)


IOC_HALF_LIFE_DAYS: dict[str, int] = {
    "ipv4": 30,
    "domain": 90,
    "url": 30,
    "email": 90,
    "md5": 0,
    "sha1": 0,
    "sha256": 0,
}


def _ioc_confidence(
    ioc_type: str,
    last_seen: date | None,
    today: date | None = None,
) -> float:
    """Return a 0..1 confidence score for an indicator given when it was last seen.

    confidence = exp(-ln(2) * age_days / half_life)
    age_days < 0 (clock skew) is clamped to 0 → 1.0.
    half_life = 0 in IOC_HALF_LIFE_DAYS means "no decay" → 1.0.
    A missing last_seen returns 1.0 (the IOC was just observed by definition
    of being in the current run); callers that want stricter behavior should
    pass an explicit last_seen.
    """
    if last_seen is None:
        return 1.0
    half_life = IOC_HALF_LIFE_DAYS.get(ioc_type, 30)
    if half_life <= 0:
        return 1.0
    today = today or date.today()
    age_days = max(0, (today - last_seen).days)
    return math.exp(-math.log(2) * age_days / half_life)


def apply_ioc_decay(iocs: list[IocRecord], today: date | None = None) -> list[IocRecord]:
    """Set rec.confidence on every IOC using the exponential half-life model.

    Mutates and returns the same list for chaining. `last_seen` falls back to
    `first_seen` when not set, so a freshly-extracted IOC defaults to 1.0.
    """
    today = today or date.today()
    for ioc in iocs:
        anchor = ioc.last_seen or ioc.first_seen
        ioc.confidence = _ioc_confidence(ioc.ioc_type, anchor, today)
    return iocs


def filter_iocs_by_confidence(iocs: list[IocRecord], floor: float) -> list[IocRecord]:
    """Drop IOCs whose confidence is below the floor. A floor of 0 keeps every IOC."""
    if floor <= 0:
        return list(iocs)
    return [i for i in iocs if (i.confidence or 0.0) >= floor]


def _redact_key(url: str) -> str:
    """Replace the apiKey query parameter value with REDACTED."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if "apiKey" in qs:
        qs["apiKey"] = ["REDACTED"]
    safe_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=safe_query))


NVD_API_KEY_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
NVD_KEY_REQUEST_URL = "https://nvd.nist.gov/developers/request-an-api-key"
ENV_FILE_PATH = Path(".env")


def _is_interactive() -> bool:
    """True if both stdin and stderr are TTYs (so prompting makes sense)."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def _save_api_key_to_env(key: str, env_path: Path = ENV_FILE_PATH) -> None:
    """Persist NVD_API_KEY=<key> to a local .env file.

    If the file exists, replace any existing NVD_API_KEY line; otherwise
    append. The file is created with mode 0o600 so the key is not
    world-readable. Other variables already in .env are preserved.

    Raises ValueError if the key contains a newline, carriage return, or
    NUL byte. Without this guard, an attacker who controls the input
    could inject additional VAR=value lines into .env.
    """
    if any(ch in key for ch in ("\n", "\r", "\x00")):
        raise ValueError("API key contains illegal control characters; refusing to write .env.")
    new_line = f"NVD_API_KEY={key}\n"
    if env_path.exists():
        existing = env_path.read_text().splitlines(keepends=True)
        replaced = False
        out_lines: list[str] = []
        for line in existing:
            if line.strip().startswith("NVD_API_KEY="):
                out_lines.append(new_line)
                replaced = True
            else:
                out_lines.append(line)
        if not replaced:
            if out_lines and not out_lines[-1].endswith("\n"):
                out_lines[-1] += "\n"
            out_lines.append(new_line)
        env_path.write_text("".join(out_lines))
    else:
        env_path.write_text(new_line)
    with contextlib.suppress(OSError):
        env_path.chmod(0o600)  # Best-effort; some filesystems (e.g. Windows) don't support it.


def _prompt_for_api_key(reason: str = "missing") -> str | None:
    """Interactively ask the user for an NVD API key and save it to .env.

    `reason` is one of "missing" (no key on disk) or "expired" (server
    rejected the existing key). Returns the new key string, or None if
    the user declined to enter one.
    """
    if not _is_interactive():
        return None

    if reason == "expired":
        message = (
            "\nThe NVD API key currently in use was rejected by the server "
            "(likely expired or revoked)."
        )
    else:
        message = "\nNo NVD API key found in environment or .env file."
    print(message, file=sys.stderr)
    print(
        f"You can request a free key at: {NVD_KEY_REQUEST_URL}\n"
        "  - With a key: ~50 requests per 30s window (recommended)\n"
        "  - Without a key: ~5 requests per 30s window\n",
        file=sys.stderr,
    )

    try:
        import questionary

        action = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("Enter a key now (saved to .env)", value="enter"),
                questionary.Choice("Continue without a key (slower)", value="skip"),
            ],
        ).unsafe_ask()
        if action != "enter":
            return None
        key = questionary.password(
            "Paste your NVD API key (input is hidden):",
            validate=lambda s: (
                True if NVD_API_KEY_REGEX.match(s.strip())
                else "Expected UUID format (8-4-4-4-12 hex chars)."
            ),
        ).unsafe_ask()
    except (KeyboardInterrupt, ImportError):
        return None

    if not key:
        return None
    key = key.strip()
    _save_api_key_to_env(key)
    print(f"Saved NVD_API_KEY to {ENV_FILE_PATH} (mode 0600).", file=sys.stderr)
    return key


def _safe_url_for_log(url: str) -> str:
    """Strip query string and fragment from a user-supplied URL before logging it.

    Arbitrary URLs may carry tokens, session IDs, or other secrets in the
    query string. We can't tell which params are sensitive, so the safest
    thing to log is scheme + host + path only.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return "<unparseable url>"
    sanitized = parsed._replace(query="", fragment="")
    rendered = urllib.parse.urlunparse(sanitized)
    if parsed.query or parsed.fragment:
        rendered += " (query/fragment redacted)"
    return rendered


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


def enrich_cves(
    records: list[CveRecord],
    cache: Cache,
    api_key: str | None,
    associations: dict[str, dict[str, list]] | None = None,
) -> list[EnrichedCve]:
    """Fetch NVD, EPSS, and CISA KEV data for each unique CVE and return enriched records.

    Deduplicates CVE IDs before hitting the APIs. When the same CVE appears in
    multiple records, only the earliest first_seen date is kept.

    If `associations` is provided, each enriched record is also annotated with
    the linked actors, campaigns, and malware for that CVE.
    """
    # Deduplicate: keep earliest first_seen per CVE, but merge TLP / Admiralty
    # across every input record so the most-restrictive sharing tag and the
    # highest-confidence source rating both reach the EnrichedCve.
    earliest: dict[str, CveRecord] = {}
    merged_tlp: dict[str, str] = {}
    merged_adm: dict[str, str] = {}
    for rec in records:
        if rec.cve_id not in earliest or rec.first_seen < earliest[rec.cve_id].first_seen:
            earliest[rec.cve_id] = rec
        merged_tlp[rec.cve_id] = _worst_tlp(merged_tlp.get(rec.cve_id), rec.tlp)
        merged_adm[rec.cve_id] = _best_admiralty(merged_adm.get(rec.cve_id), rec.admiralty)

    unique_ids = list(earliest.keys())

    # Fetch NVD data for each unique CVE. If the server rejects the API key
    # (401/403), prompt for a new one ONCE and retry the failed CVE plus all
    # remaining ones with the fresh key.
    nvd_data: dict[str, dict] = {}
    reprompted = False
    for cve_id in unique_ids:
        result = fetch_nvd(cve_id, cache, api_key)
        if result.get("nvd_status") == "auth_error" and not reprompted and api_key:
            reprompted = True
            new_key = _prompt_for_api_key(reason="expired")
            if new_key:
                api_key = new_key
                result = fetch_nvd(cve_id, cache, api_key)
        nvd_data[cve_id] = result

    # Fetch EPSS data in one batched call
    epss_data = fetch_epss(unique_ids, cache)

    # Fetch the authoritative CISA KEV catalog (one HTTP call, cached).
    kev_catalog = fetch_kev_catalog(cache)

    enriched: list[EnrichedCve] = []
    for cve_id, rec in earliest.items():
        nvd = nvd_data.get(cve_id, {})
        epss = epss_data.get(cve_id, {})
        kev = kev_catalog.get(cve_id, {})

        nvd_pub_str = nvd.get("nvd_published")
        nvd_published: date | None = None
        if nvd_pub_str:
            try:
                nvd_published = date.fromisoformat(nvd_pub_str)
            except (TypeError, ValueError):
                _log.warning(
                    "NVD returned an unparseable published date %r for %s; ignoring.",
                    nvd_pub_str,
                    cve_id,
                )

        # CISA's catalog is the authoritative source for KEV membership; if it
        # answers, prefer it over NVD's cisaExploitAdd flag. Either signal alone
        # is enough to treat the CVE as KEV-listed.
        kev_listed = bool(kev) or nvd.get("kev_listed", False)

        enriched.append(
            EnrichedCve(
                cve_id=cve_id,
                source=rec.source,
                first_seen=rec.first_seen,
                first_seen_type=rec.first_seen_type,
                cvss_score=nvd.get("cvss_score"),
                cvss_severity=nvd.get("cvss_severity"),
                cvss_vector=nvd.get("cvss_vector"),
                cvss_version=nvd.get("cvss_version"),
                kev_listed=kev_listed,
                cwe=nvd.get("cwe", []),
                nvd_published=nvd_published,
                nvd_status=nvd.get("nvd_status", "ok"),
                epss_score=epss.get("epss"),
                epss_percentile=epss.get("percentile"),
                epss_date=epss.get("date"),
                kev_due_date=_parse_kev_due_date(kev.get("dueDate")) if kev else None,
                kev_required_action=kev.get("requiredAction") if kev else None,
                kev_known_ransomware_use=(
                    (kev.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
                ),
                kev_vendor_project=kev.get("vendorProject") if kev else None,
                kev_product=kev.get("product") if kev else None,
                kev_short_description=kev.get("shortDescription") if kev else None,
                attack_techniques=map_cwes_to_attack_techniques(nvd.get("cwe", [])),
                tlp=merged_tlp.get(cve_id, "CLEAR"),
                admiralty=merged_adm.get(cve_id, ""),
                cpes=list(nvd.get("cpes") or []),
                kill_chain_phase=map_cwes_to_kill_chain(nvd.get("cwe", [])),
            )
        )

    if associations:
        for rec in enriched:
            assoc = associations.get(rec.cve_id)
            if assoc:
                rec.linked_actors = list(assoc.get("actors") or [])
                rec.linked_campaigns = list(assoc.get("campaigns") or [])
                rec.linked_malware = list(assoc.get("malware") or [])

    # Diamond Model adversary defaults to the first linked actor; capability
    # adds the primary CWE/technique label so the Diamond line in Markdown is
    # actually informative rather than just the literal word "capability".
    for rec in enriched:
        if rec.linked_actors and not rec.diamond_adversary:
            rec.diamond_adversary = rec.linked_actors[0].name
        cap_bits: list[str] = []
        if rec.cwe:
            cap_bits.append(rec.cwe[0])
        if rec.attack_techniques:
            cap_bits.append(rec.attack_techniques[0])
        if cap_bits:
            rec.diamond_capability = "exploit (" + ", ".join(cap_bits) + ")"

    return enriched


def fetch_exploitdb_cve_set(cache: Cache) -> set[str]:
    """Return the set of CVE IDs that have at least one Exploit-DB entry.

    The Exploit-DB project publishes a CSV mirror of every entry; the `codes`
    column carries CVE IDs (semicolon-separated, sometimes mixed with OSVDB IDs
    or other refs). We pull the file once per cache TTL, scan the codes column,
    and persist the resulting set. On any error returns an empty set.
    """
    cached = cache.get_exploit("exploitdb", "index")
    if cached is not None:
        return set(cached.get("cve_ids", []))

    cve_ids: set[str] = set()
    try:
        resp = requests.get(EXPLOITDB_CSV_URL, headers={"User-Agent": USER_AGENT}, timeout=60)
        resp.raise_for_status()
        reader = csv.DictReader(resp.text.splitlines())
        for row in reader:
            codes = row.get("codes") or ""
            for code in codes.split(";"):
                normalized = code.strip().upper()
                if CVE_REGEX.fullmatch(normalized):
                    cve_ids.add(normalized)
    except Exception as exc:
        _log.warning("Exploit-DB index fetch failed: %s", exc)
        return set()

    cache.set_exploit("exploitdb", "index", {"cve_ids": sorted(cve_ids)})
    _log.info("Loaded Exploit-DB index: %d CVEs.", len(cve_ids))
    return cve_ids


def fetch_nuclei_cve_set(cache: Cache) -> set[str]:
    """Return the set of CVE IDs that have a Nuclei community template.

    Hits the GitHub Git Trees API once and filters paths under `cves/` ending
    in `.yaml`. Cached per the cache TTL. On any error returns an empty set.
    """
    cached = cache.get_exploit("nuclei", "index")
    if cached is not None:
        return set(cached.get("cve_ids", []))

    cve_ids: set[str] = set()
    try:
        resp = requests.get(
            NUCLEI_TEMPLATES_TREE_URL,
            headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("tree") or []:
            path = entry.get("path") or ""
            if "cves/" in path and path.endswith(".yaml"):
                for m in CVE_REGEX.finditer(path):
                    cve_ids.add(m.group(0).upper())
    except Exception as exc:
        _log.warning("Nuclei templates index fetch failed: %s", exc)
        return set()

    cache.set_exploit("nuclei", "index", {"cve_ids": sorted(cve_ids)})
    _log.info("Loaded Nuclei templates index: %d CVEs.", len(cve_ids))
    return cve_ids


def search_github_for_cve(cve_id: str, cache: Cache, github_token: str | None) -> bool:
    """Return True if a GitHub repository name or description references this CVE.

    Returns False (without an HTTP call) when no GITHUB_TOKEN is configured —
    the unauthenticated rate limit (10 req/min) is too low to be useful for a
    CVE-by-CVE scan. Cached per CVE for the cache TTL.
    """
    if not github_token:
        return False

    cached = cache.get_exploit("github", cve_id)
    if cached is not None:
        return bool(cached.get("found", False))

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
    }
    params = {"q": f"{cve_id} in:name,description", "per_page": "1"}
    try:
        resp = requests.get(GITHUB_SEARCH_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        _log.warning("GitHub search failed for %s: %s", cve_id, exc)
        return False

    found = (data.get("total_count") or 0) > 0
    cache.set_exploit("github", cve_id, {"found": found})
    return found


def enrich_with_exploit_status(
    enriched: list[EnrichedCve],
    cache: Cache,
    github_token: str | None = None,
    *,
    skip_github: bool = False,
) -> list[EnrichedCve]:
    """Set rec.exploit_status on each EnrichedCve in place.

    Resolution order (highest priority wins):
      1. exploit_db
      2. nuclei_template
      3. github_poc (only when github_token is set and skip_github=False)
      Default: 'none'.

    The bucket assignment is intentionally NOT changed — exploit_status is a
    parallel signal that consumers can act on directly. Returns the same list
    for chaining.
    """
    edb = fetch_exploitdb_cve_set(cache)
    nuclei = fetch_nuclei_cve_set(cache)
    for rec in enriched:
        if rec.cve_id in edb:
            rec.exploit_status = "exploit_db"
        elif rec.cve_id in nuclei:
            rec.exploit_status = "nuclei_template"
        elif not skip_github and github_token and search_github_for_cve(
            rec.cve_id, cache, github_token
        ):
            rec.exploit_status = "github_poc"
    return enriched


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


def load_inventory(path: Path) -> list[dict[str, str]]:
    """Load an inventory CSV with columns host, product, version (case-insensitive).

    Returns a list of dicts. Optional columns:
      - `cpe`: explicit CPE 2.3 string (skips product/version inference).
      - `owner`: an email address used by the --digest dispatcher to route
        per-asset patch summaries to the right recipient.
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
    rec.affected_hosts. Returns the same list for chaining.
    """
    for rec in enriched:
        hits: list[str] = []
        for inv in inventory:
            host = inv["host"]
            if not host or host in hits:
                continue
            matched = False
            inv_cpe = inv.get("cpe") or ""
            if inv_cpe:
                # Direct CPE compare: lowercase substring match against any rec CPE.
                inv_cpe_l = inv_cpe.lower()
                matched = any(inv_cpe_l in c.lower() or c.lower() in inv_cpe_l for c in rec.cpes)
            else:
                for cpe in rec.cpes:
                    if _cpe_matches_inventory(cpe, inv["product"], inv["version"]):
                        matched = True
                        break
            if matched:
                hits.append(host)
        rec.affected_hosts = hits
    return enriched


class _DispatcherBase:
    """Abstract base for outbound dispatchers (Slack, generic webhook, ...).

    Subclasses set `name`, gate themselves via `enabled()`, and implement
    `dispatch(rec)` to push one EnrichedCve to the configured target. dispatch()
    must NEVER raise — return False on failure.
    """

    name: str = ""

    def enabled(self) -> bool:
        return False

    def dispatch(self, rec: EnrichedCve) -> bool:
        raise NotImplementedError


class SlackWebhookDispatcher(_DispatcherBase):
    """Post a Block-Kit summary to a Slack incoming webhook (SLACK_WEBHOOK_URL)."""

    name = "slack"

    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _build_payload(self, rec: EnrichedCve) -> dict:
        emoji = {
            "kev_override": ":rotating_light:",
            "patch_now": ":rotating_light:",
            "plan_and_patch": ":construction:",
            "watch_closely": ":eyes:",
        }.get(rec.bucket, ":pushpin:")
        title = f"{emoji} {rec.cve_id} — {rec.bucket.replace('_', ' ').title()}"
        cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
        epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
        body_lines = [
            f"*Action:* {rec.suggested_action}",
            f"*CVSS:* {cvss} ({rec.cvss_severity or 'N/A'}) · *EPSS:* {epss}",
        ]
        if rec.kev_listed:
            kev_line = "*CISA KEV:* listed"
            if rec.kev_due_date:
                kev_line += f" (due {rec.kev_due_date})"
            if rec.kev_known_ransomware_use:
                kev_line += " — known ransomware use"
            body_lines.append(kev_line)
        if rec.attack_techniques:
            body_lines.append(f"*ATT&CK:* {', '.join(rec.attack_techniques)}")
        if rec.exploit_status and rec.exploit_status != "none":
            body_lines.append(f"*Exploit Status:* `{rec.exploit_status}`")
        if rec.linked_actors:
            body_lines.append(
                "*Linked Actors:* " + ", ".join(a.name for a in rec.linked_actors)
            )
        if rec.affected_hosts:
            body_lines.append(
                f"*Affected hosts:* {len(rec.affected_hosts)} in inventory"
            )
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title}},
                {"type": "section", "text": {"type": "mrkdwn",
                                             "text": "\n".join(body_lines)}},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"<https://nvd.nist.gov/vuln/detail/{rec.cve_id}|NVD>",
                        }
                    ],
                },
            ]
        }

    def dispatch(self, rec: EnrichedCve) -> bool:
        try:
            resp = requests.post(
                self.webhook_url or "",
                json=self._build_payload(rec),
                headers={"User-Agent": USER_AGENT},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            _log.warning("Slack dispatch failed for %s: %s", rec.cve_id, exc)
            return False


class GenericWebhookDispatcher(_DispatcherBase):
    """POST a JSON-serialized EnrichedCve summary to RAMEN_DISPATCH_WEBHOOK."""

    name = "webhook"

    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _build_payload(self, rec: EnrichedCve) -> dict:
        return {
            "cve_id": rec.cve_id,
            "bucket": rec.bucket,
            "suggested_action": rec.suggested_action,
            "cvss_score": rec.cvss_score,
            "cvss_severity": rec.cvss_severity,
            "epss_score": rec.epss_score,
            "kev_listed": rec.kev_listed,
            "kev_due_date": str(rec.kev_due_date) if rec.kev_due_date else None,
            "kev_known_ransomware_use": rec.kev_known_ransomware_use,
            "cwe": list(rec.cwe),
            "attack_techniques": list(rec.attack_techniques),
            "exploit_status": rec.exploit_status,
            "linked_actors": [a.name for a in rec.linked_actors],
            "linked_malware": [m.name for m in rec.linked_malware],
            "linked_campaigns": [c.name for c in rec.linked_campaigns],
            "affected_hosts": list(rec.affected_hosts),
            "tlp": rec.tlp,
            "admiralty": rec.admiralty,
        }

    def dispatch(self, rec: EnrichedCve) -> bool:
        try:
            resp = requests.post(
                self.webhook_url or "",
                json=self._build_payload(rec),
                headers={"User-Agent": USER_AGENT},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            _log.warning("Webhook dispatch failed for %s: %s", rec.cve_id, exc)
            return False


class EmailDispatcher:
    """SMTP-based daily-digest dispatcher.

    Unlike Slack / generic-webhook dispatchers, this one is BATCH-shaped: it
    sends one email per recipient summarizing the day's high-priority
    findings, with the CSV and Markdown reports attached. The caller is
    _maybe_digest(), which groups findings by inventory owner before invoking
    send_digest() once per recipient.

    Configured entirely via env (no CLI surface area for credentials):
      RAMEN_SMTP_HOST  (required)
      RAMEN_SMTP_PORT  (default 587)
      RAMEN_SMTP_USER  (optional)
      RAMEN_SMTP_PASS  (optional)
      RAMEN_SMTP_FROM  (required — 'From:' header / envelope-from)
      RAMEN_SMTP_USE_TLS=1 (default; set to 0 to disable STARTTLS)
      RAMEN_DIGEST_TO  (fallback recipient when no inventory owner matches)
    """

    name = "email"

    def __init__(
        self,
        host: str | None,
        port: int,
        user: str | None,
        password: str | None,
        sender: str | None,
        use_tls: bool,
        fallback_recipient: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sender = sender
        self.use_tls = use_tls
        self.fallback_recipient = fallback_recipient

    @classmethod
    def from_env(cls) -> EmailDispatcher:
        """Build a dispatcher from RAMEN_SMTP_* / RAMEN_DIGEST_TO env vars."""
        import os

        try:
            port = int(os.getenv("RAMEN_SMTP_PORT") or "587")
        except ValueError:
            port = 587
        use_tls = (os.getenv("RAMEN_SMTP_USE_TLS") or "1").strip().lower() not in (
            "0", "false", "no",
        )
        return cls(
            host=os.getenv("RAMEN_SMTP_HOST") or None,
            port=port,
            user=os.getenv("RAMEN_SMTP_USER") or None,
            password=os.getenv("RAMEN_SMTP_PASS") or None,
            sender=os.getenv("RAMEN_SMTP_FROM") or None,
            use_tls=use_tls,
            fallback_recipient=os.getenv("RAMEN_DIGEST_TO") or None,
        )

    def enabled(self) -> bool:
        """True only when both SMTP host and From address are configured."""
        return bool(self.host) and bool(self.sender)

    def _build_message(
        self,
        recipient: str,
        subject: str,
        body_markdown: str,
        attachments: list[Path],
    ) -> object:
        """Compose a MIME message with a text/plain body and binary attachments."""
        from email.mime.application import MIMEApplication
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart()
        msg["From"] = self.sender or ""
        msg["To"] = recipient
        msg["Subject"] = subject
        # Markdown is plain text; if the recipient's client renders MD they get
        # rich formatting, otherwise it reads fine as-is.
        msg.attach(MIMEText(body_markdown, "plain", "utf-8"))
        for path in attachments:
            if not path or not path.exists():
                continue
            try:
                payload = path.read_bytes()
            except OSError as exc:
                _log.warning("Could not attach %s to digest: %s", path, exc)
                continue
            part = MIMEApplication(payload, Name=path.name)
            part["Content-Disposition"] = f'attachment; filename="{path.name}"'
            msg.attach(part)
        return msg

    def send_digest(
        self,
        recipient: str,
        subject: str,
        body_markdown: str,
        attachments: list[Path] | None = None,
    ) -> bool:
        """Send one digest email. Returns True on success, False on any failure."""
        import smtplib

        if not self.enabled():
            _log.warning(
                "Email digest is enabled but RAMEN_SMTP_HOST / RAMEN_SMTP_FROM "
                "are not set; nothing was sent."
            )
            return False
        msg = self._build_message(recipient, subject, body_markdown, attachments or [])
        try:
            with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.user and self.password:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
            return True
        except Exception as exc:
            _log.warning("Email digest send to %s failed: %s", recipient, exc)
            return False


def _build_default_dispatchers() -> list[_DispatcherBase]:
    """Build the default ordered list of dispatchers, gated by environment vars."""
    import os

    return [
        SlackWebhookDispatcher(os.getenv("SLACK_WEBHOOK_URL") or None),
        GenericWebhookDispatcher(os.getenv("RAMEN_DISPATCH_WEBHOOK") or None),
    ]


# Default bucket transitions worth dispatching on. KEV is highest priority,
# patch_now is next; everything else is too low-signal for a chat ping.
DISPATCH_DEFAULT_BUCKETS: tuple[str, ...] = ("kev_override", "patch_now")


def dispatch_records(
    enriched: list[EnrichedCve],
    *,
    dispatch_on: tuple[str, ...] = DISPATCH_DEFAULT_BUCKETS,
    dispatchers: list[_DispatcherBase] | None = None,
) -> int:
    """Push records whose bucket is in `dispatch_on` to every enabled dispatcher.

    Returns the count of successful (record, dispatcher) posts. Failures are
    logged but do not abort the run.
    """
    if dispatchers is None:
        dispatchers = _build_default_dispatchers()
    enabled = [d for d in dispatchers if d.enabled()]
    if not enabled:
        _log.info(
            "Dispatch enabled but no dispatchers configured "
            "(set SLACK_WEBHOOK_URL or RAMEN_DISPATCH_WEBHOOK)."
        )
        return 0
    successes = 0
    for rec in enriched:
        if rec.bucket not in dispatch_on:
            continue
        for d in enabled:
            if d.dispatch(rec):
                successes += 1
    return successes


CSV_COLUMNS = [
    "cve_id",
    "source",
    "first_seen",
    "first_seen_type",
    "cvss_score",
    "cvss_severity",
    "epss_score",
    "epss_percentile",
    "kev_listed",
    "kev_due_date",
    "kev_known_ransomware_use",
    "kev_vendor_project",
    "kev_product",
    "bucket",
    "suggested_action",
    "cwe",
    "attack_techniques",
    "exploit_status",
    "linked_actors",
    "linked_campaigns",
    "linked_malware",
    "tlp",
    "admiralty",
    "affected_hosts",
    "kill_chain_phase",
    "diamond_capability",
    "diamond_adversary",
    "diamond_infrastructure",
    "diamond_victim",
    "nvd_published",
    "enriched_at",
]


IOC_CSV_COLUMNS = [
    "ioc_type",
    "value",
    "source",
    "first_seen",
    "first_seen_type",
    "defanged_in_source",
    "enrichments",
    "tlp",
    "admiralty",
    "last_seen",
    "confidence",
]


def write_iocs_csv(iocs: list[IocRecord], path: Path) -> None:
    """Write a CSV of non-CVE indicators alongside the main CVE CSV.

    Columns are in IOC_CSV_COLUMNS order. defanged_in_source is rendered as
    'true'/'false' so consumers can grep the file directly. The enrichments
    column is a JSON-serialized dict so the schema stays one-row-per-IOC.
    confidence is rendered to 4 decimals (1.0000 means just-seen / no decay).
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(IOC_CSV_COLUMNS)
        for rec in iocs:
            writer.writerow(
                [
                    rec.ioc_type,
                    rec.value,
                    rec.source,
                    str(rec.first_seen) if rec.first_seen else "",
                    rec.first_seen_type,
                    str(rec.defanged_in_source).lower(),
                    json.dumps(rec.enrichments) if rec.enrichments else "",
                    rec.tlp or "CLEAR",
                    rec.admiralty or "",
                    str(rec.last_seen) if rec.last_seen else "",
                    f"{rec.confidence:.4f}" if rec.confidence is not None else "",
                ]
            )


def _stix_uuid(seed: str) -> str:
    """Return a deterministic UUID-shaped string from a seed.

    STIX SDO IDs require UUID v4 form; using a SHA-256 of the seed lets two
    runs of the tool produce stable IDs for the same CVE/IOC, which is useful
    for downstream platforms doing diff/dedupe across imports.
    """
    import hashlib

    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    # Force version (4) and variant (8/9/a/b) nibbles as UUIDv4 requires.
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def _ioc_to_stix_pattern(ioc: IocRecord) -> str | None:
    """Convert an IocRecord into a minimal STIX 2.1 equality pattern.

    Returns None for IOC types we don't have a pattern mapping for so the caller
    can skip them silently rather than emit a malformed Indicator SDO.
    """
    v = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
    if ioc.ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if ioc.ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc.ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc.ioc_type == "email":
        return f"[email-addr:value = '{v}']"
    if ioc.ioc_type == "md5":
        return f"[file:hashes.MD5 = '{v}']"
    if ioc.ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if ioc.ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    return None


def write_stix(
    enriched: list[EnrichedCve],
    path: Path,
    iocs: list[IocRecord] | None = None,
    run_metadata: dict | None = None,
) -> None:
    """Write a STIX 2.1 bundle: one Vulnerability + Note per CVE, one Indicator per IOC.

    The bundle also contains a single Identity SDO (`name='ramen-cve'`) that
    every other object references via `created_by_ref` so downstream platforms
    can attribute the data.
    """
    iocs = iocs or []
    now = _utcnow().isoformat(timespec="seconds") + "Z"

    identity_id = f"identity--{_stix_uuid('ramen-cve-producer')}"
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "ramen-cve",
            "identity_class": "system",
            "description": "Triage report producer (https://github.com/cesiumskater).",
        }
    ]

    for rec in enriched:
        vuln_id = f"vulnerability--{_stix_uuid(rec.cve_id)}"
        external_refs = [
            {
                "source_name": "cve",
                "external_id": rec.cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{rec.cve_id}",
            }
        ]
        for cwe in rec.cwe:
            external_refs.append({"source_name": "cwe", "external_id": cwe})
        vuln: dict = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": rec.cve_id,
            "external_references": external_refs,
        }
        if rec.kev_short_description:
            vuln["description"] = rec.kev_short_description
        objects.append(vuln)

        note_lines: list[str] = [
            f"Bucket: {rec.bucket}",
            f"Action: {rec.suggested_action}",
        ]
        if rec.cvss_score is not None:
            note_lines.append(
                f"CVSS: {rec.cvss_score:.1f} ({rec.cvss_severity or 'N/A'})"
            )
        if rec.epss_score is not None:
            note_lines.append(f"EPSS: {rec.epss_score:.4f}")
        if rec.kev_listed:
            kev_line = "KEV: Listed"
            if rec.kev_due_date:
                kev_line += f" (due {rec.kev_due_date})"
            if rec.kev_known_ransomware_use:
                kev_line += " — known ransomware use"
            note_lines.append(kev_line)
        if rec.attack_techniques:
            note_lines.append("ATT&CK: " + ", ".join(rec.attack_techniques))
        if rec.exploit_status and rec.exploit_status != "none":
            note_lines.append(f"Exploit Status: {rec.exploit_status}")

        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": f"note--{_stix_uuid(rec.cve_id + ':note')}",
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "abstract": f"ramen-cve triage for {rec.cve_id}",
                "content": "\n".join(note_lines),
                "object_refs": [vuln_id],
            }
        )

    for ioc in iocs:
        pattern = _ioc_to_stix_pattern(ioc)
        if pattern is None:
            continue
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_stix_uuid(ioc.ioc_type + ':' + ioc.value)}",
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"],
            }
        )

    bundle = {
        "type": "bundle",
        "id": f"bundle--{_stix_uuid(now + ':' + str(len(objects)))}",
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")


# Equality-pattern parser for our own emit format. We don't try to parse the
# full STIX pattern grammar; we look for `[<obj-type>:<prop> = '<value>']`.
_STIX_PATTERN_RE = re.compile(
    r"\[\s*(?P<obj>ipv4-addr|url|domain-name|email-addr|file)"
    r"(?P<prop>:value|:hashes\.'?(?:MD5|SHA-1|SHA-256)'?)"
    r"\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'\s*\]",
    re.IGNORECASE,
)


def _extract_iocs_from_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract (ioc_type, value) tuples from a STIX 2.1 equality pattern."""
    out: list[tuple[str, str]] = []
    for m in _STIX_PATTERN_RE.finditer(pattern):
        obj = m.group("obj").lower()
        prop = m.group("prop").lower()
        raw = m.group("value")
        # Reverse the STIX string-literal escape (\' and \\)
        value = raw.replace("\\'", "'").replace("\\\\", "\\")
        if obj == "ipv4-addr":
            out.append(("ipv4", value))
        elif obj == "url":
            out.append(("url", value))
        elif obj == "domain-name":
            out.append(("domain", value))
        elif obj == "email-addr":
            out.append(("email", value))
        elif obj == "file":
            if "md5" in prop:
                out.append(("md5", value))
            elif "sha-1" in prop:
                out.append(("sha1", value))
            elif "sha-256" in prop:
                out.append(("sha256", value))
    return out


def _extract_cve_id_from_vuln(obj: dict) -> str | None:
    """Pull a CVE ID out of a STIX Vulnerability SDO (name field or external_references)."""
    name = (obj.get("name") or "").upper()
    if CVE_REGEX.fullmatch(name):
        return name
    for ref in obj.get("external_references") or []:
        if (ref.get("source_name") or "").lower() == "cve":
            ext_id = (ref.get("external_id") or "").upper()
            if CVE_REGEX.fullmatch(ext_id):
                return ext_id
    return None


def parse_stix_bundle(path: Path) -> tuple[list[CveRecord], list[IocRecord]]:
    """Parse a STIX 2.1 bundle JSON file into CveRecord + IocRecord lists.

    Vulnerability SDOs become CveRecords (via _extract_cve_id_from_vuln).
    Indicator SDOs become IocRecords by matching a small set of equality
    patterns. Other SDO types are ignored.

    Raises OpmlError on missing file or unreadable JSON so the runner can
    surface a friendly message instead of a traceback.
    """
    if not path.exists():
        raise OpmlError(f"STIX bundle not found: {path}")
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise OpmlError(f"Could not parse STIX bundle {path}: {exc}") from exc

    return _stix_objects_to_records(bundle.get("objects") or [], source=str(path))


def _stix_objects_to_records(
    objects: list[dict],
    source: str,
) -> tuple[list[CveRecord], list[IocRecord]]:
    """Shared object-list parser used by both parse_stix_bundle and pull_taxii."""
    today = date.today()
    cves: list[CveRecord] = []
    iocs: list[IocRecord] = []
    seen_cves: set[str] = set()
    seen_iocs: set[tuple[str, str]] = set()

    for obj in objects:
        otype = obj.get("type")
        if otype == "vulnerability":
            cve_id = _extract_cve_id_from_vuln(obj)
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                cves.append(CveRecord(cve_id, source, today, "manual_input"))
        elif otype == "indicator":
            for ioc_type, value in _extract_iocs_from_pattern(obj.get("pattern") or ""):
                key = (ioc_type, value.lower())
                if key in seen_iocs:
                    continue
                seen_iocs.add(key)
                iocs.append(IocRecord(ioc_type, value, source, today, "manual_input"))

    return cves, iocs


def pull_taxii(
    api_root: str,
    collection_id: str,
    *,
    username: str | None = None,
    password: str | None = None,
) -> tuple[list[CveRecord], list[IocRecord]]:
    """Pull objects from a TAXII 2.1 collection and parse them as a STIX bundle.

    No pagination handling in v1: returns the first page only. On any error
    returns ([], []) so the rest of the pipeline can continue.
    """
    url = api_root.rstrip("/") + f"/collections/{collection_id}/objects/"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/taxii+json;version=2.1",
    }
    auth = (username, password) if username and password else None
    try:
        resp = requests.get(url, headers=headers, auth=auth, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        _log.warning("TAXII pull failed for %s/%s: %s", api_root, collection_id, exc)
        return [], []

    return _stix_objects_to_records(
        data.get("objects") or [],
        source=f"taxii:{api_root.rstrip('/')}/{collection_id}",
    )


SIGMA_ELIGIBLE_BUCKETS = ("kev_override", "patch_now")


def _sigma_level_for(rec: EnrichedCve) -> str:
    """Map a triage bucket + CVSS to a Sigma rule level.

    KEV-listed → critical. CVSS 9.0+ → critical. CVSS 7.0+ → high.
    Anything lower that still squeaked into 'patch_now' → medium.
    """
    if rec.bucket == "kev_override" or (rec.cvss_score is not None and rec.cvss_score >= 9.0):
        return "critical"
    if rec.cvss_score is not None and rec.cvss_score >= 7.0:
        return "high"
    return "medium"


def _sigma_yaml_escape(value: str) -> str:
    """Escape a string for use as a single-quoted YAML scalar."""
    return value.replace("'", "''")


def _build_sigma_stub(rec: EnrichedCve) -> str:
    """Build a single Sigma rule YAML document for one EnrichedCve.

    The rule is intentionally a SCAFFOLD — the logsource and detection blocks
    are TODO placeholders so a detection engineer has a pre-tagged starting
    point rather than a runnable rule. Returns a YAML document string ending
    with '\\n' (no trailing '---').
    """
    rule_id = _stix_uuid("sigma:" + rec.cve_id)
    level = _sigma_level_for(rec)
    today = date.today().isoformat().replace("-", "/")
    cvss_disp = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
    epss_disp = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
    title = f"Detection scaffold for {rec.cve_id} (CVSS {cvss_disp})"

    # Description block ----------------------------------------------------
    desc_lines = [f"Detection stub for {rec.cve_id}."]
    desc_lines.append(
        f"Bucket: {rec.bucket}. CVSS {cvss_disp} ({rec.cvss_severity or 'N/A'}); EPSS {epss_disp}."
    )
    if rec.kev_listed:
        kev_line = "CISA KEV: listed"
        if rec.kev_due_date:
            kev_line += f" (due {rec.kev_due_date})"
        if rec.kev_known_ransomware_use:
            kev_line += " — known ransomware use"
        desc_lines.append(kev_line + ".")
    if rec.linked_actors:
        desc_lines.append(
            "Linked actors: " + ", ".join(a.name for a in rec.linked_actors) + "."
        )
    if rec.exploit_status and rec.exploit_status != "none":
        desc_lines.append(f"Public exploit status: {rec.exploit_status}.")
    desc_lines.append(
        "SCAFFOLD ONLY — fill in logsource and detection blocks for your environment."
    )
    description_block = "\n  ".join(desc_lines)

    # Tags block -----------------------------------------------------------
    tags = [f"cve.{rec.cve_id.lower()}"]
    for tid in rec.attack_techniques:
        # ATT&CK tag conventions: lowercase, sub-techniques use a dot.
        tags.append("attack." + tid.lower().replace(" ", "_"))
    if rec.kev_listed:
        tags.append("cisa.kev")
    if rec.kev_known_ransomware_use:
        tags.append("ransomware.known")
    tag_block = "\n".join(f"  - {t}" for t in tags)

    references = [
        f"  - https://nvd.nist.gov/vuln/detail/{rec.cve_id}",
        f"  - https://www.cve.org/CVERecord?id={rec.cve_id}",
    ]
    if rec.kev_listed:
        references.append(
            "  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )
    ref_block = "\n".join(references)

    return (
        f"title: '{_sigma_yaml_escape(title)}'\n"
        f"id: {rule_id}\n"
        f"status: experimental\n"
        f"description: |\n  {description_block}\n"
        f"references:\n{ref_block}\n"
        f"author: ramen-cve\n"
        f"date: {today}\n"
        f"tags:\n{tag_block}\n"
        f"logsource:\n"
        f"  product: TODO  # e.g. windows | linux | network | webserver\n"
        f"  service: TODO  # e.g. sysmon | apache | nginx | iis\n"
        f"detection:\n"
        f"  selection:\n"
        f"    TODO: TODO\n"
        f"  condition: selection\n"
        f"falsepositives:\n"
        f"  - TODO — describe expected benign activity\n"
        f"level: {level}\n"
    )


def write_sigma_stubs(enriched: list[EnrichedCve], out_dir: Path) -> list[Path]:
    """Write one Sigma rule YAML stub per kev_override/patch_now CVE.

    Returns the list of file paths written. Lower-priority buckets are skipped
    because they are not actionable for detection engineering. The output dir
    is created if it doesn't exist.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rec in enriched:
        if rec.bucket not in SIGMA_ELIGIBLE_BUCKETS:
            continue
        path = out_dir / f"{rec.cve_id}.yml"
        path.write_text(_build_sigma_stub(rec), encoding="utf-8")
        written.append(path)
    return written


def _yara_safe_name(value: str) -> str:
    """Reduce an arbitrary string to a valid YARA rule-identifier fragment.

    YARA rule names must match [A-Za-z_][A-Za-z0-9_]{0,127}. We collapse every
    other character to '_' and prefix a leading digit / empty string with '_'
    so the resulting identifier is always valid.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", (value or "").strip()).strip("_")
    if not cleaned:
        return "Unknown"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned[:96]


def _yara_string_escape(value: str) -> str:
    """Escape a string for use as a YARA double-quoted metadata literal."""
    return (value or "").replace("\\", "\\\\").replace("\"", "\\\"")


def _build_yara_stub(rec: EnrichedCve, malware: Malware) -> str:
    """Build one YARA rule scaffold for a (CVE, linked-malware) pair.

    The strings + condition blocks are deliberately TODO placeholders — the
    rule isn't runnable, but it carries every piece of metadata a detection
    engineer needs to populate it (CVE, CVSS, EPSS, ATT&CK, KEV, MITRE
    software URL).
    """
    rule_id = _stix_uuid(f"yara:{rec.cve_id}:{malware.name}")
    rule_name = f"Ramen_{_yara_safe_name(malware.name)}_{_yara_safe_name(rec.cve_id)}"
    cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
    epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
    techniques = ", ".join(rec.attack_techniques) if rec.attack_techniques else "(none)"
    description = (
        f"Detection scaffold for {malware.name} (linked to {rec.cve_id})"
    )

    lines: list[str] = [
        f"rule {rule_name}",
        "{",
        "    meta:",
        f"        id = \"{rule_id}\"",
        f"        description = \"{_yara_string_escape(description)}\"",
        "        author = \"ramen-cve\"",
        f"        date = \"{date.today().isoformat()}\"",
        f"        cve = \"{rec.cve_id}\"",
        f"        malware_family = \"{_yara_string_escape(malware.name)}\"",
        f"        cvss = \"{cvss}\"",
        f"        epss = \"{epss}\"",
        f"        attack_techniques = \"{_yara_string_escape(techniques)}\"",
    ]
    if rec.kev_listed:
        kev_text = "listed"
        if rec.kev_due_date:
            kev_text += f" (due {rec.kev_due_date})"
        if rec.kev_known_ransomware_use:
            kev_text += " - known ransomware use"
        lines.append(f"        cisa_kev = \"{_yara_string_escape(kev_text)}\"")
    if malware.url:
        lines.append(
            f"        mitre_software = \"{_yara_string_escape(malware.url)}\""
        )
    lines += [
        "    strings:",
        f"        // TODO: replace with strings characteristic of {malware.name}",
        "        $stub_a = \"TODO_REPLACE_ME\"",
        "    condition:",
        "        // TODO: refine the trigger; default fires on the placeholder string",
        "        any of them",
        "}",
        "",
    ]
    return "\n".join(lines)


YARA_ELIGIBLE_BUCKETS = SIGMA_ELIGIBLE_BUCKETS  # same precedence as Sigma stubs


def write_yara_stubs(enriched: list[EnrichedCve], out_dir: Path) -> list[Path]:
    """Write one YARA rule scaffold per (kev/patch-now CVE, linked malware) pair.

    Output filenames are `<MalwareSafeName>_<CveSafeName>.yar`. A CVE without
    linked_malware records produces no files. Returns the list of written
    paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rec in enriched:
        if rec.bucket not in YARA_ELIGIBLE_BUCKETS:
            continue
        for malware in rec.linked_malware:
            mw_stem = _yara_safe_name(malware.name)
            cve_stem = _yara_safe_name(rec.cve_id)
            path = out_dir / f"{mw_stem}_{cve_stem}.yar"
            path.write_text(_build_yara_stub(rec, malware), encoding="utf-8")
            written.append(path)
    return written


def write_csv(enriched: list[EnrichedCve], path: Path) -> None:
    """Write the enriched CVE list to a CSV file.

    Columns are in the order defined by CSV_COLUMNS. Numeric formatting:
    CVSS to 1 decimal, EPSS/percentile to 4 decimals.
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(CSV_COLUMNS)
        for rec in enriched:
            cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else ""
            epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else ""
            pct = f"{rec.epss_percentile:.4f}" if rec.epss_percentile is not None else ""
            writer.writerow(
                [
                    rec.cve_id,
                    rec.source,
                    str(rec.first_seen) if rec.first_seen else "",
                    rec.first_seen_type,
                    cvss,
                    rec.cvss_severity or "",
                    epss,
                    pct,
                    str(rec.kev_listed).lower(),
                    str(rec.kev_due_date) if rec.kev_due_date else "",
                    str(rec.kev_known_ransomware_use).lower(),
                    rec.kev_vendor_project or "",
                    rec.kev_product or "",
                    rec.bucket,
                    rec.suggested_action,
                    ";".join(rec.cwe),
                    ";".join(rec.attack_techniques),
                    rec.exploit_status,
                    ";".join(a.name for a in rec.linked_actors),
                    ";".join(c.name for c in rec.linked_campaigns),
                    ";".join(m.name for m in rec.linked_malware),
                    rec.tlp or "CLEAR",
                    rec.admiralty or "",
                    ";".join(rec.affected_hosts),
                    rec.kill_chain_phase,
                    rec.diamond_capability,
                    rec.diamond_adversary,
                    rec.diamond_infrastructure,
                    rec.diamond_victim,
                    str(rec.nvd_published) if rec.nvd_published else "",
                    rec.enriched_at.isoformat(),
                ]
            )


BUCKET_ORDER = [
    "kev_override",
    "patch_now",
    "watch_closely",
    "plan_and_patch",
    "deprioritize",
    "unknown",
]

BUCKET_DISPLAY = {
    "kev_override": "KEV Override (Patch Immediately)",
    "patch_now": "Patch Now",
    "watch_closely": "Watch Closely",
    "plan_and_patch": "Plan and Patch",
    "deprioritize": "Deprioritize",
    "unknown": "Unknown / Insufficient Data",
}


def _md_safe(text: str) -> str:
    """Collapse newlines and control whitespace so a string is safe in a Markdown bullet."""
    if not text:
        return ""
    # Replace any run of \r/\n/\t/etc. with a single space so the bullet stays on one line.
    return re.sub(r"\s+", " ", text).strip()


IOC_TYPE_DISPLAY: dict[str, str] = {
    "url": "URLs",
    "domain": "Domains",
    "ipv4": "IPv4 Addresses",
    "email": "Email Addresses",
    "sha256": "SHA-256 Hashes",
    "sha1": "SHA-1 Hashes",
    "md5": "MD5 Hashes",
}
IOC_TYPE_ORDER = ["url", "domain", "ipv4", "email", "sha256", "sha1", "md5"]


def _summarize_enrichment(enricher_name: str, payload: dict) -> str:
    """Produce a one-line Markdown summary of an enricher payload, or '' to skip."""
    if not payload or payload.get("found") is False:
        return ""
    if enricher_name == "virustotal":
        mal = payload.get("malicious") or 0
        sus = payload.get("suspicious") or 0
        rep = payload.get("reputation")
        rep_str = f", rep {rep}" if rep is not None else ""
        return f"malicious={mal} suspicious={sus}{rep_str}"
    if enricher_name == "abuseipdb":
        return (
            f"abuse_confidence={payload.get('abuse_confidence')} "
            f"reports={payload.get('total_reports')}"
        )
    if enricher_name == "otx":
        return f"pulse_count={payload.get('pulse_count')}"
    if enricher_name == "malwarebazaar":
        sig = payload.get("signature") or "unsigned-sample"
        return f"known sample ({sig})"
    return ""


def write_markdown(
    enriched: list[EnrichedCve],
    path: Path,
    run_metadata: dict,
    iocs: list[IocRecord] | None = None,
) -> None:
    """Write a human-readable Markdown triage report.

    run_metadata keys: command (str), args (str — secrets redacted), version (str),
    sources (list[str]), start (str), end (str), date_mode (str),
    cvss_threshold (float), epss_threshold (float).

    If `iocs` is non-empty, an additional "Indicators of Compromise" section is
    rendered at the end of the report, grouped by IOC type.
    """
    iocs = iocs or []
    lines: list[str] = []
    now = _utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total = len(enriched)
    total_iocs = len(iocs)
    defanged_iocs = sum(1 for ioc in iocs if ioc.defanged_in_source)

    lines += [
        "# Ramen CVE Triage Report",
        "",
        f"Generated: {now}  ",
        f"Total CVEs: **{total}**  ",
    ]
    if total_iocs:
        lines.append(f"Total IOCs: **{total_iocs}** ({defanged_iocs} defanged in source)  ")
    if run_metadata.get("start") or run_metadata.get("end"):
        lines.append(
            f"Date filter: {run_metadata.get('start', '*')} → {run_metadata.get('end', '*')} "
            f"(mode: `{run_metadata.get('date_mode', 'feed')}`)  "
        )
    lines += [
        f"CVSS threshold: `{run_metadata.get('cvss_threshold', DEFAULT_CVSS_THRESHOLD)}`  ",
        f"EPSS threshold: `{run_metadata.get('epss_threshold', DEFAULT_EPSS_THRESHOLD)}`  ",
        "",
    ]

    if run_metadata.get("sources"):
        lines += ["## Sources", ""]
        for src in run_metadata["sources"]:
            lines.append(f"- {_md_safe(src)}")
        lines.append("")

    by_bucket: dict[str, list[EnrichedCve]] = {b: [] for b in BUCKET_ORDER}
    for rec in enriched:
        bucket = rec.bucket if rec.bucket in by_bucket else "unknown"
        by_bucket[bucket].append(rec)

    lines += ["## Summary", "", "| Bucket | Count | Action |", "| --- | --- | --- |"]
    for bucket in BUCKET_ORDER:
        count = len(by_bucket[bucket])
        raw = BUCKET_ACTIONS[bucket]
        action = raw.split("—")[-1].strip() if "—" in raw else raw
        lines.append(f"| {BUCKET_DISPLAY[bucket]} | {count} | {action} |")
    lines.append("")

    technique_rollup: dict[str, list[str]] = {}
    for rec in enriched:
        for tid in rec.attack_techniques:
            technique_rollup.setdefault(tid, []).append(rec.cve_id)
    if technique_rollup:
        lines += [
            "## By ATT&CK Technique",
            "",
            "| Technique | Name | CVEs |",
            "| --- | --- | --- |",
        ]
        for tid in sorted(technique_rollup):
            name = ATTACK_TECHNIQUE_NAMES.get(tid, "(unmapped)")
            cves = technique_rollup[tid]
            lines.append(f"| {tid} | {name} | {len(cves)} |")
        lines.append("")

    affected_rollup: dict[str, list[str]] = {}
    for rec in enriched:
        for host in rec.affected_hosts:
            affected_rollup.setdefault(host, []).append(rec.cve_id)
    if affected_rollup:
        lines += [
            "## Affected in Your Environment",
            "",
            "| Host | CVEs |",
            "| --- | --- |",
        ]
        for host in sorted(affected_rollup):
            lines.append(f"| {_md_safe(host)} | {len(affected_rollup[host])} |")
        lines.append("")

    actor_rollup: dict[str, list[str]] = {}
    actor_sectors: dict[str, set[str]] = {}
    for rec in enriched:
        for actor in rec.linked_actors:
            actor_rollup.setdefault(actor.name, []).append(rec.cve_id)
            if actor.sectors_targeted:
                actor_sectors.setdefault(actor.name, set()).update(actor.sectors_targeted)
    if actor_rollup:
        lines += [
            "## Linked Adversaries",
            "",
            "| Actor | CVEs | Sectors Targeted |",
            "| --- | --- | --- |",
        ]
        for actor in sorted(actor_rollup):
            sectors = sorted(actor_sectors.get(actor, set()))
            sector_disp = ", ".join(sectors) if sectors else "—"
            lines.append(
                f"| {_md_safe(actor)} | {len(actor_rollup[actor])} | {_md_safe(sector_disp)} |"
            )
        lines.append("")

    if total == 0:
        lines += ["## No CVEs found", "", "No CVEs matched the current filters.", ""]

    today = date.today()
    for bucket in BUCKET_ORDER:
        recs = by_bucket[bucket]
        if not recs:
            continue
        lines += [f"## {BUCKET_DISPLAY[bucket]}", ""]
        for rec in recs:
            lines.append(f"### {rec.cve_id}")
            lines.append("")
            lines.append(f"**Action:** {rec.suggested_action}")
            lines.append("")
            cvss_display = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
            severity_display = rec.cvss_severity or "N/A"
            lines.append(f"- **CVSS:** {cvss_display} ({severity_display})")
            if rec.epss_score is not None and rec.epss_percentile is not None:
                lines.append(f"- **EPSS:** {rec.epss_score:.4f} ({rec.epss_percentile:.4f} pct)")
            elif rec.epss_score is not None:
                lines.append(f"- **EPSS:** {rec.epss_score:.4f}")
            else:
                lines.append("- **EPSS:** N/A")
            lines.append(f"- **CWE:** {', '.join(rec.cwe) if rec.cwe else 'N/A'}")
            if rec.attack_techniques:
                techniques_display = ", ".join(
                    f"{tid} ({ATTACK_TECHNIQUE_NAMES[tid]})"
                    if tid in ATTACK_TECHNIQUE_NAMES
                    else tid
                    for tid in rec.attack_techniques
                )
                lines.append(f"- **ATT&CK:** {techniques_display}")
            if rec.exploit_status and rec.exploit_status != "none":
                lines.append(f"- **Exploit Status:** `{rec.exploit_status}`")
            if rec.linked_actors:
                actors_disp = ", ".join(
                    f"[{_md_safe(a.name)}]({a.url})" if a.url else _md_safe(a.name)
                    for a in rec.linked_actors
                )
                lines.append(f"- **Linked Actors:** {actors_disp}")
            if rec.linked_malware:
                lines.append(
                    "- **Linked Malware:** "
                    + ", ".join(_md_safe(m.name) for m in rec.linked_malware)
                )
            if rec.linked_campaigns:
                lines.append(
                    "- **Linked Campaigns:** "
                    + ", ".join(_md_safe(c.name) for c in rec.linked_campaigns)
                )
            if (rec.tlp and rec.tlp != "CLEAR") or rec.admiralty:
                tlp_disp = f"TLP:{rec.tlp}" if rec.tlp else ""
                adm_disp = f"Admiralty {rec.admiralty}" if rec.admiralty else ""
                provenance = " · ".join(p for p in (tlp_disp, adm_disp) if p)
                lines.append(f"- **Provenance:** {provenance}")
            if rec.affected_hosts:
                shown = rec.affected_hosts[:8]
                hosts_disp = ", ".join(_md_safe(h) for h in shown)
                extra = len(rec.affected_hosts) - len(shown)
                more = f" *(and {extra} more)*" if extra > 0 else ""
                lines.append(
                    f"- **Affected in your environment:** {len(rec.affected_hosts)} "
                    f"host(s) — {hosts_disp}{more}"
                )
            if rec.bucket in ("kev_override", "patch_now"):
                adversary = rec.diamond_adversary or "*unknown actor*"
                infra = rec.diamond_infrastructure or "*unknown infrastructure*"
                victim = rec.diamond_victim or (
                    f"{len(rec.affected_hosts)} inventory host(s)"
                    if rec.affected_hosts else "*your environment*"
                )
                lines.append(
                    f"- **Diamond Model:** Adversary={_md_safe(adversary)} · "
                    f"Capability={_md_safe(rec.diamond_capability)} · "
                    f"Infrastructure={_md_safe(infra)} · "
                    f"Victim={_md_safe(victim)} · "
                    f"Kill Chain={rec.kill_chain_phase.replace('_', ' ')}"
                )
            lines.append(f"- **NVD Published:** {rec.nvd_published or 'N/A'}")
            if rec.kev_listed and (rec.kev_due_date or rec.kev_vendor_project):
                if rec.kev_vendor_project or rec.kev_product:
                    affected = " ".join(
                        p for p in (rec.kev_vendor_project, rec.kev_product) if p
                    )
                    lines.append(f"- **CISA KEV — Affected:** {_md_safe(affected)}")
                if rec.kev_due_date:
                    overdue = " (OVERDUE)" if rec.kev_due_date < today else ""
                    lines.append(f"- **CISA KEV — Due Date:** {rec.kev_due_date}{overdue}")
                if rec.kev_known_ransomware_use:
                    lines.append("- **CISA KEV — Ransomware Use:** Known")
                if rec.kev_required_action:
                    lines.append(
                        f"- **CISA KEV — Required Action:** {_md_safe(rec.kev_required_action)}"
                    )
                if rec.kev_short_description:
                    lines.append(
                        f"- **CISA KEV — Description:** {_md_safe(rec.kev_short_description)}"
                    )
            lines.append(f"- **Source:** {_md_safe(rec.source)}")
            lines.append("")

    if iocs:
        by_type: dict[str, list[IocRecord]] = {t: [] for t in IOC_TYPE_ORDER}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)
        lines += ["## Indicators of Compromise", ""]
        for ioc_type in IOC_TYPE_ORDER:
            recs = by_type.get(ioc_type) or []
            if not recs:
                continue
            label = IOC_TYPE_DISPLAY.get(ioc_type, ioc_type)
            lines.append(f"### {label} ({len(recs)})")
            lines.append("")
            for rec in recs:
                marker = " *(defanged in source)*" if rec.defanged_in_source else ""
                # Only call out confidence when decay has actually lowered it;
                # a 1.0 marker would just be noise for fresh extractions.
                conf_marker = (
                    f" *(confidence {rec.confidence:.2f})*"
                    if rec.confidence is not None and rec.confidence < 0.995
                    else ""
                )
                lines.append(f"- `{_md_safe(rec.value)}`{marker}{conf_marker}")
                for enricher_name, payload in sorted(rec.enrichments.items()):
                    summary = _summarize_enrichment(enricher_name, payload)
                    if summary:
                        lines.append(f"  - {enricher_name}: {summary}")
            lines.append("")

    version = run_metadata.get("version", "0.1")
    cmd = run_metadata.get("args", "")
    lines += [
        "---",
        "",
        f"*Generated by ramen-cve v{version}*  ",
        f"*Command: `{cmd}`*  " if cmd else "",
        "*Data sources: NVD (nvd.nist.gov) · EPSS (first.org)*",
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


VERSION = "0.1"


def _parse_iso_date(value: str) -> date:
    """Argparse type: parse YYYY-MM-DD or raise ArgumentTypeError."""
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid date '{value}' — expected YYYY-MM-DD.") from exc


def _validate_cve_id(value: str) -> str:
    """Argparse type: ensure value matches the CVE ID pattern."""
    if not CVE_REGEX.fullmatch(value.upper()):
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid CVE ID. Expected format: CVE-YYYY-NNNN."
        )
    return value.upper()


def _strip_path_quotes(value: str) -> str:
    """Return `value` with surrounding whitespace and a single layer of paired
    ASCII or curly quotes stripped.

    Users habitually paste quoted paths, especially on Windows where Explorer's
    "Copy as path" wraps the result in double quotes. Argparse and questionary
    treat the quotes as literal characters, which then fails Path operations on
    Windows (where `"` is a reserved filename character) and silently produces a
    weirdly-named directory on POSIX.
    """
    s = (value or "").strip()
    pairs = (('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’"))
    for opener, closer in pairs:
        if len(s) >= 2 and s[0] == opener and s[-1] == closer:
            s = s[1:-1].strip()
            break
    return s


def _path_arg(value: str) -> Path:
    """Argparse type for user-supplied paths.

    Performs the full normalization pipeline:
      1. Strip surrounding ASCII or curly quotes (common when copying from
         Windows Explorer's "Copy as path").
      2. Strip surrounding whitespace.
      3. Expand a leading ``~`` to the user's home directory (POSIX + Windows).

    Returns a ``pathlib.Path`` — the rest of the code never sees a raw string.
    """
    return Path(_strip_path_quotes(value)).expanduser()


def _resolve_out_dir(value: Path | None) -> Path:
    """Resolve a `--out-dir` argument to a concrete directory.

    A None / empty value (``--out-dir`` omitted, or wizard answered blank)
    resolves to the current working directory rather than the literal ``.``
    so the help text and prompt placeholder stay clean.
    """
    if value is None or str(value) in ("", "."):
        return Path.cwd()
    return value.expanduser()


def _validate_opml_input(value: str) -> bool | str:
    """Wizard validator for the OPML path prompt.

    Accepts either:
      - a path to a single ``.opml`` file, or
      - a directory containing at least one ``*.opml`` file.

    Quote-stripping and ``~`` expansion are applied before the on-disk check.
    Returns True on success or a user-facing error string for questionary.
    """
    if not value or not value.strip():
        return "Enter the path to an OPML file or a directory of .opml files."
    cleaned = Path(_strip_path_quotes(value)).expanduser()
    if cleaned.is_file():
        return True
    if cleaned.is_dir():
        if any(cleaned.glob("*.opml")):
            return True
        return f"{cleaned} exists but contains no .opml files."
    return f"Path not found: {cleaned}"


def _collect_opml_files(path: Path) -> list[Path]:
    """Return the list of OPML files at ``path``.

    If ``path`` is a file we return ``[path]``. If it's a directory we return
    every ``*.opml`` under it (sorted, top-level only — no recursion to avoid
    picking up backups or unrelated bundles). An empty directory raises
    OpmlError with a clear message so the caller can surface it.
    """
    if path.is_file():
        return [path]
    if path.is_dir():
        files = sorted(path.glob("*.opml"))
        if not files:
            raise OpmlError(
                f"Directory contains no .opml files: {path}"
            )
        return files
    raise OpmlError(f"OPML path not found: {path}")


# ---------------------------------------------------------------------------
# YAML configuration system
# ---------------------------------------------------------------------------
#
# Saved configurations live as YAML files under DEFAULT_PRESETS_DIR. The
# documented template at DEFAULT_CONFIG_TEMPLATE shows every key the tool
# understands. CLI args ALWAYS win over YAML values — the YAML only fills
# the gaps. See src/ramen_cve/config/config.yaml for the full schema.
# ---------------------------------------------------------------------------


def _resolve_config_path(name_or_path: str) -> Path:
    """Resolve ``--config`` argument to a concrete YAML file.

    Plain names like ``daily-hunt`` are looked up under DEFAULT_PRESETS_DIR
    with a ``.yaml`` extension. Anything containing a path separator (``/`` or
    ``\\``) or an explicit ``.yaml`` / ``.yml`` extension is treated as a
    file path (quote-stripped + ~-expanded).
    """
    raw = (name_or_path or "").strip()
    if not raw:
        raise FileNotFoundError("No config name or path supplied.")
    looks_like_path = (
        "/" in raw or "\\" in raw
        or raw.endswith((".yaml", ".yml"))
        or raw.startswith("~")
    )
    if looks_like_path:
        return Path(_strip_path_quotes(raw)).expanduser()
    return DEFAULT_PRESETS_DIR / f"{raw}.yaml"


def load_yaml_config(name_or_path: str) -> dict:
    """Load a YAML config (preset name or explicit path) into a dict.

    Returns ``{}`` for an empty file. Raises FileNotFoundError when the
    file doesn't exist and ValueError when the file isn't YAML-parseable
    so callers can surface clean error messages.
    """
    import yaml

    path = _resolve_config_path(name_or_path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Could not parse YAML config {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Config file {path} must contain a YAML mapping at the top level."
        )
    return data


def list_yaml_presets() -> list[Path]:
    """Return every *.yaml preset under DEFAULT_PRESETS_DIR (sorted)."""
    if not DEFAULT_PRESETS_DIR.exists():
        return []
    return sorted(DEFAULT_PRESETS_DIR.glob("*.yaml"))


def delete_yaml_preset(name_or_path: str) -> Path | None:
    """Delete a saved preset. Returns the removed path, or None if absent."""
    target = _resolve_config_path(name_or_path)
    if target.is_file():
        target.unlink()
        return target
    return None


def _save_remembered_opml(path: Path) -> Path:
    """Persist the OPML source so a later `opml` run with no path reuses it.

    Writes a tiny JSON blob (``{opml_path, saved_at}``) to
    DEFAULT_LAST_OPML_PATH. Returns the state-file path written.
    """
    DEFAULT_LAST_OPML_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_LAST_OPML_PATH.write_text(
        json.dumps(
            {"opml_path": str(path), "saved_at": _utcnow().isoformat(timespec="seconds")},
            indent=2,
        ),
        encoding="utf-8",
    )
    return DEFAULT_LAST_OPML_PATH


def _load_remembered_opml() -> Path | None:
    """Return the previously-remembered OPML path, or None if not set / unreadable.

    Never raises: a missing or corrupt state file simply means "nothing
    remembered" so the caller can fall back to a clean 'path required' error.
    """
    if not DEFAULT_LAST_OPML_PATH.is_file():
        return None
    try:
        data = json.loads(DEFAULT_LAST_OPML_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    raw = (data or {}).get("opml_path")
    return Path(raw).expanduser() if raw else None


def _reset_remembered_opml() -> bool:
    """Forget the remembered OPML. Returns True if a state file was removed."""
    if DEFAULT_LAST_OPML_PATH.is_file():
        DEFAULT_LAST_OPML_PATH.unlink()
        return True
    return False


def save_yaml_config(name_or_path: str, payload: dict) -> Path:
    """Persist ``payload`` as a YAML preset. Returns the path written to.

    A bare name maps to ``DEFAULT_PRESETS_DIR/<name>.yaml``; anything with a
    path separator or ``.yaml`` / ``.yml`` extension is treated as an
    explicit file path. The presets directory is created on demand.
    """
    import yaml

    target = _resolve_config_path(name_or_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return target


# Mapping from YAML key → argparse.Namespace attribute name. Nested YAML
# blocks (output, filters, enrichment, cache, dispatch, email, logging) are
# expanded into flat attributes that mirror the CLI flag names. CLI args
# present in args.* with a non-None value override any YAML setting.
_YAML_FLAT_KEY_MAP: dict[tuple[str, ...], str] = {
    ("subcommand",): "subcommand",
    ("opml_path",): "path",
    ("url",): "url",
    ("cves",): "cves",
    ("stix_path",): "path",
    ("taxii_url",): "taxii_url",
    ("taxii_collection",): "taxii_collection",
    ("inventory_path",): "inventory",
    ("output", "out_dir"): "out_dir",
    ("output", "basename"): "basename",
    ("output", "format"): "format",
    ("output", "allow_tlp_red"): "allow_tlp_red",
    ("filters", "cvss_threshold"): "cvss_threshold",
    ("filters", "epss_threshold"): "epss_threshold",
    ("filters", "ioc_confidence_floor"): "ioc_confidence_floor",
    ("filters", "start"): "start",
    ("filters", "end"): "end",
    ("filters", "date_mode"): "date_mode",
    ("filters", "sector"): "sector",
    ("enrichment", "no_exploit_lookup"): "no_exploit_lookup",
    ("enrichment", "no_enrich_iocs"): "no_enrich_iocs",
    ("cache", "no_cache"): "no_cache",
    ("dispatch", "enabled"): "dispatch",
    ("remember_opml",): "remember_opml",
}


def _coerce_yaml_value(attr: str, value):
    """Convert a YAML value into the type argparse would have produced.

    Handles the four argparse types this tool uses: dates (from ISO strings),
    floats, Paths, and lists (passed through). Empty strings collapse to None
    so they don't override a real CLI argument by accident.
    """
    if value in ("", None):
        return None
    if attr in ("start", "end") and isinstance(value, str):
        try:
            return _parse_iso_date(value)
        except (argparse.ArgumentTypeError, ValueError):
            return None
    if attr in (
        "out_dir", "path", "inventory", "associations_file",
        "hunt_dir", "pir_dir",
    ) and isinstance(value, str):
        return Path(_strip_path_quotes(value)).expanduser()
    if attr in ("cvss_threshold", "epss_threshold", "ioc_confidence_floor"):
        return float(value)
    return value


def apply_yaml_config(args: argparse.Namespace, config: dict) -> None:
    """Fold a loaded YAML config into ``args`` IN PLACE.

    Walks _YAML_FLAT_KEY_MAP, pulling each nested-or-flat YAML key out of
    the loaded mapping and stamping it onto the corresponding args attribute
    only when the user did NOT pass that flag on the CLI (i.e. when the
    attribute is currently None / False / its argparse default).
    """
    def _get_nested(d: dict, path: tuple[str, ...]):
        cur = d
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return None
            cur = cur[key]
        return cur

    for key_path, attr in _YAML_FLAT_KEY_MAP.items():
        raw = _get_nested(config, key_path)
        if raw is None:
            continue
        coerced = _coerce_yaml_value(attr, raw)
        if coerced is None:
            continue
        current = getattr(args, attr, None)
        # "Current is unset" heuristic: argparse defaults for our flags are
        # either None, False (for store_true), or the documented numeric
        # default. We override None/False; we leave non-default values alone.
        if current in (None, False, "", []):
            setattr(args, attr, coerced)

    # Logging level: YAML's logging.level maps to args.quiet / args.verbose
    # only when neither flag was passed.
    log_level = (config.get("logging") or {}).get("level")
    if isinstance(log_level, str) and not getattr(args, "quiet", False) \
            and not getattr(args, "verbose", False):
        if log_level == "quiet":
            args.quiet = True
        elif log_level == "verbose":
            args.verbose = True

    # Email section → RAMEN_SMTP_* env vars so EmailDispatcher.from_env()
    # picks them up. Plaintext SMTP passwords in YAML are flagged in the
    # template; production users should prefer .env / keyring.
    email = config.get("email") or {}
    if isinstance(email, dict) and email.get("enabled"):
        import os

        def _set_env_if_blank(key: str, value) -> None:
            """Set `key` to `str(value)` only if `value` is truthy AND the env
            var is not already set (so a real `.env` always wins over YAML)."""
            if value:
                os.environ.setdefault(key, str(value))

        _set_env_if_blank("RAMEN_SMTP_HOST", email.get("smtp_host"))
        if email.get("smtp_port"):
            _set_env_if_blank("RAMEN_SMTP_PORT", email.get("smtp_port"))
        _set_env_if_blank("RAMEN_SMTP_USER", email.get("smtp_user"))
        _set_env_if_blank("RAMEN_SMTP_PASS", email.get("smtp_pass"))
        _set_env_if_blank("RAMEN_SMTP_FROM", email.get("smtp_from"))
        if email.get("smtp_use_tls") is False:
            _set_env_if_blank("RAMEN_SMTP_USE_TLS", "0")
        _set_env_if_blank("RAMEN_DIGEST_TO", email.get("fallback_recipient"))
        # Implicit: enabling email turns on --digest unless explicitly opted out.
        if not getattr(args, "digest", False):
            args.digest = True


def args_to_yaml_payload(args: argparse.Namespace) -> dict:
    """Snapshot the current invocation as a YAML-compatible mapping.

    Used by ``--save-config NAME``. Mirrors the schema in
    src/ramen_cve/config/config.yaml so a round-trip
    save → load → run reproduces the same behavior.
    """
    def _stringify(v):
        if isinstance(v, Path):
            return str(v)
        if isinstance(v, date):
            return v.isoformat()
        return v

    payload: dict = {"subcommand": getattr(args, "subcommand", None)}
    payload["opml_path"] = _stringify(getattr(args, "path", None)) \
        if getattr(args, "subcommand", "") == "opml" else None
    payload["url"] = getattr(args, "url", None)
    payload["cves"] = list(getattr(args, "cves", None) or []) or None
    payload["stix_path"] = _stringify(getattr(args, "path", None)) \
        if getattr(args, "subcommand", "") == "stix" else None
    payload["taxii_url"] = getattr(args, "taxii_url", None)
    payload["taxii_collection"] = getattr(args, "taxii_collection", None)
    payload["inventory_path"] = _stringify(getattr(args, "inventory", None))
    payload["output"] = {
        "out_dir": _stringify(getattr(args, "out_dir", None)),
        "basename": getattr(args, "basename", None) or "",
        "format": getattr(args, "format", None),
        "allow_tlp_red": bool(getattr(args, "allow_tlp_red", False)),
    }
    payload["filters"] = {
        "cvss_threshold": getattr(args, "cvss_threshold", None),
        "epss_threshold": getattr(args, "epss_threshold", None),
        "ioc_confidence_floor": getattr(args, "ioc_confidence_floor", None),
        "start": _stringify(getattr(args, "start", None)) or "",
        "end": _stringify(getattr(args, "end", None)) or "",
        "date_mode": getattr(args, "date_mode", None),
        "sector": getattr(args, "sector", None) or "",
    }
    payload["enrichment"] = {
        "no_exploit_lookup": bool(getattr(args, "no_exploit_lookup", False)),
        "no_enrich_iocs": bool(getattr(args, "no_enrich_iocs", False)),
    }
    payload["cache"] = {"no_cache": bool(getattr(args, "no_cache", False))}
    payload["dispatch"] = {"enabled": bool(getattr(args, "dispatch", False))}
    payload["remember_opml"] = bool(getattr(args, "remember_opml", False))
    payload["logging"] = {
        "level": "quiet" if getattr(args, "quiet", False)
        else "verbose" if getattr(args, "verbose", False)
        else "normal",
    }
    # Drop any key with a None value so the saved file stays tidy.
    return {k: v for k, v in payload.items() if v not in (None, {}, [])}


def _shared_flags(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by all three subcommands."""
    parser.add_argument("--start", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--end", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--date-mode", choices=["feed", "disclosure", "epss"], default=None)
    parser.add_argument("--cvss-threshold", type=float, default=DEFAULT_CVSS_THRESHOLD)
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD)
    # Default is None so the help text doesn't show a literal '.'; runtime
    # resolves None → Path.cwd() via _resolve_out_dir(). Threat hunters
    # typically pass a quoted Windows path here ("C:\\Users\\me\\Reports");
    # _path_arg strips the quotes and expands ~.
    parser.add_argument(
        "--out-dir",
        type=_path_arg,
        default=None,
        metavar="DIR",
        help="Directory to write output files into. Defaults to the current "
             "working directory. Surrounding quotes and a leading ~ are handled.",
    )
    parser.add_argument(
        "--basename",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Stem for output files (no extension). Default: ramen-cve-<UTC timestamp>. "
            "Path separators are stripped; -iocs is appended to the IOC CSV; -sigma to "
            "the Sigma rule directory."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["csv", "md", "both", "stix", "sigma", "yara", "all"],
        default="both",
        help=(
            "Output format. 'both' = CSV + Markdown; 'sigma' = Sigma stubs only; "
            "'yara' = YARA stubs only (one per linked malware family); "
            "'all' = CSV + Markdown + STIX + Sigma + YARA."
        ),
    )
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--no-exploit-lookup",
        action="store_true",
        help="Skip Exploit-DB / Nuclei / GitHub PoC lookups (offline mode).",
    )
    parser.add_argument(
        "--no-enrich-iocs",
        action="store_true",
        help="Skip per-IOC enrichment (VirusTotal / AbuseIPDB / OTX / MalwareBazaar).",
    )
    parser.add_argument(
        "--ioc-confidence-floor",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help=(
            "Drop IOCs whose decay-weighted confidence is below this floor "
            "(0.0..1.0; default 0.0 keeps every IOC). Half-lives per type: "
            "IPv4 30d, URL 30d, domain 90d, email 90d; file hashes never decay."
        ),
    )
    parser.add_argument(
        "--sector",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Filter the report to CVEs likely relevant to a given sector "
            "(e.g. 'financial', 'healthcare', 'energy', 'government'). "
            "Matches against each linked actor's sectors_targeted in "
            "associations.json. Records with no linked actors are KEPT "
            "(unattributed CVEs are assumed potentially relevant)."
        ),
    )
    parser.add_argument(
        "--allow-tlp-red",
        action="store_true",
        help=(
            "Permit writing TLP:RED records to disk. Default behavior is to "
            "STRIP any TLP:RED records before output and log a warning."
        ),
    )
    parser.add_argument(
        "--inventory",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CSV asset inventory with columns 'host,product,version' "
            "(or 'host,cpe'). When set, the report annotates each CVE with the "
            "list of inventory hosts whose product+version matches a CVE CPE."
        ),
    )
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help=(
            "After writing reports, push every kev_override / patch_now finding "
            "to configured dispatchers (Slack via SLACK_WEBHOOK_URL, generic "
            "webhook via RAMEN_DISPATCH_WEBHOOK). Off by default."
        ),
    )
    parser.add_argument(
        "--digest",
        action="store_true",
        help=(
            "After writing reports, batch-mail one digest email per recipient "
            "(keyed by the inventory CSV's `owner` column, falling back to "
            "RAMEN_DIGEST_TO when set). SMTP via RAMEN_SMTP_* env vars. The "
            "CSV and Markdown reports are attached. Off by default."
        ),
    )
    parser.add_argument(
        "--associations-file",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CVE→adversary associations JSON file. "
            "Defaults to associations.json in the repo. Pass an empty/missing "
            "path to disable adversary attribution."
        ),
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ramen_cve",
        description="Threat intel triage on a ramen budget.",
    )
    # YAML configuration plumbing — top-level (works before any subcommand).
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Load a saved YAML preset by name "
            "(under src/ramen_cve/config/presets/<NAME>.yaml) "
            "or an explicit YAML file path. CLI flags override YAML values."
        ),
    )
    parser.add_argument(
        "--save-config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "After this run, persist the current invocation's arguments as a "
            "YAML preset under that NAME (or write to the explicit YAML path)."
        ),
    )
    parser.add_argument(
        "--list-configs",
        action="store_true",
        help="List every saved YAML preset and exit.",
    )
    parser.add_argument(
        "--reset-config",
        type=str,
        default=None,
        metavar="NAME",
        help="Delete the saved YAML preset with that NAME (or path) and exit.",
    )
    parser.add_argument(
        "--reset-opml",
        action="store_true",
        help="Forget the remembered OPML source (clears the last_opml state) "
             "and exit.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=False)

    # opml subcommand
    opml_p = sub.add_parser("opml", help="Process an OPML feed list.")
    opml_p.add_argument(
        "path",
        type=_path_arg,
        nargs="?",
        default=None,
        help="Path to an .opml file OR a directory of *.opml files. "
             "Optional when a remembered OPML exists (see --remember-opml).",
    )
    opml_p.add_argument(
        "--remember-opml",
        action="store_true",
        help="After a successful run, save this OPML source so a later "
             "`opml` with no path argument reuses it automatically.",
    )
    _shared_flags(opml_p)

    # url subcommand
    url_p = sub.add_parser("url", help="Extract CVEs from a single URL.")
    url_p.add_argument("url", help="URL of the article or page to scan.")
    _shared_flags(url_p)

    # cve subcommand
    cve_p = sub.add_parser("cve", help="Enrich named CVE IDs directly.")
    cve_p.add_argument("cves", nargs="*", type=_validate_cve_id, metavar="CVE-ID")
    cve_p.add_argument("--from-file", type=_path_arg, metavar="FILE", help="Text file of CVE IDs.")
    _shared_flags(cve_p)

    # hunt subcommand: list / show / link / log / status against the hunts/ library
    hunt_p = sub.add_parser("hunt", help="Manage threat-hunt hypotheses.")
    hunt_p.add_argument(
        "action",
        choices=["list", "show", "link", "log", "status"],
        help="What to do with the hunts library.",
    )
    hunt_p.add_argument("hunt_id", nargs="?", help="Hunt id (filename stem under hunts/).")
    hunt_p.add_argument(
        "value",
        nargs="?",
        help=(
            "Action argument: CVE-ID for 'link', finding text for 'log', "
            "new status for 'status'."
        ),
    )
    hunt_p.add_argument(
        "--hunt-dir",
        type=_path_arg,
        default=DEFAULT_HUNT_DIR,
        help="Directory of hunt JSON files (default: hunts/ next to ramen_cve.py).",
    )

    # pir subcommand: leadership-blessed Priority Intelligence Requirements
    pir_p = sub.add_parser(
        "pir", help="Manage Priority Intelligence Requirements (PIRs)."
    )
    pir_p.add_argument(
        "action",
        choices=["list", "show", "link", "coverage"],
        help="What to do with the PIR library.",
    )
    pir_p.add_argument(
        "pir_id", nargs="?", help="PIR id (filename stem under pirs/)."
    )
    pir_p.add_argument(
        "value", nargs="?",
        help="Action argument: CVE-ID for 'link' (other actions ignore this).",
    )
    pir_p.add_argument(
        "--pir-dir",
        type=_path_arg,
        default=DEFAULT_PIR_DIR,
        help="Directory of PIR JSON files (default: pirs/ next to ramen_cve.py).",
    )

    # trend subcommand: historical bucket / CVSS / EPSS for one CVE
    trend_p = sub.add_parser(
        "trend", help="Show historical bucket / CVSS / EPSS trend for one CVE."
    )
    trend_p.add_argument("cve_id", type=_validate_cve_id, metavar="CVE-ID")
    trend_p.add_argument(
        "--no-cache",
        action="store_true",
        help="Use an in-memory cache (yields no history, mostly useful for tests).",
    )
    trend_p.add_argument("--quiet", action="store_true")
    trend_p.add_argument("--verbose", action="store_true")

    # audit subcommand: tail the append-only audit log
    audit_p = sub.add_parser(
        "audit",
        help="Show the tail of the append-only audit log of past ramen_cve commands.",
    )
    audit_p.add_argument(
        "--tail", type=int, default=20,
        help="How many of the most recent entries to print (default 20).",
    )
    audit_p.add_argument(
        "--no-cache", action="store_true",
        help="Read the in-memory audit log only (always empty; useful for tests).",
    )
    audit_p.add_argument("--quiet", action="store_true")
    audit_p.add_argument("--verbose", action="store_true")

    # schedule subcommand: emit a Task Scheduler XML or a crontab line that
    # invokes this tool against a saved YAML preset on a recurring schedule.
    schedule_p = sub.add_parser(
        "schedule",
        help="Generate a Windows Task Scheduler XML or a crontab line for "
             "automated daily runs against a saved YAML preset.",
    )
    schedule_p.add_argument(
        "action",
        choices=["windows-task", "cron"],
        help=(
            "Output format: 'windows-task' writes a Task Scheduler XML (importable "
            "via `schtasks /Create /XML`); 'cron' prints a crontab line."
        ),
    )
    schedule_p.add_argument(
        "--for-config", type=str, default=None, metavar="NAME",
        help="Saved YAML preset name (or YAML file path) the scheduled run "
             "should load. The generated command will include --config NAME.",
    )
    schedule_p.add_argument(
        "--time", type=str, default="06:15", metavar="HH:MM",
        help="Wall-clock daily run time in 24-hour HH:MM (default 06:15).",
    )
    schedule_p.add_argument(
        "--task-name", type=str, default="ramen-cve-daily", metavar="NAME",
        help="Task Scheduler task name (Windows only; ignored for cron).",
    )
    schedule_p.add_argument(
        "--python", type=str, default=None, metavar="PATH",
        help="Python interpreter path to embed in the schedule. "
             "Defaults to sys.executable.",
    )
    schedule_p.add_argument(
        "--output", type=_path_arg, default=None, metavar="FILE",
        help="Write the generated XML / crontab line to this file instead "
             "of stdout.",
    )
    schedule_p.add_argument("--quiet", action="store_true")
    schedule_p.add_argument("--verbose", action="store_true")

    # stix subcommand: ingest a STIX 2.1 bundle from disk or via TAXII 2.1
    stix_p = sub.add_parser("stix", help="Ingest a STIX 2.1 bundle (file or TAXII).")
    stix_p.add_argument("path", nargs="?", type=_path_arg, help="Path to a STIX bundle JSON file.")
    stix_p.add_argument("--taxii-url", help="TAXII 2.1 API root URL.")
    stix_p.add_argument("--taxii-collection", help="TAXII 2.1 collection ID.")
    stix_p.add_argument("--taxii-user", help="Optional TAXII basic-auth username.")
    stix_p.add_argument("--taxii-pass", help="Optional TAXII basic-auth password.")
    _shared_flags(stix_p)

    return parser


def _configure_logging(args: argparse.Namespace) -> None:
    """Set log level from --quiet / --verbose flags.

    The hunt subcommand doesn't share the analysis flags, so we read them
    defensively via getattr so logging works for every subcommand.
    """
    if getattr(args, "quiet", False):
        level = logging.WARNING
    elif getattr(args, "verbose", False):
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s %(message)s")


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Cross-field validation that argparse can't express natively."""
    if args.start is not None and args.end is not None and args.start > args.end:
        parser.error(f"--start ({args.start}) must not be later than --end ({args.end}).")
    if args.date_mode == "epss":
        if args.start is None or args.end is None:
            parser.error(
                "--date-mode epss requires both --start and --end (set to the same date "
                "for the EPSS snapshot you want)."
            )
        if args.start != args.end:
            parser.error("--date-mode epss requires --start and --end to be the same date.")


def _run_wizard() -> list[str]:
    """Interactively collect every CLI flag and return an argv list.

    Activated when ramen_cve is invoked with no arguments. Uses questionary
    for menus, text prompts, and confirmations. Returns an argv list shaped
    exactly like what the user could have typed, then main() re-parses it
    so all the normal argparse validation still applies.
    """
    import questionary

    print("Ramen CVE — interactive wizard\n", file=sys.stderr)

    mode = questionary.select(
        "What would you like to triage?",
        choices=[
            questionary.Choice("OPML feed list (a file of RSS/Atom feeds)", value="opml"),
            questionary.Choice("A single URL (article, blog post, advisory)", value="url"),
            questionary.Choice("A list of CVE IDs", value="cve"),
        ],
    ).unsafe_ask()

    argv: list[str] = [mode]

    if mode == "opml":
        # Accept EITHER a single .opml file OR a directory containing one or
        # more *.opml files. The validator handles quote-stripping and ~
        # expansion so the user can paste Windows paths straight in.
        path = questionary.path(
            "Path to an OPML file or a directory containing .opml files:",
            validate=_validate_opml_input,
        ).unsafe_ask()
        argv.append(str(Path(_strip_path_quotes(path)).expanduser()))
    elif mode == "url":
        url = questionary.text(
            "URL to scan:",
            validate=lambda s: (
                True if s.startswith(("http://", "https://")) else "Must start with http:// or https://"
            ),
        ).unsafe_ask()
        argv.append(url)
    else:  # cve
        from_file = questionary.confirm(
            "Read CVE IDs from a text file? (No = type them in)", default=False
        ).unsafe_ask()
        if from_file:
            file_path = questionary.path(
                "Path to CVE list file:",
                validate=lambda p: (
                    True
                    if Path(_strip_path_quotes(p)).expanduser().is_file()
                    else "File not found."
                ),
            ).unsafe_ask()
            argv.extend(["--from-file", str(Path(_strip_path_quotes(file_path)).expanduser())])
        else:
            # Free-form list prompt. The prompt text deliberately does NOT
            # carry a literal example (e.g. "CVE-2021-44228, CVE-2021-26855")
            # — earlier UX feedback flagged that users had to backspace
            # placeholders. The expected format is documented in
            # _wizard_validate_cve_list's docstring instead.
            cves_raw = questionary.text(
                "CVE IDs (comma- or whitespace-separated):",
                validate=_wizard_validate_cve_list,
            ).unsafe_ask()
            tokens = [t for t in re.split(r"[,\s]+", cves_raw.strip()) if t]
            argv.extend(tokens)

    date_mode = questionary.select(
        "Which date should the start/end window filter on?",
        choices=[
            questionary.Choice("feed — when the feed item was published", value="feed"),
            questionary.Choice("disclosure — when NVD published the CVE", value="disclosure"),
            questionary.Choice(
                "epss — single-day EPSS snapshot (start must equal end)", value="epss"
            ),
        ],
        default="feed",
    ).unsafe_ask()
    argv.extend(["--date-mode", date_mode])

    apply_window = questionary.confirm(
        "Restrict to a date window?", default=False
    ).unsafe_ask()
    if apply_window or date_mode == "epss":
        if date_mode == "epss":
            single = questionary.text(
                "EPSS snapshot date (YYYY-MM-DD):",
                validate=_wizard_validate_date,
            ).unsafe_ask()
            argv.extend(["--start", single, "--end", single])
        else:
            start = questionary.text(
                "Start date (YYYY-MM-DD), blank to skip:",
                validate=lambda s: _wizard_validate_date(s) if s else True,
            ).unsafe_ask()
            end = questionary.text(
                "End date (YYYY-MM-DD), blank to skip:",
                validate=lambda s: _wizard_validate_date(s) if s else True,
            ).unsafe_ask()
            if start:
                argv.extend(["--start", start])
            if end:
                argv.extend(["--end", end])

    cvss = questionary.text(
        f"CVSS threshold (0.0-10.0) [{DEFAULT_CVSS_THRESHOLD}]:",
        default=str(DEFAULT_CVSS_THRESHOLD),
        validate=lambda s: _wizard_validate_float(s, 0.0, 10.0),
    ).unsafe_ask()
    argv.extend(["--cvss-threshold", cvss])

    epss = questionary.text(
        f"EPSS threshold (0.0-1.0) [{DEFAULT_EPSS_THRESHOLD}]:",
        default=str(DEFAULT_EPSS_THRESHOLD),
        validate=lambda s: _wizard_validate_float(s, 0.0, 1.0),
    ).unsafe_ask()
    argv.extend(["--epss-threshold", epss])

    basename = questionary.text(
        "Output filename stem (no extension; blank = auto timestamp):",
    ).unsafe_ask()
    basename_clean = _safe_basename(basename)
    if basename_clean:
        argv.extend(["--basename", basename_clean])

    out_dir = questionary.path(
        "Output directory (blank = current working directory):",
        only_directories=True,
    ).unsafe_ask()
    out_dir_clean = _strip_path_quotes(out_dir)
    argv.extend([
        "--out-dir",
        str(Path(out_dir_clean).expanduser()) if out_dir_clean else ".",
    ])

    fmt = questionary.select(
        "Output format:",
        choices=["both", "csv", "md"],
        default="both",
    ).unsafe_ask()
    argv.extend(["--format", fmt])

    if questionary.confirm("Skip the local SQLite cache?", default=False).unsafe_ask():
        argv.append("--no-cache")

    verbosity = questionary.select(
        "Log verbosity:",
        choices=[
            questionary.Choice("normal (INFO)", value="normal"),
            questionary.Choice("quiet (WARNING)", value="quiet"),
            questionary.Choice("verbose (DEBUG)", value="verbose"),
        ],
        default="normal",
    ).unsafe_ask()
    if verbosity == "quiet":
        argv.append("--quiet")
    elif verbosity == "verbose":
        argv.append("--verbose")

    return argv


def _wizard_validate_date(value: str) -> bool | str:
    """Questionary validator for ISO dates."""
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return "Expected YYYY-MM-DD."


def _wizard_validate_cve_list(value: str) -> bool | str:
    """Questionary validator for a free-form list of CVE IDs.

    Accepts one or more CVE IDs separated by commas and/or whitespace. Each
    token must match the CVE regex ``CVE-YYYY-NNNN`` (with a 4-7 digit
    suffix). The runtime error message does NOT echo a literal example, so
    the user never has to backspace placeholder text.

    Example shapes (for maintainers only, in this docstring):
        "CVE-2021-44228, CVE-2021-26855"
        "CVE-2021-44228 CVE-2021-26855"
        "cve-2021-44228"            (case-insensitive; normalized later)
    """
    if not value or not value.strip():
        return "Enter at least one CVE ID."
    tokens = [t for t in re.split(r"[,\s]+", value.strip()) if t]
    if not tokens:
        return "Enter at least one CVE ID."
    bad = [t for t in tokens if not CVE_REGEX.fullmatch(t.upper())]
    if bad:
        sample = ", ".join(bad[:3])
        return (
            f"Invalid CVE ID(s): {sample}. "
            "Expected CVE-YYYY-NNNN format (NNNN may be 4–7 digits)."
        )
    return True


def _wizard_validate_float(value: str, lo: float, hi: float) -> bool | str:
    """Questionary validator for floats inside a range."""
    try:
        f = float(value)
    except ValueError:
        return "Enter a number."
    if not lo <= f <= hi:
        return f"Must be between {lo} and {hi}."
    return True


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    if argv is None and len(sys.argv) <= 1:
        if _is_interactive():
            try:
                argv = _run_wizard()
            except KeyboardInterrupt:
                print("\nCancelled.", file=sys.stderr)
                return 130
        else:
            print(
                "ramen_cve: no arguments supplied and stdin is not a TTY.\n"
                "Run with --help for usage, or invoke interactively to use the wizard.",
                file=sys.stderr,
            )
            return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    # --list-configs: dump every saved preset name + path and exit.
    if getattr(args, "list_configs", False):
        presets = list_yaml_presets()
        if not presets:
            print(f"(no saved presets under {DEFAULT_PRESETS_DIR})")
        else:
            for p in presets:
                print(f"{p.stem}\t{p}")
        return 0

    # --reset-config NAME: delete one preset and exit.
    if getattr(args, "reset_config", None):
        removed = delete_yaml_preset(args.reset_config)
        if removed:
            print(f"Deleted preset → {removed}")
            return 0
        print(f"error: no such preset: {args.reset_config}", file=sys.stderr)
        return 1

    # --reset-opml: forget the remembered OPML source and exit.
    if getattr(args, "reset_opml", False):
        if _reset_remembered_opml():
            print("Forgot the remembered OPML source.")
        else:
            print("No remembered OPML source to clear.")
        return 0

    # --config NAME / --config path/to.yaml: load YAML and overlay onto args
    # BEFORE _configure_logging so logging.level keys take effect.
    if getattr(args, "config", None):
        try:
            yaml_cfg = load_yaml_config(args.config)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        apply_yaml_config(args, yaml_cfg)
        # The YAML may have supplied the subcommand. If the parser couldn't
        # bind one, reparse the args namespace into the chosen subcommand
        # context now. The pragmatic shortcut: pass attributes through as-is
        # and let the existing dispatch logic below pick the runner.
        if not getattr(args, "subcommand", None):
            print(
                "error: no subcommand was provided and the config did not "
                "supply one (set `subcommand:` in the YAML).",
                file=sys.stderr,
            )
            return 1

    # Subcommand is required after --config / --list-configs handling.
    if not getattr(args, "subcommand", None):
        parser.error("a subcommand is required (or use --config / --list-configs).")

    _configure_logging(args)

    # If --save-config was passed, persist the (post-YAML-overlay) namespace
    # before running so the preset captures the actual run shape even on
    # later failure. The save happens regardless of run outcome.
    if getattr(args, "save_config", None):
        try:
            written = save_yaml_config(args.save_config, args_to_yaml_payload(args))
            _log.info("Saved YAML preset → %s", written)
        except Exception as exc:
            _log.warning("Could not save YAML preset %r: %s", args.save_config, exc)

    # The hunt subcommand is a pure local-file workflow but we still open
    # the cache so audit logging can persist. trend / pir / audit are similar
    # — all skip _validate_args (which expects analysis-specific args).
    if args.subcommand == "hunt":
        cache_path = DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "hunt", args, lambda: _run_hunt(args, cache, None))

    if args.subcommand == "pir":
        cache_path = DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "pir", args, lambda: _run_pir(args, cache, None))

    if args.subcommand == "trend":
        cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "trend", args, lambda: _run_trend(args, cache, None))

    # The audit subcommand reads the log; it must NOT log itself (every
    # `ramen_cve audit` would otherwise grow the table it's trying to read).
    if args.subcommand == "audit":
        cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
        return _run_audit(args, Cache(cache_path), api_key=None)

    # The schedule subcommand only emits text (XML / crontab). It needs no
    # cache, no network, and no API key — but we still audit-log it so an
    # operator can see when a scheduled task was (re)generated.
    if args.subcommand == "schedule":
        cache = Cache(DEFAULT_CACHE_PATH)
        return _audit_dispatch(
            cache, "schedule", args, lambda: _run_schedule(args, cache, None)
        )

    _validate_args(args, parser)

    cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
    cache = Cache(cache_path)

    import os

    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.getenv("NVD_API_KEY") or None
    if api_key is None:
        prompted = _prompt_for_api_key(reason="missing")
        if prompted:
            api_key = prompted

    if args.subcommand == "opml":
        return _audit_dispatch(cache, "opml", args, lambda: _run_opml(args, cache, api_key))
    if args.subcommand == "url":
        return _audit_dispatch(cache, "url", args, lambda: _run_url(args, cache, api_key))
    if args.subcommand == "cve":
        return _audit_dispatch(cache, "cve", args, lambda: _run_cve(args, cache, api_key))
    if args.subcommand == "stix":
        return _audit_dispatch(cache, "stix", args, lambda: _run_stix(args, cache, api_key))
    return 1


def _maybe_enrich_iocs(args: argparse.Namespace, iocs: list[IocRecord], cache: Cache) -> None:
    """Run enrich_iocs unless --no-enrich-iocs was passed."""
    if iocs and not args.no_enrich_iocs:
        enrich_iocs(iocs, cache)


def _maybe_filter_by_sector(
    args: argparse.Namespace, enriched: list[EnrichedCve]
) -> list[EnrichedCve]:
    """Drop CVEs whose only adversary attribution targets a different sector.

    Safe-by-default policy: a CVE with NO linked_actors stays in the report
    (we can't claim it isn't relevant). A CVE with linked_actors stays only
    if at least one actor's sectors_targeted includes the chosen sector.

    A blank `args.sector` (the default) returns the list untouched.
    """
    sector = (getattr(args, "sector", None) or "").strip().lower()
    if not sector:
        return enriched
    kept: list[EnrichedCve] = []
    dropped = 0
    for rec in enriched:
        if not rec.linked_actors:
            kept.append(rec)
            continue
        if any(sector in (a.sectors_targeted or []) for a in rec.linked_actors):
            kept.append(rec)
        else:
            dropped += 1
    if dropped:
        _log.info(
            "Dropped %d CVE(s) whose only adversary attribution did not target %r.",
            dropped, sector,
        )
    return kept


def _decay_and_filter_iocs(
    args: argparse.Namespace, iocs: list[IocRecord]
) -> list[IocRecord]:
    """Stamp every IOC with its decay-weighted confidence and drop any below the floor.

    Mutates each IOC's confidence in place, then returns a (possibly shorter)
    list with sub-floor entries excluded. The floor defaults to 0.0 — without
    --ioc-confidence-floor every input survives.
    """
    apply_ioc_decay(iocs)
    floor = float(getattr(args, "ioc_confidence_floor", 0.0) or 0.0)
    before = len(iocs)
    out = filter_iocs_by_confidence(iocs, floor)
    dropped = before - len(out)
    if dropped:
        _log.info(
            "Dropped %d IOC(s) below the confidence floor (%.3f).", dropped, floor,
        )
    return out


def _resolve_associations(args: argparse.Namespace) -> dict[str, dict[str, list]]:
    """Resolve which associations file to use for this run.

    Falls back to the bundled DEFAULT_ASSOCIATIONS_PATH unless the user passed
    --associations-file. A missing file produces an empty dict + warning so the
    rest of the pipeline still runs.
    """
    return load_associations(args.associations_file)


def _maybe_dispatch(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """If --dispatch is set, push high-priority records to configured dispatchers."""
    if not getattr(args, "dispatch", False):
        return
    sent = dispatch_records(enriched)
    _log.info("Dispatch complete: %d successful posts.", sent)


def _group_records_by_owner(
    enriched: list[EnrichedCve],
    inventory_rows: list[dict[str, str]],
    fallback_recipient: str | None,
) -> dict[str, list[EnrichedCve]]:
    """Map recipient email → list of EnrichedCves they should receive.

    Each inventory row may have an `owner` email; we build host→owner first,
    then for every record in (kev_override, patch_now) we route the record to
    each owner of every affected_host. Records with no inventory match (or
    whose hosts have no owner) go to fallback_recipient if set.
    """
    host_to_owners: dict[str, list[str]] = {}
    for row in inventory_rows or []:
        host = (row.get("host") or "").strip()
        owner = (row.get("owner") or "").strip()
        if host and owner:
            host_to_owners.setdefault(host, []).append(owner)

    by_owner: dict[str, list[EnrichedCve]] = {}
    for rec in enriched:
        if rec.bucket not in DISPATCH_DEFAULT_BUCKETS:
            continue
        owners_for_rec: set[str] = set()
        for host in rec.affected_hosts:
            for owner in host_to_owners.get(host, []):
                owners_for_rec.add(owner)
        if not owners_for_rec and fallback_recipient:
            owners_for_rec.add(fallback_recipient)
        for owner in owners_for_rec:
            by_owner.setdefault(owner, []).append(rec)
    return by_owner


def _build_digest_body(
    recipient: str,
    records: list[EnrichedCve],
    inventory_rows: list[dict[str, str]],
) -> str:
    """Render the per-recipient digest body in Markdown."""
    host_to_owners: dict[str, list[str]] = {}
    for row in inventory_rows or []:
        host = (row.get("host") or "").strip()
        owner = (row.get("owner") or "").strip()
        if host and owner:
            host_to_owners.setdefault(host, []).append(owner)

    lines = [
        f"# Daily Patch Digest for {recipient}",
        "",
        f"You have {len(records)} actionable finding(s) "
        f"({sum(1 for r in records if r.bucket == 'kev_override')} KEV-listed).",
        "",
    ]
    for rec in records:
        owned_hosts = [
            h for h in rec.affected_hosts
            if recipient in host_to_owners.get(h, [])
        ]
        cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
        lines += [
            f"## {rec.cve_id} ({rec.bucket})",
            f"- **Action:** {rec.suggested_action}",
            f"- **CVSS:** {cvss}",
        ]
        if rec.kev_listed and rec.kev_due_date:
            lines.append(f"- **CISA KEV due date:** {rec.kev_due_date}")
        if owned_hosts:
            lines.append(
                f"- **Your hosts ({len(owned_hosts)}):** " + ", ".join(owned_hosts[:8])
            )
        elif rec.affected_hosts:
            lines.append(
                f"- **Hosts in inventory:** {len(rec.affected_hosts)}"
            )
        lines.append("")
    lines += [
        "---",
        "*Full CSV and Markdown reports are attached.*",
        "",
    ]
    return "\n".join(lines)


def _maybe_digest(
    args: argparse.Namespace,
    enriched: list[EnrichedCve],
    output_paths: dict[str, Path | None],
) -> None:
    """If --digest is set, send one batched email per recipient with attachments.

    Recipients are derived from the inventory CSV's `owner` column (per host).
    A `RAMEN_DIGEST_TO` env var catches CVEs whose affected hosts have no
    explicit owner. CSV (cve + ioc) and Markdown report files are attached.
    """
    if not getattr(args, "digest", False):
        return
    dispatcher = EmailDispatcher.from_env()
    if not dispatcher.enabled():
        _log.warning(
            "--digest requested but RAMEN_SMTP_HOST / RAMEN_SMTP_FROM are "
            "not configured; no digest sent."
        )
        return
    inventory_rows = getattr(args, "_inventory_rows", []) or []
    by_owner = _group_records_by_owner(
        enriched, inventory_rows, dispatcher.fallback_recipient
    )
    if not by_owner:
        _log.info(
            "--digest: no kev_override / patch_now records mapped to a recipient; "
            "nothing sent."
        )
        return
    attachments = [
        output_paths.get("csv"),
        output_paths.get("iocs_csv"),
        output_paths.get("md"),
    ]
    attachments = [a for a in attachments if a is not None]
    sent = 0
    for recipient, recs in sorted(by_owner.items()):
        body = _build_digest_body(recipient, recs, inventory_rows)
        subject = f"ramen-cve digest — {len(recs)} actionable CVE(s)"
        if dispatcher.send_digest(recipient, subject, body, attachments):
            sent += 1
    _log.info(
        "Email digest complete: %d / %d recipient(s) reached.", sent, len(by_owner),
    )


def _maybe_correlate_inventory(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """Load --inventory (if set) and annotate each EnrichedCve with affected_hosts.

    A missing or unreadable inventory file is logged as an error but does NOT
    abort the run — the rest of the report is still useful without correlation.
    The parsed inventory rows are stashed on args._inventory_rows so the email
    digest dispatcher can map hosts → owner email addresses later.
    """
    inv_path: Path | None = getattr(args, "inventory", None)
    if not inv_path:
        args._inventory_rows = []
        return
    try:
        inventory = load_inventory(inv_path)
    except OpmlError as exc:
        _log.error("Inventory correlation skipped: %s", exc)
        args._inventory_rows = []
        return
    correlate_inventory(enriched, inventory)
    affected = sum(1 for r in enriched if r.affected_hosts)
    _log.info(
        "Inventory correlation: %d/%d CVEs affect at least one host (%d inventory rows).",
        affected, len(enriched), len(inventory),
    )
    args._inventory_rows = inventory


def _get_github_token() -> str | None:
    """Return GITHUB_TOKEN from the environment, or None if absent.

    The token is only used to lift GitHub Search rate limits when
    enrich_with_exploit_status is enabled. We never log it and never persist it.
    """
    import os

    token = os.getenv("GITHUB_TOKEN") or None
    return token


# Output-format file extensions that _safe_basename strips off a user-supplied
# basename so we don't end up with `my-report.csv.csv`. Edit here when adding
# new --format choices.
_KNOWN_OUTPUT_EXTENSIONS: tuple[str, ...] = (
    ".csv", ".md", ".json", ".yar", ".yaml", ".yml",
)


def _safe_basename(value: str | None) -> str:
    """Sanitize a user-supplied basename for use as an output-file stem.

    Steps applied in order:
      1. Strip surrounding whitespace.
      2. Replace path / glob / shell-meta characters ( \\ / : * ? " < > | )
         with ``_``.
      3. Strip leading dot / dash / underscore runs so traversal artefacts
         (``../etc/passwd``) and hidden-file shapes (``.cache``) collapse
         to a clean stem.
      4. Strip one trailing recognized output extension (``.csv``, ``.md``,
         ``.json``, ``.yar``, ``.yaml``, ``.yml``). The writer re-appends
         the correct extension based on the actual format being written,
         so a user pasting ``my-report.csv`` ends up with one ``.csv``,
         not two.

    Empty input returns ``''`` (the caller falls back to a timestamped stem).
    """
    if not value:
        return ""
    cleaned = re.sub(r"[\\/:*?\"<>|]+", "_", value.strip())
    cleaned = cleaned.lstrip(". -_")
    # Strip ONE known output extension if present (case-insensitive).
    lower = cleaned.lower()
    for ext in _KNOWN_OUTPUT_EXTENSIONS:
        if lower.endswith(ext):
            cleaned = cleaned[: -len(ext)]
            break
    return cleaned or ""


def _unique_output_path(
    out_dir: Path, ts: str, suffix: str, basename: str | None = None
) -> Path:
    """Return a path that does not yet exist by appending -N if needed.

    If `basename` is provided it becomes the file stem (e.g. 'q2-triage.csv').
    Otherwise we fall back to the timestamped 'ramen-cve-<ts>.<suffix>' shape.
    Two runs that land on the same stem must not silently overwrite each other:
    we probe -1, -2, ... up to 1000 and return the first free name.
    """
    stem = _safe_basename(basename) or f"ramen-cve-{ts}"
    base = out_dir / f"{stem}.{suffix}"
    if not base.exists():
        return base
    for i in range(1, 1000):
        candidate = out_dir / f"{stem}-{i}.{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate a unique output filename in {out_dir}")


def _output(
    enriched: list[EnrichedCve],
    args: argparse.Namespace,
    metadata: dict,
    iocs: list[IocRecord] | None = None,
) -> dict[str, Path | None]:
    """Write CSV and/or Markdown output based on --format flag.

    Returns a dict mapping output kind ('csv', 'iocs_csv', 'md', 'stix',
    'sigma_dir', 'yara_dir') to the Path that was written, or None for the
    kinds that --format didn't ask for. Callers use that dict to attach the
    rendered files in downstream pushes (see _maybe_digest).

    When `iocs` is non-empty and --format includes csv, an additional
    `<basename>-iocs.csv` file is written next to the main CVE CSV. The
    Markdown report grows an Indicators of Compromise section regardless.

    TLP:RED records are stripped from the output unless --allow-tlp-red was
    passed; the count of stripped records is logged at WARNING.
    """
    # Microsecond resolution makes single-process collisions essentially
    # impossible; the -N suffix loop in _unique_output_path covers
    # cross-process collisions and any clock that lacks sub-second
    # resolution.
    ts = _utcnow().strftime("%Y%m%dT%H%M%S%f")
    # Resolve --out-dir = None / '' / '.' to the actual cwd so the on-disk
    # path is unambiguous (no leading-period surprises on Windows).
    out_dir: Path = _resolve_out_dir(getattr(args, "out_dir", None))
    out_dir.mkdir(parents=True, exist_ok=True)
    iocs = iocs or []
    basename = _safe_basename(getattr(args, "basename", None))
    sigma_stem = basename or f"ramen-cve-{ts}"

    if not getattr(args, "allow_tlp_red", False):
        before = (len(enriched), len(iocs))
        enriched = [r for r in enriched if (r.tlp or "CLEAR").upper() != "RED"]
        iocs = [i for i in iocs if (i.tlp or "CLEAR").upper() != "RED"]
        stripped_cve = before[0] - len(enriched)
        stripped_ioc = before[1] - len(iocs)
        if stripped_cve or stripped_ioc:
            _log.warning(
                "Stripped %d TLP:RED CVE record(s) and %d TLP:RED IOC record(s); "
                "pass --allow-tlp-red to include them.",
                stripped_cve,
                stripped_ioc,
            )

    paths: dict[str, Path | None] = {
        "csv": None, "iocs_csv": None, "md": None,
        "stix": None, "sigma_dir": None, "yara_dir": None,
    }

    if args.format in ("csv", "both", "all"):
        csv_path = _unique_output_path(out_dir, ts, "csv", basename=basename)
        _log.info("Writing CVE CSV report → %s", csv_path)
        write_csv(enriched, csv_path)
        print(str(csv_path))
        paths["csv"] = csv_path
        if iocs:
            # Without a basename, we want `ramen-cve-<ts>-iocs.csv`. Encoding
            # the "-iocs" tail via the suffix kwarg keeps that shape. With a
            # basename, we instead set the stem to `<basename>-iocs` and use
            # a plain ".csv" suffix so we don't end up with `*-iocs.iocs.csv`.
            if basename:
                iocs_path = _unique_output_path(
                    out_dir, ts, "csv", basename=f"{basename}-iocs"
                )
            else:
                iocs_path = _unique_output_path(out_dir, ts, "iocs.csv")
            _log.info("Writing IOC CSV report → %s", iocs_path)
            write_iocs_csv(iocs, iocs_path)
            print(str(iocs_path))
            paths["iocs_csv"] = iocs_path

    if args.format in ("md", "both", "all"):
        md_path = _unique_output_path(out_dir, ts, "md", basename=basename)
        _log.info("Writing Markdown report → %s", md_path)
        write_markdown(enriched, md_path, metadata, iocs=iocs)
        print(str(md_path))
        paths["md"] = md_path

    if args.format in ("stix", "all"):
        stix_path = _unique_output_path(out_dir, ts, "stix.json", basename=basename)
        _log.info("Writing STIX 2.1 bundle → %s", stix_path)
        write_stix(enriched, stix_path, iocs=iocs, run_metadata=metadata)
        print(str(stix_path))
        paths["stix"] = stix_path

    if args.format in ("sigma", "all"):
        sigma_dir = out_dir / f"{sigma_stem}-sigma"
        _log.info("Writing Sigma rule stubs → %s", sigma_dir)
        files = write_sigma_stubs(enriched, sigma_dir)
        if files:
            print(str(sigma_dir))
            paths["sigma_dir"] = sigma_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs in this run; no Sigma stubs written."
            )

    if args.format in ("yara", "all"):
        yara_dir = out_dir / f"{sigma_stem}-yara"
        _log.info("Writing YARA rule stubs → %s", yara_dir)
        files = write_yara_stubs(enriched, yara_dir)
        if files:
            print(str(yara_dir))
            paths["yara_dir"] = yara_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs with linked malware; "
                "no YARA stubs written."
            )
    return paths


def _run_opml(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the opml subcommand.

    `args.path` may point at:
      - a single .opml file (the historical behavior),
      - a directory containing one or more .opml files (every top-level
        *.opml is loaded and merged into a single run), or
      - nothing, in which case a previously-remembered OPML source
        (--remember-opml on an earlier run, or a YAML `remember_opml`)
        is reused.

    Bad / missing paths raise OpmlError, surfaced as a friendly stderr
    message + non-zero exit code instead of a traceback. When
    --remember-opml (or remember_opml: true in YAML) is set, the resolved
    source is persisted at the end of a successful run.
    """
    import feedparser

    opml_source: Path | None = args.path
    if opml_source is None:
        opml_source = _load_remembered_opml()
        if opml_source is None:
            _log.error(
                "No OPML path given and nothing remembered. Provide a path "
                "(file or directory of *.opml), or run once with "
                "--remember-opml so a later bare `opml` can reuse it."
            )
            return 1
        _log.info("Reusing remembered OPML source: %s", opml_source)

    try:
        opml_files = _collect_opml_files(opml_source)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    entries: list[FeedEntry] = []
    for opml_file in opml_files:
        _log.info("Loading OPML file: %s", opml_file)
        entries.extend(parse_opml(opml_file))

    if not entries:
        _log.warning("No <outline> entries with xmlUrl found across %d OPML file(s).",
                     len(opml_files))

    records: list[CveRecord] = []
    iocs: list[IocRecord] = []
    sources: list[str] = []

    for entry in entries:
        safe_url = _safe_url_for_log(entry.url)
        _log.info("Fetching feed: %s", safe_url)
        sources.append(entry.title or entry.url)
        feed = feedparser.parse(entry.url)
        if getattr(feed, "bozo", 0):
            reason = getattr(feed, "bozo_exception", "unknown parse error")
            _log.warning("Feed %s parsed with errors: %s", safe_url, reason)
        feed_source = entry.title or entry.url
        for item in feed.entries or []:
            pub = item.get("published_parsed") or item.get("updated_parsed")
            item_date = date(*pub[:3]) if pub else date.today()
            text = " ".join(
                [
                    item.get("title", ""),
                    item.get("summary", ""),
                    item.get("content", [{}])[0].get("value", "") if item.get("content") else "",
                ]
            )
            records.extend(extract_cves(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
            ))
            iocs.extend(extract_iocs(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
            ))

    iocs = _dedupe_iocs(iocs)

    date_mode = args.date_mode or "feed"
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"opml {opml_source}",
        "sources": sources,
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)

    # OPML persistence: only after a fully successful run, so a failed
    # fetch doesn't pin a bad source for next time.
    if getattr(args, "remember_opml", False):
        try:
            state = _save_remembered_opml(opml_source)
            _log.info("Remembered OPML source for next run → %s", state)
        except OSError as exc:
            _log.warning("Could not persist remembered OPML: %s", exc)
    return 0


def _run_url(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the url subcommand."""
    safe_url = _safe_url_for_log(args.url)
    _log.info("Fetching URL: %s", safe_url)
    try:
        resp = requests.get(args.url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        _log.error("Failed to fetch URL %s: %s", safe_url, exc)
        return 1

    text = resp.text
    pub_date = date.today()
    for pattern in [
        r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
        r'<time[^>]+datetime=["\'](\d{4}-\d{2}-\d{2})',
        r'<meta[^>]+property=["\']og:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
    ]:
        m = re.search(pattern, text)
        if m:
            try:
                pub_date = date.fromisoformat(m.group(1))
                break
            except ValueError:
                _log.warning(
                    "Found publication-date-like string %r in %s but could not parse it; "
                    "trying next pattern.",
                    m.group(1),
                    safe_url,
                )
                continue
    else:
        _log.warning("Could not find publication date in %s; using today.", safe_url)

    date_mode = args.date_mode or "feed"
    records = extract_cves(text, args.url, pub_date, "feed_pub")
    iocs = extract_iocs(text, args.url, pub_date, "feed_pub")
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"url {args.url}",
        "sources": [args.url],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


def _dedupe_iocs(iocs: list[IocRecord]) -> list[IocRecord]:
    """Collapse duplicates across multiple feed items into one record per (type, value).

    Keeps the earliest first_seen, OR-merges defanged_in_source, joins distinct
    sources with '; ', and propagates the worst-TLP + best-Admiralty tags so
    the merged IOC carries provenance from every feed it appeared in.
    """
    by_key: dict[tuple[str, str], IocRecord] = {}
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = IocRecord(
                ioc_type=ioc.ioc_type,
                value=ioc.value,
                source=ioc.source,
                first_seen=ioc.first_seen,
                first_seen_type=ioc.first_seen_type,
                defanged_in_source=ioc.defanged_in_source,
                tlp=ioc.tlp,
                admiralty=ioc.admiralty,
                last_seen=ioc.last_seen or ioc.first_seen,
            )
            continue
        if ioc.first_seen < existing.first_seen:
            existing.first_seen = ioc.first_seen
            existing.first_seen_type = ioc.first_seen_type
        # last_seen: maximum across all observations wins (most recent sighting
        # is the decay anchor).
        new_last = ioc.last_seen or ioc.first_seen
        if existing.last_seen is None or new_last > existing.last_seen:
            existing.last_seen = new_last
        if ioc.defanged_in_source and not existing.defanged_in_source:
            existing.defanged_in_source = True
        if ioc.source and ioc.source not in existing.source.split("; "):
            existing.source = f"{existing.source}; {ioc.source}"
        existing.tlp = _worst_tlp(existing.tlp, ioc.tlp)
        existing.admiralty = _best_admiralty(existing.admiralty, ioc.admiralty)
    return list(by_key.values())


def _run_cve(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the cve subcommand."""
    cve_ids: list[str] = list(args.cves or [])

    if args.from_file:
        try:
            file_text = args.from_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            _log.error("--from-file path does not exist: %s", args.from_file)
            return 1
        except OSError as exc:
            _log.error("Could not read --from-file %s: %s", args.from_file, exc)
            return 1
        for line in file_text.splitlines():
            line = line.strip()
            if CVE_REGEX.fullmatch(line.upper()):
                cve_ids.append(line.upper())
            elif line:
                _log.warning("Skipping invalid CVE ID from file: %s", line)

    if not cve_ids:
        # Expected shape (kept in this comment so the error message doesn't
        # echo a literal placeholder the user has to delete):
        #   `ramen_cve cve CVE-2021-44228 CVE-2021-26855 ...`
        # or a --from-file argument whose lines each match CVE-YYYY-NNNN
        # (4-7 digit suffix).
        _log.error(
            "No valid CVE IDs provided. Pass them as positional arguments "
            "or via --from-file. Each ID must match CVE-YYYY-NNNN."
        )
        return 1

    # Default for manual CVE input is "disclosure" because there is no feed date.
    # Honor an explicit --date-mode from the user without overriding it.
    date_mode = args.date_mode or "disclosure"

    today = date.today()
    records = [CveRecord(cve_id, "manual_input", today, "manual_input") for cve_id in cve_ids]
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"cve {' '.join(cve_ids)}",
        "sources": ["manual_input"],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _output(enriched, args, metadata)
    return 0


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


_SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[float | None]) -> str:
    """Render a list of numbers as a unicode sparkline; None renders as a space."""
    real = [v for v in values if v is not None]
    if not real:
        return ""
    lo, hi = min(real), max(real)
    span = hi - lo if hi > lo else 1.0
    out: list[str] = []
    for v in values:
        if v is None:
            out.append(" ")
            continue
        idx = int(((v - lo) / span) * (len(_SPARKLINE_CHARS) - 1))
        out.append(_SPARKLINE_CHARS[max(0, min(idx, len(_SPARKLINE_CHARS) - 1))])
    return "".join(out)


def _record_runs(cache: Cache, enriched: list[EnrichedCve]) -> None:
    """Append a snapshot row per enriched CVE so `trend` has history to draw."""
    for rec in enriched:
        cache.record_run(rec.cve_id, rec.bucket, rec.cvss_score, rec.epss_score)


def _run_trend(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Print a Markdown-friendly historical trend for one CVE."""
    cve_id = (args.cve_id or "").upper()
    if not CVE_REGEX.fullmatch(cve_id):
        _log.error("trend: %r is not a valid CVE ID", args.cve_id)
        return 1
    runs = cache.get_runs(cve_id)
    if not runs:
        _log.info(
            "No historical runs recorded for %s. Run a triage with the same "
            "cache file (default: .ramen-cache.db) to seed history.",
            cve_id,
        )
        return 0
    epss_values = [r["epss_score"] for r in runs]
    cvss_values = [r["cvss_score"] for r in runs]
    print(f"# {cve_id} — {len(runs)} historical run(s)")
    print()
    print(f"EPSS: {_sparkline(epss_values)}")
    print(f"CVSS: {_sparkline(cvss_values)}")
    print()
    print("| Run timestamp (UTC) | Bucket | CVSS | EPSS |")
    print("| --- | --- | --- | --- |")
    for r in runs:
        cv = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "N/A"
        ep = f"{r['epss_score']:.4f}" if r["epss_score"] is not None else "N/A"
        print(f"| {r['ts_iso']} | {r['bucket']} | {cv} | {ep} |")
    return 0


_AUDIT_SENSITIVE_KEYS = ("key", "pass", "token", "secret")


def _audit_actor() -> str:
    """Return the current OS user for audit attribution.

    `getpass.getuser()` consults LOGNAME / USER / LNAME / USERNAME (per the
    Python stdlib) and raises OSError on platforms that have none of them.
    Fall back to 'unknown' rather than aborting the run.
    """
    import getpass

    try:
        return getpass.getuser() or "unknown"
    except OSError:
        return "unknown"


def _redact_audit_args(args: argparse.Namespace) -> str:
    """JSON-serialize argparse Namespace with sensitive values masked.

    Any field whose name contains 'key', 'pass', 'token', or 'secret' is
    replaced with '***'. Paths / dates / non-JSON-native types are stringified.
    """
    out: dict[str, object] = {}
    for k, v in vars(args).items():
        if v is None:
            out[k] = None
            continue
        if any(s in k.lower() for s in _AUDIT_SENSITIVE_KEYS):
            out[k] = "***" if v else None
            continue
        if isinstance(v, Path):
            out[k] = str(v)
        elif isinstance(v, date):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return json.dumps(out, default=str, sort_keys=True)


def _audit_dispatch(
    cache: Cache | None,
    command: str,
    args: argparse.Namespace,
    runner,
) -> int:
    """Run `runner`, persist an audit row, and return the runner's exit code.

    `runner` is a zero-arg callable that returns the subcommand's rc. We
    capture exceptions, record the outcome, and re-raise so the user-facing
    behavior is unchanged. A None `cache` (interactive bootstrap before the
    cache is opened) skips logging silently — never abort a real run for an
    audit-write failure.
    """
    actor = _audit_actor()
    args_redacted = _redact_audit_args(args)
    ts_iso = _utcnow().isoformat(timespec="seconds")
    try:
        rc = runner()
    except Exception as exc:
        if cache is not None:
            with contextlib.suppress(Exception):
                cache.log_audit(
                    actor, command, args_redacted,
                    outcome=f"error: {type(exc).__name__}",
                    ts_iso=ts_iso,
                )
        raise
    if cache is not None:
        with contextlib.suppress(Exception):
            cache.log_audit(
                actor, command, args_redacted,
                outcome=f"rc={rc}",
                ts_iso=ts_iso,
            )
    return rc


def _run_audit(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Print the tail of the append-only audit log as a Markdown table."""
    limit = max(1, int(getattr(args, "tail", 20)))
    rows = cache.get_audit(limit)
    if not rows:
        _log.info("Audit log is empty.")
        return 0
    print(f"# Audit log — last {len(rows)} entries")
    print()
    print("| Timestamp (UTC) | Actor | Command | Outcome | Args |")
    print("| --- | --- | --- | --- | --- |")
    for r in rows:
        # Backticks around args so JSON commas don't break the markdown column.
        print(
            f"| {r['ts_iso']} | {r['actor']} | {r['command']} | "
            f"{r['outcome']} | `{r['args_redacted']}` |"
        )
    return 0


def _parse_schedule_time(value: str) -> tuple[int, int]:
    """Parse an ``HH:MM`` 24-hour wall-clock string into ``(hour, minute)``.

    Raises ValueError with a clear message on bad shape so the schedule runner
    can surface it to the user.
    """
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).")
    try:
        h, m = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).") from exc
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"--time out of range: {value!r}. HH must be 0–23 and MM 0–59.")
    return h, m


def _entry_script_path() -> Path:
    """Return the absolute path to threat_intel_hunter.py for schedule commands.

    The package may live under src/ramen_cve/, so we walk one level up from
    DEFAULT_CONFIG_DIR.parent.parent.parent to find the repo root and then
    point at the script. Falls back to a relative name if the script can't
    be located on disk — e.g. when the package was pip-installed via wheel.
    """
    candidate = DEFAULT_CONFIG_DIR.parent.parent.parent / "threat_intel_hunter.py"
    if candidate.is_file():
        return candidate.resolve()
    return Path("threat_intel_hunter.py")


def _build_schedule_command(args: argparse.Namespace) -> tuple[str, list[str]]:
    """Build the (executable, argv) pair the schedule will invoke.

    Returns the Python interpreter path and the argv list that follows. The
    script path is absolute when possible so a scheduled task launched from
    SYSTEM context can still find it. --for-config NAME injects ``--config
    <NAME>`` into the argv so the scheduled run picks up the saved preset.
    """
    python_exec = args.python or sys.executable
    script = str(_entry_script_path())
    invoke = [script]
    if args.for_config:
        invoke.extend(["--config", args.for_config])
    return python_exec, invoke


def _emit_windows_task_xml(args: argparse.Namespace) -> str:
    """Return a Task Scheduler XML payload for the requested daily run.

    The XML is the minimum the Task Scheduler 2.0 schema requires for a
    DailyTrigger + Exec action. Import via:
        schtasks /Create /TN ramen-cve-daily /XML task.xml

    Hour / minute come from --time; the StartBoundary's date portion is today
    so the trigger fires from the next occurrence onward.
    """
    from xml.sax.saxutils import escape

    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    # Task Scheduler wants the executable and the argv list separated:
    cmd = python_exec
    cmd_args = " ".join(_quote_for_task_scheduler(a) for a in invoke)
    start_boundary = f"{date.today().isoformat()}T{h:02d}:{m:02d}:00"
    working_dir = str(_entry_script_path().parent if _entry_script_path().exists() else ".")
    task_name = args.task_name or "ramen-cve-daily"

    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        f'    <URI>\\{escape(task_name)}</URI>\n'
        '    <Author>ramen-cve</Author>\n'
        '    <Description>Daily CVE triage via threat_intel_hunter.py.</Description>\n'
        '  </RegistrationInfo>\n'
        '  <Triggers>\n'
        '    <CalendarTrigger>\n'
        f'      <StartBoundary>{start_boundary}</StartBoundary>\n'
        '      <Enabled>true</Enabled>\n'
        '      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n'
        '    </CalendarTrigger>\n'
        '  </Triggers>\n'
        '  <Principals>\n'
        '    <Principal id="Author">\n'
        '      <LogonType>InteractiveToken</LogonType>\n'
        '      <RunLevel>LeastPrivilege</RunLevel>\n'
        '    </Principal>\n'
        '  </Principals>\n'
        '  <Settings>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        '    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n'
        '    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n'
        '    <AllowHardTerminate>true</AllowHardTerminate>\n'
        '    <StartWhenAvailable>true</StartWhenAvailable>\n'
        '    <Enabled>true</Enabled>\n'
        '    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n'
        '  </Settings>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        f'      <Command>{escape(cmd)}</Command>\n'
        f'      <Arguments>{escape(cmd_args)}</Arguments>\n'
        f'      <WorkingDirectory>{escape(working_dir)}</WorkingDirectory>\n'
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>\n'
    )


def _quote_for_task_scheduler(value: str) -> str:
    """Quote one argv element for embedding in the Task Scheduler <Arguments>
    block. Wraps the value in double quotes if it contains whitespace or
    quote characters; leaves clean tokens untouched."""
    if not value:
        return '""'
    needs_quotes = any(c in value for c in (" ", "\t", "\"", "'"))
    if not needs_quotes:
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _emit_cron_line(args: argparse.Namespace) -> str:
    """Return a single crontab line that runs the tool daily at --time."""
    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    cmd_str = " ".join([python_exec, *invoke])
    return f"{m} {h} * * * {cmd_str}\n"


def _run_schedule(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the schedule subcommand: emit XML or a crontab line."""
    try:
        if args.action == "windows-task":
            payload = _emit_windows_task_xml(args)
        else:  # cron
            payload = _emit_cron_line(args)
    except ValueError as exc:
        _log.error(str(exc))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        _log.info("Wrote %s schedule → %s", args.action, args.output)
    else:
        sys.stdout.write(payload)
    return 0


def _run_stix(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the stix subcommand (file or TAXII source).

    The user supplies EITHER `path` or both `--taxii-url` and `--taxii-collection`.
    Combining the two is rejected so the source is unambiguous.
    """
    has_file = bool(args.path)
    has_taxii = bool(args.taxii_url and args.taxii_collection)
    if not (has_file or has_taxii):
        _log.error(
            "stix: provide a bundle path OR both --taxii-url and --taxii-collection."
        )
        return 1
    if has_file and has_taxii:
        _log.error("stix: --taxii-url is mutually exclusive with a bundle path.")
        return 1

    try:
        if has_file:
            cve_records, iocs = parse_stix_bundle(args.path)
            source_label = str(args.path)
        else:
            cve_records, iocs = pull_taxii(
                args.taxii_url,
                args.taxii_collection,
                username=args.taxii_user,
                password=args.taxii_pass,
            )
            source_label = f"taxii:{args.taxii_url}/{args.taxii_collection}"
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    if not cve_records and not iocs:
        _log.warning("STIX source produced no CVEs or IOCs.")

    date_mode = args.date_mode or "disclosure"
    enriched = enrich_cves(cve_records, cache, api_key)
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"stix {source_label}",
        "sources": [source_label],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
