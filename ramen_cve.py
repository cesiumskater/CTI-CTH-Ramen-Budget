#!/usr/bin/env python3
"""ramen_cve — Threat intel triage on a ramen budget.

Reads an OPML file, a single URL, or a list of CVE IDs; extracts CVE
identifiers via regex; enriches each with CVSS (NVD) and EPSS (FIRST.org)
data; buckets by exploitation likelihood and impact (CISA KEV as a hard
override); and writes a CSV and a Markdown report.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import logging
import re
import sqlite3
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

DEFAULT_CVSS_THRESHOLD = 7.0
DEFAULT_EPSS_THRESHOLD = 0.10
DEFAULT_CACHE_PATH = ".ramen-cache.db"
DEFAULT_CACHE_TTL_HOURS = 24

USER_AGENT = "ramen-cve/0.1 (+https://github.com/cesiumskater)"

_log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime.

    datetime.utcnow() is deprecated in Python 3.12+. We use
    datetime.now(timezone.utc).replace(tzinfo=None) so the rest of the
    code can keep treating timestamps as naive UTC (they are written
    to and read from SQLite as ISO-8601 strings without timezone, and
    the cache TTL math compares two naive UTC datetimes).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

BUCKET_ACTIONS: dict[str, str] = {
    "kev_override": ("Patch immediately — CISA KEV listed; exploitation confirmed in the wild."),
    "patch_now": "Patch now — high CVSS and high EPSS; likely exploitable and high impact.",
    "plan_and_patch": (
        "Plan and patch — high CVSS but low EPSS; exploit unlikely but impact severe."
    ),
    "watch_closely": (
        "Watch closely — low CVSS but high EPSS; active exploitation of a lower-impact flaw."
    ),
    "deprioritize": "Deprioritize — low severity and low exploitation probability.",
    "unknown": "Insufficient data; manual review required.",
}

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OpmlError(Exception):
    """Raised when an OPML file is missing or malformed."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeedEntry:
    """A single RSS/Atom feed from an OPML file."""

    title: str
    url: str
    category: str = ""


@dataclass
class CveRecord:
    """A CVE ID as extracted from a source, before enrichment."""

    cve_id: str
    source: str
    first_seen: date
    first_seen_type: str  # "feed_pub" | "disclosure" | "manual_input"


@dataclass
class EnrichedCve:
    """A CveRecord merged with NVD and EPSS data and a bucket assignment."""

    cve_id: str
    source: str
    first_seen: date
    first_seen_type: str

    # NVD fields
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    kev_listed: bool = False
    cwe: list[str] = field(default_factory=list)
    nvd_published: date | None = None
    nvd_status: str = "ok"

    # EPSS fields
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None

    # Bucket
    bucket: str = "unknown"
    suggested_action: str = BUCKET_ACTIONS["unknown"]

    enriched_at: datetime = field(default_factory=lambda: _utcnow())


class Cache:
    """SQLite-backed cache for NVD and EPSS API responses.

    Both tables store ISO-8601 timestamps in fetched_at. TTL is checked at
    read time; stale rows are left in place until purge() is called.
    Pass path=':memory:' for a transient in-memory cache (used by --no-cache).
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cve_id      TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS epss_cache (
            cve_id      TEXT NOT NULL,
            score_date  TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            fetched_at  TEXT NOT NULL,
            PRIMARY KEY (cve_id, score_date)
        );
    """

    def __init__(self, path: Path | str, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS) -> None:
        """Open (or create) the cache database and ensure the schema exists."""
        self._ttl = timedelta(hours=ttl_hours)
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    def _is_fresh(self, fetched_at: str) -> bool:
        """Return True if fetched_at timestamp is within the TTL window.

        A corrupt timestamp (from a hand-edited cache, a downgrade, or
        a partial write) is treated as stale rather than raising — the
        row will be re-fetched from the API and overwritten.
        """
        try:
            ts = datetime.fromisoformat(fetched_at)
        except (TypeError, ValueError):
            _log.warning("Cache row has unparseable fetched_at %r; treating as stale.", fetched_at)
            return False
        return _utcnow() - ts < self._ttl

    def get_nvd(self, cve_id: str) -> dict | None:
        """Return cached NVD payload if present and within TTL, else None."""
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM nvd_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_nvd(self, cve_id: str, payload: dict) -> None:
        """Upsert an NVD payload into the cache."""
        self._conn.execute(
            "INSERT OR REPLACE INTO nvd_cache VALUES (?, ?, ?)",
            (cve_id, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def get_epss(self, cve_id: str, score_date: str) -> dict | None:
        """Return cached EPSS payload if present and within TTL, else None."""
        row = self._conn.execute(
            "SELECT payload_json, fetched_at FROM epss_cache WHERE cve_id = ? AND score_date = ?",
            (cve_id, score_date),
        ).fetchone()
        if row and self._is_fresh(row[1]):
            return json.loads(row[0])
        return None

    def set_epss(self, cve_id: str, score_date: str, payload: dict) -> None:
        """Upsert an EPSS payload into the cache."""
        self._conn.execute(
            "INSERT OR REPLACE INTO epss_cache VALUES (?, ?, ?, ?)",
            (cve_id, score_date, json.dumps(payload), _utcnow().isoformat()),
        )
        self._conn.commit()

    def purge(self) -> None:
        """Delete entries older than the TTL from both tables."""
        cutoff = (_utcnow() - self._ttl).isoformat()
        self._conn.execute("DELETE FROM nvd_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM epss_cache WHERE fetched_at < ?", (cutoff,))
        self._conn.commit()


# ---------------------------------------------------------------------------
# Pipeline backbone (stubs — implemented slice by slice)
# ---------------------------------------------------------------------------


def parse_opml(path: Path) -> list[FeedEntry]:
    """Parse an OPML file and return the list of feed entries.

    Walks <outline> elements recursively. Only outlines with an xmlUrl attribute
    are returned as FeedEntry objects; folder/category outlines are traversed but
    not emitted. The category is the immediate parent outline's text attribute.
    Raises OpmlError for missing files or malformed XML.
    """
    if not path.exists():
        raise OpmlError(f"OPML file not found: {path}")
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise OpmlError(f"Malformed OPML file {path}: {exc}") from exc

    root = tree.getroot()
    body = root.find("body")
    if body is None:
        return []

    entries: list[FeedEntry] = []

    def _walk(node: ET.Element, category: str) -> None:
        for outline in node.findall("outline"):
            url = outline.get("xmlUrl")
            if url:
                title = outline.get("title") or outline.get("text") or url
                entries.append(FeedEntry(title=title, url=url, category=category))
            # Recurse into sub-outlines whether this outline has a URL or not
            child_category = outline.get("text") or category
            _walk(outline, child_category if not url else category)

    _walk(body, "")
    return entries


def extract_cves(text: str, source: str, first_seen: date, first_seen_type: str) -> list[CveRecord]:
    """Extract and deduplicate CVE IDs from arbitrary text.

    Normalizes all IDs to upper-case and preserves order of first occurrence.
    """
    seen: set[str] = set()
    records: list[CveRecord] = []
    for match in CVE_REGEX.finditer(text):
        cve_id = match.group(0).upper()
        if cve_id not in seen:
            seen.add(cve_id)
            records.append(
                CveRecord(
                    cve_id=cve_id,
                    source=source,
                    first_seen=first_seen,
                    first_seen_type=first_seen_type,
                )
            )
    return records


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

    kev_listed = "cisaExploitAdd" in cve_data

    cwe: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-noinfo":
                cwe.append(val)

    published_str = cve_data.get("published")
    nvd_published = published_str[:10] if published_str else None

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "kev_listed": kev_listed,
        "cwe": cwe,
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


def enrich_cves(
    records: list[CveRecord],
    cache: Cache,
    api_key: str | None,
) -> list[EnrichedCve]:
    """Fetch NVD and EPSS data for each unique CVE and return enriched records.

    Deduplicates CVE IDs before hitting the APIs. When the same CVE appears in
    multiple records, only the earliest first_seen date is kept.
    """
    # Deduplicate: keep earliest first_seen per CVE
    earliest: dict[str, CveRecord] = {}
    for rec in records:
        if rec.cve_id not in earliest or rec.first_seen < earliest[rec.cve_id].first_seen:
            earliest[rec.cve_id] = rec

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

    enriched: list[EnrichedCve] = []
    for cve_id, rec in earliest.items():
        nvd = nvd_data.get(cve_id, {})
        epss = epss_data.get(cve_id, {})

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
                kev_listed=nvd.get("kev_listed", False),
                cwe=nvd.get("cwe", []),
                nvd_published=nvd_published,
                nvd_status=nvd.get("nvd_status", "ok"),
                epss_score=epss.get("epss"),
                epss_percentile=epss.get("percentile"),
                epss_date=epss.get("date"),
            )
        )

    return enriched


def bucket_and_suggest(
    enriched: list[EnrichedCve],
    cvss_thr: float = DEFAULT_CVSS_THRESHOLD,
    epss_thr: float = DEFAULT_EPSS_THRESHOLD,
) -> list[EnrichedCve]:
    """Assign a bucket and suggested action to each enriched CVE.

    NOTE: this function MUTATES the records in `enriched` in place
    (setting `rec.bucket` and `rec.suggested_action`) and returns the
    same list for chaining. Callers should not rely on the input being
    untouched.

    Precedence:
      1. kev_listed=True → kev_override (always wins)
      2. CVSS >= thr AND EPSS >= thr → patch_now
      3. CVSS >= thr AND EPSS < thr  → plan_and_patch
      4. CVSS < thr  AND EPSS >= thr → watch_closely
      5. CVSS < thr  AND EPSS < thr  → deprioritize
      Missing CVSS or EPSS           → unknown
    """
    for rec in enriched:
        if rec.kev_listed:
            rec.bucket = "kev_override"
        elif rec.cvss_score is None or rec.epss_score is None:
            rec.bucket = "unknown"
        elif rec.cvss_score >= cvss_thr and rec.epss_score >= epss_thr:
            rec.bucket = "patch_now"
        elif rec.cvss_score >= cvss_thr:
            rec.bucket = "plan_and_patch"
        elif rec.epss_score >= epss_thr:
            rec.bucket = "watch_closely"
        else:
            rec.bucket = "deprioritize"
        rec.suggested_action = BUCKET_ACTIONS[rec.bucket]
    return enriched


def filter_by_date(
    enriched: list[EnrichedCve],
    start: date | None,
    end: date | None,
    date_mode: str,
) -> list[EnrichedCve]:
    """Filter enriched CVEs by date range according to the active date mode.

    date_mode:
      "feed"        — filter on record.first_seen (publication date from the feed).
      "disclosure"  — filter on record.nvd_published (NVD published date).
      "epss"        — only start==end (single day) is supported in v1.

    Records missing the relevant date are logged and dropped.
    Both start and end are inclusive. None means no bound on that side.
    """
    if date_mode == "epss" and start != end:
        raise ValueError(
            f"--date-mode epss requires --start == --end (got {start} .. {end})."
            " Use a single date for historical EPSS lookup."
        )

    result: list[EnrichedCve] = []
    for rec in enriched:
        if date_mode == "feed":
            rec_date = rec.first_seen
        elif date_mode == "disclosure":
            rec_date = rec.nvd_published
        else:  # epss — date was already used for the API call; filter on nvd_published
            rec_date = rec.nvd_published

        if rec_date is None:
            _log.warning("CVE %s has no date for date_mode=%s; skipping.", rec.cve_id, date_mode)
            continue

        if start and rec_date < start:
            continue
        if end and rec_date > end:
            continue
        result.append(rec)

    return result


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
    "bucket",
    "suggested_action",
    "cwe",
    "nvd_published",
    "enriched_at",
]


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
                    rec.bucket,
                    rec.suggested_action,
                    ";".join(rec.cwe),
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


def write_markdown(enriched: list[EnrichedCve], path: Path, run_metadata: dict) -> None:
    """Write a human-readable Markdown triage report.

    run_metadata keys: command (str), args (str — secrets redacted), version (str),
    sources (list[str]), start (str), end (str), date_mode (str),
    cvss_threshold (float), epss_threshold (float).
    """
    lines: list[str] = []
    now = _utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total = len(enriched)

    lines += [
        "# Ramen CVE Triage Report",
        "",
        f"Generated: {now}  ",
        f"Total CVEs: **{total}**  ",
    ]
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

    if total == 0:
        lines += ["## No CVEs found", "", "No CVEs matched the current filters.", ""]

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
            lines.append(f"- **NVD Published:** {rec.nvd_published or 'N/A'}")
            lines.append(f"- **Source:** {_md_safe(rec.source)}")
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


def _shared_flags(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by all three subcommands."""
    parser.add_argument("--start", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--end", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--date-mode", choices=["feed", "disclosure", "epss"], default="feed")
    parser.add_argument("--cvss-threshold", type=float, default=DEFAULT_CVSS_THRESHOLD)
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD)
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    parser.add_argument("--format", choices=["csv", "md", "both"], default="both")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ramen_cve",
        description="Threat intel triage on a ramen budget.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # opml subcommand
    opml_p = sub.add_parser("opml", help="Process an OPML feed list.")
    opml_p.add_argument("path", type=Path, help="Path to the OPML file.")
    _shared_flags(opml_p)

    # url subcommand
    url_p = sub.add_parser("url", help="Extract CVEs from a single URL.")
    url_p.add_argument("url", help="URL of the article or page to scan.")
    _shared_flags(url_p)

    # cve subcommand
    cve_p = sub.add_parser("cve", help="Enrich named CVE IDs directly.")
    cve_p.add_argument("cves", nargs="*", type=_validate_cve_id, metavar="CVE-ID")
    cve_p.add_argument("--from-file", type=Path, metavar="FILE", help="Text file of CVE IDs.")
    _shared_flags(cve_p)

    return parser


def _configure_logging(args: argparse.Namespace) -> None:
    """Set log level from --quiet / --verbose flags."""
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s %(message)s")


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Cross-field validation that argparse can't express natively."""
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
        path = questionary.path(
            "Path to your OPML file:",
            default="examples/sample.opml",
            validate=lambda p: True if Path(p).expanduser().is_file() else "File not found.",
        ).unsafe_ask()
        argv.append(str(Path(path).expanduser()))
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
                validate=lambda p: True if Path(p).expanduser().is_file() else "File not found.",
            ).unsafe_ask()
            argv.extend(["--from-file", str(Path(file_path).expanduser())])
        else:
            cves_raw = questionary.text(
                "CVE IDs (space- or comma-separated):",
                validate=lambda s: True if s.strip() else "Enter at least one CVE ID.",
            ).unsafe_ask()
            for token in re.split(r"[,\s]+", cves_raw.strip()):
                if token:
                    argv.append(token)

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

    out_dir = questionary.path(
        "Output directory:",
        default=".",
        only_directories=True,
    ).unsafe_ask()
    argv.extend(["--out-dir", str(Path(out_dir).expanduser())])

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
        try:
            argv = _run_wizard()
        except KeyboardInterrupt:
            print("\nCancelled.", file=sys.stderr)
            return 130

    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args)
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
        return _run_opml(args, cache, api_key)
    if args.subcommand == "url":
        return _run_url(args, cache, api_key)
    if args.subcommand == "cve":
        return _run_cve(args, cache, api_key)
    return 1


def _unique_output_path(out_dir: Path, ts: str, suffix: str) -> Path:
    """Return a path that does not yet exist by appending -N if needed.

    Two runs that land in the same wall-clock second must not silently
    overwrite each other. We probe -1, -2, ... and return the first
    free name. Bounded at 1000 attempts so we don't loop forever in a
    pathological setup.
    """
    base = out_dir / f"ramen-cve-{ts}.{suffix}"
    if not base.exists():
        return base
    for i in range(1, 1000):
        candidate = out_dir / f"ramen-cve-{ts}-{i}.{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate a unique output filename in {out_dir}")


def _output(enriched: list[EnrichedCve], args: argparse.Namespace, metadata: dict) -> None:
    """Write CSV and/or Markdown output based on --format flag."""
    # Microsecond resolution makes single-process collisions essentially
    # impossible; the -N suffix loop in _unique_output_path covers
    # cross-process collisions and any clock that lacks sub-second
    # resolution.
    ts = _utcnow().strftime("%Y%m%dT%H%M%S%f")
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("csv", "both"):
        csv_path = _unique_output_path(out_dir, ts, "csv")
        write_csv(enriched, csv_path)
        print(str(csv_path))

    if args.format in ("md", "both"):
        md_path = _unique_output_path(out_dir, ts, "md")
        write_markdown(enriched, md_path, metadata)
        print(str(md_path))


def _run_opml(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the opml subcommand."""
    import feedparser

    entries = parse_opml(args.path)
    records: list[CveRecord] = []
    sources: list[str] = []

    for entry in entries:
        safe_url = _safe_url_for_log(entry.url)
        _log.info("Fetching feed: %s", safe_url)
        sources.append(entry.title or entry.url)
        feed = feedparser.parse(entry.url)
        if getattr(feed, "bozo", 0):
            reason = getattr(feed, "bozo_exception", "unknown parse error")
            _log.warning("Feed %s parsed with errors: %s", safe_url, reason)
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
            records.extend(extract_cves(text, entry.title or entry.url, item_date, "feed_pub"))

    enriched = enrich_cves(records, cache, api_key)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, args.date_mode)

    metadata = {
        "version": VERSION,
        "args": f"opml {args.path}",
        "sources": sources,
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": args.date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _output(enriched, args, metadata)
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

    records = extract_cves(text, args.url, pub_date, "feed_pub")
    enriched = enrich_cves(records, cache, api_key)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, args.date_mode)

    metadata = {
        "version": VERSION,
        "args": f"url {args.url}",
        "sources": [args.url],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": args.date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _output(enriched, args, metadata)
    return 0


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
        _log.error("No valid CVE IDs provided.")
        return 1

    date_mode = args.date_mode
    if date_mode == "feed":
        _log.info("Switching date-mode from 'feed' to 'disclosure' for manual CVE input.")
        date_mode = "disclosure"

    today = date.today()
    records = [CveRecord(cve_id, "manual_input", today, "manual_input") for cve_id in cve_ids]
    enriched = enrich_cves(records, cache, api_key)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
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


if __name__ == "__main__":
    sys.exit(main())
