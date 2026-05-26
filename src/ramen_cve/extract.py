"""ramen_cve.extract — OPML / CVE / IOC extraction (Layer-1).

Parsing + regex extraction + defang. Depends on the constants/models
leaves and analyze._normalize_tlp (TLP inheritance). No network.
See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

from .analyze import _normalize_tlp
from .constants import (
    _DEFANG_DETECT,
    _DEFANG_MAP,
    _FILE_EXT_TLDS,
    CVE_REGEX,
    DOMAIN_REGEX,
    EMAIL_REGEX,
    IPV4_REGEX,
    MD5_REGEX,
    SHA1_REGEX,
    SHA256_REGEX,
    URL_REGEX,
)
from .models import CveRecord, FeedEntry, IocRecord, OpmlError

# ---------------------------------------------------------------------------
# Pipeline backbone (stubs — implemented slice by slice)
# ---------------------------------------------------------------------------


def parse_opml(path: Path) -> list[FeedEntry]:
    """Parse an OPML file and return the list of feed entries.

    Walks <outline> elements recursively. Only outlines with an xmlUrl attribute
    are returned as FeedEntry objects; folder/category outlines are traversed but
    not emitted. The category is the immediate parent outline's text attribute.

    Two extension attributes are honored: data-tlp ("CLEAR"/"GREEN"/"AMBER"/
    "AMBER+STRICT"/"RED") and data-admiralty (NATO grade, e.g. "B2"). Both are
    inherited from parent outlines so a folder can tag every feed beneath it.

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

    def _walk(node: ET.Element, category: str, tlp: str, admiralty: str) -> None:
        for outline in node.findall("outline"):
            url = outline.get("xmlUrl")
            outline_tlp = _normalize_tlp(outline.get("data-tlp")) or tlp
            outline_adm = (outline.get("data-admiralty") or admiralty or "").upper()
            # If the attribute is missing on this outline, fall through to the
            # parent's value (inheritance).
            effective_tlp = (
                _normalize_tlp(outline.get("data-tlp")) if outline.get("data-tlp") else tlp
            )
            if url:
                title = outline.get("title") or outline.get("text") or url
                entries.append(
                    FeedEntry(
                        title=title,
                        url=url,
                        category=category,
                        tlp=effective_tlp,
                        admiralty=outline_adm,
                    )
                )
            # Recurse into sub-outlines whether this outline has a URL or not
            child_category = outline.get("text") or category
            _walk(
                outline,
                child_category if not url else category,
                outline_tlp,
                outline_adm,
            )

    _walk(body, "", "CLEAR", "")
    return entries


def extract_cves(
    text: str,
    source: str,
    first_seen: date,
    first_seen_type: str,
    *,
    tlp: str = "CLEAR",
    admiralty: str = "",
) -> list[CveRecord]:
    """Extract and deduplicate CVE IDs from arbitrary text.

    Normalizes all IDs to upper-case and preserves order of first occurrence.
    Optional `tlp` and `admiralty` are stamped onto every emitted CveRecord.
    """
    seen: set[str] = set()
    records: list[CveRecord] = []
    tlp_norm = _normalize_tlp(tlp)
    admiralty_norm = (admiralty or "").upper()
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
                    tlp=tlp_norm,
                    admiralty=admiralty_norm,
                )
            )
    return records


def _defang_text(text: str) -> str:
    """Refang common IOC obfuscations: hxxp → http, [.] → ., (at) → @, etc.

    Substitutions are literal-string, case-insensitive, and applied in order.
    The original CTI convention is to defang so links don't auto-render; we
    refang first so a single regex pass can match either form.
    """
    for needle, replacement in _DEFANG_MAP:
        # re.escape on the needle so brackets/parens aren't treated as metacharacters.
        text = re.sub(re.escape(needle), replacement, text, flags=re.IGNORECASE)
    return text


# IOC confidence-decay half-lives (days). 0 means "no decay" — a SHA-256 today
# is still useful in five years. IP addresses age fastest (CDNs / DHCP); domain
# names slower (registrations rotate but campaigns reuse domains for weeks);
# emails and URLs land somewhere in between.



def _is_public_ip(ip_str: str) -> bool:
    """True if ip_str parses to a globally-routable unicast IPv4/IPv6 address."""
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


def _is_likely_filename(domain_value: str) -> bool:
    """True if the trailing label of domain_value is a common file extension."""
    return domain_value.rsplit(".", 1)[-1].lower() in _FILE_EXT_TLDS


def extract_iocs(
    text: str,
    source: str,
    first_seen: date,
    first_seen_type: str,
    *,
    tlp: str = "CLEAR",
    admiralty: str = "",
    cve_ids: list[str] | None = None,
) -> list[IocRecord]:
    """Extract a deduplicated list of non-CVE indicators from text.

    Pipeline:
      1. Detect whether the original text contained any defang markers.
      2. Refang the text via _defang_text.
      3. Run regexes for URL, email, IPv4, SHA-256/SHA-1/MD5 (in that order).
      4. If defang markers were present, additionally run the domain regex
         (false-positive rate is too high in fanged blog text to enable it
         unconditionally).
      5. Drop private/reserved IPv4 addresses and filename-shaped domains.
      6. Deduplicate by (ioc_type, value.lower()), preserving first-seen order.
    """
    defanged_in_source = bool(_DEFANG_DETECT.search(text))
    refanged = _defang_text(text)
    tlp_norm = _normalize_tlp(tlp)
    admiralty_norm = (admiralty or "").upper()
    # Deduplicate caller-supplied CVE ids while preserving order so the
    # serialized cve_ids column is deterministic across runs.
    cve_ids_norm: list[str] = []
    for cve_id in cve_ids or []:
        if cve_id not in cve_ids_norm:
            cve_ids_norm.append(cve_id)

    seen: set[tuple[str, str]] = set()
    out: list[IocRecord] = []

    def _emit(ioc_type: str, value: str) -> None:
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(
            IocRecord(
                ioc_type=ioc_type,
                value=value,
                source=source,
                first_seen=first_seen,
                first_seen_type=first_seen_type,
                defanged_in_source=defanged_in_source,
                tlp=tlp_norm,
                admiralty=admiralty_norm,
                # A freshly-extracted IOC was observed RIGHT NOW; that's the
                # decay anchor. Multi-run reservoirs (future feature) can
                # update this value when re-discovering a stale IOC.
                last_seen=first_seen,
                cve_ids=list(cve_ids_norm),
            )
        )

    for m in URL_REGEX.finditer(refanged):
        # Strip trailing sentence punctuation that the URL regex greedily ate.
        _emit("url", m.group(0).rstrip(".,;:!?"))

    for m in EMAIL_REGEX.finditer(refanged):
        _emit("email", m.group(0))

    for m in IPV4_REGEX.finditer(refanged):
        candidate = m.group(0)
        if _is_public_ip(candidate):
            _emit("ipv4", candidate)

    # Hash regexes are mutually exclusive (different fixed lengths bounded by
    # \b) so the order is purely cosmetic. Hashes are emitted lower-case.
    for regex, label in (
        (SHA256_REGEX, "sha256"),
        (SHA1_REGEX, "sha1"),
        (MD5_REGEX, "md5"),
    ):
        for m in regex.finditer(refanged):
            _emit(label, m.group(0).lower())

    if defanged_in_source:
        url_values = [r.value for r in out if r.ioc_type == "url"]
        for m in DOMAIN_REGEX.finditer(refanged):
            value = m.group(0)
            if _is_likely_filename(value):
                continue
            # Skip a domain that is the host of an already-emitted URL.
            if any(value.lower() in url_v.lower() for url_v in url_values):
                continue
            _emit("domain", value)

    return out




# ---------------------------------------------------------------------------
# URL-crawl helpers (depth-1 follow of same-host links).
#
# Pure-stdlib HTML link extraction. The tight `re` below catches the
# overwhelming majority of real-world `<a href>` tags without pulling in
# BeautifulSoup — preserving the project's 5-runtime-dep budget. Use only
# for opportunistic seed-page link discovery in `_run_url`; not a general
# HTML parser.
# ---------------------------------------------------------------------------

# `<a` followed by any tag attributes, then `href=` with optional quoting.
# Captures the URL up to the first whitespace, `>`, or matching quote.
_HREF_RE = re.compile(
    r"""<a\s+[^>]*?href=["']?([^"'>\s]+)""",
    re.IGNORECASE,
)

# Maximum links followed per seed (foot-gun + abuse guard). CLI exposes
# `--max-crawl-links` to override up to a hard ceiling.
DEFAULT_MAX_CRAWL_LINKS = 25
MAX_CRAWL_LINKS_CEILING = 200


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract every `<a href>` from `html` and resolve relatives against `base_url`.

    Order is preserved from the source HTML. Caller is responsible for any
    deduplication, host filtering, or rate limiting. Malformed URLs are
    skipped silently (this is a discovery pass, not a validator).
    """
    out: list[str] = []
    for m in _HREF_RE.finditer(html):
        href = m.group(1).strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        try:
            absolute = urllib.parse.urljoin(base_url, href)
        except ValueError:
            continue
        out.append(absolute)
    return out


def _same_host(url1: str, url2: str) -> bool:
    """True if `url1` and `url2` share a host (case-insensitive, www-stripped).

    Same-host comparison normalises:
    - Case (lowercase netloc).
    - A single leading `www.` (so `www.example.com` matches `example.com`).
    - IPv6 literal brackets (urlparse already handles).
    Port mismatch keeps two URLs distinct (intentional — different services).
    Unparseable URLs return False rather than raising.
    """
    def _norm(url: str) -> str:
        try:
            host = urllib.parse.urlparse(url).netloc.lower()
        except ValueError:
            return ""
        return host[4:] if host.startswith("www.") else host
    a, b = _norm(url1), _norm(url2)
    return bool(a) and a == b


def _filter_and_cap_links(
    seed_url: str, html: str, cap: int = DEFAULT_MAX_CRAWL_LINKS
) -> list[str]:
    """Extract, filter to same-host, dedupe (lowercased), sort, and cap to `cap`.

    Sorting + lowercasing makes the followed-link set deterministic across
    runs (critical for test snapshots + audit-log reproducibility).
    Capped at `min(cap, MAX_CRAWL_LINKS_CEILING)` so the CLI flag can't
    foot-gun arbitrarily.
    """
    cap = max(0, min(int(cap), MAX_CRAWL_LINKS_CEILING))
    candidates = _extract_links(html, seed_url)
    same_host = [u for u in candidates if _same_host(u, seed_url)]
    # Dedupe by lowercased URL, then sort for byte-stable ordering.
    deduped = sorted({u.lower() for u in same_host})
    return deduped[:cap]
