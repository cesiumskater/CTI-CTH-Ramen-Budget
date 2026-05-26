"""ramen_cve.output.stix — IOC-CSV writer + STIX 2.1 / TAXII import &
export (Layer-3 serialization). pull_taxii is the only networked path.

See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import csv
import json
import logging
import re
from datetime import date
from pathlib import Path

import requests

from ..constants import CVE_REGEX, USER_AGENT
from ..models import CveRecord, EnrichedCve, IocRecord, OpmlError, _utcnow

_log = logging.getLogger(__name__)


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
    "cve_ids",
]


def write_iocs_csv(iocs: list[IocRecord], path: Path) -> None:
    """Write a CSV of non-CVE indicators alongside the main CVE CSV.

    Columns are in IOC_CSV_COLUMNS order. defanged_in_source is rendered as
    'true'/'false' so consumers can grep the file directly. The enrichments
    column is a JSON-serialized dict so the schema stays one-row-per-IOC.
    confidence is rendered to 4 decimals (1.0000 means just-seen / no decay).
    cve_ids is semicolon-joined per IocRecord.cve_ids — the offline Web UI's
    per-CVE detail page (Task 8 §6) substring-matches this column to filter
    IOCs onto the right CVE.
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
                    ";".join(rec.cve_ids),
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

