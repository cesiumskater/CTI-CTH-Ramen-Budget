#!/usr/bin/env python3
"""Deterministically (re)generate the bundled ``examples/`` artefacts.

Usage
-----
    python scripts/regen_examples.py            # rewrite the example files
    python scripts/regen_examples.py --check     # verify they're up to date

``--check`` regenerates into a temp dir and diffs against the committed
files, exiting non-zero on any drift — suitable for CI.

Why this exists
---------------
The previously committed ``examples/`` bundle was hand-assembled from a
recipe that is no longer reproducible: it cited feed sources ("SANS ISC",
"Vendor Blog") that do not appear in ``examples/sample.opml``, and an actor
list that predates the current bundled ``associations.json``. Rather than
chase a lost recipe, this script rebuilds the bundle from a fully
self-contained, frozen fixture set, so the example outputs are a faithful,
repeatable product of the *current* pipeline.

Determinism
-----------
* All network is mocked: NVD, EPSS, and the CISA-KEV catalog via the inline
  payloads below; RSS feeds via a fake ``feedparser.parse``; exploit and IOC
  enrichment are disabled by flag (``--no-exploit-lookup``/``--no-enrich-iocs``)
  so no un-mocked call is ever made.
* The two live-clock fields — the CSV ``enriched_at`` column and the Markdown
  ``Generated:`` line — are normalised to a frozen instant *after* the run,
  so re-running yields no diff.

The showcase (one CVE per bucket + two defanged IOCs + an asset inventory)
------------------------------------------------------------------------
    CVE-2021-44228  Log4Shell    KEV-listed + ransomware  -> kev_override
    CVE-2021-26855  ProxyLogon   high CVSS / high EPSS     -> patch_now
    CVE-2024-0002   (synthetic)  high CVSS / low EPSS      -> plan_and_patch
    CVE-2024-0003   (synthetic)  low CVSS / high EPSS      -> watch_closely
    CVE-2024-0001   (synthetic)  low CVSS / low EPSS       -> deprioritize

The two real CVEs pick up threat-actor / malware context from the bundled
``src/ramen_cve/data/associations.json``; the three ``CVE-2024-000x`` ids are
deliberately synthetic placeholders so no real advisory is misrepresented.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))  # run without an editable install

EXAMPLES = REPO / "examples"
SAMPLE_OPML = EXAMPLES / "sample.opml"
OUT_CSV = EXAMPLES / "sample-output.csv"
OUT_MD = EXAMPLES / "sample-report.md"
OUT_INVENTORY = EXAMPLES / "sample-inventory.csv"

# Frozen clock values substituted into the volatile output fields.
FROZEN_ENRICHED_AT = "2026-01-15T09:00:00"
FROZEN_GENERATED = "2026-01-15 09:00"
FROZEN_EPSS_DATE = "2026-01-15"

# --- Showcase fixture set (inline = the documented, reproducible recipe) ----
# Each row drives the NVD mock, the EPSS mock, and which feed mentions it.
CVES: list[dict] = [
    {
        "id": "CVE-2021-44228", "cvss": 10.0, "sev": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "ver": "3.1",
        "cwe": ["CWE-502", "CWE-917"], "kev": True,
        "published": "2021-12-10T10:15:09.143",
        "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        "epss": "0.97565", "pct": "0.99968", "feed": "krebsonsecurity.com",
    },
    {
        "id": "CVE-2021-26855", "cvss": 9.8, "sev": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "ver": "3.1",
        "cwe": ["CWE-918"], "kev": False,
        "published": "2021-03-02T19:15:00.000",
        "cpe": "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*",
        "epss": "0.94318", "pct": "0.99012", "feed": "cisa.gov",
    },
    {
        "id": "CVE-2024-0002", "cvss": 8.2, "sev": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "ver": "3.1",
        "cwe": ["CWE-22"], "kev": False,
        "published": "2024-02-11T00:00:00.000",
        "cpe": "cpe:2.3:a:acme:gateway:5.2:*:*:*:*:*:*:*",
        "epss": "0.01840", "pct": "0.78000", "feed": "bleepingcomputer.com",
    },
    {
        "id": "CVE-2024-0003", "cvss": 5.4, "sev": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", "ver": "3.1",
        "cwe": ["CWE-79"], "kev": False,
        "published": "2024-03-19T00:00:00.000",
        "cpe": "", "epss": "0.62100", "pct": "0.97300",
        "feed": "bleepingcomputer.com",
    },
    {
        "id": "CVE-2024-0001", "cvss": 4.3, "sev": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "ver": "3.1",
        "cwe": ["CWE-200"], "kev": False,
        "published": "2024-01-05T00:00:00.000",
        "cpe": "", "epss": "0.00041", "pct": "0.07000",
        "feed": "bleepingcomputer.com",
    },
]
_CVE_BY_ID = {c["id"]: c for c in CVES}

# host, product, version, cpe, owner — explicit-CPE rows correlate against the
# CVE CPEs above (substring match in enrich/inventory.correlate_inventory).
INVENTORY_HEADER = "host,product,version,cpe,owner"
INVENTORY_ROWS = [
    "web-prod-01,Apache Log4j,2.14.1,cpe:2.3:a:apache:log4j,secops@example.com",
    "web-prod-02,Apache Log4j,2.14.1,cpe:2.3:a:apache:log4j,secops@example.com",
    "mail-01,Microsoft Exchange Server,2019,cpe:2.3:a:microsoft:exchange_server,mail@example.com",
    "app-05,ACME Gateway,5.2,cpe:2.3:a:acme:gateway,appowners@example.com",
]
INVENTORY_TEXT = "\n".join([INVENTORY_HEADER, *INVENTORY_ROWS]) + "\n"

# Per-feed RSS content. Defanged IOCs live in the CISA item's summary; the
# extractor refangs them and flags them as defanged-in-source.
_DEFANGED_URL = "hxxps://evil[.]example[.]com/payload"
_SAMPLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FEEDS: dict[str, tuple[str, str]] = {
    "krebsonsecurity.com": (
        "Log4Shell CVE-2021-44228 under active mass exploitation",
        "Apache Log4j2 remote code execution; patch or mitigate immediately.",
    ),
    "cisa.gov": (
        "Microsoft Exchange ProxyLogon CVE-2021-26855 actively exploited",
        "Server-side request forgery chained for RCE. C2 observed at "
        f"{_DEFANGED_URL}; dropper SHA-256 {_SAMPLE_SHA256}.",
    ),
    "bleepingcomputer.com": (
        "Weekly roundup: CVE-2024-0002, CVE-2024-0003 and CVE-2024-0001 disclosed",
        "A mix of high- and low-severity vulnerabilities reported this week.",
    ),
    "abuse.ch": ("abuse.ch tracker update", "No new CVEs to report this cycle."),
}


def _nvd_payload(cid: str) -> dict:
    """Build a minimal-but-valid NVD API v2.0 response for one CVE id."""
    c = _CVE_BY_ID.get(cid)
    if c is None:
        return {"vulnerabilities": [], "totalResults": 0}
    cve: dict = {
        "id": c["id"],
        "published": c["published"],
        "lastModified": c["published"],
        "vulnStatus": "Analyzed",
        "weaknesses": [
            {
                "source": "nvd@nist.gov", "type": "Primary",
                "description": [{"lang": "en", "value": w} for w in c["cwe"]],
            }
        ],
        "metrics": {
            f'cvssMetricV{c["ver"].replace(".", "")}': [
                {
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {
                        "version": c["ver"], "vectorString": c["vector"],
                        "baseScore": c["cvss"], "baseSeverity": c["sev"],
                    },
                }
            ]
        },
    }
    if c["kev"]:
        cve["cisaExploitAdd"] = c["published"][:10]
    if c["cpe"]:
        cve["configurations"] = [
            {"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": True, "criteria": c["cpe"]}]}]}
        ]
    return {
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
        "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [{"cve": cve}],
    }


def _epss_payload() -> dict:
    return {
        "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
        "total": len(CVES), "offset": 0, "limit": 100,
        "data": [
            {"cve": c["id"], "epss": c["epss"], "percentile": c["pct"],
             "date": FROZEN_EPSS_DATE}
            for c in CVES
        ],
    }


def _kev_payload() -> dict:
    """CISA KEV catalog listing only Log4Shell, so it alone buckets as KEV."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.01.15",
        "dateReleased": "2026-01-15T00:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228", "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains a deserialization-of-"
                                    "untrusted-data vulnerability enabling remote code execution.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
                "notes": "https://logging.apache.org/log4j/2.x/security.html",
            }
        ],
    }


def _fake_get(url, params=None, headers=None, timeout=None):
    """Route NVD / EPSS / CISA-KEV requests to the inline payloads above."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    u = (url or "").lower()
    if "cisa.gov" in u or "known_exploited" in u:
        resp.json.return_value = _kev_payload()
    elif "epss" in u or "first.org" in u:
        resp.json.return_value = _epss_payload()
    elif "nvd.nist.gov" in u:
        resp.json.return_value = _nvd_payload((params or {}).get("cveId", ""))
    else:  # any other endpoint: benign empty response (no hang, no crash)
        resp.json.return_value = {}
        resp.text = ""
    return resp


def _fake_feedparser_parse(url: str) -> object:
    title, summary = ("Security feed", "No items.")
    for host, (t, s) in FEEDS.items():
        if host in url:
            title, summary = t, s
            break

    class FakeEntry:
        def __init__(self, t: str, s: str) -> None:
            self.title = t
            self.summary = s
            self.content: list = []
            self.published_parsed = (2024, 6, 1, 0, 0, 0, 0, 0, 0)
            self.updated_parsed = None

        def get(self, key, default=None):
            return getattr(self, key, default)

    class FakeFeed:
        bozo = 0
        entries = [FakeEntry(title, summary)]

    return FakeFeed()


def _normalise_csv(data: bytes) -> bytes:
    # `enriched_at` is the only ISO datetime (has a 'T'); fixture dates don't.
    data = re.sub(rb"\d{4}-\d{2}-\d{2}T[\d:.]+", FROZEN_ENRICHED_AT.encode(), data)
    # Python's csv.writer emits CRLF; collapse to LF so the file stays stable
    # under git's autocrlf normalisation (otherwise `--check` after a fresh
    # checkout sees LF on disk vs CRLF from regen and reports false drift).
    return data.replace(b"\r\n", b"\n")


def _normalise_md(text: str) -> str:
    # Freeze the live-clock line, preserving its two-space Markdown hard break.
    text = re.sub(
        r"(?m)^Generated: .*$", f"Generated: {FROZEN_GENERATED} UTC  ", text
    )
    # The footer echoes the invocation's input path; rewrite the absolute path
    # we passed into a repo-relative one so the file is portable across machines
    # (otherwise --check fails anywhere but the machine that wrote it).
    return text.replace(str(SAMPLE_OPML), "examples/sample.opml")


def _generate(workdir: Path) -> dict[str, bytes]:
    """Run the mocked pipeline in `workdir`; return {filename: bytes}."""
    import ramen_cve

    inv_path = workdir / "sample-inventory.csv"
    inv_path.write_text(INVENTORY_TEXT, encoding="utf-8")
    out_dir = workdir / "out"
    out_dir.mkdir()

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", side_effect=_fake_feedparser_parse),
    ):
        rc = ramen_cve.main(
            [
                "opml", str(SAMPLE_OPML),
                "--out-dir", str(out_dir), "--format", "both",
                "--inventory", str(inv_path),
                "--no-exploit-lookup", "--no-enrich-iocs", "--no-cache",
            ]
        )
    if rc != 0:
        raise SystemExit(f"pipeline returned rc={rc}")

    csv_path = sorted(out_dir.glob("ramen-cve-*.csv"))[0]
    md_path = sorted(out_dir.glob("ramen-cve-*.md"))[0]
    return {
        OUT_INVENTORY.name: INVENTORY_TEXT.encode("utf-8"),
        OUT_CSV.name: _normalise_csv(csv_path.read_bytes()),
        OUT_MD.name: _normalise_md(md_path.read_text(encoding="utf-8")).encode("utf-8"),
    }


_TARGETS = {OUT_INVENTORY.name: OUT_INVENTORY, OUT_CSV.name: OUT_CSV, OUT_MD.name: OUT_MD}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate examples/ deterministically.")
    ap.add_argument(
        "--check", action="store_true",
        help="Verify the committed files match a fresh run; exit 1 on drift.",
    )
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory() as td:
        produced = _generate(Path(td))

    if args.check:
        drift = [
            name for name, data in produced.items()
            if not _TARGETS[name].exists() or _TARGETS[name].read_bytes() != data
        ]
        if drift:
            print("examples/ are STALE — run scripts/regen_examples.py:", file=sys.stderr)
            for name in drift:
                print(f"  - examples/{name}", file=sys.stderr)
            return 1
        print("examples/ are up to date.")
        return 0

    for name, data in produced.items():
        _TARGETS[name].write_bytes(data)
        print(f"wrote examples/{name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
