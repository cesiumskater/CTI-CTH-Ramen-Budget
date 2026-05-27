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
import csv
import re
import shutil
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
OUT_HTML = EXAMPLES / "sample-quadrant.html"
OUT_INVENTORY = EXAMPLES / "sample-inventory.csv"
WEB_SAMPLE_DIR = EXAMPLES / "_web-sample"

# Frozen clock values substituted into the volatile output fields.
FROZEN_ENRICHED_AT = "2026-01-15T09:00:00"
FROZEN_GENERATED = "2026-01-15 09:00"
FROZEN_EPSS_DATE = "2026-01-15"

# Frozen ts_iso + disk stamp for the showcase Web UI bundle. Two runs so the
# diff block has Added / Removed / Reclassified material to render.
WEB_SAMPLE_RUN_A_TS = "2025-12-01T10:00:00"
WEB_SAMPLE_RUN_B_TS = "2026-01-15T09:00:00"
WEB_SAMPLE_RUN_B_STAMP = "20260115T090000000000"

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


def _seed_web_sample_cache(workdir: Path, site_dir: Path) -> Path:
    """Seed a fresh Cache with the showcase fixture (2 runs across 7 CVEs).

    The cache is the offline source-of-truth that `build_site` walks.
    Two runs at deterministic ts_iso give the diff block all three
    flavours (Added / Removed / Reclassified). Minimal NVD/EPSS/KEV
    cache rows seed §2 summary fields on a couple of CVEs so the per-
    CVE pages look populated — the rest gracefully render "—" per the
    Slice-D best-effort contract.
    """
    from ramen_cve.cache import Cache

    cache_path = workdir / ".cache.db"
    cache = Cache(cache_path)

    # Run A (older). Becomes the "First recorded run" in the diff block;
    # also the source rows for the diff comparison against Run B.
    run_a = [
        ("CVE-2021-44228", "kev_override", 10.0, 0.9742),
        ("CVE-2021-26855", "patch_now", 9.1, 0.6800),
        ("CVE-2024-0002", "plan_and_patch", 8.8, 0.0500),
        ("CVE-2024-0003", "watch_closely", 4.3, 0.6500),
        ("CVE-2024-0001", "deprioritize", 3.1, 0.0100),
        ("CVE-2024-0009", "patch_now", 7.5, 0.4000),
    ]
    for cve_id, bucket, cvss, epss in run_a:
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            (cve_id, WEB_SAMPLE_RUN_A_TS, bucket, cvss, epss),
        )
    # Run B (newer). On-disk artefacts get recorded below. CVE-0002 is
    # reclassified (plan_and_patch → patch_now), CVE-0009 is removed,
    # CVE-0010 is added — every diff section gets one entry.
    run_b = [
        ("CVE-2021-44228", "kev_override", 10.0, 0.9750),
        ("CVE-2021-26855", "patch_now", 9.1, 0.6900),
        ("CVE-2024-0002", "patch_now", 8.8, 0.1200),  # reclassified
        ("CVE-2024-0003", "watch_closely", 4.3, 0.6700),
        ("CVE-2024-0001", "deprioritize", 3.1, 0.0150),
        ("CVE-2024-0010", "patch_now", 8.5, 0.5500),  # added
    ]
    for cve_id, bucket, cvss, epss in run_b:
        cache._conn.execute(
            "INSERT INTO runs (cve_id, ts_iso, bucket, cvss_score, epss_score) "
            "VALUES (?, ?, ?, ?, ?)",
            (cve_id, WEB_SAMPLE_RUN_B_TS, bucket, cvss, epss),
        )
    cache._conn.commit()

    # NVD/EPSS/KEV cache rows for §2 summary. Only the two real CVEs get
    # rich data; the synthetic CVE-2024-* rows leave §2 fields as "—" to
    # demonstrate the best-effort fallback.
    cache.set_nvd("CVE-2021-44228", {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
            "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
            "configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related "
            "endpoints."
        ),
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_version": "3.1",
    })
    cache.set_nvd("CVE-2021-26855", {
        "cve_id": "CVE-2021-26855",
        "description": (
            "Microsoft Exchange Server Remote Code Execution Vulnerability "
            "(ProxyLogon)."
        ),
        "cvss_score": 9.1,
        "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_version": "3.1",
    })
    cache.set_epss(
        "CVE-2021-44228", FROZEN_EPSS_DATE,
        {"epss": 0.9750, "percentile": 0.9999, "date": FROZEN_EPSS_DATE},
    )
    cache.set_epss(
        "CVE-2021-26855", FROZEN_EPSS_DATE,
        {"epss": 0.6900, "percentile": 0.9850, "date": FROZEN_EPSS_DATE},
    )
    cache.set_kev_catalog({
        "CVE-2021-44228": {
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
    })

    cache.record_artefacts(
        WEB_SAMPLE_RUN_B_TS, WEB_SAMPLE_RUN_B_STAMP, str(site_dir / "out"),
    )
    return cache_path


def _write_web_sample_artefacts(site_dir: Path) -> None:
    """Write a `ramen-cve-<stamp>.csv` + `-iocs.csv` for the most-recent run.

    Columns match `output/csv_writer.py:CSV_COLUMNS` and
    `output/stix.py:IOC_CSV_COLUMNS`. Slice E's per-CVE page reads
    these for §§4-7; Slice E.5 reads the IOC sidecar for §6. Files
    are written inside the site tree (`<site>/out/`) so the relative
    artefact links in the bundled HTML resolve when the user opens
    the committed `examples/_web-sample/index.html`.
    """
    from ramen_cve.output.csv_writer import CSV_COLUMNS
    from ramen_cve.output.stix import IOC_CSV_COLUMNS

    out_dir = site_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # The 6 CVEs in Run B + their §§4-5-7 cells. CVSS / EPSS / KEV fields
    # are left blank because the Web UI's §2 reads those from the cache,
    # not the CSV.
    csv_rows = [
        {
            "cve_id": "CVE-2021-44228", "bucket": "kev_override",
            "exploit_status": "exploit_db",
            "linked_actors": "APT41;Aquatic Panda",
            "linked_campaigns": "",
            "linked_malware": "ShadowPad;PlugX",
            "affected_hosts": "web-01.example;app-prod-02.example",
        },
        {
            "cve_id": "CVE-2021-26855", "bucket": "patch_now",
            "exploit_status": "exploit_db",
            "linked_actors": "Hafnium",
            "linked_campaigns": "",
            "linked_malware": "China Chopper",
            "affected_hosts": "mail-01.example",
        },
        {
            "cve_id": "CVE-2024-0002", "bucket": "patch_now",
            "exploit_status": "nuclei_template",
            "linked_actors": "", "linked_campaigns": "", "linked_malware": "",
            "affected_hosts": "",
        },
        {
            "cve_id": "CVE-2024-0003", "bucket": "watch_closely",
            "exploit_status": "github_poc",
            "linked_actors": "", "linked_campaigns": "", "linked_malware": "",
            "affected_hosts": "",
        },
        {
            "cve_id": "CVE-2024-0001", "bucket": "deprioritize",
            "exploit_status": "none",
            "linked_actors": "", "linked_campaigns": "", "linked_malware": "",
            "affected_hosts": "",
        },
        {
            "cve_id": "CVE-2024-0010", "bucket": "patch_now",
            "exploit_status": "none",
            "linked_actors": "", "linked_campaigns": "", "linked_malware": "",
            "affected_hosts": "",
        },
    ]
    csv_path = out_dir / f"ramen-cve-{WEB_SAMPLE_RUN_B_STAMP}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(CSV_COLUMNS)
        for row in csv_rows:
            line = {c: "" for c in CSV_COLUMNS}
            line.update(row)
            writer.writerow([line[c] for c in CSV_COLUMNS])

    # IOC sidecar: a handful of representative indicators linked to the
    # Log4Shell entry so the per-CVE §6 table renders.
    ioc_rows = [
        ("url", "https://malicious-log4j.example/payload.class", "feed-a",
         "2026-01-12", "feed_pub", "false", "", "AMBER", "B2", "2026-01-15",
         "1.0000", "CVE-2021-44228"),
        ("ipv4", "203.0.113.5", "feed-b",
         "2026-01-11", "feed_pub", "false", "", "AMBER", "C3", "2026-01-15",
         "0.9000", "CVE-2021-44228"),
        ("sha256",
         "e7eb50e2f1f2c84e1e9ae07c0c84b69a2b3b0a99f4bf6f1d8cb1d8aa8c2d9eaf",
         "feed-a", "2026-01-10", "feed_pub", "false", "", "AMBER", "B2",
         "2026-01-15", "0.8500", "CVE-2021-44228"),
    ]
    iocs_path = out_dir / f"ramen-cve-{WEB_SAMPLE_RUN_B_STAMP}-iocs.csv"
    with iocs_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(IOC_CSV_COLUMNS)
        for row in ioc_rows:
            writer.writerow(row)


def _generate_web_sample(workdir: Path) -> dict[str, bytes]:
    """Build the `_web-sample/` showcase tree and return it as `{rel: bytes}`.

    Self-contained: doesn't rely on the main `_generate` pipeline at
    all. Seeds a fresh Cache + writes on-disk artefacts directly, so
    file names and contents are byte-deterministic across regens.
    """
    from ramen_cve.cache import Cache
    from ramen_cve.web.builder import build_site

    site_dir = workdir / "_web-sample"
    cache_path = _seed_web_sample_cache(workdir, site_dir)
    _write_web_sample_artefacts(site_dir)
    build_site(Cache(cache_path), site_dir)

    files: dict[str, bytes] = {}
    for path in sorted(site_dir.rglob("*")):
        if path.is_file():
            rel = path.relative_to(site_dir).as_posix()
            files[f"_web-sample/{rel}"] = path.read_bytes()
    return files


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
        # CSV + Markdown in one run...
        rc = ramen_cve.main(
            [
                "opml", str(SAMPLE_OPML),
                "--out-dir", str(out_dir), "--format", "both",
                "--inventory", str(inv_path),
                "--no-exploit-lookup", "--no-enrich-iocs", "--no-cache",
            ]
        )
        if rc != 0:
            raise SystemExit(f"pipeline (csv+md) returned rc={rc}")
        # ...then the HTML quadrant chart in a second run (separate
        # --format so we don't pull in sigma/yara/stix artefacts that
        # aren't part of the showcase bundle).
        rc = ramen_cve.main(
            [
                "opml", str(SAMPLE_OPML),
                "--out-dir", str(out_dir), "--format", "html",
                "--inventory", str(inv_path),
                "--no-exploit-lookup", "--no-enrich-iocs", "--no-cache",
            ]
        )
        if rc != 0:
            raise SystemExit(f"pipeline (html) returned rc={rc}")

    csv_path = sorted(out_dir.glob("ramen-cve-*.csv"))[0]
    md_path = sorted(out_dir.glob("ramen-cve-*.md"))[0]
    html_path = sorted(out_dir.glob("ramen-cve-*.html"))[0]
    bundle = {
        OUT_INVENTORY.name: INVENTORY_TEXT.encode("utf-8"),
        OUT_CSV.name: _normalise_csv(csv_path.read_bytes()),
        OUT_MD.name: _normalise_md(md_path.read_text(encoding="utf-8")).encode("utf-8"),
        OUT_HTML.name: html_path.read_bytes(),
    }
    # Web UI showcase bundle (Task 8 Slice G). Self-contained: a separate
    # workdir keeps its seeded cache + on-disk artefacts from leaking
    # into the main pipeline's `out/`.
    web_workdir = workdir / "_web"
    web_workdir.mkdir()
    bundle.update(_generate_web_sample(web_workdir))
    return bundle


def _target_path(name: str) -> Path:
    """Map a produced-bundle key to its committed path under examples/.

    Works uniformly for the four flat artefacts (e.g.
    ``sample-output.csv``) and for the nested web-bundle entries
    (e.g. ``_web-sample/runs/2026-01-15T09-00-00.html``).
    """
    return EXAMPLES / name


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
            if not _target_path(name).exists()
            or _target_path(name).read_bytes() != data
        ]
        # Catch stale committed web-bundle files that the current run
        # no longer produces (e.g. a removed per-CVE page).
        if WEB_SAMPLE_DIR.exists():
            for path in sorted(WEB_SAMPLE_DIR.rglob("*")):
                if path.is_file():
                    rel = path.relative_to(WEB_SAMPLE_DIR).as_posix()
                    name = f"_web-sample/{rel}"
                    if name not in produced:
                        drift.append(name)
        if drift:
            print("examples/ are STALE — run scripts/regen_examples.py:", file=sys.stderr)
            for name in drift:
                print(f"  - examples/{name}", file=sys.stderr)
            return 1
        print("examples/ are up to date.")
        return 0

    # Wipe the committed web bundle first so renamed/removed pages don't
    # linger across regens.
    if WEB_SAMPLE_DIR.exists():
        shutil.rmtree(WEB_SAMPLE_DIR)
    for name, data in produced.items():
        target = _target_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f"wrote examples/{name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
