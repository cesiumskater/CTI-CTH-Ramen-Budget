"""ramen_cve.output.csv_writer — flat one-row-per-CVE CSV report and the
optional one-row-per-(CVE,date) EPSS trajectory sidecar (Layer-3
serialization). Column orders are the CSV_COLUMNS /
EPSS_TRAJECTORY_COLUMNS contracts.

See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..models import EnrichedCve

# CWE-1236: the CSV is intentionally written with a UTF-8 BOM (utf-8-sig)
# so Excel auto-detects encoding — which also means it opens the file as
# a spreadsheet and interprets a leading =/+/-/@/TAB/CR as a formula. Feed
# titles, URL <title>s, and a handful of other free-text fields here are
# attacker-controllable. Prefix any such cell with a single apostrophe —
# the Excel-documented escape, consumed on display so the visible value
# is unchanged.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Return `value` with a leading apostrophe if it would trigger a formula."""
    if value and value[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value

EPSS_TRAJECTORY_COLUMNS = ("cve_id", "date", "epss", "percentile")

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
    "ssvc_action",
    "ssvc_decision_points",
    "affected_host_criticality",
    "risk_score",
    "nvd_published",
    "enriched_at",
]


def write_csv(enriched: list[EnrichedCve], path: Path) -> None:
    """Write the enriched CVE list to a CSV file.

    Columns are in the order defined by CSV_COLUMNS. Numeric formatting:
    CVSS to 1 decimal, EPSS/percentile to 4 decimals.

    Written with utf-8-sig (UTF-8 + BOM) so Excel / PyCharm / etc. on
    Windows auto-detect the encoding instead of falling back to cp1252
    and rendering non-ASCII chars like the em dash as mojibake.
    """
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(CSV_COLUMNS)
        for rec in enriched:
            cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else ""
            epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else ""
            pct = f"{rec.epss_percentile:.4f}" if rec.epss_percentile is not None else ""
            writer.writerow(
                [
                    _csv_safe(rec.cve_id),
                    _csv_safe(rec.source),
                    _csv_safe(str(rec.first_seen) if rec.first_seen else ""),
                    _csv_safe(rec.first_seen_type),
                    cvss,
                    _csv_safe(rec.cvss_severity or ""),
                    epss,
                    pct,
                    str(rec.kev_listed).lower(),
                    _csv_safe(str(rec.kev_due_date) if rec.kev_due_date else ""),
                    str(rec.kev_known_ransomware_use).lower(),
                    _csv_safe(rec.kev_vendor_project or ""),
                    _csv_safe(rec.kev_product or ""),
                    _csv_safe(rec.bucket),
                    _csv_safe(rec.suggested_action),
                    _csv_safe(";".join(rec.cwe)),
                    _csv_safe(";".join(rec.attack_techniques)),
                    _csv_safe(rec.exploit_status),
                    _csv_safe(";".join(a.name for a in rec.linked_actors)),
                    _csv_safe(";".join(c.name for c in rec.linked_campaigns)),
                    _csv_safe(";".join(m.name for m in rec.linked_malware)),
                    _csv_safe(rec.tlp or "CLEAR"),
                    _csv_safe(rec.admiralty or ""),
                    _csv_safe(";".join(rec.affected_hosts)),
                    _csv_safe(rec.kill_chain_phase),
                    _csv_safe(rec.diamond_capability),
                    _csv_safe(rec.diamond_adversary),
                    _csv_safe(rec.diamond_infrastructure),
                    _csv_safe(rec.diamond_victim),
                    _csv_safe(rec.ssvc_action or ""),
                    # `k=v` pairs joined with ; — same shape the analyst sees
                    # in the Markdown report; round-trips through Excel cleanly.
                    _csv_safe(
                        ";".join(
                            f"{k}={v}" for k, v in sorted(
                                (rec.ssvc_decision_points or {}).items()
                            )
                        )
                    ),
                    _csv_safe(rec.affected_host_criticality or ""),
                    f"{rec.risk_score:.4f}" if rec.risk_score is not None else "",
                    _csv_safe(str(rec.nvd_published) if rec.nvd_published else ""),
                    _csv_safe(rec.enriched_at.isoformat()),
                ]
            )



def write_epss_trajectory_csv(enriched: list[EnrichedCve], path: Path) -> None:
    """Write the per-CVE, per-date EPSS trajectory as a sidecar CSV.

    One row per (cve_id, date) entry in EnrichedCve.epss_trajectory; records
    with an empty trajectory dict contribute zero rows (no noise). Rows are
    sorted by (cve_id, date) for byte-stable output.
    """
    rows: list[tuple[str, str, float | None, float | None]] = []
    for rec in enriched:
        for d, payload in rec.epss_trajectory.items():
            rows.append((rec.cve_id, d, payload.get("epss"), payload.get("percentile")))
    rows.sort()
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(EPSS_TRAJECTORY_COLUMNS)
        for cve_id, d, epss, pct in rows:
            writer.writerow(
                [
                    _csv_safe(cve_id),
                    _csv_safe(d),
                    f"{epss:.4f}" if epss is not None else "",
                    f"{pct:.4f}" if pct is not None else "",
                ]
            )
