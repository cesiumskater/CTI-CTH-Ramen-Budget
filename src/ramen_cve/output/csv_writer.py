"""ramen_cve.output.csv_writer — flat one-row-per-CVE CSV report
(Layer-3 serialization). Column order is the CSV_COLUMNS contract.

See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..models import EnrichedCve

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

