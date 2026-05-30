"""ramen_cve.output.sigma — Sigma detection-rule stub writer for
patch-now / KEV-override CVEs (Layer-3 serialization, offline).

See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from ..models import EnrichedCve
from .stix import _stix_uuid

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

