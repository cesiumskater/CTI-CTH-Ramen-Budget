"""ramen_cve.output.markdown — human-readable Markdown triage
report grouped by action bucket (Layer-3 serialization).

See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from ..bucket_policy import DEFAULT_BUCKET_POLICY, BucketPolicy
from ..constants import (
    ATTACK_TECHNIQUE_NAMES,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_EPSS_THRESHOLD,
)
from ..models import EnrichedCve, IocRecord, _utcnow
from ..render import _sparkline

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
    """Collapse newlines and escape Markdown structural chars for safe embedding.

    A raw `|` inside a table cell ends the cell early and breaks the row; a raw
    backtick opens inline-code mode and consumes following text. Both are
    escaped here so attacker-controllable fields (CVE descriptions, vendor /
    product names, actor names, hostnames) cannot deform tables or inject
    inline code. `<>` are left alone — most Markdown renderers don't auto-HTML
    them outside of recognised tag patterns, and escaping them would mangle
    legitimate text like "x < 5" in CVE descriptions.
    """
    if not text:
        return ""
    # Replace any run of \r/\n/\t/etc. with a single space so the bullet stays on one line.
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


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
    policy: BucketPolicy | None = None,
) -> None:
    """Write a human-readable Markdown triage report.

    run_metadata keys: command (str), args (str — secrets redacted), version (str),
    sources (list[str]), start (str), end (str), date_mode (str),
    cvss_threshold (float), epss_threshold (float).

    If `iocs` is non-empty, an additional "Indicators of Compromise" section is
    rendered at the end of the report, grouped by IOC type.

    `policy=None` falls back to `DEFAULT_BUCKET_POLICY` — whose
    display order / labels / action prose mirror today's hardcoded
    `BUCKET_ORDER` / `BUCKET_DISPLAY` / `BUCKET_ACTIONS` byte-for-byte,
    so the no-policy call path remains byte-identical to pre-Task-7.
    A populated `policy` (typically `args.bucket_policy` from the YAML
    `buckets:` block) routes section ordering and headings through the
    policy.
    """
    iocs = iocs or []
    policy = policy or DEFAULT_BUCKET_POLICY
    display_order = policy.display_order()
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

    by_bucket: dict[str, list[EnrichedCve]] = {b: [] for b in display_order}
    for rec in enriched:
        bucket = rec.bucket if rec.bucket in by_bucket else "unknown"
        by_bucket[bucket].append(rec)

    lines += ["## Summary", "", "| Bucket | Count | Action |", "| --- | --- | --- |"]
    for bucket in display_order:
        count = len(by_bucket[bucket])
        raw = policy.action(bucket)
        action = raw.split("—")[-1].strip() if "—" in raw else raw
        lines.append(f"| {policy.label(bucket)} | {count} | {action} |")
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
            name = _md_safe(ATTACK_TECHNIQUE_NAMES.get(tid, "(unmapped)"))
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
    for bucket in display_order:
        recs = by_bucket[bucket]
        if not recs:
            continue
        lines += [f"## {policy.label(bucket)}", ""]
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
            if rec.epss_trajectory:
                # EPSS trajectory mode (`--date-mode epss` with a multi-day
                # range): show a sparkline summary, and — for short windows
                # — a compact inline table. The full series is always in
                # the `<basename>-epss-trajectory.csv` sidecar (Slice B).
                traj_dates = sorted(rec.epss_trajectory.keys())
                traj_values = [rec.epss_trajectory[d]["epss"] for d in traj_dates]
                lines.append(
                    f"- **EPSS trajectory:** `{_sparkline(traj_values)}` "
                    f"({traj_dates[0]} → {traj_dates[-1]}, {len(traj_dates)} samples)"
                )
                if len(traj_dates) <= 10:
                    lines.append("")
                    lines.append("    | Date | EPSS | Percentile |")
                    lines.append("    | --- | --- | --- |")
                    for d in traj_dates:
                        p = rec.epss_trajectory[d]
                        lines.append(
                            f"    | {d} | {p['epss']:.4f} | {p['percentile']:.4f} |"
                        )
                    lines.append("")
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

