"""ramen_cve.output.siem_queries — native SIEM query stub writers.

Three platform-flavoured detection scaffolds — Kusto Query Language
(Microsoft Sentinel / Defender), Splunk SPL, and Elastic EQL — emitted as
one file per eligible CVE under a per-format directory. Same eligibility
policy as the Sigma writer: KEV-listed and patch-now CVEs only (the bucket
the analyst is actually going to *act* on).

Each emitted file is a pre-tagged **scaffold**, not a runnable rule. The
analyst replaces the `<TableName>` / `<index>` / `event.category` placeholders
with their environment-specific values; the value-add is the pre-filled
metadata header (CVE, bucket, CVSS, EPSS, KEV info, ATT&CK references,
NVD URL) so the conversion-from-Sigma step is the same kind of "20 second
tweak" that drove the original Sigma writer.

Layer-3, offline, stdlib only. Re-exported on the façade. Output is
byte-deterministic for fixed input — the same EnrichedCve set always
produces identical files.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..models import EnrichedCve

# Same as sigma — only act-now buckets get a detection scaffold.
SIEM_QUERY_ELIGIBLE_BUCKETS = ("kev_override", "patch_now")

# Public list of platforms this module knows how to emit, in canonical order.
SIEM_QUERY_PLATFORMS = ("kql", "spl", "eql")


def _comment_lines(rec: EnrichedCve, prefix: str) -> list[str]:
    """Return the metadata header lines (already prefixed) shared by every platform.

    ``prefix`` is the platform-appropriate one-line comment marker
    (``"// "`` for KQL/EQL, ``"``` "`` for SPL).
    """
    cvss_disp = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
    epss_disp = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
    lines = [
        f"{prefix}Detection scaffold for {rec.cve_id}",
        f"{prefix}Bucket: {rec.bucket} · CVSS {cvss_disp} ({rec.cvss_severity or 'N/A'})"
        f" · EPSS {epss_disp}",
    ]
    if rec.kev_listed:
        kev = "CISA KEV: listed"
        if rec.kev_due_date:
            kev += f" (due {rec.kev_due_date})"
        if rec.kev_known_ransomware_use:
            kev += " — known ransomware use"
        lines.append(f"{prefix}{kev}")
    if rec.exploit_status and rec.exploit_status != "none":
        lines.append(f"{prefix}Public exploit: {rec.exploit_status}")
    if rec.attack_techniques:
        lines.append(f"{prefix}ATT&CK: " + ", ".join(rec.attack_techniques))
    if rec.linked_actors:
        lines.append(
            f"{prefix}Linked actors: "
            + ", ".join(sorted({a.name for a in rec.linked_actors}))
        )
    lines.append(f"{prefix}Reference: https://nvd.nist.gov/vuln/detail/{rec.cve_id}")
    return lines


def _build_kql_stub(rec: EnrichedCve) -> str:
    """One KQL detection scaffold for Sentinel / Defender XDR.

    KQL is comment-by-``//``. The body shape ``<TableName> | where … | project …``
    is the idiom every Sentinel analyst expects; ``ago(7d)`` is a
    deterministic relative window that doesn't depend on wall-clock time.
    """
    header = "\n".join(_comment_lines(rec, "// "))
    return (
        f"{header}\n"
        f"{'//':<2} TODO: replace <TableName> with your event source\n"
        f"{'//':<2}       (DeviceProcessEvents, SecurityEvent, Syslog, …)\n"
        f"\n"
        f'let cve_id = "{rec.cve_id}";\n'
        f"<TableName>\n"
        f"| where TimeGenerated > ago(7d)\n"
        f"// TODO: predicate matching the exploit signature\n"
        f"// | where ProcessCommandLine has \"<indicator>\"\n"
        f'| extend cve = cve_id\n'
        f"| project TimeGenerated, DeviceName, AccountName, cve\n"
    )


def _build_spl_stub(rec: EnrichedCve) -> str:
    """One Splunk SPL detection scaffold.

    SPL block comments use the triple-backtick syntax — fine for stubs the
    user is going to edit in their SOC. The earliest/latest window is the
    deterministic relative form (``earliest=-7d@d``).
    """
    header = "\n".join(line + " ```" for line in _comment_lines(rec, "``` "))
    return (
        f"{header}\n"
        f"``` TODO: replace <index> with your event source. ```\n"
        f"\n"
        f"index=<index> earliest=-7d@d\n"
        f"| eval cve_id=\"{rec.cve_id}\"\n"
        f"``` TODO: filter to the exploit signature. ```\n"
        f"``` | search process_name=\"...\" OR command=\"<indicator>\" ```\n"
        f"| table _time, host, source, sourcetype, cve_id\n"
    )


def _build_eql_stub(rec: EnrichedCve) -> str:
    """One Elastic EQL detection scaffold.

    Elastic's EQL is comment-by-``//``. The `any where` form is the broadest
    starting point — the analyst narrows ``event.category`` to the
    appropriate set for the CVE.
    """
    header = "\n".join(_comment_lines(rec, "// "))
    return (
        f"{header}\n"
        f"// TODO: narrow event.category to the appropriate event source\n"
        f'//       ("process", "file", "network", "authentication", …)\n'
        f"\n"
        f'any where event.category in ("process", "file", "network")\n'
        f"  and @timestamp >= now() - 7d\n"
        f"  // TODO: replace with the exploit signature\n"
        f'  // and process.name == "<indicator>"\n'
    )


# Per-platform: (extension, content-builder). Drives both the writer
# dispatcher and the test matrix.
_PLATFORMS: dict[str, tuple[str, Callable[[EnrichedCve], str]]] = {
    "kql": (".kql", _build_kql_stub),
    "spl": (".spl", _build_spl_stub),
    "eql": (".eql", _build_eql_stub),
}


def _safe_filename_stem(cve_id: str) -> str:
    """`CVE-2021-44228` → `CVE-2021-44228`; strips any traversal-ish chars."""
    # CVE IDs are constrained by the project's CVE_REGEX upstream, so we
    # only have to defend against the empty string and any historical
    # weirdness (a colon or slash sneaking into a hand-built rec). Strip
    # everything that isn't [A-Za-z0-9._-].
    keep = [c if (c.isalnum() or c in "._-") else "_" for c in (cve_id or "")]
    return "".join(keep) or "unknown"


def write_siem_query_stubs(
    enriched: list[EnrichedCve],
    out_dir: Path,
    platform: str,
) -> list[Path]:
    """Write one query stub per eligible CVE into ``out_dir``.

    Eligibility matches Sigma: ``kev_override`` and ``patch_now`` buckets
    only. Returns the list of written paths sorted by filename (stable for
    diff / oracle use). Empty when no records are eligible — the caller is
    responsible for skipping the dir-create in that case.
    """
    if platform not in _PLATFORMS:
        raise ValueError(
            f"Unknown SIEM platform {platform!r}. "
            f"Known: {', '.join(_PLATFORMS)}."
        )
    extension, builder = _PLATFORMS[platform]
    written: list[Path] = []
    eligible = [r for r in enriched if r.bucket in SIEM_QUERY_ELIGIBLE_BUCKETS]
    if not eligible:
        return written
    out_dir.mkdir(parents=True, exist_ok=True)
    for rec in eligible:
        stem = _safe_filename_stem(rec.cve_id)
        path = out_dir / f"{stem}{extension}"
        path.write_text(builder(rec), encoding="utf-8")
        written.append(path)
    return sorted(written)
