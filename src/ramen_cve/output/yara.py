"""ramen_cve.output.yara — YARA rule stub writer for patch-now /
KEV-override CVEs with linked malware (Layer-3 serialization, offline).

See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from ..models import EnrichedCve, Malware
from .sigma import SIGMA_ELIGIBLE_BUCKETS
from .stix import _stix_uuid


def _yara_safe_name(value: str) -> str:
    """Reduce an arbitrary string to a valid YARA rule-identifier fragment.

    YARA rule names must match [A-Za-z_][A-Za-z0-9_]{0,127}. We collapse every
    other character to '_' and prefix a leading digit / empty string with '_'
    so the resulting identifier is always valid.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", (value or "").strip()).strip("_")
    if not cleaned:
        return "Unknown"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned[:96]


def _yara_string_escape(value: str) -> str:
    """Escape a string for use as a YARA double-quoted metadata literal."""
    return (value or "").replace("\\", "\\\\").replace("\"", "\\\"")


def _build_yara_stub(rec: EnrichedCve, malware: Malware) -> str:
    """Build one YARA rule scaffold for a (CVE, linked-malware) pair.

    The strings + condition blocks are deliberately TODO placeholders — the
    rule isn't runnable, but it carries every piece of metadata a detection
    engineer needs to populate it (CVE, CVSS, EPSS, ATT&CK, KEV, MITRE
    software URL).
    """
    rule_id = _stix_uuid(f"yara:{rec.cve_id}:{malware.name}")
    rule_name = f"Ramen_{_yara_safe_name(malware.name)}_{_yara_safe_name(rec.cve_id)}"
    cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
    epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
    techniques = ", ".join(rec.attack_techniques) if rec.attack_techniques else "(none)"
    description = (
        f"Detection scaffold for {malware.name} (linked to {rec.cve_id})"
    )

    lines: list[str] = [
        f"rule {rule_name}",
        "{",
        "    meta:",
        f"        id = \"{rule_id}\"",
        f"        description = \"{_yara_string_escape(description)}\"",
        "        author = \"ramen-cve\"",
        f"        date = \"{date.today().isoformat()}\"",
        f"        cve = \"{rec.cve_id}\"",
        f"        malware_family = \"{_yara_string_escape(malware.name)}\"",
        f"        cvss = \"{cvss}\"",
        f"        epss = \"{epss}\"",
        f"        attack_techniques = \"{_yara_string_escape(techniques)}\"",
    ]
    if rec.kev_listed:
        kev_text = "listed"
        if rec.kev_due_date:
            kev_text += f" (due {rec.kev_due_date})"
        if rec.kev_known_ransomware_use:
            kev_text += " - known ransomware use"
        lines.append(f"        cisa_kev = \"{_yara_string_escape(kev_text)}\"")
    if malware.url:
        lines.append(
            f"        mitre_software = \"{_yara_string_escape(malware.url)}\""
        )
    lines += [
        "    strings:",
        f"        // TODO: replace with strings characteristic of {malware.name}",
        "        $stub_a = \"TODO_REPLACE_ME\"",
        "    condition:",
        "        // TODO: refine the trigger; default fires on the placeholder string",
        "        any of them",
        "}",
        "",
    ]
    return "\n".join(lines)


YARA_ELIGIBLE_BUCKETS = SIGMA_ELIGIBLE_BUCKETS  # same precedence as Sigma stubs


def write_yara_stubs(enriched: list[EnrichedCve], out_dir: Path) -> list[Path]:
    """Write one YARA rule scaffold per (kev/patch-now CVE, linked malware) pair.

    Output filenames are `<MalwareSafeName>_<CveSafeName>.yar`. A CVE without
    linked_malware records produces no files. Returns the list of written
    paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rec in enriched:
        if rec.bucket not in YARA_ELIGIBLE_BUCKETS:
            continue
        for malware in rec.linked_malware:
            mw_stem = _yara_safe_name(malware.name)
            cve_stem = _yara_safe_name(rec.cve_id)
            path = out_dir / f"{mw_stem}_{cve_stem}.yar"
            path.write_text(_build_yara_stub(rec, malware), encoding="utf-8")
            written.append(path)
    return written

