"""ramen_cve.dispatch.digest — per-owner inventory e-mail digest:
group enriched CVEs by asset owner, render the body, send via the
Email dispatcher (Layer-3). See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from ..models import EnrichedCve
from .sinks import DISPATCH_DEFAULT_BUCKETS, EmailDispatcher

_log = logging.getLogger(__name__)


def _group_records_by_owner(
    enriched: list[EnrichedCve],
    inventory_rows: list[dict[str, str]],
    fallback_recipient: str | None,
) -> dict[str, list[EnrichedCve]]:
    """Map recipient email → list of EnrichedCves they should receive.

    Each inventory row may have an `owner` email; we build host→owner first,
    then for every record in (kev_override, patch_now) we route the record to
    each owner of every affected_host. Records with no inventory match (or
    whose hosts have no owner) go to fallback_recipient if set.
    """
    host_to_owners: dict[str, list[str]] = {}
    for row in inventory_rows or []:
        host = (row.get("host") or "").strip()
        owner = (row.get("owner") or "").strip()
        if host and owner:
            host_to_owners.setdefault(host, []).append(owner)

    by_owner: dict[str, list[EnrichedCve]] = {}
    for rec in enriched:
        if rec.bucket not in DISPATCH_DEFAULT_BUCKETS:
            continue
        owners_for_rec: set[str] = set()
        for host in rec.affected_hosts:
            for owner in host_to_owners.get(host, []):
                owners_for_rec.add(owner)
        if not owners_for_rec and fallback_recipient:
            owners_for_rec.add(fallback_recipient)
        for owner in owners_for_rec:
            by_owner.setdefault(owner, []).append(rec)
    return by_owner


def _build_digest_body(
    recipient: str,
    records: list[EnrichedCve],
    inventory_rows: list[dict[str, str]],
) -> str:
    """Render the per-recipient digest body in Markdown."""
    host_to_owners: dict[str, list[str]] = {}
    for row in inventory_rows or []:
        host = (row.get("host") or "").strip()
        owner = (row.get("owner") or "").strip()
        if host and owner:
            host_to_owners.setdefault(host, []).append(owner)

    lines = [
        f"# Daily Patch Digest for {recipient}",
        "",
        f"You have {len(records)} actionable finding(s) "
        f"({sum(1 for r in records if r.bucket == 'kev_override')} KEV-listed).",
        "",
    ]
    for rec in records:
        owned_hosts = [
            h for h in rec.affected_hosts
            if recipient in host_to_owners.get(h, [])
        ]
        cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
        lines += [
            f"## {rec.cve_id} ({rec.bucket})",
            f"- **Action:** {rec.suggested_action}",
            f"- **CVSS:** {cvss}",
        ]
        if rec.kev_listed and rec.kev_due_date:
            lines.append(f"- **CISA KEV due date:** {rec.kev_due_date}")
        if owned_hosts:
            lines.append(
                f"- **Your hosts ({len(owned_hosts)}):** " + ", ".join(owned_hosts[:8])
            )
        elif rec.affected_hosts:
            lines.append(
                f"- **Hosts in inventory:** {len(rec.affected_hosts)}"
            )
        lines.append("")
    lines += [
        "---",
        "*Full CSV and Markdown reports are attached.*",
        "",
    ]
    return "\n".join(lines)


def _maybe_digest(
    args: argparse.Namespace,
    enriched: list[EnrichedCve],
    output_paths: dict[str, Path | None],
) -> None:
    """If --digest is set, send one batched email per recipient with attachments.

    Recipients are derived from the inventory CSV's `owner` column (per host).
    A `RAMEN_DIGEST_TO` env var catches CVEs whose affected hosts have no
    explicit owner. CSV (cve + ioc) and Markdown report files are attached.
    """
    if not getattr(args, "digest", False):
        return
    dispatcher = EmailDispatcher.from_env()
    if not dispatcher.enabled():
        _log.warning(
            "--digest requested but RAMEN_SMTP_HOST / RAMEN_SMTP_FROM are "
            "not configured; no digest sent."
        )
        return
    inventory_rows = getattr(args, "_inventory_rows", []) or []
    by_owner = _group_records_by_owner(
        enriched, inventory_rows, dispatcher.fallback_recipient
    )
    if not by_owner:
        _log.info(
            "--digest: no kev_override / patch_now records mapped to a recipient; "
            "nothing sent."
        )
        return
    attachments = [
        output_paths.get("csv"),
        output_paths.get("iocs_csv"),
        output_paths.get("md"),
    ]
    attachments = [a for a in attachments if a is not None]
    sent = 0
    for recipient, recs in sorted(by_owner.items()):
        body = _build_digest_body(recipient, recs, inventory_rows)
        subject = f"ramen-cve digest — {len(recs)} actionable CVE(s)"
        if dispatcher.send_digest(recipient, subject, body, attachments):
            sent += 1
    _log.info(
        "Email digest complete: %d / %d recipient(s) reached.", sent, len(by_owner),
    )

