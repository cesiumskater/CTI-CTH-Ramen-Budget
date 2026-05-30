"""ramen_cve.enrich.orchestrator — per-CVE enrichment pipeline (L2).

Joins NVD/EPSS/KEV fetch + associations + ATT&CK/kill-chain mapping
into EnrichedCve. See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta

from ..analyze import (
    _best_admiralty,
    _worst_tlp,
    map_cwes_to_attack_techniques,
    map_cwes_to_kill_chain,
)
from ..associations import _parse_kev_due_date
from ..cache import Cache
from ..keyring import _prompt_for_api_key
from ..models import CveRecord, EnrichedCve
from .epss import fetch_epss
from .kev import fetch_kev_catalog
from .nvd import fetch_nvd

_log = logging.getLogger(__name__)


EPSS_TRAJECTORY_WARN_THRESHOLD = 200
EPSS_TRAJECTORY_ABUSE_THRESHOLD = 500


def enrich_cves(
    records: list[CveRecord],
    cache: Cache,
    api_key: str | None,
    associations: dict[str, dict[str, list]] | None = None,
    epss_date_range: tuple[date, date] | None = None,
    confirm_large_trajectory: bool = False,
) -> list[EnrichedCve]:
    """Fetch NVD, EPSS, and CISA KEV data for each unique CVE and return enriched records.

    Deduplicates CVE IDs before hitting the APIs. When the same CVE appears in
    multiple records, only the earliest first_seen date is kept.

    `epss_date_range` is `(start, end)` for EPSS trajectory mode: when set and
    `start != end`, EPSS is fetched once per day in the inclusive range and
    accumulated into each `EnrichedCve.epss_trajectory` dict (keyed by ISO
    date), with the scalar `epss_score`/`epss_percentile`/`epss_date` fields
    pinned to the END-date value. When `start == end` (or the range is None),
    behaviour is byte-identical to today's single-shot EPSS call.

    Trajectory volume guard: projected EPSS API calls are
    `days × ceil(len(unique_cves) / 100)`. ≥200 logs a WARNING; ≥500 raises
    `ValueError` unless `confirm_large_trajectory=True` (CLI:
    `--allow-large-epss-trajectory`).

    If `associations` is provided, each enriched record is also annotated with
    the linked actors, campaigns, and malware for that CVE.
    """
    # Deduplicate: keep earliest first_seen per CVE, but merge TLP / Admiralty
    # across every input record so the most-restrictive sharing tag and the
    # highest-confidence source rating both reach the EnrichedCve.
    earliest: dict[str, CveRecord] = {}
    merged_tlp: dict[str, str] = {}
    merged_adm: dict[str, str] = {}
    for rec in records:
        if rec.cve_id not in earliest or rec.first_seen < earliest[rec.cve_id].first_seen:
            earliest[rec.cve_id] = rec
        merged_tlp[rec.cve_id] = _worst_tlp(merged_tlp.get(rec.cve_id), rec.tlp)
        merged_adm[rec.cve_id] = _best_admiralty(merged_adm.get(rec.cve_id), rec.admiralty)

    unique_ids = list(earliest.keys())

    # Fetch NVD data for each unique CVE. If the server rejects the API key
    # (401/403), prompt for a new one ONCE and retry the failed CVE plus all
    # remaining ones with the fresh key.
    nvd_data: dict[str, dict] = {}
    reprompted = False
    for cve_id in unique_ids:
        result = fetch_nvd(cve_id, cache, api_key)
        if result.get("nvd_status") == "auth_error" and not reprompted and api_key:
            reprompted = True
            new_key = _prompt_for_api_key(reason="expired")
            if new_key:
                api_key = new_key
                result = fetch_nvd(cve_id, cache, api_key)
        nvd_data[cve_id] = result

    # Fetch EPSS data. Single-shot in the common case; if the caller asked for
    # a multi-day trajectory we loop over every day in the range and stash the
    # full time-series on each EnrichedCve.epss_trajectory while keeping the
    # scalar epss_* fields pinned to the END-date value.
    epss_trajectories: dict[str, dict[str, dict]] = {}
    if (
        epss_date_range is not None
        and epss_date_range[0] != epss_date_range[1]
    ):
        traj_start, traj_end = epss_date_range
        # Pre-flight projected EPSS API call count: days × ceil(N/100).
        # Threshold-based protection against accidentally hammering the
        # FIRST.org API with very large ranges or CVE counts. Cache hits
        # don't reduce the *projected* call count (we can't know hit
        # rates without iterating), so this is a conservative upper bound.
        days = (traj_end - traj_start).days + 1
        batches_per_day = -(-len(unique_ids) // 100)  # ceil
        projected_calls = days * batches_per_day
        if projected_calls >= EPSS_TRAJECTORY_ABUSE_THRESHOLD and not confirm_large_trajectory:
            raise ValueError(
                f"EPSS trajectory would issue {projected_calls} API calls "
                f"({days} days × {batches_per_day} batch(es)/day for "
                f"{len(unique_ids)} CVE(s)); ≥{EPSS_TRAJECTORY_ABUSE_THRESHOLD} "
                f"requires explicit confirmation. Pass --allow-large-epss-trajectory "
                f"to proceed, or shrink the date range / CVE set."
            )
        if projected_calls >= EPSS_TRAJECTORY_WARN_THRESHOLD:
            _log.warning(
                "EPSS trajectory will issue %d API calls (%d days × %d "
                "batch(es)/day for %d CVE(s)); may be slow and rate-limited.",
                projected_calls, days, batches_per_day, len(unique_ids),
            )
        end_date_str = traj_end.isoformat()
        cur = traj_start
        while cur <= traj_end:
            date_str = cur.isoformat()
            batch = fetch_epss(unique_ids, cache, score_date=date_str)
            for cid, payload in batch.items():
                epss_trajectories.setdefault(cid, {})[date_str] = {
                    "epss": payload["epss"],
                    "percentile": payload["percentile"],
                }
            cur += timedelta(days=1)
        # End-date scalars (drives epss_score / epss_percentile / epss_date).
        epss_data = {
            cid: {
                "epss": traj[end_date_str]["epss"],
                "percentile": traj[end_date_str]["percentile"],
                "date": end_date_str,
            }
            for cid, traj in epss_trajectories.items()
            if end_date_str in traj
        }
    else:
        epss_data = fetch_epss(unique_ids, cache)

    # Fetch the authoritative CISA KEV catalog (one HTTP call, cached).
    kev_catalog = fetch_kev_catalog(cache)

    enriched: list[EnrichedCve] = []
    for cve_id, rec in earliest.items():
        nvd = nvd_data.get(cve_id, {})
        epss = epss_data.get(cve_id, {})
        kev = kev_catalog.get(cve_id, {})

        nvd_pub_str = nvd.get("nvd_published")
        nvd_published: date | None = None
        if nvd_pub_str:
            try:
                nvd_published = date.fromisoformat(nvd_pub_str)
            except (TypeError, ValueError):
                _log.warning(
                    "NVD returned an unparseable published date %r for %s; ignoring.",
                    nvd_pub_str,
                    cve_id,
                )

        # CISA's catalog is the authoritative source for KEV membership; if it
        # answers, prefer it over NVD's cisaExploitAdd flag. Either signal alone
        # is enough to treat the CVE as KEV-listed.
        kev_listed = bool(kev) or nvd.get("kev_listed", False)

        enriched.append(
            EnrichedCve(
                cve_id=cve_id,
                source=rec.source,
                first_seen=rec.first_seen,
                first_seen_type=rec.first_seen_type,
                cvss_score=nvd.get("cvss_score"),
                cvss_severity=nvd.get("cvss_severity"),
                cvss_vector=nvd.get("cvss_vector"),
                cvss_version=nvd.get("cvss_version"),
                kev_listed=kev_listed,
                cwe=nvd.get("cwe", []),
                nvd_published=nvd_published,
                nvd_status=nvd.get("nvd_status", "ok"),
                epss_score=epss.get("epss"),
                epss_percentile=epss.get("percentile"),
                epss_date=epss.get("date"),
                epss_trajectory=epss_trajectories.get(cve_id, {}),
                kev_due_date=_parse_kev_due_date(kev.get("dueDate")) if kev else None,
                kev_required_action=kev.get("requiredAction") if kev else None,
                kev_known_ransomware_use=(
                    (kev.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
                ),
                kev_vendor_project=kev.get("vendorProject") if kev else None,
                kev_product=kev.get("product") if kev else None,
                kev_short_description=kev.get("shortDescription") if kev else None,
                attack_techniques=map_cwes_to_attack_techniques(nvd.get("cwe", [])),
                tlp=merged_tlp.get(cve_id, "CLEAR"),
                admiralty=merged_adm.get(cve_id, ""),
                cpes=list(nvd.get("cpes") or []),
                kill_chain_phase=map_cwes_to_kill_chain(nvd.get("cwe", [])),
            )
        )

    if associations:
        for rec in enriched:
            assoc = associations.get(rec.cve_id)
            if assoc:
                rec.linked_actors = list(assoc.get("actors") or [])
                rec.linked_campaigns = list(assoc.get("campaigns") or [])
                rec.linked_malware = list(assoc.get("malware") or [])

    # Diamond Model adversary defaults to the first linked actor; capability
    # adds the primary CWE/technique label so the Diamond line in Markdown is
    # actually informative rather than just the literal word "capability".
    for rec in enriched:
        if rec.linked_actors and not rec.diamond_adversary:
            rec.diamond_adversary = rec.linked_actors[0].name
        cap_bits: list[str] = []
        if rec.cwe:
            cap_bits.append(rec.cwe[0])
        if rec.attack_techniques:
            cap_bits.append(rec.attack_techniques[0])
        if cap_bits:
            rec.diamond_capability = "exploit (" + ", ".join(cap_bits) + ")"

    return enriched

