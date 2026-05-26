"""ramen_cve.models — exceptions + dataclasses (Layer-0 leaf).

Zero first-party deps except the constants leaf. `_utcnow` lives here
because EnrichedCve's default_factory needs it at instance-build time
and models is its lowest consumer; analyze/cache/etc. import it from
the facade. See docs/REFACTOR_PLAN.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from .constants import BUCKET_ACTIONS


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime.

    datetime.utcnow() is deprecated in Python 3.12+. We use
    datetime.now(timezone.utc).replace(tzinfo=None) so the rest of the
    code can keep treating timestamps as naive UTC (they are written
    to and read from SQLite as ISO-8601 strings without timezone, and
    the cache TTL math compares two naive UTC datetimes).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OpmlError(Exception):
    """Raised when an OPML file is missing or malformed."""


class WebUiError(Exception):
    """Raised when the static-HTML Web UI builder cannot render a site.

    The dominant case is an empty `runs` table (nothing to render); see
    `web.builder.build_site` and the Task-8 design doc §D11.
    """


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeedEntry:
    """A single RSS/Atom feed from an OPML file.

    Optional `tlp` and `admiralty` are read from data-tlp / data-admiralty
    attributes on the OPML <outline> element (with inheritance from parent
    outlines). They propagate through to every CveRecord and IocRecord
    extracted from this feed.
    """

    title: str
    url: str
    category: str = ""
    tlp: str = "CLEAR"
    admiralty: str = ""


@dataclass
class CveRecord:
    """A CVE ID as extracted from a source, before enrichment.

    `tlp` and `admiralty` carry the source's sharing/reliability tags so the
    enriched record can surface the most-restrictive TLP and best Admiralty
    grade across all sources that mentioned the same CVE.
    """

    cve_id: str
    source: str
    first_seen: date
    first_seen_type: str  # "feed_pub" | "disclosure" | "manual_input"
    tlp: str = "CLEAR"
    admiralty: str = ""


# IOC types are kept open-coded as strings so the rest of the pipeline (CSV
# columns, Markdown sections) can grow new types without a schema migration.
# Current values: "ipv4" | "url" | "domain" | "email" | "md5" | "sha1" | "sha256".
@dataclass
class ThreatActor:
    """A named adversary group; subset of the MITRE ATT&CK Groups schema.

    `sectors_targeted` is a lowercase tag list (e.g. ['financial', 'energy'])
    used by the --sector filter to keep relevant CVEs and drop ones whose
    only attribution targets a different sector.
    """

    name: str
    aliases: list[str] = field(default_factory=list)
    url: str | None = None
    sectors_targeted: list[str] = field(default_factory=list)


@dataclass
class Campaign:
    """A discrete intrusion campaign attributed to one or more actors."""

    name: str
    aliases: list[str] = field(default_factory=list)
    url: str | None = None


@dataclass
class Malware:
    """A named malware family or tool used in attacks."""

    name: str
    aliases: list[str] = field(default_factory=list)
    url: str | None = None


@dataclass
class Hunt:
    """A single threat-hunt hypothesis with linked CVEs, data sources, and findings.

    Stored on disk as one JSON file per hunt under DEFAULT_HUNT_DIR. JSON (not
    YAML) is used so this v1 stays inside the project's three-runtime-deps
    budget — PyYAML is not added.
    """

    id: str
    name: str
    hypothesis: str
    data_sources: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    linked_cves: list[str] = field(default_factory=list)
    status: str = "open"
    created: str = ""
    findings: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Hunt:
        """Build a Hunt from a dict, tolerating missing keys with sensible defaults."""
        return cls(
            id=str(d.get("id") or ""),
            name=str(d.get("name") or ""),
            hypothesis=str(d.get("hypothesis") or ""),
            data_sources=list(d.get("data_sources") or []),
            attack_techniques=list(d.get("attack_techniques") or []),
            linked_cves=list(d.get("linked_cves") or []),
            status=str(d.get("status") or "open"),
            created=str(d.get("created") or ""),
            findings=list(d.get("findings") or []),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hypothesis": self.hypothesis,
            "data_sources": list(self.data_sources),
            "attack_techniques": list(self.attack_techniques),
            "linked_cves": list(self.linked_cves),
            "status": self.status,
            "created": self.created,
            "findings": list(self.findings),
        }


@dataclass
class Pir:
    """A Priority Intelligence Requirement — the leadership-blessed question
    the CTI program exists to answer.

    Mirrors the Hunt convention: one JSON file per PIR under DEFAULT_PIR_DIR.
    """

    id: str
    name: str
    question: str
    owner: str = ""
    status: str = "active"
    created: str = ""
    tagged_cves: list[str] = field(default_factory=list)
    tagged_iocs: list[str] = field(default_factory=list)
    tagged_actors: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> Pir:
        """Build a Pir from a dict, tolerating missing keys with sensible defaults."""
        return cls(
            id=str(d.get("id") or ""),
            name=str(d.get("name") or ""),
            question=str(d.get("question") or ""),
            owner=str(d.get("owner") or ""),
            status=str(d.get("status") or "active"),
            created=str(d.get("created") or ""),
            tagged_cves=list(d.get("tagged_cves") or []),
            tagged_iocs=list(d.get("tagged_iocs") or []),
            tagged_actors=list(d.get("tagged_actors") or []),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "question": self.question,
            "owner": self.owner,
            "status": self.status,
            "created": self.created,
            "tagged_cves": list(self.tagged_cves),
            "tagged_iocs": list(self.tagged_iocs),
            "tagged_actors": list(self.tagged_actors),
        }


@dataclass
class IocRecord:
    """A non-CVE indicator extracted from feed/URL text.

    `defanged_in_source` is a per-text confidence signal: True when the
    original text contained at least one defang marker (hxxp, [.], (at), etc.).
    Defanged feeds are typically authoritative IOC publications; un-defanged
    matches are more likely to be incidental references.

    `enrichments` is a per-IOC dict keyed on enricher name (e.g. 'virustotal',
    'abuseipdb') whose values are normalized payload dicts populated by
    enrich_iocs().
    """

    ioc_type: str
    value: str
    source: str
    first_seen: date
    first_seen_type: str
    defanged_in_source: bool = False
    enrichments: dict[str, dict] = field(default_factory=dict)
    tlp: str = "CLEAR"
    admiralty: str = ""
    # `last_seen` is the most recent date this exact indicator was observed.
    # Defaults to None so apply_ioc_decay() can fall back to first_seen, but a
    # multi-run IOC reservoir should refresh it on every fresh sighting.
    last_seen: date | None = None
    # `confidence` decays exponentially per IOC type from 1.0 (just-seen) to 0.0
    # (long-stale). Populated by apply_ioc_decay() before output.
    confidence: float = 1.0


@dataclass
class EnrichedCve:
    """A CveRecord merged with NVD and EPSS data and a bucket assignment."""

    cve_id: str
    source: str
    first_seen: date
    first_seen_type: str

    # NVD fields
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    kev_listed: bool = False
    cwe: list[str] = field(default_factory=list)
    nvd_published: date | None = None
    nvd_status: str = "ok"

    # CISA KEV authoritative fields (only populated when the CVE is in the KEV catalog).
    kev_due_date: date | None = None
    kev_required_action: str | None = None
    kev_known_ransomware_use: bool = False
    kev_vendor_project: str | None = None
    kev_product: str | None = None
    kev_short_description: str | None = None

    # EPSS fields
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None

    # When `--date-mode epss` is given a multi-day range, the orchestrator
    # fetches EPSS scores for every day in the range and stores them here,
    # keyed by ISO date string ("YYYY-MM-DD" -> {"epss": float,
    # "percentile": float}). Empty for the common single-date / no-date
    # case — preserves the byte-identical contract for existing runs.
    epss_trajectory: dict[str, dict] = field(default_factory=dict)

    # MITRE ATT&CK technique IDs derived from the CWE list (best-effort, lossy).
    attack_techniques: list[str] = field(default_factory=list)

    # Public exploit / PoC availability signal: one of EXPLOIT_STATUS_VALUES.
    exploit_status: str = "none"

    # Adversary attribution joined from associations.json (or a user override).
    linked_actors: list[ThreatActor] = field(default_factory=list)
    linked_campaigns: list[Campaign] = field(default_factory=list)
    linked_malware: list[Malware] = field(default_factory=list)

    # Provenance tags propagated from the source feed(s).
    tlp: str = "CLEAR"
    admiralty: str = ""

    # CPE 2.3 strings from NVD (configurations.nodes.cpeMatch.criteria).
    cpes: list[str] = field(default_factory=list)

    # Hosts from the user's --inventory CSV whose product+version match a CPE.
    affected_hosts: list[str] = field(default_factory=list)

    # Lockheed Martin Cyber Kill Chain phase (derived from CWE; default
    # 'exploitation' since every vulnerability description reduces to that).
    kill_chain_phase: str = "exploitation"

    # Diamond Model — the vulnerability itself is always a 'capability'.
    # adversary / infrastructure / victim are filled when other features supply
    # them (associations.json, future infrastructure feeds, --inventory).
    diamond_capability: str = "capability"
    diamond_adversary: str = ""
    diamond_infrastructure: str = ""
    diamond_victim: str = ""

    # Bucket
    bucket: str = "unknown"
    suggested_action: str = BUCKET_ACTIONS["unknown"]

    enriched_at: datetime = field(default_factory=lambda: _utcnow())
