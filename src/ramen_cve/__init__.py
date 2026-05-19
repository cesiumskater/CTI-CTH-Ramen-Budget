#!/usr/bin/env python3
"""ramen_cve — Threat intel triage on a ramen budget.

Reads an OPML file, a single URL, or a list of CVE IDs; extracts CVE
identifiers via regex; enriches each with CVSS (NVD) and EPSS (FIRST.org)
data; buckets by exploitation likelihood and impact (CISA KEV as a hard
override); and writes a CSV and a Markdown report.

Navigation index — see REFACTOR_PLAN.md for the target ramen_cve/ package
layout these sections will map to when the single-file design is split up.
Use the section names with grep / your editor's outline view; line numbers
will drift.

  Section                                                Future module
  --------------------------------------------------     -----------------------
  Imports + module constants                             cli.py (top of)
  ATT&CK / Kill-Chain mappers                            analyze.py
  _utcnow + TLP / Admiralty math                         analyze.py
  Exceptions (OpmlError)                                 models.py
  Dataclasses (FeedEntry .. EnrichedCve)                 models.py
  Cache (SQLite + every *_cache + runs + audit_log)      cache.py
  parse_opml + extract_cves + extract_iocs + defang      extract.py
  IOC confidence decay (_ioc_confidence, apply_*)        decay.py
  API-key bootstrap                                      cli.py / wizard.py
  fetch_nvd / _parse_nvd_response                        enrich/nvd.py
  fetch_epss                                             enrich/epss.py
  fetch_kev_catalog                                      enrich/kev.py
  load_associations + _build_*                           associations.py
  enrich_cves                                            enrich/orchestrator.py
  exploit/PoC tracker                                    enrich/exploits.py
  _EnricherBase + VT/AbuseIPDB/OTX/MalwareBazaar         enrich/iocs.py
  load_inventory + correlate_inventory                   enrich/inventory.py
  Dispatchers (Slack / Webhook / Email)                  dispatch/*.py
  bucket_and_suggest + filter_by_date                    analyze.py
  CSV / STIX / Sigma / YARA / Markdown writers           output/*.py
  CLI parser + main + _audit_dispatch + _maybe_* helpers cli.py
  _run_opml / _run_url / _run_cve / _run_stix            cli.py
  _run_hunt + Hunt I/O                                   hunt.py
  _run_pir + PIR I/O                                     pir.py
  _run_trend + _sparkline + _record_runs                 trend.py
  _run_audit + _redact_audit_args                        audit.py
  _run_wizard + path validators                          wizard.py
"""

from __future__ import annotations

import logging
import sys
import time  # noqa: F401  # monkeypatch seam: tests patch ramen_cve.time.sleep

import requests  # noqa: F401  # monkeypatch seam: tests patch ramen_cve.requests.get

from .analyze import (  # noqa: F401
    CWE_TO_KILL_CHAIN,
    KILL_CHAIN_PHASES,
    _admiralty_score,
    _best_admiralty,
    _normalize_tlp,
    _worst_tlp,
    bucket_and_suggest,
    filter_by_date,
    map_cwes_to_attack_techniques,
    map_cwes_to_kill_chain,
)
from .associations import (  # noqa: F401
    _build_actor,
    _build_campaign,
    _build_malware,
    _parse_kev_due_date,
    load_associations,
)
from .audit import (  # noqa: F401
    _AUDIT_SENSITIVE_KEYS,
    _audit_actor,
    _audit_dispatch,
    _redact_audit_args,
    _run_audit,
)
from .cache import Cache  # noqa: F401
from .cli import (  # noqa: F401
    VERSION,
    _configure_logging,
    _dedupe_iocs,
    _run_cve,
    _run_opml,
    _run_stix,
    _run_url,
    _shared_flags,
    _validate_args,
    build_parser,
    main,
)
from .cliutil import (  # noqa: F401
    _collect_opml_files,
    _parse_iso_date,
    _path_arg,
    _resolve_out_dir,
    _strip_path_quotes,
    _validate_cve_id,
    _validate_opml_input,
)
from .config import (  # noqa: F401
    _YAML_FLAT_KEY_MAP,
    _coerce_yaml_value,
    _load_remembered_opml,
    _reset_remembered_opml,
    _resolve_config_path,
    _save_remembered_opml,
    apply_yaml_config,
    args_to_yaml_payload,
    delete_yaml_preset,
    list_yaml_presets,
    load_yaml_config,
    save_yaml_config,
)

# Constants moved to the Layer-0 `constants` leaf; re-exported so
# `from ramen_cve import X` / `ramen_cve.X` keep working (facade).
from .constants import (  # noqa: F401
    _DEFANG_DETECT,
    _DEFANG_MAP,
    _FILE_EXT_TLDS,
    ATTACK_TECHNIQUE_NAMES,
    BUCKET_ACTIONS,
    CISA_KEV_URL,
    CVE_REGEX,
    CWE_TO_ATTACK,
    DEFAULT_ASSOCIATIONS_PATH,
    DEFAULT_CACHE_PATH,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_TEMPLATE,
    DEFAULT_CVSS_THRESHOLD,
    DEFAULT_DATA_DIR,
    DEFAULT_EPSS_THRESHOLD,
    DEFAULT_HUNT_DIR,
    DEFAULT_LAST_OPML_PATH,
    DEFAULT_PIR_DIR,
    DEFAULT_PRESETS_DIR,
    DOMAIN_REGEX,
    EMAIL_REGEX,
    EPSS_API_BASE,
    EXPLOIT_STATUS_VALUES,
    EXPLOITDB_CSV_URL,
    GITHUB_SEARCH_URL,
    HUNT_STATUSES,
    IPV4_REGEX,
    MD5_REGEX,
    NUCLEI_TEMPLATES_TREE_URL,
    NVD_API_BASE,
    PIR_STATUSES,
    SHA1_REGEX,
    SHA256_REGEX,
    TLP_LEVELS,
    URL_REGEX,
    USER_AGENT,
)
from .decay import (  # noqa: F401
    IOC_HALF_LIFE_DAYS,
    _ioc_confidence,
    apply_ioc_decay,
    filter_iocs_by_confidence,
)
from .dispatch.digest import (  # noqa: F401
    _build_digest_body,
    _group_records_by_owner,
    _maybe_digest,
)
from .dispatch.runner import dispatch_records  # noqa: F401
from .dispatch.sinks import (  # noqa: F401
    DISPATCH_DEFAULT_BUCKETS,
    EmailDispatcher,
    GenericWebhookDispatcher,
    SlackWebhookDispatcher,
    _build_default_dispatchers,
    _DispatcherBase,
)
from .enrich.epss import fetch_epss  # noqa: F401
from .enrich.exploits import (  # noqa: F401
    enrich_with_exploit_status,
    fetch_exploitdb_cve_set,
    fetch_nuclei_cve_set,
    search_github_for_cve,
)
from .enrich.inventory import (  # noqa: F401
    _cpe_matches_inventory,
    correlate_inventory,
    load_inventory,
)
from .enrich.iocs import (  # noqa: F401
    ABUSEIPDB_API_BASE,
    MALWAREBAZAAR_API,
    OTX_API_BASE,
    VIRUSTOTAL_API_BASE,
    AbuseIPDBEnricher,
    MalwareBazaarEnricher,
    OtxEnricher,
    VirusTotalEnricher,
    _build_default_enrichers,
    _EnricherBase,
    enrich_iocs,
)
from .enrich.kev import fetch_kev_catalog  # noqa: F401
from .enrich.nvd import (  # noqa: F401
    _empty_nvd,
    _parse_nvd_response,
    fetch_nvd,
)
from .enrich.orchestrator import enrich_cves  # noqa: F401
from .extract import (  # noqa: F401
    _defang_text,
    _is_likely_filename,
    _is_public_ip,
    extract_cves,
    extract_iocs,
    parse_opml,
)
from .hunt import (  # noqa: F401
    _hunt_path,
    _run_hunt,
    load_all_hunts,
    load_hunt,
    save_hunt,
)
from .keyring import (  # noqa: F401
    ENV_FILE_PATH,
    NVD_API_KEY_REGEX,
    NVD_KEY_REQUEST_URL,
    _is_interactive,
    _prompt_for_api_key,
    _redact_key,
    _safe_url_for_log,
    _save_api_key_to_env,
)
from .models import (  # noqa: F401
    Campaign,
    CveRecord,
    EnrichedCve,
    FeedEntry,
    Hunt,
    IocRecord,
    Malware,
    OpmlError,
    Pir,
    ThreatActor,
    _utcnow,
)
from .output.csv_writer import (  # noqa: F401
    CSV_COLUMNS,
    write_csv,
)
from .output.markdown import (  # noqa: F401
    BUCKET_DISPLAY,
    BUCKET_ORDER,
    IOC_TYPE_DISPLAY,
    IOC_TYPE_ORDER,
    _md_safe,
    _summarize_enrichment,
    write_markdown,
)
from .output.sigma import (  # noqa: F401
    SIGMA_ELIGIBLE_BUCKETS,
    _build_sigma_stub,
    _sigma_level_for,
    _sigma_yaml_escape,
    write_sigma_stubs,
)
from .output.stix import (  # noqa: F401
    _STIX_PATTERN_RE,
    IOC_CSV_COLUMNS,
    _extract_cve_id_from_vuln,
    _extract_iocs_from_pattern,
    _ioc_to_stix_pattern,
    _stix_objects_to_records,
    _stix_uuid,
    parse_stix_bundle,
    pull_taxii,
    write_iocs_csv,
    write_stix,
)
from .output.yara import (  # noqa: F401
    YARA_ELIGIBLE_BUCKETS,
    _build_yara_stub,
    _yara_safe_name,
    _yara_string_escape,
    write_yara_stubs,
)
from .pipeline import (  # noqa: F401
    _KNOWN_OUTPUT_EXTENSIONS,
    _decay_and_filter_iocs,
    _get_github_token,
    _maybe_correlate_inventory,
    _maybe_dispatch,
    _maybe_enrich_iocs,
    _maybe_filter_by_sector,
    _output,
    _resolve_associations,
    _safe_basename,
    _unique_output_path,
)
from .pir import (  # noqa: F401
    _pir_path,
    _run_pir,
    load_all_pirs,
    load_pir,
    save_pir,
)
from .schedule import (  # noqa: F401
    _build_schedule_command,
    _emit_cron_line,
    _emit_windows_task_xml,
    _entry_script_path,
    _parse_schedule_time,
    _quote_for_task_scheduler,
    _run_schedule,
)
from .trend import (  # noqa: F401
    _SPARKLINE_CHARS,
    _record_runs,
    _run_trend,
    _sparkline,
)
from .wizard import (  # noqa: F401
    _run_wizard,
    _wizard_validate_cve_list,
    _wizard_validate_date,
    _wizard_validate_float,
)

_log = logging.getLogger(__name__)


if __name__ == "__main__":
    sys.exit(main())
