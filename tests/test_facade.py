"""Public-surface contract lock for the monolith → package refactor.

See docs/REFACTOR_PLAN.md. These tests pass NOW (monolith) and must keep
passing at every one of the 26 split steps. The instant a step forgets to
re-export a name from ``ramen_cve/__init__.py``, the relevant assertion
here fails loudly at that step instead of silently in some unrelated test.

`PUBLIC_API` is the empirically-derived contract: every name reached by
``from ramen_cve import X`` or ``ramen_cve.X`` anywhere in
tests/test_ramen_cve.py. It is intentionally explicit and auditable — a
hand-typo here is caught immediately because the symbol genuinely exists
in the current monolith (the suite is green), so a spurious entry fails
on day one rather than masking a real regression later.

The ``ramen_cve.DEFAULT_CACHE_PATH`` late-binding risk (REFACTOR_PLAN §5.2)
is already covered by the six existing ``DEFAULT_CACHE_PATH`` tests in
test_ramen_cve.py, so it is not re-implemented here.
"""

from __future__ import annotations

from unittest.mock import patch

import ramen_cve

# --- the locked public surface -------------------------------------------
PUBLIC_API: tuple[str, ...] = (
    # exceptions + dataclasses (models.py)
    "OpmlError", "FeedEntry", "CveRecord", "ThreatActor", "Campaign",
    "Malware", "Hunt", "Pir", "IocRecord", "EnrichedCve",
    # constants / data tables (constants.py)
    "CWE_TO_ATTACK", "ATTACK_TECHNIQUE_NAMES", "CSV_COLUMNS",
    "IOC_CSV_COLUMNS", "BUCKET_ACTIONS", "DEFAULT_CACHE_PATH",
    "DEFAULT_ASSOCIATIONS_PATH", "DEFAULT_HUNT_DIR", "DEFAULT_PIR_DIR",
    "DEFAULT_CONFIG_TEMPLATE",
    # cache.py
    "Cache",
    # extract.py / decay.py
    "parse_opml", "extract_cves", "extract_iocs", "_defang_text",
    "_dedupe_iocs", "_ioc_confidence", "apply_ioc_decay",
    "filter_iocs_by_confidence",
    # analyze.py
    "map_cwes_to_attack_techniques", "map_cwes_to_kill_chain", "_utcnow",
    "_normalize_tlp", "_worst_tlp", "_admiralty_score", "_best_admiralty",
    "bucket_and_suggest", "filter_by_date",
    # associations.py
    "load_associations", "_build_actor", "_parse_kev_due_date",
    # enrich/*
    "fetch_nvd", "_parse_nvd_response", "fetch_epss", "fetch_kev_catalog",
    "fetch_exploitdb_cve_set", "fetch_nuclei_cve_set",
    "search_github_for_cve", "enrich_with_exploit_status",
    "VirusTotalEnricher", "AbuseIPDBEnricher", "OtxEnricher",
    "MalwareBazaarEnricher", "enrich_iocs", "load_inventory",
    "_cpe_matches_inventory", "correlate_inventory", "enrich_cves",
    # output/*
    "write_csv", "write_epss_trajectory_csv", "EPSS_TRAJECTORY_COLUMNS",
    "write_iocs_csv", "write_markdown",
    "_summarize_enrichment", "write_stix", "parse_stix_bundle",
    "pull_taxii", "_stix_uuid", "_ioc_to_stix_pattern",
    "_extract_iocs_from_pattern", "_sigma_level_for", "_build_sigma_stub",
    "write_sigma_stubs", "_yara_safe_name", "_yara_string_escape",
    "_build_yara_stub", "write_yara_stubs",
    # dispatch/*
    "SlackWebhookDispatcher", "GenericWebhookDispatcher", "EmailDispatcher",
    "dispatch_records", "_group_records_by_owner", "_build_digest_body",
    "_maybe_dispatch", "_maybe_digest",
    # config.py
    "load_yaml_config", "save_yaml_config", "list_yaml_presets",
    "delete_yaml_preset", "apply_yaml_config", "args_to_yaml_payload",
    "_resolve_config_path", "_save_remembered_opml",
    "_load_remembered_opml", "_reset_remembered_opml",
    # cliutil.py
    "_unique_output_path", "_safe_url_for_log", "_validate_opml_input",
    "_path_arg", "_resolve_out_dir", "_collect_opml_files",
    "_safe_basename",
    # pipeline.py
    "_maybe_filter_by_sector", "_decay_and_filter_iocs",
    "_maybe_correlate_inventory", "_output",
    # wizard.py
    "_wizard_validate_cve_list",
    # hunt/pir/trend/audit/schedule/daemon
    "load_hunt", "load_all_hunts", "save_hunt", "load_pir",
    "load_all_pirs", "save_pir", "_sparkline", "_record_runs",
    "_run_opml", "_audit_actor", "_redact_audit_args", "_audit_dispatch",
    "_parse_schedule_time", "_quote_for_task_scheduler", "_emit_cron_line",
    "_emit_windows_task_xml", "_run_schedule",
    "_run_daemon", "_build_iteration_argv",
    # cli.py
    "build_parser", "main",
)


def test_every_public_name_is_an_attribute():
    """`ramen_cve.X` must resolve for every contract name (attr access)."""
    missing = [n for n in PUBLIC_API if not hasattr(ramen_cve, n)]
    assert not missing, f"facade dropped attribute(s): {missing}"


def test_every_public_name_is_flat_importable():
    """`from ramen_cve import X` must work for every contract name."""
    ns: dict = {}
    exec(  # noqa: S102 — controlled, names are a fixed literal tuple
        "from ramen_cve import (" + ", ".join(PUBLIC_API) + ")", ns
    )
    for n in PUBLIC_API:
        assert n in ns, f"`from ramen_cve import {n}` failed"


def test_no_duplicate_contract_entries():
    """Guard the lock itself against an accidental double-listing."""
    assert len(PUBLIC_API) == len(set(PUBLIC_API))


def test_requests_patch_target_is_the_shared_module():
    """patch("ramen_cve.requests.get") must mutate the one shared
    ``requests`` module every submodule resolves at call time
    (REFACTOR_PLAN §5.1). Identity + reach, no network."""
    import requests

    assert ramen_cve.requests is requests
    with patch("ramen_cve.requests.get") as m:
        import requests as r_alias

        assert r_alias.get is m  # global reach across any import alias


def test_time_patch_target_is_the_shared_module():
    """Same invariant for patch("ramen_cve.time.sleep")."""
    import time

    assert ramen_cve.time is time
    with patch("ramen_cve.time.sleep") as m:
        import time as t_alias

        assert t_alias.sleep is m
