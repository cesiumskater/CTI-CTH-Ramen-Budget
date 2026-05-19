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

import argparse
import contextlib
import json
import logging
import re
import sys
import time  # noqa: F401  # monkeypatch seam: tests patch ramen_cve.time.sleep
from datetime import date
from pathlib import Path

import requests

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
from .pir import (  # noqa: F401
    _pir_path,
    _run_pir,
    load_all_pirs,
    load_pir,
    save_pir,
)
from .trend import (  # noqa: F401
    _SPARKLINE_CHARS,
    _record_runs,
    _run_trend,
    _sparkline,
)

_log = logging.getLogger(__name__)


VERSION = "0.1"


def _parse_iso_date(value: str) -> date:
    """Argparse type: parse YYYY-MM-DD or raise ArgumentTypeError."""
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid date '{value}' — expected YYYY-MM-DD.") from exc


def _validate_cve_id(value: str) -> str:
    """Argparse type: ensure value matches the CVE ID pattern."""
    if not CVE_REGEX.fullmatch(value.upper()):
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid CVE ID. Expected format: CVE-YYYY-NNNN."
        )
    return value.upper()


def _strip_path_quotes(value: str) -> str:
    """Return `value` with surrounding whitespace and a single layer of paired
    ASCII or curly quotes stripped.

    Users habitually paste quoted paths, especially on Windows where Explorer's
    "Copy as path" wraps the result in double quotes. Argparse and questionary
    treat the quotes as literal characters, which then fails Path operations on
    Windows (where `"` is a reserved filename character) and silently produces a
    weirdly-named directory on POSIX.
    """
    s = (value or "").strip()
    pairs = (('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’"))
    for opener, closer in pairs:
        if len(s) >= 2 and s[0] == opener and s[-1] == closer:
            s = s[1:-1].strip()
            break
    return s


def _path_arg(value: str) -> Path:
    """Argparse type for user-supplied paths.

    Performs the full normalization pipeline:
      1. Strip surrounding ASCII or curly quotes (common when copying from
         Windows Explorer's "Copy as path").
      2. Strip surrounding whitespace.
      3. Expand a leading ``~`` to the user's home directory (POSIX + Windows).

    Returns a ``pathlib.Path`` — the rest of the code never sees a raw string.
    """
    return Path(_strip_path_quotes(value)).expanduser()


def _resolve_out_dir(value: Path | None) -> Path:
    """Resolve a `--out-dir` argument to a concrete directory.

    A None / empty value (``--out-dir`` omitted, or wizard answered blank)
    resolves to the current working directory rather than the literal ``.``
    so the help text and prompt placeholder stay clean.
    """
    if value is None or str(value) in ("", "."):
        return Path.cwd()
    return value.expanduser()


def _validate_opml_input(value: str) -> bool | str:
    """Wizard validator for the OPML path prompt.

    Accepts either:
      - a path to a single ``.opml`` file, or
      - a directory containing at least one ``*.opml`` file.

    Quote-stripping and ``~`` expansion are applied before the on-disk check.
    Returns True on success or a user-facing error string for questionary.
    """
    if not value or not value.strip():
        return "Enter the path to an OPML file or a directory of .opml files."
    cleaned = Path(_strip_path_quotes(value)).expanduser()
    if cleaned.is_file():
        return True
    if cleaned.is_dir():
        if any(cleaned.glob("*.opml")):
            return True
        return f"{cleaned} exists but contains no .opml files."
    return f"Path not found: {cleaned}"


def _collect_opml_files(path: Path) -> list[Path]:
    """Return the list of OPML files at ``path``.

    If ``path`` is a file we return ``[path]``. If it's a directory we return
    every ``*.opml`` under it (sorted, top-level only — no recursion to avoid
    picking up backups or unrelated bundles). An empty directory raises
    OpmlError with a clear message so the caller can surface it.
    """
    if path.is_file():
        return [path]
    if path.is_dir():
        files = sorted(path.glob("*.opml"))
        if not files:
            raise OpmlError(
                f"Directory contains no .opml files: {path}"
            )
        return files
    raise OpmlError(f"OPML path not found: {path}")


# ---------------------------------------------------------------------------
# YAML configuration system
# ---------------------------------------------------------------------------
#
# Saved configurations live as YAML files under DEFAULT_PRESETS_DIR. The
# documented template at DEFAULT_CONFIG_TEMPLATE shows every key the tool
# understands. CLI args ALWAYS win over YAML values — the YAML only fills
# the gaps. See src/ramen_cve/config/config.yaml for the full schema.
# ---------------------------------------------------------------------------


def _resolve_config_path(name_or_path: str) -> Path:
    """Resolve ``--config`` argument to a concrete YAML file.

    Plain names like ``daily-hunt`` are looked up under DEFAULT_PRESETS_DIR
    with a ``.yaml`` extension. Anything containing a path separator (``/`` or
    ``\\``) or an explicit ``.yaml`` / ``.yml`` extension is treated as a
    file path (quote-stripped + ~-expanded).
    """
    raw = (name_or_path or "").strip()
    if not raw:
        raise FileNotFoundError("No config name or path supplied.")
    looks_like_path = (
        "/" in raw or "\\" in raw
        or raw.endswith((".yaml", ".yml"))
        or raw.startswith("~")
    )
    if looks_like_path:
        return Path(_strip_path_quotes(raw)).expanduser()
    return DEFAULT_PRESETS_DIR / f"{raw}.yaml"


def load_yaml_config(name_or_path: str) -> dict:
    """Load a YAML config (preset name or explicit path) into a dict.

    Returns ``{}`` for an empty file. Raises FileNotFoundError when the
    file doesn't exist and ValueError when the file isn't YAML-parseable
    so callers can surface clean error messages.
    """
    import yaml

    path = _resolve_config_path(name_or_path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Could not parse YAML config {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Config file {path} must contain a YAML mapping at the top level."
        )
    return data


def list_yaml_presets() -> list[Path]:
    """Return every *.yaml preset under DEFAULT_PRESETS_DIR (sorted)."""
    if not DEFAULT_PRESETS_DIR.exists():
        return []
    return sorted(DEFAULT_PRESETS_DIR.glob("*.yaml"))


def delete_yaml_preset(name_or_path: str) -> Path | None:
    """Delete a saved preset. Returns the removed path, or None if absent."""
    target = _resolve_config_path(name_or_path)
    if target.is_file():
        target.unlink()
        return target
    return None


def _save_remembered_opml(path: Path) -> Path:
    """Persist the OPML source so a later `opml` run with no path reuses it.

    Writes a tiny JSON blob (``{opml_path, saved_at}``) to
    DEFAULT_LAST_OPML_PATH. Returns the state-file path written.
    """
    DEFAULT_LAST_OPML_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_LAST_OPML_PATH.write_text(
        json.dumps(
            {"opml_path": str(path), "saved_at": _utcnow().isoformat(timespec="seconds")},
            indent=2,
        ),
        encoding="utf-8",
    )
    return DEFAULT_LAST_OPML_PATH


def _load_remembered_opml() -> Path | None:
    """Return the previously-remembered OPML path, or None if not set / unreadable.

    Never raises: a missing or corrupt state file simply means "nothing
    remembered" so the caller can fall back to a clean 'path required' error.
    """
    if not DEFAULT_LAST_OPML_PATH.is_file():
        return None
    try:
        data = json.loads(DEFAULT_LAST_OPML_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    raw = (data or {}).get("opml_path")
    return Path(raw).expanduser() if raw else None


def _reset_remembered_opml() -> bool:
    """Forget the remembered OPML. Returns True if a state file was removed."""
    if DEFAULT_LAST_OPML_PATH.is_file():
        DEFAULT_LAST_OPML_PATH.unlink()
        return True
    return False


def save_yaml_config(name_or_path: str, payload: dict) -> Path:
    """Persist ``payload`` as a YAML preset. Returns the path written to.

    A bare name maps to ``DEFAULT_PRESETS_DIR/<name>.yaml``; anything with a
    path separator or ``.yaml`` / ``.yml`` extension is treated as an
    explicit file path. The presets directory is created on demand.
    """
    import yaml

    target = _resolve_config_path(name_or_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    return target


# Mapping from YAML key → argparse.Namespace attribute name. Nested YAML
# blocks (output, filters, enrichment, cache, dispatch, email, logging) are
# expanded into flat attributes that mirror the CLI flag names. CLI args
# present in args.* with a non-None value override any YAML setting.
_YAML_FLAT_KEY_MAP: dict[tuple[str, ...], str] = {
    ("subcommand",): "subcommand",
    ("opml_path",): "path",
    ("url",): "url",
    ("cves",): "cves",
    ("stix_path",): "path",
    ("taxii_url",): "taxii_url",
    ("taxii_collection",): "taxii_collection",
    ("inventory_path",): "inventory",
    ("output", "out_dir"): "out_dir",
    ("output", "basename"): "basename",
    ("output", "format"): "format",
    ("output", "allow_tlp_red"): "allow_tlp_red",
    ("filters", "cvss_threshold"): "cvss_threshold",
    ("filters", "epss_threshold"): "epss_threshold",
    ("filters", "ioc_confidence_floor"): "ioc_confidence_floor",
    ("filters", "start"): "start",
    ("filters", "end"): "end",
    ("filters", "date_mode"): "date_mode",
    ("filters", "sector"): "sector",
    ("enrichment", "no_exploit_lookup"): "no_exploit_lookup",
    ("enrichment", "no_enrich_iocs"): "no_enrich_iocs",
    ("cache", "no_cache"): "no_cache",
    ("dispatch", "enabled"): "dispatch",
    ("remember_opml",): "remember_opml",
}


def _coerce_yaml_value(attr: str, value):
    """Convert a YAML value into the type argparse would have produced.

    Handles the four argparse types this tool uses: dates (from ISO strings),
    floats, Paths, and lists (passed through). Empty strings collapse to None
    so they don't override a real CLI argument by accident.
    """
    if value in ("", None):
        return None
    if attr in ("start", "end") and isinstance(value, str):
        try:
            return _parse_iso_date(value)
        except (argparse.ArgumentTypeError, ValueError):
            return None
    if attr in (
        "out_dir", "path", "inventory", "associations_file",
        "hunt_dir", "pir_dir",
    ) and isinstance(value, str):
        return Path(_strip_path_quotes(value)).expanduser()
    if attr in ("cvss_threshold", "epss_threshold", "ioc_confidence_floor"):
        return float(value)
    return value


def apply_yaml_config(args: argparse.Namespace, config: dict) -> None:
    """Fold a loaded YAML config into ``args`` IN PLACE.

    Walks _YAML_FLAT_KEY_MAP, pulling each nested-or-flat YAML key out of
    the loaded mapping and stamping it onto the corresponding args attribute
    only when the user did NOT pass that flag on the CLI (i.e. when the
    attribute is currently None / False / its argparse default).
    """
    def _get_nested(d: dict, path: tuple[str, ...]):
        cur = d
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return None
            cur = cur[key]
        return cur

    for key_path, attr in _YAML_FLAT_KEY_MAP.items():
        raw = _get_nested(config, key_path)
        if raw is None:
            continue
        coerced = _coerce_yaml_value(attr, raw)
        if coerced is None:
            continue
        current = getattr(args, attr, None)
        # "Current is unset" heuristic: argparse defaults for our flags are
        # either None, False (for store_true), or the documented numeric
        # default. We override None/False; we leave non-default values alone.
        if current in (None, False, "", []):
            setattr(args, attr, coerced)

    # Logging level: YAML's logging.level maps to args.quiet / args.verbose
    # only when neither flag was passed.
    log_level = (config.get("logging") or {}).get("level")
    if isinstance(log_level, str) and not getattr(args, "quiet", False) \
            and not getattr(args, "verbose", False):
        if log_level == "quiet":
            args.quiet = True
        elif log_level == "verbose":
            args.verbose = True

    # Email section → RAMEN_SMTP_* env vars so EmailDispatcher.from_env()
    # picks them up. Plaintext SMTP passwords in YAML are flagged in the
    # template; production users should prefer .env / keyring.
    email = config.get("email") or {}
    if isinstance(email, dict) and email.get("enabled"):
        import os

        def _set_env_if_blank(key: str, value) -> None:
            """Set `key` to `str(value)` only if `value` is truthy AND the env
            var is not already set (so a real `.env` always wins over YAML)."""
            if value:
                os.environ.setdefault(key, str(value))

        _set_env_if_blank("RAMEN_SMTP_HOST", email.get("smtp_host"))
        if email.get("smtp_port"):
            _set_env_if_blank("RAMEN_SMTP_PORT", email.get("smtp_port"))
        _set_env_if_blank("RAMEN_SMTP_USER", email.get("smtp_user"))
        _set_env_if_blank("RAMEN_SMTP_PASS", email.get("smtp_pass"))
        _set_env_if_blank("RAMEN_SMTP_FROM", email.get("smtp_from"))
        if email.get("smtp_use_tls") is False:
            _set_env_if_blank("RAMEN_SMTP_USE_TLS", "0")
        _set_env_if_blank("RAMEN_DIGEST_TO", email.get("fallback_recipient"))
        # Implicit: enabling email turns on --digest unless explicitly opted out.
        if not getattr(args, "digest", False):
            args.digest = True


def args_to_yaml_payload(args: argparse.Namespace) -> dict:
    """Snapshot the current invocation as a YAML-compatible mapping.

    Used by ``--save-config NAME``. Mirrors the schema in
    src/ramen_cve/config/config.yaml so a round-trip
    save → load → run reproduces the same behavior.
    """
    def _stringify(v):
        if isinstance(v, Path):
            return str(v)
        if isinstance(v, date):
            return v.isoformat()
        return v

    payload: dict = {"subcommand": getattr(args, "subcommand", None)}
    payload["opml_path"] = _stringify(getattr(args, "path", None)) \
        if getattr(args, "subcommand", "") == "opml" else None
    payload["url"] = getattr(args, "url", None)
    payload["cves"] = list(getattr(args, "cves", None) or []) or None
    payload["stix_path"] = _stringify(getattr(args, "path", None)) \
        if getattr(args, "subcommand", "") == "stix" else None
    payload["taxii_url"] = getattr(args, "taxii_url", None)
    payload["taxii_collection"] = getattr(args, "taxii_collection", None)
    payload["inventory_path"] = _stringify(getattr(args, "inventory", None))
    payload["output"] = {
        "out_dir": _stringify(getattr(args, "out_dir", None)),
        "basename": getattr(args, "basename", None) or "",
        "format": getattr(args, "format", None),
        "allow_tlp_red": bool(getattr(args, "allow_tlp_red", False)),
    }
    payload["filters"] = {
        "cvss_threshold": getattr(args, "cvss_threshold", None),
        "epss_threshold": getattr(args, "epss_threshold", None),
        "ioc_confidence_floor": getattr(args, "ioc_confidence_floor", None),
        "start": _stringify(getattr(args, "start", None)) or "",
        "end": _stringify(getattr(args, "end", None)) or "",
        "date_mode": getattr(args, "date_mode", None),
        "sector": getattr(args, "sector", None) or "",
    }
    payload["enrichment"] = {
        "no_exploit_lookup": bool(getattr(args, "no_exploit_lookup", False)),
        "no_enrich_iocs": bool(getattr(args, "no_enrich_iocs", False)),
    }
    payload["cache"] = {"no_cache": bool(getattr(args, "no_cache", False))}
    payload["dispatch"] = {"enabled": bool(getattr(args, "dispatch", False))}
    payload["remember_opml"] = bool(getattr(args, "remember_opml", False))
    payload["logging"] = {
        "level": "quiet" if getattr(args, "quiet", False)
        else "verbose" if getattr(args, "verbose", False)
        else "normal",
    }
    # Drop any key with a None value so the saved file stays tidy.
    return {k: v for k, v in payload.items() if v not in (None, {}, [])}


def _shared_flags(parser: argparse.ArgumentParser) -> None:
    """Attach the flags shared by all three subcommands."""
    parser.add_argument("--start", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--end", type=_parse_iso_date, metavar="YYYY-MM-DD")
    parser.add_argument("--date-mode", choices=["feed", "disclosure", "epss"], default=None)
    parser.add_argument("--cvss-threshold", type=float, default=DEFAULT_CVSS_THRESHOLD)
    parser.add_argument("--epss-threshold", type=float, default=DEFAULT_EPSS_THRESHOLD)
    # Default is None so the help text doesn't show a literal '.'; runtime
    # resolves None → Path.cwd() via _resolve_out_dir(). Threat hunters
    # typically pass a quoted Windows path here ("C:\\Users\\me\\Reports");
    # _path_arg strips the quotes and expands ~.
    parser.add_argument(
        "--out-dir",
        type=_path_arg,
        default=None,
        metavar="DIR",
        help="Directory to write output files into. Defaults to the current "
             "working directory. Surrounding quotes and a leading ~ are handled.",
    )
    parser.add_argument(
        "--basename",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Stem for output files (no extension). Default: ramen-cve-<UTC timestamp>. "
            "Path separators are stripped; -iocs is appended to the IOC CSV; -sigma to "
            "the Sigma rule directory."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["csv", "md", "both", "stix", "sigma", "yara", "all"],
        default="both",
        help=(
            "Output format. 'both' = CSV + Markdown; 'sigma' = Sigma stubs only; "
            "'yara' = YARA stubs only (one per linked malware family); "
            "'all' = CSV + Markdown + STIX + Sigma + YARA."
        ),
    )
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--no-exploit-lookup",
        action="store_true",
        help="Skip Exploit-DB / Nuclei / GitHub PoC lookups (offline mode).",
    )
    parser.add_argument(
        "--no-enrich-iocs",
        action="store_true",
        help="Skip per-IOC enrichment (VirusTotal / AbuseIPDB / OTX / MalwareBazaar).",
    )
    parser.add_argument(
        "--ioc-confidence-floor",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help=(
            "Drop IOCs whose decay-weighted confidence is below this floor "
            "(0.0..1.0; default 0.0 keeps every IOC). Half-lives per type: "
            "IPv4 30d, URL 30d, domain 90d, email 90d; file hashes never decay."
        ),
    )
    parser.add_argument(
        "--sector",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Filter the report to CVEs likely relevant to a given sector "
            "(e.g. 'financial', 'healthcare', 'energy', 'government'). "
            "Matches against each linked actor's sectors_targeted in "
            "associations.json. Records with no linked actors are KEPT "
            "(unattributed CVEs are assumed potentially relevant)."
        ),
    )
    parser.add_argument(
        "--allow-tlp-red",
        action="store_true",
        help=(
            "Permit writing TLP:RED records to disk. Default behavior is to "
            "STRIP any TLP:RED records before output and log a warning."
        ),
    )
    parser.add_argument(
        "--inventory",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CSV asset inventory with columns 'host,product,version' "
            "(or 'host,cpe'). When set, the report annotates each CVE with the "
            "list of inventory hosts whose product+version matches a CVE CPE."
        ),
    )
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help=(
            "After writing reports, push every kev_override / patch_now finding "
            "to configured dispatchers (Slack via SLACK_WEBHOOK_URL, generic "
            "webhook via RAMEN_DISPATCH_WEBHOOK). Off by default."
        ),
    )
    parser.add_argument(
        "--digest",
        action="store_true",
        help=(
            "After writing reports, batch-mail one digest email per recipient "
            "(keyed by the inventory CSV's `owner` column, falling back to "
            "RAMEN_DIGEST_TO when set). SMTP via RAMEN_SMTP_* env vars. The "
            "CSV and Markdown reports are attached. Off by default."
        ),
    )
    parser.add_argument(
        "--associations-file",
        type=_path_arg,
        metavar="PATH",
        help=(
            "Path to a CVE→adversary associations JSON file. "
            "Defaults to associations.json in the repo. Pass an empty/missing "
            "path to disable adversary attribution."
        ),
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ramen_cve",
        description="Threat intel triage on a ramen budget.",
    )
    # YAML configuration plumbing — top-level (works before any subcommand).
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Load a saved YAML preset by name "
            "(under src/ramen_cve/config/presets/<NAME>.yaml) "
            "or an explicit YAML file path. CLI flags override YAML values."
        ),
    )
    parser.add_argument(
        "--save-config",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "After this run, persist the current invocation's arguments as a "
            "YAML preset under that NAME (or write to the explicit YAML path)."
        ),
    )
    parser.add_argument(
        "--list-configs",
        action="store_true",
        help="List every saved YAML preset and exit.",
    )
    parser.add_argument(
        "--reset-config",
        type=str,
        default=None,
        metavar="NAME",
        help="Delete the saved YAML preset with that NAME (or path) and exit.",
    )
    parser.add_argument(
        "--reset-opml",
        action="store_true",
        help="Forget the remembered OPML source (clears the last_opml state) "
             "and exit.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=False)

    # opml subcommand
    opml_p = sub.add_parser("opml", help="Process an OPML feed list.")
    opml_p.add_argument(
        "path",
        type=_path_arg,
        nargs="?",
        default=None,
        help="Path to an .opml file OR a directory of *.opml files. "
             "Optional when a remembered OPML exists (see --remember-opml).",
    )
    opml_p.add_argument(
        "--remember-opml",
        action="store_true",
        help="After a successful run, save this OPML source so a later "
             "`opml` with no path argument reuses it automatically.",
    )
    _shared_flags(opml_p)

    # url subcommand
    url_p = sub.add_parser("url", help="Extract CVEs from a single URL.")
    url_p.add_argument("url", help="URL of the article or page to scan.")
    _shared_flags(url_p)

    # cve subcommand
    cve_p = sub.add_parser("cve", help="Enrich named CVE IDs directly.")
    cve_p.add_argument("cves", nargs="*", type=_validate_cve_id, metavar="CVE-ID")
    cve_p.add_argument("--from-file", type=_path_arg, metavar="FILE", help="Text file of CVE IDs.")
    _shared_flags(cve_p)

    # hunt subcommand: list / show / link / log / status against the hunts/ library
    hunt_p = sub.add_parser("hunt", help="Manage threat-hunt hypotheses.")
    hunt_p.add_argument(
        "action",
        choices=["list", "show", "link", "log", "status"],
        help="What to do with the hunts library.",
    )
    hunt_p.add_argument("hunt_id", nargs="?", help="Hunt id (filename stem under hunts/).")
    hunt_p.add_argument(
        "value",
        nargs="?",
        help=(
            "Action argument: CVE-ID for 'link', finding text for 'log', "
            "new status for 'status'."
        ),
    )
    hunt_p.add_argument(
        "--hunt-dir",
        type=_path_arg,
        default=DEFAULT_HUNT_DIR,
        help="Directory of hunt JSON files (default: hunts/ next to ramen_cve.py).",
    )

    # pir subcommand: leadership-blessed Priority Intelligence Requirements
    pir_p = sub.add_parser(
        "pir", help="Manage Priority Intelligence Requirements (PIRs)."
    )
    pir_p.add_argument(
        "action",
        choices=["list", "show", "link", "coverage"],
        help="What to do with the PIR library.",
    )
    pir_p.add_argument(
        "pir_id", nargs="?", help="PIR id (filename stem under pirs/)."
    )
    pir_p.add_argument(
        "value", nargs="?",
        help="Action argument: CVE-ID for 'link' (other actions ignore this).",
    )
    pir_p.add_argument(
        "--pir-dir",
        type=_path_arg,
        default=DEFAULT_PIR_DIR,
        help="Directory of PIR JSON files (default: pirs/ next to ramen_cve.py).",
    )

    # trend subcommand: historical bucket / CVSS / EPSS for one CVE
    trend_p = sub.add_parser(
        "trend", help="Show historical bucket / CVSS / EPSS trend for one CVE."
    )
    trend_p.add_argument("cve_id", type=_validate_cve_id, metavar="CVE-ID")
    trend_p.add_argument(
        "--no-cache",
        action="store_true",
        help="Use an in-memory cache (yields no history, mostly useful for tests).",
    )
    trend_p.add_argument("--quiet", action="store_true")
    trend_p.add_argument("--verbose", action="store_true")

    # audit subcommand: tail the append-only audit log
    audit_p = sub.add_parser(
        "audit",
        help="Show the tail of the append-only audit log of past ramen_cve commands.",
    )
    audit_p.add_argument(
        "--tail", type=int, default=20,
        help="How many of the most recent entries to print (default 20).",
    )
    audit_p.add_argument(
        "--no-cache", action="store_true",
        help="Read the in-memory audit log only (always empty; useful for tests).",
    )
    audit_p.add_argument("--quiet", action="store_true")
    audit_p.add_argument("--verbose", action="store_true")

    # schedule subcommand: emit a Task Scheduler XML or a crontab line that
    # invokes this tool against a saved YAML preset on a recurring schedule.
    schedule_p = sub.add_parser(
        "schedule",
        help="Generate a Windows Task Scheduler XML or a crontab line for "
             "automated daily runs against a saved YAML preset.",
    )
    schedule_p.add_argument(
        "action",
        choices=["windows-task", "cron"],
        help=(
            "Output format: 'windows-task' writes a Task Scheduler XML (importable "
            "via `schtasks /Create /XML`); 'cron' prints a crontab line."
        ),
    )
    schedule_p.add_argument(
        "--for-config", type=str, default=None, metavar="NAME",
        help="Saved YAML preset name (or YAML file path) the scheduled run "
             "should load. The generated command will include --config NAME.",
    )
    schedule_p.add_argument(
        "--time", type=str, default="06:15", metavar="HH:MM",
        help="Wall-clock daily run time in 24-hour HH:MM (default 06:15).",
    )
    schedule_p.add_argument(
        "--task-name", type=str, default="ramen-cve-daily", metavar="NAME",
        help="Task Scheduler task name (Windows only; ignored for cron).",
    )
    schedule_p.add_argument(
        "--python", type=str, default=None, metavar="PATH",
        help="Python interpreter path to embed in the schedule. "
             "Defaults to sys.executable.",
    )
    schedule_p.add_argument(
        "--output", type=_path_arg, default=None, metavar="FILE",
        help="Write the generated XML / crontab line to this file instead "
             "of stdout.",
    )
    schedule_p.add_argument("--quiet", action="store_true")
    schedule_p.add_argument("--verbose", action="store_true")

    # stix subcommand: ingest a STIX 2.1 bundle from disk or via TAXII 2.1
    stix_p = sub.add_parser("stix", help="Ingest a STIX 2.1 bundle (file or TAXII).")
    stix_p.add_argument("path", nargs="?", type=_path_arg, help="Path to a STIX bundle JSON file.")
    stix_p.add_argument("--taxii-url", help="TAXII 2.1 API root URL.")
    stix_p.add_argument("--taxii-collection", help="TAXII 2.1 collection ID.")
    stix_p.add_argument("--taxii-user", help="Optional TAXII basic-auth username.")
    stix_p.add_argument("--taxii-pass", help="Optional TAXII basic-auth password.")
    _shared_flags(stix_p)

    return parser


def _configure_logging(args: argparse.Namespace) -> None:
    """Set log level from --quiet / --verbose flags.

    The hunt subcommand doesn't share the analysis flags, so we read them
    defensively via getattr so logging works for every subcommand.
    """
    if getattr(args, "quiet", False):
        level = logging.WARNING
    elif getattr(args, "verbose", False):
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s %(message)s")


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Cross-field validation that argparse can't express natively."""
    if args.start is not None and args.end is not None and args.start > args.end:
        parser.error(f"--start ({args.start}) must not be later than --end ({args.end}).")
    if args.date_mode == "epss":
        if args.start is None or args.end is None:
            parser.error(
                "--date-mode epss requires both --start and --end (set to the same date "
                "for the EPSS snapshot you want)."
            )
        if args.start != args.end:
            parser.error("--date-mode epss requires --start and --end to be the same date.")


def _run_wizard() -> list[str]:
    """Interactively collect every CLI flag and return an argv list.

    Activated when ramen_cve is invoked with no arguments. Uses questionary
    for menus, text prompts, and confirmations. Returns an argv list shaped
    exactly like what the user could have typed, then main() re-parses it
    so all the normal argparse validation still applies.
    """
    import questionary

    print("Ramen CVE — interactive wizard\n", file=sys.stderr)

    mode = questionary.select(
        "What would you like to triage?",
        choices=[
            questionary.Choice("OPML feed list (a file of RSS/Atom feeds)", value="opml"),
            questionary.Choice("A single URL (article, blog post, advisory)", value="url"),
            questionary.Choice("A list of CVE IDs", value="cve"),
        ],
    ).unsafe_ask()

    argv: list[str] = [mode]

    if mode == "opml":
        # Accept EITHER a single .opml file OR a directory containing one or
        # more *.opml files. The validator handles quote-stripping and ~
        # expansion so the user can paste Windows paths straight in.
        path = questionary.path(
            "Path to an OPML file or a directory containing .opml files:",
            validate=_validate_opml_input,
        ).unsafe_ask()
        argv.append(str(Path(_strip_path_quotes(path)).expanduser()))
    elif mode == "url":
        url = questionary.text(
            "URL to scan:",
            validate=lambda s: (
                True if s.startswith(("http://", "https://")) else "Must start with http:// or https://"
            ),
        ).unsafe_ask()
        argv.append(url)
    else:  # cve
        from_file = questionary.confirm(
            "Read CVE IDs from a text file? (No = type them in)", default=False
        ).unsafe_ask()
        if from_file:
            file_path = questionary.path(
                "Path to CVE list file:",
                validate=lambda p: (
                    True
                    if Path(_strip_path_quotes(p)).expanduser().is_file()
                    else "File not found."
                ),
            ).unsafe_ask()
            argv.extend(["--from-file", str(Path(_strip_path_quotes(file_path)).expanduser())])
        else:
            # Free-form list prompt. The prompt text deliberately does NOT
            # carry a literal example (e.g. "CVE-2021-44228, CVE-2021-26855")
            # — earlier UX feedback flagged that users had to backspace
            # placeholders. The expected format is documented in
            # _wizard_validate_cve_list's docstring instead.
            cves_raw = questionary.text(
                "CVE IDs (comma- or whitespace-separated):",
                validate=_wizard_validate_cve_list,
            ).unsafe_ask()
            tokens = [t for t in re.split(r"[,\s]+", cves_raw.strip()) if t]
            argv.extend(tokens)

    date_mode = questionary.select(
        "Which date should the start/end window filter on?",
        choices=[
            questionary.Choice("feed — when the feed item was published", value="feed"),
            questionary.Choice("disclosure — when NVD published the CVE", value="disclosure"),
            questionary.Choice(
                "epss — single-day EPSS snapshot (start must equal end)", value="epss"
            ),
        ],
        default="feed",
    ).unsafe_ask()
    argv.extend(["--date-mode", date_mode])

    apply_window = questionary.confirm(
        "Restrict to a date window?", default=False
    ).unsafe_ask()
    if apply_window or date_mode == "epss":
        if date_mode == "epss":
            single = questionary.text(
                "EPSS snapshot date (YYYY-MM-DD):",
                validate=_wizard_validate_date,
            ).unsafe_ask()
            argv.extend(["--start", single, "--end", single])
        else:
            start = questionary.text(
                "Start date (YYYY-MM-DD), blank to skip:",
                validate=lambda s: _wizard_validate_date(s) if s else True,
            ).unsafe_ask()
            end = questionary.text(
                "End date (YYYY-MM-DD), blank to skip:",
                validate=lambda s: _wizard_validate_date(s) if s else True,
            ).unsafe_ask()
            if start:
                argv.extend(["--start", start])
            if end:
                argv.extend(["--end", end])

    cvss = questionary.text(
        f"CVSS threshold (0.0-10.0) [{DEFAULT_CVSS_THRESHOLD}]:",
        default=str(DEFAULT_CVSS_THRESHOLD),
        validate=lambda s: _wizard_validate_float(s, 0.0, 10.0),
    ).unsafe_ask()
    argv.extend(["--cvss-threshold", cvss])

    epss = questionary.text(
        f"EPSS threshold (0.0-1.0) [{DEFAULT_EPSS_THRESHOLD}]:",
        default=str(DEFAULT_EPSS_THRESHOLD),
        validate=lambda s: _wizard_validate_float(s, 0.0, 1.0),
    ).unsafe_ask()
    argv.extend(["--epss-threshold", epss])

    basename = questionary.text(
        "Output filename stem (no extension; blank = auto timestamp):",
    ).unsafe_ask()
    basename_clean = _safe_basename(basename)
    if basename_clean:
        argv.extend(["--basename", basename_clean])

    out_dir = questionary.path(
        "Output directory (blank = current working directory):",
        only_directories=True,
    ).unsafe_ask()
    out_dir_clean = _strip_path_quotes(out_dir)
    argv.extend([
        "--out-dir",
        str(Path(out_dir_clean).expanduser()) if out_dir_clean else ".",
    ])

    fmt = questionary.select(
        "Output format:",
        choices=["both", "csv", "md"],
        default="both",
    ).unsafe_ask()
    argv.extend(["--format", fmt])

    if questionary.confirm("Skip the local SQLite cache?", default=False).unsafe_ask():
        argv.append("--no-cache")

    verbosity = questionary.select(
        "Log verbosity:",
        choices=[
            questionary.Choice("normal (INFO)", value="normal"),
            questionary.Choice("quiet (WARNING)", value="quiet"),
            questionary.Choice("verbose (DEBUG)", value="verbose"),
        ],
        default="normal",
    ).unsafe_ask()
    if verbosity == "quiet":
        argv.append("--quiet")
    elif verbosity == "verbose":
        argv.append("--verbose")

    return argv


def _wizard_validate_date(value: str) -> bool | str:
    """Questionary validator for ISO dates."""
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return "Expected YYYY-MM-DD."


def _wizard_validate_cve_list(value: str) -> bool | str:
    """Questionary validator for a free-form list of CVE IDs.

    Accepts one or more CVE IDs separated by commas and/or whitespace. Each
    token must match the CVE regex ``CVE-YYYY-NNNN`` (with a 4-7 digit
    suffix). The runtime error message does NOT echo a literal example, so
    the user never has to backspace placeholder text.

    Example shapes (for maintainers only, in this docstring):
        "CVE-2021-44228, CVE-2021-26855"
        "CVE-2021-44228 CVE-2021-26855"
        "cve-2021-44228"            (case-insensitive; normalized later)
    """
    if not value or not value.strip():
        return "Enter at least one CVE ID."
    tokens = [t for t in re.split(r"[,\s]+", value.strip()) if t]
    if not tokens:
        return "Enter at least one CVE ID."
    bad = [t for t in tokens if not CVE_REGEX.fullmatch(t.upper())]
    if bad:
        sample = ", ".join(bad[:3])
        return (
            f"Invalid CVE ID(s): {sample}. "
            "Expected CVE-YYYY-NNNN format (NNNN may be 4–7 digits)."
        )
    return True


def _wizard_validate_float(value: str, lo: float, hi: float) -> bool | str:
    """Questionary validator for floats inside a range."""
    try:
        f = float(value)
    except ValueError:
        return "Enter a number."
    if not lo <= f <= hi:
        return f"Must be between {lo} and {hi}."
    return True


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    if argv is None and len(sys.argv) <= 1:
        if _is_interactive():
            try:
                argv = _run_wizard()
            except KeyboardInterrupt:
                print("\nCancelled.", file=sys.stderr)
                return 130
        else:
            print(
                "ramen_cve: no arguments supplied and stdin is not a TTY.\n"
                "Run with --help for usage, or invoke interactively to use the wizard.",
                file=sys.stderr,
            )
            return 2

    parser = build_parser()
    args = parser.parse_args(argv)

    # --list-configs: dump every saved preset name + path and exit.
    if getattr(args, "list_configs", False):
        presets = list_yaml_presets()
        if not presets:
            print(f"(no saved presets under {DEFAULT_PRESETS_DIR})")
        else:
            for p in presets:
                print(f"{p.stem}\t{p}")
        return 0

    # --reset-config NAME: delete one preset and exit.
    if getattr(args, "reset_config", None):
        removed = delete_yaml_preset(args.reset_config)
        if removed:
            print(f"Deleted preset → {removed}")
            return 0
        print(f"error: no such preset: {args.reset_config}", file=sys.stderr)
        return 1

    # --reset-opml: forget the remembered OPML source and exit.
    if getattr(args, "reset_opml", False):
        if _reset_remembered_opml():
            print("Forgot the remembered OPML source.")
        else:
            print("No remembered OPML source to clear.")
        return 0

    # --config NAME / --config path/to.yaml: load YAML and overlay onto args
    # BEFORE _configure_logging so logging.level keys take effect.
    if getattr(args, "config", None):
        try:
            yaml_cfg = load_yaml_config(args.config)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        apply_yaml_config(args, yaml_cfg)
        # The YAML may have supplied the subcommand. If the parser couldn't
        # bind one, reparse the args namespace into the chosen subcommand
        # context now. The pragmatic shortcut: pass attributes through as-is
        # and let the existing dispatch logic below pick the runner.
        if not getattr(args, "subcommand", None):
            print(
                "error: no subcommand was provided and the config did not "
                "supply one (set `subcommand:` in the YAML).",
                file=sys.stderr,
            )
            return 1

    # Subcommand is required after --config / --list-configs handling.
    if not getattr(args, "subcommand", None):
        parser.error("a subcommand is required (or use --config / --list-configs).")

    _configure_logging(args)

    # If --save-config was passed, persist the (post-YAML-overlay) namespace
    # before running so the preset captures the actual run shape even on
    # later failure. The save happens regardless of run outcome.
    if getattr(args, "save_config", None):
        try:
            written = save_yaml_config(args.save_config, args_to_yaml_payload(args))
            _log.info("Saved YAML preset → %s", written)
        except Exception as exc:
            _log.warning("Could not save YAML preset %r: %s", args.save_config, exc)

    # The hunt subcommand is a pure local-file workflow but we still open
    # the cache so audit logging can persist. trend / pir / audit are similar
    # — all skip _validate_args (which expects analysis-specific args).
    if args.subcommand == "hunt":
        cache_path = DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "hunt", args, lambda: _run_hunt(args, cache, None))

    if args.subcommand == "pir":
        cache_path = DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "pir", args, lambda: _run_pir(args, cache, None))

    if args.subcommand == "trend":
        cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
        cache = Cache(cache_path)
        return _audit_dispatch(cache, "trend", args, lambda: _run_trend(args, cache, None))

    # The audit subcommand reads the log; it must NOT log itself (every
    # `ramen_cve audit` would otherwise grow the table it's trying to read).
    if args.subcommand == "audit":
        cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
        return _run_audit(args, Cache(cache_path), api_key=None)

    # The schedule subcommand only emits text (XML / crontab). It needs no
    # cache, no network, and no API key — but we still audit-log it so an
    # operator can see when a scheduled task was (re)generated.
    if args.subcommand == "schedule":
        cache = Cache(DEFAULT_CACHE_PATH)
        return _audit_dispatch(
            cache, "schedule", args, lambda: _run_schedule(args, cache, None)
        )

    _validate_args(args, parser)

    cache_path = ":memory:" if args.no_cache else DEFAULT_CACHE_PATH
    cache = Cache(cache_path)

    import os

    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.getenv("NVD_API_KEY") or None
    if api_key is None:
        prompted = _prompt_for_api_key(reason="missing")
        if prompted:
            api_key = prompted

    if args.subcommand == "opml":
        return _audit_dispatch(cache, "opml", args, lambda: _run_opml(args, cache, api_key))
    if args.subcommand == "url":
        return _audit_dispatch(cache, "url", args, lambda: _run_url(args, cache, api_key))
    if args.subcommand == "cve":
        return _audit_dispatch(cache, "cve", args, lambda: _run_cve(args, cache, api_key))
    if args.subcommand == "stix":
        return _audit_dispatch(cache, "stix", args, lambda: _run_stix(args, cache, api_key))
    return 1


def _maybe_enrich_iocs(args: argparse.Namespace, iocs: list[IocRecord], cache: Cache) -> None:
    """Run enrich_iocs unless --no-enrich-iocs was passed."""
    if iocs and not args.no_enrich_iocs:
        enrich_iocs(iocs, cache)


def _maybe_filter_by_sector(
    args: argparse.Namespace, enriched: list[EnrichedCve]
) -> list[EnrichedCve]:
    """Drop CVEs whose only adversary attribution targets a different sector.

    Safe-by-default policy: a CVE with NO linked_actors stays in the report
    (we can't claim it isn't relevant). A CVE with linked_actors stays only
    if at least one actor's sectors_targeted includes the chosen sector.

    A blank `args.sector` (the default) returns the list untouched.
    """
    sector = (getattr(args, "sector", None) or "").strip().lower()
    if not sector:
        return enriched
    kept: list[EnrichedCve] = []
    dropped = 0
    for rec in enriched:
        if not rec.linked_actors:
            kept.append(rec)
            continue
        if any(sector in (a.sectors_targeted or []) for a in rec.linked_actors):
            kept.append(rec)
        else:
            dropped += 1
    if dropped:
        _log.info(
            "Dropped %d CVE(s) whose only adversary attribution did not target %r.",
            dropped, sector,
        )
    return kept


def _decay_and_filter_iocs(
    args: argparse.Namespace, iocs: list[IocRecord]
) -> list[IocRecord]:
    """Stamp every IOC with its decay-weighted confidence and drop any below the floor.

    Mutates each IOC's confidence in place, then returns a (possibly shorter)
    list with sub-floor entries excluded. The floor defaults to 0.0 — without
    --ioc-confidence-floor every input survives.
    """
    apply_ioc_decay(iocs)
    floor = float(getattr(args, "ioc_confidence_floor", 0.0) or 0.0)
    before = len(iocs)
    out = filter_iocs_by_confidence(iocs, floor)
    dropped = before - len(out)
    if dropped:
        _log.info(
            "Dropped %d IOC(s) below the confidence floor (%.3f).", dropped, floor,
        )
    return out


def _resolve_associations(args: argparse.Namespace) -> dict[str, dict[str, list]]:
    """Resolve which associations file to use for this run.

    Falls back to the bundled DEFAULT_ASSOCIATIONS_PATH unless the user passed
    --associations-file. A missing file produces an empty dict + warning so the
    rest of the pipeline still runs.
    """
    return load_associations(args.associations_file)


def _maybe_dispatch(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """If --dispatch is set, push high-priority records to configured dispatchers."""
    if not getattr(args, "dispatch", False):
        return
    sent = dispatch_records(enriched)
    _log.info("Dispatch complete: %d successful posts.", sent)


def _maybe_correlate_inventory(args: argparse.Namespace, enriched: list[EnrichedCve]) -> None:
    """Load --inventory (if set) and annotate each EnrichedCve with affected_hosts.

    A missing or unreadable inventory file is logged as an error but does NOT
    abort the run — the rest of the report is still useful without correlation.
    The parsed inventory rows are stashed on args._inventory_rows so the email
    digest dispatcher can map hosts → owner email addresses later.
    """
    inv_path: Path | None = getattr(args, "inventory", None)
    if not inv_path:
        args._inventory_rows = []
        return
    try:
        inventory = load_inventory(inv_path)
    except OpmlError as exc:
        _log.error("Inventory correlation skipped: %s", exc)
        args._inventory_rows = []
        return
    correlate_inventory(enriched, inventory)
    affected = sum(1 for r in enriched if r.affected_hosts)
    _log.info(
        "Inventory correlation: %d/%d CVEs affect at least one host (%d inventory rows).",
        affected, len(enriched), len(inventory),
    )
    args._inventory_rows = inventory


def _get_github_token() -> str | None:
    """Return GITHUB_TOKEN from the environment, or None if absent.

    The token is only used to lift GitHub Search rate limits when
    enrich_with_exploit_status is enabled. We never log it and never persist it.
    """
    import os

    token = os.getenv("GITHUB_TOKEN") or None
    return token


# Output-format file extensions that _safe_basename strips off a user-supplied
# basename so we don't end up with `my-report.csv.csv`. Edit here when adding
# new --format choices.
_KNOWN_OUTPUT_EXTENSIONS: tuple[str, ...] = (
    ".csv", ".md", ".json", ".yar", ".yaml", ".yml",
)


def _safe_basename(value: str | None) -> str:
    """Sanitize a user-supplied basename for use as an output-file stem.

    Steps applied in order:
      1. Strip surrounding whitespace.
      2. Replace path / glob / shell-meta characters ( \\ / : * ? " < > | )
         with ``_``.
      3. Strip leading dot / dash / underscore runs so traversal artefacts
         (``../etc/passwd``) and hidden-file shapes (``.cache``) collapse
         to a clean stem.
      4. Strip one trailing recognized output extension (``.csv``, ``.md``,
         ``.json``, ``.yar``, ``.yaml``, ``.yml``). The writer re-appends
         the correct extension based on the actual format being written,
         so a user pasting ``my-report.csv`` ends up with one ``.csv``,
         not two.

    Empty input returns ``''`` (the caller falls back to a timestamped stem).
    """
    if not value:
        return ""
    cleaned = re.sub(r"[\\/:*?\"<>|]+", "_", value.strip())
    cleaned = cleaned.lstrip(". -_")
    # Strip ONE known output extension if present (case-insensitive).
    lower = cleaned.lower()
    for ext in _KNOWN_OUTPUT_EXTENSIONS:
        if lower.endswith(ext):
            cleaned = cleaned[: -len(ext)]
            break
    return cleaned or ""


def _unique_output_path(
    out_dir: Path, ts: str, suffix: str, basename: str | None = None
) -> Path:
    """Return a path that does not yet exist by appending -N if needed.

    If `basename` is provided it becomes the file stem (e.g. 'q2-triage.csv').
    Otherwise we fall back to the timestamped 'ramen-cve-<ts>.<suffix>' shape.
    Two runs that land on the same stem must not silently overwrite each other:
    we probe -1, -2, ... up to 1000 and return the first free name.
    """
    stem = _safe_basename(basename) or f"ramen-cve-{ts}"
    base = out_dir / f"{stem}.{suffix}"
    if not base.exists():
        return base
    for i in range(1, 1000):
        candidate = out_dir / f"{stem}-{i}.{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not allocate a unique output filename in {out_dir}")


def _output(
    enriched: list[EnrichedCve],
    args: argparse.Namespace,
    metadata: dict,
    iocs: list[IocRecord] | None = None,
) -> dict[str, Path | None]:
    """Write CSV and/or Markdown output based on --format flag.

    Returns a dict mapping output kind ('csv', 'iocs_csv', 'md', 'stix',
    'sigma_dir', 'yara_dir') to the Path that was written, or None for the
    kinds that --format didn't ask for. Callers use that dict to attach the
    rendered files in downstream pushes (see _maybe_digest).

    When `iocs` is non-empty and --format includes csv, an additional
    `<basename>-iocs.csv` file is written next to the main CVE CSV. The
    Markdown report grows an Indicators of Compromise section regardless.

    TLP:RED records are stripped from the output unless --allow-tlp-red was
    passed; the count of stripped records is logged at WARNING.
    """
    # Microsecond resolution makes single-process collisions essentially
    # impossible; the -N suffix loop in _unique_output_path covers
    # cross-process collisions and any clock that lacks sub-second
    # resolution.
    ts = _utcnow().strftime("%Y%m%dT%H%M%S%f")
    # Resolve --out-dir = None / '' / '.' to the actual cwd so the on-disk
    # path is unambiguous (no leading-period surprises on Windows).
    out_dir: Path = _resolve_out_dir(getattr(args, "out_dir", None))
    out_dir.mkdir(parents=True, exist_ok=True)
    iocs = iocs or []
    basename = _safe_basename(getattr(args, "basename", None))
    sigma_stem = basename or f"ramen-cve-{ts}"

    if not getattr(args, "allow_tlp_red", False):
        before = (len(enriched), len(iocs))
        enriched = [r for r in enriched if (r.tlp or "CLEAR").upper() != "RED"]
        iocs = [i for i in iocs if (i.tlp or "CLEAR").upper() != "RED"]
        stripped_cve = before[0] - len(enriched)
        stripped_ioc = before[1] - len(iocs)
        if stripped_cve or stripped_ioc:
            _log.warning(
                "Stripped %d TLP:RED CVE record(s) and %d TLP:RED IOC record(s); "
                "pass --allow-tlp-red to include them.",
                stripped_cve,
                stripped_ioc,
            )

    paths: dict[str, Path | None] = {
        "csv": None, "iocs_csv": None, "md": None,
        "stix": None, "sigma_dir": None, "yara_dir": None,
    }

    if args.format in ("csv", "both", "all"):
        csv_path = _unique_output_path(out_dir, ts, "csv", basename=basename)
        _log.info("Writing CVE CSV report → %s", csv_path)
        write_csv(enriched, csv_path)
        print(str(csv_path))
        paths["csv"] = csv_path
        if iocs:
            # Without a basename, we want `ramen-cve-<ts>-iocs.csv`. Encoding
            # the "-iocs" tail via the suffix kwarg keeps that shape. With a
            # basename, we instead set the stem to `<basename>-iocs` and use
            # a plain ".csv" suffix so we don't end up with `*-iocs.iocs.csv`.
            if basename:
                iocs_path = _unique_output_path(
                    out_dir, ts, "csv", basename=f"{basename}-iocs"
                )
            else:
                iocs_path = _unique_output_path(out_dir, ts, "iocs.csv")
            _log.info("Writing IOC CSV report → %s", iocs_path)
            write_iocs_csv(iocs, iocs_path)
            print(str(iocs_path))
            paths["iocs_csv"] = iocs_path

    if args.format in ("md", "both", "all"):
        md_path = _unique_output_path(out_dir, ts, "md", basename=basename)
        _log.info("Writing Markdown report → %s", md_path)
        write_markdown(enriched, md_path, metadata, iocs=iocs)
        print(str(md_path))
        paths["md"] = md_path

    if args.format in ("stix", "all"):
        stix_path = _unique_output_path(out_dir, ts, "stix.json", basename=basename)
        _log.info("Writing STIX 2.1 bundle → %s", stix_path)
        write_stix(enriched, stix_path, iocs=iocs, run_metadata=metadata)
        print(str(stix_path))
        paths["stix"] = stix_path

    if args.format in ("sigma", "all"):
        sigma_dir = out_dir / f"{sigma_stem}-sigma"
        _log.info("Writing Sigma rule stubs → %s", sigma_dir)
        files = write_sigma_stubs(enriched, sigma_dir)
        if files:
            print(str(sigma_dir))
            paths["sigma_dir"] = sigma_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs in this run; no Sigma stubs written."
            )

    if args.format in ("yara", "all"):
        yara_dir = out_dir / f"{sigma_stem}-yara"
        _log.info("Writing YARA rule stubs → %s", yara_dir)
        files = write_yara_stubs(enriched, yara_dir)
        if files:
            print(str(yara_dir))
            paths["yara_dir"] = yara_dir
        else:
            _log.info(
                "No kev_override / patch_now CVEs with linked malware; "
                "no YARA stubs written."
            )
    return paths


def _run_opml(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the opml subcommand.

    `args.path` may point at:
      - a single .opml file (the historical behavior),
      - a directory containing one or more .opml files (every top-level
        *.opml is loaded and merged into a single run), or
      - nothing, in which case a previously-remembered OPML source
        (--remember-opml on an earlier run, or a YAML `remember_opml`)
        is reused.

    Bad / missing paths raise OpmlError, surfaced as a friendly stderr
    message + non-zero exit code instead of a traceback. When
    --remember-opml (or remember_opml: true in YAML) is set, the resolved
    source is persisted at the end of a successful run.
    """
    import feedparser

    opml_source: Path | None = args.path
    if opml_source is None:
        opml_source = _load_remembered_opml()
        if opml_source is None:
            _log.error(
                "No OPML path given and nothing remembered. Provide a path "
                "(file or directory of *.opml), or run once with "
                "--remember-opml so a later bare `opml` can reuse it."
            )
            return 1
        _log.info("Reusing remembered OPML source: %s", opml_source)

    try:
        opml_files = _collect_opml_files(opml_source)
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    entries: list[FeedEntry] = []
    for opml_file in opml_files:
        _log.info("Loading OPML file: %s", opml_file)
        entries.extend(parse_opml(opml_file))

    if not entries:
        _log.warning("No <outline> entries with xmlUrl found across %d OPML file(s).",
                     len(opml_files))

    records: list[CveRecord] = []
    iocs: list[IocRecord] = []
    sources: list[str] = []

    for entry in entries:
        safe_url = _safe_url_for_log(entry.url)
        _log.info("Fetching feed: %s", safe_url)
        sources.append(entry.title or entry.url)
        feed = feedparser.parse(entry.url)
        if getattr(feed, "bozo", 0):
            reason = getattr(feed, "bozo_exception", "unknown parse error")
            _log.warning("Feed %s parsed with errors: %s", safe_url, reason)
        feed_source = entry.title or entry.url
        for item in feed.entries or []:
            pub = item.get("published_parsed") or item.get("updated_parsed")
            item_date = date(*pub[:3]) if pub else date.today()
            text = " ".join(
                [
                    item.get("title", ""),
                    item.get("summary", ""),
                    item.get("content", [{}])[0].get("value", "") if item.get("content") else "",
                ]
            )
            records.extend(extract_cves(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
            ))
            iocs.extend(extract_iocs(
                text, feed_source, item_date, "feed_pub",
                tlp=entry.tlp, admiralty=entry.admiralty,
            ))

    iocs = _dedupe_iocs(iocs)

    date_mode = args.date_mode or "feed"
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"opml {opml_source}",
        "sources": sources,
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)

    # OPML persistence: only after a fully successful run, so a failed
    # fetch doesn't pin a bad source for next time.
    if getattr(args, "remember_opml", False):
        try:
            state = _save_remembered_opml(opml_source)
            _log.info("Remembered OPML source for next run → %s", state)
        except OSError as exc:
            _log.warning("Could not persist remembered OPML: %s", exc)
    return 0


def _run_url(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the url subcommand."""
    safe_url = _safe_url_for_log(args.url)
    _log.info("Fetching URL: %s", safe_url)
    try:
        resp = requests.get(args.url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        _log.error("Failed to fetch URL %s: %s", safe_url, exc)
        return 1

    text = resp.text
    pub_date = date.today()
    for pattern in [
        r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
        r'<time[^>]+datetime=["\'](\d{4}-\d{2}-\d{2})',
        r'<meta[^>]+property=["\']og:published_time["\'][^>]+content=["\'](\d{4}-\d{2}-\d{2})',
    ]:
        m = re.search(pattern, text)
        if m:
            try:
                pub_date = date.fromisoformat(m.group(1))
                break
            except ValueError:
                _log.warning(
                    "Found publication-date-like string %r in %s but could not parse it; "
                    "trying next pattern.",
                    m.group(1),
                    safe_url,
                )
                continue
    else:
        _log.warning("Could not find publication date in %s; using today.", safe_url)

    date_mode = args.date_mode or "feed"
    records = extract_cves(text, args.url, pub_date, "feed_pub")
    iocs = extract_iocs(text, args.url, pub_date, "feed_pub")
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"url {args.url}",
        "sources": [args.url],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


def _dedupe_iocs(iocs: list[IocRecord]) -> list[IocRecord]:
    """Collapse duplicates across multiple feed items into one record per (type, value).

    Keeps the earliest first_seen, OR-merges defanged_in_source, joins distinct
    sources with '; ', and propagates the worst-TLP + best-Admiralty tags so
    the merged IOC carries provenance from every feed it appeared in.
    """
    by_key: dict[tuple[str, str], IocRecord] = {}
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = IocRecord(
                ioc_type=ioc.ioc_type,
                value=ioc.value,
                source=ioc.source,
                first_seen=ioc.first_seen,
                first_seen_type=ioc.first_seen_type,
                defanged_in_source=ioc.defanged_in_source,
                tlp=ioc.tlp,
                admiralty=ioc.admiralty,
                last_seen=ioc.last_seen or ioc.first_seen,
            )
            continue
        if ioc.first_seen < existing.first_seen:
            existing.first_seen = ioc.first_seen
            existing.first_seen_type = ioc.first_seen_type
        # last_seen: maximum across all observations wins (most recent sighting
        # is the decay anchor).
        new_last = ioc.last_seen or ioc.first_seen
        if existing.last_seen is None or new_last > existing.last_seen:
            existing.last_seen = new_last
        if ioc.defanged_in_source and not existing.defanged_in_source:
            existing.defanged_in_source = True
        if ioc.source and ioc.source not in existing.source.split("; "):
            existing.source = f"{existing.source}; {ioc.source}"
        existing.tlp = _worst_tlp(existing.tlp, ioc.tlp)
        existing.admiralty = _best_admiralty(existing.admiralty, ioc.admiralty)
    return list(by_key.values())


def _run_cve(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the cve subcommand."""
    cve_ids: list[str] = list(args.cves or [])

    if args.from_file:
        try:
            file_text = args.from_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            _log.error("--from-file path does not exist: %s", args.from_file)
            return 1
        except OSError as exc:
            _log.error("Could not read --from-file %s: %s", args.from_file, exc)
            return 1
        for line in file_text.splitlines():
            line = line.strip()
            if CVE_REGEX.fullmatch(line.upper()):
                cve_ids.append(line.upper())
            elif line:
                _log.warning("Skipping invalid CVE ID from file: %s", line)

    if not cve_ids:
        # Expected shape (kept in this comment so the error message doesn't
        # echo a literal placeholder the user has to delete):
        #   `ramen_cve cve CVE-2021-44228 CVE-2021-26855 ...`
        # or a --from-file argument whose lines each match CVE-YYYY-NNNN
        # (4-7 digit suffix).
        _log.error(
            "No valid CVE IDs provided. Pass them as positional arguments "
            "or via --from-file. Each ID must match CVE-YYYY-NNNN."
        )
        return 1

    # Default for manual CVE input is "disclosure" because there is no feed date.
    # Honor an explicit --date-mode from the user without overriding it.
    date_mode = args.date_mode or "disclosure"

    today = date.today()
    records = [CveRecord(cve_id, "manual_input", today, "manual_input") for cve_id in cve_ids]
    enriched = enrich_cves(records, cache, api_key, associations=_resolve_associations(args))
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"cve {' '.join(cve_ids)}",
        "sources": ["manual_input"],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _output(enriched, args, metadata)
    return 0


def _parse_schedule_time(value: str) -> tuple[int, int]:
    """Parse an ``HH:MM`` 24-hour wall-clock string into ``(hour, minute)``.

    Raises ValueError with a clear message on bad shape so the schedule runner
    can surface it to the user.
    """
    parts = (value or "").strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).")
    try:
        h, m = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Invalid --time value: {value!r}. Expected HH:MM (24-hour).") from exc
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"--time out of range: {value!r}. HH must be 0–23 and MM 0–59.")
    return h, m


def _entry_script_path() -> Path:
    """Return the absolute path to threat_intel_hunter.py for schedule commands.

    The package may live under src/ramen_cve/, so we walk one level up from
    DEFAULT_CONFIG_DIR.parent.parent.parent to find the repo root and then
    point at the script. Falls back to a relative name if the script can't
    be located on disk — e.g. when the package was pip-installed via wheel.
    """
    candidate = DEFAULT_CONFIG_DIR.parent.parent.parent / "threat_intel_hunter.py"
    if candidate.is_file():
        return candidate.resolve()
    return Path("threat_intel_hunter.py")


def _build_schedule_command(args: argparse.Namespace) -> tuple[str, list[str]]:
    """Build the (executable, argv) pair the schedule will invoke.

    Returns the Python interpreter path and the argv list that follows. The
    script path is absolute when possible so a scheduled task launched from
    SYSTEM context can still find it. --for-config NAME injects ``--config
    <NAME>`` into the argv so the scheduled run picks up the saved preset.
    """
    python_exec = args.python or sys.executable
    script = str(_entry_script_path())
    invoke = [script]
    if args.for_config:
        invoke.extend(["--config", args.for_config])
    return python_exec, invoke


def _emit_windows_task_xml(args: argparse.Namespace) -> str:
    """Return a Task Scheduler XML payload for the requested daily run.

    The XML is the minimum the Task Scheduler 2.0 schema requires for a
    DailyTrigger + Exec action. Import via:
        schtasks /Create /TN ramen-cve-daily /XML task.xml

    Hour / minute come from --time; the StartBoundary's date portion is today
    so the trigger fires from the next occurrence onward.
    """
    from xml.sax.saxutils import escape

    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    # Task Scheduler wants the executable and the argv list separated:
    cmd = python_exec
    cmd_args = " ".join(_quote_for_task_scheduler(a) for a in invoke)
    start_boundary = f"{date.today().isoformat()}T{h:02d}:{m:02d}:00"
    working_dir = str(_entry_script_path().parent if _entry_script_path().exists() else ".")
    task_name = args.task_name or "ramen-cve-daily"

    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        f'    <URI>\\{escape(task_name)}</URI>\n'
        '    <Author>ramen-cve</Author>\n'
        '    <Description>Daily CVE triage via threat_intel_hunter.py.</Description>\n'
        '  </RegistrationInfo>\n'
        '  <Triggers>\n'
        '    <CalendarTrigger>\n'
        f'      <StartBoundary>{start_boundary}</StartBoundary>\n'
        '      <Enabled>true</Enabled>\n'
        '      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\n'
        '    </CalendarTrigger>\n'
        '  </Triggers>\n'
        '  <Principals>\n'
        '    <Principal id="Author">\n'
        '      <LogonType>InteractiveToken</LogonType>\n'
        '      <RunLevel>LeastPrivilege</RunLevel>\n'
        '    </Principal>\n'
        '  </Principals>\n'
        '  <Settings>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        '    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n'
        '    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n'
        '    <AllowHardTerminate>true</AllowHardTerminate>\n'
        '    <StartWhenAvailable>true</StartWhenAvailable>\n'
        '    <Enabled>true</Enabled>\n'
        '    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n'
        '  </Settings>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        f'      <Command>{escape(cmd)}</Command>\n'
        f'      <Arguments>{escape(cmd_args)}</Arguments>\n'
        f'      <WorkingDirectory>{escape(working_dir)}</WorkingDirectory>\n'
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>\n'
    )


def _quote_for_task_scheduler(value: str) -> str:
    """Quote one argv element for embedding in the Task Scheduler <Arguments>
    block. Wraps the value in double quotes if it contains whitespace or
    quote characters; leaves clean tokens untouched."""
    if not value:
        return '""'
    needs_quotes = any(c in value for c in (" ", "\t", "\"", "'"))
    if not needs_quotes:
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _emit_cron_line(args: argparse.Namespace) -> str:
    """Return a single crontab line that runs the tool daily at --time."""
    h, m = _parse_schedule_time(args.time)
    python_exec, invoke = _build_schedule_command(args)
    cmd_str = " ".join([python_exec, *invoke])
    return f"{m} {h} * * * {cmd_str}\n"


def _run_schedule(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the schedule subcommand: emit XML or a crontab line."""
    try:
        if args.action == "windows-task":
            payload = _emit_windows_task_xml(args)
        else:  # cron
            payload = _emit_cron_line(args)
    except ValueError as exc:
        _log.error(str(exc))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        _log.info("Wrote %s schedule → %s", args.action, args.output)
    else:
        sys.stdout.write(payload)
    return 0


def _run_stix(args: argparse.Namespace, cache: Cache, api_key: str | None) -> int:
    """Execute the stix subcommand (file or TAXII source).

    The user supplies EITHER `path` or both `--taxii-url` and `--taxii-collection`.
    Combining the two is rejected so the source is unambiguous.
    """
    has_file = bool(args.path)
    has_taxii = bool(args.taxii_url and args.taxii_collection)
    if not (has_file or has_taxii):
        _log.error(
            "stix: provide a bundle path OR both --taxii-url and --taxii-collection."
        )
        return 1
    if has_file and has_taxii:
        _log.error("stix: --taxii-url is mutually exclusive with a bundle path.")
        return 1

    try:
        if has_file:
            cve_records, iocs = parse_stix_bundle(args.path)
            source_label = str(args.path)
        else:
            cve_records, iocs = pull_taxii(
                args.taxii_url,
                args.taxii_collection,
                username=args.taxii_user,
                password=args.taxii_pass,
            )
            source_label = f"taxii:{args.taxii_url}/{args.taxii_collection}"
    except OpmlError as exc:
        _log.error(str(exc))
        return 1

    if not cve_records and not iocs:
        _log.warning("STIX source produced no CVEs or IOCs.")

    date_mode = args.date_mode or "disclosure"
    enriched = enrich_cves(cve_records, cache, api_key)
    if not args.no_exploit_lookup:
        enrich_with_exploit_status(enriched, cache, _get_github_token())
    _maybe_correlate_inventory(args, enriched)
    enriched = bucket_and_suggest(enriched, args.cvss_threshold, args.epss_threshold)
    _record_runs(cache, enriched)
    if args.start or args.end:
        enriched = filter_by_date(enriched, args.start, args.end, date_mode)

    metadata = {
        "version": VERSION,
        "args": f"stix {source_label}",
        "sources": [source_label],
        "start": str(args.start) if args.start else None,
        "end": str(args.end) if args.end else None,
        "date_mode": date_mode,
        "cvss_threshold": args.cvss_threshold,
        "epss_threshold": args.epss_threshold,
    }
    _maybe_enrich_iocs(args, iocs, cache)
    iocs = _decay_and_filter_iocs(args, iocs)
    enriched = _maybe_filter_by_sector(args, enriched)
    output_paths = _output(enriched, args, metadata, iocs=iocs)
    _maybe_digest(args, enriched, output_paths)
    _maybe_dispatch(args, enriched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
