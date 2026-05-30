"""ramen_cve.config — YAML preset load/save, the flat-key⇄attr map,
value coercion, applying a config onto argparse.Namespace, and
remembered-OPML persistence (Layer-4). See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

import yaml

from .bucket_policy import BucketPolicy
from .cliutil import _parse_iso_date, _strip_path_quotes
from .constants import DEFAULT_LAST_OPML_PATH, DEFAULT_PRESETS_DIR
from .models import _utcnow


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

    # Bucket policy: read the optional `buckets:` block via
    # `BucketPolicy.from_yaml` and stamp it on `args.bucket_policy`. An
    # absent / empty block yields DEFAULT_BUCKET_POLICY by identity, so
    # callers can rely on `getattr(args, "bucket_policy", None)` always
    # being either None (no YAML loaded) or a real policy instance —
    # never a "partially merged" placeholder.
    buckets = config.get("buckets")
    if buckets is not None and not getattr(args, "bucket_policy", None):
        args.bucket_policy = BucketPolicy.from_yaml(buckets)

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

