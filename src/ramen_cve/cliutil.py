"""ramen_cve.cliutil — argparse type/validator helpers: ISO date,
CVE id, path de-quoting, opml-input validation (Layer-4 leaf, no
logging). See README.md and src/ramen_cve/__init__.py."""
from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from .constants import CVE_REGEX
from .models import OpmlError


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


def _validate_http_url(value: str) -> str:
    """Argparse type: accept only `http://` or `https://` URLs.

    Closes a CLI-side SSRF / scheme-confusion gap where a `url`-mode invocation
    could otherwise hand `file://`, `gopher://`, etc. to `requests.get`. The
    wizard already enforces the same rule (`wizard.py`); this is the
    direct-argv path's matching guard.
    """
    from urllib.parse import urlparse

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid URL. Expected scheme http:// or https://."
        )
    return value


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
# --format multi-select spec
# ---------------------------------------------------------------------------

#: Concrete output formats in canonical writer order — combos normalise to
#: this order, matching the writer blocks in pipeline._output.
FORMAT_TOKENS: tuple[str, ...] = ("csv", "md", "stix", "sigma", "yara", "html")

#: Legacy single-choice aliases, accepted anywhere a concrete token is.
_FORMAT_ALIASES: dict[str, tuple[str, ...]] = {
    "both": ("csv", "md"),
    "all": FORMAT_TOKENS,
}


def _expand_format_spec(spec: str | None) -> set[str]:
    """Expand a --format spec string into its concrete token set.

    Accepts a single token (``csv``), an alias (``both`` / ``all``), or a
    comma-separated combination (``csv,html``), case-insensitively. Unknown
    tokens are silently dropped *here* — boundary validation happens in
    :func:`_format_spec` at parse time, so a stale value arriving from a
    hand-edited YAML preset degrades to "that writer is skipped" instead of
    crashing a saved scheduled run.
    """
    out: set[str] = set()
    for raw in (spec or "").split(","):
        token = raw.strip().lower()
        if token in _FORMAT_ALIASES:
            out.update(_FORMAT_ALIASES[token])
        elif token in FORMAT_TOKENS:
            out.add(token)
    return out


def _normalize_format_spec(tokens: set[str]) -> str:
    """Collapse a concrete token set to its canonical spec string.

    The full set collapses to ``all`` and exactly ``{csv, md}`` to ``both``,
    so wizard-built argv and saved presets keep the familiar legacy
    spellings; any other combination joins in FORMAT_TOKENS order
    (``csv,html``).
    """
    if tokens == set(FORMAT_TOKENS):
        return "all"
    if tokens == {"csv", "md"}:
        return "both"
    return ",".join(t for t in FORMAT_TOKENS if t in tokens)


def _format_spec(value: str) -> str:
    """Argparse type for --format: validate every token, return canonical spec.

    Single values round-trip unchanged (``csv`` → ``csv``, ``both`` →
    ``both``, ``all`` → ``all``) so existing presets, scripts, and docs keep
    their exact spelling; combinations are deduped and normalised
    (``html,csv`` → ``csv,html``, ``csv,md`` → ``both``, ``all,csv`` →
    ``all``).
    """
    parts = [p.strip().lower() for p in (value or "").split(",")]
    parts = [p for p in parts if p]
    if not parts:
        raise argparse.ArgumentTypeError("expected at least one output format")
    known = set(FORMAT_TOKENS) | set(_FORMAT_ALIASES)
    bad = sorted({p for p in parts if p not in known})
    if bad:
        raise argparse.ArgumentTypeError(
            f"unknown format(s): {', '.join(bad)} "
            f"(valid: {', '.join(FORMAT_TOKENS)}; aliases: both = csv,md, "
            "all = everything; combine with commas, e.g. csv,html)"
        )
    if len(parts) == 1:
        return parts[0]
    return _normalize_format_spec(_expand_format_spec(value))


def _format_includes(spec: str | None, kind: str) -> bool:
    """True when --format spec ``spec`` selects the concrete format ``kind``.

    Replaces the old ``args.format in ("csv", "both", "all")`` membership
    checks; understands aliases and comma-separated combinations.
    """
    return kind in _expand_format_spec(spec)


# ---------------------------------------------------------------------------
# YAML configuration system
# ---------------------------------------------------------------------------
#
# Saved configurations live as YAML files under DEFAULT_PRESETS_DIR. The
# documented template at DEFAULT_CONFIG_TEMPLATE shows every key the tool
# understands. CLI args ALWAYS win over YAML values — the YAML only fills
# the gaps. See src/ramen_cve/config/config.yaml for the full schema.
# ---------------------------------------------------------------------------

