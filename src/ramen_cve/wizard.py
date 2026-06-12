"""ramen_cve.wizard — interactive `wizard` subcommand: questionary
prompts that build and return an argv list for main() (Layer-4).
See README.md and src/ramen_cve/__init__.py."""
from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

from .cliutil import _normalize_format_spec, _strip_path_quotes, _validate_opml_input
from .constants import CVE_REGEX, DEFAULT_CVSS_THRESHOLD, DEFAULT_EPSS_THRESHOLD
from .pipeline import _safe_basename


def _run_wizard() -> list[str]:
    """Interactively collect every CLI flag and return an argv list.

    Activated when ramen_cve is invoked with no arguments. Uses questionary
    for menus, text prompts, and confirmations. Returns an argv list shaped
    exactly like what the user could have typed, then main() re-parses it
    so all the normal argparse validation still applies.
    """
    import questionary  # deferred: keeps `patch.dict(sys.modules)` test seam

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

    # Multi-select checkbox: the user picks any combination of concrete
    # formats (space toggles, enter confirms) instead of a fixed either/or
    # list. csv + md start checked to match the historical "both" default;
    # the selection is normalised to the canonical --format spec ("both",
    # "all", or a comma combo like "csv,html") before it lands in argv.
    fmt_selected = questionary.checkbox(
        "Output formats (space toggles, enter confirms):",
        choices=[
            questionary.Choice("csv — CVE spreadsheet (+ IOC sidecar)", value="csv", checked=True),
            questionary.Choice("md — Markdown triage report", value="md", checked=True),
            questionary.Choice("stix — STIX 2.1 bundle", value="stix"),
            questionary.Choice("sigma — Sigma rule stubs", value="sigma"),
            questionary.Choice("yara — YARA rule stubs", value="yara"),
            questionary.Choice("html — CVSS x EPSS quadrant chart", value="html"),
        ],
        validate=lambda sel: True if sel else "Select at least one format (space toggles).",
    ).unsafe_ask()
    # The validator blocks an empty confirm in real questionary; the fallback
    # keeps faked/odd prompt backends safe by restoring the default pair.
    argv.extend(["--format", _normalize_format_spec(set(fmt_selected or ("csv", "md")))])

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

