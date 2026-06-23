"""ramen_cve.wizard — interactive `wizard` subcommand: questionary
prompts that build and return an argv list for main() (Layer-4).
See README.md and src/ramen_cve/__init__.py.

The wizard is a small back-navigable state machine. `_run_wizard` walks an
ordered table of `_Step` records; each step asks exactly one prompt and
records its answer in a shared dict. The user can step back — by choosing a
``← back`` row on a menu, or typing ``select ..`` at a text/path prompt —
and the driver returns to the previous question. Going back HARD-CLEARS the
answer: a revisited prompt is re-asked fresh (no pre-filled default, nothing
pre-checked) so a stale value can never be accidentally re-submitted. argv
is built once at the very end from the completed answers, so back-navigation
never leaves half-built argv fragments.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any, NamedTuple

from .cliutil import _normalize_format_spec, _strip_path_quotes, _validate_opml_input
from .constants import CVE_REGEX, DEFAULT_CVSS_THRESHOLD, DEFAULT_EPSS_THRESHOLD
from .pipeline import _safe_basename

# Sentinel an ask-helper returns to tell the driver "step back one prompt".
_BACK: Any = object()
# What the user types at a text / path prompt to step back. Chosen so it can
# never collide with a real answer: it is not a valid CVSS / EPSS / date / CVE
# / basename value, and at a path prompt it is matched BEFORE any filesystem
# check (type "../" or an absolute path for the literal parent directory).
_BACK_TEXT = "select .."
_BACK_LABEL = "← back (re-enter the previous question)"
_BACK_HINT = "  (or type 'select ..' to go back)"


def _is_back_text(value: str | None) -> bool:
    """True when the user typed the back sentinel at a text / path prompt."""
    return (value or "").strip().lower() == _BACK_TEXT


# ---------------------------------------------------------------------------
# Generic, back-aware prompt helpers. Each returns the prompt's value, or the
# _BACK sentinel. `fresh` is False when a prompt is being re-asked after a
# back: defaults / pre-checks are suppressed so the user must re-enter.
# ---------------------------------------------------------------------------


def _ask_select(
    q: Any,
    message: str,
    choices: list[tuple[str, Any]],
    *,
    default: Any = None,
    allow_back: bool,
    fresh: bool,
) -> Any:
    """Single-choice menu. Appends a ``← back`` row when `allow_back`.

    Returns the chosen value, or _BACK. `default` is honoured only on a
    fresh ask (hard-clear on revisit).
    """
    opts = [q.Choice(label, value=value) for label, value in choices]
    if allow_back:
        opts.append(q.Choice(_BACK_LABEL, value=_BACK))
    kwargs: dict[str, Any] = {}
    if fresh and default is not None:
        kwargs["default"] = default
    return q.select(message, choices=opts, **kwargs).unsafe_ask()


def _ask_yesno(
    q: Any, message: str, *, default: Any = None, allow_back: bool, fresh: bool
) -> Any:
    """Yes / No rendered as a menu (so it can host a ``← back`` row).

    Returns True / False, or _BACK.
    """
    return _ask_select(
        q,
        message,
        [("Yes", True), ("No", False)],
        default=default,
        allow_back=allow_back,
        fresh=fresh,
    )


def _ask_text(
    q: Any,
    message: str,
    *,
    validate: Callable[[str], bool | str] | None = None,
    default: str | None = None,
    allow_back: bool,
    fresh: bool,
) -> Any:
    """Free-text prompt. Returns the raw string, or _BACK if the sentinel was
    typed. `default` only on a fresh ask; the validator lets the sentinel pass
    so the user can always back out of a half-typed answer."""

    def _validate(s: str) -> bool | str:
        if _is_back_text(s):
            return True
        return validate(s) if validate is not None else True

    kwargs: dict[str, Any] = {"validate": _validate}
    if fresh and default is not None:
        kwargs["default"] = default
    raw = q.text(message + (_BACK_HINT if allow_back else ""), **kwargs).unsafe_ask()
    return _BACK if _is_back_text(raw) else raw


def _ask_path(
    q: Any,
    message: str,
    *,
    validate: Callable[[str], bool | str] | None = None,
    only_directories: bool = False,
    allow_back: bool,
) -> Any:
    """Path prompt (never pre-filled — a deliberate earlier UX fix). Returns
    the raw string, or _BACK if the sentinel was typed. The sentinel is matched
    before the validator runs, so it works even at an empty/invalid path."""

    def _validate(s: str) -> bool | str:
        if _is_back_text(s):
            return True
        return validate(s) if validate is not None else True

    kwargs: dict[str, Any] = {"validate": _validate}
    if only_directories:
        kwargs["only_directories"] = True
    raw = q.path(message + (_BACK_HINT if allow_back else ""), **kwargs).unsafe_ask()
    return _BACK if _is_back_text(raw) else raw


def _ask_format(q: Any, *, allow_back: bool, fresh: bool) -> Any:
    """The output-format multi-select. Returns the canonical --format spec
    string, or _BACK (when the ``← back`` row is ticked).

    csv + md are pre-checked only on a fresh ask; on a revisit nothing is
    pre-checked (hard-clear), so a stale selection can't be re-submitted by
    reflex. Colour carries the selection signal — green selected, red
    unselected — per the questionary 2.1.1 checkbox token classes.
    """
    choices = [
        q.Choice("csv — CVE spreadsheet (+ IOC sidecar)", value="csv", checked=fresh),
        q.Choice("md — Markdown triage report", value="md", checked=fresh),
        q.Choice("stix — STIX 2.1 bundle", value="stix"),
        q.Choice("sigma — Sigma rule stubs", value="sigma"),
        q.Choice("yara — YARA rule stubs", value="yara"),
        q.Choice("html — CVSS x EPSS quadrant chart", value="html"),
        q.Choice("navigator — MITRE ATT&CK Navigator layer JSON", value="navigator"),
        q.Choice("kql — KQL query stubs (Sentinel / Defender XDR)", value="kql"),
        q.Choice("spl — Splunk SPL query stubs", value="spl"),
        q.Choice("eql — Elastic EQL query stubs", value="eql"),
    ]
    if allow_back:
        choices.append(q.Choice(_BACK_LABEL, value=_BACK))

    def _validate(sel: list[Any]) -> bool | str:
        if _BACK in sel:
            return True
        return True if sel else "Tick at least one format (space toggles), or ← back."

    kwargs: dict[str, Any] = {
        "instruction": (
            "(space toggles · enter confirms · green = selected, red = unselected)"
        ),
        "choices": choices,
        "validate": _validate,
    }
    try:
        from questionary import Style as _QStyle
        kwargs["style"] = _QStyle([
            ("selected", "fg:ansigreen bold"),      # checked rows: ● marker + label
            ("text", "fg:ansired"),                 # unchecked rows: ○ marker + label
            ("highlighted", "fg:ansired bold"),     # cursor on an unchecked row (label)
            ("pointer", "fg:ansicyan bold"),        # the cursor arrow itself (neutral)
            ("instruction", "fg:ansibrightblack"),  # the dim legend line
        ])
    except Exception:  # pragma: no cover — defensive against API drift
        pass
    selected = q.checkbox("Output formats:", **kwargs).unsafe_ask()
    if selected and _BACK in selected:
        return _BACK
    # The validator blocks an empty submit in real questionary; the fallback
    # keeps faked / odd backends safe by restoring the default pair.
    return _normalize_format_spec(set(selected or ("csv", "md")))


# ---------------------------------------------------------------------------
# Step table. Each step asks one prompt; `applies` gates the conditional
# branches (input mode, date window). An `ask` returns the value to store
# under the step id, or _BACK.
# ---------------------------------------------------------------------------


class _Step(NamedTuple):
    id: str
    applies: Callable[[dict[str, Any]], bool]
    ask: Callable[[dict[str, Any], bool, bool], Any]


def _validate_url(value: str) -> bool | str:
    """Wizard validator: require an http(s) URL (matches the CLI's guard)."""
    if value.startswith(("http://", "https://")):
        return True
    return "Must start with http:// or https://"


def _validate_cve_file(value: str) -> bool | str:
    """Wizard validator: the --from-file path must be an existing file."""
    if Path(_strip_path_quotes(value)).expanduser().is_file():
        return True
    return "File not found."


def _clean_path(raw: str) -> str:
    """De-quote + ~-expand a user-supplied path into its final string form."""
    return str(Path(_strip_path_quotes(raw)).expanduser())


def _wizard_steps(q: Any) -> list[_Step]:
    """Build the ordered, back-navigable step table bound to questionary `q`."""

    def _opml_path(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        raw = _ask_path(
            q,
            "Path to an OPML file or a directory containing .opml files:",
            validate=_validate_opml_input,
            allow_back=allow_back,
        )
        return raw if raw is _BACK else _clean_path(raw)

    def _url(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q, "URL to scan:", validate=_validate_url, allow_back=allow_back, fresh=fresh
        )

    def _cve_from_file(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_yesno(
            q,
            "Read CVE IDs from a text file? (No = type them in)",
            default=False,
            allow_back=allow_back,
            fresh=fresh,
        )

    def _cve_file_path(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        raw = _ask_path(
            q, "Path to CVE list file:", validate=_validate_cve_file, allow_back=allow_back
        )
        return raw if raw is _BACK else _clean_path(raw)

    def _cve_list(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        raw = _ask_text(
            q,
            "CVE IDs (comma- or whitespace-separated):",
            validate=_wizard_validate_cve_list,
            allow_back=allow_back,
            fresh=fresh,
        )
        if raw is _BACK:
            return _BACK
        return [t for t in re.split(r"[,\s]+", raw.strip()) if t]

    def _date_mode(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_select(
            q,
            "Which date should the start/end window filter on?",
            [
                ("feed — when the feed item was published", "feed"),
                ("disclosure — when NVD published the CVE", "disclosure"),
                ("epss — single-day EPSS snapshot (start must equal end)", "epss"),
            ],
            default="feed",
            allow_back=allow_back,
            fresh=fresh,
        )

    def _apply_window(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_yesno(
            q, "Restrict to a date window?", default=False, allow_back=allow_back, fresh=fresh
        )

    def _epss_date(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            "EPSS snapshot date (YYYY-MM-DD):",
            validate=_wizard_validate_date,
            allow_back=allow_back,
            fresh=fresh,
        )

    def _start_date(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            "Start date (YYYY-MM-DD), blank to skip:",
            validate=lambda s: _wizard_validate_date(s) if s else True,
            allow_back=allow_back,
            fresh=fresh,
        )

    def _end_date(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            "End date (YYYY-MM-DD), blank to skip:",
            validate=lambda s: _wizard_validate_date(s) if s else True,
            allow_back=allow_back,
            fresh=fresh,
        )

    def _cvss(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            f"CVSS threshold (0.0-10.0) [{DEFAULT_CVSS_THRESHOLD}]:",
            validate=lambda s: _wizard_validate_float(s, 0.0, 10.0),
            default=str(DEFAULT_CVSS_THRESHOLD),
            allow_back=allow_back,
            fresh=fresh,
        )

    def _epss(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            f"EPSS threshold (0.0-1.0) [{DEFAULT_EPSS_THRESHOLD}]:",
            validate=lambda s: _wizard_validate_float(s, 0.0, 1.0),
            default=str(DEFAULT_EPSS_THRESHOLD),
            allow_back=allow_back,
            fresh=fresh,
        )

    def _basename(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_text(
            q,
            "Output filename stem (no extension; blank = auto timestamp):",
            allow_back=allow_back,
            fresh=fresh,
        )

    def _out_dir(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        raw = _ask_path(
            q,
            "Output directory (blank = current working directory):",
            only_directories=True,
            allow_back=allow_back,
        )
        if raw is _BACK:
            return _BACK
        cleaned = _strip_path_quotes(raw)
        return str(Path(cleaned).expanduser()) if cleaned else ""

    def _format(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_format(q, allow_back=allow_back, fresh=fresh)

    def _no_cache(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_yesno(
            q, "Skip the local SQLite cache?", default=False, allow_back=allow_back, fresh=fresh
        )

    def _verbosity(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_select(
            q,
            "Log verbosity:",
            [
                ("normal (INFO)", "normal"),
                ("quiet (WARNING)", "quiet"),
                ("verbose (DEBUG)", "verbose"),
            ],
            default="normal",
            allow_back=allow_back,
            fresh=fresh,
        )

    def _mode(answers: dict[str, Any], allow_back: bool, fresh: bool) -> Any:
        return _ask_select(
            q,
            "What would you like to triage?",
            [
                ("OPML feed list (a file of RSS/Atom feeds)", "opml"),
                ("A single URL (article, blog post, advisory)", "url"),
                ("A list of CVE IDs", "cve"),
            ],
            allow_back=allow_back,
            fresh=fresh,
        )

    always = lambda a: True  # noqa: E731 — terse predicate table reads better inline
    return [
        _Step("mode", always, _mode),
        _Step("opml_path", lambda a: a.get("mode") == "opml", _opml_path),
        _Step("url", lambda a: a.get("mode") == "url", _url),
        _Step("cve_from_file", lambda a: a.get("mode") == "cve", _cve_from_file),
        _Step(
            "cve_file_path",
            lambda a: a.get("mode") == "cve" and a.get("cve_from_file") is True,
            _cve_file_path,
        ),
        _Step(
            "cve_list",
            lambda a: a.get("mode") == "cve" and a.get("cve_from_file") is False,
            _cve_list,
        ),
        _Step("date_mode", always, _date_mode),
        _Step("apply_window", lambda a: a.get("date_mode") != "epss", _apply_window),
        _Step("epss_date", lambda a: a.get("date_mode") == "epss", _epss_date),
        _Step(
            "start_date",
            lambda a: a.get("date_mode") != "epss" and a.get("apply_window") is True,
            _start_date,
        ),
        _Step(
            "end_date",
            lambda a: a.get("date_mode") != "epss" and a.get("apply_window") is True,
            _end_date,
        ),
        _Step("cvss", always, _cvss),
        _Step("epss", always, _epss),
        _Step("basename", always, _basename),
        _Step("out_dir", always, _out_dir),
        _Step("format", always, _format),
        _Step("no_cache", always, _no_cache),
        _Step("verbosity", always, _verbosity),
    ]


def _build_argv(answers: dict[str, Any]) -> list[str]:
    """Turn the collected wizard answers into an argv list parseable by main().

    Pure function of `answers` — only the keys belonging to the chosen input
    mode and date mode are read, so a branch the user backed out of (e.g. a
    stale CVE list after switching to url mode) never leaks into the argv.
    The output is byte-for-byte what the pre-state-machine wizard produced
    for the same answers.
    """
    mode = answers["mode"]
    argv: list[str] = [mode]

    if mode == "opml":
        argv.append(answers["opml_path"])
    elif mode == "url":
        argv.append(answers["url"])
    else:  # cve
        if answers.get("cve_from_file"):
            argv.extend(["--from-file", answers["cve_file_path"]])
        else:
            argv.extend(answers.get("cve_list", []))

    date_mode = answers["date_mode"]
    argv.extend(["--date-mode", date_mode])
    if date_mode == "epss":
        single = answers.get("epss_date")
        if single:
            argv.extend(["--start", single, "--end", single])
    elif answers.get("apply_window"):
        start = answers.get("start_date") or ""
        end = answers.get("end_date") or ""
        if start:
            argv.extend(["--start", start])
        if end:
            argv.extend(["--end", end])

    argv.extend(["--cvss-threshold", answers["cvss"]])
    argv.extend(["--epss-threshold", answers["epss"]])

    basename_clean = _safe_basename(answers.get("basename"))
    if basename_clean:
        argv.extend(["--basename", basename_clean])

    out_dir = answers.get("out_dir") or ""
    argv.extend(["--out-dir", out_dir if out_dir else "."])

    argv.extend(["--format", answers["format"]])

    if answers.get("no_cache"):
        argv.append("--no-cache")

    verbosity = answers.get("verbosity")
    if verbosity == "quiet":
        argv.append("--quiet")
    elif verbosity == "verbose":
        argv.append("--verbose")

    return argv


def _run_wizard() -> list[str]:
    """Interactively collect every CLI flag and return an argv list.

    Activated when ramen_cve is invoked with no arguments. Walks a
    back-navigable step table (see module docstring): choose ``← back`` on a
    menu, or type ``select ..`` at a text/path prompt, to return to the
    previous question. Going back hard-clears the answer, so a revisited
    prompt is re-asked fresh. main() re-parses the returned argv so all the
    normal argparse validation still applies.
    """
    import questionary  # deferred: keeps `patch.dict(sys.modules)` test seam

    print("Ramen CVE — interactive wizard\n", file=sys.stderr)
    print(
        "Tip: pick '← back' on a menu, or type 'select ..' at a text prompt, to "
        "return to the previous question. Going back clears that answer so you "
        "re-enter it fresh.\n",
        file=sys.stderr,
    )

    steps = _wizard_steps(questionary)
    answers: dict[str, Any] = {}
    revisited: set[str] = set()
    asked: list[int] = []  # indices of steps answered so far (the back stack)

    i = 0
    while i < len(steps):
        step = steps[i]
        if not step.applies(answers):
            i += 1
            continue
        fresh = step.id not in revisited
        result = step.ask(answers, bool(asked), fresh)
        if result is _BACK:
            # Hard clear: drop this step's answer AND the one we return to, and
            # mark both so their next ask is fresh (no default / nothing
            # pre-checked) — the user re-enters, eliminating reflex re-submits.
            answers.pop(step.id, None)
            revisited.add(step.id)
            prev_i = asked.pop()
            answers.pop(steps[prev_i].id, None)
            revisited.add(steps[prev_i].id)
            i = prev_i
            continue
        answers[step.id] = result
        asked.append(i)
        i += 1

    return _build_argv(answers)


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
