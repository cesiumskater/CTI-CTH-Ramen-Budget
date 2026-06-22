"""Tests for the no-args interactive wizard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


def _make_questionary(answers: list):
    """Build a fake questionary module whose prompt functions return queued answers."""
    queue = list(answers)

    def _next(*_args, **_kwargs):
        prompt = MagicMock()
        prompt.unsafe_ask.return_value = queue.pop(0)
        return prompt

    fake = MagicMock()
    fake.select.side_effect = _next
    fake.text.side_effect = _next
    fake.path.side_effect = _next
    fake.confirm.side_effect = _next
    # checkbox answers are LISTS of the selected Choice values.
    fake.checkbox.side_effect = _next
    fake.Choice.side_effect = (
        lambda label, value=None, checked=False: value if value is not None else label
    )
    return fake


def _make_recording_questionary(answers: list):
    """Like _make_questionary, but records each prompt call so back-navigation
    tests can assert on the kwargs (defaults, choices) per call.

    Returns ``(fake, calls)`` where each ``calls`` entry is
    ``{"method", "args", "kwargs"}``. Choice() returns a 4-tuple
    ``("choice", label, value, checked)`` so the recorded ``choices=`` kwarg is
    inspectable (e.g. to confirm a ← back row is/ isn't offered).
    """
    queue = list(answers)
    calls: list[dict] = []

    def _make(method: str):
        def _fn(*args, **kwargs):
            calls.append({"method": method, "args": args, "kwargs": kwargs})
            prompt = MagicMock()
            prompt.unsafe_ask.return_value = queue.pop(0)
            return prompt

        return _fn

    fake = MagicMock()
    fake.select.side_effect = _make("select")
    fake.text.side_effect = _make("text")
    fake.path.side_effect = _make("path")
    fake.confirm.side_effect = _make("confirm")
    fake.checkbox.side_effect = _make("checkbox")
    fake.Choice.side_effect = (
        lambda label, value=None, checked=False: ("choice", label, value, checked)
    )
    return fake, calls


def test_wizard_opml_full_flow(tmp_path):
    """Wizard for OPML mode emits an argv list parseable by build_parser."""
    import ramen_cve

    opml = tmp_path / "feeds.opml"
    opml.write_text(
        '<?xml version="1.0"?><opml version="2.0"><body>'
        '<outline type="rss" text="Krebs" xmlUrl="https://example.com/feed"/>'
        "</body></opml>"
    )

    answers = [
        "opml",                # mode
        str(opml),             # path
        "feed",                # date_mode
        False,                 # apply_window?
        "7.0",                 # cvss
        "0.10",                # epss
        "",                    # basename (blank = auto)
        str(tmp_path),         # out_dir
        ["csv"],               # format checkbox selection
        False,                 # no-cache?
        "normal",              # verbosity
    ]
    fake_q = _make_questionary(answers)

    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    assert argv[0] == "opml"
    assert str(opml) in argv
    assert "--date-mode" in argv and argv[argv.index("--date-mode") + 1] == "feed"
    assert "--cvss-threshold" in argv
    assert "--format" in argv and argv[argv.index("--format") + 1] == "csv"
    assert "--no-cache" not in argv
    assert "--quiet" not in argv and "--verbose" not in argv

    parser = ramen_cve.build_parser()
    args = parser.parse_args(argv)
    assert args.subcommand == "opml"
    assert args.format == "csv"
    assert args.cvss_threshold == 7.0


def test_wizard_cve_inline_ids(tmp_path):
    """Wizard accepts inline CVE IDs and splits them on commas/whitespace."""
    import ramen_cve

    answers = [
        "cve",
        False,                              # from_file? no
        "CVE-2021-44228, CVE-2021-26855",   # cve list
        "feed",
        False,
        "7.0",
        "0.10",
        "",                                 # basename
        str(tmp_path),
        ["csv", "md"],                      # checkbox selection → "both"
        True,                               # no-cache? yes
        "quiet",
    ]
    fake_q = _make_questionary(answers)

    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    assert argv[0] == "cve"
    assert "CVE-2021-44228" in argv
    assert "CVE-2021-26855" in argv
    assert "--no-cache" in argv
    assert "--quiet" in argv

    args = ramen_cve.build_parser().parse_args(argv)
    assert args.cves == ["CVE-2021-44228", "CVE-2021-26855"]
    assert args.no_cache is True


def test_wizard_url_with_window():
    """URL mode + a date window produces --start and --end."""
    import ramen_cve

    answers = [
        "url",
        "https://example.com/advisory",
        "disclosure",
        True,                # apply_window
        "2024-01-01",
        "2024-12-31",
        "7.5",
        "0.20",
        "",                  # basename
        ".",
        ["md"],              # format checkbox selection
        False,
        "verbose",
    ]
    fake_q = _make_questionary(answers)

    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    args = ramen_cve.build_parser().parse_args(argv)
    assert args.subcommand == "url"
    assert args.url == "https://example.com/advisory"
    assert args.date_mode == "disclosure"
    assert str(args.start) == "2024-01-01"
    assert str(args.end) == "2024-12-31"
    assert args.format == "md"
    assert args.cvss_threshold == 7.5
    assert args.epss_threshold == 0.20


def test_wizard_epss_mode_forces_single_date():
    """EPSS date_mode always asks for one snapshot date and uses it for both --start and --end."""
    import ramen_cve

    answers = [
        "cve",
        False,
        "CVE-2021-44228",
        "epss",
        # No apply_window prompt: epss mode skips the window yes/no and asks
        # the single snapshot date directly.
        "2024-06-01",        # snapshot date
        "7.0",
        "0.10",
        "",                  # basename
        ".",
        ["csv"],             # format checkbox selection
        False,
        "normal",
    ]
    fake_q = _make_questionary(answers)

    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    args = ramen_cve.build_parser().parse_args(argv)
    assert args.date_mode == "epss"
    assert str(args.start) == "2024-06-01"
    assert str(args.end) == "2024-06-01"


def test_strip_path_quotes_handles_common_shapes():
    """ASCII, single, and curly quotes are all stripped; whitespace too."""
    import ramen_cve

    assert ramen_cve._strip_path_quotes('"C:\\Users\\me\\Downloads"') == "C:\\Users\\me\\Downloads"
    assert ramen_cve._strip_path_quotes("'/tmp/foo'") == "/tmp/foo"
    assert ramen_cve._strip_path_quotes("  /tmp/x  ") == "/tmp/x"
    assert ramen_cve._strip_path_quotes("/tmp/x") == "/tmp/x"
    # Mismatched quotes are left alone
    assert ramen_cve._strip_path_quotes('"unmatched') == '"unmatched'
    # Curly quotes (Word / Slack auto-style)
    assert ramen_cve._strip_path_quotes("“/tmp/x”") == "/tmp/x"
    # Empty / None safe
    assert ramen_cve._strip_path_quotes("") == ""
    assert ramen_cve._strip_path_quotes(None) == ""


def test_path_arg_argparse_type():
    """The argparse type returns a Path with quotes stripped."""
    import ramen_cve

    p = ramen_cve._path_arg('"/tmp/output"')
    assert isinstance(p, Path)
    assert str(p) == "/tmp/output"


def test_cli_out_dir_strips_quotes(tmp_path):
    """End-to-end: a quoted --out-dir arg parses to a Path without the quotes."""
    import ramen_cve

    quoted = f'"{tmp_path}"'
    args = ramen_cve.build_parser().parse_args([
        "cve", "CVE-2021-44228",
        "--out-dir", quoted,
        "--no-cache",
        "--format", "csv",
    ])
    assert isinstance(args.out_dir, Path)
    assert str(args.out_dir) == str(tmp_path)
    # Critically: mkdir(exist_ok=True) must work — this is the user-reported crash.
    args.out_dir.mkdir(parents=True, exist_ok=True)


def test_wizard_strips_quoted_out_dir(tmp_path):
    """Regression: wizard out_dir prompt must drop the quotes the user pasted."""
    import ramen_cve

    quoted_out = f'"{tmp_path}"'
    answers = [
        "cve",
        False,                              # from_file? no
        "CVE-2021-44228",                   # cve list
        "feed",
        False,
        "7.0",
        "0.10",
        "",                                 # basename
        quoted_out,                         # OUT-DIR with literal quotes
        ["csv"],                            # format checkbox selection
        False,
        "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    args = ramen_cve.build_parser().parse_args(argv)
    assert str(args.out_dir) == str(tmp_path)


def test_wizard_validators():
    """Date and float validators return True for valid input and a string error otherwise."""
    import ramen_cve

    assert ramen_cve._wizard_validate_date("2024-01-15") is True
    assert isinstance(ramen_cve._wizard_validate_date("not-a-date"), str)

    assert ramen_cve._wizard_validate_float("7.0", 0.0, 10.0) is True
    assert ramen_cve._wizard_validate_float("11.0", 0.0, 10.0) != True  # noqa: E712
    assert isinstance(ramen_cve._wizard_validate_float("abc", 0.0, 10.0), str)


def test_main_invokes_wizard_when_no_args(tmp_path, monkeypatch):
    """main() with no argv and empty sys.argv should call _run_wizard()."""
    import ramen_cve

    monkeypatch.setattr("sys.argv", ["ramen_cve.py"])
    # main() prompts for an NVD API key when none is set; pre-seed one so the
    # prompt path is skipped and the test doesn't try to read from stdin.
    monkeypatch.setenv("NVD_API_KEY", "ci-test-key")

    fake_argv = [
        "cve", "CVE-2021-44228", "--no-cache", "--format", "csv", "--out-dir", str(tmp_path)
    ]

    with (
        patch("ramen_cve.cli._is_interactive", return_value=True),
        patch("ramen_cve.cli._run_wizard", return_value=fake_argv) as wizard,
        patch("ramen_cve.cli._run_cve", return_value=0) as runner,
    ):
        rc = ramen_cve.main()

    wizard.assert_called_once()
    runner.assert_called_once()
    assert rc == 0


def test_main_skips_wizard_when_argv_provided(tmp_path):
    """Explicit argv must NOT trigger the wizard."""
    import ramen_cve

    with (
        patch("ramen_cve.cli._run_wizard") as wizard,
        patch("ramen_cve.cli._run_cve", return_value=0),
    ):
        ramen_cve.main(
            ["cve", "CVE-2021-44228", "--no-cache", "--out-dir", str(tmp_path), "--format", "csv"]
        )

    wizard.assert_not_called()


# ---------------------------------------------------------------------------
# UX fixes: empty defaults on OPML / out-dir, user-chosen basename
# ---------------------------------------------------------------------------


def test_wizard_opml_path_prompt_has_no_default(tmp_path):
    """The OPML path prompt must NOT pre-fill examples/sample.opml; the field is empty."""
    import inspect

    import ramen_cve

    src = inspect.getsource(ramen_cve._run_wizard)
    # The pre-filled default for the OPML prompt was 'examples/sample.opml'.
    # It must no longer appear as a default= kwarg on questionary.path(...).
    assert 'default="examples/sample.opml"' not in src
    assert "default='examples/sample.opml'" not in src


def test_wizard_out_dir_prompt_has_no_dot_default(tmp_path):
    """The Output-directory prompt must NOT pre-fill '.'; the field is empty."""
    import inspect

    import ramen_cve

    src = inspect.getsource(ramen_cve._run_wizard)
    # The old pre-fill was default=".". Confirm both the kwarg form and the
    # value have been removed for the out_dir prompt specifically.
    assert 'default="."' not in src
    assert "default='.'" not in src


def test_safe_basename_strips_path_separators_and_meta():
    """_safe_basename rejects / \\ : * ? \" < > | and leading dots."""
    import ramen_cve

    assert ramen_cve._safe_basename("q2-triage") == "q2-triage"
    assert ramen_cve._safe_basename("../etc/passwd") == "etc_passwd"
    assert ramen_cve._safe_basename("a/b\\c") == "a_b_c"
    assert ramen_cve._safe_basename('weird"name?') == "weird_name_"
    assert ramen_cve._safe_basename("  spaced  ") == "spaced"
    assert ramen_cve._safe_basename("") == ""
    assert ramen_cve._safe_basename(None) == ""
    # Leading dots stripped to avoid hidden files
    assert ramen_cve._safe_basename(".hidden") == "hidden"


def test_unique_output_path_honors_basename(tmp_path):
    """When a basename is supplied, it becomes the file stem (not the timestamp)."""
    import ramen_cve

    p = ramen_cve._unique_output_path(tmp_path, "20260101T000000", "csv", basename="q2-triage")
    assert p.name == "q2-triage.csv"
    # Collisions still produce -N suffixes
    p.write_text("first")
    p2 = ramen_cve._unique_output_path(tmp_path, "20260101T000000", "csv", basename="q2-triage")
    assert p2.name == "q2-triage-1.csv"


def test_unique_output_path_falls_back_to_timestamp(tmp_path):
    """Empty or missing basename falls back to ramen-cve-<ts>.<suffix>."""
    import ramen_cve

    p = ramen_cve._unique_output_path(tmp_path, "20260101T120000", "md", basename="")
    assert p.name == "ramen-cve-20260101T120000.md"
    p2 = ramen_cve._unique_output_path(tmp_path, "20260101T120000", "md")
    assert p2.name.startswith("ramen-cve-")


def test_cli_basename_flag_parses():
    """--basename is accepted on every analysis subcommand and round-trips."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args([
        "cve", "CVE-2021-44228", "--basename", "q2-triage",
    ])
    assert args.basename == "q2-triage"
    # Default is None so existing callers (no flag) keep the timestamp behavior
    args2 = ramen_cve.build_parser().parse_args(["cve", "CVE-2021-44228"])
    assert args2.basename is None


def test_wizard_basename_prompt_round_trips(tmp_path):
    """A non-empty basename answer is appended to argv as --basename <value>."""
    import ramen_cve

    answers = [
        "cve",
        False,
        "CVE-2021-44228",
        "feed",
        False,
        "7.0",
        "0.10",
        "q2-triage",          # basename — the user picks a stem
        str(tmp_path),
        ["csv"],              # format checkbox selection
        False,
        "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert "--basename" in argv
    assert argv[argv.index("--basename") + 1] == "q2-triage"
    args = ramen_cve.build_parser().parse_args(argv)
    assert args.basename == "q2-triage"


def test_wizard_blank_basename_omits_flag(tmp_path):
    """A blank basename answer must NOT emit a --basename arg (timestamp default holds)."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10",
        "",                   # basename blank
        str(tmp_path),
        ["csv"], False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert "--basename" not in argv


def test_wizard_blank_out_dir_defaults_to_cwd(tmp_path):
    """Empty out_dir answer must resolve to '.' (current working directory)."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10",
        "",                   # basename
        "",                   # OUT-DIR left blank
        ["csv"], False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert "--out-dir" in argv
    assert argv[argv.index("--out-dir") + 1] == "."


def test_wizard_html_format_round_trips(tmp_path):
    """Selecting 'html' in the wizard emits --format html and parses back."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10",
        "",                   # basename
        str(tmp_path),
        ["html"],             # format checkbox selection
        False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert "--format" in argv
    assert argv[argv.index("--format") + 1] == "html"
    args = ramen_cve.build_parser().parse_args(argv)
    assert args.format == "html"


def test_wizard_all_format_round_trips(tmp_path):
    """Selecting 'all' in the wizard emits --format all and parses back."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10",
        "",                   # basename
        str(tmp_path),
        # every concrete format ticked → normalises to "all"
        ["csv", "md", "stix", "sigma", "yara", "html", "navigator", "kql", "spl", "eql"],
        False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert argv[argv.index("--format") + 1] == "all"
    args = ramen_cve.build_parser().parse_args(argv)
    assert args.format == "all"


def test_wizard_format_prompt_is_checkbox_offering_all_concrete_formats():
    """The format prompt is a multi-select checkbox listing the six concrete
    formats, with no 'both' / 'all' pseudo-entries cluttering the list."""
    import inspect

    from ramen_cve import wizard

    src = inspect.getsource(wizard._ask_format)
    assert "q.checkbox" in src
    for token in ("csv", "md", "stix", "sigma", "yara", "html"):
        assert f'value="{token}"' in src
    # 'both' must no longer be a visible choice (it survives only as the
    # normalised spec the wizard emits when exactly csv+md are ticked).
    assert 'value="both"' not in src
    assert 'value="all"' not in src
    # csv + md start checked on a fresh ask — the historical "both" default.
    # checked=fresh means: pre-checked on first ask, nothing pre-checked when
    # the prompt is revisited after a back (hard-clear). Exactly csv + md.
    assert 'value="csv", checked=fresh' in src
    assert 'value="md", checked=fresh' in src
    assert src.count("checked=fresh") == 2


def test_wizard_format_prompt_disambiguates_checkbox_markers():
    """The checkbox prompt must signal selected vs. unselected by COLOUR.

    Regression lock for the UX iteration: the filled ● / empty ○ glyphs read
    ambiguously, and a legend that names the glyphs didn't match what
    rendered (the instruction line is one dim colour, so its circles can't
    be tinted green/red). The fix makes colour carry the signal — selected
    rows green, unselected rows red — and the legend describes the colours,
    which genuinely match the list. Mapped to questionary 2.1.1's checkbox
    token classes: class:selected (green) for checked rows, class:text +
    class:highlighted (red) for unchecked rows.
    """
    import inspect

    from ramen_cve import wizard

    src = inspect.getsource(wizard._ask_format)
    # The legend describes the colour semantics (which match the render),
    # not the glyphs (which can't be individually tinted in one style line).
    assert "green = selected" in src
    assert "red = unselected" in src
    # Legend lives in the instruction kwarg, in a distinct (dim) style.
    assert "instruction" in src
    # The Style applies BOTH colours: green for the checked rows'
    # class:selected, red for the unchecked rows' class:text.
    assert "Style" in src
    assert "ansigreen" in src
    assert "ansired" in src
    assert '("selected"' in src  # checked-row token → green
    assert '("text"' in src      # unchecked-row token → red
    # And the question text is the short, clean form — no parenthetical.
    assert '"Output formats:"' in src


# ---------------------------------------------------------------------------
# Back navigation + hard-clear (step state machine)
# ---------------------------------------------------------------------------


def test_wizard_back_via_text_sentinel_hard_clears_and_re_enters(tmp_path):
    """Typing 'select ..' at a text prompt returns to the previous question,
    which is hard-cleared and re-asked; the corrected value lands in argv and
    the abandoned value never leaks."""
    import ramen_cve

    answers = [
        "cve",                 # mode
        False,                 # from_file?
        "CVE-2021-44228",      # cve list
        "feed",                # date_mode
        False,                 # apply_window?
        "9.9",                 # cvss — first answer, to be abandoned
        "select ..",           # epss prompt → BACK to cvss
        "8.8",                 # cvss re-asked fresh — corrected
        "0.50",                # epss re-asked
        "",                    # basename
        str(tmp_path),         # out_dir
        ["csv"],               # format
        False,                 # no-cache?
        "normal",              # verbosity
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    args = ramen_cve.build_parser().parse_args(argv)
    assert args.cvss_threshold == 8.8        # corrected, not 9.9
    assert args.epss_threshold == 0.50
    assert "9.9" not in argv                 # the abandoned value is gone


def test_wizard_back_via_menu_choice_hard_clears(tmp_path):
    """Choosing the ← back row on a menu returns to the previous question and
    hard-clears it — the abandoned menu answer doesn't persist."""
    import ramen_cve
    from ramen_cve.wizard import _BACK

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10", "", str(tmp_path), ["csv"],
        True,                  # no-cache? YES — first answer, abandoned
        _BACK,                 # verbosity menu → ← back to no-cache
        False,                 # no-cache re-asked → NO
        "quiet",               # verbosity
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    args = ramen_cve.build_parser().parse_args(argv)
    assert args.no_cache is False            # re-answered No; earlier Yes gone
    assert "--no-cache" not in argv
    assert args.quiet is True


def test_wizard_back_switches_branch_cleanly(tmp_path):
    """Backing out of a branch and choosing differently re-routes the flow; the
    abandoned branch's answer never reaches argv."""
    import ramen_cve

    answers = [
        "cve",                 # mode
        True,                  # from_file? YES
        "select ..",           # file-path prompt → BACK to from_file
        False,                 # from_file re-asked → NO (switch branch)
        "CVE-2021-44228",      # the inline cve list now applies
        "feed", False,
        "7.0", "0.10", "", str(tmp_path), ["csv"], False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    assert "--from-file" not in argv         # abandoned branch is gone
    assert "CVE-2021-44228" in argv
    args = ramen_cve.build_parser().parse_args(argv)
    assert args.cves == ["CVE-2021-44228"]


def test_wizard_back_to_mode_changes_input_type(tmp_path):
    """The second prompt can back all the way to the (first) mode prompt and
    pick a different input type."""
    import ramen_cve

    answers = [
        "url",                 # mode
        "select ..",           # url prompt → BACK to mode
        "cve",                 # mode re-asked → switch to cve
        False,                 # from_file?
        "CVE-2021-44228",      # cve list
        "feed", False,
        "7.0", "0.10", "", str(tmp_path), ["csv"], False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()

    assert argv[0] == "cve"
    assert "https://" not in " ".join(argv)
    assert "CVE-2021-44228" in argv


def test_wizard_hard_clear_drops_default_on_revisit(tmp_path):
    """A prompt re-asked after a back is fresh: no `default=` is passed, so the
    user can't reflex-accept the stale value."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "9.9",            # cvss first
        "select ..",      # epss → back to cvss
        "8.8",            # cvss re-ask
        "0.10",           # epss re-ask
        "", str(tmp_path), ["csv"], False, "normal",
    ]
    fake_q, calls = _make_recording_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        ramen_cve._run_wizard()

    cvss_calls = [
        c for c in calls
        if c["method"] == "text" and c["args"] and "CVSS threshold" in c["args"][0]
    ]
    assert len(cvss_calls) == 2
    assert cvss_calls[0]["kwargs"].get("default") == "7.0"   # first ask: default
    assert "default" not in cvss_calls[1]["kwargs"]          # revisit: hard-cleared


def test_wizard_back_choice_present_except_on_first_prompt(tmp_path):
    """The ← back row is offered on every menu except the first (mode), which
    has nowhere to go back to."""
    import ramen_cve
    from ramen_cve.wizard import _BACK

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10", "", str(tmp_path), ["csv"], False, "normal",
    ]
    fake_q, calls = _make_recording_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        ramen_cve._run_wizard()

    selects = [c for c in calls if c["method"] == "select"]
    # Choice tuples are ("choice", label, value, checked); value is index 2.
    mode_choices = selects[0]["kwargs"]["choices"]
    assert selects[0]["args"][0] == "What would you like to triage?"
    assert not any(ch[2] is _BACK for ch in mode_choices)    # no back on step 1
    date_select = next(c for c in selects if "date should" in c["args"][0])
    assert any(ch[2] is _BACK for ch in date_select["kwargs"]["choices"])


def test_build_argv_pure_function():
    """_build_argv is a pure function of the answers dict; keys belonging to a
    branch the user backed out of are ignored."""
    from ramen_cve.wizard import _build_argv

    base = {
        "mode": "cve", "cve_from_file": False, "cve_list": ["CVE-2021-44228"],
        "date_mode": "feed", "apply_window": False,
        "cvss": "7.0", "epss": "0.10", "basename": "", "out_dir": "",
        "format": "both", "no_cache": False, "verbosity": "normal",
    }
    argv = _build_argv(base)
    assert argv[0] == "cve"
    assert argv[argv.index("--cvss-threshold") + 1] == "7.0"
    assert argv[argv.index("--out-dir") + 1] == "."
    assert "--no-cache" not in argv

    # Stale cve_* keys ignored when mode is url (branch switch via back).
    u = _build_argv(dict(base, mode="url", url="https://example.com/x"))
    assert u[0] == "url" and u[1] == "https://example.com/x"
    assert "CVE-2021-44228" not in u and "--from-file" not in u

    # epss date_mode emits --start == --end from the single snapshot.
    e = _build_argv(dict(base, date_mode="epss", epss_date="2024-06-01"))
    assert e[e.index("--start") + 1] == "2024-06-01"
    assert e[e.index("--end") + 1] == "2024-06-01"

    # no_cache + verbose flags.
    f = _build_argv(dict(base, no_cache=True, verbosity="verbose"))
    assert "--no-cache" in f and "--verbose" in f


# ---------------------------------------------------------------------------
# --format multi-select spec: combos, aliases, validation, wizard checkbox
# ---------------------------------------------------------------------------


def test_format_spec_combo_normalisation():
    """--format accepts comma combos; single/legacy spellings round-trip."""
    import ramen_cve

    def parse_fmt(spec: str) -> str:
        return ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", spec]
        ).format

    # Legacy single values keep their exact spelling (zero behaviour change).
    assert parse_fmt("csv") == "csv"
    assert parse_fmt("both") == "both"
    assert parse_fmt("all") == "all"
    assert parse_fmt("html") == "html"
    # Case-insensitive.
    assert parse_fmt("CSV") == "csv"
    # Combos normalise to canonical writer order, deduped.
    assert parse_fmt("csv,html") == "csv,html"
    assert parse_fmt("html,csv") == "csv,html"
    assert parse_fmt("csv, html") == "csv,html"
    assert parse_fmt("csv,csv,html") == "csv,html"
    # Combos that equal an alias collapse to the alias.
    assert parse_fmt("csv,md") == "both"
    assert parse_fmt("md,csv") == "both"
    assert parse_fmt("csv,md,stix,sigma,yara,html,navigator,kql,spl,eql") == "all"
    # Aliases union with extra tokens.
    assert parse_fmt("all,csv") == "all"
    assert parse_fmt("both,html") == "csv,md,html"


def test_format_spec_rejects_unknown_tokens(capsys):
    """An unknown format token exits with argparse's usage error (rc 2)."""
    import pytest

    import ramen_cve

    with pytest.raises(SystemExit) as exc:
        ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", "csv,bogus"]
        )
    assert exc.value.code == 2
    assert "bogus" in capsys.readouterr().err


def test_format_includes_helper():
    """_format_includes expands aliases and combos for the writer gates."""
    from ramen_cve.cliutil import _format_includes

    assert _format_includes("both", "csv") is True
    assert _format_includes("both", "md") is True
    assert _format_includes("both", "stix") is False
    assert _format_includes("all", "yara") is True
    assert _format_includes("csv,html", "html") is True
    assert _format_includes("csv,html", "md") is False
    assert _format_includes("csv", "csv") is True
    # Unknown / empty specs select nothing (fail-soft for stale YAML values).
    assert _format_includes("", "csv") is False
    assert _format_includes(None, "csv") is False
    assert _format_includes("bogus", "csv") is False


def test_wizard_multi_format_checkbox_combo(tmp_path):
    """Ticking csv + html in the wizard emits --format csv,html and parses."""
    import ramen_cve

    answers = [
        "cve", False, "CVE-2021-44228", "feed", False,
        "7.0", "0.10",
        "",                   # basename
        str(tmp_path),
        ["csv", "html"],      # checkbox: pick-and-mix combo
        False, "normal",
    ]
    fake_q = _make_questionary(answers)
    with patch.dict("sys.modules", {"questionary": fake_q}):
        argv = ramen_cve._run_wizard()
    assert argv[argv.index("--format") + 1] == "csv,html"
    args = ramen_cve.build_parser().parse_args(argv)
    assert args.format == "csv,html"


def test_output_format_combo_writes_selected_only(tmp_path):
    """End-to-end: --format csv,html writes exactly the CSV + quadrant HTML."""
    import argparse
    from datetime import date

    import ramen_cve

    rec = ramen_cve.EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
    )
    args = argparse.Namespace(
        format="csv,html",
        out_dir=tmp_path,
        basename="combo-run",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    assert (tmp_path / "combo-run.csv").exists()
    assert (tmp_path / "combo-run.html").exists()
    assert paths["csv"] is not None and paths["html"] is not None
    # Nothing else was written.
    assert paths["md"] is None
    assert paths["stix"] is None
    assert paths["sigma_dir"] is None and paths["yara_dir"] is None


def test_output_writes_html_file(tmp_path):
    """End-to-end: --format html produces a self-contained .html quadrant report."""
    import argparse
    from datetime import date

    import ramen_cve

    rec = ramen_cve.EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
    )
    args = argparse.Namespace(
        format="html",
        out_dir=tmp_path,
        basename="quadrant-run",
        allow_tlp_red=False,
    )
    paths = ramen_cve._output([rec], args, {"version": "0.1"})
    html_path = tmp_path / "quadrant-run.html"
    assert html_path.exists()
    assert paths["html"] == html_path
    body = html_path.read_text(encoding="utf-8")
    assert "<svg" in body          # inline-SVG quadrant present
    assert "CVE-2021-44228" in body
    # No CSV / Markdown written when only html was requested.
    assert paths["csv"] is None and paths["md"] is None


def test_output_honors_basename_end_to_end(tmp_path):
    """End-to-end: --basename produces <name>.csv / <name>.md / <name>-iocs.csv files."""
    from datetime import date
    from unittest.mock import patch

    import ramen_cve

    rec = ramen_cve.EnrichedCve(
        cve_id="CVE-2021-44228",
        source="x",
        first_seen=date(2024, 1, 1),
        first_seen_type="feed_pub",
        cvss_score=10.0,
        epss_score=0.97,
        bucket="kev_override",
    )
    ioc = ramen_cve.IocRecord(
        "ipv4", "8.8.8.8", "x", date(2024, 1, 1), "feed_pub",
    )
    import argparse

    args = argparse.Namespace(
        format="both",
        out_dir=tmp_path,
        basename="my-run",
        allow_tlp_red=False,
    )
    with patch("ramen_cve._maybe_dispatch"):  # not needed for this test
        ramen_cve._output([rec], args, {"version": "0.1"}, iocs=[ioc])
    assert (tmp_path / "my-run.csv").exists()
    assert (tmp_path / "my-run.md").exists()
    assert (tmp_path / "my-run-iocs.csv").exists()
