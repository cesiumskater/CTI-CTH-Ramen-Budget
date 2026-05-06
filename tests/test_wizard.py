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
    fake.Choice.side_effect = lambda label, value=None: value if value is not None else label
    return fake


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
        str(tmp_path),         # out_dir
        "csv",                 # format
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
        str(tmp_path),
        "both",
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
        ".",
        "md",
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
        # apply_window prompt SKIPPED because epss mode auto-asks for snapshot
        False,
        "2024-06-01",        # snapshot date
        "7.0",
        "0.10",
        ".",
        "csv",
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
        quoted_out,                         # OUT-DIR with literal quotes
        "csv",
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

    fake_argv = [
        "cve", "CVE-2021-44228", "--no-cache", "--format", "csv", "--out-dir", str(tmp_path)
    ]

    with (
        patch("ramen_cve._is_interactive", return_value=True),
        patch("ramen_cve._run_wizard", return_value=fake_argv) as wizard,
        patch("ramen_cve._run_cve", return_value=0) as runner,
    ):
        rc = ramen_cve.main()

    wizard.assert_called_once()
    runner.assert_called_once()
    assert rc == 0


def test_main_skips_wizard_when_argv_provided(tmp_path):
    """Explicit argv must NOT trigger the wizard."""
    import ramen_cve

    with (
        patch("ramen_cve._run_wizard") as wizard,
        patch("ramen_cve._run_cve", return_value=0),
    ):
        ramen_cve.main(
            ["cve", "CVE-2021-44228", "--no-cache", "--out-dir", str(tmp_path), "--format", "csv"]
        )

    wizard.assert_not_called()
