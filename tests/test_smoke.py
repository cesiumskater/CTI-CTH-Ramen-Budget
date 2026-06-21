"""End-to-end smoke test: full opml pipeline with mocked APIs."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_OPML = Path("examples/sample.opml")


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _fake_feedparser_parse(url: str) -> object:
    """Return a minimal feedparser result with one entry containing CVE mentions."""

    class FakeEntry:
        title = "Log4Shell CVE-2021-44228 and ProxyLogon CVE-2021-26855"
        summary = "Critical vulnerabilities found."
        content = []
        published_parsed = (2024, 6, 1, 0, 0, 0, 0, 0, 0)
        updated_parsed = None

        def get(self, key, default=None):
            return getattr(self, key, default)

    class FakeFeed:
        entries = [FakeEntry()]

    return FakeFeed()


def _nvd_side_effect(url, params=None, headers=None, timeout=None):
    """Return fixture NVD data keyed on the cveId param."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    cve_id = (params or {}).get("cveId", "")
    if cve_id == "CVE-2021-44228":
        mock_resp.json.return_value = _load("nvd_log4shell_v31.json")
    elif cve_id == "CVE-2021-26855":
        mock_resp.json.return_value = _load("nvd_proxylogon_v30.json")
    else:
        mock_resp.json.return_value = _load("nvd_not_found.json")
    return mock_resp


def _epss_side_effect(url, params=None, headers=None, timeout=None):
    """Return fixture EPSS data."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = _load("epss_batch.json")
    return mock_resp


def _fake_get(url, params=None, headers=None, timeout=None):
    if "epss" in url:
        return _epss_side_effect(url, params=params, headers=headers, timeout=timeout)
    return _nvd_side_effect(url, params=params, headers=headers, timeout=timeout)


def test_smoke_opml_pipeline(tmp_path):
    """Full opml pipeline against sample.opml with mocked network produces output files."""
    import ramen_cve

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", side_effect=_fake_feedparser_parse),
    ):
        exit_code = ramen_cve.main(
            [
                "opml",
                str(SAMPLE_OPML),
                "--out-dir",
                str(tmp_path),
                "--format",
                "both",
            ]
        )

    assert exit_code == 0

    csv_files = list(tmp_path.glob("ramen-cve-*.csv"))
    md_files = list(tmp_path.glob("ramen-cve-*.md"))
    assert len(csv_files) == 1, "Expected exactly one CSV output file."
    assert len(md_files) == 1, "Expected exactly one Markdown output file."

    csv_text = csv_files[0].read_text()
    assert "CVE-2021-44228" in csv_text or "CVE-2021-26855" in csv_text

    md_text = md_files[0].read_text()
    assert "# Ramen CVE Triage Report" in md_text
    # At least one bucket section should appear
    assert any(
        section in md_text
        for section in ["## KEV Override", "## Patch Now", "## Watch Closely", "## Plan and Patch"]
    )


def test_smoke_opml_handles_none_entries(tmp_path):
    """Feedparser returning entries=None must not crash _run_opml (regression for H4)."""
    import ramen_cve

    class FeedWithNoneEntries:
        bozo = 0
        entries = None

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", return_value=FeedWithNoneEntries()),
    ):
        exit_code = ramen_cve.main(
            ["opml", str(SAMPLE_OPML), "--out-dir", str(tmp_path), "--format", "csv"]
        )

    assert exit_code == 0
    csv_files = list(tmp_path.glob("ramen-cve-*.csv"))
    assert len(csv_files) == 1
    # No CVEs found because no entries were parsed; header row only.
    assert csv_files[0].read_text().count("\n") == 1


def test_smoke_opml_warns_on_bozo_feed(tmp_path, caplog):
    """A feedparser result with bozo=1 logs a WARNING but does not abort (regression for H5)."""
    import logging

    import ramen_cve

    class BozoFeed:
        bozo = 1
        bozo_exception = "mismatched tag at line 7"
        entries = []

    with (
        patch("ramen_cve.requests.get", side_effect=_fake_get),
        patch("ramen_cve.time.sleep"),
        patch("feedparser.parse", return_value=BozoFeed()),
        caplog.at_level(logging.WARNING, logger="ramen_cve"),
    ):
        exit_code = ramen_cve.main(
            ["opml", str(SAMPLE_OPML), "--out-dir", str(tmp_path), "--format", "csv"]
        )

    assert exit_code == 0
    assert any("parsed with errors" in rec.message for rec in caplog.records)


def test_version_constant_matches_pyproject():
    """cli.VERSION must stay in lockstep with [project] version in pyproject.toml.

    Regression lock: the two drifted (0.1 vs 0.2.0) until 2026-06; the report
    footer, Web UI footer, and packaging metadata silently disagreed. A regex
    read keeps this 3.10-compatible (tomllib is 3.11+).
    """
    import re
    from pathlib import Path

    from ramen_cve.cli import VERSION

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    assert match, "no [project] version found in pyproject.toml"
    assert match.group(1) == VERSION


def test_version_flag_prints_to_stdout_and_exits_zero(capsys):
    """`ramen-cve --version` is the standard "what release am I running?"
    affordance referenced in CONTRIBUTING.md and the bug-report template.
    Regression lock so a future argparse refactor can't silently drop it.
    """
    import pytest

    from ramen_cve.cli import VERSION, build_parser

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    # argparse's `action="version"` exits 0 and prints to stdout.
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert VERSION in out
    assert out.startswith("ramen-cve ")
