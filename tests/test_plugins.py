"""Plugin system: entry-point–discovered writer plugins.

The host invariants under test:
  * `--format` accepts plugin tokens after they're discovered.
  * pipeline._output dispatches to a registered plugin's callable.
  * Plugin failures are fail-soft (log + skip; never abort the pipeline).
  * Built-in token names cannot be silently shadowed by a plugin token.
  * Discovery surface (`discover_writers`, `writer_tokens`) is stable.
"""
from __future__ import annotations

import argparse
from datetime import date
from unittest.mock import patch

import pytest

import ramen_cve
from ramen_cve.plugins import (
    WRITER_ENTRY_POINT_GROUP,
    discover_writers,
    invoke_writer,
    writer_tokens,
)


def _mock_entry_point(name: str, target):
    """Build a synthetic entry-point that loads to ``target``."""
    class _EP:
        def __init__(self, ep_name, ep_target):
            self.name = ep_name
            self.group = WRITER_ENTRY_POINT_GROUP
            self._target = ep_target

        def load(self):
            return self._target

    return _EP(name, target)


def _patch_entry_points(eps):
    """Patch importlib.metadata.entry_points to return ``eps`` for our group.

    Handles both the modern (group=...) and legacy (dict-style) APIs so the
    test runs on every supported Python.
    """
    def fake(group=None):
        if group == WRITER_ENTRY_POINT_GROUP:
            return list(eps)
        return []
    return patch("ramen_cve.plugins.importlib.metadata.entry_points", side_effect=fake)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_writers_returns_empty_when_no_plugins_installed():
    """The default state ships zero writer plugins."""
    with _patch_entry_points([]):
        assert discover_writers() == {}
        assert writer_tokens() == set()


def test_discover_writers_loads_registered_plugin():
    """A plugin declared under the right group is loaded and keyed by name."""
    def fake_writer(records, path, **kwargs):  # noqa: ARG001
        return path
    ep = _mock_entry_point("jsonl", fake_writer)
    with _patch_entry_points([ep]):
        writers = discover_writers()
        assert "jsonl" in writers
        assert writers["jsonl"] is fake_writer


def test_discover_writers_swallows_load_errors(caplog):
    """A plugin that explodes during ep.load() is logged and skipped — never
    raises out of discovery."""
    class _Broken:
        name = "broken"
        group = WRITER_ENTRY_POINT_GROUP

        def load(self):
            raise RuntimeError("intentional plugin failure")

    with _patch_entry_points([_Broken()]):
        writers = discover_writers()
    assert writers == {}
    assert any("broken" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# --format validator (cliutil._format_spec) accepts plugin tokens
# ---------------------------------------------------------------------------


def test_format_spec_accepts_plugin_token_after_discovery():
    """`--format jsonl` parses once a plugin claims that token."""
    def fake_writer(records, path, **kwargs):  # noqa: ARG001
        return path
    ep = _mock_entry_point("jsonl", fake_writer)
    with _patch_entry_points([ep]):
        args = ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", "jsonl"]
        )
    assert args.format == "jsonl"


def test_format_spec_accepts_plugin_token_in_combo():
    """`--format csv,jsonl` keeps the builtin AND the plugin token; canonical
    order is builtins-first, plugins-sorted-after."""
    def fake_writer(records, path, **kwargs):  # noqa: ARG001
        return path
    ep = _mock_entry_point("jsonl", fake_writer)
    with _patch_entry_points([ep]):
        args = ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", "jsonl,csv"]
        )
    assert args.format == "csv,jsonl"


def test_format_spec_still_rejects_unknown_tokens_when_no_plugin_matches(capsys):
    """Without a matching plugin, an unknown token still errors with rc 2."""
    with _patch_entry_points([]), pytest.raises(SystemExit) as exc:
        ramen_cve.build_parser().parse_args(
            ["cve", "CVE-2021-44228", "--format", "csv,bogus"]
        )
    assert exc.value.code == 2
    assert "bogus" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# pipeline._output dispatches to a registered plugin
# ---------------------------------------------------------------------------


def test_output_invokes_plugin_writer_with_full_contract(tmp_path):
    """End-to-end: --format csv,jsonl invokes the plugin alongside the builtin,
    the plugin receives the full WRITER_CONTRACT signature, and its returned
    path is announced + recorded."""
    calls: list[dict] = []

    def fake_writer(records, path, *, run_metadata=None, iocs=None, policy=None):
        # Capture the call shape so we can assert the contract is honored.
        actual = path.with_suffix(".jsonl")
        actual.write_text(f"{len(records)} record(s)\n")
        calls.append(
            {
                "n_records": len(records),
                "metadata_version": (run_metadata or {}).get("version"),
                "iocs_kw_passed": iocs is not None,
                "policy_kw_passed": policy is None or hasattr(policy, "__class__"),
                "suggested": path,
                "returned": actual,
            }
        )
        return actual

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
        format="csv,jsonl",
        out_dir=tmp_path,
        basename="combo",
        allow_tlp_red=False,
    )
    ep = _mock_entry_point("jsonl", fake_writer)
    with _patch_entry_points([ep]):
        paths = ramen_cve._output([rec], args, {"version": "0.2.0"})

    # Built-in CSV still wrote alongside the plugin.
    assert (tmp_path / "combo.csv").exists()
    assert paths["csv"] == tmp_path / "combo.csv"
    # Plugin was called exactly once, with the full kwarg contract.
    assert len(calls) == 1
    assert calls[0]["n_records"] == 1
    assert calls[0]["metadata_version"] == "0.2.0"
    assert calls[0]["suggested"].suffix == ".out"        # host's suggestion
    assert calls[0]["returned"].suffix == ".jsonl"       # plugin's choice
    # Plugin path was recorded under a "plugin:<token>" key, distinct from
    # the built-in writer paths, so a downstream consumer can tell them
    # apart. The host suggests "<basename>-<token>.out"; the plugin chose
    # to rewrite the suffix to .jsonl.
    assert paths.get("plugin:jsonl") == tmp_path / "combo-jsonl.jsonl"


def test_output_skips_plugin_writer_that_raises(tmp_path, caplog):
    """A plugin that throws mid-write logs a warning and the pipeline keeps
    going — built-in writers still complete."""
    def broken_writer(records, path, **kwargs):  # noqa: ARG001
        raise RuntimeError("the plugin author forgot to handle empty input")

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
        format="csv,broken",
        out_dir=tmp_path,
        basename="resilient",
        allow_tlp_red=False,
    )
    ep = _mock_entry_point("broken", broken_writer)
    with _patch_entry_points([ep]):
        paths = ramen_cve._output([rec], args, {"version": "0.2.0"})

    # Built-in CSV still landed — pipeline didn't abort.
    assert (tmp_path / "resilient.csv").exists()
    assert paths.get("plugin:broken") is None
    # The failure was logged at WARNING so it's not silent.
    assert any(
        "broken" in rec.message and "RuntimeError" in rec.message
        for rec in caplog.records
    )


def test_invoke_writer_returns_none_when_plugin_returns_none(tmp_path):
    """A plugin can opt out of writing for a given run by returning None;
    invoke_writer surfaces that as None without crashing."""
    def opt_out(records, path, **kwargs):  # noqa: ARG001
        return None
    result = invoke_writer("nothing", opt_out, [], tmp_path / "x.out")
    assert result is None
