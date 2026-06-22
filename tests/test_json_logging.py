"""Structured (JSON-line) logging for SIEM ingestion.

The default --log-format text keeps the historical 'LEVEL message' stderr
shape byte-identical (the byte-oracle would catch a regression in the
showcase regen's logs). The opt-in --log-format json emits one JSON
object per line with stable keys SIEMs and jq pipelines expect.
"""
from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone

from ramen_cve.cliutil import _install_logging, _JsonFormatter


def _drain(stream: io.StringIO) -> list[str]:
    """Return non-empty lines flushed to the test stream."""
    return [line for line in stream.getvalue().splitlines() if line.strip()]


def _last_record(stream: io.StringIO) -> dict:
    """Parse the most recent JSON log line emitted to the test stream."""
    lines = _drain(stream)
    assert lines, "no log lines were emitted"
    return json.loads(lines[-1])


def test_install_logging_text_format_preserves_historical_shape():
    """The text formatter must remain "%(levelname)s %(message)s" — the
    byte-oracle and the showcase regen both depend on that string."""
    stream = io.StringIO()
    _install_logging(stream, logging.INFO, "text")
    logging.getLogger("ramen_cve.test").warning("hello world")
    out = _drain(stream)
    assert out == ["WARNING hello world"]


def test_install_logging_json_emits_one_object_per_line():
    """One log call → one parseable JSON object on its own line."""
    stream = io.StringIO()
    _install_logging(stream, logging.INFO, "json")
    logging.getLogger("ramen_cve.enrich.nvd").info("fetched %d CVEs", 12)
    rec = _last_record(stream)
    assert rec["level"] == "info"
    assert rec["logger"] == "ramen_cve.enrich.nvd"
    assert rec["message"] == "fetched 12 CVEs"
    # ts is ISO-8601 UTC with millisecond precision and a 'Z' suffix.
    parsed = datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc


def test_json_formatter_captures_exceptions_in_one_field():
    """`logging.exception(...)` records must carry the traceback as a
    single `exception` string field, not break across multiple lines."""
    stream = io.StringIO()
    _install_logging(stream, logging.DEBUG, "json")
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("ramen_cve.test").exception("caught it")
    rec = _last_record(stream)
    assert rec["level"] == "error"
    assert rec["message"] == "caught it"
    assert "ValueError: boom" in rec["exception"]
    assert "Traceback" in rec["exception"]


def test_json_formatter_passes_extras_through():
    """`extra={...}` kwargs become top-level keys, with non-JSON-serialisable
    values falling back to repr() rather than crashing the pipeline."""
    stream = io.StringIO()
    _install_logging(stream, logging.INFO, "json")
    sentinel = object()
    logging.getLogger("ramen_cve.test").info(
        "with extras",
        extra={"cve_id": "CVE-2021-44228", "host": "web-1", "sentinel": sentinel},
    )
    rec = _last_record(stream)
    assert rec["cve_id"] == "CVE-2021-44228"
    assert rec["host"] == "web-1"
    # Non-JSON-serialisable extra survives as repr — the pipeline keeps flowing.
    assert "object object at" in rec["sentinel"]


def test_install_logging_is_idempotent_and_replaces_handlers():
    """Re-calling _install_logging must not duplicate handlers — the daemon
    re-invokes per iteration."""
    stream1 = io.StringIO()
    stream2 = io.StringIO()
    _install_logging(stream1, logging.INFO, "text")
    _install_logging(stream2, logging.INFO, "json")
    logging.getLogger("ramen_cve.test").info("after second install")
    # First stream must NOT receive the log (handler was replaced).
    assert stream1.getvalue() == ""
    # Second stream gets exactly one JSON line.
    assert len(_drain(stream2)) == 1


def test_format_record_is_compact_single_line_json():
    """No pretty-printing, no embedded newlines — strict line-delimited JSON
    so a downstream `tail -F | jq` pipeline parses cleanly."""
    formatter = _JsonFormatter()
    record = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="line with %s", args=("interp",), exc_info=None,
    )
    line = formatter.format(record)
    assert "\n" not in line
    assert line.startswith("{") and line.endswith("}")
    # Compact separators — no spaces after ':' or ','.
    assert '": "' not in line
    assert '", "' not in line


def test_cli_log_format_flag_parses_at_top_level():
    """`ramen-cve --log-format json opml feeds.opml` must parse without a
    leading-positional ambiguity. Top-level flag, any subcommand."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(
        ["--log-format", "json", "cve", "CVE-2021-44228"]
    )
    assert args.log_format == "json"
    assert args.subcommand == "cve"


def test_cli_log_format_default_is_none_unset():
    """A missing --log-format must surface as None so YAML config / wizard
    can supply it without colliding with the CLI default."""
    import ramen_cve

    args = ramen_cve.build_parser().parse_args(["cve", "CVE-2021-44228"])
    assert getattr(args, "log_format", "<unset>") in (None, "<unset>")


def test_cli_log_format_rejects_unknown_choice(capsys):
    """`--log-format xml` exits with argparse's choice error (rc 2)."""
    import pytest

    import ramen_cve

    with pytest.raises(SystemExit) as exc:
        ramen_cve.build_parser().parse_args(
            ["--log-format", "xml", "cve", "CVE-2021-44228"]
        )
    assert exc.value.code == 2
    assert "log-format" in capsys.readouterr().err


def test_yaml_config_logging_format_threads_to_args(tmp_path):
    """A YAML preset with logging.format: json must populate args.log_format
    when the CLI flag was not passed; the CLI flag wins when both are set."""
    import yaml

    import ramen_cve

    preset = tmp_path / "p.yaml"
    preset.write_text(yaml.safe_dump({"subcommand": "cve", "logging": {"format": "json"}}))

    # No --log-format on CLI → YAML wins.
    args = ramen_cve.build_parser().parse_args(["cve", "CVE-2021-44228"])
    ramen_cve.apply_yaml_config(args, yaml.safe_load(preset.read_text()))
    assert args.log_format == "json"

    # --log-format text on CLI → CLI wins (text is explicit, not the unset None).
    args2 = ramen_cve.build_parser().parse_args(
        ["--log-format", "text", "cve", "CVE-2021-44228"]
    )
    ramen_cve.apply_yaml_config(args2, yaml.safe_load(preset.read_text()))
    assert args2.log_format == "text"
