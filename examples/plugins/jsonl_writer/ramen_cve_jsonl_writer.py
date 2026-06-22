"""Example ramen-cve writer plugin — line-delimited JSON.

Demonstrates the plugin contract end-to-end:
  * One ``write_jsonl`` callable matching :data:`ramen_cve.plugins.WRITER_CONTRACT`.
  * Picks its own file extension (``.jsonl``) by ignoring the ``.out``
    suffix the host suggests.
  * Returns the actual path so the host can announce it on stdout and
    record it in the cache's ``run_artefacts`` table.
  * Stdlib only — a real-world plugin would do the same unless the
    extra dep is justified.

Install for a local trial:

    pip install -e examples/plugins/jsonl_writer
    ramen-cve cve CVE-2021-44228 --format jsonl --out-dir ./out
"""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any


def _to_json_safe(value: Any) -> Any:
    """Best-effort JSON-friendly coercion for dataclass-ish records."""
    if is_dataclass(value):
        return _to_json_safe(asdict(value))
    if isinstance(value, dict):
        return {k: _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_json_safe(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def write_jsonl(
    records: list,
    path: Path,
    *,
    run_metadata: dict | None = None,
    iocs: list | None = None,
    policy: Any | None = None,
) -> Path:
    """Write one JSON object per EnrichedCve record to ``path.jsonl``.

    The host suggests ``<out_dir>/<basename>-jsonl.out``; we rewrite the
    suffix to ``.jsonl`` so downstream tools know the shape from the
    extension alone. Each line is independently parseable by ``jq``,
    Splunk, Elastic, or `for line in open(...)` in any language.
    """
    out_path = path.with_suffix(".jsonl")
    with out_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(_to_json_safe(record), separators=(",", ":")))
            fh.write("\n")
    return out_path
