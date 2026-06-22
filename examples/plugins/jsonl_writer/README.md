# ramen-cve-jsonl-writer — example writer plugin

Demonstrates the [ramen-cve plugin contract](../../../src/ramen_cve/plugins.py)
end-to-end. Drop-in line-delimited JSON output: one JSON object per CVE,
one per line, jq/Splunk/Elastic-friendly.

## Install (editable, for local trial)

```bash
pip install -e examples/plugins/jsonl_writer
```

The next `ramen-cve` invocation discovers the plugin automatically.

## Use

```bash
ramen-cve cve CVE-2021-44228 --format jsonl --out-dir ./out
# → ./out/ramen-cve-<ts>-jsonl.jsonl
```

Combine with built-in formats:

```bash
ramen-cve opml feeds.opml --format csv,jsonl --out-dir ./out
```

Inspect the file with `jq`:

```bash
jq -c 'select(.bucket == "patch_now") | {cve_id, cvss_score, epss_score}' \
   out/ramen-cve-*-jsonl.jsonl
```

## How it works

`pyproject.toml` declares the entry point:

```toml
[project.entry-points."ramen_cve.writers"]
jsonl = "ramen_cve_jsonl_writer:write_jsonl"
```

The token `jsonl` becomes a valid `--format` value the moment the plugin
is installed in the same environment as ramen-cve. The function
`write_jsonl` matches the
[`WRITER_CONTRACT`](../../../src/ramen_cve/plugins.py) signature.

## Authoring your own

1. Pick a unique token name. The validator surfaces a naming collision
   with a builtin token (`csv`, `md`, `stix`, `sigma`, `yara`, `html`,
   `both`, `all`) as an argparse error — pick a different name.
2. Match `WRITER_CONTRACT`: `(records, path, *, run_metadata, iocs,
   policy) -> Path | None`.
3. Fail soft — exceptions are caught by the host and logged at WARNING,
   so a bad plugin never crashes the pipeline. **You should still
   prefer to return early than raise.**
4. Be deterministic — the byte-oracle that gates the host's main suite
   doesn't run plugins, but downstream users will compare back-to-back
   outputs. Same input → same bytes.
5. Plugins are MIT-friendly by convention. If yours isn't, the host can
   still load it — but list the license in your README so users know.

The plugin author is responsible for their plugin's tests, packaging,
and distribution. The host repo's CI does **not** load third-party
plugins.
