# Changelog

All notable changes to **ramen-cve** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The single source of truth for usage / config / outputs is
[`README.md`](README.md); this file is the *what changed when*.

---

## [Unreleased]

### Added
- **Plugin system (writers).** Third-party output writers register via the
  `[project.entry-points."ramen_cve.writers"]` group; ramen-cve discovers
  them on the next run, accepts the plugin's token in `--format`
  (`--format jsonl`, `--format csv,jsonl`), and dispatches to the
  plugin's callable. Fail-soft: a broken plugin logs a WARNING and is
  skipped, never aborts the run. New `src/ramen_cve/plugins.py` (~100
  LOC, stdlib-only) exposes `discover_writers`, `writer_tokens`,
  `invoke_writer`, and the `WRITER_CONTRACT` signature constant. An
  end-to-end example plugin ships at
  `examples/plugins/jsonl_writer/` — an installable pip package whose
  README documents the authoring path.
- Docker image + `docker-compose.yml` for one-command deployment.
  Multi-stage `Dockerfile` (Python 3.12-slim, non-root user, venv
  copied across stages), runs the `ramen-cve` console script as the
  entry-point, has a `--version` healthcheck, and mounts `/data` for the
  SQLite cache + per-run output. Compose defines a one-shot `ramen-cve`
  service and an opt-in `--profile daemon` service that runs `daemon
  --log-format json` against a mounted preset. CI builds the image and
  smoke-tests it on every push (not advisory — a broken Dockerfile is a
  broken release).
- `--log-format {text,json}` top-level flag for SIEM ingestion. `text`
  (default) preserves the historical `LEVEL message` stderr shape
  byte-identically; `json` emits one JSON line per record (`ts`, `level`,
  `logger`, `message`, plus any `extra={}` keys) — Splunk / Elastic / Loki
  / jq-friendly. Wired through the YAML preset key `logging.format`. New
  `_JsonFormatter` + `_install_logging` helpers in `cliutil` (stdlib-only;
  zero new deps).
- `--version` prints `ramen-cve <VERSION>` and exits 0 — referenced by the
  bug-report template and CONTRIBUTING.
- Multi-select `--format` SPEC: comma-separated combinations of `csv`, `md`,
  `stix`, `sigma`, `yara`, `html` (e.g. `--format csv,html`). `both` and
  `all` survive as aliases, so every legacy single-value spelling round-trips
  unchanged.
- **Wizard** now uses a `questionary.checkbox` for the output-format prompt:
  space toggles, enter confirms, any combination allowed. `csv` and `md` start
  pre-checked (the historical `both` default); `stix` / `sigma` / `yara` are
  wizard-reachable for the first time. Selected rows render **green**,
  unselected rows **red**, so the selection state is unmistakable at a glance
  (the legend describes the colours rather than the easily-confused ●/○
  glyphs).
- Governance & community: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, this changelog, `docs/ROADMAP.md`, GitHub issue templates
  (bug / feature / CTI-data), pull-request template, `CODEOWNERS`,
  `dependabot.yml`.
- CI: advisory `mypy` and `pip-audit` jobs (non-blocking — the documented
  charter doesn't enforce type-strictness).
- Regression lock: `tests/test_smoke.py::test_version_constant_matches_pyproject`
  guards against `cli.VERSION` drifting from `[project] version` again.

### Fixed
- `cli.VERSION` was `"0.1"` while `pyproject [project] version` was `"0.2.0"`,
  so the Markdown footer, Web UI footer, and packaging metadata silently
  disagreed. Aligned to `0.2.0` and regenerated the showcase bundle (the
  only delta is the version string `v0.1` → `v0.2.0`).

### Changed
- `--format` argument is now parsed by a validating type (`_format_spec`)
  with a friendlier "unknown format(s)" error message.

---

## [0.2.0] — 2026-05-30

### Added
- Bucket-transition delta detection + `--dispatch-on-delta-only` mode
  (page only when a CVE moves *up*).
- Wizard offers `html` and `all` output formats interactively.
- Post-merge security hardening sweep — 5 audit findings.

### Fixed
- CSV formula-injection neutralisation across every CSV writer (CWE-1236).

### Documentation
- README rewritten as the single source of truth; stale facts corrected
  (test count, CSV column count); shipped roadmap items removed.
- Completed historical plans retired (`docs/REFACTOR_PLAN.md`,
  `docs/web_ui_design.md`); their ~45 source-docstring references redirected
  to `README.md` + `src/ramen_cve/__init__.py`.

---

## [0.1.0] — 2026-05-20

### Added
- Initial public release. Monolith → ~30-module package behind a pure
  re-export façade with a locked `__all__`.
- Inputs: OPML feeds, single-URL crawl, hand-supplied CVE lists, STIX 2.1
  bundle import, TAXII 2.x pull.
- Enrichment: NVD, EPSS, CISA KEV, Exploit-DB / Nuclei / GitHub PoC, VT /
  AbuseIPDB / OTX / MalwareBazaar IOC reputation, inventory correlation.
- Analysis frames: MITRE ATT&CK, Cyber Kill Chain, Diamond Model, TLP +
  NATO Admiralty.
- Outputs: CVE CSV, IOC CSV sidecar, Markdown report, STIX 2.1 bundle,
  Sigma / YARA stubs, inline-SVG quadrant HTML, static Web UI.
- Workflow primitives: `hunt`, `pir`, `trend`, `audit`.
- Operations: YAML preset system, native scheduler emitters (Windows Task
  Scheduler / cron), long-running `daemon` subcommand.

[Unreleased]: https://github.com/cesiumskater/cti-cth-ramen-budget/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cesiumskater/cti-cth-ramen-budget/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cesiumskater/cti-cth-ramen-budget/releases/tag/v0.1.0
