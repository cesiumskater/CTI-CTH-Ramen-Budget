# Roadmap

> **Scope.** The forward-looking shape of the project. For *what's
> shipped*, see [`README.md`](../README.md); for *what changed when*, see
> [`CHANGELOG.md`](../CHANGELOG.md); for the operational picking surface,
> see [`tasks/todo.md`](../tasks/todo.md).

The roadmap below preserves the project's "ramen budget" ethos: small,
auditable, CLI-first, zero-cost, five-runtime-dependency core. Anything
heavier ships as an **optional extra** or as a community-maintained
**plugin**, never as a core dependency.

---

## v0.x → v1.0 — production-grade for individuals and small teams

Status: **on the path.** v0.2.0 shipped the working core; the path to v1.0
is polish + community readiness, not new capabilities.

- [x] Single-source-of-truth README with accurate, byte-verified facts.
- [x] Bucket-transition delta alerting (`--dispatch-on-delta-only`).
- [x] CSV formula-injection neutralisation.
- [x] Multi-select `--format` (combos + wizard checkbox).
- [x] `cli.VERSION` / `pyproject` regression-locked.
- [ ] Governance file set complete (CONTRIBUTING, CoC, SECURITY,
      CHANGELOG, CODEOWNERS, issue/PR templates, dependabot, ROADMAP) —
      **this PR.**
- [ ] CI matrix: Python 3.10 / 3.11 / 3.12, advisory mypy + pip-audit.
- [ ] Release automation: tag → sdist + wheel + draft GitHub Release;
      PyPI publish via trusted publishing once the project is claimed.
- [ ] `docs/whitepaper.md` gets Mermaid architecture diagrams + an
      "Analyst Guide to CTI on a Ramen Budget" section.
- [ ] Docker image + docker-compose for one-command deployment.
- [ ] First-class JSON structured logging for SIEM ingestion.

**Target:** Q3 2026. Acceptance bar: the full DoD gate, a docs polish
pass, and a 30-day beta on the cesiumskater feeds.

---

## v1.1 — community-led iteration

What gets prioritised here is whatever the community files most often and
ranks highest in
[`docs/cti-capability-gap-analysis-v2.md`](cti-capability-gap-analysis-v2.md).
The current pick order, ranked by impact-to-effort:

1. ~~**SSVC decision tree**~~ (CISA/CMU) — shipped as `--ssvc-profile`;
   Deployer-tree scoring runs alongside the existing buckets and emits
   `ssvc_action` + four decision points in CSV + Markdown.
2. ~~**Risk-weighted prioritization**~~ — shipped. `--inventory` accepts
   an optional `criticality` column; `risk_score` is always populated
   (degrades gracefully without inventory data) and re-ranks CVEs within
   each bucket in the Markdown report.
3. **Native SIEM query generation** (KQL / SPL / Elastic EQL) beside the
   Sigma stubs.
4. ~~**MITRE ATT&CK Navigator export**~~ — shipped as `--format
   navigator`; drop the emitted `*.attack-layer.json` into the public
   Navigator and CVE-touched techniques light up the matrix.
5. **Plugin system** — entry-point–discovered parsers, enrichers, output
   writers, and dispatchers. The right shape for community contribution
   to grow without bloating the core. An example plugin under
   `examples/plugins/` is part of the deliverable.
6. **Community-curated feed bundle** — `examples/community-feeds.opml`
   with a CI validator that checks each feed parses + responds.

---

## v2.0 — commercial-tier capability, free and CLI-first

These are the levers that close the perceived gap to mid-tier commercial
TIPs (Recorded Future / Anomali / OpenCTI) for the workflows a single
analyst or small team actually run. All deliberately additive to the
working core; the "ramen budget" stays the headline.

- **MISP-native push / pull** via the optional `pymisp` extra. Different
  shape from generic STIX — MISP consumers want events with Galaxy tags.
- **Vulnerability-scanner imports** (Nessus / Qualys / Rapid7 native) —
  `import` subcommand into the existing inventory shape.
- **Hunt analytics library** — per-ATT&CK-technique query templates;
  `analytic suggest <hunt-id>` surfaces those whose techniques overlap.
- **Backtesting / replay mode** — `replay --as-of YYYY-MM-DD` reads
  cache only, re-runs the pipeline, diff-tables against the historical
  `runs` table for that date.
- **Optional API mode** — a thin FastAPI surface as an `[api]` extra, so
  other tools can integrate ramen-cve without spawning a CLI per request.
  Token-auth only; no multi-tenant.
- **Configurable cache backend** — current SQLite stays the default; an
  optional Redis backend as a `[redis]` extra for shared-host scenarios.
- **Sector / geopolitical context** weighting — surface the actor sector
  list in the Markdown cross-tab; optionally weight `risk_score` by sector
  match.
- **Anonymized intelligence sharing** — opt-in mechanism to contribute
  back to the bundled associations dataset (with explicit privacy warnings
  and TLP gating).

The mapping from each commercial capability to the right *shape* for this
project is in [`docs/cti-capability-gap-analysis-v2.md`](cti-capability-gap-analysis-v2.md).

---

## Non-goals

These will not be added, regardless of demand:

- **JavaScript-heavy UI.** The static Web UI is zero-JS by contract; a
  full SPA would break determinism, accessibility, and the budget.
- **Vendored binaries.** Pure-Python only, installable from PyPI over TLS.
- **Multi-tenant orchestration / RBAC.** Out of scope — that's where TIPs
  earn their licence cost. Optional token auth covers the integration use
  case.
- **Mandatory cloud dependency.** Everything must run on a laptop with no
  network at all (degraded but functional via `--no-cache` warm).

---

## How to contribute

| Contribution | Where to start |
| --- | --- |
| **Code** | Pick an item from this roadmap or `tasks/todo.md`; open an issue first; follow [`CONTRIBUTING.md`](../CONTRIBUTING.md). |
| **CTI data** | Correct or extend `src/ramen_cve/data/associations.json`; cite public sources only. |
| **Feeds** | Suggest entries for `examples/community-feeds.opml` — stable, HTTPS, public. |
| **Parsers** | New input formats (e.g. JSON Lines, MISP event JSON) — small, vertical PRs. |
| **Enrichers** | New free APIs that complement NVD / EPSS / KEV. Must degrade gracefully when offline. |
| **Plugins** | Build outside the repo; we'll link well-maintained ones from this roadmap once the plugin spec lands. |
| **Tests** | Edge cases, fuzz inputs, regression locks — `tests/test_smoke.py` is a good place to look for shape. |
| **Docs** | Clarity fixes, real-world cookbook entries, screenshots, translations of the README. |

All contributions follow [`CONTRIBUTING.md`](../CONTRIBUTING.md) and the
[`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md). Security issues go through
[`SECURITY.md`](../SECURITY.md) — never a public issue.
