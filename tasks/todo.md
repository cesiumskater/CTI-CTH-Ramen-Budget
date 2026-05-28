# Todo

The operational ledger for ongoing and future work, paired with
[`tasks/lessons.md`](lessons.md) (failure modes captured during work).
See [`docs/CLAUDE.md`](../docs/CLAUDE.md) (Task Management + Templates)
for conventions and [`README.md`](../README.md) for the user-facing
feature inventory.

> **Status:** every task plan from the May 2026 push (Tasks 1–8:
> monolith refactor → EPSS trajectory → URL depth-1 crawl → daemon mode
> → housekeeping → showcase regen → HTML quadrant → configurable bucket
> policy → static-HTML Web UI) has shipped. The detailed slice-by-slice
> execution logs for each lived here and have been removed; the live
> implementation, PR descriptions, and `git log` are the authoritative
> record. The next-up backlog summary is below; the prioritized
> rationale lives in
> [`docs/cti-capability-gap-analysis-v2.md`](../docs/cti-capability-gap-analysis-v2.md).

---

## In progress

*(none — pick the next item from the backlog below)*

---

## Backlog (priority-ordered)

Picking order set by the project owner. The corresponding "why it
matters" + suggested implementation approach for each item lives in
[`cti-capability-gap-analysis-v2.md`](../docs/cti-capability-gap-analysis-v2.md);
this list is the operational picking surface.

1. **SSVC decision tree.** CISA/CMU SEI's formal `track / track* /
   attend / act` action tree; runs in parallel with the existing
   bucketing (additive). Modest implementation cost; produces an
   auditor-recognized output.
2. **Risk-weighted prioritization (asset criticality).** One new
   optional inventory column (`criticality: tier1/2/3`) + one weighted
   `risk_score` function. Transforms the inventory feature from
   informational to operational.
3. **Native SIEM query generation (KQL / SPL / Elastic EQL).** Extend
   `--format` to emit per-platform query stubs alongside Sigma. Higher
   implementation cost than the three above but takes the
   detection-engineering output from "useful scaffold" to "deployable."
4. **MISP-platform native push / pull** (optional `pymisp` dep gated on
   `--misp-url`). Different shape from generic STIX — MISP consumers
   want events with Galaxy tags, not raw bundles.
5. **Vulnerability-scanner imports** (Nessus / Qualys / Rapid7 native).
   `import` subcommand parsing scanner output into the existing
   inventory shape, with scanner-reported fields passed through as
   extra columns.
6. **Hunt analytics library.** `analytics/` directory of one-JSON-per
   reusable per-ATT&CK-technique query; `analytic suggest <hunt-id>`
   prints analytics whose techniques overlap the hunt.
7. **Backtesting / replay mode.** `replay --as-of YYYY-MM-DD` reads
   cache only (no network), reconstructs `EnrichedCve` from cached
   snapshots, re-runs the pipeline, and diff-tables against the
   historical `runs` table for that day. Biggest cost is a soft-
   versioning column on cache rows.

For Web UI extensions (search, filtering, `--latest-only` incremental
builds, mobile-responsive CSS, audit-log view) see the "Explicit
deferrals" section in [`docs/web_ui_design.md`](../docs/web_ui_design.md).

---

## Operational housekeeping

- `origin/claude/daemon-mode` is a known stale-but-harmless merged
  feature branch that this session's credential cannot delete (HTTP
  403). A maintainer can delete it from the GitHub UI, or enable
  Repo Settings → General → "Automatically delete head branches" so
  future merged PRs auto-clean their head ref.

---

## Templates

### Plan template — paste under "In progress" when starting a new task

- [ ] Restate goal + acceptance criteria
- [ ] Locate existing implementation / patterns
- [ ] Design: minimal approach + key decisions
- [ ] Implement smallest safe slice
- [ ] Add / adjust tests
- [ ] Run verification (lint / tests / build / manual repro)
- [ ] Summarize changes + verification story
- [ ] Record lessons (if any) in `tasks/lessons.md`

### Bugfix template — paste under "In progress" for a bug report

- Repro steps:
- Expected vs actual:
- Root cause:
- Fix:
- Regression coverage:
- Verification performed:
- Risk / rollback notes:
