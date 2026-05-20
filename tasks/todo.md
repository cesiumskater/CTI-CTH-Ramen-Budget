# Todo

The operational ledger for ongoing and future work, paired with
[`tasks/lessons.md`](lessons.md) (failure modes captured during work).
See `docs/CLAUDE.md` (Task Management + Templates) for the conventions
and `docs/REFACTOR_PLAN.md` for completed refactor history.

---

## In progress

_(nothing live — the monolith-split refactor closed out via PR #20
(monolith decomposition) + PR #21 (post-refactor cleanup, real CI fix,
lessons L7), both on `main` as of `44f8ead`.)_

---

## Future / Parked

### From the post-refactor cleanup (small follow-ups)

- [ ] **Regenerate `examples/sample-output.csv` + `sample-report.md`
      from the current pipeline.** The committed files are pre-refactor
      May-18 snapshots. They are correct fixtures, not stale — the
      golden byte-oracle proved end-to-end pipeline output is
      byte-identical to that baseline — but a refresh against the
      current package would make the example bundle representatively
      post-refactor. Use the mocked-pipeline harness from
      `tests/test_smoke.py` to keep the regen deterministic.

### From `docs/CLAUDE.md` "Things still out of scope" (genuinely future)

These were originally listed as v1 scope-creep guards; after the
package refactor they remain genuinely future enhancements. Add a
spec + acceptance criteria before picking any of them up.

- [ ] **HTML quadrant chart output** (CVSS × EPSS visualisation).
- [ ] **EPSS trajectory mode** — date-range historical lookups
      (`--date-mode epss-trajectory` or similar) building on the
      existing single-date EPSS support.
- [ ] **Multi-page URL crawling** (`--depth 1` option for the `url`
      input mode, to follow same-host links one hop).
- [ ] **Configurable bucket labels / thresholds** beyond the current
      CVSS + EPSS cutoffs (YAML-driven bucket policies, optionally
      per-preset).
- [ ] **Web UI** — browseable triage view over the SQLite cache, the
      bundled associations, and historical runs.
- [ ] **Long-running daemon mode.** Today the `schedule` subcommand
      emits a cron line / Task XML for the user's own scheduler; a
      first-party daemon (e.g. APScheduler-backed) would let the tool
      hold its own loop.

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
