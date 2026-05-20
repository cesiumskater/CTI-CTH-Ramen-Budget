# AI Coding Agent Guidelines (claude.md)

These rules define how an AI coding agent should plan, execute, verify, communicate, and recover when working in a real codebase. Optimize for correctness, minimalism, and developer experience.

---

## Operating Principles (Non-Negotiable)

- **Correctness over cleverness**: Prefer boring, readable solutions that are easy to maintain.
- **Smallest change that works**: Minimize blast radius; don't refactor adjacent code unless it meaningfully reduces risk or complexity.
- **Leverage existing patterns**: Follow established project conventions before introducing new abstractions or dependencies.
- **Prove it works**: "Seems right" is not done. Validate with tests/build/lint and/or a reliable manual repro.
- **Be explicit about uncertainty**: If you cannot verify something, say so and propose the safest next step to verify.

---

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for any non-trivial task (3+ steps, multi-file change, architectural decision, production-impacting behavior).
- Include verification steps in the plan (not as an afterthought).
- If new information invalidates the plan: **stop**, update the plan, then continue.
- Write a crisp spec first when requirements are ambiguous (inputs/outputs, edge cases, success criteria).

### 2. Subagent Strategy (Parallelize Intelligently)
- Use subagents to keep the main context clean and to parallelize:
  - repo exploration, pattern discovery, test failure triage, dependency research, risk review.
- Give each subagent **one focused objective** and a concrete deliverable:
  - "Find where X is implemented and list files + key functions" beats "look around."
- Merge subagent outputs into a short, actionable synthesis before coding.

### 3. Incremental Delivery (Reduce Risk)
- Prefer **thin vertical slices** over big-bang changes.
- Land work in small, verifiable increments:
  - implement → test → verify → then expand.
- When feasible, keep changes behind:
  - feature flags, config switches, or safe defaults.

### 4. Self-Improvement Loop
- After any user correction or a discovered mistake:
  - add a new entry to `tasks/lessons.md` capturing:
    - the failure mode, the detection signal, and a prevention rule.
- Review `tasks/lessons.md` at session start and before major refactors.

### 5. Verification Before "Done"
- Never mark complete without evidence:
  - tests, lint/typecheck, build, logs, or a deterministic manual repro.
- Compare behavior baseline vs changed behavior when relevant.
- Ask: "Would a staff engineer approve this diff and the verification story?"

### 6. Demand Elegance (Balanced)
- For non-trivial changes, pause and ask:
  - "Is there a simpler structure with fewer moving parts?"
- If the fix is hacky, rewrite it the elegant way **if** it does not expand scope materially.
- Do not over-engineer simple fixes; keep momentum and clarity.

### 7. Autonomous Bug Fixing (With Guardrails)
- When given a bug report:
  - reproduce → isolate root cause → fix → add regression coverage → verify.
- Do not offload debugging work to the user unless truly blocked.
- If blocked, ask for **one** missing detail with a recommended default and explain what changes based on the answer.

---

## Task Management (File-Based, Auditable)

1. **Plan First**
   - Write a checklist to `tasks/todo.md` for any non-trivial work.
   - Include "Verify" tasks explicitly (lint/tests/build/manual checks).
2. **Define Success**
   - Add acceptance criteria (what must be true when done).
3. **Track Progress**
   - Mark items complete as you go; keep one "in progress" item at a time.
4. **Checkpoint Notes**
   - Capture discoveries, decisions, and constraints as you learn them.
5. **Document Results**
   - Add a short "Results" section: what changed, where, how verified.
6. **Capture Lessons**
   - Update `tasks/lessons.md` after corrections or postmortems.

---

## Communication Guidelines (User-Facing)

### 1. Be Concise, High-Signal
- Lead with outcome and impact, not process.
- Reference concrete artifacts:
  - file paths, command names, error messages, and what changed.
- Avoid dumping large logs; summarize and point to where evidence lives.

### 2. Ask Questions Only When Blocked
When you must ask:
- Ask **exactly one** targeted question.
- Provide a recommended default.
- State what would change depending on the answer.

### 3. State Assumptions and Constraints
- If you inferred requirements, list them briefly.
- If you could not run verification, say why and how to verify.

### 4. Show the Verification Story
- Always include:
  - what you ran (tests/lint/build), and the outcome.
- If you didn't run something, give a minimal command list the user can run.

### 5. Avoid "Busywork Updates"
- Don't narrate every step.
- Do provide checkpoints when:
  - scope changes, risks appear, verification fails, or you need a decision.

---

## Context Management Strategies (Don't Drown the Session)

### 1. Read Before Write
- Before editing:
  - locate the authoritative source of truth (existing module/pattern/tests).
- Prefer small, local reads (targeted files) over scanning the whole repo.

### 2. Keep a Working Memory
- Maintain a short running "Working Notes" section in `tasks/todo.md`:
  - key constraints, invariants, decisions, and discovered pitfalls.
- When context gets large:
  - compress into a brief summary and discard raw noise.

### 3. Minimize Cognitive Load in Code
- Prefer explicit names and direct control flow.
- Avoid clever meta-programming unless the project already uses it.
- Leave code easier to read than you found it.

### 4. Control Scope Creep
- If a change reveals deeper issues:
  - fix only what is necessary for correctness/safety.
  - log follow-ups as TODOs/issues rather than expanding the current task.

---

## Error Handling and Recovery Patterns

### 1. "Stop-the-Line" Rule
If anything unexpected happens (test failures, build errors, behavior regressions):
- stop adding features
- preserve evidence (error output, repro steps)
- return to diagnosis and re-plan

### 2. Triage Checklist (Use in Order)
1. **Reproduce** reliably (test, script, or minimal steps).
2. **Localize** the failure (which layer: UI, API, DB, network, build tooling).
3. **Reduce** to a minimal failing case (smaller input, fewer steps).
4. **Fix** root cause (not symptoms).
5. **Guard** with regression coverage (test or invariant checks).
6. **Verify** end-to-end for the original report.

### 3. Safe Fallbacks (When Under Time Pressure)
- Prefer "safe default + warning" over partial behavior.
- Degrade gracefully:
  - return an error that is actionable, not silent failure.
- Avoid broad refactors as "fixes."

### 4. Rollback Strategy (When Risk Is High)
- Keep changes reversible:
  - feature flag, config gating, or isolated commits.
- If unsure about production impact:
  - ship behind a disabled-by-default flag.

### 5. Instrumentation as a Tool (Not a Crutch)
- Add logging/metrics only when they:
  - materially reduce debugging time, or prevent recurrence.
- Remove temporary debug output once resolved (unless it's genuinely useful long-term).

---

## Engineering Best Practices (AI Agent Edition)

### 1. API / Interface Discipline
- Design boundaries around stable interfaces:
  - functions, modules, components, route handlers.
- Prefer adding optional parameters over duplicating code paths.
- Keep error semantics consistent (throw vs return error vs empty result).

### 2. Testing Strategy
- Add the smallest test that would have caught the bug.
- Prefer:
  - unit tests for pure logic,
  - integration tests for DB/network boundaries,
  - E2E only for critical user flows.
- Avoid brittle tests tied to incidental implementation details.

### 3. Type Safety and Invariants
- Avoid suppressions (`any`, ignores) unless the project explicitly permits and you have no alternative.
- Encode invariants where they belong:
  - validation at boundaries, not scattered checks.

### 4. Dependency Discipline
- Do not add new dependencies unless:
  - the existing stack cannot solve it cleanly, and the benefit is clear.
- Prefer standard library / existing utilities.

### 5. Security and Privacy
- Never introduce secret material into code, logs, or chat output.
- Treat user input as untrusted:
  - validate, sanitize, and constrain.
- Prefer least privilege (especially for DB access and server-side actions).

### 6. Performance (Pragmatic)
- Avoid premature optimization.
- Do fix:
  - obvious N+1 patterns, accidental unbounded loops, repeated heavy computation.
- Measure when in doubt; don't guess.

### 7. Accessibility and UX (When UI Changes)
- Keyboard navigation, focus management, readable contrast, and meaningful empty/error states.
- Prefer clear copy and predictable interactions over fancy effects.

---

## Git and Change Hygiene (If Applicable)

- Keep commits atomic and describable; avoid "misc fixes" bundles.
- Don't rewrite history unless explicitly requested.
- Don't mix formatting-only changes with behavioral changes unless the repo standard requires it.
- Treat generated files carefully:
  - only commit them if the project expects it.

---

## Definition of Done (DoD)

A task is done when:
- Behavior matches acceptance criteria.
- Tests/lint/typecheck/build (as relevant) pass or you have a documented reason they were not run.
- Risky changes have a rollback/flag strategy (when applicable).
- The code follows existing conventions and is readable.
- A short verification story exists: "what changed + how we know it works."

---

## Templates

### Plan Template (Paste into `tasks/todo.md`)
- [ ] Restate goal + acceptance criteria
- [ ] Locate existing implementation / patterns
- [ ] Design: minimal approach + key decisions
- [ ] Implement smallest safe slice
- [ ] Add/adjust tests
- [ ] Run verification (lint/tests/build/manual repro)
- [ ] Summarize changes + verification story
- [ ] Record lessons (if any)

### Bugfix Template (Use for Reports)
- Repro steps:
- Expected vs actual:
- Root cause:
- Fix:
- Regression coverage:
- Verification performed:
- Risk/rollback notes:

---

## Project: Ramen CVE — Frameworks, Dependencies, and Tools

This section is project-specific and applies only to the `ramen-cve` tool that lives in this repo. The rules above still apply globally; this section adds the concrete stack and constraints for this codebase.

### Project shape

> **Status note:** this project-specific section was originally written
> for the single-file v1 (`ramen_cve.py` at the repo root, ~400 LOC). The
> codebase has since been refactored into a ~30-module package under
> `src/ramen_cve/` behind a flat re-export façade — see
> `docs/REFACTOR_PLAN.md` for the authoritative architecture and the
> Execution Log. The entries below have been updated to reflect the
> current package shape; the global AI-agent operating principles above
> are unchanged.

- **Layered package.** Implementation lives under `src/ramen_cve/` as
  ~30 focused, layered modules: `constants`, `models`, `cache`,
  `extract`, `decay`, `analyze`, `associations`, `keyring`,
  `enrich/{nvd,epss,kev,exploits,iocs,inventory,orchestrator}`,
  `output/{csv_writer,markdown,stix,sigma,yara}`,
  `dispatch/{sinks,runner,digest}`, `config`, `cliutil`, `pipeline`,
  `wizard`, `hunt`, `pir`, `trend`, `audit`, `schedule`, `cli`.
  `src/ramen_cve/__init__.py` is a pure re-export façade with a locked
  `__all__` that preserves the flat `from ramen_cve import X` /
  `ramen_cve.X` contract.
- **Entry points:** `python -m ramen_cve`, the `ramen-cve` console
  script (installed by `pip install -e .`), and the
  `threat_intel_hunter.py` shim at the repo root. All three route
  through `ramen_cve.cli.main`.
- **Per-module line budget:** ≤~350 LOC each (CLAUDE.md §6). Documented
  exceptions where splitting adds indirection without reducing
  complexity: `cli.py` (cohesive argparse + main + runners) and
  `output/stix.py`.
- **Python version:** 3.10 or newer. Use modern syntax (`match`
  statements, structural pattern matching, `X | Y` union types,
  `dict[str, int]` generics) where it improves readability.
- **License:** MIT. The repo is meant to be forked and adapted by
  anyone who watches the talk.

### Dependencies (keep this list small)

Three runtime dependencies, no more without a written justification in `tasks/todo.md`:

- **`requests`** — HTTP client for NVD, EPSS, and URL-mode fetching. The `urllib` standard library option is technically possible but produces unreadable code for a beginner audience. `requests` is the right ramen-budget call.
- **`feedparser`** — RSS/Atom parsing. Real-world feeds are inconsistent (RSS 2.0, Atom, weird hybrids); `feedparser` normalizes them. Standard library `xml.etree.ElementTree` is fine for parsing the OPML file itself, but not for the feed bodies.
- **`python-dotenv`** — Loads `.env` for the NVD API key. Six lines saved versus rolling our own `.env` parser, and it's the convention every Python developer recognizes.

Standard library only for everything else: `argparse`, `csv`, `dataclasses`, `datetime`, `json`, `logging`, `pathlib`, `re`, `sqlite3`, `sys`, `urllib.parse`, `xml.etree.ElementTree`.

**Dev dependencies** (in `requirements-dev.txt`, separate from runtime):

- **`pytest`** — test runner. Bare `pytest`, no plugins.
- **`ruff`** — linter and formatter in one. Replaces `flake8` + `black` + `isort`. One config, fast, no debate.

That's it. No `mypy` in v1 — type hints are present in the code for readability but not enforced. No `pre-commit` hooks — the user runs `ruff` and `pytest` manually. No `tox`. No `poetry`.

### External APIs and rate limits

- **NVD CVE API** (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
  - Free, but rate-limited. Without an API key: 5 requests per 30-second window (~6s between calls).
  - With a free API key: 50 requests per 30-second window (~0.6s between calls).
  - Key request page: `https://nvd.nist.gov/developers/request-an-api-key`
  - Loaded from `NVD_API_KEY` environment variable. Tool runs without it but warns about the slower rate.
- **EPSS API** (`https://api.first.org/data/v1/epss`)
  - Free, no key required.
  - Batch up to 100 CVEs per call via `?cve=CVE-A,CVE-B,...`. Always batch when enriching more than one CVE.
  - Historical scores via `?date=YYYY-MM-DD`. Used by `--date-mode epss`.

Both APIs are documented at the URLs above and behavior is subject to change. If a future request returns a 4xx or 5xx, fail soft, log the error, continue with the rest of the CVEs.

### Caching

- **SQLite file** at `./.ramen-cache.db` by default. Two tables: `nvd_cache(cve_id, payload_json, fetched_at)` and `epss_cache(cve_id, score_date, payload_json, fetched_at)`.
- **Default TTL:** 24 hours. CVSS rarely changes; EPSS is a daily model.
- **Cache is opt-out** via `--no-cache`, never opt-in. Beginners should benefit from caching without thinking about it.
- The cache file is in `.gitignore`. Never commit it.

### Configuration and secrets

- `.env.example` is checked in with placeholder keys. Real `.env` is in `.gitignore`.
- The script never prints secrets, never logs them, and never includes them in error messages. If an API call fails, log the URL with the key parameter redacted.
- No other configuration files in v1. Everything else is CLI flags.

### File and directory layout

```
ramen-cve/
├── README.md
├── pyproject.toml              # ramen-cve console script + dev extra
├── threat_intel_hunter.py      # entry-point shim (routes to ramen_cve.cli.main)
├── conftest.py                 # tests bootstrap (src/ on sys.path)
├── .env.example
├── .gitignore
├── LICENSE
├── src/ramen_cve/
│   ├── __init__.py             # pure re-export façade + locked __all__
│   ├── __main__.py             # `python -m ramen_cve` -> cli.main
│   ├── constants.py            # regexes, thresholds, DEFAULT_*, lookup tables
│   ├── models.py               # OpmlError + 10 dataclasses (L0 leaf)
│   ├── cache.py                # SQLite cache
│   ├── extract.py, decay.py    # opml/CVE/IOC extraction; IOC decay
│   ├── analyze.py              # bucket_and_suggest, filter_by_date, TLP/Admiralty
│   ├── associations.py         # threat-actor / campaign / malware associations
│   ├── keyring.py              # API-key bootstrap + redaction
│   ├── enrich/                 # nvd, epss, kev, exploits, iocs, inventory, orchestrator
│   ├── output/                 # csv_writer, markdown, stix, sigma, yara
│   ├── dispatch/               # sinks (Slack/webhook/email), runner, digest
│   ├── config.py, cliutil.py   # YAML presets + remembered-OPML; argparse validators
│   ├── pipeline.py             # _maybe_* glue, _output multi-format writer
│   ├── wizard.py               # interactive questionary wizard
│   ├── hunt.py, pir.py, trend.py
│   ├── audit.py, schedule.py   # tamper-evident audit log; cron / Task XML emit
│   ├── cli.py                  # _shared_flags, build_parser, main, _run_*
│   └── data/                   # bundled associations.json, default hunts/ + pirs/
├── examples/
│   ├── sample.opml
│   ├── sample-output.csv
│   └── sample-report.md
├── tests/
│   ├── test_ramen_cve.py       # main suite
│   ├── test_facade.py          # façade-contract lock
│   ├── test_smoke.py           # mocked-pipeline E2E
│   ├── test_wizard.py
│   └── fixtures/               # NVD/EPSS JSON fixtures
├── docs/
│   ├── CLAUDE.md               # these guidelines
│   └── REFACTOR_PLAN.md        # authoritative architecture + Execution Log
└── tasks/
    └── lessons.md              # L1–L6 (recurring failure modes + prevention)
```

`tasks/lessons.md` is mandatory and is reviewed at session start (per the
Self-Improvement Loop). `tasks/todo.md` is currently consolidated into
`docs/REFACTOR_PLAN.md`'s Execution Log to keep a single auditable
ledger — `REFACTOR_PLAN.md` and `lessons.md` together cover the
templates in the global section above.

### Style

- **Ruff config in `pyproject.toml`.** Line length 100. Default rule selection (`E`, `F`, `W`, `I`, `UP`, `B`, `SIM`). No `--unsafe-fixes`.
- **Type hints on every function signature.** Use them for readability, not enforcement. `from __future__ import annotations` at the top of the file lets us use modern syntax without runtime overhead.
- **Docstrings on every function.** One-line summary minimum. Multi-line for anything non-obvious.
- **No `print()` for user-facing output.** Use the `logging` module configured to write to stderr at INFO by default, with `--quiet` (WARNING) and `--verbose` (DEBUG) flags. Final output (CSV path, Markdown path) prints to stdout so the script can be piped.
- **Constants at the top of the file.** API base URLs, default thresholds, the CVE regex, the cache TTL, the User-Agent string. One block, easy to find, easy to tune.

### Testing strategy for this project

- **Unit tests for pure logic.** The CVE regex, the bucket assignment function, the date filter, the OPML parser. These run offline in milliseconds.
- **No live API tests in CI.** Mock NVD and EPSS responses with fixture JSON files in `tests/fixtures/`. Live network calls happen only during manual integration testing.
- **One smoke test that runs the whole pipeline against the bundled `examples/sample.opml`** with mocked APIs and asserts the output files exist and contain expected bucket headers. This is the "would it actually work" test.
- **Coverage target:** not measured in v1. The above tests are enough.

### Things still out of scope

The list below is what remains genuinely future work after the package
refactor. Items that the v1 doc originally listed here but that have
since shipped (Slack / generic-webhook / email digest dispatchers in
`dispatch/`, the Windows Task Scheduler / cron emitter in `schedule.py`,
STIX 2.1 + Sigma + YARA writers in `output/`) are no longer out of
scope — they are documented in `docs/REFACTOR_PLAN.md` §2.

- HTML quadrant chart output.
- EPSS trajectory mode (date-range historical lookups).
- Multi-page URL crawling (the `--depth 1` option).
- Configurable bucket labels or thresholds beyond the CVSS and EPSS
  cutoffs.
- A web UI.
- A long-running daemon mode (the `schedule` subcommand emits a
  cron line / Task XML for the user's own scheduler — the tool itself
  still runs one shot at a time).

If a request would expand scope into one of these, log it as a follow-up
in `docs/REFACTOR_PLAN.md` (or its successor) rather than scope-creeping
the current change.

### Definition of Done for v1 specifically

The v1 release is done when:

- All three input modes (`opml`, `url`, `cve`) work end-to-end against the bundled `examples/sample.opml` and a real CVE.
- All three date modes (`feed`, `disclosure`, `epss`) parse correctly and apply the right filter.
- CSV and Markdown outputs are produced with the schemas specified in the design doc.
- KEV override is correctly distinguished from `patch_now` in the bucket column and the report.
- `ruff check .` and `pytest` both pass.
- `README.md` covers install, NVD key setup, three example invocations, and a "what this is not" section.
- A run against `examples/sample.opml` produces the bundled `examples/sample-output.csv` and `examples/sample-report.md` byte-for-byte (use a frozen mock-API fixture to make this reproducible).
