# Lessons

Failure modes discovered during work, with detection signal + prevention
rule. Reviewed at session start and before major refactors (per
`docs/CLAUDE.md` Self-Improvement Loop).

---

## L1 — Grep-based dependency discovery misses symbols when extracting modules

- **Failure mode:** When splitting the `src/ramen_cve/__init__.py` monolith,
  the set of imports a freshly-extracted module needs was derived from a
  regex/grep over the moved block. The regex never enumerates every needed
  name, so a real dependency is silently omitted from the new module's
  import header. Recurred 3×:
  - Step 12 `enrich/iocs.py` — missed `urllib.parse` (OTX URL-encode).
  - Step 13 `enrich/inventory.py` — missed `OpmlError` (friendly
    missing-file error raised by `load_inventory`).
  - Step 14 `dispatch/sinks.py` — missed `Path`, used **only** in
    stringised type annotations. `from __future__ import annotations`
    made annotations lazy strings, so the full test suite (463) passed
    green even though the name was undefined at module scope — a latent
    bug invisible to pytest.
- **Detection signal:** `ruff check <new_module> --select F821` reports
  `Undefined name`. This fires even for annotation-only names that the
  test suite cannot catch under `from __future__ import annotations`.
- **Prevention rule:** Treat grep only as a *first draft* of the import
  set, never authoritative. Every extraction step MUST run, as a blocking
  gate before commit:
  1. `ruff --select F821` on the new module (catches undefined names,
     including annotation-only ones tests will miss), then
  2. the full `pytest` suite (catches behavioural/repoint breakage).
  Do not rely on the test suite alone — annotation-only undefined names
  pass tests but are still bugs. Add missing imports, re-run both, only
  then commit.

---

## L2 — GitHub Actions CI is an unreliable signal in this environment

- **Failure mode:** PR #20's `test` workflow fails deterministically in
  15–25 s on a SHA whose code is provably correct. A faithful clean-room
  reproduction — fresh `python3.10 -m venv`, `pip install -e ".[dev]"`,
  then the exact `ruff` / import-guard / `pytest` commands from
  `.github/workflows/ci.yml` — passes every step (463 passed, ruff
  clean, entry point resolves). The runner fails far too fast for the
  real test phase; `ci.yml` has no pip caching, so each run does a full
  network `pip install` from PyPI. Most plausible cause: the Actions
  runner has restricted/no PyPI egress, so the install fails fast and
  deterministically — an environment limitation, not a code defect.
  (User-confirmed disposition: treat as runner/PyPI-egress.)
- **Detection signal:** CI red within <30 s **while** a same-Python
  (3.10) clean-room repro of every `ci.yml` step is green. Available
  tooling cannot fetch Actions job logs (no logs MCP tool; WebFetch
  can't authenticate to Actions), so the red check is not actionable
  from logs.
- **Prevention / mitigation rule:** Do **not** patch provably-green code
  to chase an unobservable red CI — that violates "smallest change" and
  "be explicit about uncertainty". The authoritative per-step
  verification story for this refactor is the **local clean-room repro**
  (py3.10 fresh `pip install -e ".[dev]"` + exact `ci.yml` command
  sequence) **plus** the L1 F821-before-commit gate. Record that
  verification explicitly in each step's ledger entry. Surface (don't
  silently absorb) any CI-vs-local divergence whose cause can't be
  observed; let the human decide disposition.

---

## L3 — Facade must re-export the COMPLETE moved surface, incl. `_`-private

- **Failure mode:** Step 16 moved the STIX block (9 funcs + 2 consts)
  and the facade re-export listed only the 5 *public* names. Result:
  20 test failures — `tests/test_facade.py` locks **every** name that
  was ever a `ramen_cve.*` attribute (private `_stix_uuid`,
  `_ioc_to_stix_pattern`, `_extract_iocs_from_pattern`, … included),
  and `__init__` itself still had internal call sites referencing the
  private helpers (F821 `_stix_uuid`).
- **Detection signal:** `ruff --select F821` on `__init__.py` flags the
  un-re-exported private names still called there; `test_facade.py`
  fails with `facade dropped attribute(s): [...]`; `ImportError:
  cannot import name '_X' from 'ramen_cve'`.
- **Prevention rule:** The re-export set = the **entire** top-level
  surface moved out (all `def`/`class`/CONST names, public *and*
  `_`-prefixed), not just the public API. Build the re-export list
  directly from the extraction's guard-verified `defs`+`consts`
  collections, never a hand-picked "public" subset. Then the L1
  `ruff --select F821` sweep on **both** the new module and `__init__`,
  plus the L2 clean-room suite, is the blocking gate.

---

## L4 — A golden byte-oracle must normalise EVERY volatile field; self-validate it

- **Failure mode:** The Step-19 golden oracle hashed regenerated
  CSV+MD to detect output drift, but normalised only the MD
  `Generated:` clock line. The CSV `enriched_at` column is `_utcnow()`
  at enrichment time (the committed `examples/sample-output.csv` had it
  *frozen* at `2026-01-15T09:00:00`, so it looked like fixture data,
  not a live field). Result: a **false-positive "DRIFT DETECTED"** on
  Step 19 even though every non-timestamp byte was identical and the MD
  hash matched exactly. Panic-reverting would have discarded correct
  work; the suite (test_smoke = presence checks only) gave no signal
  either way.
- **Detection signal:** Oracle reports drift, but a localized
  `git stash`-diff of pre-vs-post output shows the *only* delta is a
  wall-clock field. Equivalent self-check: running the oracle **twice
  on the same code** yields different hashes ⇒ normalisation is
  incomplete (a volatile field is unmasked), not a real regression.
- **Prevention rule:** Before trusting a golden oracle as a drift
  detector, **self-validate it**: run it twice on identical code and
  assert equal hashes; if not, a volatile field is unmasked — fix
  normalisation first. Enumerate volatile fields from the *render
  code* (`_utcnow()`, `.now()`, timestamped filenames, RNG), not from
  eyeballing a frozen committed sample. On an oracle "drift" alert,
  **localize before reverting** (Triage: Reproduce→Localize→Reduce):
  diff actual content; only a non-volatile delta is real drift.

---

## L5 — Whole-tree ruff (incl. Risk 5.7 dead stdlib import) is a BLOCKING gate; prune in the same commit

- **Failure mode:** Step 25 (`audit.py`) moved the last consumer of
  `contextlib`; `__init__`'s top-level `import contextlib` went
  F401-dead (Risk 5.7). The multi-command verify printed local-ruff
  "All checks passed!" *then* clean-room "Found 1 error", but the
  commit+push proceeded anyway — a step landed with a red whole-tree
  ruff, needing a follow-up fix commit.
- **Detection signal:** `ruff check threat_intel_hunter.py conftest.py
  src/ tests/` reports `F401 <stdlib> imported but unused` in
  `__init__.py` after an extraction that was that import's last user.
- **Prevention rule:** The per-step blocking gate is *every* check
  green: clean-room `pytest` (463) **and** whole-tree clean-room
  `ruff` **and** new-module+`__init__` F821 **and** golden oracle.
  Parse *all* results; never `git commit` until the last one is
  confirmed green. After each extraction, proactively run
  `ruff __init__.py --select F401`, and prune any now-dead stdlib
  import **in the same commit** (verify single occurrence + not a
  monkeypatch seam: `0 patch("ramen_cve.<mod>")`).

---

## L6 — Don't hoist a deliberately function-local import; it can be a test seam

- **Failure mode:** The monolith's `_run_wizard` did a *function-local*
  `import questionary` (deferred — `questionary` is heavy/optional, and
  `tests/test_wizard.py` relies on it via
  `with patch.dict("sys.modules", {"questionary": fake_q})`, which only
  takes effect if the import re-resolves through `sys.modules` on each
  call). The Step-30 extraction header hoisted `import questionary` to
  wizard.py module-top; `ruff --fix` then deleted the now-"redundant"
  function-local import. Result: `questionary` bound once at module
  import → `patch.dict` no longer intercepts it → 8 `test_wizard`
  tests `EOFError` (real questionary tried to read stdin). F821 +
  golden + clean-room ruff were all green; only pytest caught it —
  and the step had already been committed/pushed (repeat L5 process
  miss under batch pace).
- **Detection signal:** Tests using `patch.dict("sys.modules", {...})`
  or that mock an optional dep fail with `EOFError`/`ImportError`/real
  side-effects after extraction, while F821/ruff stay green. `git
  show HEAD~1:…__init__.py | grep -n "import <dep>"` shows the import
  was *inside* the function in the monolith.
- **Prevention rule:** The extraction HDR carries only imports that
  were **module-level** in the monolith. A `import X` that lived inside
  a function is a deliberate contract (deferred load and/or
  `sys.modules` test seam) — it travels untouched inside the moved seg
  and must stay function-local; never hoist it, and don't let
  `ruff --fix` dedupe it against a hoisted copy. Before extracting a
  block that imports an optional/heavy dep, grep the monolith for
  `^\s+import <dep>` (indented = function-local) and preserve scope.
  And (L5, re-affirmed) **never commit until clean-room pytest is
  confirmed 463-green** — ruff/F821/golden green is necessary, not
  sufficient.
