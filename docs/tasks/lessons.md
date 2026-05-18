# Lessons learned

Append entries here after every user correction or postmortem.
Format: short failure mode + detection signal + prevention rule.

## 2026-05-18 — monolith split: extracted module lost the shared logger
- **Failure mode:** moving `class Cache` into `cache.py` left it calling
  `_log`, which was a `__init__.py` module global → `NameError` only on
  the corrupt-timestamp branch.
- **Detection:** `pytest` (`test_cache_corrupt_timestamp_treated_as_stale`)
  + ruff `F821 Undefined name _log`.
- **Prevention:** every extracted module that logs declares its own
  `_log = logging.getLogger(__name__)`. After each split step also clear
  ruff `F401` for stdlib imports the moved code solely consumed. Recorded
  as REFACTOR_PLAN §5.6 / §5.7; check at every step.

## 2026-05-18 — split: slice end anchored on "next def" swept a constant
- **Failure mode:** Step 4's `bucket/filter` slice used `[bucket_and_suggest
  : write_iocs_csv)`; the `CSV_COLUMNS`/`IOC_CSV_COLUMNS` output constants
  sit *between* `filter_by_date` and `write_iocs_csv`, so they leaked into
  analyze.py → 33 failures (`NameError: CSV_COLUMNS`).
- **Detection:** ruff `F821` + pytest; the pre-write
  `assert not any(... in slice)` guard now catches it before write.
- **Prevention:** a slice END must be the first line of the next section
  that *stays* (constant/banner/def — verify by reading), never blindly
  "the next def". Always assert the slice contains no foreign top-level
  names. Revert uncommitted state with `git checkout --` + `rm` and redo
  rather than surgically un-leaking.

## 2026-05-18 — RECURRENCE (Step 5): interstitial constant `IOC_HALF_LIFE_DAYS`
- Same root cause again: a constant (`IOC_HALF_LIFE_DAYS`, a *decay*/Step-6
  symbol) sat between `_defang_text` and `_ioc_confidence`, inside the
  extract E1 slice → swept into `extract.py` → 12 failures. Reverted + redid
  with end anchor `IOC_HALF_LIFE_DAYS` instead of `def _ioc_confidence`.
- **Process now MANDATORY before every extraction** (pre-write, in-script):
  1. For each candidate slice `[a:b)`, grep it for module-level bindings:
     `^[A-Z_][A-Z0-9_]*\s*[:=]` and `^[a-z_]+\s*=` — eyeball every hit and
     confirm it belongs to the moving layer, not a later step.
  2. Anchor a slice END on the first *staying* line (could be a CONSTANT or
     banner, not necessarily the next `def`); verify by reading that line.
  3. Keep the `assert not any(L[k].startswith(STAY_PREFIXES) ...)` purity
     guard covering ALL later-step defs/consts known to live nearby.
- Also: `ruff --fix` does NOT auto-remove F401 in `__init__.py` (treats
  unused imports as intentional re-exports) — prune moved stdlib imports
  there *by hand* (§5.7), then re-run full ruff to confirm.

## 2026-05-18 — RE-PLAN: facade re-export ≠ monkeypatch-observable
- **Failure mode (Step 7 keyring):** moved code binds its *own* module
  globals, so `patch("ramen_cve.requests" / ".time" / "._is_interactive")`
  and `monkeypatch.setattr(ramen_cve, "DEFAULT_*", …)` are NOT observed by
  the moved function (it calls the submodule-local name). 1 keyring test
  failed; scope scan showed it is systemic: `ramen_cve.requests` ×52,
  `ramen_cve.time` ×26, `DEFAULT_PRESETS_DIR`/`_LAST_OPML_PATH`/
  `_CACHE_PATH` ×21, `_is_interactive` ×5, `ENV_FILE_PATH` ×3, plus
  `_run_wizard`/`_run_cve`/`_maybe_dispatch`/`_prompt_for_api_key` — ~90
  sites concentrated in the network/IO steps still ahead.
- **Detection:** stop-the-line on the first IO-ish move (keyring).
- **Decision (user):** *repoint patch targets to the new module paths*
  (e.g. `patch("ramen_cve.net.requests")`, `monkeypatch.setattr(
  ramen_cve.keyring, "ENV_FILE_PATH", …)`). This is **behavior-preserving**:
  only the patch *location string* changes — never inputs, assertions, or
  expected values. Facade still re-exports every symbol so non-patching
  call sites (`import ramen_cve; ramen_cve.X`) are unaffected.
- **Prevention / revised per-step procedure (MANDATORY):**
  1. Extract slice (proven script) + facade re-export, as before.
  2. A `patch("ramen_cve.X")` is still observed by callers whose code
     remains in `__init__` (they use the package namespace); only repoint
     tests whose *function under test* now lives in the submodule.
  3. For each moved symbol, grep tests for `patch("ramen_cve.<sym>"`,
     `monkeypatch.setattr(ramen_cve, "<sym>"`, and (if the moved fn does
     network/sleep) `ramen_cve.requests`/`ramen_cve.time`; repoint the
     exercising sites to `ramen_cve.<newmod>.<sym>`. Change ONLY the path.
  4. Verify: ruff clean, F821 sweep on new module, FULL pytest green,
     import-compat smoke. Commit code+test-path edits together.
- Also: enumerate real stdlib refs with `\b(\w+)\.` then filter to known
  stdlib (caught the missed `urllib.parse`/`contextlib` in keyring).
