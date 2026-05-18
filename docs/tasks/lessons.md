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
