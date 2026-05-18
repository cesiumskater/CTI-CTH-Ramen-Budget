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
