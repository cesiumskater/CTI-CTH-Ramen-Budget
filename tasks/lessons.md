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
