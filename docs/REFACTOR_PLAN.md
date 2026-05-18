# Refactor Plan — `ramen_cve` Monolith → ~30-Module Package

**Status:** APPROVED, IN PROGRESS.
**Branch:** `claude/refactor-monolith-split` (off `claude/cti-capability-gap-analysis-fPqgm` @ `8d048f2`).
**Goal:** split `src/ramen_cve/__init__.py` (6,020 LOC, 164 top-level defs)
into ~30 focused modules behind a re-export facade, with **zero behavior
change**. CLAUDE.md says >500 LOC is the split signal; this is 12× over.

This document is authoritative and self-contained: a fresh session can
execute it without re-deriving anything. The **Execution Log** at the
bottom is the live progress ledger — update it as each step lands.

---

## 0. Correction of prior claims (read first)

Earlier revisions of this file, `docs/tasks/todo.md`, and session notes
asserted the blocker was *"~150 `patch("ramen_cve.X")` call sites whose
patch-target semantics break."* **That was measured and is false.** The
real external contract (grepped from `tests/test_ramen_cve.py`):

| Metric | Stale claim | Measured |
|---|---|---|
| Unique `patch()` targets into `ramen_cve` | "~150" | **4** |
| Total `patch()` calls | ~150 | **71** (all → those 4) |
| First-party functions patched by name | many | **0** |
| Deep-path imports `from ramen_cve.sub import` | implied | **0** |
| `from ramen_cve import …` | — | flat only, fully re-exportable |

The 4 targets: `ramen_cve.requests.get`, `ramen_cve.requests.post`,
`ramen_cve.time.sleep`, `ramen_cve.DEFAULT_CACHE_PATH`. Tests mock the
**network/time boundary** then call the **real** first-party code; they
never `patch("ramen_cve.fetch_nvd")`. The "move a function, mock silently
misses" pitfall therefore **does not apply here**. The refactor is
**low-risk**, conditional on the CI gate in §5.4.

Second correction: there are **no `# region:` markers** in the monolith
(a prior claim). The authoritative in-code map is the module docstring
navigation index at `src/ramen_cve/__init__.py:9-43`, which the target
structure below intentionally matches.

Open questions from the plan are resolved: the 5 subprocess tests invoke
the stable `threat_intel_hunter.py` entry (facade-safe); there is no
traceback/module-path assertion coupling; the lone `ramen_cve.py` literal
in tests is only the test module's docstring (behaviorally inert).

---

## 1. Current state (measured line ranges)

| Lines | Responsibility | Target module |
|---|---|---|
| 1–268 | imports, ~40 constants, regexes, CWE/ATT&CK tables | `constants.py` |
| 270–393 | CWE→ATT&CK / kill-chain, `_utcnow`, TLP/Admiralty | `analyze.py` |
| 395–671 | `OpmlError` + 10 dataclasses | `models.py` |
| 673–941 | `Cache` (sqlite, *_cache, runs, audit_log) | `cache.py` |
| 943–1209 | opml/cve/ioc extraction + defang | `extract.py` |
| 1067–1109 | IOC confidence decay | `decay.py` |
| 1211–1340 | API-key bootstrap / redaction | `keyring.py` |
| 1342–1564 | nvd / epss / kev fetchers | `enrich/{nvd,epss,kev}.py` |
| 1567–1635 | associations + `_parse_kev_due_date` | `associations.py` |
| 1637–1765 | `enrich_cves` | `enrich/orchestrator.py` |
| 1767–1902 | exploit/PoC tracker | `enrich/exploits.py` |
| 1904–2128 | IOC enrichers (VT/AbuseIPDB/OTX/MB) | `enrich/iocs.py` |
| 2130–2217 | inventory / CPE correlation | `enrich/inventory.py` |
| 2219–2530 | dispatcher base + slack/webhook/email | `dispatch/*.py` |
| 2532–2661 | `bucket_and_suggest`, `filter_by_date` | `analyze.py` |
| 2663–3196 | IOC-CSV, STIX, sigma, yara writers | `output/*.py` |
| 3197–3567 | `write_csv`, `write_markdown` | `output/{csv_writer,markdown}.py` |
| 3569–3982 | CLI validators + YAML config + remembered-OPML | `cliutil.py`, `config.py` |
| 3983–4552 | `build_parser`, logging/validate, wizard | `cli.py`, `wizard.py` |
| 4553–4696 | `main()` | `cli.py` |
| 4697–5118 | `_maybe_*`, digest, `_output` | `pipeline.py` |
| 5119–5401 | `_run_opml/_url/_cve` + `_dedupe_iocs` | `cli.py` |
| 5403–5651 | hunt/pir I/O + runners | `hunt.py`, `pir.py` |
| 5652–5707 | sparkline / record_runs / trend | `trend.py` |
| 5708–5803 | audit | `audit.py` |
| 5804–5953 | schedule (Task XML / cron) | `schedule.py` |
| 5954–6020 | `_run_stix` | `cli.py` |

**Coupling:** `models.py` + `constants.py` are zero-first-party-dep
leaves (verified: dataclasses use only stdlib). `Cache` depends on
nothing first-party. `enrich/orchestrator` → analyze + enrich/* +
associations + models + cache (one-directional). No cycles **iff** every
shared constant lives in the `constants.py` leaf and arrows point down
the §4 layering.

---

## 2. Target structure (~30 units, ≤~350 LOC each)

```
src/ramen_cve/
├── __init__.py    facade: re-exports only (§3)
├── __main__.py    unchanged (`from . import main`)
├── constants.py   regexes, thresholds, CWE_TO_ATTACK, *_STATUSES, DEFAULT_*
├── models.py      OpmlError + 10 dataclasses  (ZERO first-party deps)
├── cache.py       Cache
├── extract.py     parse_opml, extract_cves, extract_iocs, _defang_text
├── decay.py       _ioc_confidence, apply_ioc_decay, filter_iocs_by_confidence
├── analyze.py     CWE maps, _utcnow, TLP/Admiralty, bucket_and_suggest, filter_by_date
├── associations.py load_associations, _build_*, _parse_kev_due_date
├── keyring.py     api-key bootstrap, _redact_key, _safe_url_for_log
├── enrich/{__init__,nvd,epss,kev,exploits,iocs,inventory,orchestrator}.py
├── output/{__init__,csv_writer,markdown,stix,sigma,yara}.py
├── dispatch/{__init__,base,slack,webhook,email,digest}.py
├── config.py      yaml presets + remembered-OPML
├── cliutil.py     path/date/cve validators, _safe_basename, _coerce_yaml_value
├── pipeline.py    _maybe_*, _output, digest grouping
├── wizard.py      _run_wizard + _wizard_validate_*
├── hunt.py / pir.py / trend.py / audit.py / schedule.py
└── cli.py         _shared_flags, build_parser, main, _run_opml/_url/_cve/_stix
```

Accepted exceptions to the ≤350 rule (document, don't fight): `cli.py`
(~430 — `build_parser` is one cohesive argparse tree) and `stix.py`
(~290). Splitting them adds indirection without reducing complexity
(CLAUDE.md §6).

---

## 3. Facade contract (`__init__.py`)

Pure re-export. Because the measured contract is flat with zero deep
imports and zero first-party patch targets, re-exporting every public +
test-referenced name preserves the contract with **no test edits**.

```python
"""ramen_cve — public facade. Implementation lives in submodules; this
module preserves the flat `from ramen_cve import X` / `ramen_cve.X`
contract tests and users depend on. See docs/REFACTOR_PLAN.md."""
from __future__ import annotations

import time       # keep ramen_cve.time resolvable for patch("ramen_cve.time.sleep")
import requests   # keep ramen_cve.requests resolvable for patch("ramen_cve.requests.get")

from .constants import *          # noqa: F401,F403  (constants only)
from .models import (             # noqa: F401
    OpmlError, FeedEntry, CveRecord, ThreatActor, Campaign, Malware,
    Hunt, Pir, IocRecord, EnrichedCve,
)
from .cache import Cache          # noqa: F401
# … extract, decay, analyze, associations, keyring,
#   enrich.*, output.*, dispatch.*, config, cliutil,
#   pipeline, wizard, hunt, pir, trend, audit, schedule, cli …
from .cli import (                # noqa: F401
    build_parser, _shared_flags, _configure_logging, _validate_args,
    main, _run_opml, _run_url, _run_cve, _run_stix, _get_github_token,
)

__all__ = [...]  # generated mechanically; locked by tests/test_facade.py
```

The complete required name set is enumerated in `tests/test_facade.py`
(the contract lock — derived empirically from every `from ramen_cve
import` token and every `ramen_cve.<name>` token in the suite).

**Patch-target handling:**

| Target | Why it keeps working | Action |
|---|---|---|
| `ramen_cve.requests.get/post` | `import requests` in facade ⇒ `ramen_cve.requests` *is* the shared `sys.modules['requests']`; patching its `.get` mutates the one object every submodule resolves at call time. | None — **invariant**: submodules use `import requests` + qualified calls, never `from requests import get`. CI grep-guards this. |
| `ramen_cve.time.sleep` | Same via `import time`. | Same invariant. |
| `ramen_cve.DEFAULT_CACHE_PATH` | **Fragile.** Defined in `constants.py`, consumed only in `main()` (6 sites). `from .constants import DEFAULT_CACHE_PATH` binds at import → `patch("ramen_cve.DEFAULT_CACHE_PATH")` (sets attr on facade) misses. | In `cli.main`, read late-bound via the facade: `import ramen_cve; … ramen_cve.DEFAULT_CACHE_PATH`. Guarded by a dedicated patch-contract test. |

---

## 4. Dependency layers (arrows point down only ⇒ acyclic by construction)

```
L0  constants  models  cache                     (zero first-party deps)
L1  analyze  extract  decay  associations  keyring
L2  enrich/{nvd,epss,kev,exploits,iocs,inventory}
L3  enrich/orchestrator  output/*  dispatch/*
L4  config  cliutil  pipeline  wizard  hunt  pir  trend  audit  schedule
L5  cli  →  __init__ (facade)  →  __main__
```

Escape hatch if a late up-arrow appears: a **function-local** deferred
import (never module-level), logged in the Execution Log as a wart.

---

## 5. Migration sequence — strangler-fig, one green commit per step

Each step *moves* code out of `__init__.py` into its target module **and**
adds the matching re-export, so `from ramen_cve import …` works at every
step. Suite stays green (currently **458**) at every commit.

| # | Moves | New module | Verify |
|---|---|---|---|
| 0 | prep | CI, contract tests, doc fix, empty subpkg dirs | suite + CI green |
| 1 | 66–268 | `constants.py` | suite; assert DEFAULT_DATA_DIR path unchanged |
| 2 | 395–671 | `models.py` | suite |
| 3 | 673–941 | `cache.py` | suite + cache tests |
| 4 | 270–393, 2532–2661 | `analyze.py` | analyze/bucket/date tests |
| 5 | 943–1209 | `extract.py` | extract tests |
| 6 | 1067–1109 | `decay.py` | decay tests |
| 7 | 1567–1635 | `associations.py` | assoc tests |
| 8 | 1211–1340 | `keyring.py` | redaction tests |
| 9 | 1342–1564 | `enrich/{nvd,epss,kev}.py` | requests-mock tests |
| 10 | 1767–1902 | `enrich/exploits.py` | exploit tests |
| 11 | 1904–2128 | `enrich/iocs.py` | enricher tests |
| 12 | 2130–2217 | `enrich/inventory.py` | cpe tests |
| 13 | 1637–1765 | `enrich/orchestrator.py` | enrich_cves tests |
| 14 | 2663–2979 | `output/stix.py` (+iocs-csv) | stix/taxii tests |
| 15 | 2981–3196 | `output/{sigma,yara}.py` | sigma/yara tests |
| 16 | 3197–3567 | `output/{csv_writer,markdown}.py` | **golden CSV/MD diff** |
| 17 | 2219–2530 | `dispatch/{base,slack,webhook,email}.py` | dispatcher tests |
| 18 | 4766–4904 | `dispatch/digest.py` | digest tests |
| 19 | 3569–3982 | `cliutil.py` + `config.py` | yaml/config/path tests |
| 20 | 4697–5118 | `pipeline.py` | _output/sector tests |
| 21 | 4343–4552 | `wizard.py` | wizard tests |
| 22 | 5403–5651 | `hunt.py`,`pir.py`,`trend.py` | hunt/pir/trend tests |
| 23 | 5708–5953 | `audit.py`,`schedule.py` | audit/schedule tests |
| 24 | 3983–4696, 5119–5401, 5954–6020 | `cli.py` (+ DEFAULT_CACHE_PATH mitigation) | full suite + CLI/subprocess tests |
| 25 | — | finalize facade, delete dead code, lock `__all__` | suite + golden + manual smoke |
| 26 | — | doc/script audit (`ramen_cve.py` literals) | grep clean; suite green |

26 commits, each independently revertable & green. Message format:
`refactor(split N/26): <section> → <module>`.

---

## 6. Risk analysis & mitigation

- **5.1 Mock/patch (LOW):** invariant — all submodules `import requests` /
  `import time`, qualified calls only. CI fails on `from requests import`
  / `from time import` anywhere in `src/ramen_cve/`.
- **5.2 `DEFAULT_CACHE_PATH` late-bind (MED, 1 symbol):** mitigation in
  §3; red→green regression test added in prep.
- **5.3 Circular imports (MED, preventable):** L0 constants leaf +
  downward arrows; after every step `python -c "import ramen_cve"` and
  `python -X importtime` must not raise.
- **5.4 No-CI auto-merge (HIGH — top risk):** the
  `claude/cti-capability-gap-analysis-fPqgm` branch auto-PRs+merges to
  `main` in ~15s with zero checks. **Mitigation / hard prerequisite:**
  this refactor runs on the dedicated `claude/refactor-monolith-split`
  branch (not auto-merged) as a reviewable draft PR, and Step 0 adds a
  GitHub Actions workflow so checks at least *run and are visible*. NB:
  branch protection / required-checks enforcement is server-side and not
  settable from here — the workflow provides signal, the dedicated
  non-auto-merge branch provides the actual containment.
- **5.6 Per-module logger (LOW, recurring):** the monolith has one
  `_log = logging.getLogger(__name__)`. Any extracted module that calls
  `_log.*` must declare its own `_log = logging.getLogger(__name__)`
  (idiomatic; logger name differs cosmetically but no test asserts it and
  it is not in user-facing output). Forgetting it ⇒ `NameError` (caught
  by the suite — happened & fixed in Step 3). Check every step.
- **5.7 Now-unused stdlib imports (LOW, recurring):** when a section
  moves out, imports it solely consumed (`sqlite3`, `datetime`,
  `timedelta` after Cache) become F401 in `__init__`. Trust ruff F401
  (it accounts for PEP-563 string annotations) and delete them.
- **5.5 Import-time side effects:** `DEFAULT_DATA_DIR` etc. use
  `Path(__file__)`; moving into `constants.py` keeps `__file__` at the
  same `src/ramen_cve/` depth ⇒ paths unchanged. Asserted in Step 1.
- **Entry points:** `threat_intel_hunter.py` shim, `python -m ramen_cve`,
  `ramen-cve` console script all route through `ramen_cve.main`, which
  the facade preserves. **No entry-point transition needed.**

---

## 7. Verification (per step + final)

1. `.venv/bin/pytest tests/ -q` → identical pass count (**458**) every step.
2. `.venv/bin/ruff check threat_intel_hunter.py conftest.py src/ tests/` clean.
3. `python -c "import ramen_cve; import ramen_cve.__main__"` exits 0.
4. Golden oracle: snapshot `examples/sample-output.csv` +
   `sample-report.md`; regenerate + byte-diff at Steps 16 & 25.
5. `tests/test_facade.py` locks the public surface (every name importable
   two ways) + patch-contract (requests/time/DEFAULT_CACHE_PATH still
   bite). Added in prep; green now (monolith) and at every step.
6. Step 25 manual smoke: `threat_intel_hunter.py --list-configs`,
   `… opml examples/sample.opml --no-cache` (offline), `python -m
   ramen_cve --help`, `ramen-cve --help` vs. a pre-refactor capture.
7. Final reviewer grep: diff shows only moves + facade + the 6-line §5.2
   change + new tests — no logic edits inside moved functions.

Stop-the-line: any red step ⇒ revert that commit, re-plan, never stack.

---

## 8. Effort

~21–26h (≈3–3.5 focused days) incl. prep + contingency. The old "6–10h"
estimate predates the 458-test suite and the YAML/schedule/remember-OPML
growth and is optimistic for the zero-behavior-change rigor required.

---

## Execution Log (live ledger — append per step)

- **Step 0 (prep):** branch `claude/refactor-monolith-split` cut @
  `8d048f2`. Plan rewritten (false claims corrected). CI workflow,
  `tests/test_facade.py` (surface + patch-contract), `todo.md`
  correction. Draft PR #18. 463 passed, ruff clean. ✅
- **Step 1/26 — `constants.py`:** moved `__init__.py:66-267` (regexes,
  CWE/ATT&CK tables, all `DEFAULT_*`, `*_STATUSES`, defang map) verbatim
  into the Layer-0 `constants.py` leaf (214 LOC); `__init__` 6020→5858,
  explicit `from .constants import (…)` re-export of all 36 names incl.
  the 3 private (`_DEFANG_MAP/_DEFANG_DETECT/_FILE_EXT_TLDS`). Verified:
  `import ramen_cve` ok; `DEFAULT_DATA_DIR` byte-identical (Risk 5.5
  confirmed); 463 passed; ruff clean (isort autofix on new block). ✅
- **Step 2/26 — `models.py`:** `OpmlError` + 10 dataclasses →
  `models.py` (308 LOC). **Plan refinement** (logged per §4): `_utcnow`
  moved into `models.py` (its lowest consumer — `EnrichedCve`
  default_factory) instead of `analyze.py`; `BUCKET_ACTIONS` moved into
  `constants.py` (it is a static lookup table, evaluated at
  `EnrichedCve` class-def time → must be an L0 import). Facade
  re-exports relocated to the top import group (avoids E402); dropped
  now-unused `dataclasses`/`timezone` imports from `__init__`. `__init__`
  5858→5566. 463 passed, ruff clean, EnrichedCve build verified. ✅
- **Step 3/26 — `cache.py`:** `class Cache` (217–479) → `cache.py`
  (282 LOC; stdlib + `DEFAULT_CACHE_TTL_HOURS`/`_utcnow` leaves).
  Stop-the-line caught 1 regression: Cache used the module `_log`; fixed
  by giving `cache.py` its own `logging.getLogger(__name__)` (→ new
  invariant §5.6). Removed now-unused `sqlite3`/`datetime`/`timedelta`
  from `__init__` (§5.7). `__init__` 5566→5301. 463 passed, ruff
  clean, Cache round-trip + corrupt-timestamp path verified. ✅
- **Step 4/26 — `analyze.py`:** 3 non-contiguous regions (CWE→ATT&CK /
  →Kill-Chain mappers incl. their `KILL_CHAIN_PHASES`/`CWE_TO_KILL_CHAIN`
  constants; TLP/Admiralty math; `bucket_and_suggest`+`filter_by_date`)
  → `analyze.py` (199 LOC, L1; own `_log`). `_log` global stayed in
  `__init__`. **Near-miss:** first attempt anchored the slice end on
  `def write_iocs_csv` and swept the output `CSV_COLUMNS`/`IOC_CSV_COLUMNS`
  constants in → 33 failures; reverted (`git checkout --`) and redid with
  end anchor `CSV_COLUMNS = [` + a slice-purity assertion (lesson logged).
  `__init__` 5301→5138. 463 passed, ruff clean. ✅
- **Step 5/26 — `extract.py`:** 2 regions (banner+`parse_opml`+
  `extract_cves`+`_defang_text`; `_is_public_ip`+`_is_likely_filename`+
  `extract_iocs`) → `extract.py` (250 LOC, L1; deps: constants/models +
  `analyze._normalize_tlp`; no `_log`). Decay funcs + `IOC_HALF_LIFE_DAYS`
  stay (Step 6). **Near-miss (same class as Step 4):** E1 first anchored on
  `def _ioc_confidence` swept the decay constant `IOC_HALF_LIFE_DAYS` in →
  12 failures; reverted + redid with `IOC_HALF_LIFE_DAYS` end anchor.
  Hand-pruned now-unused `ipaddress`/`ET` from `__init__` (ruff won't
  autofix F401 in package `__init__`). `__init__` 5136→4925. 463 passed,
  ruff clean. Pre-extraction interstitial-constant checklist added to
  lessons.md (now mandatory). ✅
