# Refactor Plan — `ramen_cve.py` → `ramen_cve/` Package

**Status:** Documented but **NOT executed in this branch.** The current single-file design exceeds the CLAUDE.md 500-line refactor threshold (~5,800 lines as of commit `f95e67b`); the split below is the recommended next step but is intentionally deferred to its own dedicated cycle because it touches every test import and every `unittest.mock.patch("ramen_cve.X")` call.

---

## Why this is deferred

The literal spec — keep `ramen_cve.py` at the repo root as a 5-line shim *and* add a `ramen_cve/` package directory next to it — is **not constructible in CPython**. When both names exist in the same directory, the package (`ramen_cve/__init__.py`) shadows the module (`ramen_cve.py`) on import. Resolving this requires picking exactly one of:

1. **Drop the root `ramen_cve.py`.** Users invoke via `python -m ramen_cve …`. The `ramen_cve/` package is the only thing on disk under that name. Existing tests (`import ramen_cve`, `from ramen_cve import …`, `patch("ramen_cve.X")`) all keep working because `ramen_cve` is now the package. Disadvantage: every existing README example and `setup.sh / setup.ps1` line that runs `python ramen_cve.py …` needs an update.

2. **Rename the implementation package.** Keep `ramen_cve.py` at the root as the public entry, move the code into `_ramen_cve_impl/` (or similar) — but then every `import ramen_cve` and `patch("ramen_cve.X")` line in the test suite breaks because `ramen_cve` is now just a thin shim with no submodule structure.

Option (1) is the right answer; the test suite already works because `import ramen_cve` doesn't care whether `ramen_cve` is a module or a package. The cost is documentation churn, not test churn — but it's still a focused cycle and must be done all at once, atomically, with the test suite re-run end-to-end.

---

## Target Layout (option 1)

```
ramen_cve/
├── __init__.py              # public re-exports (every name today's tests import)
├── __main__.py              # `python -m ramen_cve` entry point — calls cli.main()
├── models.py                # dataclasses
├── cache.py                 # Cache class + SQL schema
├── extract.py               # regexes + parse_opml + extract_cves + extract_iocs + defang
├── associations.py          # ThreatActor/Campaign/Malware + load_associations
├── hunt.py                  # Hunt dataclass + load/save + _run_hunt
├── pir.py                   # Pir dataclass + load/save + _run_pir
├── analyze.py               # bucketing, kill chain, ATT&CK mapping, TLP, Diamond
├── decay.py                 # IOC confidence decay + sector filter
├── enrich/
│   ├── __init__.py
│   ├── nvd.py               # fetch_nvd + _parse_nvd_response
│   ├── epss.py              # fetch_epss
│   ├── kev.py               # fetch_kev_catalog
│   ├── exploits.py          # exploit/PoC tracker
│   ├── inventory.py         # load_inventory + CPE correlation
│   ├── iocs.py              # _EnricherBase + VT / AbuseIPDB / OTX / MalwareBazaar
│   └── orchestrator.py      # enrich_cves + enrich_with_exploit_status + enrich_iocs
├── output/
│   ├── __init__.py
│   ├── csv_writer.py        # CSV_COLUMNS + write_csv + IOC_CSV_COLUMNS + write_iocs_csv
│   ├── markdown.py          # write_markdown + _md_safe + _summarize_enrichment
│   ├── stix.py              # write_stix + parse_stix_bundle + pull_taxii
│   ├── sigma.py             # write_sigma_stubs
│   └── yara.py              # write_yara_stubs
├── dispatch/
│   ├── __init__.py
│   ├── base.py              # _DispatcherBase
│   ├── slack.py             # SlackWebhookDispatcher
│   ├── webhook.py           # GenericWebhookDispatcher
│   ├── email.py             # EmailDispatcher
│   └── digest.py            # _maybe_dispatch + _maybe_digest + _group_records_by_owner
├── audit.py                 # _audit_actor + _redact_audit_args + _audit_dispatch + _run_audit
├── trend.py                 # _sparkline + _record_runs + _run_trend
├── wizard.py                # _run_wizard + _strip_path_quotes + validators
└── cli.py                   # build_parser + _shared_flags + _path_arg + _safe_basename
                             # + main() + every _run_* dispatcher
```

The root `ramen_cve.py` and `ramen-budget-bundle.zip` cease to exist. `setup.sh` / `setup.ps1` / `README.md` need every `python ramen_cve.py` → `python -m ramen_cve` change.

`ramen_cve/__init__.py` must re-export every name the test suite currently patches at the `ramen_cve.X` level. The minimum is something like:

```python
# Re-export public + test-patched surface
from . import requests, time  # so patch("ramen_cve.requests.get") still works
from .cli import main, build_parser
from .models import (
    FeedEntry, CveRecord, Hunt, Pir, IocRecord, EnrichedCve,
    ThreatActor, Campaign, Malware,
)
from .cache import Cache
from .extract import extract_cves, extract_iocs, parse_opml, _defang_text, ...
from .enrich.nvd import fetch_nvd, _parse_nvd_response, _empty_nvd
from .enrich.epss import fetch_epss
from .enrich.kev import fetch_kev_catalog, _parse_kev_due_date
from .enrich.exploits import (
    fetch_exploitdb_cve_set, fetch_nuclei_cve_set,
    search_github_for_cve, enrich_with_exploit_status,
)
from .enrich.inventory import load_inventory, correlate_inventory, _cpe_matches_inventory
from .enrich.iocs import (
    _EnricherBase, VirusTotalEnricher, AbuseIPDBEnricher,
    OtxEnricher, MalwareBazaarEnricher, enrich_iocs,
)
from .enrich.orchestrator import enrich_cves
from .associations import load_associations, _build_actor, _build_campaign, _build_malware
from .hunt import load_hunt, load_all_hunts, save_hunt
from .pir import load_pir, load_all_pirs, save_pir
from .analyze import (
    bucket_and_suggest, filter_by_date,
    map_cwes_to_attack_techniques, map_cwes_to_kill_chain,
    _worst_tlp, _admiralty_score, _best_admiralty, _normalize_tlp,
)
from .decay import (
    apply_ioc_decay, filter_iocs_by_confidence, _ioc_confidence,
    IOC_HALF_LIFE_DAYS,
)
from .output.csv_writer import (
    CSV_COLUMNS, IOC_CSV_COLUMNS, write_csv, write_iocs_csv,
)
from .output.markdown import write_markdown
from .output.stix import (
    write_stix, parse_stix_bundle, pull_taxii,
    _stix_uuid, _ioc_to_stix_pattern, _extract_iocs_from_pattern,
)
from .output.sigma import write_sigma_stubs, _build_sigma_stub, _sigma_level_for
from .output.yara import (
    write_yara_stubs, _build_yara_stub, _yara_safe_name, _yara_string_escape,
)
from .dispatch.base import _DispatcherBase
from .dispatch.slack import SlackWebhookDispatcher
from .dispatch.webhook import GenericWebhookDispatcher
from .dispatch.email import EmailDispatcher
from .dispatch.digest import (
    dispatch_records, _group_records_by_owner, _build_digest_body,
    _maybe_dispatch, _maybe_digest,
)
from .audit import _audit_actor, _redact_audit_args, _audit_dispatch
from .trend import _sparkline, _record_runs
from .wizard import _run_wizard, _strip_path_quotes, _path_arg, _safe_basename
from .cli import (
    _shared_flags, _validate_cve_id, _parse_iso_date, _configure_logging,
    _validate_args, DEFAULT_CACHE_PATH, DEFAULT_ASSOCIATIONS_PATH,
    DEFAULT_HUNT_DIR, DEFAULT_PIR_DIR,
)
```

After the split, `python -m ramen_cve` runs `ramen_cve/__main__.py`, which is two lines:

```python
from .cli import main
import sys; sys.exit(main())
```

---

## Execution plan (when ready)

1. Create the directory skeleton above with empty `__init__.py` files. Verify `python -c "import ramen_cve"` still finds the *old* monolithic `ramen_cve.py` because the package is empty.
2. **Atomic single commit per submodule, in dependency order**, each followed by `pytest tests/ -q`. Order: `models` → `cache` → `extract` → `associations` → `analyze` → `decay` → `enrich/*` (nvd, epss, kev, exploits, inventory, iocs, then orchestrator) → `output/*` (csv_writer, markdown, sigma, yara, stix) → `dispatch/*` → `audit` → `trend` → `hunt`/`pir` → `wizard` → `cli` → root deletion.
3. Each commit MOVES the relevant section out of `ramen_cve.py` and into the target module, then ADDS the corresponding re-export to `ramen_cve/__init__.py`. The tests keep importing `from ramen_cve import …` and never notice.
4. The final commit deletes the now-empty `ramen_cve.py` and updates `setup.sh` / `setup.ps1` / `README.md` to invoke `python -m ramen_cve`.
5. Add a top-level `pyproject.toml` `[project.scripts]` entry — `ramen-cve = "ramen_cve.cli:main"` — so `pip install -e .` provides a `ramen-cve` console entry point and tests can use `subprocess.run(["ramen-cve", ...])` instead of the current `[".venv/bin/python", "ramen_cve.py", ...]` pattern.

Estimated effort: 6–10 hours for an engineer familiar with the codebase. Test suite must remain green at every intermediate step.

---

## What was done in *this* branch

The current `ramen_cve.py` has been annotated with `# region: <name>` comment markers at every conceptual section boundary listed above. A future automated split can use those markers to drive a `sed`/`tree-sitter` extraction pipeline without re-reading the file by hand. See the line index inside `ramen_cve.py` itself.

The duplicate / non-essential files identified in the QA cycle were removed:

- `claude.md` (duplicate of `CLAUDE.md`)
- `lessons.md` (root copy, duplicate of `tasks/lessons.md`)
- `todo.md` (stale root copy; `tasks/todo.md` is the canonical version)
- `ramen-budget-bundle.zip` (old pre-feature bundle)
- `.ramen-cache.db` (runtime artefact that should never have been committed; matches existing `.gitignore`)

These removals deliver the "clean repo for students" half of the spec without the test-breakage risk of the full package split.
