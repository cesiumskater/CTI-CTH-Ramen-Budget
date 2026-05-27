# Monolith → Package Refactor (HISTORICAL)

> **Status: COMPLETE (2026-05-20).** This document is preserved because
> ~20 source-file docstrings reference it for architectural context. It
> is **not** the current architecture reference — see `README.md` and
> `src/ramen_cve/__init__.py` (the pure re-export façade with a locked
> `__all__`) for the live shape.

---

## What happened

Between 2026-05-18 and 2026-05-20, the single-file `src/ramen_cve/__init__.py`
(6,020 LOC, 164 top-level defs) was split into ~30 focused modules behind
a pure re-export façade, with **zero behaviour change** end-to-end (proven
by a golden CSV+MD byte-oracle and the full 463-case test suite at every
intermediate commit).

## Final shape

```
src/ramen_cve/
├── __init__.py    pure façade — re-exports + locked __all__
├── __main__.py    python -m ramen_cve
├── constants.py   regexes, thresholds, CWE/ATT&CK tables (L0)
├── models.py      OpmlError + 10 dataclasses (L0)
├── cache.py       Cache (L0)
├── extract.py     opml / cve / ioc extraction + link-crawl helpers (L1)
├── decay.py       IOC confidence decay (L1)
├── analyze.py     CWE maps, TLP/Admiralty, bucket_and_suggest, filter_by_date (L1)
├── associations.py threat-actor / campaign / malware (L1)
├── keyring.py     API-key bootstrap + redaction (L1)
├── render.py      sparkline + small render helpers (L1)
├── bucket_policy.py BucketPolicy / BucketSpec (L1)
├── enrich/        nvd · epss · kev · exploits · iocs · inventory · orchestrator (L2-L3)
├── output/        csv_writer · markdown · stix · sigma · yara · html_quadrant (L3)
├── dispatch/      sinks · runner · digest (L3)
├── web/           static-site builder (L4)
├── cliutil.py · config.py · pipeline.py · wizard.py (L4)
├── hunt.py · pir.py · trend.py · audit.py · schedule.py · daemon.py (L4)
└── cli.py         argparse tree + main + runners (L5)
```

Layered arrows point down only (acyclic by construction). Per-module line
budget ≤350 LOC; two accepted exceptions (`cli.py` ~870 — one cohesive
argparse + main + runners unit; `output/stix.py` ~290).

## Why it's kept

The detailed 33-step execution log lives in `git log --oneline` plus the
PR descriptions on `claude/refactor-monolith-split` (merged via PRs #20,
#21, #22). Source-file docstrings reference this path for architectural
context; deleting it would orphan those references.

For new design work or contributor onboarding, start with `README.md` and
`docs/CLAUDE.md`. For ongoing failure modes / prevention rules captured
during the refactor (and since), see `tasks/lessons.md`.
