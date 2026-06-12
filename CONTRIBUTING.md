# Contributing to ramen-cve

Thanks for considering a contribution! This project aims to deliver the
working core of a CTI / threat-hunting program on a ramen budget — small
enough for one person to hold in their head, useful enough that security
teams recommend it. Contributions that respect that spirit are very welcome.

This guide covers everything: setup, standards, the verification gate, and
the kinds of contributions we need most. For user-facing docs (install,
usage, configuration), start with the [README](README.md).

---

## Ways to contribute

You don't have to write Python to help:

| Contribution | Where | Notes |
| --- | --- | --- |
| **Bug reports** | [Issues](https://github.com/cesiumskater/cti-cth-ramen-budget/issues) | Use the bug template; include command + output |
| **Code** (features, fixes) | PRs | See the workflow below; check [`docs/ROADMAP.md`](docs/ROADMAP.md) for priorities |
| **CTI data** (associations, feeds) | PRs / issues | Correct or extend `src/ramen_cve/data/associations.json`, suggest feeds for `examples/community-feeds.opml` — public sources only, cite them |
| **Plugins** | Your own repo / `examples/plugins/` | Custom enrichers and output writers — see "Plugins" in the README |
| **Parsers / enrichers** | PRs | New input formats or free enrichment sources |
| **Tests** | PRs | Edge cases, regression coverage |
| **Docs** | PRs | Clarity fixes, examples, translations |

Good first issues are labelled
[`good first issue`](https://github.com/cesiumskater/cti-cth-ramen-budget/labels/good%20first%20issue);
the prioritized backlog lives in [`docs/ROADMAP.md`](docs/ROADMAP.md) and
[`tasks/todo.md`](tasks/todo.md).

---

## Development setup

```bash
git clone https://github.com/cesiumskater/cti-cth-ramen-budget
cd cti-cth-ramen-budget
python -m venv .venv && source .venv/bin/activate   # or scripts/setup.sh
pip install -e ".[dev]"
```

Python **3.10+**. Dev tooling is deliberately minimal: `pytest` (bare — no
plugins) and `ruff` (lint + import order). Version pins live in
[`pyproject.toml`](pyproject.toml) and are mirrored in
[`config/requirements.txt`](config/requirements.txt) /
[`config/requirements-dev.txt`](config/requirements-dev.txt).

---

## The verification gate (required for every PR)

```bash
pytest tests/ -q                                                   # full suite green
ruff check threat_intel_hunter.py conftest.py src/ tests/ scripts/ # lint clean
python scripts/regen_examples.py --check                           # byte-oracle rc=0
```

The byte-oracle regenerates the committed showcase artefacts
(`examples/sample-output.csv`, `examples/sample-report.md`,
`examples/_web-sample/`) in a temp dir and byte-compares — it catches
accidental output drift. If your change *intentionally* alters output shape,
regenerate and commit the bundle in the same PR:
`python scripts/regen_examples.py`.

CI runs the same three checks plus an import-style guard. Two additional CI
jobs are **advisory** (they don't block merges): `mypy` type-checking and
`pip-audit` dependency scanning. Type hints are required on every function
signature for readability, but mypy-strictness is not enforced — see the
roadmap.

---

## Project conventions (the short version)

These are non-negotiable; the long version lives in
[`docs/CLAUDE.md`](docs/CLAUDE.md) (which also serves as the rule file for
AI coding assistants — humans and bots follow the same rules here).

1. **Five-runtime-dependency budget.** `requests`, `feedparser`,
   `python-dotenv`, `questionary`, `PyYAML`. Adding a sixth requires a
   written justification in `tasks/todo.md` and maintainer sign-off.
   Optional integrations belong behind extras or plugins, not core deps.
2. **Layered package.** Modules sit on layers L0–L5 under
   `src/ramen_cve/`; imports point downward only.
   `src/ramen_cve/__init__.py` is a pure re-export façade with a locked
   `__all__` — never remove a re-export without updating
   `tests/test_facade.py` (additions are fine; removals are breaking).
3. **Thin vertical slices.** Land features in small, reviewable steps,
   each with tests and a verification story. Big-bang PRs will be asked
   to split.
4. **Fail soft.** A failed network enrichment logs a warning and
   continues; it never aborts the run.
5. **Determinism.** Output writers must be byte-stable for fixed inputs
   and a fixed clock. New writers need a determinism test (write twice,
   compare bytes).
6. **No secrets anywhere.** Keys come from env/`.env` only, are redacted
   from logs, and never reach artefacts or the cache.
7. **Style.** Ruff (line length 100, rules `E,F,W,I,UP,B,SIM`); type
   hints + docstrings on every function; `logging` to stderr, final
   artefact paths to stdout.

---

## Pull-request workflow

1. **Open or find an issue first** for anything non-trivial, so the
   approach can be agreed before you invest time.
2. Fork / branch from `main`.
3. Make the change in a thin slice with tests.
4. Run the full verification gate (above).
5. Update the [README](README.md) if behaviour is user-visible, and add a
   `CHANGELOG.md` entry under **[Unreleased]**.
6. Open the PR using the template. Describe **what changed and how you
   verified it** — the verification story is reviewed as seriously as the
   diff.

Commit messages: conventional-style prefixes (`feat:`, `fix:`, `docs:`,
`test:`, `chore:`) with an imperative subject line. Atomic commits beat
"misc fixes" bundles.

### Review expectations

- The maintainer reviews for correctness, scope, convention fit, and the
  verification story.
- CI must be green (the advisory jobs may be red without blocking, but
  please glance at them).
- Be patient — this is a free-time project. Pinging after a week is fine.

---

## Contributing CTI data

The bundled lookup data (`src/ramen_cve/data/associations.json`) maps CVEs
to threat actors, campaigns, malware families, and targeted sectors. To add
or correct an entry:

- **Cite public sources** (MITRE ATT&CK Groups pages, vendor reports,
  CISA advisories) in the PR description.
- No proprietary, paywalled, or TLP-restricted intel — everything bundled
  must be shareable under MIT.
- Keep the schema identical to existing entries; tests validate the file
  parses and round-trips.

Feed suggestions for `examples/community-feeds.opml`: stable, reputable,
HTTPS, security-relevant RSS/Atom feeds only.

---

## Release process (maintainers)

1. Move `CHANGELOG.md` **[Unreleased]** entries under a new version
   heading; bump `version` in `pyproject.toml` **and** `VERSION` in
   `src/ramen_cve/cli.py` (they must match — `tests/` will tell you).
2. Run the full verification gate.
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. The `release`
   workflow builds the sdist/wheel and drafts a GitHub Release with the
   artefacts attached.
4. PyPI publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/);
   the workflow's `pypi` job activates once the PyPI project is configured
   for it (see comments in `.github/workflows/release.yml`).

Versioning is [semantic](https://semver.org/): breaking CLI/output changes
bump major, features minor, fixes patch.

---

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Be excellent to each other — analysts have enough hostile actors to deal
with already.
