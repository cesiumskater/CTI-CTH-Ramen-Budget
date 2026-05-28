# Software Bill of Materials (SBOM)

> **Scope.** Supply-chain inventory for `ramen-cve`. For everything else
> (install, usage, configuration), start with [`README.md`](../README.md).

**Project:** ramen-cve / threat-intel-hunter
**Document version:** 1.1
**Generated:** 2026-05-12 (revised 2026-05-28)
**Format:** human-readable Markdown (a machine-readable CycloneDX export can be
produced with `pip install cyclonedx-bom && cyclonedx-py environment`).

This SBOM lists every component that ships in, or is required to run/develop,
the project. The tool itself is pure first-party Python (one package,
`ramen_cve`, plus a thin root entry-point shim). No vendored third-party
source is bundled — only the runtime wheels resolved from PyPI.

---

## 1. First-party components

| Component | Path | License | Notes |
| --- | --- | --- | --- |
| `ramen_cve` (package) | `src/ramen_cve/` (~30 focused modules; `__init__.py` is a re-export façade with a locked `__all__`) | MIT | The entire implementation. |
| `threat_intel_hunter.py` | repo root | MIT | 10-line entry-point shim → `ramen_cve.main()`. |
| Bundled lookup data | `src/ramen_cve/data/associations.json`, `data/hunts/*`, `data/pirs/*` | MIT | Curated CVE → actor/campaign/malware map + sample hunt + sample PIR. Sourced from public MITRE ATT&CK Groups data and public reporting; no proprietary intel. |
| YAML config template + presets | `src/ramen_cve/config/config.yaml`, `config/presets/` | MIT | Documented configuration schema. |

---

## 2. Runtime dependencies (direct)

Declared in `pyproject.toml` `[project.dependencies]` and mirrored in
`config/requirements.txt`. Pins are floor-and-ceiling ranges (`>=X,<Y`).

| Package | Resolved version | License | Purpose | Source |
| --- | --- | --- | --- | --- |
| requests | 2.33.1 | Apache-2.0 | All HTTP I/O (NVD, EPSS, CISA KEV, Exploit-DB, Nuclei, GitHub, VirusTotal, AbuseIPDB, OTX, MalwareBazaar, TAXII, Slack/webhook). | PyPI |
| feedparser | 6.0.12 | BSD-2-Clause | RSS/Atom parsing for OPML-listed feeds. | PyPI |
| python-dotenv | 1.2.2 | BSD-3-Clause | Loads `.env` API keys / SMTP secrets at startup. | PyPI |
| questionary | 2.1.1 | MIT | Interactive no-args setup wizard. | PyPI |
| PyYAML | 6.0.3 | MIT | YAML config preset load/save (`--config` / `--save-config`). | PyPI |

---

## 3. Runtime dependencies (transitive)

Pulled in automatically by the direct dependencies above.

| Package | Resolved version | License | Pulled in by |
| --- | --- | --- | --- |
| urllib3 | 2.6.3 | MIT | requests |
| certifi | 2026.4.22 | MPL-2.0 | requests (CA bundle) |
| charset-normalizer | 3.4.7 | MIT | requests |
| idna | 3.13 | BSD-3-Clause | requests |
| sgmllib3k | 1.0.0 | BSD-2-Clause | feedparser |
| prompt_toolkit | 3.0.52 | BSD-3-Clause | questionary |
| wcwidth | 0.7.0 | MIT | prompt_toolkit |

---

## 4. Development-only dependencies

Declared in `pyproject.toml` `[project.optional-dependencies] dev` and
`config/requirements-dev.txt`. Not shipped to runtime users.

| Package | Resolved version | License | Purpose |
| --- | --- | --- | --- |
| pytest | 9.0.3 | MIT | 778-case test suite. |
| ruff | 0.15.12 | MIT | Lint + import-sort gate (rules E,F,W,I,UP,B,SIM). |

---

## 5. Python standard library used (no install required)

Significant stdlib modules the tool relies on for security-relevant logic:

`argparse`, `csv`, `dataclasses`, `datetime`, `getpass` (audit actor),
`hashlib` (deterministic STIX UUIDs), `ipaddress` (public-IP filtering),
`json`, `logging`, `math` (IOC confidence decay), `pathlib`, `re`,
`smtplib` + `email.mime` (digest email), `sqlite3` (cache + runs + audit
log), `urllib.parse` (URL redaction), `xml.etree.ElementTree` /
`xml.sax.saxutils` (OPML parse + Task Scheduler XML).

---

## 6. Network endpoints contacted at runtime

Not "components" but part of the supply-chain trust surface. All are
opt-in / gated and degrade gracefully on failure.

| Endpoint | When | Auth |
| --- | --- | --- |
| `services.nvd.nist.gov` | every CVE enrichment | `NVD_API_KEY` header (optional) |
| `api.first.org` (EPSS) | every CVE enrichment | none |
| `www.cisa.gov` (KEV catalog) | every run | none |
| `gitlab.com` (Exploit-DB mirror) | exploit lookup | none |
| `api.github.com` (Nuclei tree + repo search) | exploit lookup | `GITHUB_TOKEN` (optional) |
| `www.virustotal.com` | IOC enrichment | `VT_API_KEY` |
| `api.abuseipdb.com` | IOC enrichment | `ABUSEIPDB_API_KEY` |
| `otx.alienvault.com` | IOC enrichment | `OTX_API_KEY` |
| `mb-api.abuse.ch` (MalwareBazaar) | IOC enrichment | none |
| user-supplied TAXII root | `stix` subcommand | optional basic auth |
| user-supplied Slack / webhook / SMTP | `--dispatch` / `--digest` | per-service |

---

## 7. Integrity & provenance notes

- All third-party packages are installed from PyPI over TLS via pip; no
  custom index or vendored binaries.
- The tool writes no executable code at runtime — generated artefacts are
  CSV / Markdown / STIX JSON / Sigma+YARA *stubs* (inert text) / Task
  Scheduler XML / crontab lines.
- Secrets (`NVD_API_KEY`, SMTP creds, tokens) are read from environment /
  `.env` only, redacted from logs (`_redact_key`, `_redact_audit_args`),
  and never written to any output artefact or the SQLite cache.
- License compatibility: every dependency is under a permissive license
  (MIT / BSD / Apache-2.0 / MPL-2.0) compatible with the project's MIT
  license. No copyleft (GPL/AGPL) components.
