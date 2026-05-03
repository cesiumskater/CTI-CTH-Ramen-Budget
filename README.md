# CTI-CTH-Ramen-Budget

Companion code for the BSidesSLC 2026 talk *Threat Intel on a Ramen Budget* by Danny Page ([@cesiumskater](https://github.com/cesiumskater)).

A single-file Python tool that takes an OPML file, a single URL, or a list of CVE IDs as input; enriches each CVE with CVSS data from NVD and exploitation probability from FIRST.org's EPSS; and produces both a CSV (for IOC trackers) and a Markdown report (for human review) with prioritized actions per CVE.

## Status

Under active development. See `tasks/todo.md` for the implementation plan.

## Setup

**Linux / Kubuntu:**

```bash
chmod +x setup.sh
./setup.sh
```

**Windows 11 Pro (PowerShell):**

```powershell
.\setup.ps1
```

After setup, edit `.env` and paste your free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key).

## Documentation

- `CLAUDE.md` — operating principles and project-specific stack
- `tasks/todo.md` — phased implementation plan
- `tasks/lessons.md` — accumulated learnings during development

## License

MIT — see `LICENSE`.
