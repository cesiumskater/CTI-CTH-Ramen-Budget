# Security Policy

`ramen-cve` is defensive-security tooling. We take its security posture
seriously — for the analysts who run it, for the secrets they hand it, and
for the artefacts it produces.

## Supported versions

Until v1.0, only the **latest released minor** receives security updates.

| Version | Supported |
| --- | --- |
| 0.2.x (current) | ✅ |
| < 0.2 | ❌ — please upgrade |

After v1.0, the **two most recent minors** will receive security backports.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.** Use one
of the private channels below; we will acknowledge within **3 business
days** and aim for a fix or mitigation within **30 days** of confirmation.

### Preferred: GitHub private vulnerability reporting

Go to the [Security tab → Report a vulnerability](https://github.com/cesiumskater/cti-cth-ramen-budget/security/advisories/new).
This creates a private advisory only the maintainer can see.

### Alternative: e-mail

Mail the maintainer at the address in the
[`pyproject.toml`](pyproject.toml) `[project] authors` block. Encrypt with
[age](https://github.com/FiloSottile/age) if the report contains live IOCs
or PoC payloads — a public age recipient key is published on the
maintainer's GitHub profile.

### What to include

- A clear description of the issue and its impact.
- Steps to reproduce (a minimal repro is ideal — a YAML preset + an
  invocation, or a CVE input file).
- The affected version (`ramen-cve --version` or the tag/commit).
- Whether the issue is currently being exploited in the wild — if so, lead
  with that.

## Disclosure process

1. You report privately (above).
2. Maintainer confirms receipt within 3 business days.
3. We work on a fix in a private branch and prepare release notes.
4. Coordinated public disclosure on release, crediting the reporter unless
   you ask to remain anonymous.
5. A GitHub Security Advisory is published.

## Scope

In scope:

- Code execution in any input parser (OPML, STIX bundle, URL crawler,
  inventory CSV).
- Secret leakage to logs, artefacts, the cache, or any dispatch sink.
- Path traversal in hunt / PIR IDs, output basenames, `--out-dir`,
  `--site-dir`, or YAML preset names.
- SSRF / scheme-confusion in URL-mode or TAXII pulls.
- Spreadsheet formula injection in any generated CSV (see PR #46 for the
  baseline mitigation).
- Cache poisoning of the SQLite store across runs.
- Authentication / authorization gaps in any dispatch or web mode.
- Crashes that an attacker can reach with crafted input.

Out of scope (please don't waste each other's time):

- Issues only reachable with a malicious YAML preset the user wrote
  themselves and explicitly loaded.
- Behaviour requiring a malicious local user with write access to the
  user's `.env` or cache file.
- Findings from automated scanners without a working exploit.
- Denial of service via genuinely huge inputs (we'd treat that as a perf
  bug — open a normal issue).

## Cryptographic / sensitive material

This project never accepts:

- Real, non-public CTI (live IOCs, victim names, TLP:AMBER+ material) in
  bug reports, tests, or PRs. Use anonymised / public-source equivalents.
- API keys in any committed file. The pre-commit verification gate plus CI
  secret scanning (`gitleaks`) catches accidental leaks; if you spot one,
  follow the disclosure process above.

## Hall of fame

Reporters who follow this policy and consent will be acknowledged here
after disclosure.

*(none yet)*
