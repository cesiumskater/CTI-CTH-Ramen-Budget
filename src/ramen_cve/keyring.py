"""ramen_cve.keyring — NVD API-key bootstrap + URL/key redaction.

Leaf module (stdlib only): interactive key prompt, .env persistence,
and log-safe URL redaction so secrets never reach logs. Used by the
network fetchers. See README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import contextlib
import re
import sys
import urllib.parse
from pathlib import Path


def _redact_key(url: str) -> str:
    """Replace the apiKey query parameter value with REDACTED."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if "apiKey" in qs:
        qs["apiKey"] = ["REDACTED"]
    safe_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=safe_query))


NVD_API_KEY_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
NVD_KEY_REQUEST_URL = "https://nvd.nist.gov/developers/request-an-api-key"
ENV_FILE_PATH = Path(".env")


def _is_interactive() -> bool:
    """True if both stdin and stderr are TTYs (so prompting makes sense)."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def _save_api_key_to_env(key: str, env_path: Path = ENV_FILE_PATH) -> None:
    """Persist NVD_API_KEY=<key> to a local .env file.

    If the file exists, replace any existing NVD_API_KEY line; otherwise
    append. The file is created with mode 0o600 so the key is not
    world-readable. Other variables already in .env are preserved.

    Raises ValueError if the key contains a newline, carriage return, or
    NUL byte. Without this guard, an attacker who controls the input
    could inject additional VAR=value lines into .env.
    """
    if any(ch in key for ch in ("\n", "\r", "\x00")):
        raise ValueError("API key contains illegal control characters; refusing to write .env.")
    new_line = f"NVD_API_KEY={key}\n"
    if env_path.exists():
        existing = env_path.read_text().splitlines(keepends=True)
        replaced = False
        out_lines: list[str] = []
        for line in existing:
            if line.strip().startswith("NVD_API_KEY="):
                out_lines.append(new_line)
                replaced = True
            else:
                out_lines.append(line)
        if not replaced:
            if out_lines and not out_lines[-1].endswith("\n"):
                out_lines[-1] += "\n"
            out_lines.append(new_line)
        env_path.write_text("".join(out_lines))
    else:
        env_path.write_text(new_line)
    with contextlib.suppress(OSError):
        env_path.chmod(0o600)  # Best-effort; some filesystems (e.g. Windows) don't support it.


def _prompt_for_api_key(reason: str = "missing") -> str | None:
    """Interactively ask the user for an NVD API key and save it to .env.

    `reason` is one of "missing" (no key on disk) or "expired" (server
    rejected the existing key). Returns the new key string, or None if
    the user declined to enter one.
    """
    if not _is_interactive():
        return None

    if reason == "expired":
        message = (
            "\nThe NVD API key currently in use was rejected by the server "
            "(likely expired or revoked)."
        )
    else:
        message = "\nNo NVD API key found in environment or .env file."
    print(message, file=sys.stderr)
    print(
        f"You can request a free key at: {NVD_KEY_REQUEST_URL}\n"
        "  - With a key: ~50 requests per 30s window (recommended)\n"
        "  - Without a key: ~5 requests per 30s window\n",
        file=sys.stderr,
    )

    try:
        import questionary

        action = questionary.select(
            "What would you like to do?",
            choices=[
                questionary.Choice("Enter a key now (saved to .env)", value="enter"),
                questionary.Choice("Continue without a key (slower)", value="skip"),
            ],
        ).unsafe_ask()
        if action != "enter":
            return None
        key = questionary.password(
            "Paste your NVD API key (input is hidden):",
            validate=lambda s: (
                True if NVD_API_KEY_REGEX.match(s.strip())
                else "Expected UUID format (8-4-4-4-12 hex chars)."
            ),
        ).unsafe_ask()
    except (KeyboardInterrupt, ImportError):
        return None

    if not key:
        return None
    key = key.strip()
    _save_api_key_to_env(key)
    print(f"Saved NVD_API_KEY to {ENV_FILE_PATH} (mode 0600).", file=sys.stderr)
    return key


def _safe_url_for_log(url: str) -> str:
    """Strip query string and fragment from a user-supplied URL before logging it.

    Arbitrary URLs may carry tokens, session IDs, or other secrets in the
    query string. We can't tell which params are sensitive, so the safest
    thing to log is scheme + host + path only.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return "<unparseable url>"
    sanitized = parsed._replace(query="", fragment="")
    rendered = urllib.parse.urlunparse(sanitized)
    if parsed.query or parsed.fragment:
        rendered += " (query/fragment redacted)"
    return rendered

