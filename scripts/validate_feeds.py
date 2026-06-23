#!/usr/bin/env python3
"""Structural validator for ramen-cve OPML bundles.

Run on every commit (via the new CI job) to catch malformed OPML, non-HTTPS
feed URLs, and missing required attributes in the committed
``examples/*.opml`` files. Stdlib only — no network access, deterministic,
fast (<1s on the bundled feeds).

Usage:
    python scripts/validate_feeds.py                   # default set
    python scripts/validate_feeds.py path/to.opml ...  # explicit list

Exit codes: 0 if every file is clean, 1 on any structural violation. The
companion CONTRIBUTING.md section "Contributing CTI data" documents the
selection rules; this script enforces the *enforceable* subset of them.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Files validated when no explicit args are supplied.
DEFAULT_TARGETS: tuple[Path, ...] = (
    REPO_ROOT / "examples" / "sample.opml",
    REPO_ROOT / "examples" / "community-feeds.opml",
)

#: Outline `type=` values that name an actual feed (vs. a folder grouping).
_FEED_TYPES = frozenset({"rss", "atom"})


def _violations_for(path: Path) -> list[str]:
    """Return a list of human-readable violation strings for one OPML file.

    Empty list ⇒ the file passes. The walker is forgiving on irrelevant
    detail (extra attributes, nested grouping outlines, an empty <head>
    block) but strict on the rules selection in CONTRIBUTING.md enforces:
    HTTPS-only feed URLs, required ``text`` + ``xmlUrl`` on every feed
    outline.
    """
    violations: list[str] = []
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return [f"{path}: not well-formed XML ({exc})"]
    except FileNotFoundError:
        return [f"{path}: file not found"]

    root = tree.getroot()
    if root.tag != "opml":
        violations.append(f"{path}: root element is <{root.tag}>, expected <opml>")
        return violations

    body = root.find("body")
    if body is None:
        violations.append(f"{path}: missing <body> element")
        return violations

    feed_count = 0
    for outline in body.iter("outline"):
        otype = (outline.get("type") or "").strip().lower()
        if otype not in _FEED_TYPES:
            # Grouping outlines have no `type` (or a non-feed type); they're
            # the section headers in the OPML. Validate-by-skip.
            continue
        feed_count += 1
        text = (outline.get("text") or "").strip()
        url = (outline.get("xmlUrl") or "").strip()
        if not text:
            violations.append(
                f"{path}: feed outline missing required `text` attribute "
                f"(xmlUrl={url!r})"
            )
        if not url:
            violations.append(
                f"{path}: feed outline missing required `xmlUrl` attribute "
                f"(text={text!r})"
            )
            continue
        parsed = urlparse(url)
        if parsed.scheme != "https":
            violations.append(
                f"{path}: feed {text!r} uses scheme {parsed.scheme!r} "
                f"(xmlUrl={url!r}); HTTPS required"
            )
        if not parsed.netloc:
            violations.append(
                f"{path}: feed {text!r} xmlUrl has no host ({url!r})"
            )

    if feed_count == 0:
        violations.append(f"{path}: contains no rss / atom feed outlines")
    return violations


def main(argv: list[str] | None = None) -> int:
    """Driver. Returns the process exit code (0 OK, 1 on any violation)."""
    args = argv if argv is not None else sys.argv[1:]
    targets: list[Path] = (
        [Path(a) for a in args] if args else list(DEFAULT_TARGETS)
    )

    total = 0
    failing = 0
    all_violations: list[str] = []
    for target in targets:
        violations = _violations_for(target)
        total += 1
        if violations:
            failing += 1
            all_violations.extend(violations)
            print(f"FAIL {target}: {len(violations)} violation(s)", file=sys.stderr)
            for v in violations:
                print(f"  - {v}", file=sys.stderr)
        else:
            print(f"OK   {target}")

    if failing:
        print(
            f"\n{failing}/{total} OPML file(s) failed validation "
            f"({len(all_violations)} violation(s) total).",
            file=sys.stderr,
        )
        return 1
    print(f"\n{total}/{total} OPML file(s) clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
