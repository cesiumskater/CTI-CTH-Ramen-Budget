#!/usr/bin/env python3
"""threat-intel-hunter / ramen-cve CLI bootstrap.

This file is the user-facing executable. Its only job is to make the
``ramen_cve`` package importable when the repo hasn't been pip-installed,
then hand off to :func:`ramen_cve.main`. Three equivalent invocations:

    python threat_intel_hunter.py opml feeds.opml   # uses this shim
    python -m ramen_cve opml feeds.opml             # src/ramen_cve/__main__.py
    ramen-cve opml feeds.opml                       # after `pip install -e .`

All three paths reach the same :func:`ramen_cve.main` entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Prepend src/ so an editable / uninstalled checkout still resolves the
# package. Insert at position 0 so we beat any other on-path copy.
_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ramen_cve import main  # noqa: E402 — sys.path tweak must come first

if __name__ == "__main__":
    sys.exit(main())
