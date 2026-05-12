"""pytest bootstrap.

Adds ``src/`` to :data:`sys.path` so ``import ramen_cve`` finds the package
without requiring a prior ``pip install -e .``. This mirrors what the root
``ramen.py`` shim does for end-users, so tests and direct invocations see
exactly the same package object.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
