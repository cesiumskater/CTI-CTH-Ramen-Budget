"""ramen_cve.render — small pure rendering helpers (Layer-1 leaf).

Houses primitives that need to be callable from both Layer-3 output
writers (`output/markdown.py`) and Layer-4 surfaces (`trend.py`).
Living in a lower layer keeps the arrows pointing downward and avoids
an `output/` → `trend.py` (L3 → L4) violation; see
the layered design in README.md and src/ramen_cve/__init__.py.

Pure stdlib only. No first-party imports.
"""

from __future__ import annotations

_SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[float | None]) -> str:
    """Render a list of numbers as a unicode sparkline; None renders as a space.

    Original home: `trend.py`. Lifted to this leaf module so the Markdown
    writer can reuse it for EPSS-trajectory rendering without an upward
    import.
    """
    real = [v for v in values if v is not None]
    if not real:
        return ""
    lo, hi = min(real), max(real)
    span = hi - lo if hi > lo else 1.0
    out: list[str] = []
    for v in values:
        if v is None:
            out.append(" ")
            continue
        idx = int(((v - lo) / span) * (len(_SPARKLINE_CHARS) - 1))
        out.append(_SPARKLINE_CHARS[max(0, min(idx, len(_SPARKLINE_CHARS) - 1))])
    return "".join(out)
