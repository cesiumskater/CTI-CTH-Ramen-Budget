"""Allow ``python -m ramen_cve …`` to run the CLI.

The actual CLI lives in :func:`ramen_cve.main`; this module exists so the
package can be invoked with the standard ``-m`` runner regardless of where
the user is in the filesystem.
"""

from __future__ import annotations

import sys

from . import main

if __name__ == "__main__":
    sys.exit(main())
