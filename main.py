"""PyRE Studio - All-in-One Python Reverse Engineering Desktop Toolkit.

Application Entry Point.
"""

from __future__ import annotations

import sys
from app.bootstrap import run


def main() -> None:
    """Launch PyRE Studio desktop application."""
    exit_code = run(sys.argv)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
