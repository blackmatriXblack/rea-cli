"""Entry point for the offline REA-compatible CLI (packaged as rea.exe)."""

from __future__ import annotations

import os
import sys


def _ensure_package_root() -> None:
    if getattr(sys, "frozen", False):
        return
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


_ensure_package_root()

from rea_core.cli import main  # noqa: E402  (path setup must run first)


if __name__ == "__main__":
    raise SystemExit(main())
