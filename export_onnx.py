#!/usr/bin/env python3
"""Thin wrapper: export 1dcnn weights to ONNX (uses ../1dcnn)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ONEDCNN = ROOT.parent / "1dcnn"


def main() -> int:
    script = ONEDCNN / "export_onnx.py"
    if not script.is_file():
        print(f"Missing {script}", file=sys.stderr)
        return 1
    cmd = [sys.executable, str(script), *sys.argv[1:]]
    return subprocess.call(cmd, cwd=str(ONEDCNN))


if __name__ == "__main__":
    raise SystemExit(main())
