"""Cross-platform dev bootstrap for local validation.

Usage:
  python scripts/bootstrap_dev.py
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], cwd: Path | None = None) -> int:
    print("$", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd) if cwd else None)


def main() -> int:
    print("Bootstrapping CyberShield-X dev/test environment")
    print("OS:", platform.system(), platform.release())
    print("Python:", sys.version.split()[0])

    pip_cmd = [sys.executable, "-m", "pip"]
    if run(pip_cmd + ["install", "-r", str(ROOT / "requirements-test.txt")]) != 0:
        return 1

    frontend = ROOT / "frontend"
    npm = shutil.which("npm")
    if npm and frontend.exists():
        run([npm, "ci"], cwd=frontend)
    else:
        print("[warn] npm not found; skipped frontend dependency install")

    cargo = shutil.which("cargo")
    if cargo:
        print("cargo detected:", cargo)
    else:
        print("[warn] cargo not found. Install Rust toolchain via https://rustup.rs/")

    print("Bootstrap complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
