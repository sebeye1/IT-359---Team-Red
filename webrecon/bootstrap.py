"""
bootstrap.py - Make sure WebRecon's packages are available before it starts.

Uses only the standard library, because it runs before anything else is imported. If `requests` or
`beautifulsoup4` is missing it either switches to the project's .venv, offers to create one, or explains
the one-line fix, instead of failing with a traceback. Switching to an existing .venv is silent.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

REQUIRED = {"requests": "requests", "bs4": "beautifulsoup4"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the project folder
FIX = "    Fix: run ./run.sh (Windows: run.bat), which sets everything up, or: pip install -r requirements.txt"


def missing_packages() -> list[str]:
    return [pkg for mod, pkg in REQUIRED.items() if importlib.util.find_spec(mod) is None]


def venv_python() -> str | None:
    for parts in ((".venv", "bin", "python"), (".venv", "Scripts", "python.exe")):
        path = os.path.join(ROOT, *parts)
        if os.path.exists(path):
            return path
    return None


def running_in_project_venv() -> bool:
    """True if this interpreter is the project's .venv. (Comparing interpreter paths is not enough: a
    venv's python is a symlink to the same base interpreter as every other venv's.)"""
    return os.path.realpath(sys.prefix) == os.path.realpath(os.path.join(ROOT, ".venv"))


def _run_again_with(python: str, announce: bool = True) -> None:
    if announce:
        print(f"[*] Using the project's virtual environment ({python}).")
    raise SystemExit(subprocess.call([python, os.path.join(ROOT, "main.py")] + sys.argv[1:]))


def _set_up_venv() -> str:
    """Create .venv if needed and install the requirements into it. Returns its Python, or exits."""
    python = venv_python()
    if python is None:
        print("[setup] Creating a virtual environment in .venv ...")
        if subprocess.run([sys.executable, "-m", "venv", os.path.join(ROOT, ".venv")]).returncode != 0:
            print("[!] Could not create a virtual environment. On Debian/Ubuntu: sudo apt install python3-venv")
            raise SystemExit(1)
        python = venv_python()
    print("[setup] Installing requirements ...")
    if subprocess.run([python, "-m", "pip", "install", "-r", os.path.join(ROOT, "requirements.txt")]).returncode != 0:
        print("[!] Installing the requirements failed. Check your internet connection and try again.")
        raise SystemExit(1)
    open(os.path.join(ROOT, ".venv", ".installed"), "w").close()  # lets run.sh skip a second install
    return python


def ensure_dependencies() -> None:
    missing = missing_packages()
    if not missing:
        return
    existing = venv_python()
    if (existing and not running_in_project_venv()
            and subprocess.run([existing, "-c", "import requests, bs4"], capture_output=True).returncode == 0):
        _run_again_with(existing, announce=False)  # a working environment exists: switch to it quietly
    print(f"[!] WebRecon needs {', '.join(missing)}, which this Python ({sys.executable}) does not have.")
    if sys.stdin.isatty() and os.path.exists(os.path.join(ROOT, "requirements.txt")):
        answer = input("    Set up a virtual environment (.venv) and install them now? (Y/n): ")
        if answer.strip().lower() in ("", "y", "yes"):
            _run_again_with(_set_up_venv())
    print(FIX)
    raise SystemExit(1)
