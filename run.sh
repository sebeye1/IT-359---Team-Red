#!/usr/bin/env sh
# One-step launcher for macOS and Linux: on first use it creates a virtual environment (.venv) and
# installs the requirements, then runs WebRecon. Everything after ./run.sh is passed to main.py:
#
#     ./run.sh                        guided walkthrough
#     ./run.sh https://example.com    scan a site
set -e
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    echo "[!] WebRecon needs Python 3.9 or newer ('$PY' was not found or is too old)." >&2
    echo "    Install Python, or point to it with:  PYTHON=/path/to/python ./run.sh" >&2
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    echo "[setup] Creating a virtual environment in .venv (first run only)..."
    "$PY" -m venv .venv || { echo "[!] Could not create a virtual environment. On Debian/Ubuntu: sudo apt install python3-venv" >&2; exit 1; }
fi

# Install (or refresh) the requirements whenever requirements.txt is newer than the last install.
if [ ! -f .venv/.installed ] || [ requirements.txt -nt .venv/.installed ]; then
    echo "[setup] Installing requirements..."
    .venv/bin/python -m pip install --quiet -r requirements.txt
    touch .venv/.installed
fi

exec .venv/bin/python main.py "$@"
