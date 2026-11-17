"""
storage.py - Where the AI feature keeps its small local files: the ATT&CK technique list and cached answers.

Default folder: ~/.cache/webrecon (on Windows: %LOCALAPPDATA%\\webrecon). Set WEBRECON_CACHE_DIR to change it.
"""

from __future__ import annotations

import json
import os


def cache_dir() -> str:
    explicit = os.environ.get("WEBRECON_CACHE_DIR")
    if explicit:
        return explicit
    if os.name == "nt":
        return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "webrecon")
    return os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "webrecon")


def read_json(name: str) -> dict | None:
    """The saved JSON object called `name`, or None if it is missing or unreadable."""
    try:
        with open(os.path.join(cache_dir(), name), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json(name: str, data: dict) -> str:
    """Save `data` as `name`. Written to a temporary file first, so an interrupted write cannot corrupt it."""
    folder = cache_dir()
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(temporary, path)
    return path
