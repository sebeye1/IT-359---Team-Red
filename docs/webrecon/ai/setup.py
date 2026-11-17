"""
setup.py - `--ai-setup`: save the API key once, safely.

The key is typed with hidden input and saved in a private file outside any project (see envfile.py), readable only
by you, so it can never be committed to git by accident. The key is never printed.
"""

from __future__ import annotations

import getpass
import sys

from webrecon.ai import envfile
from webrecon.errors import UserError


def run_setup(ask_key=None, path: str | None = None) -> str:
    """Ask for the key and save it. Returns the path of the file it was saved in."""
    if not sys.stdin.isatty():
        raise UserError("--ai-setup needs a terminal to type the key into. Without one, set WEBRECON_AI_KEY in the "
                        "environment instead.")
    path = path or envfile.setup_path()
    ask_key = ask_key or getpass.getpass   # looked up now, not at import, so it can be replaced in tests
    print(f"Your API key will be saved in:\n    {path}\n"
          "That file is outside your project and readable only by you, so it cannot end up on GitHub by accident.\n")
    key = ask_key("API key (typing is hidden): ").strip()
    if not key:
        raise UserError("No key entered, so nothing was saved.")
    if len(key) < 8 or any(c.isspace() for c in key):
        raise UserError("That does not look like an API key (too short, or it contains spaces), so nothing was saved.")
    envfile.write_value(path, "WEBRECON_AI_KEY", key)
    return path
