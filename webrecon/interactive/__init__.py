"""
webrecon.interactive - The two guided ways in: the walkthrough and the short menu.

    walkthrough.py   a guided tour with a live before/after demo
    menu.py          one short menu: practice lab, full demo, or your own target
    prompts.py       asking questions in the terminal
    helpers.py       lab ports and argument-list editing

Both only build ordinary main.py argument lists and hand them to a runner (the CLI's main), so
everything they do can also be typed on the command line.
"""

from __future__ import annotations

from webrecon.interactive.menu import choose_scan, run_all
from webrecon.interactive.prompts import Quit
from webrecon.interactive.walkthrough import run_walkthrough


def start(runner, mode: str = "walkthrough", raw: list[str] | None = None) -> int:
    """mode is 'walkthrough' or 'menu'. `raw` is the options already given (menu mode keeps them)."""
    try:
        if mode == "walkthrough":
            return run_walkthrough(runner)
        runs = choose_scan(raw or [])
        if runs is None:
            print("[-] Nothing to run.")
            return 0
        return run_all(runner, runs)
    except (Quit, KeyboardInterrupt, EOFError):
        print("\n[-] Cancelled.")
        return 1
