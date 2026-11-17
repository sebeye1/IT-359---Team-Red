"""
menu.py - The short menu: practice lab, full demo, or your own target. It builds ordinary main.py
argument lists, so everything it does can also be typed on the command line.
"""

from __future__ import annotations

import os
import shlex

from webrecon.interactive.helpers import REPORTS, has_flag, pick_lab_port, strip_flags
from webrecon.interactive.prompts import ask, ask_choice


def run_all(runner, runs: list[list[str]]) -> int:
    """Run each argument list through the runner, showing the equivalent command line."""
    code = 0
    for n, argv in enumerate(runs, 1):
        step = f" (step {n} of {len(runs)})" if len(runs) > 1 else ""
        print(f"\n[*] Running{step}: python main.py {shlex.join(argv)}")
        code = max(code, runner(argv))
    return code


MENU = [
    "Practice lab, vulnerable version",
    "Practice lab, hardened version",
    "Practice lab, before AND after hardening (full demo with a comparison)",
    "My own target(s)",
    "Quit",
]


def choose_scan(raw: list[str]) -> list[list[str]] | None:
    """Ask what to scan. `raw` holds options the user already gave (kept as they are).
    Returns the argument lists to run, or None if the user quits."""
    default = 2 if has_flag(raw, "--hardened-lab") else 1
    choice = ask_choice("What would you like to scan?", MENU, default)
    if choice == 5:
        return None
    if choice == 4:
        argv = _own_target(raw)
        return [argv] if argv else None

    raw = strip_flags(raw, switches=("--auto-lab", "--hardened-lab"))
    target = f"http://127.0.0.1:{pick_lab_port()}"
    if choice == 3:
        raw = strip_flags(raw, valued=("-o", "--output", "--json"))
        before, after = f"{REPORTS}/before", f"{REPORTS}/after"
        return [
            [target, "--auto-lab", "-o", f"{before}.html", "--json", f"{before}.json"] + raw,
            [target, "--auto-lab", "--hardened-lab", "-o", f"{after}.html", "--json", f"{after}.json"] + raw,
            ["--compare", f"{before}.json", f"{after}.json", "-o", f"{REPORTS}/comparison.html", "--open"],
        ]
    argv = [target, "--auto-lab"] + (["--hardened-lab"] if choice == 2 else []) + raw
    return [argv if has_flag(raw, "--open") else argv + ["--open"]]


def _own_target(raw: list[str]) -> list[str] | None:
    entry = ask("Target URL(s) separated by spaces, or a text file listing them (Enter to cancel)")
    if not entry:
        return None
    argv = (["--targets-file", entry] if os.path.isfile(entry) else entry.split()) + raw
    if not has_flag(raw, "--cookie"):
        cookie = ask("Session cookie if the site needs a login, e.g. session=abc123 (Enter to skip)")
        if cookie:
            argv += ["--cookie", cookie]
    return argv if has_flag(raw, "--open") else argv + ["--open"]
