"""
helpers.py - Small helpers for the walkthrough and the menu: lab ports, and editing argument lists.
"""

from __future__ import annotations

import socket

from webrecon.interactive.prompts import ask_int

LAB_PORT = 8080
REPORTS = "reports"


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0


def pick_lab_port(default: int = LAB_PORT) -> int:
    """The default port, unless something else is using it. The lab needs a free port so it can
    control which version (vulnerable or hardened) is served."""
    port = default
    while not port_free(port):
        print(f"  Port {port} is already in use by another program.")
        port = ask_int("  Enter another port", port + 1)
    return port


def has_flag(raw: list[str], *names: str) -> bool:
    return any(tok == n or tok.startswith(n + "=") for tok in raw for n in names)


def strip_flags(raw: list[str], switches: tuple = (), valued: tuple = ()) -> list[str]:
    """Copy of raw without the given on/off flags, and without the given flags that take a value."""
    out, skip = [], False
    for tok in raw:
        if skip:
            skip = False
        elif tok in switches or any(tok.startswith(v + "=") for v in valued):
            continue
        elif tok in valued:
            skip = True
        else:
            out.append(tok)
    return out
