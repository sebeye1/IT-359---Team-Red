"""Helpers for starting the practice lab on demand (used by the command line and the interactive modes)."""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from webrecon.lab.vulnerable_lab import start_background

LAB_HOSTS = ("localhost", "127.0.0.1")  # the lab only ever binds 127.0.0.1


def port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def ensure_local_server(target: str, hardened: bool):
    """If the target is a local http:// address and nothing is listening, start the lab there.
    Returns the server (so the caller can shut it down) or None if nothing was started."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname or ""
    if host not in LAB_HOSTS or parsed.scheme != "http":
        return None
    port = parsed.port or 80
    if port_open("127.0.0.1", port):
        print(f"[*] Server already listening on {host}:{port}, using it.")
        return None
    try:
        server = start_background(port, hardened)
    except OSError as exc:  # for example port 80 needs administrator rights
        print(f"[-] Could not start lab on port {port}: {exc}")
        return None
    print(f"[+] No server found, started {'HARDENED' if hardened else 'VULNERABLE'} lab on http://127.0.0.1:{port}")
    return server
