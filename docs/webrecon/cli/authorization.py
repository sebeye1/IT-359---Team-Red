"""
authorization.py - The "do you have permission to test this?" question for non-local targets.
"""

from __future__ import annotations

from urllib.parse import urlparse

from webrecon.scanning import is_loopback


def host_of(target: str) -> str:
    return urlparse(target if "://" in target else "http://" + target).hostname or ""


def confirm_authorization(targets, assume_yes: bool) -> bool:
    """One question covers every non-local target. Local targets never ask."""
    if isinstance(targets, str):
        targets = [targets]
    remote = sorted({host_of(t) for t in targets if not is_loopback(host_of(t))})
    if not remote or assume_yes:
        return True
    if len(remote) == 1:
        print(f"[!] Target {remote[0]} is not a local address.")
        question = "[?] Do you have explicit authorization to test this target? (yes/no): "
    else:
        print("[!] These targets are not local addresses:")
        print("".join(f"      {host}\n" for host in remote), end="")
        question = "[?] Do you have explicit authorization to test ALL of them? (yes/no): "
    try:
        return input(question).strip().lower() in ("y", "yes")
    except EOFError:
        print("\n[-] No answer received. Add -y to confirm authorization non-interactively.")
        return False
