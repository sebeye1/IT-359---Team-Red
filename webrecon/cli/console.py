"""
console.py - What WebRecon prints: the banner, colours, scan results, summaries and tips.
"""

from __future__ import annotations

import argparse
import os
import sys

from webrecon.analysis import CHECK_CATALOG
from webrecon.scanning import Scanner

BANNER = r"""
 __        __   _     ____
 \ \      / /__| |__ |  _ \ ___  ___ ___  _ __
  \ \ /\ / / _ \ '_ \| |_) / _ \/ __/ _ \| '_ \
   \ V  V /  __/ |_) |  _ <  __/ (_| (_) | | | |
    \_/\_/ \___|_.__/|_| \_\___|\___\___/|_| |_|
   IT 359 Team Red - Web Recon & Misconfiguration Scanner
"""
SEVERITY_ANSI = {"Critical": "35", "High": "31", "Medium": "33", "Low": "36", "Info": "34"}

_banner_shown = False


def show_banner() -> None:
    """Print the banner once per run, even when one run performs several scans."""
    global _banner_shown
    if not _banner_shown:
        if os.name == "nt":
            os.system("")  # switches the Windows console into ANSI-colour mode
        print(BANNER)
        _banner_shown = True


def paint(text: str, severity: str) -> str:
    """Colour text by severity when writing to a real terminal (honours NO_COLOR)."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb" or not sys.stdout.isatty():
        return text
    return f"\033[{SEVERITY_ANSI.get(severity, '0')}m{text}\033[0m"


def print_checks() -> None:
    print(f"\nWebRecon checks ({len(CHECK_CATALOG)}):\n")
    for check_id, severity, title in CHECK_CATALOG:
        print(f"  {check_id}  {severity:<12} {title}")
    print("\nHide any of them with --ignore, for example: --ignore WR-014,WR-091")


def print_unreachable(scanner: Scanner, args: argparse.Namespace) -> None:
    result = scanner.result
    print(f"[-] Could not reach {scanner.target}.")
    for note in result.notes:
        print(f"    {note}")
    for hint in result.hints:
        print(f"    Why: {hint}")
    if args.verbose:
        for err in result.errors:
            print(f"    Detail: {err}")
    else:
        print("    (add -v for the technical details)")


def print_result(result, findings, counts: dict, args: argparse.Namespace) -> None:
    summary = ", ".join(f"{k} {v}" for k, v in counts.items())
    if args.quiet:
        print(f"{result.final_url}: {len(findings)} finding(s) ({summary})")
        return
    print(f"[+] {result.final_url} responded {result.status_code}")
    for remark in result.notes + result.hints:
        print(f"[i] {remark}")
    print(f"[+] Crawled {len(result.pages)} page(s), {len(result.forms)} form(s), {len(result.cookies)} cookie(s)"
          f" ({result.requests_made} requests in {result.duration:g}s)")
    print(f"[+] {len(findings)} finding(s): {summary}")
    if result.trend:
        t = result.trend
        print(f"[+] Since your previous scan ({t['since']}): {t['fixed']} fixed, {t['new']} new, "
              f"{t['still_open']} still open")
    for f in findings:
        score = ((f.enrichment or {}).get("cvss") or {}).get("score")
        estimate = f"  (CVSS ~{score:.1f})" if isinstance(score, (int, float)) else ""
        print(f"    {paint(f'[{f.severity:<8}]', f.severity)} {f.check_id}  {f.title}{estimate}")


def print_overview(entries: list[dict]) -> None:
    print("\n=== Summary ===")
    width = max(len(e["target"]) for e in entries)
    for e in entries:
        detail = ", ".join(f"{k} {v}" for k, v in e["counts"].items() if v) or "no findings"
        print(f"  {e['target']:<{width}}  {detail if e['ok'] else 'UNREACHABLE'}")


def next_steps(findings) -> list[str]:
    lines = []
    urgent = [f for f in findings if f.severity != "Info"][:3]
    if urgent:
        lines.append("Fix first: " + "; ".join(f"{f.check_id} {f.title} ({f.severity})" for f in urgent))
    lines.append("After fixing, scan again, then run: python main.py --compare")
    return lines
