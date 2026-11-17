"""
walkthrough.py - The guided tour: checks your setup, explains each part, and runs a live before/after
demo against the practice lab.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

from webrecon import bootstrap
from webrecon.interactive.helpers import REPORTS, pick_lab_port
from webrecon.interactive.prompts import Quit, ask_yes_no, pause
from webrecon.reporting import open_in_browser
from webrecon.results import compare

PROJECT_FILES = (os.path.join("scanning", "scanner.py"), os.path.join("analysis", "engine.py"),
                 os.path.join("reporting", "assessment.py"), os.path.join("results", "compare.py"),
                 os.path.join("lab", "vulnerable_lab.py"))


STEPS = 6


def _step(number: int, title: str) -> None:
    print(f"\n{'=' * 60}\n  Step {number} of {STEPS}: {title}\n{'=' * 60}")



def check_environment() -> None:
    """Report on Python, the virtual environment, project files and packages; offer to pip install."""
    ok = sys.version_info >= (3, 9)
    print(f"  Python         : {sys.version.split()[0]}  ({'ok' if ok else '3.9 or newer is required!'})")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    print(f"  Virtual env    : {'active' if in_venv else 'not active (run.sh / run.bat sets one up for you)'}")
    package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    absent = [f for f in PROJECT_FILES if not os.path.exists(os.path.join(package_dir, f))]
    print("  Project files  : " + (f"MISSING {', '.join(absent)} (re-extract the zip)" if absent else "all present"))
    missing = bootstrap.missing_packages()
    if not missing:
        print("  Packages       : requests, beautifulsoup4 installed")
        return
    print(f"  Packages       : missing {', '.join(missing)}")
    req = os.path.join(bootstrap.ROOT, "requirements.txt")
    if os.path.exists(req) and ask_yes_no("  Install them now with pip?", True):
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", req], check=False)
        missing = bootstrap.missing_packages()
    if missing:
        print(f"  [-] Still missing: {', '.join(missing)}. Run: pip install -r requirements.txt")
        raise Quit()
    print("  [+] Packages installed.")


def _show_top_findings(json_path: str, top: int = 6) -> None:
    data = compare.load_scan(json_path)
    summary = ", ".join(f"{k} {v}" for k, v in data.get("summary", {}).items())
    print(f"\n  Result: {summary}  ({len(data['findings'])} total)\n  The {top} most severe:")
    for f in data["findings"][:top]:
        print(f"    [{f['severity']:<8}] {f['check_id']}  {f['title']}")
        print(f"               Fix: {f['recommendation'][:100]}")


def _demo_scan(runner, argv: list[str], json_path: str) -> bool:
    print(f"  Equivalent command: python main.py {shlex.join(argv)}\n")
    code = runner(argv)
    if code in (0, 2) and os.path.exists(json_path):
        return True
    print("  [-] The scan did not complete, so the walkthrough ends here.")
    return False


def run_walkthrough(runner) -> int:
    """Interactive tour. `runner` is main.main(argv) -> exit code."""
    before, after = f"{REPORTS}/before", f"{REPORTS}/after"
    print("\n=== WebRecon walkthrough ===")
    print("A short tour of the project that runs a real before/after demo as it goes.")
    print("Press Enter to move on at each pause, or type q to quit.")

    _step(1, "What WebRecon is")
    print("  WebRecon inspects a web application from the outside and reports security")
    print("  misconfigurations: missing headers, weak cookies, exposed files, risky methods.")
    print("  It never tries to exploit anything. Only scan systems you own or have written")
    print("  permission to test. The practice lab below is safe: it listens on 127.0.0.1 only.\n")
    print("  scanning/    collects data: headers, cookies, forms, TLS, a few low-impact path probes")
    print("  analysis/    decides what counts as a finding and rates its severity")
    print("  reporting/   writes the HTML report; results/ compares and remembers your scans")
    print("  lab/         a deliberately misconfigured app, with a hardened mode showing the fixes")
    pause()

    _step(2, "Checking your setup")
    check_environment()
    pause()

    _step(3, "Scan 1: the vulnerable lab (the 'before')")
    target = f"http://127.0.0.1:{pick_lab_port()}"
    print(f"  WebRecon starts the lab on {target}, crawls and probes it, then stops it.")
    pause("Press Enter to run the scan")
    if not _demo_scan(runner, [target, "--auto-lab", "-o", f"{before}.html", "--json", f"{before}.json"],
                      f"{before}.json"):
        return 1
    _show_top_findings(f"{before}.json")
    print("\n  Each finding has an ID, a severity, evidence from the target, and a fix.")
    pause()

    _step(4, "Scan 2: the hardened lab, then compare (the 'after')")
    print("  The hardened lab applies the fixes: security headers added, version banners hidden,")
    print("  cookies locked down, CSRF tokens on forms, exposed files and risky methods removed.")
    pause("Press Enter to run the retest")
    if not _demo_scan(runner, [target, "--auto-lab", "--hardened-lab", "-o", f"{after}.html",
                               "--json", f"{after}.json"], f"{after}.json"):
        return 1
    runner(["--compare", f"{before}.json", f"{after}.json", "-o", f"{REPORTS}/comparison.html"])
    print("\n  What remains is expected: the lab runs over plain HTTP. Real fixes would move it to")
    print("  HTTPS and add HSTS, a good talking point for a demo.")
    pause()

    _step(5, "Reading the reports")
    print(f"  {REPORTS}/before.html and after.html: executive summary, a 'Fix these first' box,")
    print("  severity filters, detailed findings with evidence, and all the recon data.")
    print(f"  {REPORTS}/comparison.html: what was fixed, what is new, what is still open.")
    print("  The .json files hold the same data for scripts. Reports are single files you can email.")
    if ask_yes_no("  Open the comparison in your browser now?", False):
        open_in_browser(f"{REPORTS}/comparison.html")
    pause()

    _step(6, "What to do next")
    print("  Scan a site you are authorized to test:   python main.py https://your-site.example --open")
    print("  Several sites at once:                    python main.py --targets-file sites.txt")
    print("  See what a scan will send first:          python main.py https://your-site.example --plan")
    print("  Add AI-estimated CVSS and ATT&CK:         python main.py https://your-site.example --ai   (first: --ai-setup)")
    print("  Scan as a signed-in user:                 python main.py https://app.example --cookie 'session=...'")
    print("  Compare your last two scans of a site:    python main.py --compare")
    print("  Only report what is new since last time:  python main.py https://your-site.example --baseline last")
    print("  Go easy on a fragile server:              python main.py https://your-site.example --profile gentle")
    print("  Hide noisy findings:                      python main.py <target> --ignore WR-014 --min-severity Low")
    print("  List every check:                         python main.py --list-checks")
    print("  This tour again / short menu / all flags: python main.py --walkthrough | --quick | --help")
    print("\n  A target on the command line skips all of this and just scans.")
    return 0
