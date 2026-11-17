"""
options.py - Everything about the command line: the options, the scan profiles, the short help,
and checking what the user typed (targets, headers, --ignore, --also).
"""

from __future__ import annotations

import argparse

from webrecon import __version__
from webrecon.analysis import CHECK_CATALOG, SEVERITY_ORDER
from webrecon.errors import UserError
from webrecon.scanning import normalize_target

ALSO_FORMATS = ("csv", "md")
PROFILES = {  # how hard a scan pushes; any explicit --max-pages, --delay, ... overrides the profile
    "gentle":   {"max_pages": 5, "delay": 1.0, "timeout": 15.0, "retries": 1, "max_time": 300.0},
    "standard": {"max_pages": 10, "delay": 0.2, "timeout": 10.0, "retries": 2, "max_time": 300.0},
    "thorough": {"max_pages": 50, "delay": 0.2, "timeout": 10.0, "retries": 2, "max_time": 900.0},
}

SHORT_HELP = """WebRecon checks a web application for security misconfigurations.
Only scan systems you own or have written permission to test.

  python main.py                        guided walkthrough (start here)
  python main.py https://example.com    scan a site; the report is saved in reports/
  python main.py a.com b.com            scan several, with a summary page
  python main.py --compare              compare your last two scans of a site
  python main.py --list-scans           list your saved scans
  python main.py <site> --plan          show what a scan would send, and send nothing

Handy options:
  --open                open the report when the scan finishes
  --profile gentle      go easy on fragile servers (gentle | standard | thorough)
  --cookie 'a=b'        scan as a signed-in user
  --baseline last       only report findings that are new since your last scan
  --ignore WR-091       hide a check (see --list-checks); --min-severity Medium hides the minor ones
  --ai                  add AI-estimated CVSS and MITRE ATT&CK context (needs an API key; see docs)
  --fail-on High        exit with code 2 if a finding is High or worse (for CI)
  -y                    skip the authorization question for non-local targets

Every option: python main.py --help-all"""

class _Help(argparse.Action):
    """-h prints the short help; --help-all prints every option."""

    def __init__(self, option_strings, dest, help=None):
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(SHORT_HELP if option_string in ("-h", "--help") else parser.format_help())
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py", add_help=False,
        description="WebRecon: web application reconnaissance and security misconfiguration scanner. "
                    "For authorized testing only. Run with no arguments for a guided walkthrough.",
        epilog="Examples:  python main.py https://example.com --open   |   "
               "python main.py --targets-file sites.txt --save-json   |   "
               "python main.py https://app.example.com --cookie 'session=abc123'")
    p.add_argument("targets", nargs="*", metavar="target",
                   help="One or more targets, e.g. https://example.com, example.com, 10.0.0.5:8443 "
                        "(omit for the walkthrough). A bare host is tried over HTTPS, then HTTP.")
    p.add_argument("-h", "--help", action=_Help, help="Show a short help")
    p.add_argument("--help-all", action=_Help, help="Show every option")
    p.add_argument("--targets-file", help="Text file with one target per line (blank lines and # comments ignored)")
    p.add_argument("--version", action="version", version=f"WebRecon {__version__}")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", help="HTML report path (single target). Default: reports/<host>_<time>.html")
    out.add_argument("--output-dir", default="reports", help="Folder for automatically named reports (default: reports)")
    out.add_argument("--json", dest="json_path",
                     help="Path for the JSON results (single target). By default they are saved next to the report")
    out.add_argument("--save-json", action="store_true", help=argparse.SUPPRESS)  # JSON is always saved now
    out.add_argument("--also", action="append", default=[], metavar="FORMATS",
                     help="Also write these next to every report: csv, md (comma list, repeatable)")
    out.add_argument("--open", action="store_true", help="Open the report in your browser when finished")
    out.add_argument("-q", "--quiet", action="store_true", help="Less console output (good for scripts)")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose logging and technical error details")

    scan = p.add_argument_group("scan behaviour")
    scan.add_argument("--profile", choices=list(PROFILES), default="standard",
                      help="Preset for how hard to push: gentle (5 pages, 1s pauses), standard (default), "
                           "thorough (50 pages). Options below override it")
    scan.add_argument("--max-pages", type=int, help="Maximum same-origin pages to crawl (standard: 10)")
    scan.add_argument("--timeout", type=float, help="Request timeout in seconds (standard: 10)")
    scan.add_argument("--delay", type=float, help="Delay between requests in seconds (standard: 0.2)")
    scan.add_argument("--max-time", type=float, metavar="SECONDS",
                      help="Stop a target's scan after this long and keep the partial results (standard: 300, 0 = no limit)")
    scan.add_argument("--retries", type=int, help="Retries when a server is busy or rate limiting (standard: 2)")
    scan.add_argument("--no-probes", action="store_true", help="Skip the sensitive path probes")
    scan.add_argument("--respect-robots", action="store_true", help="Do not crawl paths that robots.txt disallows")
    scan.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (self-signed certs)")

    net = p.add_argument_group("authenticated scans and networking")
    net.add_argument("--cookie", help="Cookies to send, e.g. 'session=abc123; theme=dark' (scan as a signed-in user)")
    net.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'",
                     help="Extra request header, repeatable, e.g. --header 'Authorization: Bearer TOKEN'")
    net.add_argument("--user-agent", help="Override the User-Agent string")
    net.add_argument("--proxy", help="Send traffic through a proxy, e.g. http://127.0.0.1:8081 (Burp, ZAP)")

    flt = p.add_argument_group("filtering and comparing")
    flt.add_argument("--ignore", action="append", default=[], metavar="IDS",
                     help="Hide findings by check ID, e.g. --ignore WR-014,WR-091 (repeatable). See --list-checks")
    flt.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                     help="Hide findings below this severity, e.g. --min-severity Medium")
    flt.add_argument("--baseline", metavar="RESULTS.json|last",
                     help="Hide findings already in a saved result, so only new ones are reported (and counted by "
                          "--fail-on). 'last' uses your previous scan of the same site")
    flt.add_argument("--compare", nargs="*", metavar="RESULTS.json",
                     help="Compare two saved results instead of scanning. With no files, compares your last two "
                          "scans of a site")
    flt.add_argument("--list-scans", action="store_true",
                     help="List the scans saved in the reports folder (newest first), then exit")
    flt.add_argument("--list-checks", action="store_true", help="List every check WebRecon can report, then exit")

    ai = p.add_argument_group("AI risk context (optional)",
                              "Ask an AI server for an estimated CVSS score and MITRE ATT&CK techniques for each kind of "
                              "finding. Only generic check descriptions are sent, never anything about the scanned site. "
                              "The API key comes from --ai-setup (a private file outside your project), or from "
                              "WEBRECON_AI_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY, never from an option. See docs/USAGE.md.")
    ai.add_argument("--ai", action="store_true", help="Add AI-estimated CVSS scores and ATT&CK techniques to the findings")
    ai.add_argument("--ai-provider", choices=["anthropic", "openai"],
                    help="API style: anthropic (default) or openai (OpenAI and compatible servers such as Ollama, vLLM, LM Studio)")
    ai.add_argument("--ai-url", help="Server address, e.g. https://api.anthropic.com or http://localhost:11434/v1")
    ai.add_argument("--ai-model", help="Model name (default for anthropic: claude-haiku-5-5; required for openai)")
    ai.add_argument("--ai-timeout", type=float, default=60.0, help="Seconds to wait for the AI server (default 60)")
    ai.add_argument("--ai-setup", action="store_true",
                    help="Save your API key once, safely: typed with hidden input into a private file outside your project")
    ai.add_argument("--attack-update", action="store_true",
                    help="Download MITRE's official ATT&CK technique list (about 55 MB, once) so AI-suggested IDs can be verified")

    misc = p.add_argument_group("automation, practice lab and guided modes")
    misc.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                      help="Exit with code 2 if any finding is at or above this severity")
    misc.add_argument("--plan", action="store_true", help="Show exactly what a scan would send, without sending anything")
    misc.add_argument("-y", "--yes", action="store_true", help="Confirm you are authorized, without prompting")
    misc.add_argument("--auto-lab", action="store_true", help="Start the local lab server if nothing is listening on a local target")
    misc.add_argument("--hardened-lab", action="store_true", help="With --auto-lab, serve the remediated configuration")
    misc.add_argument("--walkthrough", action="store_true", help="Guided tour with setup checks and a live before/after demo")
    misc.add_argument("--quick", action="store_true", help="Short menu: practice lab, full demo, or your own target")
    misc.add_argument("--guided", action="store_true", help=argparse.SUPPRESS)  # old name for --walkthrough
    return p


def apply_profile(args: argparse.Namespace) -> None:
    """Fill in every scan setting the user did not give from the chosen profile."""
    for name, value in PROFILES[args.profile].items():
        if getattr(args, name) is None:
            setattr(args, name, value)


def parse_args(argv=None) -> argparse.Namespace:
    args = build_parser().parse_intermixed_args(argv)
    apply_profile(args)
    return args


def load_targets(args: argparse.Namespace) -> list[str]:
    """Targets from the command line plus --targets-file, without duplicates."""
    items = [t.strip() for t in args.targets if t.strip()]
    if args.targets_file:
        try:
            with open(args.targets_file, encoding="utf-8") as fh:
                items += [line for line in (raw.split("#", 1)[0].strip() for raw in fh) if line]
        except OSError as exc:
            raise UserError(f"Could not read the targets file: {exc}")
        if not items:
            raise UserError(f"No targets found in {args.targets_file}. Put one URL per line.")
    seen, unique = set(), []
    for item in items:
        key = normalize_target(item)[0].rstrip("/")
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def parse_headers(raw_headers: list[str]) -> dict:
    headers = {}
    for raw in raw_headers:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            raise UserError(f"Bad --header {raw!r}. Use the form 'Name: value'.")
        headers[name.strip()] = value.strip()
    return headers


def parse_ignore(raw_values: list[str]) -> set[str]:
    known = {check_id for check_id, _, _ in CHECK_CATALOG}
    ids = set()
    for raw in raw_values:
        for item in (part.strip().upper() for part in raw.split(",")):
            if item and item not in known:
                raise UserError(f"Unknown check ID {item!r}. Run: python main.py --list-checks")
            if item:
                ids.add(item)
    return ids


def parse_also(raw_values: list[str]) -> set[str]:
    """--also csv,md. (json is accepted for backward compatibility; it is always written.)"""
    formats = set()
    for raw in raw_values:
        for item in (part.strip().lower() for part in raw.split(",")):
            if item == "json":
                continue  # JSON is always saved, so this is accepted and does nothing
            if item and item not in ALSO_FORMATS:
                raise UserError(f"Unknown format {item!r}. Choose from: {', '.join(ALSO_FORMATS)}.")
            if item:
                formats.add(item)
    return formats
