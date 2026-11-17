"""
app.py - The entry point: reads the command line and decides what to do.

    no arguments            guided walkthrough
    options but no target   short menu
    one or more targets     scan them
    --compare, --list-scans, --list-checks, --plan   the other commands
"""

from __future__ import annotations

import argparse
import logging
import sys

from webrecon import ai
from webrecon.cli.authorization import confirm_authorization
from webrecon.cli.console import print_checks, show_banner
from webrecon.cli.options import (UserError, load_targets, parse_also, parse_args, parse_headers,
                                  parse_ignore)
from webrecon.cli.plan import print_plan
from webrecon.cli.workflow import run_all
from webrecon.lab.control import ensure_local_server
from webrecon.results import compare, history
from webrecon.results.filters import load_baseline

def run_compare(args: argparse.Namespace) -> int:
    files = args.compare
    try:
        if not files:
            pair = history.last_two_scans(args.output_dir)
            if pair is None:
                raise compare.CompareError(
                    f"Need two saved scans of the same site in {args.output_dir}/ to compare. Every scan saves its "
                    "results there automatically, so scan the site twice and run this again.")
            files = [pair[0]["path"], pair[1]["path"]]
            print(f"[*] Comparing your last two scans of {pair[1]['target']}")
        elif len(files) != 2:
            raise compare.CompareError("--compare takes two result files, or none to compare your last two scans.")
        return compare.run(files[0], files[1], args.output, args.output_dir, args.open)
    except compare.CompareError as exc:
        print(f"[-] {exc}")
        return 1


def save_api_key() -> int:
    try:
        path = ai.run_setup()
    except (UserError, KeyboardInterrupt, EOFError) as exc:
        print(f"\n[-] {exc}" if isinstance(exc, UserError) else "\n[-] Cancelled, nothing was saved.")
        return 1
    print(f"[+] Saved. It is used automatically whenever you run --ai. ({path})")
    return 0


def update_attack_list() -> int:
    print("[*] Downloading MITRE's ATT&CK Enterprise technique list (about 55 MB) ...")
    try:
        index = ai.update_index()
    except UserError as exc:
        print(f"[-] {exc}")
        return 1
    print(f"[+] Saved {len(index['techniques'])} techniques (ATT&CK version {index['version']}). "
          "AI-suggested technique IDs are now checked against this list.")
    return 0


def interactive(mode: str, raw: list[str] | None = None) -> int:
    from webrecon.interactive import start
    show_banner()
    if raw:
        print(f"[*] No target given (options so far: {' '.join(raw)}).")
    return start(main, mode, raw)


def main(argv=None) -> int:
    args = parse_args(argv)
    args.tips = argv is None and not args.quiet  # tips only for real command-line runs, not the guided modes
    raw = list(sys.argv[1:] if argv is None else argv)
    if args.walkthrough or args.guided:
        return interactive("walkthrough")
    if args.quick:
        return interactive("menu")
    if args.list_checks:
        print_checks()
        return 0
    if args.ai_setup:
        return save_api_key()
    if args.attack_update:
        return update_attack_list()
    if args.list_scans:
        print(history.format_scans(history.saved_scans(args.output_dir), args.output_dir))
        return 0
    if args.compare is not None:
        return run_compare(args)

    try:
        targets = load_targets(args)
        parse_headers(args.header)               # fail early on malformed input
        args.ignore_set = parse_ignore(args.ignore)
        parse_also(args.also)
        args.baseline_keys = load_baseline(args.baseline) if args.baseline not in (None, "last") else None
    except UserError as exc:
        print(f"[-] {exc}")
        return 1

    if not targets:  # nothing given: full walkthrough; some options given: ask what to scan
        return interactive("menu", raw) if raw else interactive("walkthrough")

    if args.plan:
        print_plan(targets, args)
        return 0

    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR,
                        format="[%(levelname)s] %(name)s: %(message)s")
    if not args.quiet:
        show_banner()
    if not confirm_authorization(targets, args.yes):
        print("[-] Scan cancelled. Only scan systems you are authorized to test.")
        return 1

    if args.ai:  # fail early, before any scanning, if the AI server is not set up
        try:
            args.ai_client = ai.build_client(provider=args.ai_provider, url=args.ai_url, model=args.ai_model,
                                             timeout=args.ai_timeout)
        except UserError as exc:
            print(f"[-] {exc}")
            return 1
        for warning in ai.key_warnings(args.ai_client.config):
            print(f"[!] {warning}")
        if not args.quiet:
            config = args.ai_client.config
            print(f"[i] AI: asking {config.url} ({config.model}) about the kinds of finding, using generic "
                  "descriptions only. No URLs, evidence or results are sent.")
            if ai.load_index() is None:
                print("[i] Tip: run --attack-update once so suggested ATT&CK technique IDs can be verified.")

    lab_servers = []
    if args.auto_lab:
        lab_servers = [s for s in (ensure_local_server(t, args.hardened_lab) for t in targets) if s]
    try:
        return run_all(targets, args)
    except UserError as exc:
        print(f"[-] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[-] Interrupted.")
        return 1
    finally:
        for server in lab_servers:
            server.shutdown()
            server.server_close()
