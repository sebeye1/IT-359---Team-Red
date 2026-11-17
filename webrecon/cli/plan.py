"""
plan.py - --plan: describe exactly what a scan would send, without sending anything.
"""

from __future__ import annotations

import argparse

from webrecon.ai import resolve_config
from webrecon.cli.authorization import host_of
from webrecon.errors import UserError
from webrecon.scanning import PROBE_PATHS, USER_AGENT, is_loopback, normalize_target


def print_plan(targets: list[str], args: argparse.Namespace) -> None:
    """Describe the requests a scan would send. Sends nothing."""
    print("\n=== Scan plan: nothing is sent in this mode ===")
    for number, target in enumerate(targets, 1):
        url, guessed = normalize_target(target)
        https = url.startswith("https://")
        total = 1 + args.max_pages + 3          # first page, crawl, sitemap.xml, OPTIONS, TRACE
        also = ["OPTIONS and TRACE (which HTTP methods are allowed)", "/sitemap.xml (extra pages to crawl)"]
        if guessed:
            also.append("a fallback to http:// if https:// does not answer")
        if https:
            also += ["one plain-http request (does it redirect to HTTPS?)", "one TLS handshake (certificate check)"]
            total += 1
        if args.respect_robots:
            also.append("/robots.txt, read before crawling")
            total += 1
        print(f"\n  Target {number}: {url}")
        print(f"    Crawls up to {args.max_pages} same-origin pages with GET requests.")
        print(f"    Also sends: {'; '.join(also)}.")
        if args.no_probes:
            print("    Path probes: off (--no-probes).")
        else:
            total += len(PROBE_PATHS) + 2
            print(f"    Path probes: {len(PROBE_PATHS)} GET requests, one for a page that cannot exist, and one with an "
                  "unknown Origin header (CORS):")
            print("      " + ", ".join(PROBE_PATHS))
        print(f"    At most {total} requests (retries not counted), with {args.delay:g}s between them (at least {total * args.delay:.0f}s of "
              f"pauses). Stops after {args.max_time:g}s." if args.max_time else
              f"    At most {total} requests, with {args.delay:g}s between them. No time limit.")
    sent = [f"User-Agent: {args.user_agent or USER_AGENT}"]
    sent += [f"header {h.split(':', 1)[0].strip()} (value not shown)" for h in args.header]
    if args.cookie:
        sent.append("a session cookie (value not shown)")
    if args.proxy:
        sent.append(f"all traffic through the proxy {args.proxy}")
    print("\n  Every request carries: " + "; ".join(sent) + ".")
    print("  Nothing is submitted to forms, and no login or exploit is attempted.")
    if args.ai:
        print("\n  AI risk context (--ai): after the scan, one short description per kind of finding (check ID, generic")
        print("  title, category, usual severity) is sent to the AI server. Nothing about the target is sent: no")
        print("  address, evidence, cookies, headers or results.")
        try:
            config = resolve_config(provider=args.ai_provider, url=args.ai_url, model=args.ai_model,
                                    timeout=args.ai_timeout, ask_key=lambda: None)
            print(f"    Server: {config.url} (model {config.model}, {config.provider} style).")
        except UserError as exc:
            print(f"    Not ready yet: {exc}")
    if any(not is_loopback(host_of(t)) for t in targets):
        print("  Scanning a non-local target asks you to confirm authorization first.")
