"""
workflow.py - Doing the scans: where files go, scanning one target, scanning a list, and the exit code.
"""

from __future__ import annotations

import argparse
import os
import re
import time
from urllib.parse import urlparse

from webrecon import ai
from webrecon.analysis import SEVERITY_ORDER, analyze, severity_counts
from webrecon.cli.console import next_steps, print_overview, print_result, print_unreachable
from webrecon.cli.options import parse_also, parse_headers
from webrecon.reporting import open_in_browser, write_csv, write_html, write_index, write_json, write_markdown
from webrecon.results import history
from webrecon.results.filters import filter_findings, resolve_baseline
from webrecon.scanning import Scanner, normalize_target


def _unique(path: str) -> str:
    base, ext = os.path.splitext(path)
    candidate, n = path, 2
    while os.path.exists(candidate):
        candidate, n = f"{base}_{n}{ext}", n + 1
    return candidate


def output_paths(target: str, args: argparse.Namespace, multiple: bool):
    """Where to write this target's HTML report and its JSON results. Returns (html_path, json_path)."""
    if not multiple and args.output:
        html = args.output
    else:
        parsed = urlparse(normalize_target(target)[0])
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", (parsed.netloc + parsed.path).rstrip("/")).strip("_") or "target"
        html = _unique(os.path.join(args.output_dir, f"{name}_{time.strftime('%Y%m%d-%H%M%S')}.html"))
    js = args.json_path if not multiple and args.json_path else os.path.splitext(html)[0] + ".json"
    for path in (html, js):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    return html, js




def build_scanner(target: str, args: argparse.Namespace, headers: dict) -> Scanner:
    progress = None if args.quiet else (lambda message: print(f"    ... {message}"))
    return Scanner(target, timeout=args.timeout, max_pages=args.max_pages, delay=args.delay,
                   verify_tls=not args.insecure, run_probes=not args.no_probes,
                   headers=headers, cookie=args.cookie, user_agent=args.user_agent,
                   proxy=args.proxy, retries=args.retries, respect_robots=args.respect_robots,
                   max_time=args.max_time or None, progress=progress)




def add_ai_context(findings, client, result) -> None:
    """Ask the AI server for CVSS and ATT&CK context. A failure here only adds a note; the scan is unaffected."""
    outcome = ai.enrich_findings(findings, client)
    if outcome.enriched:
        result.notes.append(
            f"AI context added to {outcome.enriched} finding(s) ({outcome.asked} check type(s) asked, "
            f"{outcome.from_cache} from the local cache). CVSS scores are calculated from an AI-suggested vector: "
            "estimates for this kind of weakness, not measurements of this site.")
    for problem in outcome.problems[:5]:
        result.notes.append(f"AI: {problem}")


def scan_target(target: str, args: argparse.Namespace, html_path: str, json_path, headers: dict) -> dict:
    """Scan one target, print and save the results. Returns a summary entry for run_all."""
    scanner = build_scanner(target, args, headers)
    if not args.quiet:
        print(f"[*] Scanning {scanner.target} ...")
    result = scanner.run()
    if result.status_code is None:
        print_unreachable(scanner, args)
        return {"target": scanner.target, "ok": False, "findings": [], "counts": {},
                "interrupted": result.interrupted,
                "error": "; ".join(result.hints or result.errors[:1])}

    # `visible` is the complete state after --ignore and --min-severity. The JSON records all of it, so scans
    # stay comparable. `findings` additionally drops what --baseline says is already known; that is what the
    # report, the console and --fail-on use.
    visible, hidden = filter_findings(analyze(result), getattr(args, "ignore_set", set()), args.min_severity)
    baseline, baseline_note = resolve_baseline(args, scanner.target)
    findings, known = filter_findings(visible, set(), None, baseline)
    if baseline_note:
        result.notes.append(baseline_note)
    if hidden:
        result.notes.append(f"{len(hidden)} finding(s) hidden by --ignore or --min-severity "
                            f"({', '.join(sorted({f.check_id for f in hidden}))}).")
    if known:
        result.notes.append(f"{len(known)} finding(s) already in the baseline were hidden "
                            "(the JSON results still record them).")
    previous = history.previous_scan(scanner.target, args.output_dir)
    if previous:
        result.trend = history.trend(previous, [f.to_dict() for f in visible])
    client = getattr(args, "ai_client", None)
    if client and visible:
        add_ai_context(visible, client, result)
    counts = severity_counts(findings)
    print_result(result, findings, counts, args)

    write_html(result, findings, html_path)
    print(f"[+] HTML report written to {html_path}")
    write_json(result, visible, json_path)
    print(f"[+] JSON results written to {json_path}")
    formats = parse_also(args.also)
    for fmt, writer in (("csv", write_csv), ("md", write_markdown)):
        if fmt in formats:
            path = os.path.splitext(html_path)[0] + "." + fmt
            writer(result, findings, path)
            print(f"[+] {'CSV' if fmt == 'csv' else 'Markdown'} export written to {path}")
    return {"target": scanner.target, "ok": True, "findings": findings, "counts": counts,
            "report": html_path, "json": json_path, "partial": result.partial,
            "interrupted": result.interrupted}




def exit_code(entries: list[dict], fail_on) -> int:
    """0 = fine, 1 = a target could not be reached or a scan stopped early, 2 = a finding met --fail-on."""
    if fail_on:
        limit = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for e in entries for f in e["findings"]):
            return 2
    return 0 if all(e["ok"] and not e.get("partial") for e in entries) else 1




def run_all(targets: list[str], args: argparse.Namespace) -> int:
    headers = parse_headers(args.header)
    multiple = len(targets) > 1
    if multiple and (args.output or args.json_path):
        print(f"[i] -o and --json apply to a single target. Using automatic names in "
              f"{args.output_dir}/ instead (add --save-json for JSON files).")

    entries = []
    for number, target in enumerate(targets, 1):
        if multiple:
            print(f"\n--- Target {number} of {len(targets)}: {target}")
        html_path, json_path = output_paths(target, args, multiple)
        entries.append(scan_target(target, args, html_path, json_path, headers))
        if entries[-1].get("interrupted"):
            print("[-] Stopping: the run was interrupted.")
            break

    to_open = entries[0].get("report")
    if multiple:
        print_overview(entries)
        index_path = _unique(os.path.join(args.output_dir, f"summary_{time.strftime('%Y%m%d-%H%M%S')}.html"))
        write_index([{**e, "report": os.path.relpath(e["report"], args.output_dir) if e["ok"] else ""}
                     for e in entries], index_path)
        print(f"[+] Summary page written to {index_path}")
        to_open = index_path
    if args.open and to_open:
        open_in_browser(to_open)
    if getattr(args, "tips", False) and not multiple and entries[0]["ok"]:
        print("".join(f"[>] {line}\n" for line in next_steps(entries[0]["findings"])), end="")
    return exit_code(entries, args.fail_on)
