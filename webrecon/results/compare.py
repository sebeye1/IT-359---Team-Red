"""
compare.py - Compare two WebRecon JSON results (for example before and after a fix).

    python main.py --compare before.json after.json

Findings are matched by check ID and title. Anything in the first file but not the
second is "fixed", the reverse is "new", and the rest are "still open".
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict

from webrecon.analysis import SEVERITY_ORDER
from webrecon.reporting import build_compare_html, open_in_browser


class CompareError(Exception):
    """Raised with a message that is safe to show the user."""


def load_scan(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise CompareError(f"Could not read {path}: {exc}")
    except json.JSONDecodeError:
        raise CompareError(f"{path} is not valid JSON. Use a file written with --json or --save-json.")
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise CompareError(f"{path} does not look like a WebRecon results file (no 'findings' list).")
    return data


def _sort_key(f: dict):
    return (SEVERITY_ORDER.get(f.get("severity"), 9), f.get("check_id", ""))


def finding_counts(data: dict) -> Counter:
    """How many findings of each kind a saved result holds, keyed the same way diff() matches them."""
    return Counter((f.get("check_id"), f.get("title")) for f in data["findings"])


def diff(before: dict, after: dict) -> dict:
    """Return {'fixed', 'new', 'unchanged', 'changed'}. 'changed' holds (before, after) pairs
    whose severity moved; the other lists hold finding dicts."""
    groups_b, groups_a = defaultdict(list), defaultdict(list)
    for f in before["findings"]:
        groups_b[(f.get("check_id"), f.get("title"))].append(f)
    for f in after["findings"]:
        groups_a[(f.get("check_id"), f.get("title"))].append(f)

    fixed, new, unchanged, changed = [], [], [], []
    for key in list(groups_b) + [k for k in groups_a if k not in groups_b]:
        b, a = groups_b.get(key, []), groups_a.get(key, [])
        paired = min(len(b), len(a))  # same finding repeated (for example one per cookie)
        for old, cur in zip(b[:paired], a[:paired]):
            if old.get("severity") != cur.get("severity"):
                changed.append((old, cur))
            else:
                unchanged.append(cur)
        fixed.extend(b[paired:])
        new.extend(a[paired:])
    fixed.sort(key=_sort_key)
    new.sort(key=_sort_key)
    unchanged.sort(key=_sort_key)
    changed.sort(key=lambda pair: _sort_key(pair[1]))
    return {"fixed": fixed, "new": new, "unchanged": unchanged, "changed": changed}


def _describe(data: dict) -> str:
    scan = data.get("scan", {})
    when = scan.get("started") or "unknown time"
    return f"{scan.get('target', 'unknown target')} ({when}), {len(data['findings'])} finding(s)"


def format_diff(before: dict, after: dict, d: dict) -> str:
    lines = ["", "=== Comparison ===",
             f"  Before: {_describe(before)}",
             f"  After : {_describe(after)}", "",
             f"  Fixed {len(d['fixed'])}   New {len(d['new'])}   "
             f"Still open {len(d['unchanged'])}   Severity changed {len(d['changed'])}"]

    def section(title: str, findings: list) -> None:
        if findings:
            lines.append(f"\n  {title}:")
            lines.extend(f"    [{f.get('severity', '?'):<8}] {f.get('check_id')}  {f.get('title')}" for f in findings)

    section("Fixed", d["fixed"])
    section("New", d["new"])
    section("Still open", d["unchanged"])
    if d["changed"]:
        lines.append("\n  Severity changed:")
        lines.extend(f"    {o.get('check_id')}  {o.get('title')}: {o.get('severity')} -> {c.get('severity')}"
                     for o, c in d["changed"])
    return "\n".join(lines)


def run(before_path: str, after_path: str, output: str | None = None,
        output_dir: str = "reports", open_report: bool = False) -> int:
    """Compare two result files, print the summary and write an HTML report.
    Returns 0 normally, 2 if the second scan has findings the first did not (handy for CI)."""
    before, after = load_scan(before_path), load_scan(after_path)
    d = diff(before, after)
    print(format_diff(before, after, d))
    path = output or os.path.join(output_dir, f"compare_{time.strftime('%Y%m%d-%H%M%S')}.html")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_compare_html(before, after, d, _describe(before), _describe(after)))
    print(f"\n[+] Comparison report written to {path}")
    if open_report:
        open_in_browser(path)
    return 2 if d["new"] else 0
