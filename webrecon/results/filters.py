"""
filters.py - Which findings to show: --ignore, --min-severity and --baseline.
"""

from __future__ import annotations

import argparse
from collections import Counter

from webrecon.analysis import SEVERITY_ORDER
from webrecon.errors import UserError
from webrecon.results import compare, history


def load_baseline(path: str) -> Counter:
    """Findings from a saved result, counted the same way --compare matches them."""
    try:
        return compare.finding_counts(compare.load_scan(path))
    except compare.CompareError as exc:
        raise UserError(str(exc))


def resolve_baseline(args: argparse.Namespace, target: str):
    """Returns (baseline counts or None, a note for the report or None) for --baseline."""
    if args.baseline == "last":
        previous = history.previous_scan(target, args.output_dir)
        if previous is None:
            return None, (f"--baseline last: no earlier scan of this site was found in {args.output_dir}/, "
                          "so nothing was hidden.")
        return (compare.finding_counts(previous["data"]),
                f"Baseline: your previous scan of this site ({previous['started'] or 'time unknown'}).")
    return getattr(args, "baseline_keys", None), None


def filter_findings(findings, ignore: set, min_severity, baseline=None):
    """Split findings into (kept, hidden): hidden are ignored IDs, findings below --min-severity,
    and findings already in the baseline. Kept findings are the ones worth acting on."""
    limit = SEVERITY_ORDER[min_severity] if min_severity else None
    known = Counter(baseline) if baseline else Counter()
    kept, hidden = [], []
    for f in findings:
        key = (f.check_id, f.title)
        if f.check_id in ignore or (limit is not None and SEVERITY_ORDER[f.severity] > limit):
            hidden.append(f)
        elif known[key] > 0:
            known[key] -= 1
            hidden.append(f)
        else:
            kept.append(f)
    return kept, hidden
