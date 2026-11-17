"""
pages.py - The multi-target summary page and the before/after comparison page.
"""

from __future__ import annotations

from html import escape

from webrecon.reporting.components import badge, overall_risk, page, write_text
from webrecon.reporting.style import SEVERITY_COLORS


def build_index_html(entries: list[dict]) -> str:
    """Summary page for a multi-target run. Each entry: target, ok, counts, report (relative path), error."""
    rows = []
    for e in entries:
        if e["ok"]:
            summary = ", ".join(f"{k} {v}" for k, v in e["counts"].items() if v) or "No findings"
            rows.append(f"<tr><td>{escape(e['target'])}</td><td>{badge(overall_risk(e['counts']))}</td>"
                        f"<td>{escape(summary)}</td><td><a href=\"{escape(e['report'])}\">Open report</a></td></tr>")
        else:
            rows.append(f"<tr><td>{escape(e['target'])}</td><td class=\"muted\">Unreachable</td>"
                        f"<td>{escape(e.get('error') or '')}</td><td></td></tr>")
    body = ("<section><h2>Targets</h2><table><tr><th>Target</th><th>Overall risk</th><th>Findings</th>"
            f"<th>Report</th></tr>{''.join(rows)}</table></section>")
    return page("WebRecon Scan Summary", "WebRecon Scan Summary", [f"{len(entries)} target(s) scanned"], body)


def write_index(entries: list[dict], path: str) -> None:
    write_text(path, build_index_html(entries))


def _diff_block(title: str, findings: list[dict], empty: str) -> str:
    if findings:
        rows = "".join(f"<tr><td>{badge(f.get('severity'))}</td><td>{escape(str(f.get('check_id')))}</td>"
                       f"<td>{escape(str(f.get('title')))}</td></tr>" for f in findings)
        table = f"<table><tr><th>Severity</th><th>ID</th><th>Finding</th></tr>{rows}</table>"
    else:
        table = f'<p class="muted">{escape(empty)}</p>'
    return f"<section><h2>{escape(title)} ({len(findings)})</h2>{table}</section>"


def build_compare_html(before: dict, after: dict, d: dict, before_label: str, after_label: str) -> str:
    colors = SEVERITY_COLORS
    cards = "".join(f'<div class="card{cls}"{style}><div class="n">{len(d[key])}</div>{label}</div>'
                    for key, label, cls, style in (
                        ("fixed", "Fixed", " good", ""),
                        ("new", "New", "", f' style="background:{colors["High"]}"'),
                        ("unchanged", "Still open", "", f' style="background:{colors["Medium"]}"'),
                        ("changed", "Severity changed", "", f' style="background:{colors["Info"]}"')))
    changed = ""
    if d["changed"]:
        rows = "".join(f"<tr><td>{escape(str(o.get('check_id')))}</td><td>{escape(str(o.get('title')))}</td>"
                       f"<td>{escape(str(o.get('severity')))} &rarr; {escape(str(c.get('severity')))}</td></tr>"
                       for o, c in d["changed"])
        changed = (f"<section><h2>Severity changed ({len(d['changed'])})</h2><table><tr><th>ID</th>"
                   f"<th>Finding</th><th>Change</th></tr>{rows}</table></section>")
    body = (f'<section><h2>Result</h2><div class="cards">{cards}</div></section>'
            + _diff_block("Fixed", d["fixed"], "Nothing was fixed between these scans.")
            + _diff_block("New", d["new"], "No new findings appeared.")
            + _diff_block("Still open", d["unchanged"], "Nothing remains open.")
            + changed)
    return page("WebRecon Comparison", "WebRecon Comparison Report",
                 [f"Before: {before_label}", f"After: {after_label}"], body)
