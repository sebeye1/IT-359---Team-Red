"""
exports.py - Machine-readable and paste-ready copies of a scan: JSON, CSV and Markdown.
"""

from __future__ import annotations

import csv
import io
import json

from webrecon.analysis import Finding, severity_counts
from webrecon.reporting.components import (ai_scores, ai_techniques, overall_risk, reference_label, safe_references,
                                           write_text)
from webrecon.scanning import ScanResult


def write_json(result: ScanResult, findings: list[Finding], path: str) -> None:
    payload = {
        "scan": result.to_dict(),
        "summary": severity_counts(findings),
        "findings": [f.to_dict() for f in findings],
    }
    write_text(path, json.dumps(payload, indent=2))


CSV_COLUMNS = ("target", "check_id", "severity", "title", "category", "evidence", "recommendation", "references",
               "ai_cvss_score", "ai_cvss_vector", "ai_attack_techniques")


def _csv_safe(value) -> str:
    """Evidence comes from the scanned site, so stop spreadsheets from running it as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def build_csv(result: ScanResult, findings: list[Finding]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        score, _, vector = ai_scores(f)
        techniques = "; ".join(f"{t['id']} {t['name']}".strip() for t in ai_techniques(f))
        writer.writerow([_csv_safe(v) for v in (
            result.final_url or result.target, f.check_id, f.severity, f.title, f.category,
            f.evidence, f.recommendation, " ".join(safe_references(f)),
            "" if score is None else f"{score:.1f}", vector, techniques)])
    return out.getvalue()


def write_csv(result: ScanResult, findings: list[Finding], path: str) -> None:
    write_text(path, build_csv(result, findings), "utf-8-sig")  # the BOM makes Excel read it as UTF-8


def _md(text) -> str:
    """One line of text that is safe inside a Markdown table cell or heading."""
    return " ".join(str(text).split()).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _md_code(text) -> str:
    return "`" + " ".join(str(text).split()).replace("`", "'") + "`"


def build_markdown(result: ScanResult, findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    lines = [f"# WebRecon report: {_md(result.target)}", "",
             f"- **Scanned:** {_md(result.started)} to {_md(result.finished)}",
             f"- **Overall risk:** {overall_risk(counts)}",
             f"- **Findings:** {len(findings)} ({', '.join(f'{k} {v}' for k, v in counts.items())})",
             f"- **Requests sent:** {result.requests_made}"]
    if result.trend:
        t = result.trend
        lines.append(f"- **Since your previous scan ({_md(t.get('since'))}):** {t.get('fixed', 0)} fixed, "
                     f"{t.get('new', 0)} new, {t.get('still_open', 0)} still open")
    lines.append("")
    remarks = list(result.notes) + list(result.hints)
    if remarks:
        lines += ["## Notes", ""] + [f"- {_md(r)}" for r in remarks] + [""]
    if not findings:
        return "\n".join(lines + ["No findings.", ""])
    lines += ["## Summary", "", "| # | Severity | ID | Finding |", "| --- | --- | --- | --- |"]
    lines += [f"| {i} | {f.severity} | {f.check_id} | {_md(f.title)} |" for i, f in enumerate(findings, 1)]
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines += [f"### {i}. {_md(f.title)}", "", f"**{f.severity}** | {f.check_id} | {_md(f.category)}", "",
                  _md(f.description), "", f"**Evidence:** {_md_code(f.evidence)}", "",
                  f"**Recommendation:** {_md(f.recommendation)}", ""]
        refs = [f"[{_md(reference_label(u))}]({u})" for u in safe_references(f)]
        if refs:
            lines += ["**References:** " + ", ".join(refs), ""]
        score, rating, vector = ai_scores(f)
        techniques = [f"[{_md(t['id'] + ' ' + t['name'])}]({t['url']})" if t["url"] else _md(t["id"] + " " + t["name"])
                      for t in ai_techniques(f)]
        if score is not None or techniques:
            parts = ([f"CVSS {score:.1f} ({_md(rating)}) {_md_code(vector)}"] if score is not None else [])
            parts += (["ATT&CK " + ", ".join(techniques)] if techniques else [])
            lines += ["**AI-estimated risk context:** " + "; ".join(parts) + " _(an estimate for this kind of check, "
                      "not measured on your site; verify before relying on it)_", ""]
    return "\n".join(lines)


def write_markdown(result: ScanResult, findings: list[Finding], path: str) -> None:
    write_text(path, build_markdown(result, findings))
