"""
components.py - Small pieces every report is built from: severity badges, tables, the page shell,
reference links, writing a file, and opening a report in the browser.
"""

from __future__ import annotations

import os
import webbrowser
from html import escape
from urllib.parse import urlparse

from webrecon.analysis import Finding
from webrecon.reporting.style import CSS, FOOTER, RATING_MEANINGS, SEVERITY_COLORS


def badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#666")
    return f'<span class="sev" style="background:{color}">{escape(str(severity))}</span>'


def table(rows: list[tuple], headers: tuple) -> str:
    if not rows:
        return '<p class="muted">None found.</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def bullets(title: str, items: list[str]) -> str:
    if not items:
        return ""
    return f"<section><h2>{escape(title)}</h2><ul>" + "".join(f"<li>{escape(i)}</li>" for i in items) + "</ul></section>"


def cards(counts: dict) -> str:
    return "".join(
        f'<div class="card" style="background:{SEVERITY_COLORS[s]}"><div class="n">{n}</div>{s}</div>'
        for s, n in counts.items())


def overall_risk(counts: dict) -> str:
    for level in ("Critical", "High", "Medium", "Low"):
        if counts.get(level):
            return level
    return "Info"


def page(title: str, heading: str, subtitles: list[str], body: str, script: str = "") -> str:
    sub = "".join(f"<p>{escape(line)}</p>" for line in subtitles)
    script_tag = f"<script>{script}</script>" if script else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>{CSS}</style></head>
<body>
<header><h1>{escape(heading)}</h1>{sub}</header>
<main>
{body}
</main>
<footer>{FOOTER}</footer>
{script_tag}
</body></html>"""


def write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    with open(path, "w", encoding=encoding) as fh:
        fh.write(text)


def safe_references(finding: Finding) -> list[str]:
    return [u for u in finding.references if u.startswith("https://")]


ATTACK_PREFIX = "https://attack.mitre.org/"


def ai_scores(finding: Finding) -> tuple:
    """(score, rating, vector) of the AI-estimated CVSS on a finding, or (None, '', '') if it has none."""
    cvss = (finding.enrichment or {}).get("cvss") or {}
    score = cvss.get("score")
    if isinstance(score, (int, float)):
        return float(score), str(cvss.get("rating", "")), str(cvss.get("vector", ""))
    return None, "", ""


def ai_techniques(finding: Finding) -> list[dict]:
    """The ATT&CK techniques on a finding, each with a link that is only kept if it really points at MITRE."""
    out = []
    for t in (finding.enrichment or {}).get("attack") or []:
        if isinstance(t, dict) and isinstance(t.get("id"), str):
            url = t.get("url") if str(t.get("url", "")).startswith(ATTACK_PREFIX) else ""
            out.append({"id": t["id"], "name": str(t.get("name", "")), "url": url, "verified": bool(t.get("verified")),
                        "tactics": [str(x) for x in t.get("tactics") or []], "reason": str(t.get("reason", ""))})
    return out


def reference_label(url: str) -> str:
    parts = urlparse(url)
    tail = parts.path.rstrip("/").rsplit("/", 1)[-1]
    if "cwe.mitre.org" in parts.netloc:
        return "CWE-" + tail.removesuffix(".html")
    if "mozilla.org" in parts.netloc:
        return "MDN: " + tail.replace("_", " ")
    if "nvd.nist.gov" in parts.netloc:
        return "NVD: " + tail
    if "owasp.org" in parts.netloc:
        return "OWASP: " + tail.replace("_", " ")
    return parts.netloc


def legend() -> str:
    items = "".join(f"<li>{badge(sev)} {escape(text)}</li>" for sev, text in RATING_MEANINGS.items())
    return f'<details class="legend"><summary>What do the ratings mean?</summary><ul>{items}</ul></details>'


def open_in_browser(path: str) -> None:
    try:
        webbrowser.open("file://" + os.path.abspath(path))
    except Exception:
        print(f"[-] Could not open a browser. Open {path} manually.")
