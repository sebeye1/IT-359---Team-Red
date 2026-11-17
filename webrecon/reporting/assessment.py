"""
assessment.py - The per-target HTML security assessment report.
"""

from __future__ import annotations

from html import escape

from webrecon.analysis import Finding, severity_counts
from webrecon.reporting.components import (ai_scores, ai_techniques, badge, bullets, cards, legend, overall_risk, page,
                                           reference_label, safe_references, table, write_text)
from webrecon.reporting.style import FILTER_JS, SEVERITY_COLORS
from webrecon.scanning import ScanResult


def _findings_summary(findings: list[Finding], counts: dict) -> str:
    if not findings:
        return '<p class="muted">None found.</p>'
    rows = "".join(
        f'<tr data-sev="{escape(f.severity)}"><td>{badge(f.severity)}</td><td>{escape(f.check_id)}</td>'
        f'<td><a href="#f{i}">{escape(f.title)}</a></td><td>{escape(f.category)}</td></tr>'
        for i, f in enumerate(findings, 1))
    buttons = "".join(f'<button data-sev="{escape(sev)}">{escape(sev)} ({counts[sev]})</button>'
                      for sev in SEVERITY_COLORS if counts.get(sev))
    return ('<div class="filters"><button class="on" data-sev="all">All</button>' + buttons + "</div>"
            "<table><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Category</th></tr>" + rows + "</table>")


def _trend(trend: dict) -> str:
    if not trend:
        return ""
    return (f'<div class="trend"><strong>Since your previous scan</strong> ({escape(str(trend.get("since")))}): '
            f'{trend.get("fixed", 0)} fixed, {trend.get("new", 0)} new, {trend.get("still_open", 0)} still open.</div>')


def _fix_first(findings: list[Finding]) -> str:
    urgent = [(i, f) for i, f in enumerate(findings, 1) if f.severity != "Info"][:3]
    if not urgent:
        return ""
    items = "".join(f'<li><a href="#f{i}">{escape(f.title)}</a> ({escape(f.severity)}): '
                    f'{escape(f.recommendation)}</li>' for i, f in urgent)
    return f'<div class="fixfirst"><strong>Fix these first</strong><ol>{items}</ol></div>'


def _ai_context(f: Finding) -> str:
    """CVSS and ATT&CK estimated by an AI server, always labelled as an estimate."""
    if not f.enrichment:
        return ""
    score, rating, vector = ai_scores(f)
    parts = []
    if score is not None:
        parts.append(f"CVSS {score:.1f} ({escape(rating)}) <code>{escape(vector)}</code>")
    techniques = []
    for t in ai_techniques(f):
        label = escape(f"{t['id']} {t['name']}".strip())
        text = (f'<a href="{escape(t["url"])}" rel="noopener noreferrer">{label}</a>' if t["url"] else label)
        if t["tactics"]:
            text += f' <span class="muted">({escape(", ".join(t["tactics"]))})</span>'
        if not t["verified"]:
            text += ' <span class="muted">(not checked against MITRE&rsquo;s list)</span>'
        if t["reason"]:
            text += f' <span class="muted">&ndash; {escape(t["reason"])}</span>'
        techniques.append(text)
    if techniques:
        parts.append("MITRE ATT&amp;CK: " + "; ".join(techniques))
    if not parts:
        return ""
    rationale = f" {escape(str(f.enrichment.get('rationale', '')))}" if f.enrichment.get("rationale") else ""
    model = escape(str(f.enrichment.get("model", "an AI model")))
    return (f'\n          <p><span class="label">AI-estimated risk context:</span> {" | ".join(parts)}<br>'
            f'<span class="muted">Estimated by {model} from the kind of check, not measured on your site.{rationale} '
            f'Verify before relying on it.</span></p>')


def _ai_summary(findings: list[Finding]) -> str:
    scored = [(ai_scores(f)[0], f) for f in findings if ai_scores(f)[0] is not None]
    if not scored:
        return ""
    score, worst = max(scored, key=lambda pair: pair[0])
    return (f'<p class="muted"><strong>Highest AI-estimated CVSS:</strong> {score:.1f} ({escape(ai_scores(worst)[1])}), '
            f'{escape(worst.title)}. Estimates for the kind of weakness, not measurements of this site.</p>')


def _finding_detail(i: int, f: Finding) -> str:
    links = " ".join(f'<a href="{escape(u)}" rel="noopener noreferrer">{escape(reference_label(u))}</a>'
                     for u in safe_references(f))
    references = f'\n          <p><span class="label">References:</span> {links}</p>' if links else ""
    return f"""
        <div class="finding" id="f{i}" data-sev="{escape(f.severity)}" style="border-left-color:{SEVERITY_COLORS[f.severity]}">
          <h3>{i}. {escape(f.title)} {badge(f.severity)}</h3>
          <p class="muted">{escape(f.check_id)} | {escape(f.category)}</p>
          <p><span class="label">Description:</span> {escape(f.description)}</p>
          <p><span class="label">Evidence:</span> <code>{escape(f.evidence)}</code></p>
          <p><span class="label">Recommendation:</span> {escape(f.recommendation)}</p>{references}{_ai_context(f)}
        </div>"""


def _tls_summary(tls: dict) -> str:
    if tls.get("verified"):
        return (f"Certificate valid, expires {tls.get('expires') or 'unknown'} "
                f"({tls.get('days_left')} day(s) left), issuer {tls.get('issuer') or 'unknown'}, "
                f"{tls.get('version') or 'unknown protocol'}")
    if tls.get("verified") is False:
        return f"Certificate failed validation: {tls.get('error') or 'unknown error'}"
    return "Not checked (target is not HTTPS or the TLS check could not complete)"


def _recon_data(result: ScanResult) -> str:
    cookie_rows = [(c.name, "Yes" if c.secure else "No", "Yes" if c.httponly else "No",
                    c.samesite or "Not set", c.source_url) for c in result.cookies]
    form_rows = [(f.page_url, f.method, f.action,
                  ", ".join(f"{i['name'] or '(unnamed)'} [{i['type']}]" for i in f.inputs))
                 for f in result.forms]
    page_rows = [(p.status_code, p.url, p.title) for p in result.pages]
    probe_rows = [(p.path, f"{p.status_code} (same as the site's catch-all page, ignored)"
                   if p.catch_all else p.status_code) for p in result.probes]
    methods = ", ".join(result.allowed_methods) or "Not advertised"
    robots = (f"<pre>{escape(result.robots_txt)}</pre>" if result.robots_txt
              else '<p class="muted">Not found.</p>')
    return f"""<section>
  <h2>Reconnaissance Data</h2>
  <p><span class="label">Final URL:</span> {escape(result.final_url)} |
     <span class="label">Status:</span> {escape(str(result.status_code))} |
     <span class="label">Allowed methods:</span> {escape(methods)} |
     <span class="label">TRACE enabled:</span> {"Yes" if result.trace_enabled else "No"}</p>
  <p><span class="label">Requests sent:</span> {result.requests_made} |
     <span class="label">Scan time:</span> {result.duration:g}s</p>
  <p><span class="label">TLS:</span> {escape(_tls_summary(result.tls or {}))}</p>
  <p><span class="label">Redirect chain:</span> {escape(" -> ".join(result.redirect_chain)) or "None"}</p>
  <h3>Response Headers</h3>{table(sorted(result.headers.items()), ("Header", "Value"))}
  <h3>Cookies</h3>{table(cookie_rows, ("Name", "Secure", "HttpOnly", "SameSite", "Set by"))}
  <h3>Pages Crawled</h3>{table(page_rows, ("Status", "URL", "Title"))}
  <h3>Forms</h3>{table(form_rows, ("Page", "Method", "Action", "Inputs"))}
  <h3>Internal Links ({len(result.links)})</h3>{table([(u,) for u in result.links], ("URL",))}
  <h3>External Links ({len(result.external_links)})</h3>{table([(u,) for u in result.external_links], ("URL",))}
  <h3>Path Probes</h3>{table(probe_rows, ("Path", "Status"))}
  <h3>robots.txt</h3>{robots}
</section>"""


def build_html(result: ScanResult, findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    details = "".join(_finding_detail(i, f) for i, f in enumerate(findings, 1)) or '<p class="muted">No findings.</p>'
    body = f"""<section>
  <h2>Executive Summary</h2>
  <p>WebRecon performed automated reconnaissance and configuration analysis against
  <code>{escape(result.final_url or result.target)}</code>. The scan crawled {len(result.pages)} page(s),
  found {len(result.forms)} form(s) and {len(result.cookies)} cookie(s), and identified
  <strong>{len(findings)}</strong> finding(s). Overall risk rating: {badge(overall_risk(counts))}</p>
  <div class="cards">{cards(counts)}</div>
  {legend()}
  {_trend(result.trend)}
  {_ai_summary(findings)}
  {_fix_first(findings)}
  <p class="muted">Automated results should be manually verified. This scan was limited to an
  authorized testing environment and did not attempt exploitation.</p>
</section>
{bullets("Scan Notes", list(result.notes) + list(result.hints))}
<section><h2>Findings Summary</h2>{_findings_summary(findings, counts)}</section>
<section><h2>Detailed Findings</h2>{details}</section>
{_recon_data(result)}
{bullets("Scan Errors", list(result.errors))}"""
    return page(f"WebRecon Report - {result.target}", "WebRecon Security Assessment Report",
                 [f"Target: {result.target}", f"Scan window: {result.started} to {result.finished}"],
                 body, FILTER_JS)


def write_html(result: ScanResult, findings: list[Finding], path: str) -> None:
    write_text(path, build_html(result, findings))
