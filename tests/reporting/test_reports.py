"""Tests for webrecon/reporting."""

from helpers import base_result
from webrecon.analysis import Finding, analyze
from webrecon.reporting import build_html, build_index_html


def test_report_escapes_html():
    r = base_result(headers={"X-Test": "<script>alert(1)</script>"})
    html = build_html(r, analyze(r))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_index_page_and_notes_in_report():
    page = build_index_html([
        {"target": "http://a", "ok": True, "counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
         "report": "a.html"},
        {"target": "http://<b>", "ok": False, "error": "no route"}])
    assert 'href="a.html"' in page and "High" in page and "&lt;b&gt;" in page and "Unreachable" in page
    r = base_result(notes=["Used HTTP <fallback>"], hints=["Try --insecure"])
    html = build_html(r, [])
    assert "Scan Notes" in html and "Used HTTP &lt;fallback&gt;" in html


def test_report_has_filters_links_and_fix_first_box():
    r = base_result()
    findings = [Finding("WR-060", "Git exposed", "High", "c", "d", "e", "Remove .git"),
                Finding("WR-014", "Permissions", "Info", "c", "d", "e", "Add header")]
    html = build_html(r, findings)
    assert 'data-sev="High"' in html and 'href="#f1"' in html and 'id="f2"' in html
    assert "Fix these first" in html and "Remove .git" in html
    assert "Add header</li>" not in html          # Info findings are not "fix first"
    assert "Fix these first" not in build_html(r, [])


def test_every_page_uses_the_same_shell_and_footer():
    from webrecon.reporting import build_compare_html
    diff = {"fixed": [], "new": [], "unchanged": [], "changed": []}
    pages = [build_html(base_result(), []), build_index_html([]),
             build_compare_html({}, {}, diff, "before", "after")]
    assert all("IT 359 Team Red" in p and "prefers-color-scheme:dark" in p for p in pages)


def test_unknown_severity_does_not_break_the_comparison_page():
    from webrecon.reporting import build_compare_html
    odd = {"severity": "Weird", "check_id": "WR-1", "title": "t"}
    diff = {"fixed": [odd], "new": [], "unchanged": [], "changed": []}
    assert "Weird" in build_compare_html({}, {}, diff, "b", "a")


def test_open_in_browser_never_raises(monkeypatch, capsys):
    from webrecon.reporting import components

    def broken(_url):
        raise RuntimeError("no browser")
    monkeypatch.setattr(components.webbrowser, "open", broken)
    components.open_in_browser("x.html")
    assert "Could not open a browser" in capsys.readouterr().out


def test_report_shows_request_count_and_scan_time():
    html = build_html(base_result(requests_made=27, duration=4.5), [])
    assert "Requests sent:</span> 27" in html and "4.5s" in html


# ------------------------------------------------------------------ references, legend, CSV and Markdown exports

def _finding(**overrides):
    values = dict(check_id="WR-010", title="Missing CSP", severity="Medium", category="Security Headers",
                  description="d", evidence="e", recommendation="Add the header",
                  references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                              "https://cwe.mitre.org/data/definitions/79.html"])
    values.update(overrides)
    return Finding(**values)


def test_report_links_references_and_skips_unsafe_ones():
    f = _finding(references=["https://cwe.mitre.org/data/definitions/79.html", "javascript:alert(1)"])
    html = build_html(base_result(), [f])
    assert 'href="https://cwe.mitre.org/data/definitions/79.html"' in html and ">CWE-79<" in html
    assert "javascript:alert(1)" not in html
    assert "References:" not in build_html(base_result(), [_finding(references=[])])


def test_report_explains_what_the_ratings_mean():
    assert "What do the ratings mean?" in build_html(base_result(), [])


def test_csv_has_one_row_per_finding_and_defuses_spreadsheet_formulas():
    import csv
    import io
    from webrecon.reporting import build_csv
    rows = list(csv.reader(io.StringIO(build_csv(
        base_result(), [_finding(evidence='=HYPERLINK("http://evil","click")'), _finding(title="+cmd", evidence="a,b\n\"c\"")]))))
    assert rows[0][:3] == ["target", "check_id", "severity"] and len(rows) == 3
    assert rows[1][5].startswith("'=") and rows[2][3] == "'+cmd"   # a leading quote stops formula execution
    assert rows[2][5] == 'a,b\n"c"'                               # commas, quotes and newlines survive
    assert "developer.mozilla.org" in rows[1][7]


def test_write_csv_adds_a_bom_so_excel_reads_utf8(tmp_path):
    from webrecon.reporting import write_csv
    path = tmp_path / "f.csv"
    write_csv(base_result(), [_finding(title="caf\u00e9")], str(path))
    assert path.read_bytes().startswith(b"\xef\xbb\xbf") and "caf\u00e9" in path.read_text(encoding="utf-8-sig")


def test_markdown_escapes_tables_html_and_backticks():
    from webrecon.reporting import build_markdown
    f = _finding(title="A | B <script>", evidence="x`y` <b>z</b>")
    md = build_markdown(base_result(notes=["a note"]), [f])
    assert "| 1 | Medium | WR-010 | A \\| B &lt;script&gt; |" in md
    assert "`x'y' <b>z</b>`" in md                      # evidence sits inside a code span, with backticks removed
    assert "- a note" in md and "[MDN: CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)" in md
    assert "No findings." in build_markdown(base_result(), [])


def test_trend_is_shown_in_the_html_and_markdown_reports():
    from webrecon.reporting import build_markdown
    trend = {"since": "2026-11-01 09:00:00", "fixed": 4, "new": 1, "still_open": 3}
    r = base_result(trend=trend)
    html = build_html(r, [])
    assert "Since your previous scan" in html and "4 fixed, 1 new, 3 still open" in html
    assert "Since your previous scan (2026-11-01 09:00:00):** 4 fixed, 1 new, 3 still open" in build_markdown(r, [])
    assert "Since your previous scan" not in build_html(base_result(), [])


# ------------------------------------------------------------------ AI-estimated context

def _enriched(**overrides):
    enrichment = {"source": "ai", "model": "test-model", "estimated": True,
                  "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1, "rating": "Medium"},
                  "attack": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"],
                              "url": "https://attack.mitre.org/techniques/T1190/", "verified": True, "reason": "Reachable."}],
                  "rationale": "Typical for this weakness."}
    enrichment.update(overrides)
    finding = _finding()
    finding.enrichment = enrichment
    return finding


def test_the_ai_estimate_is_shown_with_its_score_vector_technique_and_a_warning():
    html = build_html(base_result(), [_enriched()])
    assert "AI-estimated risk context" in html and "CVSS 6.1 (Medium)" in html
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in html
    assert 'href="https://attack.mitre.org/techniques/T1190/"' in html and "T1190 Exploit Public-Facing Application" in html
    assert "initial-access" in html and "Reachable." in html
    assert "Estimated by test-model" in html and "not measured on your site" in html and "Verify before relying on it" in html
    assert "Highest AI-estimated CVSS:</strong> 6.1 (Medium)" in html


def test_findings_without_ai_context_look_exactly_as_before():
    html = build_html(base_result(), [_finding()])
    assert "AI-estimated" not in html and "ATT&amp;CK" not in html


def test_the_ai_text_is_escaped_and_only_mitre_links_are_clickable():
    hostile = _enriched(rationale="<script>alert(1)</script>",
                        attack=[{"id": "T1190", "name": "<img src=x onerror=alert(1)>", "tactics": ["<b>x</b>"],
                                 "url": "javascript:alert(1)", "verified": False, "reason": "<i>r</i>"},
                                {"id": "T1040", "name": "Sniffing", "tactics": [], "url": "https://evil.example/x",
                                 "verified": True, "reason": ""}])
    html = build_html(base_result(), [hostile])
    for raw in ("<script>alert(1)</script>", "<img src=x", "<b>x</b>", "<i>r</i>", "javascript:alert(1)", "evil.example"):
        assert raw not in html, raw
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "not checked against MITRE" in html


def test_a_score_that_is_not_a_number_is_ignored():
    html = build_html(base_result(), [_enriched(cvss={"vector": "x", "score": "9.9; DROP TABLE", "rating": "High"})])
    assert "9.9" not in html and "Highest AI-estimated" not in html


def test_the_csv_has_ai_columns_and_stays_safe():
    import csv
    import io
    from webrecon.reporting import build_csv
    rows = list(csv.reader(io.StringIO(build_csv(base_result(), [_enriched(), _finding()]))))
    header = rows[0]
    assert header[-3:] == ["ai_cvss_score", "ai_cvss_vector", "ai_attack_techniques"]
    assert rows[1][-3:] == ["6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "T1190 Exploit Public-Facing Application"]
    assert rows[2][-3:] == ["", "", ""]
    tampered = _enriched(cvss={"vector": "=HYPERLINK(\"http://evil\")", "score": 6.1, "rating": "Medium"})
    cell = list(csv.reader(io.StringIO(build_csv(base_result(), [tampered]))))[1][-2]
    assert cell.startswith("'=")                                  # a leading quote stops a spreadsheet running it


def test_the_markdown_line_marks_the_estimate_and_links_to_mitre():
    from webrecon.reporting import build_markdown
    md = build_markdown(base_result(), [_enriched()])
    assert "**AI-estimated risk context:** CVSS 6.1 (Medium)" in md
    assert "[T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)" in md
    assert "verify before relying on it" in md
    assert "AI-estimated" not in build_markdown(base_result(), [_finding()])
