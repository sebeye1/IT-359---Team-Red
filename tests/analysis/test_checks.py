"""Tests for the checks in webrecon/analysis: one behaviour per test."""

import re
from pathlib import Path

import pytest

from helpers import base_result, ids
from webrecon.analysis import CHECK_CATALOG, REFERENCES, SEVERITY_ORDER, analyze
from webrecon.analysis.checks import content, cookies, cors, exposure, forms, headers, transport
from webrecon.scanning import Form, ProbeResult, ScanResult, parse_set_cookie


def test_http_target_flagged():
    assert "WR-001" in ids(transport.check_https(base_result()))


def test_missing_headers_flagged_and_present_headers_not():
    findings = headers.check_security_headers(base_result(headers={}))
    assert {"WR-010", "WR-011", "WR-012"} <= ids(findings)
    good = base_result(headers={
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()"})
    assert headers.check_security_headers(good) == []


def test_server_version_disclosure():
    r = base_result(headers={"Server": "Apache/2.4.29", "X-Powered-By": "PHP/7.2"})
    assert {"WR-020", "WR-021"} <= ids(headers.check_information_disclosure(r))


def test_insecure_session_cookie_is_medium():
    r = base_result(cookies=[parse_set_cookie("sessionid=1; Path=/", "http://x/")])
    findings = cookies.check_cookies(r)
    assert findings and findings[0].severity == "Medium"


def test_secure_cookie_not_flagged():
    r = base_result(cookies=[parse_set_cookie("sessionid=1; Secure; HttpOnly; SameSite=Lax", "http://x/")])
    assert cookies.check_cookies(r) == []


def test_cors_wildcard_with_credentials_is_high():
    r = base_result(headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert cors.check_cors(r)[0].severity == "High"


def test_exposed_git_requires_signature():
    real = ProbeResult("/.git/HEAD", "http://x/.git/HEAD", 200, body_snippet="ref: refs/heads/main")
    soft404 = ProbeResult("/.git/HEAD", "http://x/.git/HEAD", 200, body_snippet="<html>Page not found</html>")
    assert "WR-060" in ids(exposure.check_exposed_paths(base_result(probes=[real])))
    assert exposure.check_exposed_paths(base_result(probes=[soft404])) == []


def test_password_form_over_http_and_no_csrf():
    form = Form("http://x/login", "http://x/login", "POST",
                [{"name": "password", "type": "password", "autocomplete": ""}])
    assert {"WR-070", "WR-073"} <= ids(forms.check_forms(base_result(forms=[form])))


def test_csrf_token_suppresses_finding():
    form = Form("http://x/c", "http://x/c", "POST", [{"name": "csrf_token", "type": "hidden", "autocomplete": ""}])
    assert "WR-073" not in ids(forms.check_forms(base_result(forms=[form])))


def test_findings_sorted_by_severity():
    r = base_result(headers={"Server": "Apache/2.4.29"},
                    probes=[ProbeResult("/.env", "http://x/.env", 200, body_snippet="DB_PASSWORD=x")])
    order = [SEVERITY_ORDER[f.severity] for f in analyze(r)]
    assert order == sorted(order)


def test_unreachable_target_gives_no_findings():
    assert analyze(ScanResult(target="http://x")) == []


def test_catch_all_probe_is_ignored_by_analyzer():
    p = ProbeResult("/.env", "http://x/.env", 200, body_snippet="DB_PASSWORD=x", catch_all=True)
    assert exposure.check_exposed_paths(base_result(probes=[p])) == []


def test_tls_findings():
    https = dict(final_url="https://x/", target="https://x/")
    bad = base_result(tls={"verified": False, "error": "self-signed certificate"}, **https)
    assert "WR-002" in ids(transport.check_tls(bad))
    soon = transport.check_tls(base_result(tls={"verified": True, "days_left": 5, "expires": "2026-11-11"}, **https))
    assert soon[0].check_id == "WR-003" and soon[0].severity == "Medium"
    later = transport.check_tls(base_result(tls={"verified": True, "days_left": 25, "expires": "x"}, **https))
    assert later[0].severity == "Low"
    assert transport.check_tls(base_result(tls={"verified": True, "days_left": 90}, **https)) == []
    assert transport.check_tls(base_result(tls={"verified": False, "error": "x"})) == []  # plain HTTP target


def test_weak_csp_flagged_but_nonce_policy_is_not():
    weak = base_result(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    assert ids(headers.check_csp_quality(weak)) == {"WR-017"}
    good = base_result(headers={"Content-Security-Policy": "script-src 'self' 'nonce-abc' 'unsafe-inline'"})
    assert headers.check_csp_quality(good) == []
    assert headers.check_csp_quality(base_result(headers={})) == []


def test_new_file_and_actuator_signatures():
    probes = [
        ProbeResult("/actuator/env", "http://x/actuator/env", 200, body_snippet='{"propertySources":[]}'),
        ProbeResult("/.htaccess", "http://x/.htaccess", 200, body_snippet="RewriteEngine On"),
        ProbeResult("/web.config", "http://x/web.config", 200, body_snippet="<html>Not found</html>"),
        ProbeResult("/uploads/", "http://x/uploads/", 200, body_snippet="<p>nothing about an index of things</p>"),
    ]
    found = exposure.check_exposed_paths(base_result(probes=probes))
    assert ids(found) == {"WR-065", "WR-066"}
    assert [f.severity for f in found if f.check_id == "WR-066"] == ["High"]


def test_check_catalog_matches_the_checks_in_the_code():
    checks_dir = Path(__file__).resolve().parents[2] / "webrecon" / "analysis" / "checks"
    source = "".join(p.read_text() for p in sorted(checks_dir.glob("*.py")))
    in_code = set(re.findall(r'"(WR-\d{3})"', source))
    in_catalog = {cid for cid, _, _ in CHECK_CATALOG}
    assert in_code == in_catalog


def test_http_that_serves_content_on_an_https_site_is_flagged():
    https = dict(final_url="https://x/", target="https://x/")
    serving = base_result(http_redirect={"url": "http://x/", "status": 200, "location": ""}, **https)
    assert ids(transport.check_http_redirect(serving)) == {"WR-004"}
    redirecting = base_result(http_redirect={"url": "http://x/", "status": 301, "location": "https://x/"}, **https)
    assert transport.check_http_redirect(redirecting) == []
    assert transport.check_http_redirect(base_result(**https)) == []


def test_mixed_content_distinguishes_active_from_passive():
    res = [
        {"page": "https://x/", "kind": "script", "url": "http://evil/a.js", "integrity": False},
        {"page": "https://x/", "kind": "img", "url": "http://evil/a.png", "integrity": False},
        {"page": "https://x/", "kind": "script", "url": "https://ok/a.js", "integrity": False},
        {"page": "http://x/", "kind": "script", "url": "http://x/b.js", "integrity": False},  # plain-HTTP page: not mixed
    ]
    found = content.check_mixed_content(base_result(resources=res))
    assert sorted(f.severity for f in found) == ["Low", "Medium"]
    assert content.check_mixed_content(base_result(resources=res[2:])) == []


def test_sri_only_flags_third_party_resources_without_integrity():
    res = [
        {"page": "https://x/", "kind": "script", "url": "https://cdn.other/a.js", "integrity": False},
        {"page": "https://x/", "kind": "script", "url": "https://cdn.other/b.js", "integrity": True},
        {"page": "https://x/", "kind": "script", "url": "https://x/own.js", "integrity": False},
        {"page": "https://x/", "kind": "img", "url": "https://cdn.other/i.png", "integrity": False},
    ]
    found = content.check_sri(base_result(resources=res, final_url="https://x/"))
    assert len(found) == 1 and "a.js" in found[0].evidence and "b.js" not in found[0].evidence
    assert "own.js" not in found[0].evidence


def test_cors_reflection_is_high_with_credentials_and_medium_without():
    origin = "https://webrecon-probe.example"
    with_creds = base_result(cors_probe={"origin": origin, "allow_origin": origin, "allow_credentials": "True"})
    found = cors.check_cors_reflection(with_creds)
    assert [(f.check_id, f.severity) for f in found] == [("WR-041", "High")]
    no_creds = base_result(cors_probe={"origin": origin, "allow_origin": origin, "allow_credentials": ""})
    assert cors.check_cors_reflection(no_creds)[0].severity == "Medium"


def test_cors_reflection_ignores_wildcards_fixed_origins_and_missing_probe():
    origin = "https://webrecon-probe.example"
    assert cors.check_cors_reflection(base_result(cors_probe={"origin": origin, "allow_origin": "*"})) == []
    assert cors.check_cors_reflection(
        base_result(cors_probe={"origin": origin, "allow_origin": "https://app.example"})) == []
    assert cors.check_cors_reflection(base_result()) == []


def test_generator_tag_flagged_only_when_it_reveals_a_version():
    found = headers.check_generator(base_result(generators=["WordPress 5.2.1", "Hugo"]))
    assert ids(found) == {"WR-022"} and "WordPress 5.2.1" in found[0].evidence and "Hugo" not in found[0].evidence
    assert headers.check_generator(base_result(generators=["Hugo"])) == []
    assert headers.check_generator(base_result()) == []


def test_analyze_attaches_reference_links_to_findings():
    found = analyze(base_result(headers={}))
    by_id = {f.check_id: f for f in found}
    assert any("developer.mozilla.org" in u for u in by_id["WR-010"].references)
    assert any("cwe.mitre.org" in u for u in by_id["WR-001"].references)


def test_reference_table_only_uses_https_links_and_known_check_ids():
    catalog = {cid for cid, _, _ in CHECK_CATALOG}
    assert set(REFERENCES) <= catalog
    assert all(url.startswith("https://") for urls in REFERENCES.values() for url in urls)


# ------------------------------------------------------------------ outdated JavaScript libraries

def scripts(*urls):
    return base_result(resources=[{"page": "https://x/", "kind": "script", "url": u, "integrity": False}
                                  for u in urls])


@pytest.mark.parametrize("url,flagged", [
    ("https://x/js/jquery-1.12.4.min.js", True),
    ("https://x/js/jquery-3.4.1.js", True),
    ("https://x/js/jquery-3.5.0.min.js", False),
    ("https://x/js/jquery-3.5.min.js", False),                       # 3.5 means 3.5.0
    ("https://x/js/jquery-3.4.min.js", True),
    ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js", True),
    ("https://x/js/jquery-ui-1.12.1.min.js", False),                 # jQuery UI is a different library
    ("https://x/js/jquery-migrate-1.4.1.min.js", False),
    ("https://x/js/jquery.min.js", False),                           # no version in the URL: not judged
    ("https://x/js/bootstrap-3.3.7.min.js", True),
    ("https://x/js/bootstrap-3.4.1.min.js", False),
    ("https://x/js/bootstrap-4.0.0.js", True),
    ("https://x/js/bootstrap-4.3.1.js", False),
    ("https://x/js/bootstrap-5.3.0.js", False),
    ("https://x/js/bootstrap-datepicker-1.9.0.js", False),
    ("https://ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js", True),
    ("https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js", True),
    ("https://x/js/angular-route-1.6.9.js", False),
    ("https://x/js/app.v2.js", False),
])
def test_outdated_library_detection_from_script_urls(url, flagged):
    assert bool(content.check_outdated_libraries(scripts(url))) is flagged


def test_outdated_library_finding_details():
    (f,) = content.check_outdated_libraries(scripts("https://x/js/jquery-1.12.4.min.js"))
    assert (f.check_id, f.severity, f.title) == ("WR-023", "Medium", "Outdated jQuery 1.12.4 in use")
    assert "3.5.0" in f.recommendation and "jquery-1.12.4.min.js" in f.evidence
    assert all(u.startswith("https://") for u in f.references) and any("CVE-2020-11022" in u for u in f.references)
    via_analyze = next(x for x in analyze(scripts("https://x/js/jquery-1.12.4.min.js"))
                       if x.check_id == "WR-023")
    assert via_analyze.references == f.references           # analyze() keeps the check's own links


def test_the_same_library_version_is_reported_once_and_only_scripts_count():
    res = scripts("https://x/a/jquery-1.12.4.js", "https://x/b/jquery-1.12.4.js", "https://x/jquery-2.2.4.js")
    res.resources.append({"page": "https://x/", "kind": "img", "url": "https://x/jquery-1.0.0.js", "integrity": False})
    assert [f.title for f in content.check_outdated_libraries(res)] == [
        "Outdated jQuery 1.12.4 in use", "Outdated jQuery 2.2.4 in use"]
