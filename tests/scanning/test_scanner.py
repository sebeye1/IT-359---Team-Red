"""Tests for webrecon/scanning: parsing, retries, URL handling, TLS, crawling helpers (no real network)."""

import shutil
import socket
import ssl
import subprocess
import threading

import pytest
import requests
from bs4 import BeautifulSoup

import webrecon.scanning.scanner as scanner_mod
from helpers import FakeResp
from webrecon.scanning import (Scanner, diagnose, normalize_target, parse_forms, parse_set_cookie, probe_tls)


def test_parse_set_cookie_flags():
    c = parse_set_cookie("sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Strict", "http://x/")
    assert c.name == "sessionid" and c.secure and c.httponly and c.samesite == "Strict"


def test_parse_forms_resolves_action_and_inputs():
    html = '<form action="/login" method="post"><input type="password" name="pw"></form>'
    forms = parse_forms(BeautifulSoup(html, "html.parser"), "http://x/page")
    assert forms[0].action == "http://x/login"
    assert forms[0].method == "POST"
    assert forms[0].inputs[0]["type"] == "password"


def test_normalize_target_variants():
    assert normalize_target("localhost:8080") == ("http://localhost:8080", False)
    assert normalize_target("127.0.0.1:9000") == ("http://127.0.0.1:9000", False)
    assert normalize_target("example.com") == ("https://example.com", True)
    assert normalize_target("  10.0.0.5:8443 ") == ("https://10.0.0.5:8443", True)
    assert normalize_target("HTTP://Example.com/a") == ("http://Example.com/a", False)
    assert normalize_target("https://x.org") == ("https://x.org", False)


def test_diagnose_gives_actionable_advice():
    E = requests.exceptions
    assert "--insecure" in diagnose(E.SSLError("certificate verify failed"))
    assert "resolved" in diagnose(E.ConnectionError("Name or service not known"))
    assert "port" in diagnose(E.ConnectionError("Connection refused"))
    assert "--timeout" in diagnose(E.Timeout("slow"))
    assert "loop" in diagnose(E.TooManyRedirects("x"))
    assert diagnose(None) == ""


def test_retries_when_server_is_rate_limiting(monkeypatch):
    s = Scanner("http://x/", delay=0, retries=2)
    monkeypatch.setattr(scanner_mod.time, "sleep", lambda _: None)
    replies = iter([FakeResp(status=429, headers={"Retry-After": "0"}), FakeResp(status=503), FakeResp(status=200)])
    calls = []
    monkeypatch.setattr(s, "_send", lambda *a, **k: calls.append(1) or next(replies))
    assert s._request("GET", "http://x/").status_code == 200
    assert len(calls) == 3


def test_bare_host_falls_back_from_https_to_http(monkeypatch):
    s = Scanner("example.test", delay=0, retries=0)

    def fake_send(method, url, **kw):
        if url.startswith("https://"):
            raise requests.ConnectionError("refused")
        return FakeResp(url=url, headers={"Server": "x"})

    monkeypatch.setattr(s, "_send", fake_send)
    assert s.fetch_main() is True
    assert s.target.startswith("http://") and s.result.errors == []
    assert any("HTTP" in n for n in s.result.notes)


def test_unreachable_target_gets_a_hint(monkeypatch):
    s = Scanner("http://nowhere.test", delay=0, retries=0)
    monkeypatch.setattr(s, "_send", lambda *a, **k: (_ for _ in ()).throw(
        requests.ConnectionError("Name or service not known")))
    assert s.fetch_main() is False
    assert "resolved" in s.result.hints[0]


def test_insecure_is_not_overridden_by_environment(monkeypatch):
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/bundle.pem")
    s = Scanner("http://x/", verify_tls=False)
    seen = {}

    class R:
        def iter_content(self, chunk_size): return iter([b"ok"])
        def close(self): pass

    monkeypatch.setattr(s.session, "request", lambda *a, **k: seen.update(k) or R())
    s._send("GET", "http://x/")
    assert seen["verify"] is False


def test_response_body_is_capped(monkeypatch):
    s = Scanner("http://x/")

    class R:
        def iter_content(self, chunk_size):
            for _ in range(100):
                yield b"a" * 500_000
        def close(self): pass

    monkeypatch.setattr(s.session, "request", lambda *a, **k: R())
    assert len(s._send("GET", "http://x/")._content) < 3_000_000


def test_cookie_is_only_sent_to_the_target_host():
    s = Scanner("http://localhost:1", cookie="a=b; c=d")
    ok = s.session.prepare_request(requests.Request("GET", "http://localhost:1/"))
    other = s.session.prepare_request(requests.Request("GET", "http://evil.test/"))
    assert "a=b" in ok.headers.get("Cookie", "")
    assert "Cookie" not in other.headers


def test_robots_txt_is_respected_when_asked(monkeypatch):
    s = Scanner("http://x/", respect_robots=True)
    monkeypatch.setattr(s, "_request", lambda *a, **k: FakeResp(text="User-agent: *\nDisallow: /admin/\n"))
    s._load_robots("http://x/")
    assert not s._allowed("http://x/admin/panel") and s._allowed("http://x/about")
    monkeypatch.setattr(s, "_request", lambda *a, **k: FakeResp(status=404))
    s._load_robots("http://x/")
    assert s._allowed("http://x/anything")


def test_catch_all_detection():
    base = {"hash": scanner_mod.hashlib.sha256(b"x" * 1000).hexdigest(), "length": 1000}
    assert Scanner._looks_like_catch_all(FakeResp(content=b"x" * 1000), base)          # identical
    assert Scanner._looks_like_catch_all(FakeResp(content=b"y" * 1010), base)          # nearly same size
    assert not Scanner._looks_like_catch_all(FakeResp(content=b"DB_PASSWORD=x"), base)  # short real file
    assert not Scanner._looks_like_catch_all(FakeResp(content=b"x"), None)


def test_probe_tls_flags_self_signed_certificate(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    key, crt = str(tmp_path / "k.pem"), str(tmp_path / "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-days", "5", "-subj", "/CN=localhost"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        try:
            conn, _ = srv.accept()
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except Exception:
                pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    info = probe_tls("127.0.0.1", srv.getsockname()[1], 5)
    assert info["verified"] is False and "self" in info["error"].lower()


def test_cookie_reaches_ipv6_and_single_label_hosts():
    for url in ("http://[::1]:8080/", "http://localhost:8080/", "http://intranet/"):
        s = Scanner(url, cookie="a=b")
        prepared = s.session.prepare_request(requests.Request("GET", url))
        assert "a=b" in prepared.headers.get("Cookie", ""), url


def test_crawler_records_page_resources():
    s = Scanner("https://x/")
    html = ('<link rel="stylesheet" href="/a.css"><link rel="icon" href="/f.ico">'
            '<script src="https://cdn/x.js" integrity="sha384-1"></script><img src="data:image/png;base64,AA">'
            '<iframe src="http://frame/"></iframe>')
    s._collect_resources(BeautifulSoup(html, "html.parser"), "https://x/")
    got = {(r["kind"], r["url"], r["integrity"]) for r in s.result.resources}
    assert got == {("stylesheet", "https://x/a.css", False), ("script", "https://cdn/x.js", True),
                   ("iframe", "http://frame/", False)}


def test_http_redirect_probe_is_quiet_when_port_80_is_closed(monkeypatch):
    s = Scanner("https://x/", retries=0)
    s.result.final_url = "https://x/"
    monkeypatch.setattr(s, "_send", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("refused")))
    s.collect_http_redirect()
    assert s.result.http_redirect == {} and s.result.errors == []


# ------------------------------------------------------------------ time limit, Ctrl+C, counting, sitemap, CORS

def test_requests_are_counted(monkeypatch):
    s = Scanner("http://x/")

    class R:
        def iter_content(self, chunk_size): return iter([b"ok"])
        def close(self): pass

    monkeypatch.setattr(s.session, "request", lambda *a, **k: R())
    s._send("GET", "http://x/")
    s._send("GET", "http://x/")
    assert s.result.requests_made == 2


def test_time_limit_gives_partial_results_instead_of_an_error(monkeypatch):
    import itertools
    s = Scanner("http://x/", max_time=5, delay=0)
    clock = itertools.chain([0.0], itertools.repeat(100.0))  # the first reading starts the clock, then time is up
    monkeypatch.setattr(scanner_mod.time, "monotonic", lambda: next(clock))
    result = s.run()
    assert result.partial and not result.interrupted
    assert "--max-time" in result.notes[0] and result.status_code is None


def test_ctrl_c_gives_partial_results_and_flags_the_interruption(monkeypatch):
    s = Scanner("http://x/")

    def interrupt():
        raise KeyboardInterrupt
    monkeypatch.setattr(s, "_run_steps", interrupt)
    result = s.run()
    assert result.partial and result.interrupted and "Ctrl+C" in result.notes[0]


def test_no_time_limit_when_max_time_is_unset(monkeypatch):
    s = Scanner("http://x/", max_time=None)
    monkeypatch.setattr(s, "_run_steps", lambda: None)
    assert s.run().partial is False and s.deadline is None


SITEMAP = """<urlset><url><loc>http://x/a</loc></url><url><loc> http://x/b?p=1&amp;q=2#frag </loc></url>
<url><loc>http://other.example/c</loc></url><url><loc>http://x/more.xml</loc></url>
<url><loc>http://x/a</loc></url></urlset>"""


def test_sitemap_urls_are_same_origin_unique_and_not_nested_sitemaps(monkeypatch):
    s = Scanner("http://x/")
    monkeypatch.setattr(s, "_request", lambda *a, **k: FakeResp(text=SITEMAP))
    assert s._sitemap_urls("http://x/") == ["http://x/a", "http://x/b?p=1&q=2"]
    assert "2 page(s)" in s.result.notes[0]


def test_missing_or_bogus_sitemap_adds_nothing(monkeypatch):
    s = Scanner("http://x/")
    monkeypatch.setattr(s, "_request", lambda *a, **k: FakeResp(status=404))
    assert s._sitemap_urls("http://x/") == []
    monkeypatch.setattr(s, "_request", lambda *a, **k: FakeResp(text="<html>soft 404</html>"))
    assert s._sitemap_urls("http://x/") == []
    monkeypatch.setattr(s, "_request", lambda *a, **k: None)
    assert s._sitemap_urls("http://x/") == []


def test_cors_probe_records_how_the_site_answers_an_unknown_origin(monkeypatch):
    s = Scanner("http://x/")
    s.result.final_url = "http://x/"
    sent = {}

    def fake_request(method, url, **kw):
        sent.update(kw)
        return FakeResp(headers={"Access-Control-Allow-Origin": scanner_mod.CORS_PROBE_ORIGIN,
                                 "Access-Control-Allow-Credentials": "true"})

    monkeypatch.setattr(s, "_request", fake_request)
    s.collect_cors()
    assert sent["headers"] == {"Origin": scanner_mod.CORS_PROBE_ORIGIN}
    assert s.result.cors_probe["allow_origin"] == scanner_mod.CORS_PROBE_ORIGIN
    assert s.result.cors_probe["allow_credentials"] == "true"


def test_generator_meta_tags_are_collected_once_whatever_the_case():
    s = Scanner("http://x/")
    html = ('<meta name="Generator" content="WordPress 5.2.1"><meta name="generator" content="WordPress 5.2.1">'
            '<meta name="generator" content=""><meta name="description" content="not a generator">')
    s._collect_generators(BeautifulSoup(html, "html.parser"))
    assert s.result.generators == ["WordPress 5.2.1"]
