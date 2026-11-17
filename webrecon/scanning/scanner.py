"""
scanner.py - The reconnaissance step. Collects observable information from an authorized target:
HTTP response details, headers, cookies, links, forms, robots.txt, supported HTTP methods, the TLS
certificate, and a small set of low-impact path probes.

This module only gathers data. All judgments about what is a finding live in webrecon.analysis.
"""

from __future__ import annotations

import hashlib
import html
import logging
import random
import re
import string
import time
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
import urllib3
from bs4 import BeautifulSoup

from webrecon.scanning.models import Cookie, PageInfo, ProbeResult, ScanResult
from webrecon.scanning.netutil import diagnose, normalize_target, probe_tls
from webrecon.scanning.parsing import parse_forms, parse_links, parse_set_cookie, raw_set_cookies, same_origin
from webrecon.scanning.settings import (CORS_PROBE_ORIGIN, MAX_BODY_BYTES, PROBE_PATHS, RETRY_STATUS,
                                        SAFE_METHODS, USER_AGENT)

log = logging.getLogger(__name__)


class TimeLimitReached(Exception):
    """Raised inside a scan when --max-time has run out. Scanner.run() turns it into partial results."""


class Scanner:
    def __init__(self, target: str, timeout: float = 10.0, max_pages: int = 10,
                 delay: float = 0.2, verify_tls: bool = True, run_probes: bool = True,
                 headers: dict | None = None, cookie: str | None = None,
                 user_agent: str | None = None, proxy: str | None = None,
                 retries: int = 2, respect_robots: bool = False, max_time: float | None = None,
                 progress=None):
        self.target, self.scheme_guessed = normalize_target(target)
        self.timeout = timeout
        self.max_pages = max(1, max_pages)
        self.delay = delay
        self.run_probes = run_probes
        self.retries = max(0, retries)
        self.respect_robots = respect_robots
        self.max_time = max_time
        self.deadline: float | None = None
        self.proxy = proxy
        self.progress = progress or (lambda message: None)
        self.last_exc: Exception | None = None
        self._robots: RobotFileParser | None = None
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent or USER_AGENT
        for name, value in (headers or {}).items():
            self.session.headers[name] = value
        self.verify_tls = verify_tls
        self.session.verify = verify_tls
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookie:
            host = urlparse(self.target).hostname or ""
            if ":" in host:
                # Python's cookie jar cannot match IPv6 literals, so send the header directly.
                self.session.headers["Cookie"] = cookie
            else:
                if "." not in host:
                    host += ".local"  # the jar treats single-label hosts (localhost, intranet names) this way
                for pair in cookie.split(";"):
                    name, sep, value = pair.strip().partition("=")
                    if sep and name:
                        self.session.cookies.set(name, value, domain=host, path="/")
        self.result = ScanResult(target=self.target)
        if not verify_tls:
            self.result.notes.append("TLS certificate verification was disabled (--insecure).")

    def _send(self, method: str, url: str, **kwargs) -> requests.Response:
        """One request, reading at most MAX_BODY_BYTES so huge downloads cannot hang the scan."""
        self.result.requests_made += 1
        # verify is passed per request on purpose: requests lets the REQUESTS_CA_BUNDLE
        # environment variable override session.verify, which would silently undo --insecure.
        response = self.session.request(method, url, timeout=self.timeout, stream=True,
                                        verify=self.verify_tls, **kwargs)
        try:
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    break
            response._content = bytes(body)
            response._content_consumed = True
        finally:
            response.close()
        return response

    def _backoff(self, attempt: int, retry_after: str | None = None) -> None:
        wait = 1.5 ** attempt
        if retry_after and retry_after.strip().isdigit():
            wait = min(int(retry_after), 15)
        self.progress(f"Server is busy or rate limiting; waiting {wait:.0f}s before retrying")
        time.sleep(wait)

    def _record_failure(self, method: str, url: str, exc: Exception) -> None:
        message = f"{method} {url} failed: {exc.__class__.__name__}: {exc}"
        log.warning(message)
        self.result.errors.append(message)

    def _request(self, method: str, url: str, quiet: bool = False, **kwargs) -> requests.Response | None:
        for attempt in range(self.retries + 1):
            if self.deadline is not None and time.monotonic() > self.deadline:
                raise TimeLimitReached()
            try:
                response = self._send(method, url, **kwargs)
            except requests.Timeout as exc:
                self.last_exc = exc
                if attempt < self.retries:
                    self._backoff(attempt)
                    continue
                if not quiet:
                    self._record_failure(method, url, exc)
                return None
            except requests.RequestException as exc:
                self.last_exc = exc
                if not quiet:
                    self._record_failure(method, url, exc)
                return None
            time.sleep(self.delay)
            if (response.status_code in RETRY_STATUS and method in SAFE_METHODS
                    and attempt < self.retries):
                self._backoff(attempt, response.headers.get("Retry-After"))
                continue
            return response
        return None

    def _collect_cookies(self, response: requests.Response) -> None:
        # The same cookie is usually set on many pages. Keep one entry per name
        # and flag combination so each distinct configuration is reported once.
        def key(c: Cookie):
            return (c.name, c.secure, c.httponly, (c.samesite or "").lower())

        seen = {key(c) for c in self.result.cookies}
        for resp in list(response.history) + [response]:
            for raw in raw_set_cookies(resp):
                cookie = parse_set_cookie(raw, resp.url)
                if key(cookie) not in seen:
                    self.result.cookies.append(cookie)
                    seen.add(key(cookie))

    def fetch_main(self) -> bool:
        log.info("Fetching %s", self.target)
        errors_before = len(self.result.errors)
        response = self._request("GET", self.target, allow_redirects=True)
        if response is None and self.scheme_guessed and self.target.startswith("https://"):
            first_exc = self.last_exc
            alternative = "http://" + self.target[len("https://"):]
            self.progress("HTTPS did not respond, trying HTTP")
            response = self._request("GET", alternative, allow_redirects=True)
            if response is not None:
                del self.result.errors[errors_before:]
                self.target = self.result.target = alternative
                self.result.notes.append("HTTPS did not respond on this host, so the scan used HTTP.")
            else:
                self.last_exc = first_exc
        if response is None:
            hint = diagnose(self.last_exc)
            if hint:
                self.result.hints.append(hint)
            return False
        r = self.result
        r.final_url = response.url
        r.status_code = response.status_code
        r.redirect_chain = [f"{h.status_code} {h.url}" for h in response.history]
        r.headers = dict(response.headers)
        self._collect_cookies(response)
        if response.status_code in (401, 403):
            r.hints.append(f"The site answered {response.status_code}. Findings reflect that response only. "
                           "If the site needs a login, pass --cookie or --header to scan as a signed-in user.")
        return True

    def _sitemap_urls(self, start: str) -> list[str]:
        """Same-origin page URLs listed in /sitemap.xml, so the crawl reaches pages nothing links to."""
        response = self._request("GET", urljoin(start, "/sitemap.xml"), quiet=True, allow_redirects=True)
        if response is None or response.status_code != 200 or "<urlset" not in response.text:
            return []
        found = []
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", response.text):
            url = urldefrag(html.unescape(loc))[0]
            if same_origin(url, start) and not url.lower().endswith(".xml") and url not in found:
                found.append(url)
        found = found[: self.max_pages * 3]
        if found:
            self.result.notes.append(f"Added {len(found)} page(s) from sitemap.xml to the crawl.")
        return found

    def crawl(self) -> None:
        """Breadth-first crawl of same-origin pages, capped at max_pages."""
        start = self.result.final_url or self.target
        self._load_robots(start)
        queue, visited = [start] + self._sitemap_urls(start), set()
        all_links: set[str] = set()
        skipped_by_robots = 0
        try:
            while queue and len(visited) < self.max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                response = self._request("GET", url, allow_redirects=True)
                if response is None:
                    continue
                self._collect_cookies(response)
                content_type = response.headers.get("Content-Type", "")
                page = PageInfo(url=response.url, status_code=response.status_code,
                                content_type=content_type)
                if "html" in content_type.lower():
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.title and soup.title.string:
                        page.title = soup.title.string.strip()
                    self.result.forms.extend(parse_forms(soup, response.url))
                    self._collect_resources(soup, response.url)
                    self._collect_generators(soup)
                    for link in parse_links(soup, response.url):
                        all_links.add(link)
                        if same_origin(link, start) and link not in visited:
                            if self._allowed(link):
                                queue.append(link)
                            else:
                                skipped_by_robots += 1
                self.result.pages.append(page)
                log.info("Crawled %s (%s)", response.url, response.status_code)
        finally:  # keep what was found even if the scan is stopped part-way
            if skipped_by_robots:
                self.result.notes.append(
                    f"Skipped {skipped_by_robots} link(s) disallowed by robots.txt (--respect-robots).")
            self.result.links = sorted(l for l in all_links if same_origin(l, start))
            self.result.external_links = sorted(l for l in all_links if not same_origin(l, start))

    def _collect_resources(self, soup: BeautifulSoup, page_url: str) -> None:
        """Remember what each page loads, so the analyzer can spot mixed content and missing SRI."""
        for tag in soup.find_all(["script", "link", "img", "iframe"]):
            if len(self.result.resources) >= 1000:
                return
            if tag.name == "link":
                if "stylesheet" not in [r.lower() for r in (tag.get("rel") or [])]:
                    continue
                raw, kind = tag.get("href"), "stylesheet"
            else:
                raw, kind = tag.get("src"), tag.name
            if not raw or raw.strip().startswith(("data:", "javascript:", "#", "about:")):
                continue
            self.result.resources.append({"page": page_url, "kind": kind,
                                          "url": urljoin(page_url, raw.strip()),
                                          "integrity": bool(tag.get("integrity"))})

    def _collect_generators(self, soup: BeautifulSoup) -> None:
        for meta in soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)}):
            content = (meta.get("content") or "").strip()
            if content and content not in self.result.generators:
                self.result.generators.append(content)

    def collect_http_redirect(self) -> None:
        """On an HTTPS site, see whether plain HTTP redirects to it or serves content."""
        parsed = urlparse(self.result.final_url or self.target)
        if parsed.scheme != "https" or parsed.port not in (None, 443) or not parsed.hostname:
            return
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        url = f"http://{host}/"
        self.progress("Checking whether HTTP redirects to HTTPS")
        response = self._request("GET", url, quiet=True, allow_redirects=False)
        if response is not None:
            self.result.http_redirect = {"url": url, "status": response.status_code,
                                         "location": response.headers.get("Location", "")}

    def collect_cors(self) -> None:
        """Send one request with a made-up Origin and record whether the site trusts it."""
        self.progress("Checking how the site answers an unknown Origin (CORS)")
        response = self._request("GET", self.result.final_url or self.target, quiet=True,
                                 allow_redirects=False, headers={"Origin": CORS_PROBE_ORIGIN})
        if response is not None:
            self.result.cors_probe = {
                "origin": CORS_PROBE_ORIGIN, "status": response.status_code,
                "allow_origin": response.headers.get("Access-Control-Allow-Origin", ""),
                "allow_credentials": response.headers.get("Access-Control-Allow-Credentials", "")}

    def _load_robots(self, base: str) -> None:
        if not self.respect_robots:
            return
        response = self._request("GET", urljoin(base, "/robots.txt"), allow_redirects=True)
        parser = RobotFileParser()
        parser.parse(response.text.splitlines() if response is not None and response.status_code == 200 else [])
        parser.modified()  # without this, can_fetch() refuses everything
        self._robots = parser

    def _allowed(self, url: str) -> bool:
        return self._robots is None or self._robots.can_fetch("*", url)

    def collect_methods(self) -> None:
        base = self.result.final_url or self.target
        response = self._request("OPTIONS", base)
        if response is not None:
            allow = response.headers.get("Allow", "")
            self.result.allowed_methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        response = self._request("TRACE", base)
        if response is not None and response.status_code == 200 and "TRACE" in response.text.upper():
            self.result.trace_enabled = True

    def _catch_all_baseline(self, base: str) -> dict | None:
        """Ask for a page that cannot exist. If the site answers 200, it serves a catch-all page
        (common with single-page apps), and 200 responses for probes can't be trusted."""
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        response = self._request("GET", urljoin(base, f"/webrecon-{token}"), allow_redirects=False)
        if response is None or response.status_code != 200:
            return None
        return {"hash": hashlib.sha256(response.content).hexdigest(), "length": len(response.content)}

    @staticmethod
    def _looks_like_catch_all(response: requests.Response, baseline: dict | None) -> bool:
        if not baseline:
            return False
        if hashlib.sha256(response.content).hexdigest() == baseline["hash"]:
            return True
        base_len = baseline["length"]
        # Dynamic catch-all pages differ slightly (nonces, timestamps). Only trust the
        # length comparison for pages big enough that a coincidence is unlikely.
        return base_len >= 200 and abs(len(response.content) - base_len) <= base_len * 0.03

    def probe_paths(self) -> None:
        base = self.result.final_url or self.target
        baseline = self._catch_all_baseline(base)
        if baseline:
            self.result.notes.append(
                "This site returns 200 for pages that do not exist (a catch-all page), so path "
                "probes that match it were ignored to avoid false positives.")
        for path in PROBE_PATHS:
            url = urljoin(base, path)
            response = self._request("GET", url, allow_redirects=False)
            if response is None:
                continue
            catch_all = (response.status_code == 200 and path != "/robots.txt"
                         and self._looks_like_catch_all(response, baseline))
            probe = ProbeResult(
                path=path, url=url, status_code=response.status_code,
                content_type=response.headers.get("Content-Type", ""),
                body_snippet=response.text[:2000] if response.status_code == 200 else "",
                catch_all=catch_all,
            )
            self.result.probes.append(probe)
            if path == "/robots.txt" and response.status_code == 200 and "html" not in probe.content_type.lower():
                self.result.robots_txt = response.text[:5000]

    def collect_tls(self) -> None:
        parsed = urlparse(self.result.final_url or self.target)
        if parsed.scheme != "https" or self.proxy or not parsed.hostname:
            return
        self.progress("Checking the TLS certificate")
        self.result.tls = probe_tls(parsed.hostname, parsed.port or 443, min(self.timeout, 10.0))

    def _run_steps(self) -> None:
        self.progress(f"Fetching {self.target}")
        if not self.fetch_main():
            return
        self.progress(f"Crawling up to {self.max_pages} page(s)")
        self.crawl()
        self.progress("Checking HTTP methods")
        self.collect_methods()
        self.collect_tls()
        self.collect_http_redirect()
        if self.run_probes:
            self.collect_cors()
            self.progress(f"Probing {len(PROBE_PATHS)} common paths")
            self.probe_paths()

    def _stop_early(self, message: str) -> None:
        self.result.partial = True
        self.result.notes.append(message)

    def run(self) -> ScanResult:
        began = time.monotonic()
        self.result.started = time.strftime("%Y-%m-%d %H:%M:%S")
        self.deadline = began + self.max_time if self.max_time else None
        try:
            self._run_steps()
        except TimeLimitReached:
            self._stop_early(f"Stopped early: the {self.max_time:g}s time limit (--max-time) was "
                             "reached, so these results are partial.")
        except KeyboardInterrupt:
            self.result.interrupted = True
            self._stop_early("Interrupted with Ctrl+C, so these results are partial.")
        self.result.duration = round(time.monotonic() - began, 1)
        self.result.finished = time.strftime("%Y-%m-%d %H:%M:%S")
        return self.result
