"""
headers.py - Security headers, CSP quality, and what the response headers and page metadata give away.
"""

from __future__ import annotations

import re

from webrecon.analysis.checks.common import headers_lower, is_https
from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



HEADER_CHECKS = [
    # header, check id, severity, why it matters, recommended value
    ("content-security-policy", "WR-010", "Medium",
     "No Content Security Policy was set, so the browser has no restriction on where "
     "scripts and other resources can load from. This makes cross-site scripting easier to exploit.",
     "Add a Content-Security-Policy header, starting with something like default-src 'self'."),
    ("x-content-type-options", "WR-012", "Low",
     "Without X-Content-Type-Options the browser may guess content types, which can turn "
     "an uploaded file into executable script.",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "WR-013", "Low",
     "No Referrer-Policy was set, so full URLs including query strings may leak to other sites.",
     "Add Referrer-Policy: strict-origin-when-cross-origin or stricter."),
    ("permissions-policy", "WR-014", "Info",
     "No Permissions-Policy was set to limit browser features such as camera, microphone, and geolocation.",
     "Add a Permissions-Policy header that disables features the site does not use."),
]


def check_security_headers(result: ScanResult) -> list[Finding]:
    headers = headers_lower(result)
    findings = []
    for name, check_id, severity, why, fix in HEADER_CHECKS:
        if name not in headers:
            findings.append(Finding(
                check_id, f"Missing {name.title()} header", severity, "Security Headers",
                why, f"Header {name.title()} not present in response", fix))

    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        findings.append(Finding(
            "WR-011", "No clickjacking protection", "Medium", "Security Headers",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was set, so the page "
            "can be embedded in a frame on another site and used for clickjacking.",
            "X-Frame-Options and CSP frame-ancestors both absent",
            "Add X-Frame-Options: DENY or a CSP frame-ancestors 'none' directive."))

    if is_https(result):
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(Finding(
                "WR-015", "Missing Strict-Transport-Security header", "Medium", "Security Headers",
                "Without HSTS, a user's first request can be downgraded to HTTP by an attacker on the network.",
                "Strict-Transport-Security not present",
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."))
        else:
            match = re.search(r"max-age=(\d+)", hsts)
            if match and int(match.group(1)) < 15552000:
                findings.append(Finding(
                    "WR-016", "Weak HSTS max-age", "Low", "Security Headers",
                    "The HSTS max-age is shorter than six months, which limits its protection.",
                    f"Strict-Transport-Security: {hsts}",
                    "Raise max-age to at least 31536000 seconds."))
    return findings


def check_csp_quality(result: ScanResult) -> list[Finding]:
    csp = headers_lower(result).get("content-security-policy", "")
    if not csp:
        return []
    directives = {}
    for part in csp.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    script = directives.get("script-src") or directives.get("default-src") or []
    issues = []
    protected = any(t.startswith(("'nonce-", "'sha")) or t == "'strict-dynamic'" for t in script)
    if "'unsafe-inline'" in script and not protected:
        issues.append("'unsafe-inline' allows inline scripts")
    if "'unsafe-eval'" in script:
        issues.append("'unsafe-eval' allows eval()")
    if "*" in script:
        issues.append("a wildcard source allows scripts from anywhere")
    if not issues:
        return []
    return [Finding(
        "WR-017", "Weak Content-Security-Policy", "Low", "Security Headers",
        "A CSP is present but allows constructs that defeat much of its protection against "
        "cross-site scripting.",
        "; ".join(issues) + f". Policy: {csp[:200]}",
        "Remove 'unsafe-inline', 'unsafe-eval' and wildcards from script sources; use nonces or hashes instead.")]


def check_information_disclosure(result: ScanResult) -> list[Finding]:
    headers = headers_lower(result)
    findings = []
    server = headers.get("server", "")
    if re.search(r"\d", server):
        findings.append(Finding(
            "WR-020", "Server version disclosed", "Low", "Information Disclosure",
            "The Server header reveals software version details, which helps an attacker "
            "look up known vulnerabilities for that exact version.",
            f"Server: {server}",
            "Configure the web server to hide version details, for example ServerTokens Prod "
            "in Apache or server_tokens off in Nginx."))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if name in headers:
            findings.append(Finding(
                "WR-021", f"Technology disclosed in {name.title()} header", "Low",
                "Information Disclosure",
                "This header advertises the framework or platform behind the site.",
                f"{name.title()}: {headers[name]}",
                f"Remove the {name.title()} header from responses."))
    return findings


def check_generator(result: ScanResult) -> list[Finding]:
    versioned = [g for g in result.generators if re.search(r"\d+\.\d+", g)]
    if not versioned:
        return []
    return [Finding(
        "WR-022", "Software version disclosed in the page's generator tag", "Low", "Information Disclosure",
        "A <meta name=\"generator\"> tag names the software and version that built the site, which "
        "helps an attacker look up known vulnerabilities for that exact version.",
        "; ".join(f"generator: {g}" for g in versioned[:5]),
        "Remove the generator tag (most CMSs have a setting or plugin for it) and keep the software updated.")]
