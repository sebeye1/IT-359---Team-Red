"""
transport.py - HTTPS, the TLS certificate, and whether plain HTTP redirects to HTTPS.
"""

from __future__ import annotations

from webrecon.analysis.checks.common import is_https
from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



def check_https(result: ScanResult) -> list[Finding]:
    if is_https(result):
        return []
    return [Finding(
        "WR-001", "Site served over unencrypted HTTP", "Medium", "Transport Security",
        "The application responded over plain HTTP. Traffic, including credentials and "
        "session cookies, can be read or modified by anyone on the network path.",
        f"Final URL: {result.final_url or result.target}",
        "Serve the application over HTTPS and redirect all HTTP requests to HTTPS.",
    )]


def check_tls(result: ScanResult) -> list[Finding]:
    tls = result.tls or {}
    if not tls or not is_https(result):
        return []
    findings = []
    if tls.get("verified") is False:
        findings.append(Finding(
            "WR-002", "TLS certificate failed validation", "Medium", "Transport Security",
            "The certificate did not validate against trusted authorities. Browsers show a "
            "warning, and users who click through can be intercepted. This is common for "
            "self-signed certificates on internal or lab systems.",
            f"Validation error: {tls.get('error') or 'unknown'}",
            "Install a certificate from a trusted authority that matches the hostname and "
            "includes the full chain."))
    days = tls.get("days_left")
    if tls.get("verified") and isinstance(days, int) and days <= 30:
        findings.append(Finding(
            "WR-003", "TLS certificate expires soon", "Medium" if days <= 14 else "Low",
            "Transport Security",
            "An expired certificate takes the site down for most visitors and trains users to ignore warnings.",
            f"Certificate expires {tls.get('expires')} ({days} day(s) left)",
            "Renew the certificate and automate renewal, for example with an ACME client such as certbot."))
    return findings


def check_http_redirect(result: ScanResult) -> list[Finding]:
    info = result.http_redirect or {}
    if not info or not is_https(result) or info.get("status") != 200:
        return []
    return [Finding(
        "WR-004", "HTTP version of the site does not redirect to HTTPS", "Medium", "Transport Security",
        "The site also answers on plain HTTP with real content instead of redirecting. Anyone who "
        "types the address without https:// stays unencrypted, and an attacker on the network can "
        "keep them there.",
        f"GET {info.get('url')} returned 200",
        "Redirect all HTTP requests to HTTPS with a permanent redirect, then add HSTS.")]
