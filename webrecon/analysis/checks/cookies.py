"""
cookies.py - Cookie flags: Secure, HttpOnly and SameSite.
"""

from __future__ import annotations

from webrecon.analysis.checks.common import is_https
from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



SESSION_COOKIE_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "remember")


def check_cookies(result: ScanResult) -> list[Finding]:
    findings = []
    https = is_https(result)
    for cookie in result.cookies:
        looks_like_session = any(h in cookie.name.lower() for h in SESSION_COOKIE_HINTS)
        problems = []
        if not cookie.secure:
            problems.append("Secure flag missing")
        if not cookie.httponly:
            problems.append("HttpOnly flag missing")
        if not cookie.samesite:
            problems.append("SameSite attribute missing")
        elif cookie.samesite.lower() == "none" and not cookie.secure:
            problems.append("SameSite=None used without Secure")
        if not problems:
            continue

        if looks_like_session and ("HttpOnly flag missing" in problems
                                   or ("Secure flag missing" in problems and https)):
            severity = "Medium"
        else:
            severity = "Low"

        findings.append(Finding(
            "WR-030", f"Insecure cookie attributes: {cookie.name}", severity, "Cookie Security",
            "Cookie flags limit how a cookie can be stolen or misused. Secure keeps it off "
            "plain HTTP, HttpOnly keeps it away from JavaScript, and SameSite limits cross-site "
            "request forgery." + (" The name suggests this is a session cookie." if looks_like_session else ""),
            f"{'; '.join(problems)}. Raw header: {cookie.raw}",
            "Set the cookie with Secure, HttpOnly, and SameSite=Lax or Strict."))
    return findings
