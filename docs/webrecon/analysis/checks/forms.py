"""
forms.py - Forms: passwords over HTTP, GET login forms, and missing CSRF tokens.
"""

from __future__ import annotations

from urllib.parse import urlparse

from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



CSRF_FIELD_HINTS = ("csrf", "xsrf", "token", "authenticity", "nonce", "__requestverification")


def check_forms(result: ScanResult) -> list[Finding]:
    findings = []
    for form in result.forms:
        page_scheme = urlparse(form.page_url).scheme
        action_scheme = urlparse(form.action).scheme
        has_password = any(i["type"] == "password" for i in form.inputs)
        where = f"Form on {form.page_url} ({form.method} to {form.action})"

        if has_password and action_scheme == "http":
            findings.append(Finding(
                "WR-070", "Password submitted over HTTP", "High", "Forms",
                "A login or password form sends credentials without encryption.",
                where, "Serve the page and the form action over HTTPS only."))
        elif page_scheme == "https" and action_scheme == "http":
            findings.append(Finding(
                "WR-071", "HTTPS page posts form data to HTTP", "Medium", "Forms",
                "Form data entered on a secure page is sent to an insecure endpoint.",
                where, "Change the form action to an HTTPS URL."))

        if has_password and form.method == "GET":
            findings.append(Finding(
                "WR-072", "Password form uses GET", "Medium", "Forms",
                "With GET, the password ends up in the URL, browser history, and server logs.",
                where, "Change the form method to POST."))

        if form.method == "POST":
            names = [i["name"].lower() for i in form.inputs if i["type"] == "hidden"]
            if not any(h in n for n in names for h in CSRF_FIELD_HINTS):
                findings.append(Finding(
                    "WR-073", "POST form with no visible CSRF token", "Medium", "Forms",
                    "No hidden anti-CSRF token field was found. Unless the app protects against "
                    "CSRF another way, such as SameSite cookies or custom headers, an attacker's "
                    "site could submit this form as a logged-in user. Verify manually.",
                    where, "Add a per-session or per-request anti-CSRF token to state-changing forms."))

        for field_info in form.inputs:
            if field_info["type"] == "password" and field_info["autocomplete"] not in (
                    "off", "new-password", "current-password"):
                findings.append(Finding(
                    "WR-074", "Password field without autocomplete guidance", "Info", "Forms",
                    "The password field has no autocomplete attribute. This is informational; "
                    "modern guidance prefers current-password or new-password over turning it off.",
                    where, "Set autocomplete=\"current-password\" or \"new-password\" on password fields."))
    return findings
