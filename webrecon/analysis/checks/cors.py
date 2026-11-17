"""
cors.py - Cross-origin resource sharing: wildcards, and a policy that trusts any origin.
"""

from __future__ import annotations

from webrecon.analysis.checks.common import headers_lower
from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



def check_cors(result: ScanResult) -> list[Finding]:
    headers = headers_lower(result)
    origin = headers.get("access-control-allow-origin")
    if origin != "*":
        return []
    creds = headers.get("access-control-allow-credentials", "").lower() == "true"
    return [Finding(
        "WR-040", "Overly permissive CORS policy", "High" if creds else "Medium", "CORS",
        "Access-Control-Allow-Origin is set to a wildcard, so any website can read responses "
        "from this application in a visitor's browser.",
        "Access-Control-Allow-Origin: *" + ("; Access-Control-Allow-Credentials: true" if creds else ""),
        "Restrict Access-Control-Allow-Origin to a list of trusted origins.")]


def check_cors_reflection(result: ScanResult) -> list[Finding]:
    probe = result.cors_probe or {}
    origin = probe.get("origin")
    if not origin or probe.get("allow_origin") != origin:
        return []
    credentials = probe.get("allow_credentials", "").lower() == "true"
    return [Finding(
        "WR-041", "CORS policy reflects any Origin", "High" if credentials else "Medium", "CORS",
        "The site echoed back an origin it has no reason to trust. Any website can then read its "
        "responses from a visitor's browser" + (", including signed-in pages, because credentials "
        "are allowed." if credentials else "."),
        f"Origin: {origin} came back in Access-Control-Allow-Origin"
        + (" with Access-Control-Allow-Credentials: true" if credentials else ""),
        "Compare the Origin header against a fixed allow-list of trusted sites instead of echoing it, "
        "and never combine a reflected origin with credentials.")]
