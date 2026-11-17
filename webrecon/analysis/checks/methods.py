"""
methods.py - HTTP methods the server allows.
"""

from __future__ import annotations

from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



def check_http_methods(result: ScanResult) -> list[Finding]:
    findings = []
    if result.trace_enabled:
        findings.append(Finding(
            "WR-050", "HTTP TRACE method enabled", "Low", "HTTP Methods",
            "TRACE echoes the request back, which can expose headers and has been used in "
            "cross-site tracing attacks.",
            "TRACE request returned 200 with the request echoed",
            "Disable TRACE, for example TraceEnable Off in Apache."))
    risky = [m for m in result.allowed_methods if m in ("PUT", "DELETE", "PATCH", "CONNECT")]
    if risky:
        findings.append(Finding(
            "WR-051", "Potentially dangerous HTTP methods allowed", "Medium", "HTTP Methods",
            "The server advertises methods that can change or remove content. Verify they "
            "require authentication.",
            f"Allow: {', '.join(result.allowed_methods)}",
            "Disable methods the application does not need."))
    return findings
