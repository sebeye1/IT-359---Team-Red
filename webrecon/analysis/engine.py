"""
engine.py - Runs every check against a scan result and sorts the findings, worst first.

To add a check: write the function in the matching module under analysis/checks, add it to ALL_CHECKS
below, give it an entry in catalog.CHECK_CATALOG, and write a test. See docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from webrecon.analysis.catalog import REFERENCES
from webrecon.analysis.checks.content import check_mixed_content, check_outdated_libraries, check_sri
from webrecon.analysis.checks.cookies import check_cookies
from webrecon.analysis.checks.cors import check_cors, check_cors_reflection
from webrecon.analysis.checks.exposure import check_exposed_paths, check_robots
from webrecon.analysis.checks.forms import check_forms
from webrecon.analysis.checks.headers import (check_csp_quality, check_generator, check_information_disclosure,
                                              check_security_headers)
from webrecon.analysis.checks.methods import check_http_methods
from webrecon.analysis.checks.transport import check_http_redirect, check_https, check_tls
from webrecon.analysis.findings import SEVERITY_ORDER, Finding
from webrecon.scanning import ScanResult

ALL_CHECKS = [
    check_https,
    check_tls,
    check_http_redirect,
    check_security_headers,
    check_csp_quality,
    check_information_disclosure,
    check_generator,
    check_outdated_libraries,
    check_cookies,
    check_cors,
    check_cors_reflection,
    check_http_methods,
    check_exposed_paths,
    check_forms,
    check_mixed_content,
    check_sri,
    check_robots,
]


def analyze(result: ScanResult) -> list[Finding]:
    findings: list[Finding] = []
    if result.status_code is None:
        return findings
    for check in ALL_CHECKS:
        findings.extend(check(result))
    for f in findings:
        if not f.references:
            f.references = list(REFERENCES.get(f.check_id, []))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.check_id))
    return findings
