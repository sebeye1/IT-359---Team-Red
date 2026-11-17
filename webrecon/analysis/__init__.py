"""
webrecon.analysis - Turns what the scanner collected into findings.

    findings.py   the Finding record, severity order, counting
    catalog.py    every check ID with its severity, and reference links
    engine.py     runs all checks: analyze(result) -> findings, worst first
    checks/       one module per kind of check
"""

from webrecon.analysis.catalog import CHECK_CATALOG, REFERENCES
from webrecon.analysis.engine import ALL_CHECKS, analyze
from webrecon.analysis.findings import SEVERITY_ORDER, Finding, severity_counts

__all__ = ["ALL_CHECKS", "CHECK_CATALOG", "REFERENCES", "SEVERITY_ORDER", "Finding", "analyze", "severity_counts"]
