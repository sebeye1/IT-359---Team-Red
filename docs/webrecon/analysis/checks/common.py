"""
common.py - Small helpers shared by the check modules.
"""

from __future__ import annotations

from urllib.parse import urlparse

from webrecon.scanning import ScanResult


def headers_lower(result: ScanResult) -> dict:
    return {k.lower(): v for k, v in result.headers.items()}


def is_https(result: ScanResult) -> bool:
    return urlparse(result.final_url or result.target).scheme == "https"


def evidence_list(items: list[str], limit: int = 5) -> str:
    """Join up to `limit` items for a finding's evidence, noting how many were left out."""
    text = "; ".join(items[:limit])
    return text + (f" (and {len(items) - limit} more)" if len(items) > limit else "")
