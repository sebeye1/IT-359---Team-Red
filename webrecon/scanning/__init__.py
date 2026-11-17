"""
webrecon.scanning - Collects data from a target. Nothing here judges what it finds.

    models.py     the data a scan collects (ScanResult, Cookie, Form, ...)
    scanner.py    the Scanner that crawls, probes and records
    parsing.py    cookies, forms and links out of raw HTTP and HTML
    netutil.py    turning typed targets into URLs, explaining errors, TLS certificate check
    settings.py   user agent, probe paths and limits
"""

from webrecon.scanning.models import Cookie, Form, PageInfo, ProbeResult, ScanResult
from webrecon.scanning.netutil import diagnose, is_loopback, normalize_target, probe_tls
from webrecon.scanning.parsing import parse_forms, parse_links, parse_set_cookie, same_origin
from webrecon.scanning.scanner import Scanner, TimeLimitReached
from webrecon.scanning.settings import PROBE_PATHS, USER_AGENT

__all__ = [
    "Cookie", "Form", "PageInfo", "ProbeResult", "ScanResult", "Scanner", "TimeLimitReached",
    "PROBE_PATHS", "USER_AGENT", "diagnose", "is_loopback", "normalize_target", "probe_tls",
    "parse_forms", "parse_links", "parse_set_cookie", "same_origin",
]
