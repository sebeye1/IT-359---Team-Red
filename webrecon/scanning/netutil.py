"""
netutil.py - Helpers about addresses and connections: turning typed targets into URLs, explaining
network errors in plain English, and checking a TLS certificate.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

import requests

try:  # certifi ships with requests; it gives the same trust store for the TLS probe
    import certifi
except ImportError:  # pragma: no cover
    certifi = None


def is_loopback(host: str) -> bool:
    return host in ("localhost", "::1") or host.startswith("127.")


def normalize_target(raw: str) -> tuple[str, bool]:
    """Turn what the user typed into a URL. Returns (url, scheme_was_guessed).

    A bare host such as example.com or 10.0.0.5:8443 is tried over HTTPS first
    (the Scanner falls back to HTTP). Loopback addresses default to plain HTTP.
    """
    raw = raw.strip()
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        return f"{scheme.lower()}://{rest}", False
    host = urlparse("//" + raw).hostname or ""
    if is_loopback(host):
        return "http://" + raw, False
    return "https://" + raw, True


def diagnose(exc: Exception | None) -> str:
    """Translate a requests exception into advice a person can act on."""
    if exc is None:
        return ""
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.SSLError) or ("ssl" in text and "certificate" in text):
        return ("The TLS/SSL handshake failed. For a lab or self-signed certificate, rerun with "
                "--insecure. Otherwise the site's certificate may be expired, for the wrong "
                "hostname, or from an untrusted authority.")
    if isinstance(exc, requests.exceptions.ProxyError):
        return "Could not connect through the proxy. Check the --proxy address and that the proxy is running."
    if isinstance(exc, requests.exceptions.Timeout):
        return ("The request timed out. Try a larger --timeout, and check for a firewall, VPN "
                "or a host that is down.")
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "The site redirected in a loop. Check the URL, or whether a login is required."
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema,
                        requests.exceptions.InvalidSchema)):
        return "The URL does not look valid. Use a form like https://example.com or http://127.0.0.1:8080."
    if any(m in text for m in ("name or service not known", "nodename nor servname",
                               "getaddrinfo failed", "temporary failure in name resolution",
                               "no address associated")):
        return "The hostname could not be resolved. Check the spelling and your network or DNS."
    if "connection refused" in text or "actively refused" in text:
        return ("Nothing is accepting connections at that address and port. Check the port number. "
                "For the practice lab, add --auto-lab.")
    if any(m in text for m in ("connection reset", "remote end closed", "connection aborted")):
        return ("The server closed the connection. It may be blocking automated requests or rate "
                "limiting. Try --delay 1, a different --user-agent, or a lower --max-pages.")
    return "The request failed. Re-run with -v for details, and check the URL and your connection."


def probe_tls(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Open one TLS connection and record whether the certificate validates and when it expires."""
    info = {"host": host, "port": port, "verified": None, "error": "",
            "version": "", "issuer": "", "expires": "", "days_left": None}
    try:
        ctx = ssl.create_default_context(cafile=certifi.where() if certifi else None)
        # Python 3.13+ turns on strict X.509 checks that browsers and requests do not apply, which would
        # report certificates that real visitors accept. Keep the check consistent with what they see.
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                info["verified"] = True
                info["version"] = tls.version() or ""
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not_after:
                    ts = ssl.cert_time_to_seconds(not_after)
                    info["expires"] = time.strftime("%Y-%m-%d", time.gmtime(ts))
                    info["days_left"] = int((ts - time.time()) // 86400)
                issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
                info["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "")
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["error"] = getattr(exc, "verify_message", "") or str(exc)
    except (OSError, ssl.SSLError, ValueError) as exc:
        info["error"] = str(exc)  # could not complete a handshake; verified stays None
    return info
