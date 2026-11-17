"""
parsing.py - Turn raw HTTP and HTML into the small structures the scanner records.
"""

from __future__ import annotations

import requests
from bs4 import BeautifulSoup
from urllib.parse import urldefrag, urljoin, urlparse

from webrecon.scanning.models import Cookie, Form


def parse_set_cookie(header_value: str, source_url: str) -> Cookie:
    """Parse one raw Set-Cookie header, keeping the security attributes."""
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    cookie = Cookie(name=name, source_url=source_url, raw=header_value)
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.httponly = True
        elif key == "samesite":
            cookie.samesite = value.strip() or None
        elif key == "path":
            cookie.path = value.strip()
        elif key == "domain":
            cookie.domain = value.strip()
    return cookie


def raw_set_cookies(response: requests.Response) -> list[str]:
    """Return every Set-Cookie header separately. requests merges them otherwise."""
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return raw_headers.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def parse_forms(soup: BeautifulSoup, page_url: str) -> list[Form]:
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        inputs = []
        for field_tag in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": field_tag.get("name", ""),
                "type": (field_tag.get("type") or field_tag.name).lower(),
                "autocomplete": (field_tag.get("autocomplete") or "").lower(),
            })
        forms.append(Form(page_url=page_url, action=action, method=method, inputs=inputs))
    return forms


def parse_links(soup: BeautifulSoup, page_url: str) -> list[str]:
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("mailto:", "javascript:", "tel:", "#")):
            continue
        absolute, _ = urldefrag(urljoin(page_url, href))
        links.append(absolute)
    return links


def same_origin(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)
