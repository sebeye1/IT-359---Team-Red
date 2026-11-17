"""
models.py - The plain data a scan collects. The scanner fills these in; the analyzer and the
reports only read them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None
    source_url: str = ""
    raw: str = ""


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # list of {"name", "type", "autocomplete"}


@dataclass
class PageInfo:
    url: str
    status_code: int
    title: str = ""
    content_type: str = ""


@dataclass
class ProbeResult:
    path: str
    url: str
    status_code: int | None
    content_type: str = ""
    body_snippet: str = ""
    catch_all: bool = False  # True when the site answers any path with the same page


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status_code: int | None = None
    redirect_chain: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    pages: list = field(default_factory=list)
    links: list = field(default_factory=list)
    external_links: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    robots_txt: str | None = None
    allowed_methods: list = field(default_factory=list)
    trace_enabled: bool = False
    probes: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    hints: list = field(default_factory=list)   # plain-English advice when something fails
    notes: list = field(default_factory=list)   # non-error remarks, e.g. fell back to HTTP
    tls: dict = field(default_factory=dict)
    resources: list = field(default_factory=list)      # scripts, styles, images, frames seen on pages
    http_redirect: dict = field(default_factory=dict)  # what plain HTTP does on an HTTPS site
    cors_probe: dict = field(default_factory=dict)     # how the site answers a made-up Origin header
    generators: list = field(default_factory=list)     # <meta name="generator"> values seen on pages
    trend: dict = field(default_factory=dict)          # this scan vs the previous one of the same site
    requests_made: int = 0
    duration: float = 0.0
    partial: bool = False       # stopped early (time limit or Ctrl+C)
    interrupted: bool = False   # specifically Ctrl+C, so a multi-target run should stop too
    started: str = ""
    finished: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
