"""
exposure.py - Files and pages that should not be public: .git, .env, config files, directory listings, and robots.txt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



@dataclass(frozen=True)
class PathRule:
    """What an exposed file or page looks like. A probe is a finding only if its body matches,
    so a custom 200 'not found' page does not cause a false positive."""
    path: str | None        # exact probe path, or None to apply to any path
    matches: Callable[[str], bool]
    check_id: str
    title: str              # may contain {path}
    severity: str
    category: str
    description: str
    evidence: str           # may contain {url} and {snippet}
    recommendation: str

    def finding(self, probe) -> Finding:
        snippet = probe.body_snippet.strip()[:80]
        return Finding(self.check_id, self.title.format(path=probe.path), self.severity, self.category,
                       self.description, self.evidence.format(url=probe.url, snippet=snippet),
                       self.recommendation)


_SENSITIVE_FILE = dict(
    check_id="WR-065", title="Sensitive file exposed: {path}", severity="Medium",
    category="Sensitive File Exposure",
    description="A server configuration or project file is publicly readable. These files reveal "
                "rewrite rules, authentication file paths, dependency versions, or directory contents "
                "that help an attacker plan an attack.",
    evidence="{url} returned file content",
    recommendation="Block access to this file in the web server config and remove it from the web root.")

_DIRECTORY_LISTING_DESCRIPTION = ("The server lists directory contents, letting anyone browse files "
                                  "that were never linked.")
_DIRECTORY_LISTING_FIX = "Disable directory listing, for example Options -Indexes in Apache."

PATH_RULES = [
    PathRule("/.git/HEAD", lambda b: b.strip().startswith("ref:"),
             "WR-060", "Git repository exposed", "High", "Sensitive File Exposure",
             "The .git directory is reachable over the web. An attacker can often rebuild "
             "the full source code, including history and secrets.",
             "{url} returned: {snippet}",
             "Block access to .git in the web server config and remove it from the web root."),
    PathRule("/.env", lambda b: bool(re.search(r"^[A-Z_][A-Z0-9_]*=", b, re.M)),
             "WR-061", "Environment file exposed", "High", "Sensitive File Exposure",
             "A .env file is publicly readable. These files usually hold passwords, API keys, "
             "and database connection strings.",
             "{url} returned key=value content",
             "Remove the .env file from the web root, block it in the server config, and rotate "
             "every secret it contained."),
    PathRule("/server-status", lambda b: "server status" in b.lower(),
             "WR-062", "Apache server-status page exposed", "Medium", "Information Disclosure",
             "The server-status page reveals client IPs, requested URLs, and server internals.",
             "{url} returned a server status page",
             "Restrict server-status to localhost or remove mod_status."),
    PathRule("/phpinfo.php", lambda b: "phpinfo" in b.lower(),
             "WR-063", "phpinfo page exposed", "Medium", "Information Disclosure",
             "phpinfo output reveals PHP version, modules, paths, and environment variables.",
             "{url} returned phpinfo output",
             "Delete phpinfo.php from the server."),
    PathRule("/.htaccess", lambda b: bool(re.search(
                 r"^\s*(RewriteEngine|RewriteRule|AuthType|AuthUserFile|Require|Options|Order|"
                 r"Deny from|Allow from|SetEnv|php_value)\b", b, re.M | re.I)), **_SENSITIVE_FILE),
    PathRule("/web.config", lambda b: "<configuration" in b.lower(), **_SENSITIVE_FILE),
    PathRule("/composer.json", lambda b: bool(re.search(r'"require"\s*:', b)), **_SENSITIVE_FILE),
    PathRule("/.DS_Store", lambda b: "Bud1" in b, **_SENSITIVE_FILE),
    PathRule("/actuator/env", lambda b: "propertysources" in b.lower(),
             "WR-066", "Spring Boot Actuator environment endpoint exposed", "High",
             "Sensitive File Exposure",
             "The /actuator/env endpoint lists configuration properties, which often include "
             "credentials, tokens, and internal hostnames.",
             "{url} returned propertySources",
             "Restrict Actuator endpoints to an internal network or authenticated admins, and "
             "rotate any secrets shown."),
    PathRule("/actuator", lambda b: '"_links"' in b and "actuator" in b.lower(),
             "WR-066", "Spring Boot Actuator endpoints exposed", "Medium", "Information Disclosure",
             "The Actuator index is public. It advertises management endpoints that can leak "
             "internals or allow changes.",
             "{url} returned an Actuator link index",
             "Expose only the endpoints you need, and require authentication for the rest."),
    PathRule(None, lambda b: bool(re.search(r"<(title|h1)[^>]*>\s*index of", b, re.I)),
             "WR-064", "Directory listing enabled at {path}", "Medium", "Information Disclosure",
             _DIRECTORY_LISTING_DESCRIPTION, "{url} returned an 'Index of' page", _DIRECTORY_LISTING_FIX),
]


def check_exposed_paths(result: ScanResult) -> list[Finding]:
    findings = []
    for probe in result.probes:
        if probe.status_code != 200 or probe.catch_all:
            continue
        rule = next((r for r in PATH_RULES
                     if r.path in (None, probe.path) and r.matches(probe.body_snippet)), None)
        if rule:
            findings.append(rule.finding(probe))

    # Directory listings spotted while crawling (page title "Index of ...") that no probe reported.
    listed = {urlparse(f.evidence.split(" ")[0]).path for f in findings if f.check_id == "WR-064"}
    for page in result.pages:
        path = urlparse(page.url).path or "/"
        if page.title.lower().startswith("index of") and path not in listed:
            listed.add(path)
            findings.append(Finding(
                "WR-064", f"Directory listing enabled at {path}", "Medium", "Information Disclosure",
                _DIRECTORY_LISTING_DESCRIPTION, f"{page.url} has title '{page.title}'",
                _DIRECTORY_LISTING_FIX))
    return findings


def check_robots(result: ScanResult) -> list[Finding]:
    if not result.robots_txt:
        return []
    disallowed = [line.split(":", 1)[1].strip() for line in result.robots_txt.splitlines()
                  if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()]
    if not disallowed:
        return []
    return [Finding(
        "WR-080", "robots.txt lists hidden paths", "Info", "Reconnaissance",
        "robots.txt tells crawlers which paths to skip, but anyone can read it. Paths listed "
        "here are worth reviewing during testing.",
        "Disallowed: " + ", ".join(disallowed[:20]),
        "Do not rely on robots.txt to hide sensitive areas. Protect them with authentication.")]
