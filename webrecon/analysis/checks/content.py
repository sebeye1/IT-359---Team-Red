"""
content.py - What pages load: mixed content, third-party scripts without integrity hashes, and outdated JavaScript libraries.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from webrecon.analysis.checks.common import evidence_list
from webrecon.analysis.findings import Finding
from webrecon.scanning import ScanResult



def check_mixed_content(result: ScanResult) -> list[Finding]:
    active, passive = [], []
    for res in result.resources:
        if urlparse(res["page"]).scheme == "https" and urlparse(res["url"]).scheme == "http":
            (passive if res["kind"] == "img" else active).append(f"{res['kind']} {res['url']}")
    findings = []
    if active:
        findings.append(Finding(
            "WR-090", "Insecure scripts, styles or frames loaded on HTTPS pages", "Medium", "Mixed Content",
            "HTTPS pages load active content over plain HTTP. Browsers may block it, which breaks the "
            "page, and where they do not, an attacker can alter the content in transit.",
            evidence_list(list(dict.fromkeys(active))),
            "Load every script, stylesheet and frame over HTTPS."))
    if passive:
        findings.append(Finding(
            "WR-090", "Insecure images loaded on HTTPS pages", "Low", "Mixed Content",
            "HTTPS pages load images over plain HTTP, which weakens the page's security indicator "
            "and lets an attacker swap the images.",
            evidence_list(list(dict.fromkeys(passive))),
            "Load images over HTTPS."))
    return findings


def check_sri(result: ScanResult) -> list[Finding]:
    site = urlparse(result.final_url or result.target).hostname or ""
    missing = [f"{r['kind']} {r['url']}" for r in result.resources
               if r["kind"] in ("script", "stylesheet") and not r["integrity"]
               and (urlparse(r["url"]).hostname or site) != site]
    if not missing:
        return []
    return [Finding(
        "WR-091", "Third-party scripts or styles loaded without Subresource Integrity", "Low", "Supply Chain",
        "Resources from other hosts have no integrity hash. If that host is compromised, malicious "
        "code runs on this site. Scripts that vendors change often, such as analytics tags, cannot "
        "use SRI, so review these and ignore the ones that cannot.",
        evidence_list(list(dict.fromkeys(missing))),
        "Add integrity and crossorigin attributes to third-party scripts and styles where the file is "
        "versioned, or host a pinned copy yourself.")]


def _nvd(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


# Libraries recognised by the version in a script's URL (for example jquery-1.12.4.min.js or
# /ajax/libs/jquery/3.3.1/jquery.min.js). A script whose URL carries no version is not judged.
LIBRARY_RULES = [
    # (name, URL patterns capturing the version, is this version vulnerable?, severity, why, fix, references)
    ("jQuery", [r"jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", r"/jquery/(\d+\.\d+(?:\.\d+)?)/"],
     lambda v: v < (3, 5, 0), "Medium",
     "versions before 3.5.0 allow cross-site scripting through HTML passed to DOM methods such as "
     "html() and append() (CVE-2020-11022 and CVE-2020-11023)",
     "Upgrade to jQuery 3.5.0 or newer.", [_nvd("CVE-2020-11022"), _nvd("CVE-2020-11023")]),
    ("Bootstrap", [r"bootstrap[-.](\d+\.\d+\.\d+)", r"/bootstrap/(\d+\.\d+\.\d+)/"],
     lambda v: v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1), "Low",
     "versions before 3.4.1 (3.x) and 4.3.1 (4.x) allow cross-site scripting through unsanitised "
     "tooltip and popover templates (CVE-2019-8331)",
     "Upgrade to Bootstrap 3.4.1, 4.3.1 or newer.", [_nvd("CVE-2019-8331")]),
    ("AngularJS", [r"angular(?:js)?[-.](1\.\d+\.\d+)", r"/angular(?:js|\.js)/(1\.\d+\.\d+)/"],
     lambda v: True, "Medium",
     "AngularJS 1.x reached end of life in January 2022 and no longer receives security fixes",
     "Migrate to a supported framework, or adopt a long-term-support fork if migration must wait.",
     ["https://docs.angularjs.org/misc/version-support-status"]),
]


def _version(text: str) -> tuple:
    parts = [int(p) for p in text.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))     # 3.5 means 3.5.0


def check_outdated_libraries(result: ScanResult) -> list[Finding]:
    findings, seen = [], set()
    for res in result.resources:
        if res["kind"] != "script":
            continue
        path = urlparse(res["url"]).path.lower()
        for name, patterns, vulnerable, severity, why, fix, refs in LIBRARY_RULES:
            found = next((m.group(1) for m in (re.search(p, path) for p in patterns) if m), None)
            if found is None:
                continue
            if vulnerable(_version(found)) and (name, found) not in seen:
                seen.add((name, found))
                findings.append(Finding(
                    "WR-023", f"Outdated {name} {found} in use", severity, "Vulnerable Components",
                    f"{name} {found}: {why}.", f"script {res['url']}", fix, list(refs)))
            break
    return findings
