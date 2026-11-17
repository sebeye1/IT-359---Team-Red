"""
prompt.py - What is sent to the AI server, and nothing more.

The request describes check TYPES only: an ID, the check's generic title, its category and its usual
severity. It never contains the target's address, evidence, cookies, headers, page content or results, so
nothing about the site being scanned leaves the machine. (--plan shows this before anything is sent.)
"""

from __future__ import annotations

import hashlib
import json

from webrecon.analysis import CHECK_CATALOG

PROMPT_VERSION = 1  # bump when SYSTEM changes, so cached answers made with an older prompt are not reused

SYSTEM = """You are an application security analyst. You receive a JSON list of web application \
misconfiguration check types that an automated scanner can report. For each one:

1. Give a CVSS v3.1 base vector estimating how severe this kind of weakness typically is on a real site.
   Use exactly this form with all eight base metrics: CVSS:3.1/AV:x/AC:x/PR:x/UI:x/S:x/C:x/I:x/A:x
   Do not calculate a score; it is calculated from your vector.
2. List up to 3 MITRE ATT&CK Enterprise techniques that an attacker could realistically use because of this
   weakness. Use real technique IDs only (T1234 or T1234.001). If you are not sure an ID exists, leave it out.
   An empty list is a good answer when no technique fits.

Keep every reason under 20 words. Reply with a single JSON object and nothing else (no prose, no code \
fences), in this shape, with one entry per input check:
{"results":[{"check_id":"WR-001","cvss_vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",\
"attack":[{"id":"T1040","reason":"Traffic can be read on the network."}],"rationale":"One short sentence."}]}"""

_CATALOG = {check_id: (severity, title) for check_id, severity, title in CHECK_CATALOG}


def items_for(findings) -> list[dict]:
    """One entry per distinct check type among the findings, in a stable order. Generic text only."""
    first = {}
    for f in findings:
        first.setdefault(f.check_id, f)
    items = []
    for check_id in sorted(first):
        severity, title = _CATALOG.get(check_id, (first[check_id].severity, first[check_id].title))
        items.append({"check_id": check_id, "title": title, "category": first[check_id].category,
                      "typical_severity": severity})
    return items


def user_message(items: list[dict]) -> str:
    return json.dumps({"checks": items}, indent=1)


def item_hash(item: dict) -> str:
    """Identifies exactly what was asked, so a cached answer is reused only for the same question."""
    return hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()[:16]
