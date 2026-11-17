"""
findings.py - What the analyzer produces: the Finding record, severity ordering, and counting.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    references: list = field(default_factory=list)  # https links, filled in by analyze()
    enrichment: dict = field(default_factory=dict)  # optional AI-estimated CVSS and ATT&CK context (webrecon.ai)

    def to_dict(self) -> dict:
        return asdict(self)




def severity_counts(findings: list[Finding]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts
