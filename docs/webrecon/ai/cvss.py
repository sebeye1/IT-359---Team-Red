"""
cvss.py - CVSS v3.1 base scores, computed locally from a vector string.

An AI server may suggest a vector such as CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, but the number
shown in a report is always calculated here with the formula from the FIRST CVSS v3.1 specification, so a
wrong or invented score can never get through. A vector that is not valid CVSS v3.1 is rejected.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# metric -> allowed values, in the order the specification writes them
METRICS = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN",
}
PREFIX = "CVSS:3.1"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


@dataclass(frozen=True)
class CvssScore:
    vector: str      # normalised: prefix first, then the metrics in specification order
    score: float
    rating: str      # None, Low, Medium, High or Critical


def roundup(value: float) -> float:
    """The CVSS v3.1 Roundup function: the smallest number with one decimal that is >= value."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def rating(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(text: str) -> dict | None:
    """The metrics in a CVSS v3.1 base vector, or None if the text is not a valid one."""
    if not isinstance(text, str):
        return None
    parts = text.strip().split("/")
    if not parts or parts[0].upper() != PREFIX:
        return None
    metrics = {}
    for part in parts[1:]:
        name, sep, value = part.partition(":")
        name, value = name.upper(), value.upper()
        if not sep or name not in METRICS or value not in METRICS[name] or len(value) != 1 or name in metrics:
            return None
        metrics[name] = value
    return metrics if set(metrics) == set(METRICS) else None


def calculate(metrics: dict) -> float:
    changed = metrics["S"] == "C"
    privileges = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[metrics["UI"]]
    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1.0) * (impact + exploitability), 10))


def evaluate(vector: str) -> CvssScore | None:
    """Validate a vector and compute its score. None if the vector is not valid CVSS v3.1."""
    metrics = parse_vector(vector)
    if metrics is None:
        return None
    score = calculate(metrics)
    normalised = PREFIX + "".join(f"/{name}:{metrics[name]}" for name in METRICS)
    return CvssScore(normalised, score, rating(score))
