"""Shared test helpers."""

import json
import os
import time

from webrecon.analysis import Finding
from webrecon.scanning import ScanResult


def base_result(**overrides) -> ScanResult:
    r = ScanResult(target="http://127.0.0.1:8080", final_url="http://127.0.0.1:8080/", status_code=200)
    for key, value in overrides.items():
        setattr(r, key, value)
    return r


def ids(findings) -> set:
    return {f.check_id for f in findings}


def make_finding(check_id, title="t", severity="Medium") -> Finding:
    return Finding(check_id, title, severity, "c", "d", "e", "r")


def save_scan(path, target, check_ids, age=0):
    """Write a minimal saved scan result, as if it had been made `age` seconds ago."""
    path.write_text(json.dumps({"scan": {"target": target, "started": "t"},
                                "findings": [{"check_id": c, "title": "t", "severity": "Low"} for c in check_ids]}))
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))


class FakeResp:
    """Just enough of requests.Response for the scanner code paths under test."""

    def __init__(self, url="http://x/", status=200, text="", headers=None, history=None, content=None):
        self.url, self.status_code, self.text = url, status, text
        self.content = content if content is not None else text.encode()
        self.headers = headers or {}
        self.history = history or []
        self.raw = None


def answers(monkeypatch, *values):
    """Feed the prompts these answers in order. Running out of answers fails the test."""
    it = iter(values)
    monkeypatch.setattr("builtins.input", lambda _="": next(it))
