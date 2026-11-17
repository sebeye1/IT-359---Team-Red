"""Tests for compare.py."""

import json

import pytest

from webrecon.results import compare


def _scan(findings, target="http://x"):
    return {"scan": {"target": target, "started": "t"}, "findings": findings}


def _f(cid, title, sev="Medium"):
    return {"check_id": cid, "title": title, "severity": sev}


def test_compare_classifies_fixed_new_open_and_changed():
    before = _scan([_f("WR-060", "Git exposed", "High"), _f("WR-001", "HTTP"), _f("WR-013", "Referrer", "Low")])
    after = _scan([_f("WR-001", "HTTP"), _f("WR-013", "Referrer", "Medium"), _f("WR-091", "SRI", "Low")])
    d = compare.diff(before, after)
    assert [f["check_id"] for f in d["fixed"]] == ["WR-060"]
    assert [f["check_id"] for f in d["new"]] == ["WR-091"]
    assert [f["check_id"] for f in d["unchanged"]] == ["WR-001"]
    assert [(o["severity"], c["severity"]) for o, c in d["changed"]] == [("Low", "Medium")]


def test_compare_handles_repeated_findings_by_count():
    two = _scan([_f("WR-073", "POST form with no visible CSRF token")] * 2)
    one = _scan([_f("WR-073", "POST form with no visible CSRF token")])
    d = compare.diff(two, one)
    assert len(d["fixed"]) == 1 and len(d["unchanged"]) == 1 and d["new"] == []


def test_compare_run_writes_report_and_signals_new_findings(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_scan([_f("WR-060", "Git exposed", "High")])))
    b.write_text(json.dumps(_scan([_f("WR-060", "Git exposed", "High"), _f("WR-091", "SRI <x>", "Low")])))
    out = tmp_path / "diff.html"
    assert compare.run(str(a), str(b), str(out)) == 2
    html = out.read_text()
    assert "SRI &lt;x&gt;" in html and "Still open" in html
    assert compare.run(str(b), str(b), str(out)) == 0


def test_compare_rejects_bad_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("nope")
    other = tmp_path / "other.json"
    other.write_text('{"x": 1}')
    for path in (str(bad), str(other), str(tmp_path / "missing.json")):
        with pytest.raises(compare.CompareError):
            compare.load_scan(path)
