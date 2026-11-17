"""Tests for results/filters.py: --ignore, --min-severity and --baseline."""

from collections import Counter

import pytest

from helpers import make_finding, save_scan
from webrecon.analysis import Finding
from webrecon.cli.options import parse_args
from webrecon.errors import UserError
from webrecon.results.filters import filter_findings, load_baseline, resolve_baseline
from webrecon.cli.options import parse_ignore


def test_ignore_and_min_severity_filtering():
    mk = lambda cid, sev: Finding(cid, "t", sev, "c", "d", "e", "r")
    found = [mk("WR-001", "Medium"), mk("WR-014", "Info"), mk("WR-091", "Low")]
    kept, hidden = filter_findings(found, parse_ignore(["wr-091, WR-014"]), None)
    assert [f.check_id for f in kept] == ["WR-001"] and len(hidden) == 2
    kept, _ = filter_findings(found, set(), "Low")
    assert {f.check_id for f in kept} == {"WR-001", "WR-091"}
    with pytest.raises(UserError):
        parse_ignore(["WR-999"])


def test_baseline_hides_known_findings_and_keeps_new_ones():
    baseline = Counter({("WR-001", "t"): 1, ("WR-073", "form"): 1})
    found = [make_finding("WR-001"), make_finding("WR-010"), make_finding("WR-073", "form"), make_finding("WR-073", "form")]
    kept, hidden = filter_findings(found, set(), None, baseline)
    assert [f.check_id for f in kept] == ["WR-010", "WR-073"]   # a second copy of a known finding is new
    assert len(hidden) == 2


def test_baseline_combines_with_ignore_and_min_severity():
    found = [make_finding("WR-001"), make_finding("WR-014", severity="Info"), make_finding("WR-091", severity="Low"),
             make_finding("WR-010")]
    kept, _ = filter_findings(found, {"WR-091"}, "Medium", Counter({("WR-001", "t"): 1}))
    assert [f.check_id for f in kept] == ["WR-010"]


def test_load_baseline_counts_findings_from_a_saved_result(tmp_path):
    import json
    saved = tmp_path / "before.json"
    saved.write_text(json.dumps({"findings": [{"check_id": "WR-001", "title": "t"}] * 2}))
    assert load_baseline(str(saved)) == {("WR-001", "t"): 2}
    with pytest.raises(UserError):
        load_baseline(str(tmp_path / "missing.json"))


def test_baseline_last_uses_the_previous_scan_of_the_same_site(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    save_scan(reports / "mine.json", "https://a.example/", ["WR-001", "WR-001"], age=50)
    save_scan(reports / "theirs.json", "https://b.example/", ["WR-010"], age=10)
    args = parse_args(["x", "--baseline", "last"])
    counts, note = resolve_baseline(args, "a.example")
    assert counts == {("WR-001", "t"): 2} and "previous scan" in note
    counts, note = resolve_baseline(args, "https://never-scanned.example")
    assert counts is None and "nothing was hidden" in note
    assert resolve_baseline(parse_args(["x"]), "a.example") == (None, None)
