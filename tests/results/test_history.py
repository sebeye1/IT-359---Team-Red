"""Tests for history.py: finding earlier scans in the reports folder."""

import json
import os
import time

from webrecon.results import history


def save(path, target, findings=(), age=0):
    path.write_text(json.dumps({"scan": {"target": target, "started": "t"}, "findings": list(findings)}))
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))


def test_saved_scans_are_newest_first_and_skip_other_json(tmp_path):
    save(tmp_path / "old.json", "https://a.example/", age=200)
    save(tmp_path / "new.json", "https://a.example/", age=10)
    (tmp_path / "notes.json").write_text('{"hello": 1}')
    (tmp_path / "broken.json").write_text("not json")
    assert [os.path.basename(e["path"]) for e in history.saved_scans(str(tmp_path))] == ["new.json", "old.json"]


def test_missing_folder_means_no_scans(tmp_path):
    assert history.saved_scans(str(tmp_path / "nope")) == []
    assert history.previous_scan("a.example", str(tmp_path / "nope")) is None
    assert history.last_two_scans(str(tmp_path / "nope")) is None


def test_previous_scan_matches_the_site_not_the_scheme_or_path(tmp_path):
    save(tmp_path / "a.json", "http://a.example/", age=100)
    save(tmp_path / "b.json", "https://b.example/", age=50)
    assert os.path.basename(history.previous_scan("https://A.example/login", str(tmp_path))["path"]) == "a.json"
    assert history.previous_scan("c.example", str(tmp_path)) is None


def test_last_two_scans_pairs_the_newest_with_the_one_before_for_that_site(tmp_path):
    save(tmp_path / "a1.json", "https://a.example/", age=300)
    save(tmp_path / "b1.json", "https://b.example/", age=200)
    save(tmp_path / "a2.json", "https://a.example/", age=100)
    older, newer = history.last_two_scans(str(tmp_path))
    assert (os.path.basename(older["path"]), os.path.basename(newer["path"])) == ("a1.json", "a2.json")


def test_last_two_scans_needs_two_scans_of_the_same_site(tmp_path):
    save(tmp_path / "a.json", "https://a.example/", age=100)
    save(tmp_path / "b.json", "https://b.example/", age=50)
    assert history.last_two_scans(str(tmp_path)) is None


def test_format_scans_lists_newest_first_with_counts_and_next_commands(tmp_path):
    def save_with_summary(name, target, summary, findings, age):
        path = tmp_path / name
        path.write_text(json.dumps({"scan": {"target": target, "started": "2026-11-08 10:00:00"},
                                    "summary": summary, "findings": findings}))
        stamp = time.time() - age
        os.utime(path, (stamp, stamp))

    save_with_summary("old.json", "https://a.example/", {"High": 1, "Low": 0}, [{}], 100)
    save_with_summary("new.json", "https://bb.example/", {"High": 0, "Low": 0}, [], 10)
    text = history.format_scans(history.saved_scans(str(tmp_path)), "reports")
    assert text.index("bb.example") < text.index("a.example")        # newest first
    assert "1 finding(s)  (High 1)" in text and "0 finding(s)  (no findings)" in text
    assert "python main.py --compare" in text and "--baseline last" in text


def test_format_scans_explains_an_empty_folder():
    assert "No saved scans in reports/ yet" in history.format_scans([], "reports")


def test_trend_counts_fixed_new_and_still_open():
    prev = {"started": "2026-11-01 09:00:00", "data": {"findings": [
        {"check_id": "WR-001", "title": "a", "severity": "Medium"},
        {"check_id": "WR-002", "title": "b", "severity": "Low"},
        {"check_id": "WR-003", "title": "c", "severity": "Low"}]}}
    now = [{"check_id": "WR-001", "title": "a", "severity": "High"},      # severity moved: still open
           {"check_id": "WR-003", "title": "c", "severity": "Low"},
           {"check_id": "WR-004", "title": "d", "severity": "Low"}]
    assert history.trend(prev, now) == {"since": "2026-11-01 09:00:00", "fixed": 1, "new": 1, "still_open": 2}


def test_previous_scan_stops_reading_at_the_first_match(tmp_path, monkeypatch):
    save(tmp_path / "a_old.json", "https://a.example/", age=300)
    save(tmp_path / "a_new.json", "https://a.example/", age=100)
    loaded = []
    real = history.load_scan
    monkeypatch.setattr(history, "load_scan", lambda path: loaded.append(os.path.basename(path)) or real(path))
    assert os.path.basename(history.previous_scan("a.example", str(tmp_path))["path"]) == "a_new.json"
    assert loaded == ["a_new.json"]                       # the older file was never opened
