"""Tests for interactive/walkthrough.py and the start() entry point."""

import json

from helpers import answers
from webrecon.interactive import run_walkthrough, start


def make_fake_runner(tmp_path, calls):
    """Stands in for main.main: writes the JSON files the walkthrough reads back."""
    def runner(argv):
        calls.append(argv)
        if "--compare" in argv:
            return 0
        n = 1 if "--hardened-lab" in argv else 3
        findings = [{"severity": "High", "check_id": f"WR-0{i}", "title": "t", "recommendation": "r"}
                    for i in range(n)]
        path = tmp_path / argv[argv.index("--json") + 1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"summary": {"High": n}, "findings": findings}))
        return 0
    return runner


def test_walkthrough_runs_both_scans_then_compares(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _="": "")
    calls = []
    assert run_walkthrough(make_fake_runner(tmp_path, calls)) == 0
    assert len(calls) == 3
    assert "--hardened-lab" in calls[1] and calls[2][0] == "--compare"


def test_walkthrough_stops_when_a_scan_fails(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _="": "")
    calls = []
    assert run_walkthrough(lambda argv: calls.append(argv) or 1) == 1
    assert len(calls) == 1


def test_start_quits_cleanly_on_q_and_on_eof(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _="": "q")
    assert start(lambda argv: 0, "walkthrough") == 1

    def eof(_=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    assert start(lambda argv: 0, "menu") == 1


def test_start_menu_runs_the_chosen_scans(monkeypatch):
    answers(monkeypatch, "2")
    seen = []
    assert start(lambda argv: seen.append(argv) or 0, "menu", ["-q"]) == 0
    assert seen[0][-2:] == ["-q", "--open"] and "--hardened-lab" in seen[0]
