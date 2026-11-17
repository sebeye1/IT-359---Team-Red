"""Tests for cli/app.py: how main() routes what the user typed."""

import pytest

from helpers import save_scan
from webrecon.cli import app


@pytest.fixture
def routed(monkeypatch):
    """Record which interactive mode main() picks instead of starting it."""
    calls = []
    monkeypatch.setattr(app, "interactive", lambda mode, raw=None: calls.append((mode, raw)) or 0)
    return calls


def test_no_arguments_start_the_walkthrough(routed):
    assert app.main([]) == 0 and routed == [("walkthrough", None)]


def test_options_without_a_target_open_the_menu_and_keep_the_options(routed):
    app.main(["--auto-lab", "--delay", "0"])
    assert routed == [("menu", ["--auto-lab", "--delay", "0"])]


def test_mode_flags_choose_the_interactive_mode(routed):
    app.main(["--quick"])
    app.main(["--walkthrough"])
    app.main(["--guided"])  # old name, still accepted
    assert [mode for mode, _ in routed] == ["menu", "walkthrough", "walkthrough"]


def test_list_checks_prints_the_catalog(capsys):
    assert app.main(["--list-checks"]) == 0
    assert "WR-091" in capsys.readouterr().out


def test_unknown_ignore_id_and_bad_header_are_reported_not_raised(capsys):
    assert app.main(["http://127.0.0.1:1", "--ignore", "WR-999"]) == 1
    assert app.main(["http://127.0.0.1:1", "--header", "nocolon"]) == 1
    out = capsys.readouterr().out
    assert "Unknown check ID" in out and "Name: value" in out


def test_bad_also_or_baseline_is_reported_not_raised(capsys):
    assert app.main(["http://127.0.0.1:1", "--also", "pdf"]) == 1
    assert app.main(["http://127.0.0.1:1", "--baseline", "nope.json"]) == 1
    out = capsys.readouterr().out
    assert "Unknown format" in out and "Could not read" in out


def test_compare_without_files_uses_the_last_two_scans_of_a_site(tmp_path, capsys):
    reports = tmp_path / "reports"
    reports.mkdir()
    save_scan(reports / "old.json", "https://a.example/", ["WR-001", "WR-010"], age=300)
    save_scan(reports / "other.json", "https://b.example/", ["WR-099"], age=200)
    save_scan(reports / "new.json", "https://a.example/", ["WR-001"], age=100)
    assert app.main(["--compare", "-o", str(tmp_path / "diff.html")]) == 0
    out = capsys.readouterr().out
    assert "last two scans of https://a.example/" in out and "Fixed 1" in out and "WR-099" not in out


def test_compare_without_files_explains_what_is_missing(tmp_path, capsys):
    assert app.main(["--compare"]) == 1
    assert "scan the site twice" in capsys.readouterr().out
    assert app.main(["--compare", "only-one.json"]) == 1
    assert "two result files" in capsys.readouterr().out


def test_list_scans_shows_what_is_saved_and_works_when_nothing_is(tmp_path, capsys):
    assert app.main(["--list-scans"]) == 0
    assert "No saved scans" in capsys.readouterr().out
    reports = tmp_path / "reports"
    reports.mkdir()
    save_scan(reports / "a.json", "https://a.example/", ["WR-001"], age=10)
    assert app.main(["--list-scans"]) == 0
    out = capsys.readouterr().out
    assert "https://a.example/" in out and "a.json" in out


def test_plan_describes_the_scan_and_sends_nothing(monkeypatch, capsys):
    import webrecon.scanning.scanner as scanner_mod

    def must_not_run(self):
        raise AssertionError("--plan must not scan")
    monkeypatch.setattr(scanner_mod.Scanner, "run", must_not_run)
    code = app.main(["example.com", "--plan", "--header", "X-Key: secret", "--cookie", "s=topsecret",
                     "--max-pages", "5", "--delay", "0.5"])
    out = capsys.readouterr().out
    assert code == 0 and "nothing is sent" in out
    assert "https://example.com" in out and "/.env" in out and "up to 5 same-origin pages" in out
    assert "X-Key" in out and "secret" not in out and "topsecret" not in out  # values are never shown
    assert "confirm authorization" in out


def test_plan_counts_requests_for_http_and_https(capsys):
    app.main(["http://127.0.0.1:1", "--plan", "--max-pages", "4", "--no-probes"])
    assert "At most 8 requests" in capsys.readouterr().out    # 1 + 4 pages + sitemap + OPTIONS + TRACE
    app.main(["https://example.com", "--plan", "--max-pages", "4", "--no-probes", "--max-time", "0"])
    out = capsys.readouterr().out
    assert "At most 9 requests" in out and "No time limit" in out  # plus the http redirect check
