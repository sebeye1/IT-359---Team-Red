"""Tests for cli/workflow.py, console.py and authorization.py: output files, exit codes, tips, the permission question."""

from helpers import make_finding
from webrecon.analysis import Finding
from webrecon.cli import authorization, console, workflow
from webrecon.cli.options import parse_args


def test_output_paths(tmp_path):
    d = str(tmp_path / "out")
    auto = parse_args(["https://example.com/app", "--output-dir", d])
    html, js = workflow.output_paths("https://example.com/app", auto, multiple=False)
    assert html.startswith(d) and html.endswith(".html") and "example.com_app" in html
    assert js == html[:-5] + ".json"
    explicit = parse_args(["a.com", "-o", str(tmp_path / "mine.html"), "--json", str(tmp_path / "m.json")])
    assert workflow.output_paths("a.com", explicit, multiple=False) == (str(tmp_path / "mine.html"), str(tmp_path / "m.json"))
    h2, j2 = workflow.output_paths("a.com", explicit, multiple=True)  # -o is ignored for several targets
    assert "mine.html" not in h2 and j2 == h2[:-5] + ".json"
    only_html = parse_args(["a.com", "-o", str(tmp_path / "x" / "r.html")])
    assert workflow.output_paths("a.com", only_html, multiple=False) == (str(tmp_path / "x" / "r.html"),
                                                                    str(tmp_path / "x" / "r.json"))


def test_json_results_are_always_saved_next_to_the_report(tmp_path):
    args = parse_args(["a.com", "--output-dir", str(tmp_path)])
    html, js = workflow.output_paths("a.com", args, multiple=False)
    assert js == html[:-5] + ".json"


def test_authorization_prompt_covers_all_remote_targets(monkeypatch):
    assert authorization.confirm_authorization(["http://127.0.0.1:1", "localhost:2"], False) is True
    monkeypatch.setattr("builtins.input", lambda _="": "yes")
    assert authorization.confirm_authorization(["http://a.example", "b.example"], False) is True
    monkeypatch.setattr("builtins.input", lambda _="": "no")
    assert authorization.confirm_authorization(["http://a.example"], False) is False
    assert authorization.confirm_authorization(["http://a.example"], True) is True


def test_authorization_prompt_without_input_declines(monkeypatch):

    def no_input(_=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", no_input)
    assert authorization.confirm_authorization(["http://a.example"], False) is False


def test_exit_code_prefers_fail_on_over_unreachable():
    finding = Finding("WR-001", "t", "High", "c", "d", "e", "r")
    ok = {"ok": True, "findings": [finding]}
    down = {"ok": False, "findings": []}
    assert workflow.exit_code([ok], None) == 0
    assert workflow.exit_code([ok], "High") == 2 and workflow.exit_code([ok], "Critical") == 0
    assert workflow.exit_code([ok, down], None) == 1
    assert workflow.exit_code([ok, down], "High") == 2


def test_a_partial_scan_is_reported_as_incomplete():
    done = {"ok": True, "findings": [], "partial": False}
    cut_short = {"ok": True, "findings": [], "partial": True}
    assert workflow.exit_code([done], None) == 0
    assert workflow.exit_code([cut_short], None) == 1


def test_ctrl_c_stops_the_remaining_targets(monkeypatch):
    seen = []

    def fake_scan(target, args, html, js, headers):
        seen.append(target)
        return {"target": target, "ok": True, "findings": [], "counts": {}, "report": html,
                "interrupted": len(seen) == 1}

    monkeypatch.setattr(workflow, "scan_target", fake_scan)
    workflow.run_all(["http://a.example", "http://b.example", "http://c.example"],
                parse_args(["a", "b", "c", "-q"]))
    assert seen == ["http://a.example"]


def test_next_steps_name_the_urgent_findings_and_the_compare_command():
    found = [make_finding("WR-060", "Git exposed", "High"), make_finding("WR-014", "Permissions", "Info")]
    lines = console.next_steps(found)
    assert "WR-060 Git exposed (High)" in lines[0] and "WR-014" not in lines[0]
    assert lines[-1].endswith("python main.py --compare")
    assert len(console.next_steps([])) == 1  # nothing to fix first, but still how to re-check later


def test_tips_appear_for_real_command_lines_only(monkeypatch, capsys):
    entry = {"target": "t", "ok": True, "findings": [], "counts": {}, "report": "r.html"}
    monkeypatch.setattr(workflow, "scan_target", lambda *a, **k: dict(entry))
    args = parse_args(["http://a.example", "-q"])
    workflow.run_all(["http://a.example"], args)
    assert "[>]" not in capsys.readouterr().out           # no tips unless main() asked for them
    args.tips = True
    workflow.run_all(["http://a.example"], args)
    assert "python main.py --compare" in capsys.readouterr().out


def test_banner_prints_only_once_per_run(monkeypatch, capsys):
    monkeypatch.setattr(console, "_banner_shown", False)
    console.show_banner()
    console.show_banner()
    assert capsys.readouterr().out.count("Web Recon & Misconfiguration Scanner") == 1
