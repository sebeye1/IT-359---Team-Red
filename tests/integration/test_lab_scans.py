"""End-to-end tests: the real scanner against the practice lab on 127.0.0.1 (no outside network).

These pin the numbers used in the project demo, so a change that alters them gets noticed."""

import json
import socket

import pytest

from webrecon.cli import main


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def scan_lab(tmp_path, *extra):
    """Scan a freshly started lab and return the saved results."""
    out = tmp_path / "result.html"
    port = free_port()
    code = main([f"http://127.0.0.1:{port}", "--auto-lab", "--delay", "0", "-q", "-o", str(out), *extra])
    return code, json.loads(out.with_suffix(".json").read_text()), out


def test_vulnerable_lab_gives_the_demo_numbers(tmp_path):
    code, data, out = scan_lab(tmp_path)
    assert code == 0 and len(data["findings"]) == 21
    assert data["summary"] == {"Critical": 0, "High": 3, "Medium": 9, "Low": 6, "Info": 3}
    assert {"WR-060", "WR-061", "WR-070"} <= {f["check_id"] for f in data["findings"]}   # .git, .env, password over HTTP
    assert "Fix these first" in out.read_text()


def test_hardened_lab_leaves_only_the_expected_three(tmp_path):
    code, data, _ = scan_lab(tmp_path, "--hardened-lab")
    assert code == 0
    assert sorted(f["check_id"] for f in data["findings"]) == ["WR-001", "WR-070", "WR-080"]  # plain HTTP, form, robots


def test_findings_carry_reference_links_and_evidence(tmp_path):
    _, data, _ = scan_lab(tmp_path)
    git = next(f for f in data["findings"] if f["check_id"] == "WR-060")
    assert git["references"] and git["evidence"] and git["recommendation"]


def test_fail_on_and_baseline_work_together_end_to_end(tmp_path):
    port = free_port()
    target = f"http://127.0.0.1:{port}"
    before = tmp_path / "before.json"
    assert main([target, "--auto-lab", "--delay", "0", "-q", "-o", str(tmp_path / "b.html"),
                     "--json", str(before), "--fail-on", "High"]) == 2          # High findings present
    # The same lab against its own baseline has nothing new, so --fail-on no longer trips.
    assert main([target, "--auto-lab", "--delay", "0", "-q", "-o", str(tmp_path / "c.html"),
                     "--baseline", str(before), "--fail-on", "Info"]) == 0


def test_compare_of_vulnerable_and_hardened_runs_reports_what_was_fixed(tmp_path, capsys):
    port = free_port()
    target = f"http://127.0.0.1:{port}"
    for name, extra in (("before", []), ("after", ["--hardened-lab"])):
        main([target, "--auto-lab", "--delay", "0", "-q", "-o", str(tmp_path / f"{name}.html"), *extra])
    capsys.readouterr()
    assert main(["--compare", str(tmp_path / "before.json"), str(tmp_path / "after.json"),
                     "-o", str(tmp_path / "diff.html")]) == 0
    assert "Fixed 18   New 0   Still open 3" in capsys.readouterr().out


@pytest.mark.parametrize("flag", ["--also", "--min-severity"])
def test_exports_and_filters_work_on_a_real_scan(tmp_path, flag):
    extra = ["--also", "csv,md"] if flag == "--also" else ["--min-severity", "High"]
    _, data, out = scan_lab(tmp_path, *extra)
    if flag == "--also":
        assert out.with_suffix(".csv").exists() and out.with_suffix(".md").exists()
    else:
        assert {f["severity"] for f in data["findings"]} <= {"Critical", "High"} and len(data["findings"]) == 3


# ------------------------------------------------------------------ history: trend line and baseline chains

def scan_in_reports(*extra, hardened=False, port=None):
    """Scan a lab on the given port into ./reports (the default), returning the newest saved result."""
    import glob
    import os
    args = [f"http://127.0.0.1:{port}", "--auto-lab", "--delay", "0", "-q", *extra]
    if hardened:
        args.append("--hardened-lab")
    code = main(args)
    newest = max(glob.glob("reports/*.json"), key=os.path.getmtime)
    return code, json.loads(open(newest).read())


def test_second_scan_reports_how_it_compares_with_the_first():
    port = free_port()
    _, first = scan_in_reports(port=port)
    assert first["scan"]["trend"] == {}                                     # nothing to compare with yet
    _, second = scan_in_reports(hardened=True, port=port)
    t = second["scan"]["trend"]
    assert (t["fixed"], t["new"], t["still_open"]) == (18, 0, 3)


def test_trend_appears_in_the_console_and_the_report(capsys):
    port = free_port()
    scan_in_reports(port=port)
    capsys.readouterr()
    code = main([f"http://127.0.0.1:{port}", "--auto-lab", "--hardened-lab", "--delay", "0", "--open"])
    out = capsys.readouterr().out
    assert code == 0 and "Since your previous scan" in out and "18 fixed, 0 new, 3 still open" in out
    import glob
    newest = sorted(glob.glob("reports/*.html"))[-1]
    assert "Since your previous scan" in open(newest).read()


def test_baseline_last_can_be_repeated_because_the_json_stays_complete():
    port = free_port()
    scan_in_reports(port=port)                                              # 21 findings recorded
    for _ in range(2):                                                      # two runs that hide everything known
        code, data = scan_in_reports("--baseline", "last", "--fail-on", "Info", port=port)
        assert code == 0                                                    # nothing new, so --fail-on stays quiet
        assert len(data["findings"]) == 21                                  # the record is complete, not just "new"
        assert data["scan"]["trend"]["still_open"] == 21 and data["scan"]["trend"]["new"] == 0
