"""End-to-end: scan the practice lab with --ai against a fake AI server (no real key, no outside network)."""

import json
import math
import socket

import pytest

from webrecon import ai
from webrecon.ai import attack, storage
from webrecon.cli import main

KEY = "sk-integration-SECRET"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ai_args(fake, provider="anthropic"):
    url = fake.url if provider == "anthropic" else fake.url + "/v1"
    return ["--ai", "--ai-provider", provider, "--ai-url", url, "--ai-model", "test-model"]


def lab_scan(tmp_path, fake, *extra, provider="anthropic", quiet=True, name="r"):
    out = tmp_path / f"{name}.html"
    args = [f"http://127.0.0.1:{free_port()}", "--auto-lab", "--delay", "0", "-o", str(out),
            "--also", "csv,md", *ai_args(fake, provider), *extra]
    code = main(args + (["-q"] if quiet else []))
    return code, json.loads(out.with_suffix(".json").read_text()), out


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_every_finding_gets_a_locally_calculated_estimate(tmp_path, fake_ai, provider):
    code, data, _ = lab_scan(tmp_path, fake_ai, provider=provider)
    assert code == 0 and len(data["findings"]) == 21
    assert all(f["enrichment"]["cvss"]["score"] == 3.7 for f in data["findings"])
    distinct = {f["check_id"] for f in data["findings"]}
    assert len(fake_ai.requests) == math.ceil(len(distinct) / 10)       # one request per ten check types, not per finding
    assert fake_ai.requests[0]["path"] == ("/v1/messages" if provider == "anthropic" else "/v1/chat/completions")


def test_nothing_about_the_scanned_site_is_sent(tmp_path, fake_ai):
    lab_scan(tmp_path, fake_ai)
    sent = json.dumps([r["body"] for r in fake_ai.requests])
    for private in ("127.0.0.1", "Summer2026", "db_backup", "uploads", "Apache/2.4.29", "PHP/7.2.24", "sessionid",
                    "a81b2c", "3f9a1c7e5b2d4a60", "WebRecon/1.0", "localhost"):
        assert private not in sent, private
    assert "check_id" in sent and "typical_severity" in sent             # what IS sent: generic descriptions


def test_the_reports_show_the_estimate_with_a_warning_and_links(tmp_path, fake_ai):
    _, _, out = lab_scan(tmp_path, fake_ai)
    html = out.read_text()
    assert "AI-estimated risk context" in html and "CVSS 3.7 (Low)" in html and "Highest AI-estimated CVSS" in html
    assert 'href="https://attack.mitre.org/techniques/T1190/"' in html and "Verify before relying on it" in html
    csv_text = out.with_suffix(".csv").read_text(encoding="utf-8-sig").splitlines()
    assert csv_text[0].endswith("ai_cvss_score,ai_cvss_vector,ai_attack_techniques") and ",3.7,CVSS:3.1/" in csv_text[1]
    assert "AI-estimated risk context" in out.with_suffix(".md").read_text()


def test_a_second_scan_is_answered_from_the_cache(tmp_path, fake_ai):
    lab_scan(tmp_path, fake_ai, name="first")
    asked = len(fake_ai.requests)
    _, data, out = lab_scan(tmp_path, fake_ai, name="second")
    assert len(fake_ai.requests) == asked and all(f["enrichment"] for f in data["findings"])
    assert "0 check type(s) asked" in out.read_text() and "from the local cache" in out.read_text()


def test_mitres_list_checks_the_ids_when_it_has_been_downloaded(tmp_path, fake_ai):
    storage.write_json(attack.INDEX_FILE, {"version": "20.1", "techniques": {
        "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]}}})
    fake_ai.results_for["WR-001"] = {"attack": [{"id": "T1190"}, {"id": "T4242", "reason": "made up"}]}
    _, data, out = lab_scan(tmp_path, fake_ai)
    technique = next(f for f in data["findings"] if f["check_id"] == "WR-001")["enrichment"]["attack"]
    assert [t["id"] for t in technique] == ["T1190"] and technique[0]["verified"] is True
    assert "T4242" in out.read_text() and "not in MITRE" in out.read_text()      # the note explains what was dropped


def test_a_failing_ai_server_never_breaks_the_scan(tmp_path, fake_ai):
    fake_ai.status = 401
    code, data, out = lab_scan(tmp_path, fake_ai)
    assert code == 0 and len(data["findings"]) == 21                    # the exit code and findings are untouched
    assert not any(f["enrichment"] for f in data["findings"])
    assert "AI: The server rejected the API key" in out.read_text()


def test_the_key_goes_in_the_header_and_nowhere_else(tmp_path, fake_ai, monkeypatch, capsys):
    monkeypatch.setenv("WEBRECON_AI_KEY", KEY)
    lab_scan(tmp_path, fake_ai, quiet=False)
    assert fake_ai.requests[0]["headers"]["x-api-key"] == KEY
    shown = capsys.readouterr()
    assert KEY not in shown.out + shown.err
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes(), path


def test_a_missing_key_stops_before_anything_is_scanned(tmp_path, capsys):
    code = main([f"http://127.0.0.1:{free_port()}", "--auto-lab", "--ai", "--ai-url", "https://llm.example.com/v1",
                 "--ai-model", "m"])
    out = capsys.readouterr().out
    assert code == 1 and "No API key found" in out and "WEBRECON_AI_KEY" in out
    assert not (tmp_path / "reports").exists()                          # no scan happened


def test_the_disclosure_line_and_the_attack_update_tip_are_shown(tmp_path, fake_ai, capsys):
    lab_scan(tmp_path, fake_ai, quiet=False)
    out = capsys.readouterr().out
    assert "[i] AI: asking" in out and "No URLs, evidence or results are sent" in out and "--attack-update" in out
    assert "(CVSS ~3.7)" in out                                          # the estimate is marked as approximate


def test_plan_describes_the_ai_step_without_sending_or_asking_for_anything(fake_ai, capsys):
    code = main(["https://example.com", "--plan", *ai_args(fake_ai)])
    out = capsys.readouterr().out
    assert code == 0 and "AI risk context" in out and "Nothing about the target is sent" in out and fake_ai.url in out
    assert fake_ai.requests == []
    main(["https://example.com", "--plan", "--ai"])
    assert "Not ready yet: No API key found" in capsys.readouterr().out


def test_the_attack_update_command_reports_success_and_failure(monkeypatch, capsys):
    monkeypatch.setattr(ai, "update_index", lambda: {"version": "20.1", "techniques": {"T1190": {}, "T1040": {}}})
    assert main(["--attack-update"]) == 0
    assert "Saved 2 techniques (ATT&CK version 20.1)" in capsys.readouterr().out

    def fail():
        raise ai.attack.UserError("Could not download the ATT&CK data from MITRE: ConnectionError.")
    monkeypatch.setattr(ai, "update_index", fail)
    assert main(["--attack-update"]) == 1
    assert "Could not download" in capsys.readouterr().out


# ------------------------------------------------------------------ keys kept in private files

def private_file(tmp_path, text, mode=0o600):
    path = tmp_path / "private" / "env"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def test_a_key_in_a_private_file_is_used_and_never_leaks(tmp_path, fake_ai, monkeypatch, capsys):
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(private_file(tmp_path, f"WEBRECON_AI_KEY={KEY}\n")))
    code, data, _ = lab_scan(tmp_path, fake_ai, quiet=False)
    assert code == 0 and all(f["enrichment"] for f in data["findings"])
    assert fake_ai.requests[0]["headers"]["x-api-key"] == KEY                  # found the key with no variable set
    shown = capsys.readouterr()
    assert KEY not in shown.out + shown.err and "[!]" not in shown.out         # and a properly private file raises no warning
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "env":                              # every output file, but not the key file itself
            assert KEY.encode() not in path.read_bytes(), path


@pytest.mark.skipif(__import__("os").name == "nt", reason="file permissions work differently on Windows")
def test_a_key_file_other_users_can_read_is_reported_even_in_quiet_mode(tmp_path, fake_ai, monkeypatch, capsys):
    path = private_file(tmp_path, f"WEBRECON_AI_KEY={KEY}\n", mode=0o644)
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(path))
    lab_scan(tmp_path, fake_ai, quiet=True)
    out = capsys.readouterr().out
    assert "[!]" in out and "chmod 600" in out and KEY not in out


def test_a_file_cannot_redirect_the_scan_through_a_proxy_or_weaken_tls(tmp_path, fake_ai, monkeypatch):
    import os
    names = ("HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "http_proxy", "https_proxy")
    for name in names:
        monkeypatch.delenv(name, raising=False)                               # start from a clean environment
    path = private_file(tmp_path, f"WEBRECON_AI_KEY={KEY}\nHTTP_PROXY=http://evil.example:3128\n"
                                  "REQUESTS_CA_BUNDLE=/nonexistent\nHTTPS_PROXY=http://evil.example:3128\n")
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(path))
    lab_scan(tmp_path, fake_ai)
    assert not any(name in os.environ for name in names)                      # the file set none of them
    assert fake_ai.requests                                                   # and the scan still worked normally
