"""Tests for bootstrap.py: what happens when requests or beautifulsoup4 is not installed."""

import subprocess
import sys

import pytest

from webrecon import bootstrap


class Done:
    def __init__(self, returncode=0):
        self.returncode = returncode


@pytest.fixture
def packages_missing(monkeypatch):
    monkeypatch.setattr(bootstrap, "missing_packages", lambda: ["beautifulsoup4"])


def interactive(monkeypatch, answer):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _="": answer)


def test_nothing_happens_when_the_packages_are_installed(monkeypatch, capsys):
    monkeypatch.setattr(bootstrap, "missing_packages", lambda: [])
    bootstrap.ensure_dependencies()
    assert capsys.readouterr().out == ""


def test_real_environment_has_the_packages():
    assert bootstrap.missing_packages() == []  # the test suite itself needs them


def test_without_a_terminal_it_explains_the_fix_and_exits(packages_missing, monkeypatch, capsys):
    monkeypatch.setattr(bootstrap, "venv_python", lambda: None)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    out = capsys.readouterr().out
    assert stop.value.code == 1 and "beautifulsoup4" in out and "./run.sh" in out and "pip install -r" in out


def test_an_existing_working_venv_is_used_automatically_and_silently(packages_missing, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(bootstrap, "venv_python", lambda: "/proj/.venv/bin/python")
    monkeypatch.setattr(bootstrap, "running_in_project_venv", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd) or Done(0))
    monkeypatch.setattr(subprocess, "call", lambda cmd: calls.append(cmd) or 7)
    monkeypatch.setattr(sys, "argv", ["main.py", "https://example.com", "--open"])
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 7                                  # the child's exit code is passed on
    assert calls[1][0] == "/proj/.venv/bin/python" and calls[1][-2:] == ["https://example.com", "--open"]
    assert capsys.readouterr().out == ""                         # nothing that looks like an error


def test_a_venv_that_lacks_the_packages_is_not_used(packages_missing, monkeypatch, capsys):
    monkeypatch.setattr(bootstrap, "venv_python", lambda: "/proj/.venv/bin/python")
    monkeypatch.setattr(bootstrap, "running_in_project_venv", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: Done(1))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 1 and "./run.sh" in capsys.readouterr().out


def test_it_never_restarts_itself_from_inside_the_venv(packages_missing, monkeypatch):
    monkeypatch.setattr(bootstrap, "venv_python", lambda: sys.executable)
    monkeypatch.setattr(bootstrap, "running_in_project_venv", lambda: True)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(subprocess, "call", lambda cmd: pytest.fail("must not re-run itself"))
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 1


def test_accepting_the_offer_creates_a_venv_installs_and_reruns(packages_missing, monkeypatch, tmp_path):
    interactive(monkeypatch, "")  # just press Enter
    monkeypatch.setattr(bootstrap, "ROOT", str(tmp_path))
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / ".venv").mkdir()
    created = {"python": None}
    monkeypatch.setattr(bootstrap, "venv_python", lambda: created["python"])
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if "venv" in cmd:
            created["python"] = str(tmp_path / ".venv" / "python")
        return Done(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "call", lambda cmd: calls.append(cmd) or 0)
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 0
    assert "venv" in calls[0] and calls[1][1:4] == ["-m", "pip", "install"] and calls[2][0] == created["python"]
    assert (tmp_path / ".venv" / ".installed").exists()          # run.sh will not reinstall


def test_declining_the_offer_explains_the_fix(packages_missing, monkeypatch, capsys):
    interactive(monkeypatch, "n")
    monkeypatch.setattr(bootstrap, "venv_python", lambda: None)
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 1 and "./run.sh" in capsys.readouterr().out


@pytest.mark.parametrize("failing", ["venv", "pip"])
def test_a_failed_setup_gives_a_plain_message(packages_missing, monkeypatch, capsys, tmp_path, failing):
    interactive(monkeypatch, "y")
    monkeypatch.setattr(bootstrap, "ROOT", str(tmp_path))
    (tmp_path / "requirements.txt").write_text("requests\n")
    state = {"python": None}
    monkeypatch.setattr(bootstrap, "venv_python", lambda: state["python"])

    def fake_run(cmd, **kw):
        if "venv" in cmd:
            state["python"] = "/x/python"
            return Done(1 if failing == "venv" else 0)
        return Done(1)  # pip

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as stop:
        bootstrap.ensure_dependencies()
    assert stop.value.code == 1
    assert ("python3-venv" if failing == "venv" else "Installing the requirements failed") in capsys.readouterr().out
