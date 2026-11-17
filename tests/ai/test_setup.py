"""Tests for ai/setup.py and the --ai-setup command: saving the key safely, and never showing it."""

import os
import stat
import sys

import pytest

from webrecon.ai import envfile, setup
from webrecon.cli import main
from webrecon.errors import UserError

KEY = "sk-setup-TEST-KEY-1234"


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)


def test_the_key_is_saved_outside_the_project_and_never_printed(terminal, capsys, tmp_path):
    path = setup.run_setup(ask_key=lambda prompt: f"  {KEY}  ")
    assert path == envfile.user_file() and str(tmp_path / "config") in path          # the per-user file, not a project file
    assert open(path).read() == f"WEBRECON_AI_KEY={KEY}\n"
    shown = capsys.readouterr()
    assert KEY not in shown.out + shown.err and "cannot end up on GitHub" in shown.out


@pytest.mark.skipif(os.name == "nt", reason="file permissions work differently on Windows")
def test_the_saved_file_is_readable_only_by_its_owner(terminal):
    path = setup.run_setup(ask_key=lambda prompt: KEY)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert envfile.warnings_for(path) == []


def test_a_custom_location_is_honoured_and_other_settings_are_kept(terminal, monkeypatch, tmp_path):
    target = tmp_path / "somewhere" / "my.env"
    target.parent.mkdir()
    target.write_text("WEBRECON_AI_MODEL=my-model\n")
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(target))
    assert setup.run_setup(ask_key=lambda prompt: KEY) == str(target)
    assert target.read_text() == f"WEBRECON_AI_MODEL=my-model\nWEBRECON_AI_KEY={KEY}\n"


@pytest.mark.parametrize("typed,message", [("", "No key entered"), ("   ", "No key entered"), ("short", "does not look like"),
                                           ("has a space inside", "does not look like")])
def test_bad_input_saves_nothing(terminal, typed, message):
    with pytest.raises(UserError, match=message):
        setup.run_setup(ask_key=lambda prompt: typed)
    assert not os.path.exists(envfile.user_file())


def test_without_a_terminal_it_explains_the_alternative(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(UserError, match="WEBRECON_AI_KEY"):
        setup.run_setup(ask_key=lambda prompt: KEY)


def test_the_command_saves_the_key_and_it_is_then_used_automatically(terminal, monkeypatch, capsys, fake_ai):
    monkeypatch.setattr(setup.getpass, "getpass", lambda prompt: KEY)
    assert main(["--ai-setup"]) == 0
    out = capsys.readouterr()
    assert "Saved" in out.out and KEY not in out.out + out.err
    # the next scan finds the key by itself and sends it in the header
    port = fake_ai.url
    assert main(["http://127.0.0.1:1", "--no-probes", "--max-pages", "1", "--timeout", "1", "-q", "--ai",
                 "--ai-provider", "anthropic", "--ai-url", port, "--ai-model", "m"]) in (0, 1)   # 1: nothing at :1 to scan
    from webrecon.ai.config import resolve_config
    assert resolve_config(provider="anthropic", url=port, model="m").key == KEY


def test_the_command_reports_a_problem_without_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["--ai-setup"]) == 1
    assert "needs a terminal" in capsys.readouterr().out


def test_cancelling_leaves_nothing_behind(terminal, monkeypatch, capsys):
    def interrupted(prompt):
        raise KeyboardInterrupt
    monkeypatch.setattr(setup.getpass, "getpass", interrupted)
    assert main(["--ai-setup"]) == 1
    assert "nothing was saved" in capsys.readouterr().out and not os.path.exists(envfile.user_file())
