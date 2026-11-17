"""Tests for the one-step launchers (run.sh and run.bat). They are checked, not executed."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_run_sh_is_executable_and_valid_shell():
    script = ROOT / "run.sh"
    assert os.access(script, os.X_OK)
    text = script.read_text()
    assert text.startswith("#!/usr/bin/env sh") and 'main.py "$@"' in text and "requirements.txt" in text
    if shutil.which("sh"):
        assert subprocess.run(["sh", "-n", str(script)]).returncode == 0


def test_run_bat_uses_crlf_and_passes_arguments_through():
    raw = (ROOT / "run.bat").read_bytes()
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")  # every line ends in CRLF, as cmd.exe expects
    text = raw.decode()
    assert "main.py %*" in text and "requirements.txt" in text and ".venv" in text


def test_the_virtual_environment_folder_is_not_committed():
    assert ".venv/" in (ROOT / ".gitignore").read_text().split()


@pytest.mark.parametrize("name", ["run.sh", "run.bat"])
def test_launchers_install_requirements_only_when_needed(name):
    text = (ROOT / name).read_text()
    assert ".installed" in text  # a stamp file, so later runs start straight away
