"""Tests for scripts/check_secrets.py, the pre-commit hook, and the project's own protections against leaking a key.

The key-shaped strings below are assembled at run time so that this file itself stays clean when it is scanned."""

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from webrecon.ai import envfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_secrets", ROOT / "scripts" / "check_secrets.py")
check_secrets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_secrets)

needs_git = pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
                               reason="git is not installed")

ANTHROPIC = "sk-" + "ant-" + "A" * 40
OPENAI = "sk-" + "B" * 48
OPENAI_PROJECT = "sk-" + "proj-" + "C" * 40
GITHUB = "gh" + "p_" + "D" * 36
AWS = "AK" + "IA" + "E" * 16
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
GENERIC = "F" * 12 + "g" * 12 + "7" * 4


@pytest.mark.parametrize("secret,kind", [
    (ANTHROPIC, "Anthropic API key"), (OPENAI, "OpenAI-style API key"), (OPENAI_PROJECT, "OpenAI-style API key"),
    (GITHUB, "GitHub token"), (AWS, "AWS access key ID"), (PRIVATE_KEY, "Private key block"),
    (f'API_KEY = "{GENERIC}"', "Secret assigned in code"), (f"token: '{GENERIC}'", "Secret assigned in code"),
    (f'password="{GENERIC}"', "Secret assigned in code"),
])
def test_known_secret_shapes_are_found_with_their_line_number(secret, kind):
    found = check_secrets.scan_text(f"nothing here\nline two {secret} trailing\n")
    assert [(n, k) for n, k, _ in found] == [(2, kind)]


@pytest.mark.parametrize("text", [
    "sk-short", "sk-" + "x" * 10, "ghp_tooshort", "AKIA123", "the word secret", "api_key = os.environ['API_KEY']",
    'api_key = "your-api-key-goes-here-please-0000"', 'token = "<paste your token here, 30 chars>"',
    'secret = "example-secret-value-for-docs-xx"', 'API_KEY="short"', "WEBRECON_AI_KEY=paste-your-key-here",
    'password = "..........................."',
])
def test_ordinary_text_and_obvious_placeholders_are_not_flagged(text):
    assert check_secrets.scan_text(text) == []


def test_a_deliberate_example_can_be_allowed_on_its_line():
    assert check_secrets.scan_text(f"{ANTHROPIC}  # secret-scan: allow\n") == []
    assert len(check_secrets.scan_text(f"{ANTHROPIC}\n{ANTHROPIC}  # secret-scan: allow\n")) == 1


def test_a_finding_never_contains_the_secret_itself():
    findings = check_secrets.scan_text(f"x = '{ANTHROPIC}'\n")
    assert ANTHROPIC not in repr(findings) and findings[0][2] == len(ANTHROPIC)


def test_scanning_a_plain_folder_skips_environments_caches_and_binary_files(tmp_path):
    (tmp_path / "code.py").write_text(f"KEY = '{ANTHROPIC}'\n")
    for hidden in (".venv", "venv", "__pycache__", "reports", ".git"):
        (tmp_path / hidden).mkdir()
        (tmp_path / hidden / "x.py").write_text(ANTHROPIC)
    (tmp_path / "blob.bin").write_bytes(b"\x00" + ANTHROPIC.encode())
    (tmp_path / "huge.txt").write_text(ANTHROPIC + "x" * 1_100_000)
    assert [(p, n) for p, n, _, _ in check_secrets.scan(str(tmp_path))] == [("code.py", 1)]


def git(repo, *args, check=True):
    return subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args], cwd=repo,
                          capture_output=True, text=True, check=check)


@needs_git
def test_inside_a_repo_ignored_files_are_left_alone_but_everything_else_is_scanned(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text(f"WEBRECON_AI_KEY={ANTHROPIC}\n")          # a private key file: allowed
    (tmp_path / "new.py").write_text(f"KEY = '{ANTHROPIC}'\n")                # not ignored, not even added yet
    assert [p for p, *_ in check_secrets.scan(str(tmp_path))] == ["new.py"]


@needs_git
def test_staged_mode_checks_what_will_be_committed_not_the_working_copy(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.py").write_text("clean = 1\n")
    git(tmp_path, "add", "a.py")
    (tmp_path / "a.py").write_text(f"KEY = '{ANTHROPIC}'\n")                  # the dirty edit is NOT staged
    assert check_secrets.scan(str(tmp_path), staged=True) == []
    git(tmp_path, "add", "a.py")                                              # now it is
    assert [(p, n) for p, n, _, _ in check_secrets.scan(str(tmp_path), staged=True)] == [("a.py", 1)]


@needs_git
def test_the_command_reports_without_revealing_and_sets_its_exit_status(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    (tmp_path / "clean.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    assert check_secrets.main(["--root", str(tmp_path), "--staged"]) == 0
    (tmp_path / "leak.py").write_text(f"KEY = '{OPENAI}'\n")
    git(tmp_path, "add", "-A")
    assert check_secrets.main(["--root", str(tmp_path), "--staged"]) == 1
    shown = capsys.readouterr()
    assert "leak.py:1" in shown.err and "REVOKE" in shown.err and OPENAI not in shown.out + shown.err


@needs_git
def test_the_pre_commit_hook_really_blocks_a_commit_that_contains_a_key(tmp_path):
    git(tmp_path, "init", "-q")
    shutil.copytree(ROOT / ".githooks", tmp_path / ".githooks")
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "check_secrets.py", tmp_path / "scripts" / "check_secrets.py")
    git(tmp_path, "config", "core.hooksPath", ".githooks")

    (tmp_path / "ok.py").write_text("x = 1\n")
    git(tmp_path, "add", "ok.py")
    assert git(tmp_path, "commit", "-q", "-m", "clean", check=False).returncode == 0

    (tmp_path / "leak.py").write_text(f"KEY = '{ANTHROPIC}'\n")
    git(tmp_path, "add", "leak.py")
    blocked = git(tmp_path, "commit", "-q", "-m", "oops", check=False)
    assert blocked.returncode != 0 and "Nothing was committed" in blocked.stderr
    assert ANTHROPIC not in blocked.stdout + blocked.stderr
    assert git(tmp_path, "log", "--oneline").stdout.count("\n") == 1          # only the clean commit exists


# ------------------------------------------------------------------ the project's own safeguards

def test_the_hook_is_executable_and_calls_the_scanner_on_staged_changes():
    hook = ROOT / ".githooks" / "pre-commit"
    assert os.access(hook, os.X_OK) and hook.read_text().startswith("#!/usr/bin/env sh")
    assert "scripts/check_secrets.py --staged" in hook.read_text() and "core.hooksPath" in hook.read_text()


def test_the_project_itself_contains_no_secrets():
    assert check_secrets.scan(str(ROOT)) == []


@needs_git
def test_gitignore_excludes_key_files_but_keeps_the_template(tmp_path):
    git(tmp_path, "init", "-q")
    shutil.copy(ROOT / ".gitignore", tmp_path / ".gitignore")
    ignored = {name: git(tmp_path, "check-ignore", "-q", name, check=False).returncode == 0
               for name in (".env", ".env.local", ".env.production", "server.key", ".env.example", "README.md")}
    assert ignored == {".env": True, ".env.local": True, ".env.production": True, "server.key": True,
                       ".env.example": False, "README.md": False}


def test_the_env_template_contains_no_real_settings():
    text = (ROOT / ".env.example").read_text()
    assert envfile.parse(text) == {}                       # every setting line is commented out
    assert "--ai-setup" in text and check_secrets.scan_text(text) == []
