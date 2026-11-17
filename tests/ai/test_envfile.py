"""Tests for ai/envfile.py: private settings files, where they live, and the warnings that protect the key."""

import os
import stat
import subprocess

import pytest

from webrecon.ai import envfile

needs_git = pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
                               reason="git is not installed")
posix_only = pytest.mark.skipif(os.name == "nt", reason="file permissions work differently on Windows")


# ------------------------------------------------------------------ parsing

def test_parse_understands_comments_export_quotes_and_trailing_comments():
    text = ('# a comment\n\nWEBRECON_AI_KEY = "abc123"\nexport ANTHROPIC_API_KEY=\'def456\'\n'
            "WEBRECON_AI_MODEL=my-model   # which model\nWEBRECON_AI_URL=https://x.example/v1?a=b=c\n")
    assert envfile.parse(text) == {"WEBRECON_AI_KEY": "abc123", "ANTHROPIC_API_KEY": "def456",
                                   "WEBRECON_AI_MODEL": "my-model", "WEBRECON_AI_URL": "https://x.example/v1?a=b=c"}


def test_parse_handles_a_byte_order_mark_and_windows_line_endings():
    assert envfile.parse("\ufeffWEBRECON_AI_KEY=k1\r\nOPENAI_API_KEY=k2\r\n") == {"WEBRECON_AI_KEY": "k1", "OPENAI_API_KEY": "k2"}


def test_a_file_can_only_set_the_allowed_names():
    """A settings file must not be able to quietly change TLS, proxy or path behaviour."""
    text = "\n".join(f"{name}=evil" for name in ("PATH", "HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE",
                                                "SSL_CERT_FILE", "PYTHONPATH", "LD_PRELOAD", "HOME"))
    assert envfile.parse(text + "\nWEBRECON_AI_KEY=ok") == {"WEBRECON_AI_KEY": "ok"}


def test_nothing_is_expanded_and_junk_lines_are_ignored():
    text = "WEBRECON_AI_KEY=$HOME/secret\nnot a setting\n=novalue\nWEBRECON_AI_MODEL=\nWEBRECON_AI_URL\n"
    assert envfile.parse(text) == {"WEBRECON_AI_KEY": "$HOME/secret"}


def test_unreadable_or_oversized_files_are_treated_as_missing(tmp_path):
    assert envfile.read_file(str(tmp_path / "nope")) is None
    big = tmp_path / "big"
    big.write_text("WEBRECON_AI_KEY=x\n" + "# pad\n" * 20000)
    assert envfile.read_file(str(big)) is None
    binary = tmp_path / "bin"
    binary.write_bytes(b"\xff\xfe\x00bad")
    assert envfile.read_file(str(binary)) is None


# ------------------------------------------------------------------ where files are, and which one wins

def test_the_per_user_file_lives_in_the_config_folder_outside_any_project(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert envfile.user_file() == str(tmp_path / "cfg" / "webrecon" / "env")
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    assert envfile.user_file() == str(tmp_path / "h" / ".config" / "webrecon" / "env")
    monkeypatch.setattr(envfile.os, "name", "nt")
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    assert envfile.user_file() == str(tmp_path / "roaming" / "webrecon" / "env")


def test_explicit_file_beats_project_env_beats_user_file(monkeypatch, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(envfile, "PROJECT_ROOT", str(project))
    explicit = tmp_path / "explicit.env"
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(explicit))
    user = envfile.user_file()
    os.makedirs(os.path.dirname(user))
    open(user, "w").write("WEBRECON_AI_KEY=from-user\nWEBRECON_AI_MODEL=user-model\nWEBRECON_AI_URL=https://user.example\n")
    (project / ".env").write_text("WEBRECON_AI_KEY=from-project\nWEBRECON_AI_MODEL=project-model\n")
    explicit.write_text("WEBRECON_AI_KEY=from-explicit\n")
    loaded = envfile.load()
    assert loaded.values == {"WEBRECON_AI_KEY": "from-explicit", "WEBRECON_AI_MODEL": "project-model",
                             "WEBRECON_AI_URL": "https://user.example"}
    assert loaded.sources == {"WEBRECON_AI_KEY": str(explicit), "WEBRECON_AI_MODEL": str(project / ".env"),
                              "WEBRECON_AI_URL": user}


def test_with_no_files_nothing_is_loaded():
    assert envfile.load().values == {}


# ------------------------------------------------------------------ writing

@posix_only
def test_the_file_is_created_private_and_the_folder_is_made(tmp_path):
    path = tmp_path / "deep" / "er" / "env"
    envfile.write_value(str(path), "WEBRECON_AI_KEY", "sk-abc")
    assert path.read_text() == "WEBRECON_AI_KEY=sk-abc\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]


def test_writing_updates_in_place_and_keeps_everything_else(tmp_path):
    path = tmp_path / "env"
    path.write_text("# my settings\nWEBRECON_AI_MODEL=m\nexport WEBRECON_AI_KEY=old\nWEBRECON_AI_URL=https://x\n")
    envfile.write_value(str(path), "WEBRECON_AI_KEY", "new")
    envfile.write_value(str(path), "WEBRECON_AI_KEY", "newer")
    assert path.read_text() == "# my settings\nWEBRECON_AI_MODEL=m\nWEBRECON_AI_KEY=newer\nWEBRECON_AI_URL=https://x\n"
    envfile.write_value(str(path), "OPENAI_API_KEY", "other")
    assert path.read_text().endswith("OPENAI_API_KEY=other\n") and "WEBRECON_AI_KEY=newer" in path.read_text()


@pytest.mark.parametrize("name,value", [("WEBRECON_AI_KEY", ""), ("WEBRECON_AI_KEY", "a\nWEBRECON_AI_URL=https://evil"),
                                        ("WEBRECON_AI_KEY", "a\rb"), ("WEBRECON_AI_KEY", "a\x00b"), ("PATH", "/evil")])
def test_values_that_could_inject_other_settings_are_refused(tmp_path, name, value):
    with pytest.raises(ValueError):
        envfile.write_value(str(tmp_path / "env"), name, value)
    assert not (tmp_path / "env").exists()


@posix_only
def test_a_loose_existing_file_is_tightened_when_rewritten(tmp_path):
    path = tmp_path / "env"
    path.write_text("WEBRECON_AI_MODEL=m\n")
    os.chmod(path, 0o644)
    envfile.write_value(str(path), "WEBRECON_AI_KEY", "k")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ------------------------------------------------------------------ warnings

@posix_only
def test_a_file_other_users_can_read_is_reported(tmp_path):
    path = tmp_path / "env"
    path.write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(path, 0o644)
    assert any("chmod 600" in w for w in envfile.warnings_for(str(path)))
    os.chmod(path, 0o600)
    assert envfile.warnings_for(str(path)) == []


def git(repo, *args):
    return subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args], cwd=repo,
                          capture_output=True, text=True, check=True)


@needs_git
def test_a_key_file_inside_a_repo_that_does_not_ignore_it_is_flagged(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".env").write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(tmp_path / ".env", 0o600)
    (warning,) = envfile.warnings_for(str(tmp_path / ".env"))
    assert "NOT ignored" in warning and ".gitignore" in warning and "--ai-setup" in warning


@needs_git
def test_a_properly_ignored_key_file_gets_no_warning(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(tmp_path / ".env", 0o600)
    assert envfile.warnings_for(str(tmp_path / ".env")) == []


@needs_git
def test_a_key_file_that_git_already_tracks_triggers_the_strong_warning(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".env").write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(tmp_path / ".env", 0o600)
    git(tmp_path, "add", ".env")
    (warning,) = envfile.warnings_for(str(tmp_path / ".env"))
    assert "TRACKED" in warning and "revoke" in warning and "git rm --cached .env" in warning


@needs_git
def test_a_key_file_outside_any_repo_is_never_flagged_for_git(tmp_path):
    (tmp_path / "env").write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(tmp_path / "env", 0o600)
    assert envfile.warnings_for(str(tmp_path / "env")) == []


def test_missing_git_or_a_hanging_git_never_causes_a_crash(tmp_path, monkeypatch):
    (tmp_path / "env").write_text("WEBRECON_AI_KEY=k\n")
    os.chmod(tmp_path / "env", 0o600)

    def no_git(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(envfile.subprocess, "run", no_git)
    assert envfile.warnings_for(str(tmp_path / "env")) == []

    def hangs(*a, **k):
        raise subprocess.TimeoutExpired("git", 5)
    monkeypatch.setattr(envfile.subprocess, "run", hangs)
    assert envfile.warnings_for(str(tmp_path / "env")) == []
