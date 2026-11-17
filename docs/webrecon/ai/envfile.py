"""
envfile.py - Keeping the AI settings (above all the API key) in a private file instead of the shell or the code.

Files are read in this order, and a real environment variable always beats all of them:

    1. the file named by WEBRECON_ENV_FILE (if set)
    2. .env in the project folder                  (convenient, but it sits next to your code: it must stay git-ignored)
    3. ~/.config/webrecon/env                       (Windows: %APPDATA%\\webrecon\\env), outside any repository, so it
                                                     cannot be committed by accident. `--ai-setup` writes this one.

Only a short list of names is ever read from a file. A file cannot set PATH, HTTP_PROXY, REQUESTS_CA_BUNDLE or anything
else that could quietly change how WebRecon behaves. Nothing here ever prints or logs a value.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field

ALLOWED = ("WEBRECON_AI_KEY", "WEBRECON_AI_URL", "WEBRECON_AI_MODEL", "WEBRECON_AI_PROVIDER",
           "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "WEBRECON_CACHE_DIR")
MAX_BYTES = 64_000
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def user_file() -> str:
    """The per-user settings file, in the user's own config folder (never inside a project)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "webrecon", "env")


def setup_path() -> str:
    """Where --ai-setup saves the key: WEBRECON_ENV_FILE if set, otherwise the per-user file."""
    return os.environ.get("WEBRECON_ENV_FILE") or user_file()


def candidate_files() -> list[str]:
    """Settings files in priority order, highest first."""
    files = []
    if os.environ.get("WEBRECON_ENV_FILE"):
        files.append(os.environ["WEBRECON_ENV_FILE"])
    files += [os.path.join(PROJECT_ROOT, ".env"), user_file()]
    return files


def parse(text: str) -> dict:
    """NAME=value lines for the allowed names. Understands comments, `export`, and quotes; never expands anything."""
    values = {}
    for raw in text.lstrip("\ufeff").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or name not in ALLOWED:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if value:
            values[name] = value
    return values


def read_file(path: str) -> dict | None:
    """The settings in one file, or None if it is missing, unreadable or suspiciously large."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(MAX_BYTES + 1)
    except (OSError, UnicodeDecodeError):
        return None
    return None if len(text) > MAX_BYTES else parse(text)


@dataclass
class Loaded:
    values: dict = field(default_factory=dict)    # name -> value, from the highest-priority file that sets it
    sources: dict = field(default_factory=dict)   # name -> the file that value came from


def load() -> Loaded:
    loaded = Loaded()
    for path in reversed(candidate_files()):      # lowest priority first, so higher ones overwrite
        for name, value in (read_file(path) or {}).items():
            loaded.values[name], loaded.sources[name] = value, path
    return loaded


# ------------------------------------------------------------------ writing

def write_value(path: str, name: str, value: str) -> None:
    """Set NAME=value in the file, keeping its other lines. Created with permissions only the owner has."""
    if name not in ALLOWED:
        raise ValueError(f"{name} is not a setting WebRecon reads from a file")
    if not value or any(c in value for c in "\r\n\x00"):
        raise ValueError("The value must be one line of text")
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        stripped = stripped[7:].lstrip() if stripped.startswith("export ") else stripped
        if stripped.partition("=")[0].strip() == name:
            lines[i] = f"{name}={value}"
            break
    else:
        lines.append(f"{name}={value}")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    temporary = path + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, 0o600)


# ------------------------------------------------------------------ warnings about a key file

def _git(args: list[str], folder: str):
    try:
        return subprocess.run(["git", *args], cwd=folder, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None   # no git, or it hung: say nothing rather than guess


def git_warnings(path: str) -> list[str]:
    """If the file sits inside a git repository, say so when it is tracked, or when it is not ignored."""
    folder, name = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    inside = _git(["rev-parse", "--is-inside-work-tree"], folder)
    if inside is None or inside.returncode != 0:
        return []
    tracked = _git(["ls-files", "--error-unmatch", name], folder)
    if tracked is not None and tracked.returncode == 0:
        return [f"{path} is TRACKED by git, so your API key may already be in your repository's history. Run "
                f"`git rm --cached {name}`, then revoke this key with your AI provider and create a new one. "
                "Deleting it from a later commit does not remove it from the history."]
    ignored = _git(["check-ignore", "-q", name], folder)
    if ignored is not None and ignored.returncode == 1:
        return [f"{path} is inside a git repository and is NOT ignored by it. Add it to .gitignore before you commit, "
                "or keep the key outside the repository with: python3 main.py --ai-setup"]
    return []


def warnings_for(path: str) -> list[str]:
    """Plain-English problems with a file that holds a key: readable by others, or at risk of being committed."""
    problems = []
    if os.name != "nt":
        try:
            if os.stat(path).st_mode & 0o077:
                problems.append(f"{path} can be read by other users of this computer. Run: chmod 600 {path}")
        except OSError:
            pass
    return problems + git_warnings(path)
