#!/usr/bin/env python3
"""
check_secrets.py - Stop API keys and other secrets from reaching git (and so GitHub).

    python3 scripts/check_secrets.py            scan the project's files: everything git tracks or would add,
                                                skipping anything .gitignore excludes (so a private .env is fine)
    python3 scripts/check_secrets.py --staged   scan exactly what is staged for the next commit
                                                (this is what the pre-commit hook in .githooks runs)

Exit status 0 means nothing suspicious was found, 1 means something was. A secret is never printed: a finding shows the
file, the line number, the kind of secret and its length. To allow a deliberate example, put `secret-scan: allow` on
the same line.

It looks for well-known key shapes (Anthropic and OpenAI-style keys, GitHub tokens, AWS access key IDs, private key
blocks) and for long values assigned to names like api_key, secret, token or password. It cannot catch everything, so
treat it as a safety net, not a guarantee, and turn on GitHub's own secret scanning and push protection as well.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

RULES = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), False),
    ("OpenAI-style API key", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"), False),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), False),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), False),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), False),
    ("Secret assigned in code", re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[=:]\s*['"]([A-Za-z0-9_\-/+=]{24,})['"]"""), True),
]
PLACEHOLDER = re.compile(r"(?i)your|example|placeholder|changeme|xxx|dummy|sample|fake|<|\.\.\.")
ALLOW_MARKER = "secret-scan: allow"
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "reports", "node_modules", "build", "dist"}
MAX_BYTES = 1_000_000


def git(args: list[str], root: str, text: bool = True):
    try:
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=text, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def project_files(root: str) -> list[str]:
    """Files git tracks or would add (so ignored files such as .env are left out); every file if this is not a repo."""
    result = git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    if result is not None and result.returncode == 0:
        return sorted(set(p for p in result.stdout.split("\0") if p))
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        found += [os.path.relpath(os.path.join(folder, f), root) for f in files]
    return sorted(found)


def staged_files(root: str) -> list[str]:
    result = git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], root)
    return sorted(p for p in (result.stdout.split("\0") if result and result.returncode == 0 else []) if p)


def read_text(root: str, path: str, staged: bool) -> str | None:
    """The file's text, or None for binary or very large files."""
    if staged:
        result = git(["show", f":{path}"], root, text=False)
        data = result.stdout if result is not None and result.returncode == 0 else b""
    else:
        try:
            with open(os.path.join(root, path), "rb") as fh:
                data = fh.read(MAX_BYTES + 1)
        except OSError:
            return None
    if len(data) > MAX_BYTES or b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def scan_text(text: str) -> list[tuple[int, str, int]]:
    """(line number, kind of secret, length) for every suspicious value. The value itself is never returned."""
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARKER in line:
            continue
        claimed = []  # stretches of this line already reported, so one secret is reported once, by the most specific rule
        for kind, pattern, check_placeholder in RULES:
            for match in pattern.finditer(line):
                value = match.group(1) if pattern.groups else match.group(0)
                if check_placeholder and PLACEHOLDER.search(value):
                    continue
                if any(match.start() < end and start < match.end() for start, end in claimed):
                    continue
                claimed.append((match.start(), match.end()))
                findings.append((number, kind, len(value)))
    return findings


def scan(root: str, staged: bool = False) -> list[tuple[str, int, str, int]]:
    problems = []
    for path in (staged_files(root) if staged else project_files(root)):
        text = read_text(root, path, staged)
        if text is not None:
            problems += [(path, n, kind, size) for n, kind, size in scan_text(text)]
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fail if API keys or other secrets are in the project's files.")
    parser.add_argument("--staged", action="store_true", help="scan what is staged for the next commit")
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        help="the project folder (default: the folder above scripts/)")
    args = parser.parse_args(argv)
    problems = scan(args.root, args.staged)
    if not problems:
        print("[+] No secrets found" + (" in the staged changes." if args.staged else "."))
        return 0
    print("[-] Something that looks like a secret was found. Nothing was committed.\n", file=sys.stderr)
    for path, number, kind, size in problems:
        print(f"    {path}:{number}: {kind} ({size} characters)", file=sys.stderr)
    print("\nIf it is a real key: remove it from the file, and REVOKE it with the provider (a key that has been\n"
          "typed into a file you might share should be treated as exposed). Keep keys outside the project with\n"
          "`python3 main.py --ai-setup`. If it is a deliberate example, add `secret-scan: allow` to that line.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
