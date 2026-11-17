"""Keeps the package structure honest: imports may only point in the directions docs/ARCHITECTURE.md allows."""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "webrecon"

# package -> the other webrecon packages it may import
ALLOWED = {
    "scanning": set(),
    "analysis": {"scanning"},
    "ai": {"analysis", "scanning"},
    "reporting": {"analysis", "scanning"},
    "results": {"analysis", "reporting", "scanning"},
    "interactive": {"reporting", "results", "bootstrap"},
    "lab": set(),
    "cli": {"ai", "analysis", "reporting", "results", "scanning", "interactive", "lab"},
}
ANYWHERE = {"errors"}  # tiny shared modules (webrecon/errors.py)


def imported_packages(path: Path) -> set:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        for name in names:
            parts = name.split(".")
            if parts[0] == "webrecon" and len(parts) > 1 and not parts[1].startswith("__"):
                found.add(parts[1])
    return found


@pytest.mark.parametrize("package", sorted(ALLOWED))
def test_packages_only_import_what_the_architecture_allows(package):
    problems = []
    for path in sorted((PACKAGE / package).rglob("*.py")):
        for target in imported_packages(path) - {package} - ANYWHERE - ALLOWED[package]:
            problems.append(f"{path.relative_to(PACKAGE)} imports webrecon.{target}")
    assert not problems, "\n".join(problems)


def test_every_package_is_covered_by_the_rules():
    folders = {p.name for p in PACKAGE.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    assert folders == set(ALLOWED)


def root_names(path: Path) -> set:
    """The top-level module names a file imports."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_the_package_root_and_bootstrap_use_only_the_standard_library():
    """bootstrap runs before requests and beautifulsoup4 are known to be installed, so it (and the package
    __init__ it is imported through) must not need them, or anything else in webrecon."""
    assert root_names(PACKAGE / "__init__.py") == set()
    assert root_names(PACKAGE / "bootstrap.py") <= {"__future__", "importlib", "os", "subprocess", "sys"}
