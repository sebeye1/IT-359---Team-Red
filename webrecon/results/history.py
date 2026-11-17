"""
history.py - Find earlier scans saved in the reports folder.

Every scan saves its JSON next to its HTML report, so "compare my last two scans", "only show what is
new since last time" and the "since your previous scan" line need no file names.
"""

from __future__ import annotations

import glob
import os
from urllib.parse import urlparse

from webrecon.results import compare
from webrecon.results.compare import CompareError, load_scan
from webrecon.scanning import normalize_target


def _site(target: str) -> str:
    return urlparse(normalize_target(target)[0]).netloc.lower()


def _newest_first(output_dir: str) -> list[str]:
    """JSON paths, newest first. Only file times are read here, so large folders stay fast."""
    stamped = []
    for path in glob.glob(os.path.join(output_dir, "*.json")):
        try:
            stamped.append((os.path.getmtime(path), path))
        except OSError:
            continue  # deleted while we were looking
    return [path for _, path in sorted(stamped, reverse=True)]


def _entry(path: str) -> dict | None:
    """The saved result at path, or None if it is not a WebRecon result."""
    try:
        data = load_scan(path)
    except CompareError:
        return None
    scan = data.get("scan") or {}
    return {"path": path, "data": data, "target": scan.get("target", ""), "started": scan.get("started", "")}


def _same_site(entry: dict, site: str) -> bool:
    return bool(entry["target"]) and _site(entry["target"]) == site


def saved_scans(output_dir: str) -> list[dict]:
    """Every WebRecon result in the folder, newest first. Other JSON files are ignored."""
    return [e for e in map(_entry, _newest_first(output_dir)) if e]


def previous_scan(target: str, output_dir: str) -> dict | None:
    """The most recent saved scan of the same site, or None. Stops reading at the first match."""
    site = _site(target)
    for path in _newest_first(output_dir):
        entry = _entry(path)
        if entry and _same_site(entry, site):
            return entry
    return None


def last_two_scans(output_dir: str) -> tuple[dict, dict] | None:
    """(older, newer): the newest saved scan and the one before it for the same site."""
    newest, site = None, None
    for path in _newest_first(output_dir):
        entry = _entry(path)
        if entry is None:
            continue
        if newest is None:
            newest, site = entry, (_site(entry["target"]) if entry["target"] else None)
        elif site is not None and _same_site(entry, site):
            return entry, newest
    return None


def trend(previous: dict, findings: list[dict]) -> dict:
    """How this scan's findings compare with a previous saved scan of the same site."""
    d = compare.diff(previous["data"], {"findings": findings})
    return {"since": previous["started"] or "time unknown", "fixed": len(d["fixed"]), "new": len(d["new"]),
            "still_open": len(d["unchanged"]) + len(d["changed"])}


def format_scans(entries: list[dict], output_dir: str) -> str:
    """A readable table of saved scans (newest first) with the commands that use them."""
    if not entries:
        return (f"\nNo saved scans in {output_dir}/ yet. Scan a site and its results are saved there "
                "automatically.")
    width = max(len(e["target"]) for e in entries)
    lines = [f"\nSaved scans in {output_dir}/ (newest first):\n"]
    for e in entries:
        counts = (e["data"].get("summary") or {})
        detail = ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no findings"
        total = len(e["data"]["findings"])
        lines.append(f"  {e['started'] or 'unknown time':<19}  {e['target']:<{width}}  "
                     f"{total:>3} finding(s)  ({detail})")
        lines.append(f"  {'':<19}  {e['path']}")
    lines += ["", "Compare the last two scans of a site:  python main.py --compare",
              "Compare two specific scans:           python main.py --compare OLD.json NEW.json",
              "Only show what is new since a scan:   python main.py <site> --baseline last"]
    return "\n".join(lines)
