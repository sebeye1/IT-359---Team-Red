"""Tests for ai/attack.py: technique IDs, links, parsing MITRE's data, and the --attack-update download."""

import json
import os

import pytest

from webrecon.ai import attack, storage
from webrecon.errors import UserError


def technique(external_id, name, phases=("initial-access",), **extra):
    return {"type": "attack-pattern", "name": name,
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"},
                                    {"source_name": "mitre-attack", "external_id": external_id}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases], **extra}


BUNDLE = {"type": "bundle", "objects": [
    {"type": "x-mitre-collection", "x_mitre_version": "20.1", "modified": "2026-11-05"},
    technique("T1190", "Exploit Public-Facing Application"),
    technique("T1059.003", "Windows Command Shell", phases=("execution",)),
    technique("T1040", "Network Sniffing", phases=("credential-access", "discovery")),
    technique("T9000", "Old and revoked", revoked=True),
    technique("T9001", "Deprecated", x_mitre_deprecated=True),
    {"type": "attack-pattern", "name": "No MITRE id", "external_references": [{"source_name": "other", "external_id": "T1"}]},
    {"type": "malware", "name": "Not a technique"},
]}


@pytest.mark.parametrize("value,ok", [("T1190", True), ("T1059.003", True), ("t1190", False), ("T119", False),
                                      ("T1190.1", False), ("T1190/x", False), ("T1190 ", False), (None, False), (1190, False)])
def test_technique_id_format(value, ok):
    assert attack.is_technique_id(value) is ok


def test_technique_links_point_at_attack_mitre_org():
    assert attack.technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"
    assert attack.technique_url("T1059.003") == "https://attack.mitre.org/techniques/T1059/003/"


def test_parse_bundle_keeps_only_current_techniques_with_names_and_tactics():
    index = attack.parse_bundle(BUNDLE)
    assert index["version"] == "20.1" and index["modified"] == "2026-11-05"
    assert sorted(index["techniques"]) == ["T1040", "T1059.003", "T1190"]            # revoked, deprecated, other: gone
    assert index["techniques"]["T1190"] == {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]}
    assert index["techniques"]["T1040"]["tactics"] == ["credential-access", "discovery"]


class FakeDownload:
    def __init__(self, payload, status_ok=True):
        self.payload, self.status_ok = payload, status_ok

    def raise_for_status(self):
        if not self.status_ok:
            raise attack.requests.HTTPError("404")

    def iter_content(self, chunk_size):
        for start in range(0, len(self.payload), 64):
            yield self.payload[start:start + 64]


def test_update_downloads_parses_saves_and_load_index_reads_it_back(monkeypatch):
    monkeypatch.setattr(attack.requests, "get", lambda *a, **k: FakeDownload(json.dumps(BUNDLE).encode()))
    assert attack.load_index() is None                                                # nothing yet
    index = attack.update_index()
    assert len(index["techniques"]) == 3
    assert attack.load_index()["techniques"]["T1190"]["name"] == "Exploit Public-Facing Application"


@pytest.mark.parametrize("download,message", [
    (lambda *a, **k: (_ for _ in ()).throw(attack.requests.ConnectionError("down")), "Could not download"),
    (lambda *a, **k: FakeDownload(b"", status_ok=False), "Could not download"),
    (lambda *a, **k: FakeDownload(b"<html>not json"), "not valid JSON"),
    (lambda *a, **k: FakeDownload(json.dumps({"objects": []}).encode()), "no techniques"),
])
def test_update_failures_are_plain_messages_and_save_nothing(monkeypatch, download, message):
    monkeypatch.setattr(attack.requests, "get", download)
    with pytest.raises(UserError, match=message):
        attack.update_index()
    assert attack.load_index() is None


def test_update_stops_a_download_that_is_too_large(monkeypatch):
    monkeypatch.setattr(attack, "MAX_DOWNLOAD_BYTES", 100)
    monkeypatch.setattr(attack.requests, "get", lambda *a, **k: FakeDownload(b"x" * 1000))
    with pytest.raises(UserError, match="larger than expected"):
        attack.update_index()


def test_a_damaged_saved_index_is_treated_as_missing():
    storage.write_json(attack.INDEX_FILE, {"techniques": "oops"})
    assert attack.load_index() is None
    with open(os.path.join(storage.cache_dir(), attack.INDEX_FILE), "w") as fh:
        fh.write("{not json")
    assert attack.load_index() is None
