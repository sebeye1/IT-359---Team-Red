"""Tests for ai/prompt.py: what is sent to the AI server. Nothing about the scanned site may be in it."""

import json

from helpers import make_finding
from webrecon.ai import prompt
from webrecon.analysis import CHECK_CATALOG, Finding


def test_one_item_per_check_type_in_a_stable_order_using_the_generic_title():
    findings = [make_finding("WR-010", "Missing Content-Security-Policy header", "Medium"),
                make_finding("WR-001", "Site served over unencrypted HTTP", "Medium"),
                make_finding("WR-010", "Missing Content-Security-Policy header", "Medium")]
    items = prompt.items_for(findings)
    assert [i["check_id"] for i in items] == ["WR-001", "WR-010"]
    assert items[1] == {"check_id": "WR-010", "title": "Missing Content-Security-Policy header", "category": "c",
                        "typical_severity": "Medium"}


def test_nothing_about_the_target_is_ever_included():
    secrets = ["http://secret-host.internal/admin", "SECRET123", "sessionid=a81b2c", "Summer2026!"]
    findings = [
        Finding("WR-064", "Directory listing enabled at /private-backups/", "Medium", "Information Disclosure",
                "desc mentioning secret-host.internal", f"{secrets[0]} returned an 'Index of' page", "fix"),
        Finding("WR-030", "Cookie sessionid is missing flags", "Low", "Cookie Security",
                "d", f"Set-Cookie: {secrets[2]}; token={secrets[1]}", "r"),
        Finding("WR-061", "Environment file exposed", "High", "Sensitive File Exposure", "d", f"DB_PASSWORD={secrets[3]}", "r"),
    ]
    sent = prompt.user_message(prompt.items_for(findings))
    for secret in secrets + ["private-backups", "sessionid", "secret-host"]:
        assert secret not in sent, secret
    assert "Directory listing enabled" in sent        # the generic catalog title is what is sent instead


def test_the_message_is_json_with_only_the_four_expected_fields():
    sent = json.loads(prompt.user_message(prompt.items_for([make_finding("WR-001")])))
    assert set(sent) == {"checks"}
    assert set(sent["checks"][0]) == {"check_id", "title", "category", "typical_severity"}


def test_an_unknown_check_id_falls_back_to_its_own_title_and_severity():
    (item,) = prompt.items_for([make_finding("WR-999", "A new check", "High")])
    assert item["title"] == "A new check" and item["typical_severity"] == "High"


def test_every_catalog_entry_can_be_described():
    findings = [make_finding(cid) for cid, _, _ in CHECK_CATALOG]
    assert len(prompt.items_for(findings)) == len(CHECK_CATALOG)


def test_the_hash_changes_whenever_the_question_changes():
    item = {"check_id": "WR-001", "title": "t", "category": "c", "typical_severity": "Low"}
    assert prompt.item_hash(item) == prompt.item_hash(dict(reversed(list(item.items()))))
    assert prompt.item_hash(item) != prompt.item_hash({**item, "title": "other"})


def test_the_instructions_ask_for_json_a_31_vector_real_ids_and_no_calculation():
    text = prompt.SYSTEM
    for phrase in ("CVSS:3.1/", "JSON object and nothing else", "real technique IDs only", "Do not calculate a score",
                   "leave it out"):
        assert phrase in text
