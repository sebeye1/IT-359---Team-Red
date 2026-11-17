"""Tests for ai/enrich.py: asking, checking the answers, caching, and attaching them to findings."""

import json

import pytest

from helpers import make_finding
from webrecon.ai import enrich, prompt, storage
from webrecon.ai.client import AiClient, AiConfig, AiFormatError
from webrecon.analysis import CHECK_CATALOG

INDEX = {"version": "20.1", "techniques": {
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
    "T1040": {"name": "Network Sniffing", "tactics": ["credential-access", "discovery"]},
    "T1557": {"name": "Adversary-in-the-Middle", "tactics": ["credential-access", "collection"]},
    "T1592": {"name": "Gather Victim Host Information", "tactics": ["reconnaissance"]}}}


@pytest.fixture
def ai(fake_ai):
    return AiClient(AiConfig("anthropic", fake_ai.url, "test-model", "sk-test", 5.0), retries=0)


def findings_for(*ids):
    return [make_finding(i) for i in ids]


def test_findings_get_a_locally_calculated_score_and_a_checked_technique(ai, fake_ai):
    found = findings_for("WR-001", "WR-010", "WR-010")
    result = enrich.enrich_findings(found, ai, index=INDEX)
    assert (result.enriched, result.asked, result.from_cache, result.problems) == (3, 2, 0, [])
    assert len(fake_ai.requests) == 1 and fake_ai.asked == [["WR-001", "WR-010"]]        # one request, check types once
    e = found[0].enrichment
    assert e["cvss"] == {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 3.7, "rating": "Low"}
    assert e["attack"] == [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"],
                            "url": "https://attack.mitre.org/techniques/T1190/", "verified": True, "reason": "Reachable service."}]
    assert e["estimated"] is True and e["source"] == "ai" and e["model"] == "test-model"
    assert found[1].enrichment == found[2].enrichment and found[1].enrichment is not found[2].enrichment


def test_a_score_the_ai_states_is_ignored_because_the_vector_decides(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"cvss_score": 9.9, "score": 10, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    (f,) = findings_for("WR-001")
    enrich.enrich_findings([f], ai, index=INDEX)
    assert f.enrichment["cvss"]["score"] == 9.8                      # calculated from the vector, not copied


def test_an_invalid_vector_is_dropped_but_the_techniques_are_kept(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"cvss_vector": "CVSS:3.1/AV:N/AC:L"}
    (f,) = findings_for("WR-001")
    result = enrich.enrich_findings([f], ai, index=INDEX)
    assert f.enrichment["cvss"] is None and f.enrichment["attack"][0]["id"] == "T1190" and result.enriched == 1


def test_an_answer_with_nothing_usable_is_reported_and_attaches_nothing(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"cvss_vector": "nonsense", "attack": [{"id": "T9999999"}]}
    (f,) = findings_for("WR-001")
    result = enrich.enrich_findings([f], ai, index=INDEX)
    assert f.enrichment == {} and result.enriched == 0
    assert any("WR-001" in p and "no usable" in p for p in result.problems)


def test_invented_technique_ids_are_dropped_when_mitres_list_is_available(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"attack": [{"id": "T9999", "reason": "invented"}, {"id": "T1040", "reason": "real"},
                                                {"id": "T1190.999", "reason": "invented sub-technique"}]}
    (f,) = findings_for("WR-001")
    result = enrich.enrich_findings([f], ai, index=INDEX)
    assert [t["id"] for t in f.enrichment["attack"]] == ["T1040"]
    assert f.enrichment["attack"][0]["name"] == "Network Sniffing"               # the name comes from MITRE's list
    assert any("T9999" in p and "T1190.999" in p for p in result.problems)


def test_without_mitres_list_ids_are_only_format_checked_and_marked_unverified(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"attack": [{"id": "T1040", "reason": "r"}, {"id": "banana"}, {"id": "t1190"}]}
    (f,) = findings_for("WR-001")
    enrich.enrich_findings([f], ai, index=None)
    (t,) = f.enrichment["attack"]
    assert t["id"] == "T1040" and t["verified"] is False and t["name"] == "" and t["tactics"] == []


def test_at_most_three_distinct_techniques_and_malformed_entries_are_skipped(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"attack": [{"id": "T1040"}, {"id": "T1040"}, "T1190", {"id": 5}, None,
                                                {"id": "T1190"}, {"id": "T1557"}, {"id": "T1592"}]}
    (f,) = findings_for("WR-001")
    enrich.enrich_findings([f], ai, index=INDEX)
    assert [t["id"] for t in f.enrichment["attack"]] == ["T1040", "T1190", "T1557"]


def test_text_from_the_ai_is_cleaned_and_limited(ai, fake_ai):
    fake_ai.results_for["WR-001"] = {"attack": [{"id": "T1040", "reason": "line one\nline\ttwo\x07" + "x" * 500}],
                                     "rationale": "ok\r\n" + "y" * 500}
    (f,) = findings_for("WR-001")
    enrich.enrich_findings([f], ai, index=INDEX)
    reason, rationale = f.enrichment["attack"][0]["reason"], f.enrichment["rationale"]
    assert "\n" not in reason and "\t" not in reason and "\x07" not in reason and len(reason) <= 160
    assert "\r" not in rationale and len(rationale) <= 240


def test_a_check_type_the_ai_skipped_is_reported_and_the_others_still_work(ai, fake_ai):
    fake_ai.text = json.dumps({"results": [{"check_id": "WR-001", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}]})
    found = findings_for("WR-001", "WR-010")
    result = enrich.enrich_findings(found, ai, index=INDEX)
    assert found[0].enrichment and not found[1].enrichment
    assert any("WR-010" in p for p in result.problems)


# ------------------------------------------------------------------ caching

def test_a_second_run_is_answered_from_the_cache_without_asking(ai, fake_ai):
    enrich.enrich_findings(findings_for("WR-001", "WR-010"), ai, index=INDEX)
    again = findings_for("WR-001", "WR-010", "WR-001")
    result = enrich.enrich_findings(again, ai, index=INDEX)
    assert len(fake_ai.requests) == 1                                  # nothing new was sent
    assert (result.asked, result.from_cache, result.enriched) == (0, 2, 3)
    assert again[0].enrichment["cvss"]["score"] == 3.7


def test_only_the_new_check_types_are_asked_about(ai, fake_ai):
    enrich.enrich_findings(findings_for("WR-001"), ai, index=INDEX)
    enrich.enrich_findings(findings_for("WR-001", "WR-013"), ai, index=INDEX)
    assert fake_ai.asked == [["WR-001"], ["WR-013"]]


def test_a_different_model_or_prompt_version_does_not_reuse_old_answers(fake_ai, monkeypatch):
    first = AiClient(AiConfig("anthropic", fake_ai.url, "model-a", "k", 5.0), retries=0)
    second = AiClient(AiConfig("anthropic", fake_ai.url, "model-b", "k", 5.0), retries=0)
    enrich.enrich_findings(findings_for("WR-001"), first, index=INDEX)
    enrich.enrich_findings(findings_for("WR-001"), second, index=INDEX)
    assert len(fake_ai.requests) == 2
    monkeypatch.setattr(prompt, "PROMPT_VERSION", prompt.PROMPT_VERSION + 1)
    enrich.enrich_findings(findings_for("WR-001"), second, index=INDEX)
    assert len(fake_ai.requests) == 3


def test_a_damaged_cache_file_is_ignored(ai, fake_ai):
    storage.write_json(enrich.CACHE_FILE, {"anything": 1})
    with open(f"{storage.cache_dir()}/{enrich.CACHE_FILE}", "w") as fh:
        fh.write("{broken")
    (f,) = findings_for("WR-001")
    assert enrich.enrich_findings([f], ai, index=INDEX).enriched == 1


def test_failed_answers_are_not_cached(ai, fake_ai):
    fake_ai.text = "no json here at all"
    enrich.enrich_findings(findings_for("WR-001"), ai, index=INDEX)
    assert storage.read_json(enrich.CACHE_FILE) is None


# ------------------------------------------------------------------ requests, chunks, failures

def test_many_check_types_are_split_into_requests_of_ten(ai, fake_ai):
    ids = [cid for cid, _, _ in CHECK_CATALOG][:25]
    found = findings_for(*ids)
    result = enrich.enrich_findings(found, ai, index=INDEX)
    assert [len(a) for a in fake_ai.asked] == [10, 10, 5] and result.enriched == 25 and result.problems == []


def test_no_findings_means_no_request(ai, fake_ai):
    assert enrich.enrich_findings([], ai, index=INDEX).enriched == 0 and fake_ai.requests == []


def test_a_garbled_answer_is_retried_once_with_a_reminder(ai, fake_ai):
    fake_ai.texts = ["Sure! Here you go: not json", None]
    fake_ai.texts[1] = fake_ai.good_text([{"check_id": "WR-001"}])
    (f,) = findings_for("WR-001")
    result = enrich.enrich_findings([f], ai, index=INDEX)
    assert result.enriched == 1 and len(fake_ai.requests) == 2
    assert "not valid JSON" in fake_ai.requests[1]["body"]["messages"][-1]["content"]


def test_one_bad_chunk_does_not_lose_the_others(ai, fake_ai):
    ids = [cid for cid, _, _ in CHECK_CATALOG][:12]
    fake_ai.texts = [fake_ai.good_text([{"check_id": i} for i in ids[:10]]), "garbage", "still garbage"]
    found = findings_for(*ids)
    result = enrich.enrich_findings(found, ai, index=INDEX)
    assert result.enriched == 10 and all(f.enrichment for f in found[:10]) and not any(f.enrichment for f in found[10:])
    assert any(ids[10] in p and ids[11] in p for p in result.problems)


def test_a_key_or_quota_problem_stops_further_requests_and_never_raises(ai, fake_ai):
    fake_ai.status = 401
    ids = [cid for cid, _, _ in CHECK_CATALOG][:25]
    found = findings_for(*ids)
    result = enrich.enrich_findings(found, ai, index=INDEX)
    assert len(fake_ai.requests) == 1 and result.enriched == 0
    assert any("rejected the API key" in p for p in result.problems) and not any(f.enrichment for f in found)


@pytest.mark.parametrize("text,ok", [
    ('{"results": [{"check_id": "WR-001"}]}', True),
    ('```json\n{"results": [{"check_id": "WR-001"}]}\n```', True),
    ('Here is the answer:\n{"results": [{"check_id": "WR-001"}]}\nHope this helps!', True),
    ('{"results": []}', True),
    ('{"results": "nope"}', False), ('[1, 2]', False), ('{"other": 1}', False), ('no braces', False), ('{broken', False),
])
def test_parse_answer_accepts_fences_and_chatter_and_rejects_the_wrong_shape(text, ok):
    if ok:
        assert isinstance(enrich.parse_answer(text), dict)
    else:
        with pytest.raises(AiFormatError):
            enrich.parse_answer(text)


def test_parse_answer_skips_entries_that_are_not_objects_with_a_check_id():
    answer = enrich.parse_answer('{"results": [{"check_id": "WR-001"}, "x", {"no_id": 1}, {"check_id": 5}, null]}')
    assert list(answer) == ["WR-001"]
