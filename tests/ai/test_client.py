"""Tests for ai/client.py against a fake server: request shapes, errors, retries, and key handling."""

import pytest
import requests

from webrecon.ai.client import AiClient, AiConfig, AiError, AiFormatError

KEY = "sk-test-SECRET-KEY"


def client(fake, provider="anthropic", url=None, key=KEY, retries=2, timeout=5.0):
    base = url or (fake.url if provider == "anthropic" else fake.url + "/v1")
    return AiClient(AiConfig(provider, base, "test-model", key, timeout), retries=retries)


def test_anthropic_request_uses_the_messages_api(fake_ai):
    fake_ai.text = "hello"
    assert client(fake_ai).complete("be brief", "question") == "hello"
    (request,) = fake_ai.requests
    assert request["path"] == "/v1/messages"
    assert request["headers"]["x-api-key"] == KEY and request["headers"]["anthropic-version"] == "2023-06-01"
    body = request["body"]
    assert body["model"] == "test-model" and body["system"] == "be brief" and body["temperature"] == 0
    assert body["messages"] == [{"role": "user", "content": "question"}] and body["max_tokens"] > 0


def test_openai_style_request_uses_chat_completions_with_a_bearer_token(fake_ai):
    fake_ai.text = "hi"
    assert client(fake_ai, "openai").complete("be brief", "question") == "hi"
    (request,) = fake_ai.requests
    assert request["path"] == "/v1/chat/completions"
    assert request["headers"]["authorization"] == f"Bearer {KEY}" and "x-api-key" not in request["headers"]
    assert request["body"]["messages"] == [{"role": "system", "content": "be brief"},
                                           {"role": "user", "content": "question"}]


def test_a_local_server_without_a_key_gets_no_credentials_header(fake_ai):
    fake_ai.text = "ok"
    client(fake_ai, "openai", key=None).complete("s", "u")
    assert "authorization" not in fake_ai.requests[0]["headers"]
    client(fake_ai, "anthropic", key=None).complete("s", "u")
    assert "x-api-key" not in fake_ai.requests[1]["headers"]


def test_a_url_already_ending_in_v1_is_not_doubled(fake_ai):
    fake_ai.text = "ok"
    client(fake_ai, "anthropic", url=fake_ai.url + "/v1").complete("s", "u")
    client(fake_ai, "anthropic", url=fake_ai.url + "/").complete("s", "u")
    assert [r["path"] for r in fake_ai.requests] == ["/v1/messages", "/v1/messages"]


@pytest.mark.parametrize("status,words", [(401, "rejected the API key"), (403, "refused"), (404, "Not found"),
                                          (400, "rejected the request")])
def test_http_errors_become_plain_messages(fake_ai, status, words):
    fake_ai.status = status
    with pytest.raises(AiError) as stop:
        client(fake_ai).complete("s", "u")
    assert words in str(stop.value) and str(status) in str(stop.value)
    assert len(fake_ai.requests) == 1                    # these are not retried


def test_busy_servers_are_retried_and_then_succeed(fake_ai, monkeypatch):
    monkeypatch.setattr("webrecon.ai.client.time.sleep", lambda _: None)
    fake_ai.statuses, fake_ai.text = [429, 500], "finally"
    assert client(fake_ai).complete("s", "u") == "finally"
    assert len(fake_ai.requests) == 3


def test_a_server_that_stays_busy_gives_up_after_the_retries(fake_ai, monkeypatch):
    monkeypatch.setattr("webrecon.ai.client.time.sleep", lambda _: None)
    fake_ai.status = 429
    with pytest.raises(AiError, match="Rate limited"):
        client(fake_ai, retries=2).complete("s", "u")
    assert len(fake_ai.requests) == 3


def test_the_key_is_removed_from_anything_a_server_says(fake_ai):
    fake_ai.status, fake_ai.error_message = 401, f"Invalid key {KEY} for this account"
    with pytest.raises(AiError) as stop:
        client(fake_ai).complete("s", "u")
    assert KEY not in str(stop.value) and "***" in str(stop.value)


def test_a_slow_server_times_out_with_advice(fake_ai):
    fake_ai.delay = 1.0
    with pytest.raises(AiError, match="--ai-timeout"):
        client(fake_ai, timeout=0.2, retries=0).complete("s", "u")


def test_an_unreachable_server_is_explained():
    unreachable = AiClient(AiConfig("anthropic", "http://127.0.0.1:9", "m", KEY, 2.0), retries=0)
    with pytest.raises(AiError, match="Could not reach the AI server") as stop:
        unreachable.complete("s", "u")
    assert KEY not in str(stop.value)


def test_a_reply_in_the_wrong_shape_points_at_the_provider_setting(fake_ai):
    fake_ai.wrong_shape = True
    with pytest.raises(AiFormatError, match="provider"):
        client(fake_ai, "openai").complete("s", "u")


def test_a_reply_that_is_not_json_is_refused(fake_ai):
    fake_ai.raw_body = b"just some text"
    with pytest.raises(AiFormatError, match="not valid JSON"):
        client(fake_ai).complete("s", "u")


def test_a_huge_reply_is_refused(fake_ai):
    fake_ai.big = True
    with pytest.raises(AiError, match="unexpectedly large"):
        client(fake_ai).complete("s", "u")


def test_calls_are_counted(fake_ai):
    fake_ai.text = "x"
    c = client(fake_ai)
    c.complete("s", "u")
    c.complete("s", "u")
    assert c.calls == 2


def test_requests_really_go_over_the_network_stack():
    assert requests.post  # the client uses requests, so proxies and TLS settings behave as usual


def test_openai_models_that_reject_max_tokens_get_max_completion_tokens_instead(fake_ai):
    fake_ai.reject, fake_ai.text = ["max_tokens"], "ok"
    c = client(fake_ai, "openai")
    assert c.complete("s", "u") == "ok"
    first, second = (r["body"] for r in fake_ai.requests)
    assert "max_tokens" in first and "max_completion_tokens" in second and "max_tokens" not in second
    c.complete("s", "u")                                         # remembered: no failed attempt this time
    assert len(fake_ai.requests) == 3 and "max_completion_tokens" in fake_ai.requests[2]["body"]


def test_models_that_only_allow_the_default_temperature_are_asked_without_one(fake_ai):
    fake_ai.reject, fake_ai.text = ["temperature"], "ok"
    assert client(fake_ai, "openai").complete("s", "u") == "ok"
    assert "temperature" in fake_ai.requests[0]["body"] and "temperature" not in fake_ai.requests[1]["body"]


def test_both_unsupported_options_can_be_worked_around_in_turn(fake_ai):
    fake_ai.reject, fake_ai.text = ["max_tokens", "temperature"], "ok"
    assert client(fake_ai, "openai").complete("s", "u") == "ok"
    assert len(fake_ai.requests) == 3


def test_a_400_that_is_not_about_those_options_is_not_retried(fake_ai):
    fake_ai.status = 400
    with pytest.raises(AiError, match="rejected the request"):
        client(fake_ai, "openai").complete("s", "u")
    assert len(fake_ai.requests) == 1
