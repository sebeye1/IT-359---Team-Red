"""Tests for ai/config.py: choosing the server, and refusing unsafe setups."""

import pytest

from webrecon.ai.client import AiConfig
from webrecon.ai.config import resolve_config
from webrecon.errors import UserError

NO_PROMPT = lambda: None  # noqa: E731  (a terminal that cannot be asked for a key)


def resolve(env=None, ask_key=NO_PROMPT, **settings):
    return resolve_config(env=env or {}, ask_key=ask_key, **settings)


def test_defaults_to_anthropic_with_a_small_model_and_the_key_from_the_environment():
    cfg = resolve({"WEBRECON_AI_KEY": "sk-secret"})
    assert (cfg.provider, cfg.url, cfg.model, cfg.key) == ("anthropic", "https://api.anthropic.com", "claude-haiku-5-5", "sk-secret")
    assert cfg.timeout == 60.0


def test_the_providers_own_key_variable_is_used_when_webrecon_ai_key_is_not_set():
    assert resolve({"ANTHROPIC_API_KEY": "a"}).key == "a"
    assert resolve({"OPENAI_API_KEY": "o"}, provider="openai", model="m").key == "o"
    assert resolve({"WEBRECON_AI_KEY": "w", "ANTHROPIC_API_KEY": "a"}).key == "w"      # the specific one wins


def test_options_beat_environment_variables():
    env = {"WEBRECON_AI_KEY": "k", "WEBRECON_AI_MODEL": "from-env", "WEBRECON_AI_URL": "https://env.example/v1",
           "WEBRECON_AI_PROVIDER": "openai"}
    assert resolve(env).model == "from-env" and resolve(env).url == "https://env.example/v1"
    cfg = resolve(env, model="from-option", url="https://option.example", provider="anthropic")
    assert (cfg.model, cfg.url, cfg.provider) == ("from-option", "https://option.example", "anthropic")


def test_a_url_that_is_not_anthropic_means_an_openai_style_server():
    cfg = resolve({"WEBRECON_AI_KEY": "k"}, url="https://llm.example.com/v1", model="m")
    assert cfg.provider == "openai"
    assert resolve({"WEBRECON_AI_KEY": "k"}, url="https://api.anthropic.com").provider == "anthropic"


def test_openai_style_servers_need_a_model_name():
    with pytest.raises(UserError, match="--ai-model"):
        resolve({"WEBRECON_AI_KEY": "k"}, provider="openai")


def test_a_local_server_needs_neither_a_key_nor_https():
    cfg = resolve(url="http://localhost:11434/v1", model="llama3")
    assert cfg.key is None and cfg.provider == "openai"
    assert resolve(url="http://127.0.0.1:9", model="m").key is None


def test_a_key_is_never_sent_over_plain_http_to_another_machine():
    with pytest.raises(UserError, match="plain http"):
        resolve({"WEBRECON_AI_KEY": "sk-secret"}, url="http://llm.example.com/v1", model="m")


def test_a_missing_key_is_asked_for_once_and_otherwise_explained():
    asked = []
    cfg = resolve(ask_key=lambda: asked.append(1) or "typed-key")
    assert cfg.key == "typed-key" and asked == [1]
    with pytest.raises(UserError) as stop:
        resolve()
    text = str(stop.value)
    assert "WEBRECON_AI_KEY" in text and "ANTHROPIC_API_KEY" in text and "shell history" in text


@pytest.mark.parametrize("settings,message", [
    ({"provider": "gemini"}, "Unknown AI provider"),
    ({"url": "ftp://x.example"}, "not valid"),
    ({"url": "not a url"}, "not valid"),
])
def test_bad_settings_are_explained(settings, message):
    with pytest.raises(UserError, match=message):
        resolve({"WEBRECON_AI_KEY": "k"}, model="m", **settings)


def test_the_key_never_appears_when_a_config_is_printed():
    cfg = AiConfig("anthropic", "https://api.anthropic.com", "m", key="sk-very-secret")
    assert "sk-very-secret" not in repr(cfg) and "sk-very-secret" not in str(cfg) and "set" in repr(cfg)
    assert "none" in repr(AiConfig("openai", "http://localhost/v1", "m"))


def test_the_key_never_appears_in_an_error_message():
    with pytest.raises(UserError) as stop:
        resolve({"WEBRECON_AI_KEY": "sk-very-secret"}, url="http://llm.example.com/v1", model="m")
    assert "sk-very-secret" not in str(stop.value)


# ------------------------------------------------------------------ keys from private files

def write_settings(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o600)
    return str(path)


def test_the_key_can_come_from_a_private_file(monkeypatch, tmp_path):
    saved = write_settings(tmp_path / "private" / "env", "WEBRECON_AI_KEY=sk-from-file\nWEBRECON_AI_MODEL=file-model\n")
    monkeypatch.setenv("WEBRECON_ENV_FILE", saved)
    cfg = resolve_config(ask_key=NO_PROMPT)
    assert (cfg.key, cfg.model, cfg.key_source) == ("sk-from-file", "file-model", saved)


def test_a_real_environment_variable_beats_the_file(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBRECON_ENV_FILE", write_settings(tmp_path / "env", "WEBRECON_AI_KEY=from-file\n"))
    monkeypatch.setenv("WEBRECON_AI_KEY", "from-environment")
    cfg = resolve_config(ask_key=NO_PROMPT)
    assert (cfg.key, cfg.key_source) == ("from-environment", "environment")


def test_the_providers_own_variable_in_a_file_is_used_and_its_source_recorded(monkeypatch, tmp_path):
    saved = write_settings(tmp_path / "env", "ANTHROPIC_API_KEY=anthropic-file-key\n")
    monkeypatch.setenv("WEBRECON_ENV_FILE", saved)
    cfg = resolve_config(ask_key=NO_PROMPT)
    assert (cfg.key, cfg.key_source) == ("anthropic-file-key", saved)


def test_sources_are_environment_or_prompt_when_no_file_is_involved():
    assert resolve({"WEBRECON_AI_KEY": "k"}).key_source == "environment"
    assert resolve(ask_key=lambda: "typed").key_source == "prompt"
    assert resolve(url="http://localhost:1/v1", model="m").key_source == ""


def test_key_warnings_only_apply_to_keys_read_from_a_file(monkeypatch, tmp_path):
    from webrecon.ai import key_warnings
    assert key_warnings(resolve({"WEBRECON_AI_KEY": "k"})) == []
    assert key_warnings(resolve(ask_key=lambda: "typed")) == []
    loose = tmp_path / "env"
    loose.write_text("WEBRECON_AI_KEY=k\n")
    loose.chmod(0o644)
    monkeypatch.setenv("WEBRECON_ENV_FILE", str(loose))
    assert any("chmod 600" in w for w in key_warnings(resolve_config(ask_key=NO_PROMPT)))


def test_the_missing_key_message_points_at_the_safe_way_first():
    with pytest.raises(UserError) as stop:
        resolve()
    assert str(stop.value).index("--ai-setup") < str(stop.value).index("WEBRECON_AI_KEY")
