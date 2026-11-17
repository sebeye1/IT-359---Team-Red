"""
config.py - Working out which AI server to use, from options, environment variables and defaults.

Order of precedence for every setting: command-line option, then environment variable, then a private settings
file (see envfile.py), then a default. The API key is never a command-line option, because anything typed on a
command line is visible in the shell history and in the process list. It comes from the environment, from a
private file kept out of your repository, or is asked for with hidden input.
"""

from __future__ import annotations

import getpass
import os
import sys
from urllib.parse import urlparse

from webrecon.ai import envfile
from webrecon.ai.client import AiClient, AiConfig
from webrecon.errors import UserError
from webrecon.scanning import is_loopback

PROVIDERS = ("sushi", "anthropic", "openai")
DEFAULT_PROVIDER = "sushi"
DEFAULT_URLS = {"sushi": "http://sushi.it.ilstu.edu:8080/api",
                "anthropic": "https://api.anthropic.com",
                "openai": "https://api.openai.com/v1"}
DEFAULT_MODELS = {"sushi": "llama3.3:latest",
                  "anthropic": "claude-haiku-5-5"}  # a small, fast model is plenty for this task
# These are the NAMES of environment variables, never the key itself.
KEY_VARIABLES = {"sushi": "SUSHI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

# Hosts that are allowed to use plain HTTP (lab / internal servers).
# Treated the same as localhost for the HTTP and API-key checks.
ALLOWED_HTTP_HOSTS = {"sushi.it.ilstu.edu"}


def _ask_for_key() -> str | None:
    if not sys.stdin.isatty():
        return None
    return getpass.getpass("AI API key (typing is hidden, and the key is not saved): ").strip() or None


def _provider_for_url(url: str | None) -> str:
    """Which provider a URL implies when none was named. No URL means the priority server, sushi."""
    if not url:
        return DEFAULT_PROVIDER
    host = (urlparse(url).hostname or "").lower()
    if "anthropic.com" in url.lower():
        return "anthropic"
    if host in ALLOWED_HTTP_HOSTS:
        return "sushi"
    return "openai"


def resolve_config(provider: str | None = None, url: str | None = None, model: str | None = None,
                   timeout: float = 60.0, env=None, ask_key=_ask_for_key) -> AiConfig:
    """Build the AiConfig, or raise UserError saying exactly what is missing or unsafe."""
    file_sources = {}
    if env is None:
        loaded = envfile.load()
        env = {**loaded.values, **os.environ}   # real environment variables win over any file
        file_sources = {name: path for name, path in loaded.sources.items() if name not in os.environ}
    url = url or env.get("WEBRECON_AI_URL") or None
    provider = (provider or env.get("WEBRECON_AI_PROVIDER") or _provider_for_url(url)).lower()
    if provider not in PROVIDERS:
        raise UserError(f"Unknown AI provider {provider!r}. Use one of: {', '.join(PROVIDERS)}.")
    url = url or DEFAULT_URLS[provider]

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UserError(f"The AI server URL {url!r} is not valid. Use a form like https://api.example.com/v1.")
    local = is_loopback(parsed.hostname)
    # Treat the lab server the same as localhost for the HTTP / key checks
    trusted = local or parsed.hostname in ALLOWED_HTTP_HOSTS
    if parsed.scheme == "http" and not trusted:
        raise UserError(f"Refusing to talk to {parsed.hostname} over plain http, because the API key would be "
                        "sent unencrypted. Use an https:// URL (plain http is only allowed for localhost).")

    model = model or env.get("WEBRECON_AI_MODEL") or DEFAULT_MODELS.get(provider)
    if not model:
        raise UserError("No AI model chosen. Give --ai-model NAME (or set WEBRECON_AI_MODEL).")

    key, key_source = None, ""
    for name in ("WEBRECON_AI_KEY", KEY_VARIABLES[provider]):
        if env.get(name):
            key, key_source = env[name], file_sources.get(name, "environment")
            break
    if not key and not trusted:
        key = ask_key()
        key_source = "prompt" if key else ""
    if not key and not trusted:
        raise UserError("No API key found. Run  python3 main.py --ai-setup  to save one safely outside your project, or "
                        f"set WEBRECON_AI_KEY (or {KEY_VARIABLES[provider]}) in your environment. Keys are not "
                        "accepted as command-line options because they would be saved in your shell history.")
    return AiConfig(provider=provider, url=url, model=model, key=key, timeout=timeout, key_source=key_source)


def key_warnings(config: AiConfig) -> list[str]:
    """Problems with the file the key was read from (readable by others, tracked or unignored by git)."""
    if config.key_source in ("", "environment", "prompt"):
        return []
    return envfile.warnings_for(config.key_source)


def build_client(**settings) -> AiClient:
    return AiClient(resolve_config(**settings))
