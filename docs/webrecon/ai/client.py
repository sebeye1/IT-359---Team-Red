"""
client.py - Talking to an AI server over HTTP.

Two request styles are supported, which between them cover most servers:

    anthropic   POST {url}/v1/messages           header x-api-key            (Anthropic's Messages API)
    openai      POST {url}/chat/completions      header Authorization: Bearer  (OpenAI and the many servers that copy
                                                                               its API: Ollama, vLLM, LM Studio, ...)

The API key lives only in an AiConfig, is sent only in the request header, and is removed from any error
message before it can be shown.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests

ANTHROPIC_VERSION = "2023-06-01"
MAX_RESPONSE_BYTES = 2_000_000
RETRY_STATUS = {429, 500, 502, 503, 504}


class AiError(Exception):
    """The AI server could not be used. The message is safe to show: it never contains the API key."""


class AiFormatError(AiError):
    """The server answered, but not in a form that could be used (not JSON, wrong shape)."""


@dataclass
class AiConfig:
    provider: str            # "anthropic" or "openai"
    url: str                 # base URL, for example https://api.anthropic.com or http://localhost:11434/v1
    model: str
    key: str | None = None   # None for local servers that do not need one
    timeout: float = 60.0
    key_source: str = ""     # where the key came from: "environment", "prompt", or the path of a settings file

    def __repr__(self) -> str:
        shown = "set" if self.key else "none"
        return f"AiConfig(provider={self.provider!r}, url={self.url!r}, model={self.model!r}, key=<{shown}>)"

    __str__ = __repr__


class AiClient:
    def __init__(self, config: AiConfig, retries: int = 2):
        self.config = config
        self.retries = retries
        self.calls = 0
        self._token_field = "max_tokens"      # some OpenAI models want max_completion_tokens instead
        self._send_temperature = True         # and some accept only their default temperature

    # ------------------------------------------------------------------ request building

    def _endpoint(self) -> str:
        base = self.config.url.rstrip("/")
        if self.config.provider == "anthropic":
            return base + ("/messages" if base.endswith("/v1") else "/v1/messages")
        return base + "/chat/completions"

    def _headers(self) -> dict:
        headers = {"content-type": "application/json"}
        if self.config.provider == "anthropic":
            headers["anthropic-version"] = ANTHROPIC_VERSION
            if self.config.key:
                headers["x-api-key"] = self.config.key
        elif self.config.key:
            headers["authorization"] = f"Bearer {self.config.key}"
        return headers

    def _body(self, system: str, user: str, max_tokens: int) -> dict:
        if self.config.provider == "anthropic":
            return {"model": self.config.model, "max_tokens": max_tokens, "temperature": 0,
                    "system": system, "messages": [{"role": "user", "content": user}]}
        body = {"model": self.config.model, self._token_field: max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if self._send_temperature:
            body["temperature"] = 0
        return body

    def _adapt(self, response: requests.Response) -> bool:
        """After a 400 from an OpenAI-style server, switch off an option it says it does not support.
        Returns True if something changed, so the request is worth sending once more."""
        try:
            message = str(response.json().get("error", {}).get("message", "")).lower()
        except (ValueError, AttributeError):
            return False
        if "max_completion_tokens" in message and self._token_field == "max_tokens":
            self._token_field = "max_completion_tokens"
            return True
        if "temperature" in message and self._send_temperature:
            self._send_temperature = False
            return True
        return False

    # ------------------------------------------------------------------ responses

    def _clean(self, text: str) -> str:
        """Never let the key appear in a message, even if a server echoes it back."""
        key = self.config.key
        return text.replace(key, "***") if key else text

    def _explain(self, response: requests.Response) -> str:
        detail = ""
        try:
            error = response.json().get("error")
            detail = error.get("message", "") if isinstance(error, dict) else str(error or "")
        except (ValueError, AttributeError):
            pass
        status = response.status_code
        hint = {401: "The server rejected the API key.", 403: "The server refused this key or model.",
                404: "Not found: check the URL and the model name.", 400: "The server rejected the request.",
                429: "Rate limited or out of quota."}.get(status, "The server returned an error.")
        return self._clean(f"{hint} (HTTP {status}" + (f": {detail[:200]}" if detail else "") + ")")

    def _text(self, data: dict) -> str:
        try:
            if self.config.provider == "anthropic":
                return "".join(block.get("text", "") for block in data["content"] if block.get("type") == "text")
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError, AttributeError):
            raise AiFormatError("The AI server's reply was not in the expected format. Is the provider "
                                f"({self.config.provider}) right for this URL?")

    # ------------------------------------------------------------------ the call

    def complete(self, system: str, user: str, max_tokens: int = 3000) -> str:
        """Send one prompt and return the model's text. Raises AiError with a plain-English reason."""
        for attempt in range(self.retries + 1):
            self.calls += 1
            try:
                response = requests.post(self._endpoint(), headers=self._headers(), timeout=self.config.timeout,
                                         json=self._body(system, user, max_tokens), stream=True)
                body = bytearray()
                for chunk in response.iter_content(chunk_size=65536):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        break
                response.close()
            except requests.Timeout:
                if attempt < self.retries:
                    time.sleep(1.5 ** attempt)
                    continue
                raise AiError(f"The AI server did not answer within {self.config.timeout:g} seconds "
                              "(try --ai-timeout).")
            except requests.RequestException as exc:
                raise AiError(self._clean(f"Could not reach the AI server ({exc.__class__.__name__}). "
                                          "Check --ai-url and your connection."))
            if len(body) > MAX_RESPONSE_BYTES:
                raise AiError("The AI server's reply was unexpectedly large, so it was ignored.")
            response._content = bytes(body)
            if response.status_code in RETRY_STATUS and attempt < self.retries:
                time.sleep(1.5 ** attempt)
                continue
            if response.status_code == 400 and self.config.provider == "openai" and attempt < self.retries + 2 \
                    and self._adapt(response):
                continue
            if response.status_code != 200:
                raise AiError(self._explain(response))
            try:
                return self._text(response.json())
            except ValueError:
                raise AiFormatError("The AI server's reply was not valid JSON.")
        raise AiError("The AI server could not be reached.")  # pragma: no cover
