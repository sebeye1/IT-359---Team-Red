"""
webrecon.ai - Optional AI-estimated risk context: a CVSS score and MITRE ATT&CK techniques for each finding.

    config.py    which AI server to use (options, WEBRECON_AI_* variables; the API key is never an option)
    envfile.py   private settings files for the key, kept outside the repository; warnings if one could be committed
    setup.py     --ai-setup: save the key once, safely
    client.py    talking to Anthropic-style and OpenAI-compatible servers
    prompt.py    what is sent: generic check descriptions only, never anything about the scanned site
    cvss.py      CVSS v3.1 scores calculated locally from a vector
    attack.py    MITRE ATT&CK technique IDs, links, and the official list (--attack-update)
    enrich.py    asks, checks the answers, caches them, and attaches them to findings
    storage.py   the local cache folder
"""

from webrecon.ai.attack import load_index, update_index
from webrecon.ai.client import AiClient, AiConfig, AiError
from webrecon.ai.config import build_client, key_warnings, resolve_config
from webrecon.ai.enrich import EnrichResult, enrich_findings
from webrecon.ai.setup import run_setup

__all__ = ["AiClient", "AiConfig", "AiError", "EnrichResult", "build_client", "enrich_findings", "key_warnings",
           "load_index", "resolve_config", "run_setup", "update_index"]
