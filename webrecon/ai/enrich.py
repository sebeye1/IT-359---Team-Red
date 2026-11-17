"""
enrich.py - Adds an estimated CVSS score and MITRE ATT&CK techniques to findings.

The AI server is asked once per check TYPE (not per finding), answers are cached on disk, and every answer is
checked before use:

    CVSS      the AI proposes a vector; the score is calculated here (see cvss.py). An invalid vector is dropped.
    ATT&CK    technique IDs must look like T1234 or T1234.001, and, once `--attack-update` has been run, must
              exist in MITRE's list. Unknown IDs are dropped; names and tactics come from MITRE, not the AI.

Everything added is marked as an estimate. The scan itself never depends on this: if the server fails, the
findings are simply left as they were.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field

from webrecon.ai import attack, cvss, prompt, storage
from webrecon.ai.client import AiClient, AiError, AiFormatError

CHUNK_SIZE = 10          # check types per request, to keep each answer short
MAX_TECHNIQUES = 3
CACHE_FILE = "ai-cache.json"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class EnrichResult:
    enriched: int = 0                 # findings that received AI context
    from_cache: int = 0               # check types answered from the local cache
    asked: int = 0                    # check types sent to the server
    problems: list = field(default_factory=list)   # plain-English notes about anything that went wrong


def _text(value, limit: int) -> str:
    return _CONTROL.sub(" ", value).strip()[:limit] if isinstance(value, str) else ""


def parse_answer(text: str) -> dict:
    """{check_id: raw result} from the model's reply. Tolerates code fences and a little surrounding prose."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise AiFormatError("The AI server's answer did not contain JSON.")
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        raise AiFormatError("The AI server's answer was not valid JSON.")
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise AiFormatError("The AI server's answer did not have a results list.")
    return {r["check_id"]: r for r in results if isinstance(r, dict) and isinstance(r.get("check_id"), str)}


def build_enrichment(raw: dict, model: str, index: dict | None, dropped: list) -> dict | None:
    """Turn one raw answer into a checked enrichment, or None if nothing in it was usable."""
    score = cvss.evaluate(raw.get("cvss_vector"))
    techniques = []
    for entry in raw.get("attack") or []:
        technique_id = entry.get("id") if isinstance(entry, dict) else None
        if not attack.is_technique_id(technique_id) or any(t["id"] == technique_id for t in techniques):
            continue
        known = index["techniques"].get(technique_id) if index else None
        if index and known is None:
            dropped.append(technique_id)       # not in MITRE's list: the AI invented it
            continue
        techniques.append({"id": technique_id, "name": known["name"] if known else "",
                           "tactics": list(known["tactics"]) if known else [],
                           "url": attack.technique_url(technique_id), "verified": bool(known),
                           "reason": _text(entry.get("reason"), 160)})
        if len(techniques) == MAX_TECHNIQUES:
            break
    if score is None and not techniques:
        return None
    return {"source": "ai", "model": model, "prompt_version": prompt.PROMPT_VERSION, "estimated": True,
            "cvss": {"vector": score.vector, "score": score.score, "rating": score.rating} if score else None,
            "attack": techniques, "rationale": _text(raw.get("rationale"), 240)}


def _ask(client: AiClient, chunk: list[dict]) -> dict:
    message = prompt.user_message(chunk)
    try:
        return parse_answer(client.complete(prompt.SYSTEM, message))
    except AiFormatError:  # one polite retry: models occasionally wrap the JSON in chatter
        return parse_answer(client.complete(
            prompt.SYSTEM, message + "\n\nYour previous reply was not valid JSON. Reply with the JSON object only."))


def enrich_findings(findings, client: AiClient, index="load") -> EnrichResult:
    """Attach `finding.enrichment` to every finding whose check type the AI could describe."""
    result = EnrichResult()
    items = prompt.items_for(findings)
    if not items:
        return result
    index = attack.load_index() if index == "load" else index
    model = client.config.model
    cache = storage.read_json(CACHE_FILE) or {}
    keys = {i["check_id"]: f"{model}|v{prompt.PROMPT_VERSION}|{i['check_id']}|{prompt.item_hash(i)}" for i in items}

    ready = {i["check_id"]: cache[keys[i["check_id"]]] for i in items if isinstance(cache.get(keys[i["check_id"]]), dict)}
    result.from_cache = len(ready)
    pending = [i for i in items if i["check_id"] not in ready]

    dropped, learned = [], False
    for start in range(0, len(pending), CHUNK_SIZE):
        chunk = pending[start:start + CHUNK_SIZE]
        result.asked += len(chunk)
        try:
            answers = _ask(client, chunk)
        except AiFormatError as exc:
            result.problems.append(f"{', '.join(i['check_id'] for i in chunk)}: {exc}")
            continue
        except AiError as exc:                       # network, key or quota problem: no point trying the rest
            result.problems.append(str(exc))
            break
        for item in chunk:
            enrichment = build_enrichment(answers.get(item["check_id"], {}), model, index, dropped)
            if enrichment is None:
                result.problems.append(f"{item['check_id']}: the AI gave no usable score or technique.")
                continue
            ready[item["check_id"]] = enrichment
            cache[keys[item["check_id"]]] = enrichment
            learned = True
    if dropped:
        result.problems.append("Ignored technique ID(s) that are not in MITRE's list: " + ", ".join(sorted(set(dropped))) + ".")
    if learned:
        try:
            storage.write_json(CACHE_FILE, cache)
        except OSError:
            pass  # a read-only home folder only costs us the cache

    for f in findings:
        if f.check_id in ready:
            f.enrichment = copy.deepcopy(ready[f.check_id])
            result.enriched += 1
    return result
