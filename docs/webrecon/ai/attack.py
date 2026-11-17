"""
attack.py - MITRE ATT&CK technique IDs: checking them, linking to them, and the official list.

MITRE ATT&CK catalogues adversary techniques. It does not publish CVSS scores (those come from NVD, or from
a CVSS vector). WebRecon uses ATT&CK to say which techniques a weakness helps an attacker with, and checks
every technique ID an AI suggests against MITRE's own list so an invented one is dropped.

`python3 main.py --attack-update` downloads that list (about 55 MB, once) and keeps a small summary locally.
"""

from __future__ import annotations

import json
import re

import requests

from webrecon.ai import storage
from webrecon.errors import UserError

ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
INDEX_FILE = "attack-techniques.json"
MAX_DOWNLOAD_BYTES = 200_000_000
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
ATTACK_SITE = "https://attack.mitre.org/techniques/"


def is_technique_id(value) -> bool:
    return isinstance(value, str) and TECHNIQUE_ID.match(value) is not None


def technique_url(technique_id: str) -> str:
    """Link to a technique's page on attack.mitre.org. Sub-technique T1059.003 lives at /T1059/003/."""
    return ATTACK_SITE + technique_id.replace(".", "/") + "/"


def parse_bundle(bundle: dict) -> dict:
    """A compact index {version, modified, techniques: {id: {name, tactics}}} from an ATT&CK STIX bundle.
    Revoked and deprecated techniques are left out."""
    techniques = {}
    version = modified = ""
    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            version, modified = str(obj.get("x_mitre_version", "")), str(obj.get("modified", ""))
        elif kind == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            external_id = next((r.get("external_id") for r in obj.get("external_references", [])
                                if r.get("source_name") == "mitre-attack"), None)
            if is_technique_id(external_id):
                tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                           if p.get("kill_chain_name") == "mitre-attack" and "phase_name" in p]
                techniques[external_id] = {"name": obj.get("name", ""), "tactics": tactics}
    return {"version": version, "modified": modified, "source": ATTACK_DATA_URL, "techniques": techniques}


def update_index(url: str = ATTACK_DATA_URL, timeout: float = 120.0) -> dict:
    """Download MITRE's ATT&CK Enterprise data, save the compact index locally, and return it."""
    try:
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(chunk_size=1 << 20):
            body.extend(chunk)
            if len(body) > MAX_DOWNLOAD_BYTES:
                raise UserError("The ATT&CK download is larger than expected, so it was stopped.")
        index = parse_bundle(json.loads(bytes(body)))
    except requests.RequestException as exc:
        raise UserError(f"Could not download the ATT&CK data from MITRE: {exc.__class__.__name__}. "
                        "Check your internet connection and try again.")
    except ValueError:
        raise UserError("The ATT&CK download was not valid JSON, so nothing was saved.")
    if not index["techniques"]:
        raise UserError("The ATT&CK download contained no techniques, so nothing was saved.")
    storage.write_json(INDEX_FILE, index)
    return index


def load_index() -> dict | None:
    """The saved technique index, or None if --attack-update has not been run."""
    index = storage.read_json(INDEX_FILE)
    return index if index and isinstance(index.get("techniques"), dict) else None
