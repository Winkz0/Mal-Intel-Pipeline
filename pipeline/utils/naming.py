"""
naming.py
Maps SHA256 hashes to human-readable aliases.
Registry stored in samples/registry.json.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "samples" / "registry.json"


def _load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {}
    with open(REGISTRY_PATH, "r") as f:
        return json.load(f)


def _save_registry(registry: dict):
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def register_alias(sha256: str, alias: str):
    registry = _load_registry()
    registry[sha256] = alias
    _save_registry(registry)
    logger.info(f"Registered alias: {alias} -> {sha256[:16]}...")


def resolve(identifier: str) -> dict | None:
    """
    Takes a SHA256 or alias, returns {"sha256": ..., "alias": ...}
    or None if not found.
    """
    registry = _load_registry()

    # Check if identifier is a known SHA256
    if identifier in registry:
        return {"sha256": identifier, "alias": registry[identifier]}

    # Check if identifier is an alias
    for sha256, alias in registry.items():
        if alias == identifier:
            return {"sha256": sha256, "alias": alias}

    # Try prefix match on SHA256
    matches = {k: v for k, v in registry.items() if k.startswith(identifier)}
    if len(matches) == 1:
        sha256, alias = next(iter(matches.items()))
        return {"sha256": sha256, "alias": alias}

    return None