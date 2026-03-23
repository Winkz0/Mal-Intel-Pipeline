"""
normalizer.py
Validates and normalizes IOC dicts from all feed parsers
into a guaranteed-consistent schema before deduplication.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

VALID_IOC_TYPES = {"hash", "ip", "domain", "url", "email", "cve"}
VALID_SOURCES = {"cisa_kev", "otx", "malwarebazaar"}

SCHEMA_DEFAULTS = {
    "source": "unknown",
    "ioc_type": "unknown",
    "value": "",
    "context": {
        "vendor": None,
        "product": None,
        "vulnerability_name": None,
        "description": "",
        "date_added": "",
        "due_date": None,
        "known_ransomware": None,
        "notes": "",
        "malware_family": None,
        "tags": [],
        "ttp_refs": [],
        "campaign": None,
        "first_seen": "",
        "source_pulse_id": None
    },
    "approved_for_analysis": False,
    "ingested_at": ""
}


def normalize_ioc(ioc: dict) -> dict | None:
    """
    Validates and normalizes a single IOC dict.
    Returns None if the IOC is invalid and should be dropped.
    """
    if not ioc.get("value"):
        logger.debug("Dropping IOC with empty value")
        return None

    if ioc.get("ioc_type") not in VALID_IOC_TYPES:
        logger.debug(f"Dropping IOC with invalid type: {ioc.get('ioc_type')}")
        return None

    normalized = {
        "source": ioc.get("source", "unknown"),
        "ioc_type": ioc.get("ioc_type"),
        "value": str(ioc.get("value", "")).strip().lower(),
        "context": {},
        "approved_for_analysis": False,
        "ingested_at": ioc.get("ingested_at", datetime.now(timezone.utc).isoformat())
    }

    # Preserve extra fields from bazaar (hashes, file_info)
    if "hashes" in ioc:
        normalized["hashes"] = ioc["hashes"]
    if "file_info" in ioc:
        normalized["file_info"] = ioc["file_info"]

    # Normalize context block
    raw_ctx = ioc.get("context", {})
    defaults = SCHEMA_DEFAULTS["context"]

    for field, default in defaults.items():
        val = raw_ctx.get(field, default)
        if isinstance(default, list) and not isinstance(val, list):
            val = []
        normalized["context"][field] = val

    return normalized


def normalize_all(iocs: list[dict]) -> list[dict]:
    """
    Normalizes a list of IOC dicts, dropping invalid entries.
    """
    results = []
    dropped = 0

    for ioc in iocs:
        normalized = normalize_ioc(ioc)
        if normalized:
            results.append(normalized)
        else:
            dropped += 1

    logger.info(f"Normalizer: {len(results)} valid, {dropped} dropped")
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test with a sample from each feed type
    test_iocs = [
        {
            "source": "malwarebazaar",
            "ioc_type": "hash",
            "value": "abc123def456",
            "context": {"malware_family": "Mirai", "tags": ["botnet"]},
            "approved_for_analysis": False,
            "ingested_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "source": "otx",
            "ioc_type": "ip",
            "value": "192.168.1.1",
            "context": {"campaign": "test campaign", "ttp_refs": ["T1059"]},
            "approved_for_analysis": False,
            "ingested_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "source": "unknown_source",
            "ioc_type": "invalid_type",
            "value": "shouldbedropped",
            "context": {},
            "approved_for_analysis": False,
            "ingested_at": ""
        }
    ]

    results = normalize_all(test_iocs)
    print(f"\nNormalized: {len(results)} IOCs")
    import json
    for r in results:
        print(json.dumps(r, indent=2))