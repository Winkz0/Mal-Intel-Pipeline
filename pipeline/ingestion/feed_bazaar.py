"""
feed_bazaar.py
Fetches and parses the MalwareBazaar recent samples feed.
Requires MALWAREBAZAAR_API_KEY in config/secrets.env
"""

import logging
import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv("config/secrets.env")

logger = logging.getLogger(__name__)

BAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
BAZAAR_LIMIT = 100


def fetch_bazaar_recent() -> list[dict]:
    """
    Fetches recent MB submissions and returns normalized IOC dicts.
    """
    if not BAZAAR_API_KEY:
        logger.error("MALWAREBAZAAR_API_KEY not set in config/secrets.env")
        return []

    logger.info(f"Fetching {BAZAAR_LIMIT} recent MalwareBazaar samples...")

    response = requests.post(
        BAZAAR_URL,
        data={
            "query": "get_recent",
            "selector": "100",
        },
        headers={"Auth-Key": BAZAAR_API_KEY},
        timeout=30
    )

    data = response.json()

    if data.get("query_status") != "ok":
        logger.error(f"MalwareBazaar API error: {data.get('query_status')}")
        return []

    samples = data.get("data", [])
    logger.info(f"MalwareBazaar: retrieved {len(samples)} samples")

    normalized = []
    for sample in samples:
        tags = sample.get("tags") or []
        signature = sample.get("signature") or None

        normalized.append({
            "source": "malwarebazaar",
            "ioc_type": "hash",
            "value": sample.get("sha256_hash", ""),
            "context": {
                "vendor": None,
                "product": None,
                "vulnerability_name": None,
                "description": f"{sample.get('file_type', '')} sample - {signature or 'unknown family'}",
                "date_added": sample.get("first_seen", ""),
                "due_date": None,
                "known_ransomware": None,
                "notes": f"File: {sample.get('file_name', 'unknown')} | Size: {sample.get('file_size', 0)} bytes",
                "malware_family": signature,
                "tags": tags,
                "ttp_refs": [],
                "campaign": None,
                "first_seen": sample.get("first_seen", ""),
                "source_pulse_id": None
            },
            "hashes": {
                "md5": sample.get("md5_hash", ""),
                "sha1": sample.get("sha1_hash", ""),
                "sha256": sample.get("sha256_hash", ""),
            },
            "file_info": {
                "name": sample.get("file_name", ""),
                "size": sample.get("file_size", 0),
                "type": sample.get("file_type", ""),
                "mime": sample.get("file_type_mime", ""),
                "delivery_method": sample.get("delivery_method", ""),
            },
            "approved_for_analysis": False,
            "ingested_at": datetime.now(timezone.utc).isoformat()
        })

    logger.info(f"MalwareBazaar: normalized {len(normalized)} indicators")
    return normalized


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = fetch_bazaar_recent()
    print(f"\nTotal MalwareBazaar indicators: {len(results)}")
    if results:
        print("\nSample entry:")
        import json
        print(json.dumps(results[0], indent=2))