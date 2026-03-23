"""
deduplicator.py
Deduplicates normalized IOCs across all feed sources.
Primary dedup key is ioc_type + value.
Where duplicates exist, context is merged to preserve
the richest possible data from all sources.
"""

import logging

logger = logging.getLogger(__name__)


def deduplicate(iocs: list[dict]) -> list[dict]:
    """
    Deduplicates IOCs by ioc_type + value.
    Merges context from duplicate entries, preserving the richest data.
    Tracks all source feeds that reported the IOC.
    """
    seen = {}

    for ioc in iocs:
        key = f"{ioc['ioc_type']}:{ioc['value']}"

        if key not in seen:
            # First time seeing this IOC — store it with sources as a list
            entry = ioc.copy()
            entry["sources"] = [ioc["source"]]
            seen[key] = entry
        else:
            # Duplicate — merge context and track additional source
            existing = seen[key]

            if ioc["source"] not in existing["sources"]:
                existing["sources"].append(ioc["source"])

            existing["context"] = merge_context(
                existing["context"],
                ioc.get("context", {})
            )

            # Prefer richer file_info and hashes if present
            if "hashes" in ioc and "hashes" not in existing:
                existing["hashes"] = ioc["hashes"]
            if "file_info" in ioc and "file_info" not in existing:
                existing["file_info"] = ioc["file_info"]

    results = list(seen.values())
    dupes = len(iocs) - len(results)
    logger.info(f"Deduplicator: {len(iocs)} in, {len(results)} out, {dupes} duplicates merged")
    return results


def merge_context(base: dict, incoming: dict) -> dict:
    """
    Merges two context dicts, preferring non-null/non-empty values.
    Lists are unioned. Strings prefer the longer/more descriptive value.
    """
    merged = base.copy()

    for key, incoming_val in incoming.items():
        base_val = merged.get(key)

        if isinstance(incoming_val, list) and isinstance(base_val, list):
            # Union lists, preserve order, no duplicates
            merged[key] = base_val + [v for v in incoming_val if v not in base_val]

        elif incoming_val and not base_val:
            # Fill in missing values
            merged[key] = incoming_val

        elif isinstance(incoming_val, str) and isinstance(base_val, str):
            # Prefer the longer, more descriptive string
            if len(incoming_val) > len(base_val):
                merged[key] = incoming_val

    return merged


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    test_iocs = [
        {
            "source": "otx",
            "ioc_type": "hash",
            "value": "abc123",
            "context": {"malware_family": "Mirai", "tags": ["botnet"], "campaign": None},
            "sources": ["otx"]
        },
        {
            "source": "malwarebazaar",
            "ioc_type": "hash",
            "value": "abc123",
            "context": {"malware_family": None, "tags": ["ddos"], "campaign": "Operation X"},
            "sources": ["malwarebazaar"]
        },
        {
            "source": "otx",
            "ioc_type": "ip",
            "value": "10.0.0.1",
            "context": {"tags": ["c2"], "campaign": "Operation X"},
            "sources": ["otx"]
        },
    ]

    results = deduplicate(test_iocs)
    print(f"\nAfter dedup: {len(results)} IOCs")
    import json
    for r in results:
        print(json.dumps(r, indent=2))