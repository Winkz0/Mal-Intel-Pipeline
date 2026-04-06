"""
checkpoint.py
Human Checkpoint #1 — Post-ingestion IOC review.
Presents deduplicated IOCs to the analyst for review.
Analyst approves individual samples for analysis.
Nothing proceeds to acquisition without explicit approval.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = "checkpoints"


def run_checkpoint(iocs: list[dict]) -> list[dict]:
    """
    Presents IOCs to the analyst for review and approval.
    Returns the full IOC list with approved_for_analysis flags set.
    Saves checkpoint state to disk before and after review.
    """
    hashes = [i for i in iocs if i["ioc_type"] == "hash"]
    other = [i for i in iocs if i["ioc_type"] != "hash"]

    print("\n" + "="*60)
    print("CHECKPOINT #1 — POST-INGESTION IOC REVIEW")
    print("="*60)
    print(f"\nTotal IOCs ingested: {len(iocs)}")
    print(f"  Hashes (actionable samples): {len(hashes)}")
    print(f"  Other IOCs (IPs, domains, CVEs, etc.): {len(other)}")

    if not hashes:
        print("\nNo hash IOCs found. Nothing to approve for analysis.")
        return iocs

    print("\n--- HASH IOCs AVAILABLE FOR ANALYSIS ---\n")
    for i, ioc in enumerate(hashes):
        family = ioc["context"].get("malware_family") or "Unknown"
        tags = ", ".join(ioc["context"].get("tags") or []) or "none"
        sources = ", ".join(ioc.get("sources", [ioc.get("source", "unknown")]))
        file_info = ioc.get("file_info", {})
        file_type = file_info.get("type", "unknown") if file_info else "unknown"

        print(f"[{i}] {ioc['value'][:16]}...{ioc['value'][-8:]}")
        print(f"     Family  : {family}")
        print(f"     Type    : {file_type}")
        print(f"     Tags    : {tags}")
        print(f"     Sources : {sources}")
        print()

    print("Options:")
    print("  Enter comma-separated indices to approve (e.g. 0,2,5)")
    print("  Enter 'all' to approve all hashes")
    print("  Enter 'none' to approve nothing and exit")
    print()

    while True:
        selection = input("Your selection: ").strip().lower()

        if selection == "none":
            print("No samples approved. Exiting.")
            save_checkpoint(iocs, approved_count=0)
            save_approved_manifest(iocs)
            return iocs

        elif selection == "all":
            approved_indices = list(range(len(hashes)))
            break

        else:
            try:
                approved_indices = [int(x.strip()) for x in selection.split(",")]
                if all(0 <= idx < len(hashes) for idx in approved_indices):
                    break
                else:
                    print(f"Invalid indices. Enter numbers between 0 and {len(hashes)-1}")
            except ValueError:
                print("Invalid input. Enter comma-separated numbers, 'all', or 'none'")

    for idx in approved_indices:
        hashes[idx]["approved_for_analysis"] = True

    approved_count = len(approved_indices)
    print(f"\n{approved_count} sample(s) approved for analysis.")

    # Rebuild full IOC list with updated approval flags
    approved_hashes = {h["value"] for h in hashes if h["approved_for_analysis"]}
    for ioc in iocs:
        if ioc["value"] in approved_hashes:
            ioc["approved_for_analysis"] = True

    save_checkpoint(iocs, approved_count=approved_count)
    return iocs


def save_checkpoint(iocs: list[dict], approved_count: int):
    """
    Saves checkpoint state to disk for audit trail and pipeline resume.
    """
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{CHECKPOINT_DIR}/checkpoint1_{timestamp}.json"

    state = {
        "checkpoint": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(iocs),
        "approved_for_analysis": approved_count,
        "iocs": iocs
    }

    with open(filename, "w") as f:
        json.dump(state, f, indent=2)

    logger.info(f"Checkpoint saved: {filename}")
    print(f"Checkpoint saved: {filename}")

def save_approved_manifest(iocs: list[dict]):
    """
    Save a clean manifest of only approved hash IOCs.
    Includes family name, tags, and a ready-to-use wget command
    for each sample. Designed as an acquisition shopping list for REMnux.
    """
    approved_hashes = [
        ioc for ioc in iocs
        if ioc.get("approved_for_analysis") is True
        and ioc.get("ioc_type") == "hash"
    ]

    if not approved_hashes:
        print("  [~] No approved hash IOCs — skipping manifest.")
        return

    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    manifest_path = f"{CHECKPOINT_DIR}/approved_{timestamp}.json"

    entries = []
    for ioc in approved_hashes:
        sha256 = ioc.get("value", "")
        family = ioc.get("context", {}).get("malware_family", "unknown")
        tags = ioc.get("context", {}).get("tags", [])
        file_info = ioc.get("file_info", {})
        safe_family = family.replace(" ", "_") if family else "unknown"

        entries.append({
            "sha256": sha256,
            "family": family,
            "tags": tags,
            "file_name": file_info.get("name", "unknown"),
            "file_type": file_info.get("type", "unknown"),
            "file_size": file_info.get("size", 0),
            "wget_command": f'wget --header "Auth-Key: $BAZAAR_KEY" --post-data "query=get_file&sha256_hash={sha256}" https://mb-api.abuse.ch/api/v1/ -O ~/{safe_family}.zip',
        })

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(entries),
        "samples": entries,
    }

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  [+] Approved manifest saved: {manifest_path}")
    print(f"      {len(entries)} sample(s) ready for acquisition")
    for e in entries:
        print(f"      • {e['family']} — {e['sha256'][:16]}...")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test with mock IOCs
    test_iocs = [
        {
            "source": "malwarebazaar",
            "ioc_type": "hash",
            "value": "fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4",
            "context": {
                "malware_family": "Mirai",
                "tags": ["botnet", "ddos"],
                "ttp_refs": [],
                "campaign": None,
                "first_seen": "2026-03-23",
                "description": "apk sample",
                "date_added": "",
                "due_date": None,
                "known_ransomware": None,
                "notes": "File: app0.apk | Size: 5401317 bytes",
                "vendor": None,
                "product": None,
                "vulnerability_name": None,
                "source_pulse_id": None
            },
            "file_info": {"type": "apk", "size": 5401317, "name": "app0.apk"},
            "hashes": {"sha256": "fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4"},
            "sources": ["malwarebazaar"],
            "approved_for_analysis": False,
            "ingested_at": "2026-03-23T16:50:53+00:00"
        },
        {
            "source": "otx",
            "ioc_type": "ip",
            "value": "192.168.1.100",
            "context": {
                "malware_family": None,
                "tags": ["c2"],
                "ttp_refs": ["T1071"],
                "campaign": "Operation X",
                "first_seen": "2026-03-20",
                "description": "C2 server",
                "date_added": "",
                "due_date": None,
                "known_ransomware": None,
                "notes": "",
                "vendor": None,
                "product": None,
                "vulnerability_name": None,
                "source_pulse_id": "abc123"
            },
            "sources": ["otx"],
            "approved_for_analysis": False,
            "ingested_at": "2026-03-23T16:50:53+00:00"
        }
    ]

    result = run_checkpoint(test_iocs)
    approved = [i for i in result if i["approved_for_analysis"]]
    print(f"\nApproved for analysis: {len(approved)}")