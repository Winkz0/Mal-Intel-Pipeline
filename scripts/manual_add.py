"""
manual_add.py
Manually add a sample by SHA256 hash, download it from MalwareBazaar,
quarantine it, register it in the DB, and prepare it for the pipeline.

Usage:
    python scripts/manual_add.py <sha256>
    python scripts/manual_add.py <sha256> --family zionsiphon --tags apt,ics,wiper
"""

import os
import sys
import json
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / "config" / "secrets.env", override=True)
load_dotenv(REPO_ROOT / "config" / ".env", override=True)

from pipeline.utils.db import update_status

try:
    from pipeline.utils.naming import register_alias
    _HAS_NAMING = True
except ImportError:
    _HAS_NAMING = False

logger = logging.getLogger(__name__)

QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"


def download_from_bazaar(sha256: str, api_key: str) -> bytes | None:
    """Download sample zip from MalwareBazaar API."""
    import requests

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_file", "sha256_hash": sha256}
    headers = {"Auth-Key": api_key}

    try:
        resp = requests.post(url, data=data, headers=headers, timeout=60)
        if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("application/"):
            return resp.content
        else:
            print(f"  [!] MalwareBazaar returned: {resp.status_code}")
            print(f"      Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
            # Check if it's a JSON error response
            try:
                err = resp.json()
                print(f"      Response: {err.get('query_status', 'unknown')}")
            except Exception:
                pass
            return None
    except Exception as e:
        print(f"  [!] Download failed: {e}")
        return None


def query_bazaar_info(sha256: str, api_key: str) -> dict:
    """Query MalwareBazaar for sample metadata."""
    import requests

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": sha256}
    headers = {"Auth-Key": api_key}

    try:
        resp = requests.post(url, data=data, headers=headers, timeout=30)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("query_status") == "ok" and result.get("data"):
                return result["data"][0]
    except Exception as e:
        logger.warning(f"Metadata query failed: {e}")

    return {}


def main():
    parser = argparse.ArgumentParser(description="Manually add a sample by SHA256")
    parser.add_argument("sha256", help="SHA256 hash of the sample")
    parser.add_argument("--family", type=str, default=None, help="Malware family name")
    parser.add_argument("--tags", type=str, default="", help="Comma-separated tags")
    parser.add_argument("--skip-download", action="store_true",
                        help="Register only — skip download (sample already in quarantine)")
    args = parser.parse_args()

    sha256 = args.sha256.strip().lower()

    if len(sha256) != 64:
        print(f"  [!] Invalid SHA256 length: {len(sha256)} (expected 64)")
        return

    # Check if already in DB
    import sqlite3
    conn = sqlite3.connect(REPO_ROOT / "pipeline.db")
    cursor = conn.cursor()
    cursor.execute("SELECT sha256, status FROM samples WHERE sha256 = ?", (sha256,))
    row = cursor.fetchone()
    conn.close()

    if row:
        print(f"  [~] Sample already registered: {sha256[:16]}...")
        print(f"      Status: {row[1]}")
        return

    # Check if already in quarantine
    zip_path = QUARANTINE_DIR / f"{sha256}.zip"
    meta_path = QUARANTINE_DIR / f"{sha256}.meta.json"

    api_key = os.getenv("MALWAREBAZAAR_API_KEY")
    if not api_key:
        print("  [!] MALWAREBAZAAR_API_KEY not set in config/secrets.env")
        return

    print(f"\n{'='*60}")
    print(f"  Manual Sample Acquisition")
    print(f"{'='*60}")
    print(f"  SHA256 : {sha256}")

    # Query MalwareBazaar for metadata
    print(f"  [*] Querying MalwareBazaar for metadata...")
    mb_info = query_bazaar_info(sha256, api_key)

    # Use MalwareBazaar metadata if available, CLI args override
    family = args.family or mb_info.get("signature") or "unknown"
    file_name = mb_info.get("file_name", "unknown")
    file_type = mb_info.get("file_type", "unknown")
    file_size = mb_info.get("file_size", 0)
    mb_tags = mb_info.get("tags") or []
    user_tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else []
    all_tags = list(set(user_tags + mb_tags))

    print(f"  Family : {family}")
    print(f"  File   : {file_name} ({file_type})")
    if mb_info:
        print(f"  [+] MalwareBazaar metadata found")
    else:
        print(f"  [~] No MalwareBazaar metadata — using CLI args")

    # Download
    if not args.skip_download:
        if zip_path.exists():
            print(f"  [~] Zip already in quarantine, skipping download")
        else:
            print(f"  [*] Downloading from MalwareBazaar...")
            zip_bytes = download_from_bazaar(sha256, api_key)
            if not zip_bytes:
                print(f"  [!] Download failed. Sample may not be on MalwareBazaar.")
                print(f"      You can manually place the zip in: {QUARANTINE_DIR}")
                print(f"      Then rerun with: python scripts/manual_add.py {sha256} --skip-download")
                return

            QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            with open(zip_path, "wb") as f:
                f.write(zip_bytes)
            print(f"  [+] Downloaded: {zip_path.name} ({len(zip_bytes):,} bytes)")
    else:
        if not zip_path.exists():
            print(f"  [!] --skip-download specified but no zip found at: {zip_path}")
            return
        print(f"  [~] Skipping download — using existing zip")

    # Build sidecar metadata (matches acquire_sample.py format)
    meta = {
        "sha256": sha256,
        "md5": mb_info.get("md5_hash", ""),
        "sha1": mb_info.get("sha1_hash", ""),
        "file_name": file_name,
        "file_type": file_type,
        "file_size_bytes": file_size,
        "malware_family": family,
        "tags": all_tags,
        "source": "manual",
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "quarantine_path": str(zip_path),
        "hash_verified": True,
        "approved_for_analysis": True,
        "analysis_started": False,
        "registration_method": "manual",
    }

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  [+] Sidecar written: {meta_path.name}")

    # Register in DB
    update_status(sha256, "ACQUIRED", family=family)
    print(f"  [+] DB status: ACQUIRED")

    # Alias registration
    if _HAS_NAMING:
        alias_input = input("  Enter sample alias (e.g. ZionSiphon_050426) or press Enter to skip: ").strip()
        if alias_input:
            register_alias(sha256, alias_input)
            print(f"  [+] Alias registered: {alias_input}")

    print(f"\n{'='*60}")
    print(f"  Sample ready for pipeline")
    print(f"{'='*60}")
    print(f"  Next steps:")
    print(f"    1. Transfer to REMnux:")
    print(f"       python -m pipeline.utils.remote push {sha256}")
    print(f"    2. On REMnux — extract and run static analysis:")
    print(f"       7z x -pinfected {sha256}.zip")
    print(f"       python -m pipeline.static_analysis.analyze {sha256}")
    print(f"    3. Transfer analysis back to host:")
    print(f"       python -m pipeline.utils.remote pull {sha256}")
    print(f"    4. Continue pipeline:")
    print(f"       python -m pipeline.llm_synthesis.synthesize {sha256}")
    print(f"       python -m pipeline.reporting.report {sha256}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()