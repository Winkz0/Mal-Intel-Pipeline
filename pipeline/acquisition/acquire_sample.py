"""
M5: Sample Acquisition Module
Pulls approved malware samples from MalwareBazaar (primary) and
optionally enriches via VirusTotal. Only processes IOCs flagged
approved_for_analysis=True from checkpoint state.
"""

import os
import json
import hashlib
import logging
import zipfile
import requests
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Paths
REPO_ROOT = Path(__file__).resolve().parents[2]
QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
CHECKPOINT_DIR = REPO_ROOT / "checkpoints"
LOG_DIR = REPO_ROOT / "output" / "logs"

BAZAAR_DOWNLOAD_URL = "https://mb-api.abuse.ch/api/v1/"
BAZAAR_ZIP_PASSWORD = b"infected"  # Standard MalwareBazaar ZIP password


def load_approved_iocs(checkpoint_file: str = None) -> list[dict]:
    """
    Load IOCs approved at checkpoint #1.
    If no checkpoint_file specified, auto-selects the most recent
    checkpoint1_*.json file in the checkpoints directory.
    Returns only hash-type IOCs with approved_for_analysis=True.
    """
    if checkpoint_file:
        cp_path = CHECKPOINT_DIR / checkpoint_file
    else:
        candidates = sorted(CHECKPOINT_DIR.glob("checkpoint1_*.json"), reverse=True)
        if not candidates:
            logger.error(f"No checkpoint1_*.json files found in {CHECKPOINT_DIR}")
            return []
        cp_path = candidates[0]
        logger.info(f"Auto-selected checkpoint: {cp_path.name}")

    if not cp_path.exists():
        logger.error(f"Checkpoint file not found: {cp_path}")
        return []

    with open(cp_path, "r") as f:
        data = json.load(f)
        # Handle both wrapped {"iocs": [...]} and flat [...] checkpoint formats
        all_iocs = data.get("iocs", data) if isinstance(data, dict) else data

    approved = [
        ioc for ioc in all_iocs
        if ioc.get("approved_for_analysis") is True
        and ioc.get("ioc_type") == "hash"
    ]

    logger.info(f"Loaded {len(approved)} approved hash IOCs from {cp_path.name}")
    return approved


def download_from_bazaar(sha256_hash: str, api_key: str) -> bytes | None:
    """
    Download a sample ZIP from MalwareBazaar by SHA256.
    Returns raw ZIP bytes or None on failure.
    MalwareBazaar packages samples as password-protected ZIPs.
    """
    payload = {
        "query": "get_file",
        "sha256_hash": sha256_hash,
        "api_key": api_key,
    }

    try:
        resp = requests.post(
            BAZAAR_DOWNLOAD_URL,
            data=payload,
            timeout=60,
            stream=True
        )
        resp.raise_for_status()

        # MalwareBazaar returns JSON error responses for unknown hashes
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            err = resp.json()
            logger.warning(f"Bazaar API error for {sha256_hash}: {err.get('query_status')}")
            return None

        return resp.content

    except requests.RequestException as e:
        logger.error(f"Download failed for {sha256_hash}: {e}")
        return None


def download_from_virustotal(sha256_hash: str, api_key: str) -> bytes | None:
    """
    Download a sample from VirusTotal by SHA256.
    Requires VT account with download privileges (free tier supports this).
    Returns raw file bytes or None on failure.
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}/download"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=60, stream=True)
        
        if resp.status_code == 401:
            logger.error("VT API key invalid or unauthorized")
            return None
        elif resp.status_code == 404:
            logger.warning(f"Sample not found on VT: {sha256_hash[:16]}...")
            return None
        elif resp.status_code == 429:
            logger.warning("VT rate limit hit")
            return None
            
        resp.raise_for_status()
        return resp.content

    except requests.RequestException as e:
        logger.error(f"VT download failed for {sha256_hash}: {e}")
        return None

def extract_sample_from_zip(zip_bytes: bytes, sha256_hash: str) -> bytes | None:
    """
    Extract the malware binary from the password-protected ZIP.
    MalwareBazaar always uses 'infected' as the ZIP password.
    Returns raw sample bytes or None on failure.
    """
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            if not names:
                logger.error(f"Empty ZIP for {sha256_hash}")
                return None

            # Extract first file in archive (always the sample)
            sample_bytes = zf.read(names[0], pwd=BAZAAR_ZIP_PASSWORD)
            logger.debug(f"Extracted {names[0]} from ZIP ({len(sample_bytes)} bytes)")
            return sample_bytes

    except zipfile.BadZipFile as e:
        logger.error(f"Bad ZIP for {sha256_hash}: {e}")
        return None
    except RuntimeError as e:
        logger.error(f"ZIP extraction error for {sha256_hash}: {e}")
        return None


def verify_hash(sample_bytes: bytes, expected_sha256: str) -> bool:
    """
    SHA256 integrity check post-extraction.
    If this fails, the sample is corrupted or we got the wrong file.
    """
    actual = hashlib.sha256(sample_bytes).hexdigest().lower()
    expected = expected_sha256.lower()

    if actual != expected:
        logger.error(f"Hash mismatch! Expected: {expected} | Got: {actual}")
        return False

    logger.info(f"Hash verified: {actual}")
    return True


def write_quarantine(sample_bytes: bytes, ioc: dict) -> Path | None:
    """
    Write sample binary + JSON sidecar to quarantine directory.
    Naming convention: <sha256>.<ext> + <sha256>.meta.json
    """
    sha256 = ioc.get("value", "unknown")
    file_info = ioc.get("file_info", {})
    file_ext = file_info.get("type", "bin").lower().strip(".")

    # Sanitize extension
    if not file_ext or len(file_ext) > 10:
        file_ext = "bin"

    sample_path = QUARANTINE_DIR / f"{sha256}.{file_ext}"
    meta_path = QUARANTINE_DIR / f"{sha256}.meta.json"

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Write sample
    with open(sample_path, "wb") as f:
        f.write(sample_bytes)

    # Write sidecar metadata
    meta = {
        "sha256": sha256,
        "md5": ioc.get("hashes", {}).get("md5", ""),
        "sha1": ioc.get("hashes", {}).get("sha1", ""),
        "file_name": file_info.get("name", "unknown"),
        "file_type": file_info.get("type", "unknown"),
        "file_size_bytes": len(sample_bytes),
        "malware_family": ioc.get("context", {}).get("malware_family", "unknown"),
        "tags": ioc.get("context", {}).get("tags", []),
        "source": ioc.get("source", "unknown"),
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "quarantine_path": str(sample_path),
        "hash_verified": True,
        "approved_for_analysis": True,
        "analysis_started": False,
    }

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Quarantined: {sample_path.name}")
    return sample_path


def acquire_approved_samples(api_key: str, checkpoint_file: str = None) -> list[dict]:
    """
    Main acquisition loop.
    Loads approved IOCs → downloads → verifies → quarantines.
    Returns acquisition log entries for each processed sample.
    """
    approved = load_approved_iocs(checkpoint_file)
    if not approved:
        logger.warning("No approved IOCs to acquire. Run checkpoint #1 first.")
        return []

    acquisition_log = []

    for ioc in approved:
        sha256 = ioc.get("value", "")
        if not sha256 or len(sha256) != 64:
            logger.warning(f"Skipping invalid hash: {sha256}")
            continue

        sample_path = QUARANTINE_DIR / f"{sha256}.*"
        # Skip if already quarantined
        existing = list(QUARANTINE_DIR.glob(f"{sha256}.*"))
        if any(p.suffix != ".json" for p in existing):
            logger.info(f"Already quarantined, skipping: {sha256[:16]}...")
            acquisition_log.append({"sha256": sha256, "status": "already_present"})
            continue

        logger.info(f"Acquiring: {sha256[:16]}... ({ioc.get('context', {}).get('malware_family', 'unknown')})")

        # Download - try Bazaar first, fall back to VT
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        zip_bytes = download_from_bazaar(sha256, api_key)
        
        if zip_bytes:
            # Extract from Bazaar ZIP
            sample_bytes = extract_sample_from_zip(zip_bytes, sha256)
            if not sample_bytes:
                acquisition_log.append({"sha256": sha256, "status": "extraction_failed"})
                continue
        else:
            # Bazaar failed - try VT direct download
            logger.info(f"Bazaar failed, trying VirusTotal for {sha256[:16]}...")
            if not vt_key:
                logger.error("VIRUSTOTAL_API_KEY not set, cannot fall back to VT")
                acquisition_log.append({"sha256": sha256, "status": "download_failed"})
                continue
            sample_bytes = download_from_virustotal(sha256, vt_key)
            if not sample_bytes:
                acquisition_log.append({"sha256": sha256, "status": "download_failed"})
                continue

        # Verify
        if not verify_hash(sample_bytes, sha256):
            acquisition_log.append({"sha256": sha256, "status": "hash_mismatch"})
            continue

        # Quarantine
        path = write_quarantine(sample_bytes, ioc)
        if path:
            acquisition_log.append({
                "sha256": sha256,
                "status": "acquired",
                "path": str(path),
                "family": ioc.get("context", {}).get("malware_family", "unknown"),
                "acquired_at": datetime.now(timezone.utc).isoformat(),
            })
        else:
            acquisition_log.append({"sha256": sha256, "status": "write_failed"})

    return acquisition_log


def save_acquisition_log(log: list[dict]) -> None:
    """Write acquisition run log to output/logs/."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = LOG_DIR / f"acquisition_{ts}.json"
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    logger.info(f"Acquisition log saved: {log_path}")


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / "config" / "secrets.env")

    bazaar_key = os.getenv("MALWAREBAZAAR_API_KEY")
    if not bazaar_key:
        logger.error("MALWAREBAZAAR_API_KEY not set in config/.env")
        sys.exit(1)

    log = acquire_approved_samples(bazaar_key)

    print(f"\n{'='*50}")
    print(f"Acquisition complete: {len(log)} samples processed")
    print(f"{'='*50}")

    for entry in log:
        status = entry.get("status", "unknown")
        sha = entry.get("sha256", "")[:16]
        family = entry.get("family", "")
        print(f"  [{status.upper():20s}] {sha}... {family}")

    save_acquisition_log(log)