"""
M5: Sample Acquisition Module
Pulls approved malware samples from MalwareBazaar. 
Only processes IOCs flagged approved_for_analysis=True from checkpoint state.
"""

import os
import sys
import json
import hashlib
import logging
import io
import requests
import pyzipper
from pathlib import Path
from datetime import datetime, timezone
import concurrent.futures

logger = logging.getLogger(__name__)

# Resolve the root directory so Python can find the 'pipeline' module
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.utils.db import update_status

# Paths
QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
CHECKPOINT_DIR = REPO_ROOT / "checkpoints" # Ensure this matches your ingest.py output
LOG_DIR = REPO_ROOT / "output" / "logs"

BAZAAR_ZIP_PASSWORD = b"infected"  # Standard MalwareBazaar ZIP password


def load_approved_iocs(checkpoint_file: str = None) -> list[dict]:
    """
    Load IOCs approved at checkpoint #1.
    If no checkpoint_file specified, auto-selects the most recent
    checkpoint1_*.json file in the checkpoints directory.
    """
    if checkpoint_file:
        cp_path = CHECKPOINT_DIR / checkpoint_file
    else:
        # Create dir if it doesn't exist yet
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
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
    Download a sample ZIP from MalwareBazaar using native OS wget.
    Bypasses Cloudflare JA3/TLS fingerprinting that blocks Python's requests library.
    """
    import subprocess
    import json

    # Construct the exact wget command validated on REMnux
    cmd = [
        "wget",
        "-q",  # Quiet mode: suppress progress bars to keep the byte stream clean
        "--header", f"Auth-Key: {api_key}",
        "--post-data", f"query=get_file&sha256_hash={sha256_hash}",
        "https://mb-api.abuse.ch/api/v1/",
        "-O", "-"  # Output directly to standard out
    ]

    try:
        # Execute wget and capture the raw binary output directly into memory
        result = subprocess.run(cmd, capture_output=True, check=True)
        content = result.stdout

        # Verify we got the ZIP payload (starts with 'PK')
        if content.startswith(b"PK"):
            return content
            
        # If it's not a ZIP, read the JSON error message
        try:
            err = json.loads(content.decode('utf-8', errors='ignore'))
            logger.warning(f"Bazaar API error for {sha256_hash}: {err.get('query_status')}")
        except Exception:
            logger.error(f"Unknown response format from Bazaar for {sha256_hash}")
            
        return None

    except subprocess.CalledProcessError as e:
        logger.error(f"Wget execution failed for {sha256_hash}: {e}")
        # If wget fails, stderr might contain useful hints (like DNS or SSL errors)
        if e.stderr:
            logger.error(f"Wget error output: {e.stderr.decode('utf-8', errors='ignore')}")
        return None

    except subprocess.CalledProcessError as e:
        logger.error(f"Curl execution failed for {sha256_hash}: {e}")
        return None


def extract_sample_from_zip(zip_bytes: bytes, sha256_hash: str) -> bytes | None:
    """
    Extract the malware binary from the AES-encrypted ZIP using pyzipper.
    """
    try:
        with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            if not names:
                logger.error(f"Empty ZIP for {sha256_hash}")
                return None
            
            zf.pwd = BAZAAR_ZIP_PASSWORD
            sample_bytes = zf.read(names[0])
            logger.debug(f"Extracted {names[0]} from ZIP ({len(sample_bytes)} bytes)")
            return sample_bytes
    except Exception as e:
        logger.error(f"Failed to extract {sha256_hash}: {e}")
        return None


def verify_hash(sample_bytes: bytes, expected_sha256: str) -> bool:
    """SHA256 integrity check post-extraction."""
    actual = hashlib.sha256(sample_bytes).hexdigest().lower()
    expected = expected_sha256.lower()

    if actual != expected:
        logger.error(f"Hash mismatch! Expected: {expected} | Got: {actual}")
        return False

    return True


def write_quarantine(sample_bytes: bytes, ioc: dict) -> Path | None:
    """
    Write sample binary + JSON sidecar to quarantine directory securely.
    """
    sha256 = ioc.get("value", "unknown")
    file_info = ioc.get("file_info", {})
    file_ext = file_info.get("type", "bin").lower().strip(".")

    if not file_ext or len(file_ext) > 10:
        file_ext = "bin"

    sample_path = QUARANTINE_DIR / f"{sha256}.zip"
    meta_path = QUARANTINE_DIR / f"{sha256}.meta.json"

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Secure repackaging
    with pyzipper.AESZipFile(sample_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b'infected')
        zf.writestr(f"{sha256}.{file_ext}", sample_bytes)

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

    # Log to the database pipeline
    update_status(sha256, 'ACQUIRED', meta.get("malware_family", "unknown"))

    logger.info(f"Quarantined and Defanged: {sample_path.name}")
    return sample_path


def acquire_approved_samples(api_key: str, checkpoint_file: str = None) -> list[dict]:
    """
    Main threaded acquisition loop.
    """
    approved = load_approved_iocs(checkpoint_file)
    if not approved:
        logger.warning("No approved IOCs to acquire. Run checkpoint #1 first.")
        return []

    def process_ioc(ioc):
        sha256 = ioc.get("value", "")
        if not sha256 or len(sha256) != 64:
            logger.warning(f"Skipping invalid hash: {sha256}")
            return None

        zip_path = QUARANTINE_DIR / f"{sha256}.zip"
        if zip_path.exists():
            logger.info(f"Already quarantined, skipping: {sha256[:16]}...")
            return {"sha256": sha256, "status": "already_present"}

        logger.info(f"Acquiring: {sha256[:16]}... ({ioc.get('context', {}).get('malware_family', 'unknown')})")

        zip_bytes = download_from_bazaar(sha256, api_key)
        
        if zip_bytes:
            sample_bytes = extract_sample_from_zip(zip_bytes, sha256)
            if not sample_bytes:
                return {"sha256": sha256, "status": "extraction_failed"}
        else:
            return {"sha256": sha256, "status": "download_failed"}

        if not verify_hash(sample_bytes, sha256):
            return {"sha256": sha256, "status": "hash_mismatch"}

        path = write_quarantine(sample_bytes, ioc)
        if path:
            return {
                "sha256": sha256,
                "status": "acquired",
                "path": str(path),
                "family": ioc.get("context", {}).get("malware_family", "unknown"),
                "acquired_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            return {"sha256": sha256, "status": "write_failed"}

    acquisition_log = []

    print(f"[*] Starting parallel acquisition of {len(approved)} samples...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_ioc, ioc) for ioc in approved]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                acquisition_log.append(result)

    return acquisition_log


def save_acquisition_log(log: list[dict]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = LOG_DIR / f"acquisition_{ts}.json"
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    logger.info(f"Acquisition log saved: {log_path}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    from dotenv import load_dotenv
    
    # Force override to bypass any cached environment variables
    load_dotenv(REPO_ROOT / "config" / "secrets.env", override=True)
    load_dotenv(REPO_ROOT / "config" / ".env", override=True)

    bazaar_key = os.getenv("MALWAREBAZAAR_API_KEY")
    if not bazaar_key:
        logger.error("MALWAREBAZAAR_API_KEY not set in config/.env or secrets.env")
        sys.exit(1)
        
    # Strip any accidental formatting from the text file
    # bazaar_key = bazaar_key.strip().strip('"\'')
    
    print(f"[*] Pipeline is authenticating with key ending in: ...{bazaar_key[-4:]}")

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