"""
register_sample.py
Manual sample registration helper.
Generates a metadata sidecar for samples manually placed in samples/quarantine/.
Allows manually acquired samples to be treated identically to automated downloads
by the static analysis layer (M6).

Usage:
    python register_sample.py <path_to_sample>
    python register_sample.py <path_to_sample> --family Mirai --tags botnet,ddos
"""

import os
import sys
import json
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
try:
    from pipeline.utils.naming import register_alias
    _HAS_NAMING = True
except ImportError:
    _HAS_NAMING = False

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"


def compute_hashes(file_path: Path) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def detect_file_type(file_path: Path) -> str:
    """
    Basic magic byte detection for common malware file types.
    REMnux has 'file' and 'diec' for deeper inspection — this is just
    a quick registration-time hint.
    """
    magic_map = {
        b"MZ": "pe",
        b"\x7fELF": "elf",
        b"PK\x03\x04": "zip/apk",
        b"\xca\xfe\xba\xbe": "macho",
        b"dex\n": "dex",
        b"<?php": "php",
    }

    with open(file_path, "rb") as f:
        header = f.read(16)

    for magic, filetype in magic_map.items():
        if header.startswith(magic):
            return filetype

    return "unknown"


def build_sidecar(file_path: Path, family: str = None, tags: list = None, source: str = "manual") -> dict:
    hashes = compute_hashes(file_path)
    file_type = detect_file_type(file_path)
    file_size = file_path.stat().st_size

    return {
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "file_name": file_path.name,
        "file_type": file_type,
        "file_size_bytes": file_size,
        "malware_family": family or "unknown",
        "tags": tags or [],
        "source": source,
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "quarantine_path": str(file_path),
        "hash_verified": True,
        "approved_for_analysis": True,
        "analysis_started": False,
        "registration_method": "manual",
    }


def register_sample(sample_path: Path, family: str = None, tags: list = None) -> Path | None:
    if not sample_path.exists():
        print(f"[!] File not found: {sample_path}")
        return None

    # If sample isn't already in quarantine, move it there
    if sample_path.parent != QUARANTINE_DIR:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        dest = QUARANTINE_DIR / sample_path.name
        sample_path.rename(dest)
        sample_path = dest
        print(f"[*] Moved sample to quarantine: {dest}")

    print(f"[*] Computing hashes for {sample_path.name}...")
    sidecar = build_sidecar(sample_path, family=family, tags=tags)

    sha256 = sidecar["sha256"]
    meta_path = QUARANTINE_DIR / f"{sha256}.meta.json"

    with open(meta_path, "w") as f:
        json.dump(sidecar, f, indent=2)

    print(f"\n{'='*55}")
    print(f"  Sample registered successfully")
    print(f"{'='*55}")
    print(f"  File     : {sidecar['file_name']}")
    print(f"  Type     : {sidecar['file_type']}")
    print(f"  Size     : {sidecar['file_size_bytes']:,} bytes")
    print(f"  SHA256   : {sha256}")
    print(f"  MD5      : {sidecar['md5']}")
    print(f"  Family   : {sidecar['malware_family']}")
    print(f"  Tags     : {', '.join(sidecar['tags']) or 'none'}")
    print(f"  Sidecar  : {meta_path.name}")
    print(f"{'='*55}")

    # Prompt for human-readable alias
    if _HAS_NAMING:
        alias_input = input("  Enter sample alias (e.g. SmokeLoader_033126) or press Enter to skip: ").strip()
        if alias_input:
            register_alias(sha256, alias_input)
            print(f"  [+] Alias registered: {alias_input}")
    else:
        print("  [~] Naming module not available — alias skipped")
        
    return meta_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Register a manually acquired malware sample into the pipeline quarantine."
    )
    parser.add_argument("sample", help="Path to the sample file")
    parser.add_argument("--family", default=None, help="Malware family name (e.g. Mirai, Emotet)")
    parser.add_argument("--tags", default=None, help="Comma-separated tags (e.g. botnet,ddos,apk)")
    parser.add_argument("--source", default="manual", help="Acquisition source label (default: manual)")
    args = parser.parse_args()

    sample_path = Path(args.sample).resolve()
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []

    register_sample(sample_path, family=args.family, tags=tags)