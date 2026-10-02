"""
analyze.py
M6 Static Analysis Orchestrator.
Runs all four tools against a sample, normalizes output,
saves unified analysis JSON to output/analysis/.

Usage:
    python analyze.py <sha256>
    python analyze.py --all
"""

import os
import re
import sys
import hashlib
import logging
import argparse
from pathlib import Path, PurePosixPath
import shutil
import pyzipper
import concurrent.futures

# 1. RESOLVE PATH FIRST
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# 2. THEN IMPORT FROM PIPELINE
from pipeline.utils.db import get_samples_by_status, update_status
from pipeline.static_analysis.run_floss import run_floss
from pipeline.static_analysis.run_capa import run_capa
from pipeline.static_analysis.run_diec import run_diec
from pipeline.static_analysis.run_pefile import run_pefile
from pipeline.static_analysis.normalizer import normalize, save_analysis, load_meta
from pipeline.scoring.triage import calculate_score

logger = logging.getLogger(__name__)

QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
OUTPUT_DIR = REPO_ROOT / "output" / "analysis"

ZIP_PASSWORD = b"infected"
_EXT_RE = re.compile(r"^[a-z0-9]{1,10}$")


class SampleExtractionError(RuntimeError):
    """The quarantine zip can't be turned into the sample it claims to hold."""


def _pick_member(zf, sha256: str):
    """
    Choose the sample inside the zip without trusting the sidecar's file_type.

    MalwareBazaar names the member <sha256>.<ext>; manual downloads and honeypot
    captures may not. Take the one member whose basename starts with the hash,
    otherwise the archive's only file. Anything else is ambiguous and refused.
    """
    files = [i for i in zf.infolist() if not i.is_dir()]
    named = [i for i in files if PurePosixPath(i.filename).name.lower().startswith(sha256)]
    if len(named) == 1:
        return named[0]
    if not named and len(files) == 1:
        return files[0]
    raise SampleExtractionError(
        f"can't choose a member: {len(files)} file(s) in zip, {len(named)} named after the hash"
    )


def _member_ext(member_name: str, meta_type: str) -> str:
    """Extension from the member name; fall back to the sidecar, then 'bin'."""
    ext = PurePosixPath(member_name).suffix.lstrip(".").lower()
    if _EXT_RE.match(ext):
        return ext
    meta_type = (meta_type or "").lower()
    if meta_type != "unknown" and _EXT_RE.match(meta_type):
        return meta_type
    return "bin"


def extract_to_ram(zip_path: Path, sha256: str, ram_disk_dir: Path, meta: dict):
    """
    Stream the sample into the RAM disk and prove it is the hash we expect.

    The output name is always <sha256>.<ext>, so no path stored in the archive
    ever reaches the filesystem. Returns (bin_path, ext, {"md5", "sha1"}).
    Raises SampleExtractionError on an ambiguous archive or a hash mismatch.
    """
    md5, sha1, sha = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(ZIP_PASSWORD)
        member = _pick_member(zf, sha256)
        ext = _member_ext(member.filename, meta.get("file_type", ""))
        bin_path = ram_disk_dir / f"{sha256}.{ext}"
        with zf.open(member) as src, open(bin_path, "wb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha.update(chunk)
                dst.write(chunk)
    if sha.hexdigest() != sha256:
        raise SampleExtractionError(
            f"SHA-256 mismatch: member '{member.filename}' hashes to {sha.hexdigest()}"
        )
    return bin_path, ext, {"md5": md5.hexdigest(), "sha1": sha1.hexdigest()}


def analyze_sample(sha256: str) -> dict | None:
    zip_path = QUARANTINE_DIR / f"{sha256}.zip"
    if not zip_path.exists():
        logger.error(f"Defanged ZIP not found in quarantine: {sha256[:16]}...")
        return None

    print(f"\n{'='*60}")
    print(f"  Analyzing: {zip_path.name}")
    print(f"{'='*60}")

    meta = dict(load_meta(sha256, QUARANTINE_DIR))

    # 1. Setup RAM Disk
    ram_disk_dir = Path("/dev/shm") / f"malware_{sha256}"
    ram_disk_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 2. Extract to RAM; the hash is verified before any tool touches the bytes
        try:
            bin_path, file_ext, hashes = extract_to_ram(zip_path, sha256, ram_disk_dir, meta)
        except (RuntimeError, pyzipper.BadZipFile) as exc:
            # RuntimeError covers SampleExtractionError and a wrong zip password
            print(f"  [!] Extraction refused: {exc}")
            return None
        print(f"  [+] Extracted {bin_path.name} to RAM disk; SHA-256 verified")

        # Fill sidecar gaps from the verified bytes (manual and honeypot intake
        # arrive without MalwareBazaar metadata)
        for key in ("md5", "sha1"):
            if not meta.get(key):
                meta[key] = hashes[key]
        if str(meta.get("file_type", "")).lower() in ("", "unknown"):
            meta["file_type"] = file_ext
        if not meta.get("file_size_bytes"):
            meta["file_size_bytes"] = bin_path.stat().st_size

        # 3. Run tools against the RAM-disk binary
        print("  [1/4] FLOSS — string extraction...")
        floss_result = run_floss(bin_path)
        print(f"        {'✓' if floss_result['success'] else '✗'} "
              f"{floss_result['summary']['total_static']} static strings, "
              f"{len(floss_result['summary']['notable'])} notable")

        print("  [2/4] Capa — capability detection...")
        capa_result = run_capa(bin_path)
        print(f"        {'✓' if capa_result['success'] else '✗'} "
              f"{capa_result['summary']['total_capabilities']} capabilities, "
              f"{capa_result['summary']['total_attack_ttps']} ATT&CK TTPs")

        print("  [3/4] diec — file type detection...")
        diec_result = run_diec(bin_path)
        print(f"        {'✓' if diec_result['success'] else '✗'} "
              f"{diec_result['summary']['file_type'] or 'unknown type'}")

        print("  [4/4] pefile — PE header analysis...")
        pefile_result = run_pefile(bin_path)
        print(f"        {'✓' if pefile_result['success'] else '✗'} "
              f"{'PE parsed' if pefile_result['is_pe'] else 'not a PE — skipped'}")

        analysis = normalize(
            sha256=sha256,
            floss_result=floss_result,
            capa_result=capa_result,
            diec_result=diec_result,
            pefile_result=pefile_result,
            meta=meta,
        )
        analysis["sample"]["sha256_verified"] = True

        out_path = save_analysis(analysis)
        update_status(sha256, 'ANALYZED')
    
        # New: Execute Triage Scoring (Now properly indented inside the try block)
        triage = calculate_score(analysis)
        from pipeline.utils.db import update_triage_score
        update_triage_score(sha256, triage['score'], triage['needs_dynamic'])
        
        print(f"\n Triage Score   : {triage['score']}")
        if triage['needs_dynamic']:
            print(" [!] Flagged for Dynamic Detonation (Score >= 50)")
        
        print("\n  IOC Candidates:")
        iocs = analysis["ioc_candidates"]
        print(f"    IPs      : {len(iocs['ips'])}")
        print(f"    URLs     : {len(iocs['urls'])}")
        print(f"    Commands : {len(iocs['commands'])}")
        print(f"\n  Analysis saved: {out_path.name}")
        print(f"{'='*60}")

        return analysis

    finally:
        # 4. INSTANT WIPE: This runs even if a tool crashes the script
        if ram_disk_dir.exists():
            shutil.rmtree(ram_disk_dir)
            print(f"  [*] Volatile RAM disk wiped for {sha256[:16]}...")


def get_pending_analyses() -> list[str]:
    return get_samples_by_status('ACQUIRED')

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M6 Static Analysis Orchestrator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 of sample to analyze")
    group.add_argument("--all", action="store_true", help="Analyze all quarantined samples")
    args = parser.parse_args()

    if args.all:
        hashes = get_pending_analyses()
        print(f"Found {len(hashes)} sample(s) pending analysis in database")
        
        # Leave 1 core free for the OS to prevent the VM from locking up
        max_workers = max(1, os.cpu_count() - 1)
        print(f"[*] Starting parallel analysis using {max_workers} CPU cores...")
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(analyze_sample, h): h for h in hashes}
            for future in concurrent.futures.as_completed(futures):
                h = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"  [!] Analysis for {h[:16]} generated an exception: {exc}")
    else:
        sys.exit(0 if analyze_sample(args.sha256.strip().lower()) else 1)