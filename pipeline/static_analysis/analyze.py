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
import sys
import json
import logging
import argparse
from pathlib import Path
import shutil
import pyzipper
from pipeline.utils.db import get_samples_by_status, update_status
import concurrent.futures

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.static_analysis.run_floss import run_floss
from pipeline.static_analysis.run_capa import run_capa
from pipeline.static_analysis.run_diec import run_diec
from pipeline.static_analysis.run_pefile import run_pefile
from pipeline.static_analysis.normalizer import normalize, save_analysis, load_meta
from pipeline.scoring.triage import calculate_score

logger = logging.getLogger(__name__)

QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
OUTPUT_DIR = REPO_ROOT / "output" / "analysis"


def analyze_sample(sha256: str) -> dict | None:
    zip_path = QUARANTINE_DIR / f"{sha256}.zip"
    if not zip_path.exists():
        logger.error(f"Defanged ZIP not found in quarantine: {sha256[:16]}...")
        return None

    print(f"\n{'='*60}")
    print(f"  Analyzing: {zip_path.name}")
    print(f"{'='*60}")

    meta = load_meta(sha256, QUARANTINE_DIR)

  # 1. Setup RAM Disk
    ram_disk_dir = Path("/dev/shm") / f"malware_{sha256}"
    ram_disk_dir.mkdir(parents=True, exist_ok=True)
    
    file_ext = meta.get("file_type", "bin").lower()
    if file_ext == "unknown":
        file_ext = "bin"
    bin_path = ram_disk_dir / f"{sha256}.{file_ext}"

    try:
        # 2. Safely extract to RAM
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.pwd = b'infected'
            zf.extract(f"{sha256}.{file_ext}", path=ram_disk_dir)

        # 3. Run tools against the RAM-disk binary
        print(f"  [1/4] FLOSS — string extraction...")
        floss_result = run_floss(bin_path)
        print(f"        {'✓' if floss_result['success'] else '✗'} "
              f"{floss_result['summary']['total_static']} static strings, "
              f"{len(floss_result['summary']['notable'])} notable")

        print(f"  [2/4] Capa — capability detection...")
        capa_result = run_capa(bin_path)
        print(f"        {'✓' if capa_result['success'] else '✗'} "
              f"{capa_result['summary']['total_capabilities']} capabilities, "
              f"{capa_result['summary']['total_attack_ttps']} ATT&CK TTPs")

        print(f"  [3/4] diec — file type detection...")
        diec_result = run_diec(bin_path)
        print(f"        {'✓' if diec_result['success'] else '✗'} "
              f"{diec_result['summary']['file_type'] or 'unknown type'}")

        print(f"  [4/4] pefile — PE header analysis...")
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

        out_path = save_analysis(analysis)
        update_status(sha256, 'ANALYZED')
    
    # New: Execute Triage Scoring
    triage = calculate_score(analysis)
    from pipeline.utils.db import update_triage_score
    update_triage_score(sha256, triage['score'], triage['needs_dynamic'])
    
    print(f"\n Triage Score   : {triage['score']}")
    if triage['needs_dynamic']:
        print(f" [!] Flagged for Dynamic Detonation (Score >= 50)")
    

    print(f"\n  IOC Candidates:")
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
        analyze_sample(args.sha256)