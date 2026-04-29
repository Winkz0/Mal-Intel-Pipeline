"""
handoff.py
M12 Dynamic Detonation Handoff.
Queries the DB for samples flagged needs_dynamic=True,
bundles the defanged ZIP and analysis JSON, and copies them to an export queue.
"""

import sys
import sqlite3
import shutil
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

DB_PATH = REPO_ROOT / "pipeline.db"
QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
ANALYSIS_DIR = REPO_ROOT / "output" / "analysis"
EXPORT_DIR = REPO_ROOT / "output" / "dynamic_queue"

def get_flagged_samples() -> list[tuple]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Fetch samples that need dynamic analysis but haven't been pushed to the sandbox yet.
    # You can add a 'detonated_at' column later if you want to track sandbox status fully.
    cursor.execute('SELECT sha256, family, triage_score FROM samples WHERE needs_dynamic = 1')
    results = cursor.fetchall()
    conn.close()
    return results

def bundle_for_sandbox():
    flagged = get_flagged_samples()
    if not flagged:
        print("[*] No high-priority samples currently waiting for dynamic analysis.")
        return

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"  Preparing Dynamic Analysis Handoff: {len(flagged)} samples")
    print(f"{'='*60}")

    success_count = 0
    for sha256, family, score in flagged:
        bundle_dir = EXPORT_DIR / f"{sha256}_score{score}_{(family or 'unknown').replace(' ', '')}"
        
        if bundle_dir.exists():
            continue # Already bundled previously
            
        bundle_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Grab the defanged ZIP
        zip_source = QUARANTINE_DIR / f"{sha256}.zip"
        if zip_source.exists():
            shutil.copy2(zip_source, bundle_dir / zip_source.name)
            
        # 2. Grab the Analysis Context (useful for sandbox ingestion tags)
        analysis_source = ANALYSIS_DIR / f"{sha256}.analysis.json"
        if analysis_source.exists():
            shutil.copy2(analysis_source, bundle_dir / analysis_source.name)
            
        print(f"  [+] Bundled: {sha256[:16]}... (Score: {score})")
        success_count += 1

    print(f"\n{'='*60}")
    print(f"  {success_count} new samples staged in {EXPORT_DIR.name}/")
    print(f"{'='*60}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Package high-priority samples for sandbox detonation")
    parser.parse_args()
    bundle_for_sandbox()