"""
reset_pipeline.py
Automates the 'Clean Slate' protocol to prep the environment for a new batch of IOCs.
Safely wipes the database, empties output directories, and verifies quarantine hygiene.

Usage:
    python reset_pipeline.py
"""

import os
import shutil
from pathlib import Path

# 1. Resolve the project root dynamically
REPO_ROOT = Path(__file__).resolve().parent

# 2. Define the exact targets
DB_PATH = REPO_ROOT / "pipeline.db"

# ONLY delete the heavy, raw analysis data. Keep the finished intelligence!
TARGET_DIRS = [
    REPO_ROOT / "output" / "analysis"
]
QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"

def delete_database():
    """Safely removes the SQLite database."""
    if DB_PATH.exists():
        try:
            DB_PATH.unlink()
            print(f"  [+] Deleted  : {DB_PATH.name}")
        except Exception as e:
            print(f"  [!] Error deleting database: {e}")
    else:
        print(f"  [~] Skipped  : {DB_PATH.name} (Already deleted or missing)")

def empty_directory(target_dir: Path):
    """Deletes all contents inside a directory without deleting the directory itself."""
    if not target_dir.exists():
        print(f"  [~] Skipped  : {target_dir.relative_to(REPO_ROOT)}/ (Directory missing)")
        return
        
    try:
        count = 0
        for item in target_dir.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
            count += 1
        print(f"  [+] Emptied  : {target_dir.relative_to(REPO_ROOT)}/ (Removed {count} items)")
    except Exception as e:
        print(f"  [!] Error emptying {target_dir.name}: {e}")

def verify_quarantine():
    """Checks if the quarantine folder is actually empty."""
    if not QUARANTINE_DIR.exists():
        print(f"  [~] Warning  : {QUARANTINE_DIR.relative_to(REPO_ROOT)}/ directory is missing entirely.")
        return

    remaining_files = list(QUARANTINE_DIR.iterdir())
    if not remaining_files:
        print(f"  [+] Verified : {QUARANTINE_DIR.relative_to(REPO_ROOT)}/ is completely empty.")
    else:
        print(f"\n  [!] WARNING  : QUARANTINE IS NOT EMPTY!")
        print(f"      Found {len(remaining_files)} rogue item(s) left behind:")
        for item in remaining_files:
            print(f"      - {item.name}")

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  Initiating Clean Slate Protocol...")
    print(f"{'='*60}\n")

    delete_database()
    
    for directory in TARGET_DIRS:
        empty_directory(directory)
        
    print(f"\n{'-'*60}")
    verify_quarantine()
    print(f"{'='*60}\n")