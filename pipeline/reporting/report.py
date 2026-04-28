"""
report.py
M8 Report Generation Orchestrator.
Loads synthesis JSON and produces all human-readable outputs.

Usage:
    python report.py <sha256>
    python report.py --all
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from pipeline.rag.indexer import index_corpus
from pipeline.delta_analysis.delta import generate_delta
import os

# 1. RESOLVE PATH FIRST
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# 2. THEN IMPORT FROM PIPELINE
from pipeline.utils.db import get_samples_by_status, update_status
from pipeline.reporting.report_builder import (
    render_technical_report,
    render_executive_summary,
    save_report,
)
from pipeline.reporting.rule_extractor import extract_yara, extract_sigma

logger = logging.getLogger(__name__)

REPORTS_DIR = REPO_ROOT / "output" / "reports"


def load_synthesis(sha256: str) -> dict | None:
    # Try exact match first
    path = REPORTS_DIR / f"{sha256}.synthesis.json"
    if not path.exists():
        # Partial match
        matches = list(REPORTS_DIR.glob(f"{sha256}*.synthesis.json"))
        if not matches:
            logger.error(f"No synthesis file found for: {sha256[:16]}...")
            return None
        path = matches[0]

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_reports(sha256: str) -> None:
    synthesis = load_synthesis(sha256)
    if not synthesis:
        return

    sample = synthesis.get("sample", {})
    actual_sha256 = sample.get("sha256", sha256)
    family = sample.get("malware_family", "unknown")

    print(f"\n{'='*60}")
    print(f"  Generating reports: {actual_sha256[:32]}...")
    print(f"{'='*60}")

    # Technical report
    technical_md = render_technical_report(synthesis)
    tech_path = save_report(
        technical_md,
        REPORTS_DIR / f"{actual_sha256}.technical.md"
    )
    print(f"  [+] Technical report : {tech_path.name}")

    # Executive summary
    executive_md = render_executive_summary(synthesis)
    exec_path = save_report(
        executive_md,
        REPORTS_DIR / f"{actual_sha256}.executive.md"
    )
    print(f"  [+] Executive summary: {exec_path.name}")

    # YARA rule
    yara_rule, yara_path = extract_yara(synthesis)
    if yara_path:
        print(f"  [+] YARA rule        : {yara_path.name}")
    else:
        print(f"  [-] YARA rule        : skipped (dry run or not generated)")

    # Sigma rule
    sigma_rule, sigma_path = extract_sigma(synthesis)
    if sigma_path:
        print(f"  [+] Sigma rule       : {sigma_path.name}")
    else:
        print(f"  [-] Sigma rule       : skipped (dry run or not generated)")

    update_status(actual_sha256, 'REPORTED')
    
    # NEW: Update DB and Cleanup Storage
    zip_path = REPO_ROOT / "samples" / "quarantine" / f"{actual_sha256}.zip"
    meta_path = REPO_ROOT / "samples" / "quarantine" / f"{actual_sha256}.meta.json"
    
    if zip_path.exists():
        try:
            os.remove(zip_path)
            print(f"  [+] Storage cleanup  : Removed {zip_path.name} to save disk space")
        except Exception as e:
            print(f"  [!] Storage cleanup  : Failed to remove {zip_path.name} ({e})")
            
    if meta_path.exists():
        try:
            os.remove(meta_path)
            print(f"  [+] Storage cleanup  : Removed {meta_path.name}")
        except Exception as e:
            import traceback
            print(f"  [!] Storage cleanup  : Failed to remove {meta_path.name} ({e})")
            traceback.print_exec()

        # Incremental RAG reindex — keeps vector store current
    try:
        count = index_corpus()
        print(f"  [+] RAG reindex      : {count} chunks indexed")
    except Exception as e:
        print(f"  [!] RAG reindex      : Failed ({e})")

# Auto-run delta analysis against corpus
    try:
        generate_delta(actual_sha256)
        print(f"  [+] Delta analysis   : Complete")
    except Exception as e:
        print(f"  [!] Delta analysis   : Failed ({e})")

def get_pending_reports() -> list[str]:
    return get_samples_by_status('SYNTHESIZED')


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M8 Report Generation Orchestrator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 (or prefix) of sample to report")
    group.add_argument("--all", action="store_true", help="Generate reports for all synthesis files")
    args = parser.parse_args()

    if args.all:
        hashes = get_pending_reports()
        print(f"Found {len(hashes)} sample(s) pending report generation")
        for h in hashes:
            generate_reports(h)
    else:
        generate_reports(args.sha256)