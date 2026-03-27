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

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.static_analysis.run_floss import run_floss
from pipeline.static_analysis.run_capa import run_capa
from pipeline.static_analysis.run_diec import run_diec
from pipeline.static_analysis.run_pefile import run_pefile
from pipeline.static_analysis.normalizer import normalize, save_analysis, load_meta

logger = logging.getLogger(__name__)

QUARANTINE_DIR = REPO_ROOT / "samples" / "quarantine"
OUTPUT_DIR = REPO_ROOT / "output" / "analysis"


def find_sample(sha256: str) -> Path | None:
    """Locate sample file in quarantine by SHA256 prefix match."""
    matches = [
        p for p in QUARANTINE_DIR.iterdir()
        if p.stem.startswith(sha256) and p.suffix != ".json"
    ]
    return matches[0] if matches else None


def analyze_sample(sha256: str) -> dict | None:
    sample_path = find_sample(sha256)
    if not sample_path:
        logger.error(f"Sample not found in quarantine: {sha256[:16]}...")
        return None

    print(f"\n{'='*60}")
    print(f"  Analyzing: {sample_path.name}")
    print(f"{'='*60}")

    meta = load_meta(sha256, QUARANTINE_DIR)

    print(f"  [1/4] FLOSS — string extraction...")
    floss_result = run_floss(sample_path)
    print(f"        {'✓' if floss_result['success'] else '✗'} "
          f"{floss_result['summary']['total_static']} static strings, "
          f"{len(floss_result['summary']['notable'])} notable")

    print(f"  [2/4] Capa — capability detection...")
    capa_result = run_capa(sample_path)
    print(f"        {'✓' if capa_result['success'] else '✗'} "
          f"{capa_result['summary']['total_capabilities']} capabilities, "
          f"{capa_result['summary']['total_attack_ttps']} ATT&CK TTPs")

    print(f"  [3/4] diec — file type detection...")
    diec_result = run_diec(sample_path)
    print(f"        {'✓' if diec_result['success'] else '✗'} "
          f"{diec_result['summary']['file_type'] or 'unknown type'}")

    print(f"  [4/4] pefile — PE header analysis...")
    pefile_result = run_pefile(sample_path)
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

    print(f"\n  IOC Candidates:")
    iocs = analysis["ioc_candidates"]
    print(f"    IPs      : {len(iocs['ips'])}")
    print(f"    URLs     : {len(iocs['urls'])}")
    print(f"    Commands : {len(iocs['commands'])}")
    print(f"\n  Analysis saved: {out_path.name}")
    print(f"{'='*60}")

    return analysis


def get_all_quarantined_hashes() -> list[str]:
    return [
        p.stem for p in QUARANTINE_DIR.iterdir()
        if p.suffix != ".json" and not p.name.startswith(".")
    ]


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
        hashes = get_all_quarantined_hashes()
        print(f"Found {len(hashes)} sample(s) in quarantine")
        for h in hashes:
            analyze_sample(h)
    else:
        analyze_sample(args.sha256)