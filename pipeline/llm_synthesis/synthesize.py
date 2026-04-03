"""
synthesize.py
M7 LLM Synthesis Orchestrator.
Loads analysis JSON, runs checkpoint #2, calls Claude API,
saves structured synthesis output.

Usage:
    python synthesize.py <sha256>
    python synthesize.py <sha256> --dry-run
"""

import os
import sys
import logging
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / "config" / "secrets.env")

from pipeline.llm_synthesis.prompt_builder import build_synthesis_prompt, estimate_cost
from pipeline.llm_synthesis.synthesizer import load_analysis, synthesize, save_synthesis
from pipeline.llm_synthesis.checkpoint2 import run_checkpoint2

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M7 LLM Synthesis Orchestrator")
    parser.add_argument("sha256", help="SHA256 of sample to synthesize")
    parser.add_argument("--dry-run", action="store_true", help="Skip API call, return placeholder output")
    parser.add_argument("--skip-checkpoint", action="store_true", help="Skip checkpoint #2 review")
    parser.add_argument("--no-raw", action="store_true", help="Suppress raw_response in synthesis JSON (still logged to output/logs/raw_responses/)")
    args = parser.parse_args()

    # Load analysis
    analysis = load_analysis(args.sha256)
    if not analysis:
        print(f"[!] No analysis found for {args.sha256[:16]}...")
        sys.exit(1)

    # Build prompt
    prompt = build_synthesis_prompt(analysis)
    cost = estimate_cost(prompt)

    # Checkpoint #2
    dry_run = args.dry_run
    analyst_notes = ""

    if not args.skip_checkpoint:
        decision, analyst_notes = run_checkpoint2(analysis, cost)
        if decision is False:
            sys.exit(0)
        if decision == "dry":
            dry_run = True

    # Inject analyst notes into prompt if provided
    if analyst_notes:
        prompt += f"\n\n## Analyst Notes\n{analyst_notes}"

    # Synthesize
    result = synthesize(
        analysis=analysis,
        prompt=prompt,
        dry_run=dry_run,
        cost_estimate=cost,
    )

    if result["error"]:
        print(f"\n[!] Synthesis failed: {result['error']}")
        sys.exit(1)
    
    if args.no_raw:
        result["raw_response"] = None
    
    # Save
    out_path = save_synthesis(result)

    print(f"\n{'='*60}")
    print(f"  Synthesis {'(DRY RUN) ' if dry_run else ''}complete")
    print(f"{'='*60}")

    if not dry_run and result["synthesis"]:
        s = result["synthesis"]
        ttp = s.get("ttp_mapping", {})
        yara = s.get("yara_rule", {})
        sigma = s.get("sigma_rule", {})
        report = s.get("technical_report", {})

        print(f"  TTP Confidence   : {ttp.get('confidence', 'n/a')}")
        print(f"  TTPs Mapped      : {len(ttp.get('techniques', []))}")
        print(f"  YARA Confidence  : {yara.get('confidence', 'n/a')}")
        print(f"  Sigma Confidence : {sigma.get('confidence', 'n/a')}")
        print(f"  Key Indicators   : {len(report.get('key_indicators', []))}")

    print(f"\n  Output: {out_path.name}")
    print(f"{'='*60}")