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
import concurrent.futures

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / "config" / "secrets.env")

from pipeline.llm_synthesis.prompt_builder import build_synthesis_prompt, estimate_cost
from pipeline.llm_synthesis.synthesizer import load_analysis, synthesize, save_synthesis
from pipeline.llm_synthesis.checkpoint2 import run_checkpoint2

logger = logging.getLogger(__name__)

# NEW: Wrap core logic into a reusable function
def process_synthesis(sha256: str, dry_run: bool, skip_checkpoint: bool, no_raw: bool):
    analysis = load_analysis(sha256)
    if not analysis:
        print(f"[!] No analysis found for {sha256[:16]}...")
        return False

    prompt = build_synthesis_prompt(analysis)
    cost = estimate_cost(prompt)

    analyst_notes = ""
    if not skip_checkpoint:
        decision, analyst_notes = run_checkpoint2(analysis, cost)
        if decision is False:
            return False
        if decision == "dry":
            dry_run = True

    if analyst_notes:
        prompt += f"\n\n## Analyst Notes\n{analyst_notes}"

    result = synthesize(analysis=analysis, prompt=prompt, dry_run=dry_run, cost_estimate=cost)

    if result["error"]:
        print(f"\n[!] Synthesis failed for {sha256[:16]}: {result['error']}")
        return False
    
    if no_raw:
        result["raw_response"] = None
    
    out_path = save_synthesis(result)
    
    # Database update from earlier
    from pipeline.utils.db import update_status
    update_status(sha256, 'SYNTHESIZED')
    
    print(f"  [+] Synthesis complete for {sha256[:16]}... -> {out_path.name}")
    return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M7 LLM Synthesis Orchestrator")
    # NEW: Replace `parser.add_argument("sha256", ...)` with a mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 of sample to synthesize")
    group.add_argument("--all", action="store_true", help="Synthesize all samples pending synthesis")
    parser.add_argument("--dry-run", action="store_true", help="Skip API call, return placeholder output")
    parser.add_argument("--skip-checkpoint", action="store_true", help="Skip checkpoint #2 review")
    parser.add_argument("--no-raw", action="store_true", help="Suppress raw_response in synthesis JSON (still logged to output/logs/raw_responses/)")
    args = parser.parse_args()

   # NEW: Execution routing
    if args.all:
        from pipeline.utils.db import get_samples_by_status
        hashes = get_samples_by_status('ANALYZED')
        print(f"Found {len(hashes)} sample(s) pending synthesis.")
        
        # Interactive checkpoints don't work well when 5 threads prompt at the same time
        if not args.skip_checkpoint:
            print("  [!] Warning: Running batch synthesis. Auto-skipping Checkpoint #2.")
            args.skip_checkpoint = True
        
        # 5 is a safe concurrency limit for Claude/OpenAI APIs to avoid rate-limiting
        print(f"[*] Starting parallel LLM synthesis (max 5 concurrent calls)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(process_synthesis, h, args.dry_run, args.skip_checkpoint, args.no_raw): h 
                for h in hashes
            }
            for future in concurrent.futures.as_completed(futures):
                h = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"  [!] Synthesis for {h[:16]} generated an exception: {exc}")
    else:
        # Single run behavior
        process_synthesis(args.sha256, args.dry_run, args.skip_checkpoint, args.no_raw)