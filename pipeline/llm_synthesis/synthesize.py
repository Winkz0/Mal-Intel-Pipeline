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
import copy
from pathlib import Path
import concurrent.futures

# 1. Truncation Helper Function
def truncate_heavy_data(analysis_dict: dict, max_items: int = 500, max_str_len: int = 256) -> dict:
    """
    Creates a minified version of the JSON payload by slicing massive lists
    and capping the character length of insanely long concatenated strings.
    Prevents token-limit exceptions and saves API costs on packed/Golang malware.
    """
    truncated = copy.deepcopy(analysis_dict)
    static = truncated.get("static_analysis", {})
    
    # 1. Cap FLOSS Strings
    if "floss" in static and "notable_strings" in static["floss"]:
        strings = static["floss"]["notable_strings"]
        
        # Cap the length of each individual string (Critical for Go binaries)
        minified_strings = []
        for s in strings:
            if isinstance(s, str) and len(s) > max_str_len:
                minified_strings.append(s[:max_str_len] + "... [TRUNCATED]")
            else:
                minified_strings.append(s)
                
        # Cap the total number of items
        if len(minified_strings) > max_items:
            static["floss"]["notable_strings"] = minified_strings[:max_items]
            static["floss"]["_notice"] = f"[WARNING] Strings capped at {max_items} items & {max_str_len} chars each."
        else:
            static["floss"]["notable_strings"] = minified_strings
            
    # 2. Cap PEfile Imports
    if "pefile" in static and "suspicious_imports" in static["pefile"]:
        imports = static["pefile"]["suspicious_imports"]
        if len(imports) > max_items:
            static["pefile"]["suspicious_imports"] = imports[:max_items]
            static["pefile"]["_notice"] = f"[WARNING] Imports truncated from {len(imports)} to {max_items}."
            
    # 3. Cap Capa Capabilities
    if "capa" in static and "capabilities" in static["capa"]:
        caps = static["capa"]["capabilities"]
        if isinstance(caps, list) and len(caps) > max_items:
            static["capa"]["capabilities"] = caps[:max_items]
            
    return truncated

# 2. Pathing and Imports
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / "config" / "secrets.env")

from pipeline.llm_synthesis.prompt_builder import build_synthesis_prompt, estimate_cost
from pipeline.llm_synthesis.synthesizer import load_analysis, synthesize, save_synthesis
from pipeline.llm_synthesis.checkpoint2 import run_checkpoint2

logger = logging.getLogger(__name__)

# 3. Core Logic with Fallback Integration
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

    # Initial API Attempt
    result = synthesize(analysis=analysis, prompt=prompt, dry_run=dry_run, cost_estimate=cost)

    # NEW: Catch the token limit error and trigger the fallback
    if result.get("error") and ("prompt is too long" in result["error"].lower() or "maximum" in result["error"].lower()):
        print(f"  [!] Token limit exceeded for {sha256[:8]}. Truncating heavy data and retrying...")
        
        # Shrink the data
        minified_analysis = truncate_heavy_data(analysis, max_items=500)
        
        # Rebuild the prompt with the smaller data
        minified_prompt = build_synthesis_prompt(minified_analysis)
        if analyst_notes:
            minified_prompt += f"\n\n## Analyst Notes\n{analyst_notes}"
            
        # Second API Attempt
        result = synthesize(analysis=minified_analysis, prompt=minified_prompt, dry_run=dry_run, cost_estimate=cost)
        
        if not result.get("error"):
            print(f"  [+] Retry successful! Sample minified and synthesized.")

    # Final Error Check
    if result.get("error"):
        print(f"\n[!] Synthesis failed for {sha256[:16]}: {result['error']}")
        return False
    
    if no_raw:
        result["raw_response"] = None
    
    out_path = save_synthesis(result)
    
    if not dry_run:
        from pipeline.utils.db import update_status
        update_status(sha256, 'SYNTHESIZED')
        print(f"  [+] Synthesis complete for {sha256[:16]}... -> {out_path.name}")
    else:
        print(f"  [~] DRY RUN complete for {sha256[:16]}... (DB state NOT advanced)")
        
    return True

# 4. CLI Execution
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M7 LLM Synthesis Orchestrator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 of sample to synthesize")
    group.add_argument("--all", action="store_true", help="Synthesize all samples pending synthesis")
    parser.add_argument("--dry-run", action="store_true", help="Skip API call, return placeholder output")
    parser.add_argument("--skip-checkpoint", action="store_true", help="Skip checkpoint #2 review")
    parser.add_argument("--no-raw", action="store_true", help="Suppress raw_response in synthesis JSON (still logged to output/logs/raw_responses/)")
    args = parser.parse_args()

    if args.all:
        from pipeline.utils.db import get_samples_by_status
        hashes = get_samples_by_status('ANALYZED')
        print(f"Found {len(hashes)} sample(s) pending synthesis.")
        
        if not args.skip_checkpoint:
            print("  [!] Warning: Running batch synthesis. Auto-skipping Checkpoint #2.")
            args.skip_checkpoint = True
        
        import time
        
        print(f"[*] Starting sequential LLM synthesis (Throttled to respect API Tier limits)...")
        
        for index, h in enumerate(hashes):
            if index > 0:
                print("  [~] Rate limit cooldown: Sleeping for 20 seconds...")
                time.sleep(20)
                
            try:
                process_synthesis(h, args.dry_run, args.skip_checkpoint, args.no_raw)
            except Exception as exc:
                print(f"  [!] Synthesis for {h[:16]} generated an exception: {exc}")
    else:
        process_synthesis(args.sha256, args.dry_run, args.skip_checkpoint, args.no_raw)