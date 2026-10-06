"""
synthesize.py
M7 LLM Synthesis Orchestrator.
Loads analysis JSON, runs checkpoint #2, calls Claude API,
saves structured synthesis output.

Usage:
    python synthesize.py <sha256>
    python synthesize.py <sha256> --dry-run
"""

import sys
import logging
import argparse
from pathlib import Path

# 1. Pathing and Imports
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(REPO_ROOT / "config" / "secrets.env")

from pipeline.llm_synthesis.bundle import DEFAULT_CAPS, BundleError, build_bundle, save_bundle
from pipeline.llm_synthesis.prompt_builder import (
    DEFAULT_TEMPLATE,
    PromptTooLarge,
    estimate_cost,
    render,
)
from pipeline.llm_synthesis.synthesizer import load_analysis, synthesize, save_synthesis
from pipeline.llm_synthesis.checkpoint2 import run_checkpoint2

logger = logging.getLogger(__name__)

BUNDLE_DIR = REPO_ROOT / "output" / "bundles"


def build_model_input(analysis: dict, analyst_notes: str = ""):
    """Bundle + rendered prompt. Caps are applied here, once, before any API call."""
    bundle = build_bundle(analysis, caps=DEFAULT_CAPS, analyst_notes=analyst_notes)
    return bundle, render(bundle, DEFAULT_TEMPLATE)

# 2. Core Logic
def process_synthesis(sha256: str, dry_run: bool, skip_checkpoint: bool, no_raw: bool):
    analysis = load_analysis(sha256)
    if not analysis:
        print(f"[!] No analysis found for {sha256[:16]}...")
        return False

    try:
        bundle, rendered = build_model_input(analysis)
    except (BundleError, PromptTooLarge) as e:
        print(f"[!] Cannot build model input for {sha256[:16]}: {e}")
        return False
    cost = estimate_cost(rendered.prompt)

    analyst_notes = ""
    if not skip_checkpoint:
        decision, analyst_notes = run_checkpoint2(analysis, cost)
        if decision is False:
            return False
        if decision == "dry":
            dry_run = True

    if analyst_notes:
        # Notes are model input, so they're part of the bundle (and its hash).
        try:
            bundle, rendered = build_model_input(analysis, analyst_notes)
        except (BundleError, PromptTooLarge) as e:
            print(f"[!] Cannot build model input for {sha256[:16]}: {e}")
            return False

    bundle_sha, _ = save_bundle(bundle, BUNDLE_DIR)
    print(f"  [*] Bundle   : {bundle_sha[:16]}... | template {rendered.template_id} "
          f"({rendered.template_sha256[:12]})")

    result = synthesize(analysis=analysis, prompt=rendered.prompt, dry_run=dry_run, cost_estimate=cost)
    result["bundle_sha256"] = bundle_sha
    result["template"] = {"id": rendered.template_id, "sha256": rendered.template_sha256}
    result["prompt_sha256"] = rendered.prompt_sha256
    if analyst_notes:
        result["analyst_notes"] = analyst_notes

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

# 3. CLI Execution
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
        
        print("[*] Starting sequential LLM synthesis (Throttled to respect API Tier limits)...")
        
        for index, h in enumerate(hashes):
            if index > 0:
                print("  [~] Rate limit cooldown: Sleeping for 20 seconds...")
                time.sleep(20)
                
            try:
                process_synthesis(h, args.dry_run, args.skip_checkpoint, args.no_raw)
            except Exception as exc:
                print(f"  [!] Synthesis for {h[:16]} generated an exception: {exc}")
    else:
        # Non-zero exit so run_host_pipeline.sh stops instead of reporting on stale output.
        ok = process_synthesis(args.sha256, args.dry_run, args.skip_checkpoint, args.no_raw)
        sys.exit(0 if ok else 1)