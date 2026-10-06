"""
synthesize.py
M7 LLM Synthesis Orchestrator (M13 v2: bundles, engines, run manifests).
Loads analysis JSON, builds the model-input bundle, runs checkpoint #2,
runs the engine, and saves structured synthesis output plus a run manifest.

Usage:
    python synthesize.py <sha256>                  # API engine, checkpoint #2
    python synthesize.py <sha256> --dry-run        # same as --engine dry-run
    python synthesize.py <sha256> --engine api --model claude-sonnet-5-5
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
from pipeline.llm_synthesis.engines import ENGINE_IDS, get_engine
from pipeline.llm_synthesis.engines.api import DEFAULT_MODEL
from pipeline.llm_synthesis.pricing import estimate_cost
from pipeline.llm_synthesis.prompt_builder import DEFAULT_TEMPLATE, PromptTooLarge, render
from pipeline.llm_synthesis.synthesizer import load_analysis, run_synthesis, save_synthesis
from pipeline.llm_synthesis.checkpoint2 import run_checkpoint2

logger = logging.getLogger(__name__)

BUNDLE_DIR = REPO_ROOT / "output" / "bundles"


def build_model_input(analysis: dict, analyst_notes: str = ""):
    """Bundle + rendered prompt. Caps are applied here, once, before any API call."""
    bundle = build_bundle(analysis, caps=DEFAULT_CAPS, analyst_notes=analyst_notes)
    return bundle, render(bundle, DEFAULT_TEMPLATE)


# 2. Core Logic
def process_synthesis(sha256: str, engine_id: str, skip_checkpoint: bool, no_raw: bool,
                      model: str = DEFAULT_MODEL):
    analysis = load_analysis(sha256)
    if not analysis:
        print(f"[!] No analysis found for {sha256[:16]}...")
        return False

    try:
        bundle, rendered = build_model_input(analysis)
    except (BundleError, PromptTooLarge) as e:
        print(f"[!] Cannot build model input for {sha256[:16]}: {e}")
        return False
    cost = estimate_cost(rendered.prompt, model if engine_id == "api" else "dry-run")

    analyst_notes = ""
    if not skip_checkpoint:
        decision, analyst_notes = run_checkpoint2(analysis, cost)
        if decision is False:
            return False
        if decision == "dry":
            engine_id = "dry-run"

    if analyst_notes:
        # Notes are model input, so they're part of the bundle (and its hash).
        try:
            bundle, rendered = build_model_input(analysis, analyst_notes)
        except (BundleError, PromptTooLarge) as e:
            print(f"[!] Cannot build model input for {sha256[:16]}: {e}")
            return False

    bundle_sha, bundle_path = save_bundle(bundle, BUNDLE_DIR)
    engine = get_engine(engine_id, model=model) if engine_id == "api" else get_engine(engine_id)
    print(f"  [*] Bundle   : {bundle_sha[:16]}... | template {rendered.template_id} "
          f"({rendered.template_sha256[:12]}) | engine {engine.id}")

    result = run_synthesis(
        analysis=analysis,
        rendered=rendered,
        bundle_sha=bundle_sha,
        bundle_path=bundle_path,
        engine=engine,
        cost_estimate=cost,
        analyst_notes=analyst_notes,
    )
    print(f"  [*] Run      : {result['manifest']['path']}")

    if result.get("error"):
        print(f"\n[!] Synthesis failed for {sha256[:16]}: {result['error']}")
        return False

    if no_raw:
        result["raw_response"] = None

    out_path = save_synthesis(result)

    if not result["dry_run"]:
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
    parser.add_argument("--engine", choices=ENGINE_IDS, default="api", help="Synthesis engine (default: api)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"API model (default: {DEFAULT_MODEL})")
    parser.add_argument("--dry-run", action="store_true", help="Same as --engine dry-run")
    parser.add_argument("--skip-checkpoint", action="store_true", help="Skip checkpoint #2 review")
    parser.add_argument("--no-raw", action="store_true", help="Suppress raw_response in synthesis JSON (the run directory keeps the full response)")
    args = parser.parse_args()

    engine_id = "dry-run" if args.dry_run else args.engine

    if args.all:
        # Every API call is approved individually (M13 v2 decision E-1): batch mode
        # keeps checkpoint #2 per sample unless it's a dry run.
        if engine_id == "api" and args.skip_checkpoint:
            print("[!] --all --skip-checkpoint is not allowed with the API engine "
                  "(every API call needs checkpoint #2 approval).")
            sys.exit(2)

        from pipeline.utils.db import get_samples_by_status
        hashes = get_samples_by_status('ANALYZED')
        print(f"Found {len(hashes)} sample(s) pending synthesis.")

        import time

        print("[*] Starting sequential LLM synthesis (Throttled to respect API Tier limits)...")

        for index, h in enumerate(hashes):
            if index > 0 and engine_id == "api":
                print("  [~] Rate limit cooldown: Sleeping for 20 seconds...")
                time.sleep(20)

            try:
                process_synthesis(h, engine_id, args.skip_checkpoint, args.no_raw, args.model)
            except Exception as exc:
                print(f"  [!] Synthesis for {h[:16]} generated an exception: {exc}")
    else:
        # Non-zero exit so run_host_pipeline.sh stops instead of reporting on stale output.
        ok = process_synthesis(args.sha256, engine_id, args.skip_checkpoint, args.no_raw, args.model)
        sys.exit(0 if ok else 1)
