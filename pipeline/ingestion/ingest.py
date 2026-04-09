"""
ingest.py
Main orchestrator for M4 - Intel Feed Ingestion.
Runs all three feed parsers, normalizes, deduplicates,
and presents human checkpoint #1 for analyst approval.
"""

import json
import logging
import os
from datetime import datetime, timezone

from pipeline.ingestion.feed_cisa import fetch_cisa_kev
from pipeline.ingestion.feed_otx import fetch_otx_pulses
from pipeline.ingestion.feed_bazaar import fetch_bazaar_recent
from pipeline.ingestion.normalizer import normalize_all
from pipeline.ingestion.deduplicator import deduplicate
from pipeline.ingestion.checkpoint import run_checkpoint

logger = logging.getLogger(__name__)

OUTPUT_DIR = "output/logs"


def run_ingestion(dry_run: bool = False) -> list[dict]:
    """
    Full ingestion pipeline:
    1. Fetch all three feeds
    2. Normalize to common schema
    3. Deduplicate across feeds
    4. Human checkpoint #1
    5. Return approved IOCs

    Args:
        dry_run: If True, skips checkpoint and returns all IOCs unapproved.
    """
    start = datetime.now(timezone.utc)
    logger.info("="*60)
    logger.info("MAL-INTEL-PIPELINE — INGESTION START")
    logger.info(f"Timestamp: {start.isoformat()}")
    logger.info(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    logger.info("="*60)

    # Step 1 — Fetch all feeds
    logger.info("\n[1/4] Fetching intel feeds...")
    cisa_iocs = fetch_cisa_kev()
    otx_iocs = fetch_otx_pulses()
    bazaar_iocs = fetch_bazaar_recent()

    raw_iocs = cisa_iocs + otx_iocs + bazaar_iocs
    logger.info(f"Raw IOCs: CISA={len(cisa_iocs)}, OTX={len(otx_iocs)}, Bazaar={len(bazaar_iocs)}, Total={len(raw_iocs)}")

    # Step 2 — Normalize
    logger.info("\n[2/4] Normalizing IOCs...")
    normalized = normalize_all(raw_iocs)

    # Step 3 — Deduplicate
    logger.info("\n[3/4] Deduplicating...")
    deduped = deduplicate(normalized)

    # Step 4 — Checkpoint or dry run
    if dry_run:
        logger.info("\n[4/4] DRY RUN — skipping checkpoint, returning all IOCs unapproved")
        final_iocs = deduped
    else:
        logger.info("\n[4/4] Human Checkpoint #1...")
        final_iocs = run_checkpoint(deduped)

    # Summary
    approved = [i for i in final_iocs if i.get("approved_for_analysis")]
    end = datetime.now(timezone.utc)
    elapsed = (end - start).total_seconds()

    logger.info("\n" + "="*60)
    logger.info("INGESTION COMPLETE")
    logger.info(f"  Total IOCs processed : {len(raw_iocs)}")
    logger.info(f"  After normalization  : {len(normalized)}")
    logger.info(f"  After deduplication : {len(deduped)}")
    logger.info(f"  Approved for analysis: {len(approved)}")
    logger.info(f"  Elapsed              : {elapsed:.1f}s")
    logger.info("="*60)

    # Save run log
    save_run_log(raw_iocs, normalized, deduped, final_iocs, elapsed)

    return final_iocs


def save_run_log(raw, normalized, deduped, final, elapsed):
    """
    Saves a summary run log to output/logs.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{OUTPUT_DIR}/ingest_{timestamp}.json"

    log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "raw": len(raw),
            "normalized": len(normalized),
            "deduplicated": len(deduped),
            "approved": len([i for i in final if i.get("approved_for_analysis")])
        },
        "elapsed_seconds": elapsed
    }

    with open(filename, "w") as f:
        json.dump(log, f, indent=2)

    logger.info(f"Run log saved: {filename}")
    
    # Save ingestion summary
    save_ingestion_summary(final, elapsed)

def save_ingestion_summary(iocs: list[dict], elapsed: float):
    """
    Generate a human-readable Markdown summary of the ingestion run.
    Saved to output/logs/ for session reference.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = f"{OUTPUT_DIR}/ingest_summary_{timestamp}.md"
    
    approved = [i for i in iocs if i.get("approved_for_analysis") is True and i.get("ioc_type") == "hash"]
    total = len(iocs)
    hash_count = len([i for i in iocs if i.get("ioc_type") == "hash"])
    
    lines = [
        f"# Ingestion Summary - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"**Total IOCs:** {hash_count}",
        f"**Approved for analysis:** {len(approved)}",
        f"**Elapsed:** {elapsed:.1f}s",
        f"",
        f"---"
        f"",
    ]
    
    if approved:
        lines.append("## Approved Samples")
        lines.append("")
        lines.append("| Family | SHA256 | Type | Size | Tags |")
        lines.append("|--------|--------|------|------|------|")
        for ioc in approved:
            ctx = ioc.get("context", {})
            fi = ioc.get("file.info", {})
            family = ctx.get("malware_family", "unknown")
            sha = ioc.get("value", "")[:16] + "..."
            ftype = fi.get("type", "?")
            fsize = f"{fi.get('size', 0):,}"
            tags = ", ".join(ctx.get("tags", []))
            lines.append(f"| {family} | '{sha}' | {ftype} | {fsize} | {tags} |")
    else:
        lines.append("_No samples approved._")
        
    with open(path, "w") as f:
        f.write("\n".join(lines))
        
    print(f" [+] Ingestion summary: {path}")
        
       
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S"
    )

    import argparse
    parser = argparse.ArgumentParser(description="Mal-Intel-Pipeline Ingestion")
    parser.add_argument("--dry-run", action="store_true", help="Skip checkpoint, return all IOCs unapproved")
    parser.add_argument("--fresh", action="store_true", help="Bypass feed cache, force fresh API calls")
    args = parser.parse_args()
    
    if args.fresh:
        from pipeline.ingestion.cache import clear_cache
        clear_cache()
        print("[*] Feed cache cleared - fetching fresh data")
    
    results = run_ingestion(dry_run=args.dry_run)
    approved = [i for i in results if i.get("approved_for_analysis")]
    print(f"\nReady for acquisition: {len(approved)} approved samples")