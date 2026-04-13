"""
synthesizer.py
Claude API integration for LLM synthesis.
Includes dry-run mode, cost estimation, and structured output parsing.
"""

import os
import json
import logging
import re
from pathlib import Path
from datetime import datetime, timezone

import anthropic

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "output" / "reports"
MODEL = "claude-sonnet-4-5"


def load_analysis(sha256: str) -> dict | None:
    analysis_path = REPO_ROOT / "output" / "analysis" / f"{sha256}.analysis.json"
    if not analysis_path.exists():
        # Try partial match
        matches = list((REPO_ROOT / "output" / "analysis").glob(f"{sha256}*.analysis.json"))
        if not matches:
            logger.error(f"Analysis file not found for: {sha256[:16]}...")
            return None
        analysis_path = matches[0]

    with open(analysis_path, "r") as f:
        return json.load(f)

def validate_yara_strings(yara_rule: str) -> str:
    """
    Check for unreferenced strings in a YARA rule.
    If a declared string isn't in the condition, log a warning
    and drop it from the strings section.
    Returns the (possibly modified) YARA rule string.
    """
    if not yara_rule or yara_rule == "[DRY RUN]":
        return yara_rule

    # Extract declared string names from strings: section
    declared = re.findall(r'(\$\w+)\s*=', yara_rule)
    if not declared:
        return yara_rule

    # Extract the condition: section
    condition_match = re.search(r'condition\s*:(.*)', yara_rule, re.DOTALL)
    if not condition_match:
        return yara_rule

    condition_text = condition_match.group(1)

    # Check for wildcard references that cover all strings
    if re.search(r'(any|all)\s+of\s+(them|\(\s*\$)', condition_text):
        return yara_rule

    # Build a set of prefixes used in wildcard references like "2 of ($api_*)"
    wildcard_prefixes = set()
    for match in re.finditer(r'of\s*\(\s*(\$\w+?)_\*\s*\)', condition_text):
        wildcard_prefixes.add(match.group(1) + "_")

    unreferenced = []
    for var in declared:
        if var not in condition_text:
            continue
        # Check if this string is covered by a wildcard references
        covered_by_wildcard = False
        for prefix in wildcard_prefixes:
            if var.startswith(prefix):
                covered_by_wildcard = True
                break
        if not covered_by_wildcard:
            unreferenced.append(var)

    if unreferenced:
        logger.warning(f"YARA: unreferenced strings found: {unreferenced}")
        # Remove unreferenced strings from the rule
        for var in unreferenced:
            # Remove the full line declaring this string
            yara_rule = re.sub(
                r'\n\s*' + re.escape(var) + r'\s*=.*', '', yara_rule
            )
        logger.info(f"YARA: removed {len(unreferenced)} unreferenced strings")

    return yara_rule

def synthesize(
    analysis: dict,
    prompt: str,
    dry_run: bool = False,
    cost_estimate: dict = None,
) -> dict:
    """
    Send prompt to Claude API and return structured synthesis result.
    dry_run=True skips the API call and returns a placeholder.
    Raw response is always logged to output/logs/raw_responses regardless
    of whether raw_response is retained in the synthesis JSON
    """
    result = {
        "schema_version": "1.0",
        "synthesized_at": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "dry_run": dry_run,
        "cost_estimate": cost_estimate,
        "sample": analysis.get("sample", {}),
        "synthesis": None,
        "error": None,
        "raw_response": None,
    }

    if dry_run:
        logger.info("Dry run mode — skipping Claude API call")
        result["synthesis"] = {
            "ttp_mapping": {"narrative": "[DRY RUN]", "techniques": [], "confidence": "n/a", "reasoning": ""},
            "yara_rule": {"rule": "[DRY RUN]", "confidence": "n/a", "reasoning": ""},
            "sigma_rule": {"rule": "[DRY RUN]", "log_sources": [], "crowdstrike_notes": "", "splunk_notes": "", "confidence": "n/a", "reasoning": ""},
            "technical_report": {"executive_summary": "[DRY RUN]", "technical_summary": "", "key_indicators": [], "recommended_actions": []},
        }
        return result

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        result["error"] = "ANTHROPIC_API_KEY not set"
        logger.error(result["error"])
        return result

    try:
        client = anthropic.Anthropic(api_key=api_key)

        logger.info(f"Sending synthesis request to Claude ({MODEL})...")

        message = client.messages.create(
            model=MODEL,
            max_tokens=8192,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = message.content[0].text
        result["raw_response"] = raw
        
        # Dump raw response to log file
        raw_log_dir = REPO_ROOT / "output" / "logs" / "raw_responses"
        raw_log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sample_sha = analysis.get("sample", {}).get("sha256", "unknown")
        raw_log_path = raw_log_dir / f"{sample_sha}_{ts}.json"
        with open(raw_log_path, "w") as rl:
            json.dump({"model": MODEL, "raw_text": raw, "timestamp": ts}, rl, indent=2)
        logger.info(f"Raw response logged: {raw_log_path}")

        # Strip markdown code blocks if Claude wraps JSON anyway
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip()

        result["synthesis"] = json.loads(clean)
        logger.info("Synthesis complete")

        # Validate YARA rule — remove unreferenced strings
        yara_section = result["synthesis"].get("yara_rule", {})
        if isinstance(yara_section, dict) and "rule" in yara_section:
            yara_section["rule"] = validate_yara_strings(yara_section["rule"])

    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse Claude response as JSON: {e}"
        logger.error(result["error"])
    except anthropic.APIError as e:
        result["error"] = f"Anthropic API error: {e}"
        logger.error(result["error"])
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.error(result["error"])

    return result


def save_synthesis(synthesis: dict) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sha256 = synthesis["sample"].get("sha256", "unknown")
    out_path = OUTPUT_DIR / f"{sha256}.synthesis.json"
    with open(out_path, "w") as f:
        json.dump(synthesis, f, indent=2)
    logger.info(f"Synthesis saved: {out_path}")
    return out_path