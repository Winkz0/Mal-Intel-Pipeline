"""
run_floss.py
FLOSS wrapper — extracts static, stack, and decoded strings from a sample.
Runs as a subprocess, parses JSON output.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def run_floss(sample_path: Path, timeout: int = 300) -> dict:
    """
    Run FLOSS against a sample and return structured results.
    FLOSS extracts:
      - Static strings (like classic 'strings' tool)
      - Stack strings (constructed on the stack at runtime)
      - Decoded strings (deobfuscated by FLOSS's emulation engine)
    
    Returns a normalized dict with findings and metadata.
    Timeout defaults to 5 minutes — FLOSS can be slow on large samples.
    """
    result = {
        "tool": "floss",
        "sample": str(sample_path),
        "success": False,
        "error": None,
        "strings": {
            "static": [],
            "stack": [],
            "decoded": [],
        },
        "summary": {
            "total_static": 0,
            "total_stack": 0,
            "total_decoded": 0,
            "notable": [],
        }
    }

    if not sample_path.exists():
        result["error"] = f"Sample not found: {sample_path}"
        logger.error(result["error"])
        return result

    cmd = [
        "floss",
        "-j",
        "-q",
        "--only", "static",
        str(sample_path)
    ]

    logger.info(f"Running FLOSS on {sample_path.name}...")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if proc.returncode not in (0, 1):
            result["error"] = f"FLOSS exited with code {proc.returncode}: {proc.stderr[:500]}"
            logger.error(result["error"])
            return result

        if not proc.stdout.strip():
            result["error"] = "FLOSS produced no output"
            logger.error(result["error"])
            return result

        floss_data = json.loads(proc.stdout)

        # Extract string lists
        static = [s.get("string", "") for s in floss_data.get("strings", {}).get("static_strings", [])]
        stack = [s.get("string", "") for s in floss_data.get("strings", {}).get("stack_strings", [])]
        decoded = [s.get("string", "") for s in floss_data.get("strings", {}).get("decoded_strings", [])]

        result["strings"]["static"] = static
        result["strings"]["stack"] = stack
        result["strings"]["decoded"] = decoded

        result["summary"]["total_static"] = len(static)
        result["summary"]["total_stack"] = len(stack)
        result["summary"]["total_decoded"] = len(decoded)

        # Flag notable strings — IPs, URLs, commands, registry keys
        notable = extract_notable(static + stack + decoded)
        result["summary"]["notable"] = notable

        result["success"] = True
        logger.info(
            f"FLOSS complete: {len(static)} static, "
            f"{len(stack)} stack, {len(decoded)} decoded strings"
        )

    except subprocess.TimeoutExpired:
        result["error"] = f"FLOSS timed out after {timeout}s"
        logger.error(result["error"])
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse FLOSS JSON output: {e}"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = "FLOSS not found — is it installed and in PATH?"
        logger.error(result["error"])

    return result


def extract_notable(strings: list[str]) -> list[str]:
    """
    Filter strings for high-value indicators — IPs, URLs, registry paths,
    suspicious commands, C2 patterns, etc.
    """
    import re

    patterns = [
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",   # IPv4
        r"https?://[^\s]+",                              # URLs
        r"HKEY_[A-Z_]+\\[^\s]+",                        # Registry keys
        r"/bin/sh|/bin/bash|cmd\.exe|powershell",        # Shell refs
        r"wget|curl|tftp|ftp://",                        # Download tools
        r"chmod|chown|crontab",                          # Unix persistence
        r"SELECT|INSERT|DROP TABLE",                     # SQL
        r"[a-zA-Z0-9+/]{40,}={0,2}",                   # Possible base64
    ]

    notable = []
    seen = set()

    for s in strings:
        for pattern in patterns:
            if re.search(pattern, s, re.IGNORECASE):
                if s not in seen:
                    notable.append(s)
                    seen.add(s)
                break

    return notable[:100]  # Cap at 100 to keep output manageable


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python run_floss.py <sample_path>")
        sys.exit(1)

    sample = Path(sys.argv[1])
    results = run_floss(sample)

    print(f"\n{'='*55}")
    print(f"  FLOSS Results: {sample.name}")
    print(f"{'='*55}")
    print(f"  Success  : {results['success']}")

    if results["error"]:
        print(f"  Error    : {results['error']}")
    else:
        s = results["summary"]
        print(f"  Static   : {s['total_static']} strings")
        print(f"  Stack    : {s['total_stack']} strings")
        print(f"  Decoded  : {s['total_decoded']} strings")
        print(f"  Notable  : {len(s['notable'])} flagged")

        if s["notable"]:
            print(f"\n  --- Notable Strings ---")
            for n in s["notable"][:20]:
                print(f"    {n}")