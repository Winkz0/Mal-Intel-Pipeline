"""
validate_sigma.py
Sigma CLI-based Sigma rule validation.
Runs sigma convert as a subprocess to catch syntax and schema errors.
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_sigma_rule(rule_path: Path) -> dict:
    """
    Validate a Sigma rule file using sigma-cli.
    Uses 'sigma convert' with a minimal backend to catch schema errors.
    A rule that converts successfully is syntactically valid.
    """
    result = {
        "tool": "sigma-cli",
        "rule_path": str(rule_path),
        "valid": False,
        "error": None,
        "warnings": [],
        "converted_output": None,
    }

    if not rule_path.exists():
        result["error"] = f"Rule file not found: {rule_path}"
        logger.error(result["error"])
        return result

    # Use 'sigma check' if available, fall back to convert with splunk backend
    cmd_check = ["sigma", "check", str(rule_path)]
    cmd_convert = ["sigma", "convert", "-t", "splunk", str(rule_path)]

    try:
        # Try sigma check first (cleaner validation)
        proc = subprocess.run(
            cmd_check,
            capture_output=True,
            text=True,
            timeout=30
        )

        if proc.returncode == 0:
            result["valid"] = True
            result["converted_output"] = proc.stdout.strip()
            logger.info(f"Sigma rule valid: {rule_path.name}")
            return result

        # If check fails, try convert as fallback
        proc = subprocess.run(
            cmd_convert,
            capture_output=True,
            text=True,
            timeout=30
        )

        if proc.returncode == 0:
            result["valid"] = True
            result["converted_output"] = proc.stdout.strip()
            logger.info(f"Sigma rule valid (convert): {rule_path.name}")
        else:
            stderr = proc.stderr.strip()
            stdout = proc.stdout.strip()
            result["error"] = stderr or stdout or f"sigma exited with code {proc.returncode}"
            logger.error(f"Sigma validation failed for {rule_path.name}: {result['error']}")

    except subprocess.TimeoutExpired:
        result["error"] = "sigma-cli timed out"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = "sigma not found — is sigma-cli installed and on PATH?"
        logger.error(result["error"])
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.error(result["error"])

    return result


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python validate_sigma.py <rule_path>")
        sys.exit(1)

    path = Path(sys.argv[1])
    result = validate_sigma_rule(path)

    print(f"\n{'='*50}")
    print(f"  Sigma Validation: {path.name}")
    print(f"{'='*50}")
    print(f"  Valid  : {result['valid']}")
    if result["error"]:
        print(f"  Error  : {result['error']}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  Warning: {w}")
    if result["converted_output"]:
        print(f"\n  Converted Output:")
        print(f"  {result['converted_output'][:300]}")
    print(f"{'='*50}")