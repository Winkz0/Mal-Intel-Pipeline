"""
validate_yara.py
PyYARA-based YARA rule syntax validation.
Compiles the rule and reports any syntax errors.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_yara_rule(rule_path: Path) -> dict:
    """
    Compile a YARA rule file using yara-python.
    Compilation catches syntax errors, undefined identifiers,
    and invalid regex patterns.
    """
    result = {
        "tool": "yara-python",
        "rule_path": str(rule_path),
        "valid": False,
        "error": None,
        "warnings": [],
        "rule_count": 0,
    }

    if not rule_path.exists():
        result["error"] = f"Rule file not found: {rule_path}"
        logger.error(result["error"])
        return result

    try:
        import yara

        compiled = yara.compile(filepath=str(rule_path))

        # Count rules by scanning an empty buffer
        matches = compiled.match(data=b"")
        result["valid"] = True
        result["rule_count"] = 1  # yara-python doesn't expose rule count directly
        logger.info(f"YARA rule valid: {rule_path.name}")

    except yara.SyntaxError as e:
        result["error"] = f"Syntax error: {e}"
        logger.error(f"YARA validation failed for {rule_path.name}: {e}")
    except yara.Error as e:
        result["error"] = f"YARA error: {e}"
        logger.error(f"YARA error for {rule_path.name}: {e}")
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.error(result["error"])

    return result


def validate_yara_string(rule_string: str, rule_name: str = "inline") -> dict:
    """
    Validate a YARA rule provided as a string rather than a file.
    Useful for validating rules extracted directly from synthesis JSON.
    """
    result = {
        "tool": "yara-python",
        "rule_path": f"<string:{rule_name}>",
        "valid": False,
        "error": None,
        "warnings": [],
        "rule_count": 0,
    }

    try:
        import yara

        compiled = yara.compile(source=rule_string)
        result["valid"] = True
        result["rule_count"] = 1
        logger.info(f"YARA string rule valid: {rule_name}")

    except yara.SyntaxError as e:
        result["error"] = f"Syntax error: {e}"
        logger.error(f"YARA string validation failed [{rule_name}]: {e}")
    except yara.Error as e:
        result["error"] = f"YARA error: {e}"
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
        print("Usage: python validate_yara.py <rule_path>")
        sys.exit(1)

    path = Path(sys.argv[1])
    result = validate_yara_rule(path)

    print(f"\n{'='*50}")
    print(f"  YARA Validation: {path.name}")
    print(f"{'='*50}")
    print(f"  Valid  : {result['valid']}")
    if result["error"]:
        print(f"  Error  : {result['error']}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  Warning: {w}")
    print(f"{'='*50}")