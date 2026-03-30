"""
rule_extractor.py
Extracts YARA and Sigma rules from synthesis JSON
into standalone rule files for use with validation tools.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
YARA_DIR = REPO_ROOT / "output" / "rules" / "yara"
SIGMA_DIR = REPO_ROOT / "output" / "rules" / "sigma"


def extract_yara(synthesis: dict) -> tuple[str, Path] | tuple[None, None]:
    """Extract YARA rule and write to output/rules/yara/<sha256>.yar"""
    sha256 = synthesis.get("sample", {}).get("sha256", "unknown")
    rule = synthesis.get("synthesis", {}).get("yara_rule", {}).get("rule", "")

    if not rule or rule == "[DRY RUN]":
        return None, None

    YARA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = YARA_DIR / f"{sha256}.yar"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rule)
        f.write("\n")

    return rule, out_path


def extract_sigma(synthesis: dict) -> tuple[str, Path] | tuple[None, None]:
    """Extract Sigma rule and write to output/rules/sigma/<sha256>.yml"""
    sha256 = synthesis.get("sample", {}).get("sha256", "unknown")
    rule = synthesis.get("synthesis", {}).get("sigma_rule", {}).get("rule", "")

    if not rule or rule == "[DRY RUN]":
        return None, None

    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SIGMA_DIR / f"{sha256}.yml"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rule)
        f.write("\n")

    return rule, out_path