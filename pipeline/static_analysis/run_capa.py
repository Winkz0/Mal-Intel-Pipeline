"""
run_capa.py
Capa wrapper — identifies malware capabilities using rule matching.
Produces MITRE ATT&CK TTP mappings and MBC behavior classifications.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def run_capa(sample_path: Path, timeout: int = 300) -> dict:
    """
    Run Capa against a sample and return structured capability results.
    Capa maps binary behavior to:
      - MITRE ATT&CK techniques
      - Malware Behavior Catalog (MBC) behaviors
      - Namespace-based capability groupings
    """
    result = {
        "tool": "capa",
        "sample": str(sample_path),
        "success": False,
        "error": None,
        "capabilities": [],
        "attack": [],
        "mbc": [],
        "summary": {
            "total_capabilities": 0,
            "total_attack_ttps": 0,
            "total_mbc": 0,
            "notable": []
        }
    }

    if not sample_path.exists():
        result["error"] = f"Sample not found: {sample_path}"
        logger.error(result["error"])
        return result

    cmd = [
        "capa",
        "-j",
        "--quiet",
        "-r", str(Path.home() / "capa-rules"),
	"--signatures", str(Path.home() / ".capa" / "sigs"),
        str(sample_path)
    ]

    logger.info(f"Running Capa on {sample_path.name}...")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Capa returns 1 when it finds capabilities — that's normal
        if proc.returncode not in (0, 1):
            # Check for the "unsupported format" message specifically
            if "unsupported file type" in proc.stderr.lower() or \
               "unsupported file type" in proc.stdout.lower():
                result["error"] = "Capa does not support this file format"
                logger.warning(result["error"])
                return result

            result["error"] = f"Capa exited with code {proc.returncode}: {proc.stderr[:500]}"
            logger.error(result["error"])
            return result

        output = proc.stdout.strip()
        if not output:
            result["error"] = "Capa produced no output"
            logger.error(result["error"])
            return result

        capa_data = json.loads(output)

        # Extract capabilities
        rules = capa_data.get("rules", {})
        capabilities = []
        attack_ttps = []
        mbc_behaviors = []

        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})
            capabilities.append(rule_name)

            # Extract ATT&CK mappings
            for attack in meta.get("attack", []):
                ttp = {
                    "technique": attack.get("technique", ""),
                    "subtechnique": attack.get("subtechnique", ""),
                    "id": attack.get("id", ""),
                    "tactic": attack.get("tactic", ""),
                }
                if ttp not in attack_ttps:
                    attack_ttps.append(ttp)

            # Extract MBC mappings
            for mbc in meta.get("mbc", []):
                behavior = {
                    "objective": mbc.get("objective", ""),
                    "behavior": mbc.get("behavior", ""),
                    "id": mbc.get("id", ""),
                }
                if behavior not in mbc_behaviors:
                    mbc_behaviors.append(behavior)

        result["capabilities"] = capabilities
        result["attack"] = attack_ttps
        result["mbc"] = mbc_behaviors
        result["summary"]["total_capabilities"] = len(capabilities)
        result["summary"]["total_attack_ttps"] = len(attack_ttps)
        result["summary"]["total_mbc"] = len(mbc_behaviors)
        result["summary"]["notable"] = capabilities[:20]
        result["success"] = True

        logger.info(
            f"Capa complete: {len(capabilities)} capabilities, "
            f"{len(attack_ttps)} ATT&CK TTPs, {len(mbc_behaviors)} MBC behaviors"
        )

    except subprocess.TimeoutExpired:
        result["error"] = f"Capa timed out after {timeout}s"
        logger.error(result["error"])
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse Capa JSON output: {e}"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = "Capa not found — is it installed and in PATH?"
        logger.error(result["error"])

    return result


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python run_capa.py <sample_path>")
        sys.exit(1)

    sample = Path(sys.argv[1])
    results = run_capa(sample)

    print(f"\n{'='*55}")
    print(f"  Capa Results: {sample.name}")
    print(f"{'='*55}")
    print(f"  Success      : {results['success']}")

    if results["error"]:
        print(f"  Error        : {results['error']}")
    else:
        s = results["summary"]
        print(f"  Capabilities : {s['total_capabilities']}")
        print(f"  ATT&CK TTPs  : {s['total_attack_ttps']}")
        print(f"  MBC Behaviors: {s['total_mbc']}")

        if results["attack"]:
            print(f"\n  --- ATT&CK TTPs ---")
            for ttp in results["attack"]:
                tid = ttp.get('id', '')
                technique = ttp.get('technique', '')
                tactic = ttp.get('tactic', '')
                print(f"    [{tid}] {technique} ({tactic})")

        if s["notable"]:
            print(f"\n  --- Capabilities ---")
            for cap in s["notable"]:
                print(f"    {cap}")
