"""
run_diec.py
Detect-It-Easy (diec) wrapper — identifies file type, compiler,
packer, protector, and linker information.
Works on PE, ELF, APK, and most binary formats.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def run_diec(sample_path: Path, timeout: int = 60) -> dict:
    """
    Run diec against a sample and return structured detection results.
    diec identifies:
      - File type and architecture
      - Compiler/language used
      - Packer or protector if present
      - Linker information
    """
    result = {
        "tool": "diec",
        "sample": str(sample_path),
        "success": False,
        "error": None,
        "detections": [],
        "summary": {
            "file_type": None,
            "architecture": None,
            "compiler": None,
            "packer": None,
            "linker": None,
            "is_packed": False,
        }
    }

    if not sample_path.exists():
        result["error"] = f"Sample not found: {sample_path}"
        logger.error(result["error"])
        return result

    cmd = [
        "diec",
        "-j",
        str(sample_path)
    ]

    logger.info(f"Running diec on {sample_path.name}...")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if proc.returncode != 0:
            result["error"] = f"diec exited with code {proc.returncode}: {proc.stderr[:500]}"
            logger.error(result["error"])
            return result

        output = proc.stdout.strip()
        if not output:
            result["error"] = "diec produced no output"
            logger.error(result["error"])
            return result

        diec_data = json.loads(output)

        detections = diec_data.get("detects", [])
        result["detections"] = detections

        # Parse summary from detections
        for entry in detections:
            det_type = entry.get("type", "").lower()
            name = entry.get("name", "")
            info = entry.get("info", "")
            version = entry.get("version", "")
            label = f"{name} {version}".strip() if version else name

            if det_type == "archive" or det_type == "format":
                result["summary"]["file_type"] = label
            elif det_type == "compiler":
                result["summary"]["compiler"] = label
            elif det_type == "packer" or det_type == "protector":
                result["summary"]["packer"] = label
                result["summary"]["is_packed"] = True
            elif det_type == "linker":
                result["summary"]["linker"] = label

        # File type from top-level if present
        if not result["summary"]["file_type"]:
            result["summary"]["file_type"] = diec_data.get("filetype", None)

        result["success"] = True
        logger.info(f"diec complete: {len(detections)} detections")

    except subprocess.TimeoutExpired:
        result["error"] = f"diec timed out after {timeout}s"
        logger.error(result["error"])
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse diec JSON output: {e}"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = "diec not found — is it installed and in PATH?"
        logger.error(result["error"])

    return result


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python run_diec.py <sample_path>")
        sys.exit(1)

    sample = Path(sys.argv[1])
    results = run_diec(sample)

    print(f"\n{'='*55}")
    print(f"  diec Results: {sample.name}")
    print(f"{'='*55}")
    print(f"  Success      : {results['success']}")

    if results["error"]:
        print(f"  Error        : {results['error']}")
    else:
        s = results["summary"]
        print(f"  File Type    : {s['file_type'] or 'unknown'}")
        print(f"  Architecture : {s['architecture'] or 'unknown'}")
        print(f"  Compiler     : {s['compiler'] or 'unknown'}")
        print(f"  Packer       : {s['packer'] or 'none detected'}")
        print(f"  Linker       : {s['linker'] or 'unknown'}")
        print(f"  Packed       : {s['is_packed']}")

        if results["detections"]:
            print(f"\n  --- All Detections ---")
            for d in results["detections"]:
                dtype = d.get("type", "")
                name = d.get("name", "")
                version = d.get("version", "")
                info = d.get("info", "")
                line = f"    [{dtype}] {name}"
                if version:
                    line += f" {version}"
                if info:
                    line += f" ({info})"
                print(line)
