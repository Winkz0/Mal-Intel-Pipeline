"""
normalizer.py
Merges outputs from all static analysis tools into a single
unified analysis result JSON per sample.
This is the handoff artifact from M6 → M7 LLM synthesis.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "output" / "analysis"


def normalize(
    sha256: str,
    floss_result: dict,
    capa_result: dict,
    diec_result: dict,
    pefile_result: dict,
    meta: dict = None,
) -> dict:
    """
    Merge all tool outputs into a unified analysis document.
    This is what gets handed to the LLM synthesis layer.
    """
    return {
        "schema_version": "1.0",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "sha256": sha256,
            "md5": meta.get("md5", "") if meta else "",
            "sha1": meta.get("sha1", "") if meta else "",
            "file_name": meta.get("file_name", "") if meta else "",
            "file_type": meta.get("file_type", "") if meta else "",
            "file_size_bytes": meta.get("file_size_bytes", 0) if meta else 0,
            "malware_family": meta.get("malware_family", "unknown") if meta else "unknown",
            "tags": meta.get("tags", []) if meta else [],
            "source": meta.get("source", "unknown") if meta else "unknown",
        },
        "static_analysis": {
            "diec": {
                "success": diec_result.get("success", False),
                "file_type": diec_result.get("summary", {}).get("file_type"),
                "architecture": diec_result.get("summary", {}).get("architecture"),
                "compiler": diec_result.get("summary", {}).get("compiler"),
                "packer": diec_result.get("summary", {}).get("packer"),
                "linker": diec_result.get("summary", {}).get("linker"),
                "is_packed": diec_result.get("summary", {}).get("is_packed", False),
                "error": diec_result.get("error"),
            },
            "pefile": {
                "success": pefile_result.get("success", False),
                "is_pe": pefile_result.get("is_pe", False),
                "architecture": pefile_result.get("summary", {}).get("architecture"),
                "compile_timestamp": pefile_result.get("summary", {}).get("compile_timestamp"),
                "imphash": pefile_result.get("summary", {}).get("imphash"),
                "sections": pefile_result.get("sections", []),
                "imports": pefile_result.get("imports", []),
                "exports": pefile_result.get("exports", []),
                "high_entropy_sections": pefile_result.get("summary", {}).get("high_entropy_sections", []),
                "suspicious_imports": pefile_result.get("summary", {}).get("suspicious_imports", []),
                "error": pefile_result.get("error"),
            },
            "floss": {
                "success": floss_result.get("success", False),
                "total_static": floss_result.get("summary", {}).get("total_static", 0),
                "total_stack": floss_result.get("summary", {}).get("total_stack", 0),
                "total_decoded": floss_result.get("summary", {}).get("total_decoded", 0),
                "notable_strings": floss_result.get("summary", {}).get("notable", []),
                "all_strings": floss_result.get("strings", {}).get("static", []),
                "error": floss_result.get("error"),
            },
            "capa": {
                "success": capa_result.get("success", False),
                "capabilities": capa_result.get("capabilities", []),
                "attack_ttps": capa_result.get("attack", []),
                "mbc_behaviors": capa_result.get("mbc", []),
                "total_capabilities": capa_result.get("summary", {}).get("total_capabilities", 0),
                "total_attack_ttps": capa_result.get("summary", {}).get("total_attack_ttps", 0),
                "error": capa_result.get("error"),
            },
        },
        "ioc_candidates": extract_ioc_candidates(floss_result),
        "analysis_notes": "",  # Analyst fills this in at checkpoint #2
    }


def extract_ioc_candidates(floss_result: dict) -> dict:
    """
    Pull structured IOC candidates out of FLOSS notable strings.
    These feed into the LLM synthesis layer as candidate indicators.
    """
    import re

    notable = floss_result.get("summary", {}).get("notable", [])
    all_strings = floss_result.get("strings", {}).get("static", [])
    search_pool = notable + all_strings

    ips, urls, domains, registry_keys, commands = [], [], [], [], []
    seen = set()

    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    domain_pattern = re.compile(r"\b([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b")
    registry_pattern = re.compile(r"HKEY_[A-Z_]+\\[^\s]+", re.IGNORECASE)
    command_pattern = re.compile(
        r"(cmd\.exe|powershell|/bin/sh|/bin/bash|wget|curl|tftp|chmod|crontab)",
        re.IGNORECASE
    )

    for s in search_pool:
        if s in seen:
            continue
        seen.add(s)

        if url_pattern.search(s):
            urls.append(s)
        elif ip_pattern.search(s):
            ips.append(s)
        elif registry_pattern.search(s):
            registry_keys.append(s)
        elif command_pattern.search(s):
            commands.append(s)

    return {
        "ips": ips[:50],
        "urls": urls[:50],
        "domains": domains[:50],
        "registry_keys": registry_keys[:50],
        "commands": commands[:50],
    }


def save_analysis(analysis: dict, output_dir: Path = None) -> Path:
    """Write normalized analysis JSON to output/analysis/."""
    out_dir = output_dir or OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    sha256 = analysis["sample"]["sha256"]
    out_path = out_dir / f"{sha256}.analysis.json"

    with open(out_path, "w") as f:
        json.dump(analysis, f, indent=2)

    logger.info(f"Analysis saved: {out_path}")
    return out_path


def load_meta(sha256: str, quarantine_dir: Path) -> dict:
    """Load the sample's metadata sidecar if it exists."""
    meta_path = quarantine_dir / f"{sha256}.meta.json"
    if meta_path.exists():
        with open(meta_path, "r") as f:
            return json.load(f)
    return {}