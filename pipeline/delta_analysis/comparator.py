"""
comparator.py
Delta analysis — compares a sample's analysis JSON against all
previously analyzed samples in the corpus.
Surfaces shared strings, IOCs, TTPs, capabilities, and file characteristics.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_DIR = REPO_ROOT / "output" / "analysis"


def load_corpus(exclude_sha256: str = None) -> list[dict]:
    """Load all analysis JSONs except the current sample."""
    corpus = []
    for path in ANALYSIS_DIR.glob("*.analysis.json"):
        stem = path.stem.replace(".analysis", "")
        if exclude_sha256 and stem.startswith(exclude_sha256):
            continue
        try:
            with open(path, "r") as f:
                corpus.append(json.load(f))
        except Exception as e:
            logger.warning(f"Failed to load {path.name}: {e}")
    return corpus


def extract_features(analysis: dict) -> dict:
    """Pull comparable features out of a normalized analysis document."""
    static = analysis.get("static_analysis", {})
    iocs = analysis.get("ioc_candidates", {})
    sample = analysis.get("sample", {})

    floss = static.get("floss", {})
    capa = static.get("capa", {})
    diec = static.get("diec", {})
    pe = static.get("pefile", {})

    return {
        "sha256": sample.get("sha256", "unknown"),
        "family": sample.get("malware_family") or "unknown",
        "file_type": diec.get("file_type") or sample.get("file_type") or "unknown",
        "compiler": diec.get("compiler") or None,
        "packer": diec.get("packer") or None,
        "is_packed": diec.get("is_packed", False),
        "architecture": pe.get("architecture") or diec.get("architecture"),
        "imphash": pe.get("imphash"),
        "notable_strings": set(floss.get("notable_strings", [])),
        "all_strings": set(floss.get("all_strings", [])[:500]),  # cap for performance
        "capabilities": set(capa.get("capabilities", [])),
        "attack_ids": set(
            t.get("id", "") for t in capa.get("attack_ttps", [])
        ),
        "ips": set(iocs.get("ips", [])),
        "urls": set(iocs.get("urls", [])),
        "commands": set(iocs.get("commands", [])),
        "tags": set(sample.get("tags", [])),
        "analyzed_at": analysis.get("analyzed_at", "unknown"),
    }


def compare(current: dict, previous: dict) -> dict:
    """
    Compare two feature sets and return overlap metrics.
    All comparisons are set intersections — exact matches only.
    """
    shared_notable = current["notable_strings"] & previous["notable_strings"]
    shared_strings = current["all_strings"] & previous["all_strings"]
    shared_capabilities = current["capabilities"] & previous["capabilities"]
    shared_ttps = current["attack_ids"] & previous["attack_ids"]
    shared_ips = current["ips"] & previous["ips"]
    shared_urls = current["urls"] & previous["urls"]
    shared_commands = current["commands"] & previous["commands"]
    shared_tags = current["tags"] & previous["tags"]

    same_family = (
        current["family"] != "unknown"
        and current["family"].lower() == previous["family"].lower()
    )
    same_file_type = current["file_type"] == previous["file_type"]
    same_compiler = (
        current["compiler"] and previous["compiler"]
        and current["compiler"] == previous["compiler"]
    )
    same_packer = (
        current["packer"] and previous["packer"]
        and current["packer"] == previous["packer"]
    )
    same_imphash = (
        current["imphash"] and previous["imphash"]
        and current["imphash"] == previous["imphash"]
    )

    # Simple overlap score — weighted sum of matches
    score = (
        len(shared_notable) * 3 +
        len(shared_capabilities) * 3 +
        len(shared_ttps) * 2 +
        len(shared_ips) * 2 +
        len(shared_urls) * 2 +
        len(shared_strings) * 1 +
        (5 if same_family else 0) +
        (3 if same_imphash else 0) +
        (2 if same_packer else 0) +
        (1 if same_compiler else 0) +
        (1 if same_file_type else 0)
    )

    return {
        "compared_sha256": previous["sha256"],
        "compared_family": previous["family"],
        "compared_analyzed_at": previous["analyzed_at"],
        "overlap_score": score,
        "same_family": same_family,
        "same_file_type": same_file_type,
        "same_compiler": same_compiler,
        "same_packer": same_packer,
        "same_imphash": same_imphash,
        "shared_notable_strings": sorted(shared_notable),
        "shared_capabilities": sorted(shared_capabilities),
        "shared_attack_ttps": sorted(shared_ttps),
        "shared_ips": sorted(shared_ips),
        "shared_urls": sorted(shared_urls),
        "shared_commands": sorted(shared_commands),
        "shared_tags": sorted(shared_tags),
        "shared_string_count": len(shared_strings),
    }


def run_delta(sha256: str) -> dict:
    """
    Run delta analysis for a given sample against the full corpus.
    Returns sorted comparison results, highest overlap score first.
    """
    # Load current sample
    matches = list(ANALYSIS_DIR.glob(f"{sha256}*.analysis.json"))
    if not matches:
        logger.error(f"Analysis not found for: {sha256[:16]}...")
        return {"error": f"Analysis not found for {sha256}", "comparisons": []}

    with open(matches[0], "r") as f:
        current_analysis = json.load(f)

    current_features = extract_features(current_analysis)
    corpus = load_corpus(exclude_sha256=sha256)

    if not corpus:
        return {
            "sha256": sha256,
            "corpus_size": 0,
            "comparisons": [],
            "top_match": None,
            "note": "No previous samples in corpus to compare against."
        }

    comparisons = []
    for prev_analysis in corpus:
        prev_features = extract_features(prev_analysis)
        result = compare(current_features, prev_features)
        comparisons.append(result)

    # Sort by overlap score descending
    comparisons.sort(key=lambda x: x["overlap_score"], reverse=True)

    return {
        "sha256": sha256,
        "family": current_features["family"],
        "corpus_size": len(corpus),
        "comparisons": comparisons,
        "top_match": comparisons[0] if comparisons else None,
    }