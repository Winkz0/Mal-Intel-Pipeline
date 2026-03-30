"""
delta.py
M10 Delta Analysis Orchestrator.
Compares a sample against the analyzed corpus and generates
a delta report highlighting relationships to previous samples.

Usage:
    python delta.py <sha256>
    python delta.py --all
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.delta_analysis.comparator import run_delta

logger = logging.getLogger(__name__)

REPORTS_DIR = REPO_ROOT / "output" / "reports"


def render_delta_report(delta: dict) -> str:
    sha256 = delta.get("sha256", "unknown")
    family = delta.get("family", "unknown")
    corpus_size = delta.get("corpus_size", 0)
    comparisons = delta.get("comparisons", [])
    note = delta.get("note", "")

    md = f"""# Delta Analysis Report — {family.title()}

**SHA256:** `{sha256}`
**Family:** {family}
**Corpus Size:** {corpus_size} previously analyzed sample(s)
**Generated:** {datetime.now(timezone.utc).isoformat()}

---

"""

    if note:
        md += f"> {note}\n\n---\n\n"
        return md

    if not comparisons:
        md += "_No overlaps found with previously analyzed samples._\n"
        return md

    top = comparisons[0]
    md += f"""## Top Match

| Field | Value |
|-------|-------|
| SHA256 | `{top['compared_sha256'][:32]}...` |
| Family | {top['compared_family']} |
| Analyzed | {top['compared_analyzed_at']} |
| Overlap Score | {top['overlap_score']} |
| Same Family | {top['same_family']} |
| Same File Type | {top['same_file_type']} |
| Same Compiler | {top['same_compiler']} |
| Same Packer | {top['same_packer']} |
| Same Imphash | {top['same_imphash']} |

---

## All Comparisons

| Sample | Family | Score | Same Family | Shared TTPs | Shared IOCs |
|--------|--------|-------|-------------|-------------|-------------|
"""

    for c in comparisons:
        sha_short = c['compared_sha256'][:16] + '...'
        shared_iocs = len(c['shared_ips']) + len(c['shared_urls'])
        md += (
            f"| `{sha_short}` | {c['compared_family']} | {c['overlap_score']} | "
            f"{c['same_family']} | {len(c['shared_attack_ttps'])} | {shared_iocs} |\n"
        )

    # Detailed overlaps for top match only
    md += f"\n---\n\n## Detailed Overlaps — Top Match\n\n"

    if top["shared_attack_ttps"]:
        md += f"### Shared ATT&CK TTPs\n"
        for ttp in top["shared_attack_ttps"]:
            md += f"- `{ttp}`\n"
        md += "\n"

    if top["shared_notable_strings"]:
        md += f"### Shared Notable Strings\n"
        for s in top["shared_notable_strings"][:20]:
            md += f"- `{s}`\n"
        md += "\n"

    if top["shared_ips"]:
        md += f"### Shared IPs\n"
        for ip in top["shared_ips"]:
            md += f"- `{ip}`\n"
        md += "\n"

    if top["shared_urls"]:
        md += f"### Shared URLs\n"
        for url in top["shared_urls"]:
            md += f"- `{url}`\n"
        md += "\n"

    if top["shared_capabilities"]:
        md += f"### Shared Capabilities\n"
        for cap in top["shared_capabilities"]:
            md += f"- {cap}\n"
        md += "\n"

    if top["shared_string_count"] > 0:
        md += f"### Shared Static Strings\n"
        md += f"_{top['shared_string_count']} strings in common (see full analysis JSON for details)_\n\n"

    md += "---\n\n_Delta analysis uses exact match overlaps only. " \
          "Similarity scoring engine planned for v2._\n"

    return md


def generate_delta(sha256: str) -> None:
    print(f"\n{'='*60}")
    print(f"  Running delta analysis: {sha256[:32]}...")
    print(f"{'='*60}")

    delta = run_delta(sha256)

    if "error" in delta:
        print(f"  [!] {delta['error']}")
        return

    corpus_size = delta.get("corpus_size", 0)
    print(f"  Corpus size : {corpus_size} sample(s)")

    if corpus_size == 0:
        print(f"  [~] No previous samples to compare against.")
        print(f"      Run more samples through the pipeline to enable delta analysis.")
    else:
        top = delta.get("top_match", {})
        print(f"  Top match   : {top.get('compared_sha256', 'n/a')[:16]}...")
        print(f"  Top score   : {top.get('overlap_score', 0)}")
        print(f"  Same family : {top.get('same_family', False)}")

    # Render and save report
    report_md = render_delta_report(delta)
    out_path = REPORTS_DIR / f"{sha256}.delta.md"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    # Save raw delta JSON
    json_path = REPORTS_DIR / f"{sha256}.delta.json"
    with open(json_path, "w") as f:
        json.dump(delta, f, indent=2)

    print(f"\n  [+] Delta report : {out_path.name}")
    print(f"  [+] Delta JSON   : {json_path.name}")
    print(f"{'='*60}")


def get_all_analysis_hashes() -> list[str]:
    analysis_dir = REPO_ROOT / "output" / "analysis"
    return [
        p.stem.replace(".analysis", "")
        for p in analysis_dir.glob("*.analysis.json")
    ]


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M10 Delta Analysis Orchestrator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("sha256", nargs="?", help="SHA256 of sample to analyze")
    group.add_argument("--all", action="store_true", help="Run delta for all analyzed samples")
    args = parser.parse_args()

    if args.all:
        hashes = get_all_analysis_hashes()
        print(f"Found {len(hashes)} analysis file(s)")
        for h in hashes:
            generate_delta(h)
    else:
        generate_delta(args.sha256)