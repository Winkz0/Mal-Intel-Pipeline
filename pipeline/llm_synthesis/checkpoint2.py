"""
checkpoint2.py
Human Checkpoint #2 — analyst reviews static analysis findings
before LLM synthesis API call is made.
Analyst can add notes that get injected into the synthesis prompt.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run_checkpoint2(analysis: dict, cost_estimate: dict) -> tuple[bool, str]:
    """
    Present analysis summary to analyst for review.
    Returns (proceed: bool, analyst_notes: str).
    """
    sample = analysis.get("sample", {})
    static = analysis.get("static_analysis", {})
    iocs = analysis.get("ioc_candidates", {})

    print(f"\n{'='*60}")
    print(f"  CHECKPOINT #2 — PRE-SYNTHESIS REVIEW")
    print(f"{'='*60}")
    print(f"  Sample   : {sample.get('sha256', 'unknown')[:32]}...")
    print(f"  Family   : {sample.get('malware_family', 'unknown')}")
    print(f"  Type     : {sample.get('file_type', 'unknown')}")

    print(f"\n  --- Static Analysis Summary ---")
    floss = static.get("floss", {})
    capa = static.get("capa", {})
    diec = static.get("diec", {})
    pe = static.get("pefile", {})

    print(f"  FLOSS    : {floss.get('total_static', 0)} strings, "
          f"{len(floss.get('notable_strings', []))} notable")
    print(f"  Capa     : {capa.get('total_capabilities', 0)} capabilities, "
          f"{capa.get('total_attack_ttps', 0)} ATT&CK TTPs")
    print(f"  diec     : {diec.get('file_type', 'unknown')} | "
          f"packed: {diec.get('is_packed', False)}")
    print(f"  pefile   : {'PE parsed' if pe.get('is_pe') else 'not a PE'}")

    print(f"\n  --- IOC Candidates ---")
    print(f"  IPs      : {len(iocs.get('ips', []))}")
    print(f"  URLs     : {len(iocs.get('urls', []))}")
    print(f"  Commands : {len(iocs.get('commands', []))}")

    print(f"\n  --- Cost Estimate ---")
    print(f"  Model    : {cost_estimate.get('model', 'unknown')}")
    print(f"  Input    : ~{cost_estimate.get('estimated_input_tokens', 0):,} tokens")
    print(f"  Output   : ~{cost_estimate.get('estimated_output_tokens', 0):,} tokens")
    print(f"  Est. Cost: ${cost_estimate.get('estimated_cost_usd', 0):.6f} USD")

    print(f"\n  Options:")
    print(f"  [y] Proceed with synthesis")
    print(f"  [n] Abort")
    print(f"  [d] Dry run (no API call)")
    print(f"  [note] Add analyst notes before proceeding")

    analyst_notes = ""

    while True:
        cmd = input("\n  Selection: ").strip().lower()

        if cmd == "y":
            return True, analyst_notes

        elif cmd == "n":
            print("  [!] Synthesis aborted.")
            return False, ""

        elif cmd == "d":
            print("  [*] Dry run mode selected.")
            return "dry", analyst_notes

        elif cmd == "note":
            print("  Enter notes (press Enter twice to finish):")
            lines = []
            while True:
                line = input("  > ")
                if line == "":
                    break
                lines.append(line)
            analyst_notes = "\n".join(lines)
            print(f"  [+] Notes added ({len(analyst_notes)} chars)")

        else:
            print("  [!] Unknown command. Enter y, n, d, or note.")