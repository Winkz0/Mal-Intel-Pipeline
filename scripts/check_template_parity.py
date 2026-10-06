"""
check_template_parity.py
M13 v2 (D2.1) exit check: the synthesis_v1 template, rendered from a bundle built
with LEGACY_CAPS, must reproduce the pre-v2 prompt byte for byte.

Read-only: loads analysis JSONs, writes nothing.

Usage (pipeline, repo root, venv active):
    python scripts/check_template_parity.py ~/baseline-2026-04/output/analysis
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.llm_synthesis.bundle import DEFAULT_CAPS, LEGACY_CAPS, build_bundle
from pipeline.llm_synthesis.legacy_prompt import legacy_build_synthesis_prompt
from pipeline.llm_synthesis.prompt_builder import render

NOTE = "Parity check note: compare with prior variant; ignore $HOME and {braces}."


def first_diff(a: str, b: str) -> int:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def check(analysis: dict, notes: str) -> tuple[bool, str, int]:
    legacy = legacy_build_synthesis_prompt(analysis)
    if notes:
        legacy += f"\n\n## Analyst Notes\n{notes}"
    bundle = build_bundle(analysis, caps=LEGACY_CAPS, analyst_notes=notes)
    new = render(bundle, "synthesis_v1").prompt
    if new == legacy:
        return True, "", len(legacy)
    i = first_diff(legacy, new)
    ctx = f"at char {i}: legacy={legacy[max(0, i - 30):i + 30]!r} new={new[max(0, i - 30):i + 30]!r}"
    return False, ctx, len(legacy)


def main() -> int:
    ap = argparse.ArgumentParser(description="synthesis_v1 template parity check")
    ap.add_argument("analysis_dir", type=Path, help="directory of *.analysis.json files")
    args = ap.parse_args()

    files = sorted(args.analysis_dir.glob("*.analysis.json"))
    if not files:
        print(f"[!] no *.analysis.json files in {args.analysis_dir}")
        return 1

    failures = 0
    print(f"{'sample':<14}{'plain':<7}{'+notes':<8}{'legacy chars':>13}{'default-caps chars':>20}")
    for path in files:
        analysis = json.loads(path.read_text(encoding="utf-8"))
        ok_plain, ctx_plain, n = check(analysis, "")
        ok_notes, ctx_notes, _ = check(analysis, NOTE)
        default_len = len(render(build_bundle(analysis, caps=DEFAULT_CAPS), "synthesis_v1").prompt)
        print(f"{path.name[:12]:<14}{'OK' if ok_plain else 'DIFF':<7}{'OK' if ok_notes else 'DIFF':<8}"
              f"{n:>13,}{default_len:>20,}")
        for ok, ctx in ((ok_plain, ctx_plain), (ok_notes, ctx_notes)):
            if not ok:
                failures += 1
                print(f"    {ctx}")

    print(f"\n{len(files)} file(s), {failures} mismatch(es)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
