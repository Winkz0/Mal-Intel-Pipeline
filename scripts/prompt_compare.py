"""
prompt_compare.py
M13 v2 (D2.4): score a candidate synthesis against a reference.

Inputs can be run directories (output/runs/<run_id>/), result files
(output/reports/<sha>.synthesis.json, <run>/synthesis.json) or bare synthesis
objects. Read-only.

Usage (pipeline, repo root, venv active):
    python scripts/prompt_compare.py REF CAND [--json]
    python scripts/prompt_compare.py --pairs pairs.json [--json]

pairs.json: [{"ref": "<path>", "cand": "<path>", "label": "optional"}, ...]
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.eval.compare import IOC_TYPES, CompareInputError, aggregate, compare, load_synthesis


def fmt(v):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def set_line(name, m):
    if m is None:
        return f"  {name:<22} n/a (field missing on one side)"
    if m.get("empty"):
        return f"  {name:<22} both empty"
    return (f"  {name:<22} J {fmt(m['jaccard'])}  P {fmt(m['precision'])}  R {fmt(m['recall'])}"
            f"   ref {m['ref']}  cand {m['cand']}  shared {m['tp']}")


def print_pair(ref_meta, cand_meta, s, label=None):
    if label:
        print(f"== {label}")
    for tag, m in (("ref ", ref_meta), ("cand", cand_meta)):
        print(f"  {tag} {m.get('run_id') or m['path']}  engine={m.get('engine') or '—'}  "
              f"model={m.get('model') or '—'}  template={m.get('template') or '—'}  "
              f"bundle={(m.get('bundle_sha256') or '—')[:12]}")
    if ref_meta.get("bundle_sha256") and ref_meta.get("bundle_sha256") == cand_meta.get("bundle_sha256"):
        print("  same bundle: yes")
    v = s["verdict"]
    if v:
        print(f"  {'classification':<22} {fmt(v['classification']['ref'])} -> {fmt(v['classification']['cand'])}"
              f"  match {fmt(v['classification']['match'])}")
        print(f"  {'family':<22} {fmt(v['family']['ref'])} -> {fmt(v['family']['cand'])}  match {fmt(v['family']['match'])}")
        print(f"  {'confidence':<22} {fmt(v['confidence']['ref'])} -> {fmt(v['confidence']['cand'])}"
              f"  delta {fmt(v['confidence']['delta'])}")
    else:
        print(f"  {'verdict':<22} n/a (field missing on one side)")
    a = s["attack"]
    print(set_line("ATT&CK exact", a and a["exact"]))
    print(set_line("ATT&CK parent", a and a["parent"]))
    if a and a["exact"] and not a["exact"]["empty"]:
        if a["exact"]["missed"]:
            print(f"  {'':<22} missed {', '.join(a['exact']['missed'])}")
        if a["exact"]["extra"]:
            print(f"  {'':<22} extra  {', '.join(a['exact']['extra'])}")
    i = s["iocs"]
    for k in IOC_TYPES + ("all",):
        print(set_line(f"IOC {k}", i and i.get(k)))
    m = s["manipulation"]
    if m:
        print(f"  {'manipulation flag':<22} {fmt(m['ref'])} -> {fmt(m['cand'])}  match {fmt(m['match'])}"
              f"  cand evidence {m['cand_evidence_count']}")
    for k, r in s["rules"].items():
        print(f"  {k + ' present':<22} {fmt(r['ref'])} -> {fmt(r['cand'])}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a candidate synthesis against a reference")
    ap.add_argument("ref", nargs="?")
    ap.add_argument("cand", nargs="?")
    ap.add_argument("--pairs", type=Path, help="JSON list of {ref, cand, label}")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.pairs:
        if args.ref or args.cand:
            ap.error("use either REF CAND or --pairs, not both")
        pairs = json.loads(args.pairs.read_text(encoding="utf-8"))
    elif args.ref and args.cand:
        pairs = [{"ref": args.ref, "cand": args.cand}]
    else:
        ap.error("need REF and CAND, or --pairs")

    results, failures = [], 0
    for pr in pairs:
        try:
            r, rm = load_synthesis(pr["ref"])
            c, cm = load_synthesis(pr["cand"])
        except (CompareInputError, KeyError) as e:
            failures += 1
            results.append({"label": pr.get("label"), "error": str(e)})
            if not args.json:
                print(f"[!] {pr.get('label') or ''} {e}")
            continue
        s = compare(r, c)
        results.append({"label": pr.get("label"), "ref": rm, "cand": cm, "scores": s})
        if not args.json:
            print_pair(rm, cm, s, pr.get("label"))
            print()

    scored = [x["scores"] for x in results if "scores" in x]
    summary = aggregate(scored) if len(pairs) > 1 else None
    if args.json:
        print(json.dumps({"pairs": results, "aggregate": summary}, indent=2))
    elif summary:
        print("== aggregate")
        for k, v in summary.items():
            print(f"  {k:<32} {v}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
