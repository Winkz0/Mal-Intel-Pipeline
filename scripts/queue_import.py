"""
queue_import.py
M13 v2 (D2.6): import Claude Desktop answers pushed back by the Vivo.

Reads <queue>/returned/*.synthesis.json, checks each against its pending request
and stored bundle, re-validates the schema here (validation on the Vivo is not
trusted), and records a normal run (engine desktop-mcp). Production imports
also write output/reports/<sha>.synthesis.json and mark the sample SYNTHESIZED.

Usage (pipeline, repo root, venv active):
    python scripts/queue_import.py --model "<model selected in Desktop>"
    python scripts/queue_import.py --model "<model>" --eval LABEL
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.llm_synthesis import desktop_queue
from pipeline.utils import run_context


def main() -> int:
    ap = argparse.ArgumentParser(description="Import Claude Desktop answers from the synthesis queue")
    ap.add_argument("--model", required=True,
                    help='model selected in the Desktop app, recorded in the manifest (e.g. "claude-opus-5-5")')
    ap.add_argument("--eval", metavar="LABEL", help="import into output/eval/LABEL/ instead of production")
    args = ap.parse_args()

    if not args.model.strip():
        ap.error("--model must not be empty")

    if args.eval:
        try:
            run_context.enter_eval(args.eval)
        except ValueError as e:
            print(f"[!] {e}")
            return 2
        qdir = desktop_queue.queue_root(REPO_ROOT, args.eval)
        bdir = desktop_queue.bundle_dir_for(REPO_ROOT, args.eval)
        runs_dir = run_context.eval_root(REPO_ROOT, args.eval) / "runs"
        mode, save = "eval", None
    else:
        from pipeline.llm_synthesis.synthesizer import save_synthesis
        from pipeline.utils.db import update_status

        def save(result):
            save_synthesis(result)
            update_status(result["sample"]["sha256"], "SYNTHESIZED")

        qdir = desktop_queue.queue_root(REPO_ROOT)
        bdir = desktop_queue.bundle_dir_for(REPO_ROOT)
        runs_dir, mode = None, "prod"

    if not (qdir / "returned").is_dir():
        print(f"[~] Nothing to import: {qdir / 'returned'} does not exist")
        return 0

    outcomes = desktop_queue.import_returned(qdir, bdir, args.model.strip(), runs_dir=runs_dir,
                                             mode=mode, save=save)
    if not outcomes:
        print("[~] Nothing to import")
        return 0

    bad = 0
    for o in outcomes:
        tag = {"imported": "[+]", "invalid": "[!]", "rejected": "[!]"}[o["status"]]
        print(f"  {tag} {o['status']:<9} {o['file'][:24]}...  {o['run'] or ''}")
        if o["error"]:
            bad += 1
            print(f"      {o['error']}")
            for d in o.get("details") or []:
                print(f"        - {d}")
    print(f"\n{len(outcomes)} file(s): {len(outcomes) - bad} imported, {bad} rejected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
