"""
ask.py
CLI entry point for the RAG analyst assistant.

Usage:
    python scripts/ask.py "which samples use process injection?"
    python scripts/ask.py "show me SmokeLoader IOCs" --family smokeloader
    python scripts/ask.py "what YARA rules have high confidence?" --doc-type synthesis
    python scripts/ask.py --interactive
"""

import sys
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pipeline.rag.assistant import ask


def run_query(question: str, family: str = None, doc_type: str = None, verbose: bool = False):
    """Execute a single query and print results."""
    print(f"\n{'='*60}")
    print(f"  Q: {question}")
    if family:
        print(f"  Filter: family={family}")
    if doc_type:
        print(f"  Filter: doc_type={doc_type}")
    print(f"{'='*60}\n")

    result = ask(
        question=question,
        family=family,
        doc_type=doc_type,
        verbose=verbose,
    )

    if result["error"]:
        print(f"  [!] Error: {result['error']}")
        return

    print(result["answer"])

    # Source attribution
    sources = result["sources"]
    if sources:
        families = set(s.get("family", "?") for s in sources)
        doc_types = set(s.get("doc_type", "?") for s in sources)
        print(f"\n{'─'*60}")
        print(f"  Sources: {len(sources)} chunks | Families: {', '.join(families)} | Types: {', '.join(doc_types)}")
    print()


def interactive_mode(family: str = None, doc_type: str = None, verbose: bool = False):
    """REPL loop for continuous querying."""
    print(f"\n{'='*60}")
    print(f"  Mal-Intel RAG Assistant — Interactive Mode")
    print(f"  Type 'quit' or 'exit' to stop")
    print(f"  Type 'reindex' to rebuild the vector store")
    print(f"{'='*60}\n")

    while True:
        try:
            question = input("  ask> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye.")
            break

        if not question:
            continue
        if question.lower() in ("quit", "exit", "q"):
            print("  Goodbye.")
            break
        if question.lower() == "reindex":
            from pipeline.rag.indexer import index_corpus
            count = index_corpus(force=True)
            print(f"  [+] Reindexed {count} chunks\n")
            continue

        run_query(question, family=family, doc_type=doc_type, verbose=verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="M11 RAG Analyst Assistant")
    parser.add_argument("question", nargs="?", help="Question to ask the corpus")
    parser.add_argument("--family", type=str, help="Filter results by malware family")
    parser.add_argument("--doc-type", type=str, help="Filter by doc type (analysis, synthesis, delta, yara_file, sigma_file)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Enter interactive REPL mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show retrieval debug info")
    args = parser.parse_args()

    if args.interactive:
        interactive_mode(family=args.family, doc_type=args.doc_type, verbose=args.verbose)
    elif args.question:
        run_query(args.question, family=args.family, doc_type=args.doc_type, verbose=args.verbose)
    else:
        parser.print_help()