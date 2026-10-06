"""
publish.py
M13 v2 (D2.5): steps that run only after the analyst approves at checkpoint #3
(rule_validation/validate.py): delta analysis, STIX export, then the RAG reindex
(last, so it picks up the new delta). Before D2.5 these ran inside report.py,
ahead of the checkpoint.

Heavy imports (chromadb, stix2) load here, on demand.
"""

from pipeline.utils.run_context import require_side_effects


def publish_after_approval(sha256: str) -> bool:
    """Run the post-approval steps. Returns True if all of them succeeded."""
    require_side_effects("post-approval publish")
    ok = True
    print(f"\n  [*] Post-approval steps for {sha256[:16]}...")

    try:
        from pipeline.delta_analysis.delta import generate_delta
        generate_delta(sha256)
        print("  [+] Delta analysis   : Complete")
    except Exception as e:
        ok = False
        print(f"  [!] Delta analysis   : Failed ({e})")

    try:
        from pipeline.export.stix_export import export_stix
        stix_path = export_stix(sha256)
        if stix_path:
            print(f"  [+] STIX export      : {stix_path.name}")
    except Exception as e:
        ok = False
        print(f"  [!] STIX export      : Failed ({e})")

    try:
        from pipeline.rag.indexer import index_corpus
        count = index_corpus()
        print(f"  [+] RAG reindex      : {count} chunks indexed")
    except Exception as e:
        ok = False
        print(f"  [!] RAG reindex      : Failed ({e})")

    return ok
