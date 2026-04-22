"""
retriever.py
Queries ChromaDB for the most relevant corpus chunks given a natural language query.
Supports optional metadata filtering by family, doc_type, section.
"""

import logging
from pipeline.rag.indexer import get_collection

logger = logging.getLogger(__name__)


def retrieve(
    query: str,
    n_results: int = 10,
    family: str = None,
    doc_type: str = None,
    section: str = None,
) -> list[dict]:
    """
    Semantic search over the indexed corpus.

    Returns list of dicts: {"text": str, "metadata": dict, "distance": float}
    Lower distance = more relevant (cosine distance).
    """
    collection = get_collection()

    if collection.count() == 0:
        logger.warning("Index is empty — run indexer first")
        return []

    # Build optional metadata filter
    where_filter = None
    conditions = []
    if family:
        conditions.append({"family": {"$eq": family}})
    if doc_type:
        conditions.append({"doc_type": {"$eq": doc_type}})
    if section:
        conditions.append({"section": {"$eq": section}})

    if len(conditions) == 1:
        where_filter = conditions[0]
    elif len(conditions) > 1:
        where_filter = {"$and": conditions}

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    # Flatten ChromaDB's nested list structure
    hits = []
    for i in range(len(results["ids"][0])):
        hits.append({
            "text": results["documents"][0][i],
            "metadata": results["metadatas"][0][i],
            "distance": results["distances"][0][i],
        })

    return hits


def format_context(hits: list[dict], max_chars: int = 12000) -> str:
    """
    Formats retrieval hits into a context block for the LLM prompt.
    Respects a character budget to avoid blowing up the context window.
    """
    lines = []
    char_count = 0

    for i, hit in enumerate(hits):
        meta = hit["metadata"]
        header = f"[{i+1}] {meta.get('doc_type','?')}/{meta.get('section','?')} — {meta.get('family','?')} ({meta.get('sha256','?')[:16]})"
        entry = f"{header}\n{hit['text']}\n"

        if char_count + len(entry) > max_chars:
            break

        lines.append(entry)
        char_count += len(entry)

    return "\n".join(lines)