"""
indexer.py
Loads all corpus documents, chunks them, and indexes into ChromaDB.
Supports full reindex and incremental updates.
"""

import logging
import hashlib
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from pipeline.rag.chunkers import (
    chunk_analysis,
    chunk_synthesis,
    chunk_delta,
    chunk_yara_file,
    chunk_sigma_file,
)

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
CHROMA_DIR = REPO_ROOT / "data" / "chromadb"
COLLECTION_NAME = "mal_intel_corpus"

# Directories to index
ANALYSIS_DIR = REPO_ROOT / "output" / "analysis"
REPORTS_DIR = REPO_ROOT / "output" / "reports"
YARA_DIR = REPO_ROOT / "output" / "rules" / "yara"
SIGMA_DIR = REPO_ROOT / "output" / "rules" / "sigma"


def get_collection():
    """Initialize ChromaDB client and return the corpus collection."""
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Use local sentence-transformers for embedding — no API cost
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"}
    )
    return collection


def make_chunk_id(source_file: str, section: str, index: int) -> str:
    """Deterministic chunk ID so re-indexing overwrites instead of duplicating."""
    raw = f"{source_file}::{section}::{index}"
    return hashlib.md5(raw.encode()).hexdigest()


def gather_documents() -> list[dict]:
    """Walk all output directories and chunk everything."""
    all_chunks = []

    # Analysis JSONs
    if ANALYSIS_DIR.exists():
        for path in ANALYSIS_DIR.glob("*.analysis.json"):
            try:
                all_chunks.extend(chunk_analysis(path))
            except Exception as e:
                logger.warning(f"Failed to chunk {path.name}: {e}")

    # Synthesis JSONs
    if REPORTS_DIR.exists():
        for path in REPORTS_DIR.glob("*.synthesis.json"):
            try:
                all_chunks.extend(chunk_synthesis(path))
            except Exception as e:
                logger.warning(f"Failed to chunk {path.name}: {e}")

    # Delta JSONs
    if REPORTS_DIR.exists():
        for path in REPORTS_DIR.glob("*.delta.json"):
            try:
                all_chunks.extend(chunk_delta(path))
            except Exception as e:
                logger.warning(f"Failed to chunk {path.name}: {e}")

    # YARA rules
    if YARA_DIR.exists():
        for path in YARA_DIR.glob("*.yar"):
            try:
                all_chunks.extend(chunk_yara_file(path))
            except Exception as e:
                logger.warning(f"Failed to chunk {path.name}: {e}")

    # Sigma rules
    if SIGMA_DIR.exists():
        for path in SIGMA_DIR.glob("*.yml"):
            try:
                all_chunks.extend(chunk_sigma_file(path))
            except Exception as e:
                logger.warning(f"Failed to chunk {path.name}: {e}")

    return all_chunks


def index_corpus(force: bool = False) -> int:
    """
    Index the full corpus into ChromaDB.
    force=True wipes and rebuilds; otherwise upserts (idempotent).
    """
    collection = get_collection()

    if force:
        # Wipe existing data
        client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        client.delete_collection(COLLECTION_NAME)
        collection = get_collection()
        logger.info("Force reindex: wiped existing collection")

    chunks = gather_documents()

    if not chunks:
        logger.warning("No documents found to index")
        return 0

    # Prepare batch upsert
    ids = []
    documents = []
    metadatas = []

    for i, chunk in enumerate(chunks):
        source = chunk["metadata"].get("source_file", "unknown")
        section = chunk["metadata"].get("section", "unknown")
        chunk_id = make_chunk_id(source, section, i)

        ids.append(chunk_id)
        documents.append(chunk["text"])
        metadatas.append(chunk["metadata"])

    # ChromaDB batch limit is 5461 — batch if needed
    batch_size = 5000
    for start in range(0, len(ids), batch_size):
        end = start + batch_size
        collection.upsert(
            ids=ids[start:end],
            documents=documents[start:end],
            metadatas=metadatas[start:end],
        )

    logger.info(f"Indexed {len(ids)} chunks into ChromaDB")
    return len(ids)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="M11 RAG Corpus Indexer")
    parser.add_argument("--force", action="store_true", help="Wipe and rebuild index from scratch")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  M11: RAG Corpus Indexer")
    print(f"{'='*60}")

    count = index_corpus(force=args.force)
    print(f"  [+] Indexed {count} chunks")
    print(f"  [+] Vector store: {CHROMA_DIR}")
    print(f"{'='*60}")