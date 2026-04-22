"""
assistant.py
RAG-powered analyst assistant.
Retrieves relevant corpus context, injects it into a Claude prompt,
and returns a grounded answer.
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

import anthropic

from pipeline.rag.retriever import retrieve, format_context

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / "config" / "secrets.env")

MODEL = "claude-sonnet-4-5"

SYSTEM_PROMPT = """You are an analyst assistant for the Mal-Intel-Pipeline, a malware intelligence and analysis platform.

You answer questions using ONLY the retrieved corpus context provided below. If the context doesn't contain enough information to answer, say so — do not hallucinate or infer beyond what the data shows.

When referencing samples, use their family name and truncated SHA256 (first 16 chars).
When citing specific findings, mention which document type the information came from (analysis, synthesis, delta, YARA rule, Sigma rule).

Be concise and technical. The analyst asking these questions is experienced — no hand-holding."""


def ask(
    question: str,
    n_results: int = 10,
    family: str = None,
    doc_type: str = None,
    verbose: bool = False,
) -> dict:
    """
    Ask a question against the corpus.

    Returns dict with:
    - answer: str (Claude's response)
    - sources: list of metadata dicts for retrieved chunks
    - error: str or None
    """
    result = {"answer": None, "sources": [], "error": None}

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        result["error"] = "ANTHROPIC_API_KEY not set"
        return result

    # 1. Retrieve relevant context
    hits = retrieve(
        query=question,
        n_results=n_results,
        family=family,
        doc_type=doc_type,
    )

    if not hits:
        result["answer"] = "No relevant documents found in the corpus. Run the indexer first or try a different query."
        return result

    result["sources"] = [h["metadata"] for h in hits]
    context = format_context(hits)

    if verbose:
        print(f"\n  [RAG] Retrieved {len(hits)} chunks")
        for i, h in enumerate(hits[:5]):
            print(f"    [{i+1}] dist={h['distance']:.3f} | {h['metadata'].get('family','?')}/{h['metadata'].get('section','?')}")

    # 2. Build prompt
    user_prompt = f"""## Retrieved Corpus Context

{context}

---

## Analyst Question

{question}"""

    # 3. Call Claude
    try:
        client = anthropic.Anthropic(api_key=api_key)

        message = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        result["answer"] = message.content[0].text

    except anthropic.APIError as e:
        result["error"] = f"Claude API error: {e}"
        logger.error(result["error"])
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.error(result["error"])

    return result