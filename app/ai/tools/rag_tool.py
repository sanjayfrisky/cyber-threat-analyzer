"""Tool 4: RAG Retrieval — uses the existing hybrid search pipeline (pgvector + tsvector + RRF)."""
from __future__ import annotations

import logging
import time

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from app.ai.rag.pipeline import RAGPipeline
from app.ai.tools._tool_utils import get_db_session
from app.core.config import settings

logger = logging.getLogger(__name__)

_rag = RAGPipeline()


class RAGRetrieveInput(BaseModel):
    query: str = Field(
        description="Security question or topic to retrieve relevant documents for"
    )
    top_k: int = Field(
        default=6,
        ge=1,
        le=20,
        description="Number of document chunks to retrieve (default 6)",
    )


@tool(args_schema=RAGRetrieveInput)
def rag_retrieve(query: str, top_k: int = 6) -> dict:
    """
    Retrieve relevant cybersecurity documents using the existing hybrid search pipeline.

    Uses pgvector cosine similarity search + PostgreSQL full-text search with
    Reciprocal Rank Fusion (RRF) — no new vector database is created.

    Returns document chunks with source metadata (source, external_id, title, url, score).

    Use this tool for general threat intelligence questions, CVE context, or
    when you need supporting evidence before generating an answer.
    """
    t0 = time.perf_counter()
    query = query.strip()
    logger.info("[tool] rag_retrieve | query='%s' top_k=%d", query[:80], top_k)

    if not query:
        return {"query": query, "results": [], "note": "Empty query provided"}

    db = get_db_session()
    try:
        results = _rag.retrieve(db, query, top_k=top_k)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "[tool] rag_retrieve | %d chunks retrieved in %.1f ms", len(results), elapsed_ms
        )
        return {
            "query": query,
            "results": results,
            "retrieved_count": len(results),
            "confirmed_source": "Local vector DB (hybrid pgvector + tsvector RRF)",
        }
    finally:
        db.close()
