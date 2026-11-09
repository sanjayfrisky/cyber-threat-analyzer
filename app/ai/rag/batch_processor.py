"""
Re-export module for backward compatibility.
Batching engine is located in app.ai.rag.batch_process.
Ingestion logic is located in app.ai.rag.ingestion.
"""
from app.ai.rag.batch_process import (
    BatchProcess,
    LOCAL_EMBEDDING_SETTINGS,
    GEMINI_FREE_TIER_SETTINGS,
    BASE_RETRY_DELAY,
    MAX_RETRY_DELAY,
    RATE_LIMIT_WINDOW,
    CHARS_PER_TOKEN,
)
from app.ai.rag.ingestion import (
    LOADERS,
    ingest_scraped_records,
    ingest_scraped_records_async,
    scrape_and_ingest_all,
)

class BatchProcessor:
    """Legacy class wrapper for backward compatibility."""
    def __init__(self):
        from app.ai.rag.pipeline import RAGPipeline
        self.rag = RAGPipeline()

    def run(self, db, sources=None, records=None):
        if records is not None:
            return ingest_scraped_records(db, records, rag=self.rag)
        import asyncio
        return asyncio.run(scrape_and_ingest_all(db, sources=sources))
