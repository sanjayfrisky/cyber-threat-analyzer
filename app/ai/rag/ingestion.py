import asyncio
import logging
from sqlalchemy.orm import Session
from app.core.config import settings
from app.ai.rag.pipeline import RAGPipeline
from app.ai.rag.embed import Embedder
from app.ai.rag.vector_store import chunk_text
from app.ai.rag.batch_process import BatchProcess, GEMINI_FREE_TIER_SETTINGS
from app.ai.rag.data_loader import load_cisa_kev, load_mitre_attack

logger = logging.getLogger(__name__)

try:
    from app.ai.rag.data_loader import load_nvd_recent
except ImportError:
    load_nvd_recent = None

LOADERS = {
    "mitre": load_mitre_attack,
    "cisa": load_cisa_kev,
}
if load_nvd_recent is not None:
    LOADERS["nvd"] = load_nvd_recent

def _create_default_batch_engine() -> BatchProcess:
    return BatchProcess(
        batch_size=settings.embedding_batch_size,
        max_concurrency=settings.embedding_max_concurrency,
        requests_per_minute=settings.embedding_requests_per_minute,
        tokens_per_minute=settings.embedding_tokens_per_minute,
        max_retries=settings.embedding_max_retries
    )

async def ingest_scraped_records_async(
    db: Session,
    records: list[dict],
    rag: RAGPipeline | None = None,
    embedder: Embedder | None = None,
    batch_engine: BatchProcess | None = None
) -> dict:
    """
    Asynchronously ingests scraped intelligence records using batch embedding.
    1. Bulk-checks existing external_ids in the vector DB and skips existing records.
    2. Chunks all new records' text.
    3. Batches all chunks and embeds them via BatchProcess (with rate limiting and retries).
    4. Bulk-inserts records and chunks into the vector DB.
    """
    if not records:
        return {"total_scraped": 0, "already_existing": 0, "newly_ingested": 0, "chunks_added": 0}

    rag = rag or RAGPipeline()
    existing_ids = rag.get_existing_external_ids(db)

    new_records = []
    already_existing = 0

    for record in records:
        ext_id = record.get("external_id")
        if ext_id and ext_id in existing_ids:
            already_existing += 1
        else:
            new_records.append(record)

    if not new_records:
        return {
            "total_scraped": len(records),
            "already_existing": already_existing,
            "newly_ingested": 0,
            "chunks_added": 0,
        }

    # Extract all chunks across new records
    all_chunks = []  # tuples of (external_id, chunk_index, content)
    for record in new_records:
        ext_id = record.get("external_id")
        parts = chunk_text(record.get("text", ""))
        for index, part in enumerate(parts):
            all_chunks.append((ext_id, index, part))

    if not all_chunks:
        return {
            "total_scraped": len(records),
            "already_existing": already_existing,
            "newly_ingested": len(new_records),
            "chunks_added": 0,
        }

    embedder = embedder or Embedder()
    batch_engine = batch_engine or _create_default_batch_engine()

    chunk_texts = [c[2] for c in all_chunks]

    async def embed_batch_fn(batch: list[str]) -> list[list[float]]:
        # In case embedder is a mock or sync function, call directly
        res = embedder.embed_batch(batch)
        if asyncio.iscoroutine(res):
            return await res
        return res

    all_embeddings = await batch_engine.run(chunk_texts, embed_batch_fn)

    # Group embeddings by external_id
    chunk_map: dict[str, list[tuple[int, str, list[float]]]] = {}
    for (ext_id, chunk_index, content), embedding in zip(all_chunks, all_embeddings):
        chunk_map.setdefault(ext_id, []).append((chunk_index, content, embedding))

    chunks_added = rag.bulk_ingest(db, new_records, chunk_map)

    return {
        "total_scraped": len(records),
        "already_existing": already_existing,
        "newly_ingested": len(new_records),
        "chunks_added": chunks_added,
    }

def ingest_scraped_records(
    db: Session,
    records: list[dict],
    rag: RAGPipeline | None = None,
    embedder: Embedder | None = None,
    batch_engine: BatchProcess | None = None
) -> dict:
    """
    Synchronous entry point for ingest_scraped_records.
    Safely executes the async batching logic regardless of caller context.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                asyncio.run,
                ingest_scraped_records_async(db, records, rag, embedder, batch_engine)
            ).result()
    else:
        return asyncio.run(ingest_scraped_records_async(db, records, rag, embedder, batch_engine))

async def scrape_and_ingest_all(db: Session, sources: list[str] | None = None) -> dict:
    """
    Scrapes external cyber threat feeds and ingests them into the vector DB
    using async batch processing for embeddings.
    """
    selected = set(sources or ["mitre", "cisa", "nvd"])
    summary = {}
    rag = RAGPipeline()
    embedder = Embedder()
    batch_engine = _create_default_batch_engine()

    for name, loader in LOADERS.items():
        if name not in selected:
            continue
        try:
            logger.info("Scraping source: %s", name)
            records = loader()
            result = await ingest_scraped_records_async(
                db, records, rag=rag, embedder=embedder, batch_engine=batch_engine
            )
            summary[name] = result
            logger.info(
                "Source %s completed: %d total, %d existing (skipped), %d new, %d chunks added",
                name, result["total_scraped"], result["already_existing"],
                result["newly_ingested"], result["chunks_added"]
            )
        except Exception as exc:
            logger.error("Scraping/ingestion failed for %s: %s", name, exc)
            summary[name] = {
                "error": str(exc),
                "total_scraped": 0,
                "already_existing": 0,
                "newly_ingested": 0,
                "chunks_added": 0
            }

    return summary

