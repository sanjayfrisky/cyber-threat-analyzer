"""
MITRE ATT&CK ingestion script — run separately after CISA KEV completes.
MITRE has ~600+ techniques and takes ~10-15 minutes on the free embedding tier.
Run from backend/ directory: python -u ingest_mitre.py
"""
import asyncio
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ingest_mitre")

sys.path.insert(0, ".")

from app.db.database import SessionLocal
from app.ai.rag.ingestion import ingest_scraped_records_async
from app.ai.rag.data_loader import load_mitre_attack
from sqlalchemy import text


async def main():
    db = SessionLocal()
    try:
        doc_before = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
        chunk_before = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
        logger.info("BEFORE: %d source_documents, %d document_chunks", doc_before, chunk_before)

        logger.info("=== Fetching MITRE ATT&CK techniques ===")
        records = load_mitre_attack()
        logger.info("MITRE ATT&CK returned %d techniques", len(records))

        result = await ingest_scraped_records_async(db, records)
        logger.info("MITRE ingestion: %s", result)

        doc_after = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
        chunk_after = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
        logger.info("AFTER:  %d source_documents, %d document_chunks", doc_after, chunk_after)
        logger.info("NET NEW: %d docs, %d chunks", doc_after - doc_before, chunk_after - chunk_before)

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
