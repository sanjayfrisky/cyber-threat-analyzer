"""
Initial ingestion script.
Step 1: Ingest CVE-2021-44228 specifically from NVD by ID.
Step 2: Ingest CISA KEV (all known exploited vulnerabilities).
Step 3: Optionally ingest MITRE ATT&CK (large - ~600 techniques).
Run from backend/ directory: python -u ingest_initial.py
"""
import asyncio
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ingest_initial")

sys.path.insert(0, ".")

from app.db.database import SessionLocal
from app.ai.rag.ingestion import ingest_scraped_records_async, scrape_and_ingest_all
from app.ai.rag.data_loader import load_nvd_cve_by_id, load_cisa_kev
from sqlalchemy import text


async def main():
    db = SessionLocal()
    try:
        # ----- Step 0: DB counts before -----
        doc_before = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
        chunk_before = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
        logger.info("BEFORE: %d source_documents, %d document_chunks", doc_before, chunk_before)

        # ----- Step 1: Targeted NVD CVE-2021-44228 -----
        logger.info("=== Step 1: Fetching CVE-2021-44228 from NVD by ID ===")
        record = load_nvd_cve_by_id("CVE-2021-44228")
        if record:
            logger.info("Got NVD record: %s", record["title"][:80])
            result = await ingest_scraped_records_async(db, [record])
            logger.info("Ingestion result: %s", result)
        else:
            logger.error("NVD returned no data for CVE-2021-44228")

        # Also ingest a few more important CVEs for breadth
        important_cves = ["CVE-2021-45046", "CVE-2022-26134", "CVE-2023-44487", "CVE-2024-3400"]
        for cve_id in important_cves:
            try:
                rec = load_nvd_cve_by_id(cve_id)
                if rec:
                    res = await ingest_scraped_records_async(db, [rec])
                    logger.info("Ingested %s: %s", cve_id, res)
            except Exception as e:
                logger.warning("Failed to fetch %s: %s", cve_id, e)

        # ----- Step 2: CISA KEV -----
        logger.info("=== Step 2: Ingesting CISA KEV (all known exploited vulnerabilities) ===")
        try:
            cisa_records = load_cisa_kev()
            logger.info("CISA KEV returned %d records", len(cisa_records))
            result = await ingest_scraped_records_async(db, cisa_records)
            logger.info("CISA KEV ingestion: %s", result)
        except Exception as e:
            logger.error("CISA KEV ingestion failed: %s", e)

        # ----- Final counts -----
        doc_after = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
        chunk_after = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
        logger.info("AFTER:  %d source_documents, %d document_chunks", doc_after, chunk_after)
        logger.info("NET NEW: %d docs, %d chunks", doc_after - doc_before, chunk_after - chunk_before)

        # ----- Verify CVE-2021-44228 is now retrievable -----
        logger.info("=== Verifying CVE-2021-44228 retrieval ===")
        from app.ai.rag.pipeline import RAGPipeline
        rag = RAGPipeline()
        results = rag.retrieve(db, "CVE-2021-44228 Log4Shell remediation", top_k=6)
        logger.info("Retrieval returned %d results", len(results))
        for r in results:
            logger.info("  external_id=%s, source=%s, score=%.4f, title=%s",
                        r["external_id"], r["source"], r.get("score", 0), r["title"][:60])

    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
