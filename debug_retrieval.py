"""Quick retrieval test for CVE-2021-44228 — run while ingestion is still going."""
import sys
sys.path.insert(0, ".")
from app.db.database import SessionLocal
from sqlalchemy import text

db = SessionLocal()
try:
    # Count current state
    doc_count = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
    chunk_count = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
    print(f"Current: {doc_count} source_documents, {chunk_count} document_chunks")

    rows = db.execute(text("SELECT source, COUNT(*) FROM source_documents GROUP BY source ORDER BY source")).all()
    for src, cnt in rows:
        print(f"  {src}: {cnt} docs")

    # Confirm CVE-2021-44228 is in DB
    cve_check = db.execute(
        text("SELECT id, external_id, title FROM source_documents WHERE external_id = 'CVE-2021-44228'")
    ).first()
    print(f"\nCVE-2021-44228 record: {cve_check}")

    chunks = db.execute(
        text("SELECT id, chunk_index, LEFT(content, 120) FROM document_chunks WHERE external_id = 'CVE-2021-44228'")
    ).all()
    print(f"CVE-2021-44228 chunks: {len(chunks)}")
    for c in chunks:
        print(f"  chunk {c[1]}: {c[2]}")

    # Test RAG retrieval
    print("\n--- RAG Retrieval Test: 'CVE-2021-44228 Log4Shell remediation' ---")
    from app.ai.rag.pipeline import RAGPipeline
    rag = RAGPipeline()
    results = rag.retrieve(db, "CVE-2021-44228 Log4Shell remediation", top_k=6)
    print(f"Results returned: {len(results)}")
    for r in results:
        print(f"  external_id={r['external_id']}, source={r['source']}, score={r.get('score', 0):.4f}")
        print(f"  title={r['title'][:70]}")
        print(f"  content[:100]={r['content'][:100]}")
        print()

    # Also test build_context
    from app.ai.rag.pipeline import build_context
    ctx = build_context(results)
    print("--- Context snippet ---")
    print(ctx[:800])

finally:
    db.close()
print("DONE")
