"""Debug script: check DB record counts and CVE-2021-44228 presence."""
import sys
sys.path.insert(0, ".")

from app.db.database import SessionLocal
from sqlalchemy import text

db = SessionLocal()
try:
    doc_count = db.execute(text("SELECT COUNT(*) FROM source_documents")).scalar()
    chunk_count = db.execute(text("SELECT COUNT(*) FROM document_chunks")).scalar()
    print(f"Total SourceDocuments: {doc_count}")
    print(f"Total DocumentChunks: {chunk_count}")

    rows = db.execute(
        text("SELECT source, COUNT(*) as cnt FROM source_documents GROUP BY source ORDER BY cnt DESC")
    ).all()
    print("--- By Source ---")
    for src, cnt in rows:
        print(f"  {src}: {cnt} docs")

    # CVE-2021-44228 check
    cve_rows = db.execute(
        text("SELECT id, external_id, title, source FROM source_documents WHERE external_id ILIKE '%44228%' LIMIT 5")
    ).all()
    print("--- CVE-2021-44228 records ---")
    if cve_rows:
        for r in cve_rows:
            print(f"  id={r[0]}, external_id={r[1]}, source={r[3]}, title={str(r[2])[:60]}")
    else:
        print("  NOT FOUND in database")

    # Check embedding validity on first chunk
    first_chunk = db.execute(
        text("SELECT id, content, source FROM document_chunks LIMIT 1")
    ).first()
    if first_chunk:
        print(f"\n--- Sample chunk ---")
        print(f"  id={first_chunk[0]}, source={first_chunk[2]}")
        print(f"  content[:80]={first_chunk[1][:80]}")
        emb = db.execute(
            text(f"SELECT embedding IS NOT NULL FROM document_chunks WHERE id={first_chunk[0]}")
        ).scalar()
        print(f"  has embedding: {emb}")
    else:
        print("\nNo document chunks found.")
finally:
    db.close()
print("DONE")
