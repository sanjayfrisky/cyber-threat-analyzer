from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.db.database import SourceDocument, DocumentChunk
from app.ai.rag.embed import Embedder

def chunk_text(text: str, chunk_size=1200, overlap=180) -> list[str]:
    text = " ".join(text.split())
    if not text:
        return []
    if overlap >= chunk_size:
        raise ValueError("overlap must be smaller than chunk_size")
    chunks, start = [], 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            boundary = max(text.rfind(". ", start, end), text.rfind(" ", start, end))
            if boundary > start + chunk_size // 2:
                end = boundary + 1
        part = text[start:end].strip()
        if part:
            chunks.append(part)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks

class VectorStore:
    def __init__(self):
        self.embedder = Embedder()

    def get_existing_external_ids(self, db: Session, source: str | None = None) -> set[str]:
        stmt = select(SourceDocument.external_id)
        if source:
            stmt = stmt.where(SourceDocument.source == source)
        return set(db.scalars(stmt).all())

    def document_exists(self, db: Session, external_id: str) -> bool:
        stmt = select(SourceDocument.id).where(SourceDocument.external_id == external_id)
        return db.scalar(stmt) is not None

    def upsert_document(self, db: Session, item: dict, skip_if_exists: bool = False) -> int:
        doc = db.scalar(select(SourceDocument).where(SourceDocument.external_id == item["external_id"]))
        if doc and skip_if_exists:
            chunk_count = db.scalar(
                select(func.count()).select_from(DocumentChunk).where(DocumentChunk.document_id == doc.id)
            ) or 0
            if chunk_count > 0:
                return 0

        if doc:
            db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).delete()
        else:
            doc = SourceDocument(source=item["source"], external_id=item["external_id"], title=item["title"][:500])
            db.add(doc)
            db.flush()

        doc.source, doc.title = item["source"], item["title"][:500]
        doc.url, doc.category = item.get("url"), item.get("category")
        doc.raw_metadata = item.get("metadata", {})
        parts = chunk_text(item.get("text", ""))
        for index, part in enumerate(parts):
            db.add(DocumentChunk(
                document_id=doc.id,
                chunk_index=index,
                content=part,
                embedding=self.embedder.embed(part),
                source=item["source"],
                external_id=item["external_id"],
                title=item["title"][:500],
                url=item.get("url"),
                metadata_json=item.get("metadata", {})
            ))
        db.commit()
        return len(parts)

    def bulk_ingest(
        self,
        db: Session,
        records: list[dict],
        chunk_embeddings: dict[str, list[tuple[int, str, list[float]]]]
    ) -> int:
        """
        Bulk insert source documents and their pre-computed embedded chunks.
        chunk_embeddings maps external_id to list of (chunk_index, content, embedding_vector).
        Returns total number of chunks created.
        """
        if not records:
            return 0

        total_chunks = 0
        for item in records:
            ext_id = item["external_id"]
            chunks = chunk_embeddings.get(ext_id, [])
            if not chunks:
                continue

            doc = db.scalar(select(SourceDocument).where(SourceDocument.external_id == ext_id))
            if doc:
                db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).delete()
            else:
                doc = SourceDocument(
                    source=item["source"],
                    external_id=ext_id,
                    title=item["title"][:500]
                )
                db.add(doc)
                db.flush()

            doc.source, doc.title = item["source"], item["title"][:500]
            doc.url, doc.category = item.get("url"), item.get("category")
            doc.raw_metadata = item.get("metadata", {})

            for chunk_index, content, embedding in chunks:
                db.add(DocumentChunk(
                    document_id=doc.id,
                    chunk_index=chunk_index,
                    content=content,
                    embedding=embedding,
                    source=item["source"],
                    external_id=ext_id,
                    title=item["title"][:500],
                    url=item.get("url"),
                    metadata_json=item.get("metadata", {})
                ))
                total_chunks += 1

        db.commit()
        return total_chunks

    def search(self, db: Session, query: str, top_k=6) -> list[dict]:
        vector = self.embedder.embed(query, task_type="RETRIEVAL_QUERY")
        vector_rows = db.scalars(select(DocumentChunk).order_by(
            DocumentChunk.embedding.cosine_distance(vector)).limit(top_k * 3)).all()
        tsq = func.plainto_tsquery("english", query)
        keyword_rows = db.scalars(select(DocumentChunk).where(
            func.to_tsvector("english", DocumentChunk.content).op("@@")(tsq)
        ).order_by(func.ts_rank(func.to_tsvector("english", DocumentChunk.content), tsq).desc()).limit(top_k * 3)).all()
        scores, records = {}, {}
        for rows in (vector_rows, keyword_rows):
            for rank, row in enumerate(rows, 1):
                scores[row.id] = scores.get(row.id, 0) + 1/(60+rank)
                records[row.id] = row
        ordered = sorted(scores, key=scores.get, reverse=True)[:top_k]
        return [{"content":records[i].content,"source":records[i].source,"external_id":records[i].external_id,
                 "title":records[i].title,"url":records[i].url,"score":scores[i]} for i in ordered]
