from app.ai.rag.vector_store import VectorStore

def build_context(results: list[dict]) -> str:
    if not results:
        return "No matching indexed documents were found."
    return "\n\n".join(
        f"[S{i}] Source: {r['source']} | ID: {r['external_id']}\nTitle: {r['title']}\n"
        f"URL: {r.get('url') or 'Not supplied'}\nContent: {r['content']}"
        for i, r in enumerate(results, 1)
    )

class RAGPipeline:
    def __init__(self):
        self.store = VectorStore()

    def retrieve(self, db, query: str, top_k=6):
        return self.store.search(db, query, top_k)

    def ingest(self, db, record: dict, skip_if_exists: bool = False):
        return self.store.upsert_document(db, record, skip_if_exists=skip_if_exists)

    def bulk_ingest(self, db, records: list[dict], chunk_embeddings: dict) -> int:
        return self.store.bulk_ingest(db, records, chunk_embeddings)

    def get_existing_external_ids(self, db, source: str | None = None) -> set[str]:
        return self.store.get_existing_external_ids(db, source=source)
