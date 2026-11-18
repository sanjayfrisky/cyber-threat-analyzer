
from langchain_core.documents import Document

from app.ai.rag.vector_store import VectorStore


def build_context(results: list[dict]) -> str:

    if not results:
        return "No matching indexed documents were found."

    return "\n\n".join(
        f"[S{i}] Source: {r['source']} | ID: {r['external_id']}\n"
        f"Title: {r['title']}\n"
        f"URL: {r.get('url') or 'Not supplied'}\n"
        f"Content: {r['content']}"
        for i, r in enumerate(results, 1)
    )


class RAGPipeline:

    def __init__(self):
        self.store = VectorStore()

    # Existing retrieval method - preserve compatibility
    def retrieve(self, db, query: str, top_k=6):
        return self.store.search(db, query, top_k)

    # New LangChain integration
    def retrieve_documents(
        self,
        db,
        query: str,
        top_k: int = 6
    ) -> list[Document]:

        results = self.retrieve(db, query, top_k)

        documents = []

        for result in results:

            metadata = {
                "source": result["source"],
                "external_id": result["external_id"],
                "title": result["title"],
                "url": result.get("url"),
                "score": result.get("score")
            }

            metadata = {
                key: value
                for key, value in metadata.items()
                if value is not None
            }

            documents.append(
                Document(
                    page_content=result["content"],
                    metadata=metadata
                )
            )

        return documents

    # Existing ingestion methods
    def ingest(
        self,
        db,
        record: dict,
        skip_if_exists: bool = False
    ):
        return self.store.upsert_document(
            db,
            record,
            skip_if_exists=skip_if_exists
        )

    def bulk_ingest(
        self,
        db,
        records: list[dict],
        chunk_embeddings: dict
    ) -> int:

        return self.store.bulk_ingest(
            db,
            records,
            chunk_embeddings
        )

    def get_existing_external_ids(
        self,
        db,
        source: str | None = None
    ) -> set[str]:

        return self.store.get_existing_external_ids(
            db,
            source=source
        )
