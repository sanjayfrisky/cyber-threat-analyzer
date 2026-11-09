import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from sqlalchemy.orm import Session

from app.ai.rag.embed import Embedder
from app.ai.rag.batch_process import BatchProcess, GEMINI_FREE_TIER_SETTINGS
from app.ai.rag.vector_store import VectorStore
from app.ai.rag.ingestion import ingest_scraped_records_async, scrape_and_ingest_all
from app.db.database import SourceDocument, DocumentChunk

def test_embed_batch_success():
    with patch("google.genai.Client") as mock_genai:
        mock_client = MagicMock()
        mock_emb_1 = MagicMock()
        mock_emb_1.values = [0.1, 0.2, 0.3]
        mock_emb_2 = MagicMock()
        mock_emb_2.values = [0.4, 0.5, 0.6]

        mock_resp = MagicMock()
        mock_resp.embeddings = [mock_emb_1, mock_emb_2]
        mock_client.models.embed_content.return_value = mock_resp
        mock_genai.return_value = mock_client

        embedder = Embedder()
        results = embedder.embed_batch(["text 1", "text 2"])

        assert len(results) == 2
        assert results[0] == [0.1, 0.2, 0.3]
        assert results[1] == [0.4, 0.5, 0.6]

        mock_client.models.embed_content.assert_called_once()
        call_kwargs = mock_client.models.embed_content.call_args[1]
        assert call_kwargs["contents"] == ["text 1", "text 2"]

def test_embed_batch_empty():
    embedder = Embedder()
    assert embedder.embed_batch([]) == []

def test_embed_batch_mismatched_length_raises():
    with patch("google.genai.Client") as mock_genai:
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.embeddings = [MagicMock()]  # returns 1 embedding for 2 texts
        mock_client.models.embed_content.return_value = mock_resp
        mock_genai.return_value = mock_client

        embedder = Embedder()
        with pytest.raises(RuntimeError, match="Expected 2 embeddings"):
            embedder.embed_batch(["text 1", "text 2"])

def test_batch_process_splits_and_preserves_order():
    async def run_test():
        bp = BatchProcess(batch_size=3, max_concurrency=2, max_retries=1)
        items = list(range(10))

        async def process_batch(batch):
            return [x * 2 for x in batch]

        results = await bp.run(items, process_batch)
        assert results == [x * 2 for x in items]

    asyncio.run(run_test())

def test_batch_process_retries_on_failure():
    async def run_test():
        bp = BatchProcess(batch_size=2, max_concurrency=1, max_retries=3, window_seconds=1.0)
        attempts = 0

        async def flaky_batch(batch):
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise RuntimeError("Transient rate limit error")
            return [x * 10 for x in batch]

        results = await bp.run([1, 2], flaky_batch)
        assert results == [10, 20]
        assert attempts == 2

    asyncio.run(run_test())

def test_vector_store_bulk_ingest():
    mock_db = MagicMock(spec=Session)
    mock_db.scalar.return_value = None  # documents don't exist yet

    store = VectorStore()
    records = [
        {
            "source": "MITRE_ATTACK",
            "external_id": "MITRE-T1059",
            "title": "Command and Scripting Interpreter",
            "url": "https://attack.mitre.org/techniques/T1059/",
            "category": "attack_technique",
            "metadata": {"platforms": ["Windows"]}
        },
        {
            "source": "MITRE_ATTACK",
            "external_id": "MITRE-T1068",
            "title": "Privilege Escalation",
            "url": "https://attack.mitre.org/techniques/T1068/",
            "category": "attack_technique",
            "metadata": {}
        }
    ]

    chunk_embeddings = {
        "MITRE-T1059": [
            (0, "chunk 0 text", [0.1] * 768),
            (1, "chunk 1 text", [0.2] * 768)
        ],
        "MITRE-T1068": [
            (0, "chunk 0 text", [0.3] * 768)
        ]
    }

    total_chunks = store.bulk_ingest(mock_db, records, chunk_embeddings)

    assert total_chunks == 3
    assert mock_db.commit.called

def test_ingest_scraped_records_async_full_flow():
    async def run_test():
        mock_db = MagicMock(spec=Session)
        mock_rag = MagicMock()
        mock_rag.get_existing_external_ids.return_value = set()
        mock_rag.bulk_ingest.return_value = 2

        mock_embedder = MagicMock()
        mock_embedder.embed_batch.return_value = [[0.1] * 768, [0.2] * 768]

        bp = BatchProcess(batch_size=2, max_concurrency=1, max_retries=1)

        records = [
            {
                "source": "CISA_KEV",
                "external_id": "CISA-KEV-CVE-2024-0001",
                "title": "CVE 1",
                "text": "Short text for CVE 1"
            },
            {
                "source": "CISA_KEV",
                "external_id": "CISA-KEV-CVE-2024-0002",
                "title": "CVE 2",
                "text": "Short text for CVE 2"
            }
        ]

        result = await ingest_scraped_records_async(
            mock_db, records, rag=mock_rag, embedder=mock_embedder, batch_engine=bp
        )

        assert result["total_scraped"] == 2
        assert result["already_existing"] == 0
        assert result["newly_ingested"] == 2
        assert result["chunks_added"] == 2
        assert mock_rag.bulk_ingest.called

    asyncio.run(run_test())

