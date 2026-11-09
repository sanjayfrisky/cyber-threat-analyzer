import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.orm import Session
from app.ai.rag.ingestion import ingest_scraped_records, scrape_and_ingest_all
from app.ai.rag.vector_store import VectorStore
from app.main import run_startup_ingestion

def test_ingest_scraped_records_deduplication():
    mock_db = MagicMock(spec=Session)
    mock_rag = MagicMock()
    mock_embedder = MagicMock()
    mock_embedder.embed_batch.return_value = [[0.1] * 768]

    # Suppose MITRE-T1059 is already in DB
    mock_rag.get_existing_external_ids.return_value = {"MITRE-T1059"}
    mock_rag.bulk_ingest.return_value = 2  # returns chunks added for new items

    scraped_records = [
        {
            "source": "MITRE_ATTACK",
            "external_id": "MITRE-T1059",
            "title": "Command and Scripting Interpreter",
            "text": "Technique description..."
        },
        {
            "source": "MITRE_ATTACK",
            "external_id": "MITRE-T1068",
            "title": "Exploitation for Privilege Escalation",
            "text": "Privilege escalation description..."
        }
    ]

    result = ingest_scraped_records(mock_db, scraped_records, rag=mock_rag, embedder=mock_embedder)

    assert result["total_scraped"] == 2
    assert result["already_existing"] == 1
    assert result["newly_ingested"] == 1
    assert result["chunks_added"] == 2

    # Verify bulk_ingest was called only for new records
    assert mock_rag.bulk_ingest.call_count == 1
    call_records = mock_rag.bulk_ingest.call_args[0][1]
    assert len(call_records) == 1
    assert call_records[0]["external_id"] == "MITRE-T1068"

def test_ingest_scraped_records_all_existing():
    mock_db = MagicMock(spec=Session)
    mock_rag = MagicMock()
    mock_embedder = MagicMock()

    mock_rag.get_existing_external_ids.return_value = {"CISA-KEV-CVE-2023-34362", "CISA-KEV-CVE-2024-1709"}

    scraped_records = [
        {"source": "CISA_KEV", "external_id": "CISA-KEV-CVE-2023-34362", "title": "CVE 1", "text": "..."},
        {"source": "CISA_KEV", "external_id": "CISA-KEV-CVE-2024-1709", "title": "CVE 2", "text": "..."}
    ]

    result = ingest_scraped_records(mock_db, scraped_records, rag=mock_rag, embedder=mock_embedder)

    assert result["total_scraped"] == 2
    assert result["already_existing"] == 2
    assert result["newly_ingested"] == 0
    assert result["chunks_added"] == 0
    mock_rag.bulk_ingest.assert_not_called()
    mock_embedder.embed_batch.assert_not_called()

def test_vector_store_upsert_document_skip_if_exists():
    mock_db = MagicMock(spec=Session)
    store = VectorStore()

    store.embedder = MagicMock()

    mock_doc = MagicMock(id=101)
    mock_db.scalar.side_effect = [
        mock_doc, # select(SourceDocument)
        3         # select(func.count(DocumentChunk))
    ]

    item = {
        "source": "MITRE_ATTACK",
        "external_id": "MITRE-T1059",
        "title": "Title",
        "text": "Some text"
    }

    chunks_added = store.upsert_document(mock_db, item, skip_if_exists=True)
    assert chunks_added == 0
    store.embedder.embed.assert_not_called()

def test_scrape_and_ingest_all():
    mock_db = MagicMock(spec=Session)

    mock_cisa_record = [{"source": "CISA_KEV", "external_id": "CISA-KEV-CVE-2023-0001", "text": "...", "title": "CVE"}]

    with patch("app.ai.rag.ingestion.LOADERS", {"cisa": lambda: mock_cisa_record}), \
         patch("app.ai.rag.ingestion.RAGPipeline") as mock_rag_cls, \
         patch("app.ai.rag.ingestion.Embedder") as mock_embed_cls:

        mock_rag = MagicMock()
        mock_rag.get_existing_external_ids.return_value = set()
        mock_rag.bulk_ingest.return_value = 1
        mock_rag_cls.return_value = mock_rag

        mock_embed = MagicMock()
        mock_embed.embed_batch.return_value = [[0.1] * 768]
        mock_embed_cls.return_value = mock_embed

        summary = asyncio.run(scrape_and_ingest_all(mock_db, sources=["cisa"]))

        assert "cisa" in summary
        assert summary["cisa"]["total_scraped"] == 1
        assert summary["cisa"]["newly_ingested"] == 1
        assert summary["cisa"]["chunks_added"] == 1

def test_run_startup_ingestion():
    with patch("app.main.SessionLocal") as mock_session_local, \
         patch("app.main.scrape_and_ingest_all", new_callable=AsyncMock) as mock_scrape:

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        mock_scrape.return_value = {"mitre": {"total_scraped": 10, "already_existing": 10, "newly_ingested": 0, "chunks_added": 0}}

        asyncio.run(run_startup_ingestion())

        mock_scrape.assert_called_once_with(mock_db)
        mock_db.close.assert_called_once()
