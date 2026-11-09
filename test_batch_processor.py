from app.ai.rag.vector_store import chunk_text

def test_chunking_empty_text():
    assert chunk_text("") == []

def test_chunking_splits_text():
    chunks=chunk_text("security event " * 500,chunk_size=250,overlap=30)
    assert len(chunks)>1
    assert all(chunks)
