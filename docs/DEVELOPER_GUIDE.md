# Developer Guide: How a chatbot request moves through the code

## A. Request path

1. `app/routes/chat.py`
   - Validates the request using `ChatRequest`.
   - Sends the prompt to the shared `chat_service`.
   - Returns a Server-Sent Events response.

2. `app/ai/chat.py` (`ChatService.stream_answer`)
   - Opens a database session.
   - Calls `RAGPipeline.retrieve()` once.
   - Builds source citations and the context prompt.
   - Calls `LLMFallbackManager.generate()`.
   - Saves the user question and final assistant answer to `chat_messages`.
   - Emits `sources`, `chunk`, and `done` SSE events.

3. `app/ai/rag/pipeline.py`
   - Provides a small interface around retrieval and ingestion.
   - Delegates retrieval to `VectorStore`.

4. `app/ai/rag/vector_store.py`
   - Embeds the user query using `Embedder`.
   - Searches pgvector by cosine distance.
   - Searches PostgreSQL full-text index.
   - Combines both ranked lists with reciprocal-rank fusion.
   - Returns the top matching chunks with source metadata.

5. `app/ai/llm/fallback_manager.py`
   - Gets the configured provider list from `LLMs.get_fallback_chain()`.
   - Tries providers in priority order.
   - Buffers a provider's complete response.
   - If a provider fails or returns empty text, tries the next provider.
   - Returns `{answer, provider}` when one provider succeeds.

6. `app/ai/llm/providers.py`
   - Contains only provider client initialization and provider-specific streaming calls.
   - It does not know about database sessions or RAG retrieval.

## B. Why the fallback manager buffers output

Imagine Groq sends 200 words and then its stream disconnects. If those words have already been sent to the browser, Mistral's answer would be appended to an incomplete Groq answer. The result would be confusing and potentially unsafe.

The fallback manager therefore waits for one provider to finish before sending answer text to the browser. The API remains SSE-based, but the answer is delivered after generation completes. A later optimization can use a non-streaming completion call for failover and stream only after a provider has been selected, or use provider health checks/circuit breakers.

## C. Provider order

The chain is defined in one place: `app/ai/llm/providers.py`.

```python
if settings.groq_api_key:
    chain.append(("Groq", self.stream_groq))
if settings.mistral_api_key:
    chain.append(("Mistral", self.stream_mistral))
if settings.nvidia_api_key:
    chain.append(("NVIDIA", self.stream_nvidia))
if settings.gemini_api_key:
    chain.append(("Gemini", self.stream_gemini))
```

Change provider priority here only. Do not duplicate provider ordering in routes or the RAG pipeline.

## D. Data ingestion path

`app/ai/rag/data_loader.py` fetches public cybersecurity source records. `app/ai/rag/ingestion.py` filters existing IDs, chunks new records, batches embedding calls and passes records/vectors to `RAGPipeline.bulk_ingest()`. The vector store persists source records and their chunks in PostgreSQL.

Ingestion is separate from chat. A user asking a question should search the indexed data; it should not trigger a complete scrape on every prompt.

## E. Important design boundaries

- LLM quota failures should change the LLM provider, not re-run RAG retrieval.
- RAG retrieval should happen once per question.
- Embedding model selection is separate from chat LLM selection. This project currently uses Gemini embeddings, so Gemini credentials are still needed for ingestion and query embeddings.
- An IOC or vector similarity match is not proof of compromise.
- Retrieved documents are untrusted data; the system prompt tells the LLM not to follow instructions found inside retrieved content.
- Never send API keys or raw provider exception details to the browser.

## F. How to add a new provider

1. Add its API key and model setting to `app/core/config.py`.
2. Add and initialize its client in `app/ai/llm/providers.py`.
3. Implement an async `stream_<provider>()` method yielding text strings.
4. Add it to `get_fallback_chain()` at the intended priority.
5. Add mocked tests for successful streaming and provider failure.
6. Never put provider API calls in `app/routes/chat.py`.
