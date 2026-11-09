# Cyber Threat Intelligence RAG Backend

A modular FastAPI backend for a cybersecurity knowledge chatbot, CVE/threat-intelligence ingestion, hybrid retrieval, and evidence screening.

## Architecture

```text
Client / Swagger
      |
      v
FastAPI routes (app/routes)
      |
      +---- /api/chat --------> ChatService
      |                            |
      |                            +--> RAGPipeline.retrieve()
      |                            |       |
      |                            |       +--> PostgreSQL + pgvector
      |                            |       +--> PostgreSQL full-text search
      |                            |
      |                            +--> LLMFallbackManager
      |                                    1. Groq
      |                                    2. Mistral
      |                                    3. NVIDIA NIM
      |                                    4. Gemini
      |
      +---- /api/screening ---> ScreeningService
      |
      +---- ingestion -------> official source loaders
                                   |
                                   v
                            chunk + embed + store
```

### Separation of responsibilities

- `app/routes/`: HTTP request/response handling only.
- `app/ai/chat.py`: chat orchestration, conversation persistence and SSE formatting.
- `app/ai/llm/`: provider-specific API adapters and ordered fallback manager.
- `app/ai/rag/`: chunking, embeddings, ingestion, hybrid retrieval and vector storage.
- `app/ai/screening.py`: evidence screening and IOC/heuristic analysis.
- `app/db/`: SQLAlchemy models, engine and session lifecycle.
- `app/core/`: environment-backed configuration and security settings.

## LLM fallback behavior

Chat generation uses this fixed priority:

1. Groq
2. Mistral
3. NVIDIA NIM
4. Google Gemini

Providers without configured API keys are skipped. If a provider errors, times out, returns an empty answer, or its stream fails, the manager tries the next configured provider.

**Important streaming design:** the manager buffers one provider's complete response before returning it. This prevents a partial Groq answer from being mixed with a Mistral/NVIDIA/Gemini answer if the first provider fails mid-stream. The endpoint still uses Server-Sent Events (SSE), but answer chunks are sent after a provider has completed. This favors answer integrity over time-to-first-token.

Gemini is currently also used by `app/ai/rag/embed.py` for embeddings. Therefore, even if Gemini is only the last chat-generation fallback, its API key remains required by the current embedding architecture.

## Windows setup (Python 3.13)

1. Install PostgreSQL and enable pgvector:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```
2. Create and activate a virtual environment:
   ```bat
   py -3.13 -m venv .venv
   .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env`, then configure the database URL and API keys.
5. Start the API:
   ```bat
   python server.py
   ```
6. Open Swagger:
   `http://127.0.0.1:8000/docs`

Do not commit `.env`. The archive intentionally excludes the uploaded `.env` file and local caches/virtual environments.

## Environment configuration

See `.env.example`.

- `DATABASE_URL`: PostgreSQL connection string.
- `GEMINI_API_KEY`: currently required for Gemini embeddings; also enables Gemini as final chat fallback.
- `GROQ_API_KEY`, `MISTRAL_API_KEY`, `NVIDIA_API_KEY`: optional chat providers.
- Model IDs are configurable because provider model availability can change.

Use model IDs currently enabled for your account. A valid API key does not guarantee that a particular model ID is available or that your account has quota.

## API endpoints

- `POST /api/chat`: accepts `{"prompt":"Explain CVE-2024-3400","session_id":"demo"}` (legacy `question` field is also accepted). Response is SSE.
- `POST /api/screening`: accepts multipart form data containing `content` or an evidence `file`, plus optional `context`.

## Data ingestion

The ingestion module loads public records from MITRE ATT&CK, CISA KEV and NVD (where configured). Records are chunked, embedded and stored in PostgreSQL/pgvector. Retrieval uses reciprocal-rank fusion of vector similarity and PostgreSQL full-text results.

Run ingestion through the project's ingestion route if enabled/registered in your current build. Startup ingestion is disabled by default in `.env.example` to avoid unexpectedly calling external APIs every time the development server restarts.

## Tests

```bat
pytest -q
```

Provider tests should use mocks; they must not consume live API quota.

## Production hardening still required

Before public SaaS deployment, add authentication, tenant-level data isolation, API rate limiting, background ingestion workers, upload scanning, request/response size limits, observability, secret management, database migrations, retention controls, and provider cooldown/circuit-breaker state shared across workers.
