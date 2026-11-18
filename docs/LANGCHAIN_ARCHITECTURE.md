# Advanced LangChain Architecture & Cybersecurity Agent

## Overview

The Cyber Threat Intelligence RAG and CVE Explainer application uses a production-grade LangChain integration that provides:
1. Unified multi-provider LLM management (`ChatGroq`, `ChatMistralAI`, `ChatOpenAI` for NVIDIA NIM, and `ChatGoogleGenerativeAI`).
2. Automatic provider failover using LangChain's native `with_fallbacks()` runnable mechanism.
3. Exponential backoff with jitter using LangChain's `with_retry()`.
4. 10 cybersecurity tools registered as `@tool` callables with Pydantic v2 schemas.
5. Conditional tool selection to bind only relevant tools based on query intent.
6. Structured cybersecurity outputs separating confirmed sources, retrieved evidence, AI explanations, and recommended remediations.
7. Agent REST API endpoints for agent analysis, tool discovery, and provider health.

---

## 1. Model Management & Providers

### Provider Hierarchy & Configuration
Providers are configured via environment variables and loaded centrally in `app/ai/llm/provider_config.py`.

The failover priority order is:
```
Primary:    Groq (openai/gpt-oss-20b or llama-3.3-70b-versatile)
Fallback 1: Mistral (mistral-small-latest)
Fallback 2: NVIDIA NIM (meta/llama-3.1-8b-instruct via ChatOpenAI)
Fallback 3: Google Gemini (gemini-2.0-flash via ChatGoogleGenerativeAI)
```

Each provider is encapsulated in a validated Pydantic model:
- `app/ai/llm/provider_config.py`: `ProviderConfig` holds model names, temperatures, token limits, and credential validation.
- `app/ai/llm/model_factory.py`: `build_models_from_config()` and `build_model_with_retry_and_fallback()` dynamically instantiate official LangChain chat models.

---

## 2. Fallback & Retry Mechanisms

### Transient Retries (`with_retry`)
- Implemented in `app/ai/llm/retry_manager.py` and wrapped on each model before building fallbacks.
- **Retryable Exceptions**: `httpx.HTTPStatusError` (429 rate limit, 503 unavailable), `httpx.TimeoutException`, `httpx.ConnectError`, `asyncio.TimeoutError`, `ConnectionResetError`.
- **Permanent Errors** (401 Unauthorized, 403 Forbidden, invalid request format) are never retried to prevent quota exhaustion and latency spikes.
- **Backoff Strategy**: Exponential backoff with randomized jitter, maximum of 2 additional attempts per provider (3 total).

### Provider Failover (`with_fallbacks`)
- Constructed in `app/ai/llm/model_factory.py` and `app/ai/llm/fallback_manager.py`:
```python
chain = primary_model.with_fallbacks(
    fallbacks=fallback_models,
    exceptions_to_handle=(Exception,),
)
```
- If Groq encounters rate-limiting or an outage after its retry budget, execution seamlessly transitions to Mistral, then NVIDIA, then Gemini.

---

## 3. The 10 Cybersecurity Tools

All tools are located in `app/ai/tools/` and exposed via `@tool`:

| # | Tool Name | Module | Input | Purpose |
|---|---|---|---|---|
| 1 | `cve_lookup` | `cve_tool.py` | `cve_id: str` | Retrieves description, CVSS base score, severity, and affected products from PostgreSQL and NVD API fallback. |
| 2 | `kev_lookup` | `kev_tool.py` | `cve_id: str` | Checks CISA Known Exploited Vulnerabilities catalog for active exploitation and required remediation deadlines. |
| 3 | `mitre_lookup` | `mitre_tool.py` | `technique_id: str` | Queries MITRE ATT&CK techniques by ID (e.g. `T1059.001`) or search keywords. |
| 4 | `rag_retrieve` | `rag_tool.py` | `query: str, top_k: int` | Searches local vector database using hybrid pgvector cosine similarity + tsvector full-text search with RRF. |
| 5 | `cvss_analysis` | `cvss_tool.py` | `cvss_vector_or_cve: str` | Decodes CVSS v3.x vector metrics (Attack Vector, Complexity, Privileges, Scope, Impacts). |
| 6 | `extract_iocs_tool` | `ioc_tool.py` | `text: str` | Deterministic regex extraction of IPv4, URLs, domains, and MD5/SHA1/SHA256 hashes. |
| 7 | `analyze_command` | `command_analysis_tool.py` | `command: str` | Identifies suspicious PowerShell, Bash, and shell commands; maps them to MITRE techniques without execution. |
| 8 | `screen_file` | `file_screening_tool.py` | `file_content_or_text: str` | Screens extracted file text for prompt injection, malicious commands, and IOCs via `ScreeningService`. |
| 9 | `get_remediation` | `remediation_tool.py` | `cve_id: str, affected_product: str` | Gathers official vendor advisories and patch links, returning actionable guidance with disclaimers. |
| 10 | `enrich_threat_intel` | `threat_intelligence_tool.py` | `indicator: str` | Multi-source enrichment across NVD, CISA KEV, MITRE ATT&CK, and hybrid RAG. |

---

## 4. Conditional Tool Selection & Agent Architecture

The agent does not bind all 10 tools on every request. Instead, `ToolRegistry` (`app/ai/agent/tool_registry.py`) classifies the incoming query into one of several intent classes:

- **CVE Exploitation** (`"Is CVE-2023-44487 actively exploited?"`):
  -> Binds `cve_lookup`, `kev_lookup`
- **CVE Remediation** (`"How can I fix CVE-2024-1234?"`):
  -> Binds `cve_lookup`, `cvss_analysis`, `get_remediation`, `rag_retrieve`
- **Command Analysis** (`"Explain this suspicious powershell command"`):
  -> Binds `analyze_command`, `mitre_lookup`, `rag_retrieve`
- **IOC Analysis** (`"Check IP 198.51.100.25"`):
  -> Binds `extract_iocs_tool`, `enrich_threat_intel`, `rag_retrieve`
- **Screening** (`"Screen uploaded attachment"`):
  -> Binds `screen_file`, `extract_iocs_tool`, `rag_retrieve`
- **General Inquiry**:
  -> Binds `rag_retrieve`, `cve_lookup`, `mitre_lookup`

### Safety Boundaries
- `agent_max_iterations`: Default 10 cycles.
- `agent_max_tool_calls`: Default 15 executions per request.
- No shell execution, no script evaluation, and strictly read-only database queries.

---

## 5. Structured Schemas

Defined under `app/ai/schemas/`:
- `CVEAnalysis` & `CVSSAnalysis`
- `IOCExtractionResult` & `SecurityScreeningResult`
- `RemediationResult`
- `ToolExecutionResult` & `ThreatIntelligenceResult`

Each schema separates:
1. **Confirmed source information** (`confirmed_source`)
2. **Retrieved evidence** (`retrieved_evidence`)
3. **AI-generated explanation** (`ai_explanation` / `remediation_steps`)
4. **Missing or unverified information** (`missing_info`)

---

## 6. API Endpoints

- `POST /api/agent/analyze`
  Accepts: `{"query": "Is CVE-2023-44487 exploited?", "session_id": "abc"}`
  Returns structured analysis, tools executed, timing, and cited sources.
- `POST /api/agent/tools`
  Returns all registered tools, descriptions, and JSON Schema parameters.
- `GET /api/agent/health`
  Returns availability status for all configured providers and registered tool count.

Existing endpoints (`/api/chat` for SSE streaming and `/api/screening/*` for file screening) remain fully intact and operational.
