import sys
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    gemini_api_key: str
    gemini_chat_model: str = "gemini-2.5-flash"
    gemini_embedding_model: str = "gemini-embedding-001"
    embedding_dimension: int = 768
    top_k: int = 6
    max_upload_mb: int = 15
    nvd_api_key: str | None = None
    # Comma-separated list of allowed CORS origins.
    # In production set this to your exact frontend URL only, e.g.:
    #   CORS_ORIGINS=https://your-frontend.pages.dev
    # In local dev the default covers common Next.js / Vite ports.
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    enable_startup_ingestion: bool = True
    embedding_batch_size: int = 20
    embedding_max_concurrency: int = 2
    embedding_requests_per_minute: int = 80
    embedding_tokens_per_minute: int = 25_000
    embedding_max_retries: int = 5

    # Multi-LLM provider settings
    groq_api_key: str | None = None
    mistral_api_key: str | None = None
    nvidia_api_key: str | None = None
    groq_model: str = "openai/gpt-oss-20b"
    mistral_model: str = "mistral-small-latest"
    nvidia_model: str = "meta/llama-3.1-8b-instruct"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def GEMINI_API_KEY(self) -> str:
        return self.gemini_api_key

    @property
    def GROQ_API_KEY(self) -> str | None:
        return self.groq_api_key

    @property
    def MISTRAL_API_KEY(self) -> str | None:
        return self.mistral_api_key

    @property
    def NVIDIA_API_KEY(self) -> str | None:
        return self.nvidia_api_key

    @property
    def cors_origin_list(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

@lru_cache
def get_settings():
    s = Settings()
    if "pytest" in sys.modules:
        s.enable_startup_ingestion = False
    return s

settings = get_settings()
