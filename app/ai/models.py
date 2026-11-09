from pydantic import BaseModel, Field

class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=5000)
    session_id: str = Field(default="default-session", min_length=1, max_length=120)


class IngestionRequest(BaseModel):
    sources: list[str] = Field(default_factory=lambda: ["mitre", "nvd", "cisa"])
    force_refresh: bool = Field(default=False)

class SourceCitation(BaseModel):
    citation: str
    source: str
    id: str
    title: str
    url: str | None = None
