import re
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from app.ai.models import ChatRequest
from app.ai.chat import ChatService

router = APIRouter()

# Reuse provider and embedding clients instead of recreating them per request.
chat_service = ChatService()

def extract_iocs(text: str) -> dict:
    """Helper utility for extracting indicators of compromise from text."""
    urls = sorted(set(x.rstrip(".,;") for x in re.findall(r"https?://[^\s\]\[()<>\"']+", text, re.I)))
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    ips = sorted(ip for ip in ips if all(0 <= int(p) <= 255 for p in ip.split(".")))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)))
    return {
        "ipv4": ips,
        "urls": urls,
        "domains": domains,
        "md5": sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text))),
        "sha1": sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text))),
        "sha256": sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
    }

@router.post("/chat")
def chat(payload: ChatRequest):
    """
    Streaming chat endpoint.
    Accepts a user prompt and streams the threat intelligence response in real-time
    using Server-Sent Events (SSE).
    """
    user_prompt = payload.prompt
    return StreamingResponse(
        chat_service.stream_answer(user_prompt, payload.session_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
