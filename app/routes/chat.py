import re
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from app.ai.models import ChatRequest
from app.ai.chat import ChatService
from app.db.database import get_db, ChatMessage

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
    using Server-Sent Events (SSE). Automatically persists conversation to Supabase PostgreSQL.
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

@router.get("/chat/sessions")
def get_chat_sessions(db: Session = Depends(get_db)):
    """
    Retrieves all conversation sessions stored in Supabase PostgreSQL (free cloud DB).
    """
    sessions = (
        db.query(
            ChatMessage.session_id,
            func.min(ChatMessage.created_at).label("created_at"),
            func.max(ChatMessage.created_at).label("updated_at"),
            func.count(ChatMessage.id).label("message_count"),
        )
        .group_by(ChatMessage.session_id)
        .order_by(desc("updated_at"))
        .all()
    )

    result = []
    for s in sessions:
        first_msg = (
            db.query(ChatMessage)
            .filter(ChatMessage.session_id == s.session_id, ChatMessage.role == "user")
            .order_by(ChatMessage.created_at.asc())
            .first()
        )
        title = first_msg.content[:50] + ("..." if len(first_msg.content) > 50 else "") if first_msg else "Investigation Session"
        result.append({
            "id": s.session_id,
            "title": title,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
            "message_count": s.message_count,
        })
    return {"sessions": result}

@router.get("/chat/sessions/{session_id}")
def get_chat_session_messages(session_id: str, db: Session = Depends(get_db)):
    """
    Retrieves all messages for a given session from Supabase PostgreSQL.
    """
    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    return {
        "session_id": session_id,
        "messages": [
            {
                "id": str(m.id),
                "role": m.role,
                "content": m.content,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
            for m in messages
        ],
    }

@router.delete("/chat/sessions/{session_id}")
def delete_chat_session(session_id: str, db: Session = Depends(get_db)):
    """
    Deletes all messages for a session from Supabase PostgreSQL.
    """
    deleted = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete()
    db.commit()
    return {"success": True, "deleted_count": deleted}

