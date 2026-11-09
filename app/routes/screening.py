import json
import sys
from pathlib import Path

# Ensure project root is in sys.path when running file directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import pymupdf as fitz
except ImportError:
    import fitz

from fastapi import APIRouter, Depends, File, Form, UploadFile, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.core.config import settings
from app.core.security import ALLOWED_EXTENSIONS
from app.ai.screening import ScreeningService

router = APIRouter(prefix="/screening", tags=["screening"])

def extract_screening_file_text(filename: str, content: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        with fitz.open(stream=content, filetype="pdf") as pdf:
            return "\n".join(page.get_text() for page in pdf)
    decoded = content.decode("utf-8", errors="replace")
    if ext == ".json":
        try:
            return json.dumps(json.loads(decoded), indent=2)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON file.") from exc
    return decoded

@router.post("", summary="Unified Cyber Threat & Incident Screening")
def screen(
    content: str | None = Form(None, description="Raw security log, terminal command, or IOC list."),
    file: UploadFile | None = File(None, description="Optional evidence file (PDF, TXT, LOG, JSON)."),
    context: str = Form("", description="Optional operational context."),
    db: Session = Depends(get_db)
):
    """
    Unified screening endpoint.
    Accepts raw text/IOCs in 'content' OR an uploaded evidence 'file'.
    Evaluates threat severity, risk score (0-100), prompt injection, and MITRE techniques.
    """
    text_to_screen = ""
    filename = None

    if file and file.filename:
        filename = file.filename
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=415, detail=f"Allowed file types: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

        limit = settings.max_upload_mb * 1024 * 1024
        file_bytes = file.file.read(limit + 1)
        if len(file_bytes) > limit:
            raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB.")
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        try:
            text_to_screen = extract_screening_file_text(filename, file_bytes)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not context:
            context = f"Uploaded file: {filename}"
    elif content and content.strip():
        text_to_screen = content.strip()
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either text in 'content' or upload an evidence 'file'."
        )

    try:
        service = ScreeningService()
        result = service.screen_text(db=db, content=text_to_screen, context=context)
        if filename:
            result["filename"] = filename
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Screening failed: {exc}") from exc

if __name__ == "__main__":
    print("Screening module loaded successfully.")
    print("To start the full API server, run: python server.py")
