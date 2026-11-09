from pathlib import Path
from fastapi import HTTPException, UploadFile
from app.core.config import settings

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".log", ".json"}

def validate_upload_name(filename: str) -> str:
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Allowed file types: PDF, TXT, LOG, JSON.")

    return suffix

async def read_limited_upload(file: UploadFile) -> bytes:
    validate_upload_name(file.filename or "")
    limit = settings.max_upload_mb * 1024 * 1024

    content = await file.read(limit + 1)

    if len(content) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB.")

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    return content

