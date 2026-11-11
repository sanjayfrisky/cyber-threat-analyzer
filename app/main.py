import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.database import init_db, SessionLocal
from app.routes.chat import router
from app.routes.screening import router as screening_router
from app.ai.rag.ingestion import scrape_and_ingest_all

logger = logging.getLogger(__name__)


async def run_startup_ingestion():
    """
    Executes web scraping and ingests threat intelligence into the vector DB
    using batch processing for embeddings.
    Strictly checks vector DB first and skips any already-ingested data.
    """
    try:
        db = SessionLocal()
        try:
            logger.info("Initiating startup web scrap ingestion into vector DB...")
            summary = await scrape_and_ingest_all(db)
            logger.info("Startup web scrap ingestion completed: %s", summary)
        finally:
            db.close()
    except Exception as exc:
        logger.warning("Startup web scrap ingestion skipped or failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Log the exact CORS origins that will be enforced — visible in server logs.
    allowed = settings.cors_origin_list
    if not allowed:
        logger.warning(
            "CORS_ORIGINS is empty. No browser origin will be allowed. "
            "Set CORS_ORIGINS in your .env to your frontend URL."
        )
    else:
        logger.info("CORS allowed origins: %s", allowed)

    if settings.enable_startup_ingestion:
        try:
            init_db()
        except Exception as exc:
            logger.warning("Database initialization skipped or failed: %s", exc)

        # Uncomment to enable background ingestion on startup:
        # asyncio.create_task(run_startup_ingestion())
    yield


app = FastAPI(
    title="Cyber Threat Intelligence RAG",
    version="1.0.0",
    description="Knowledge chatbot and evidence-based incident analysis backend.",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — strictly limited to the origins listed in CORS_ORIGINS (.env).
#
# Local dev default  : http://localhost:3000,http://localhost:5173
# Production example : CORS_ORIGINS=https://your-frontend.pages.dev
#
# Any origin NOT in this list will receive a CORS error from the browser.
# Server-to-server requests (curl, Postman, etc.) bypass CORS at the HTTP
# level — use API-key auth (app/core/security.py) to restrict those too.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,   # explicit whitelist, no wildcards
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],   # only methods the frontend needs
    allow_headers=["Content-Type", "Authorization", "X-Session-Id"],
)


app.include_router(router, prefix="/api")
app.include_router(screening_router, prefix="/api")
