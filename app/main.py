import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
    if settings.enable_startup_ingestion:
        try:
            init_db()
        except Exception as exc:
            logger.warning("Database initialization skipped or failed: %s", exc)

        # Run web scrap ingestion on startup in background task so network scrapers
        # don't delay the initial server port binding
        # asyncio.create_task(run_startup_ingestion())
    yield

app = FastAPI(
    title="Cyber Threat Intelligence RAG",
    version="1.0.0",
    description="Knowledge chatbot and evidence-based incident analysis backend.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(router, prefix="/api")
app.include_router(screening_router, prefix="/api")
