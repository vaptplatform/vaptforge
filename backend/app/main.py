"""
VAPTForge Enterprise - Main Application Entry Point
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.db.session import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vapt.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VAPTForge starting up...")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("VAPTForge shutting down...")


app = FastAPI(
    title="VAPTForge Enterprise API",
    description="Authorized Web Application Vulnerability Assessment Platform",
    version="3.4.1",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {
        "status": "operational",
        "version": "3.4.1",
        "platform": "VAPTForge Enterprise",
    }
