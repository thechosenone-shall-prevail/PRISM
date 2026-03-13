"""
APTrace Backend — FastAPI Application
Main entry point for the backend API.
"""

import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add project root to path for engine imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ml_engine
from routers import analyze, retrace, profiles, history, intel, ml


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Startup: load ML model
    ml_engine.startup()
    yield
    # Shutdown: nothing needed


app = FastAPI(
    title="APTrace API",
    description="APT Attribution Engine — ML-powered threat actor identification",
    version="3.0.0",
    lifespan=lifespan,
)

# CORS — allow Streamlit frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(analyze.router, prefix="/api", tags=["Attribution"])
app.include_router(retrace.router, prefix="/api", tags=["Malware Retracing"])
app.include_router(profiles.router, prefix="/api/profiles", tags=["Profiles"])
app.include_router(ml.router, prefix="/api/ml", tags=["ML Management"])
app.include_router(history.router, prefix="/api", tags=["History"])
app.include_router(intel.router, prefix="/api", tags=["Intel Pipeline"])


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "ml_model_loaded": ml_engine.is_model_loaded(),
        "ml_model_version": ml_engine.get_model_version(),
    }
