"""
PRISM Backend — FastAPI Application
Main entry point for the backend API.
"""

import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Add project root to path for engine imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ml_engine
from routers import analyze, retrace, profiles, history, intel, ml, blast_radius, auth, sandbox, report


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Startup: load ML model
    ml_engine.startup()
    yield
    # Shutdown: nothing needed


app = FastAPI(
    title="PRISM API",
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
app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(analyze.router, prefix="/api", tags=["Attribution"])
app.include_router(retrace.router, prefix="/api", tags=["Malware Retracing"])
app.include_router(profiles.router, prefix="/api/profiles", tags=["Profiles"])
app.include_router(ml.router, prefix="/api/ml", tags=["ML Management"])
app.include_router(history.router, prefix="/api", tags=["History"])
app.include_router(intel.router, prefix="/api", tags=["Intel Pipeline"])
app.include_router(blast_radius.router, prefix="/api", tags=["Blast Radius"])
app.include_router(sandbox.router, prefix="/api", tags=["Sandbox"])
app.include_router(report.router, prefix="/api", tags=["Report"])


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "ml_model_loaded": ml_engine.is_model_loaded(),
        "ml_model_version": ml_engine.get_model_version(),
    }


# Serve static files (dashboard.html, k.png, etc.)
@app.get("/dashboard.html")
async def serve_dashboard_page():
    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {"message": "Dashboard not found"}


@app.get("/k.png")
async def serve_logo():
    logo_path = Path(__file__).resolve().parent.parent / "k.png"
    if logo_path.exists():
        return FileResponse(logo_path, media_type="image/png")
    return {"message": "Logo not found"}


# Serve the HTML dashboard (login page)
@app.get("/")
async def serve_dashboard():
    login_path = Path(__file__).resolve().parent.parent / "login.html"
    if login_path.exists():
        return FileResponse(login_path)
    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    return {"message": "Dashboard not found. Use /api endpoints."}


# Serve static assets (images, etc.)
try:
    static_path = Path(__file__).resolve().parent.parent
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
except Exception:
    pass  # Static files optional
