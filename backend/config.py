"""
APTrace Backend — Configuration
Loads environment variables for Supabase and ML model paths.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend directory
_BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(_BACKEND_DIR / ".env")

# Supabase
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_KEY: str = os.getenv("SUPABASE_SERVICE_KEY", "")

# ML Model
ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", str(_BACKEND_DIR.parent / "ml" / "models" / "aptrace_model.pkl"))
FEATURE_SCHEMA_PATH: str = os.getenv("FEATURE_SCHEMA_PATH", str(_BACKEND_DIR.parent / "ml" / "models" / "feature_schema.json"))

# Engine
RULE_ENGINE_ENABLED: bool = os.getenv("RULE_ENGINE_ENABLED", "false").lower() == "true"

# Project root (for importing engine modules)
PROJECT_ROOT: Path = _BACKEND_DIR.parent
