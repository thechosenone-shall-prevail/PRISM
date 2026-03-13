"""
PRISM API — ML Management Endpoints
POST /api/ml/retrain — Pulls new feedback samples from Supabase, appends to training dataset, and triggers the XGBoost retraining pipeline.
"""

import sys
import json
import csv
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

import db
import ml_engine

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ML_DIR = PROJECT_ROOT / "ml"
DATA_DIR = ML_DIR / "data"
MODELS_DIR = ML_DIR / "models"
TRAINING_CSV_PATH = DATA_DIR / "training_data.csv"
FEATURE_SCHEMA_PATH = DATA_DIR / "feature_schema.json"


class RetrainResponse(BaseModel):
    status: str
    message: str


def run_retraining_pipeline():
    """Background task to run the ML retraining pipeline."""
    try:
        # Step 1: Run synthetic data generator to build the base dataset (if missing or to refresh)
        print("[ML PIPELINE] Generating base synthetic dataset...")
        res = subprocess.run(
            [sys.executable, str(ML_DIR / "generate_training_data.py")],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Step 2: Fetch validated training samples from Supabase
        print("[ML PIPELINE] Fetching analyst feedback samples from Supabase...")
        client = db.get_client()
        response = client.table("training_samples").select("label, features").eq("validated", True).execute()
        db_samples = response.data or []
        
        if db_samples:
            print(f"[ML PIPELINE] Found {len(db_samples)} database samples. Appending to CSV...")
            # Load feature schema to know the exact columns required
            with open(FEATURE_SCHEMA_PATH, encoding="utf-8") as f:
                schema = json.load(f)
            feature_names = schema["features"]
            
            # Format DB samples for CSV
            csv_samples = []
            for sample in db_samples:
                label = sample["label"]
                features = sample.get("features", {})
                
                # Techniques from DB payload
                techs = set(features.get("techniques", []))
                ctxs = set(features.get("context_signals", []))
                
                csv_row = {}
                for fn in feature_names:
                    if fn.startswith("ttp_"):
                        t_id = fn[4:]
                        csv_row[fn] = 1 if t_id in techs else 0
                    elif fn.startswith("ctx_"):
                        c_id = fn[4:].replace("_", " ")
                        csv_row[fn] = 1 if c_id in ctxs else 0
                    elif fn == "technique_count":
                        csv_row[fn] = len(techs)
                    elif fn == "context_count":
                        csv_row[fn] = len(ctxs)
                    elif fn == "tactic_coverage":
                        # Simplistic fallback mapping, real feature engine uses tactic dicts
                        csv_row[fn] = max(1, min(14, len(techs) // 2)) 
                    else:
                        csv_row[fn] = 0
                        
                csv_row["label"] = label
                csv_samples.append(csv_row)
            
            # Append to training_data.csv
            with open(TRAINING_CSV_PATH, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=feature_names + ["label"])
                for row in csv_samples:
                    writer.writerow(row)
                    
            print(f"[ML PIPELINE] Appended {len(csv_samples)} feedback rows to training data.")
        else:
            print("[ML PIPELINE] No DB feedback samples found. Proceeding with synthetic baseline only.")

        # Step 3: Run the training script
        print("[ML PIPELINE] Running XGBoost training script...")
        train_res = subprocess.run(
            [sys.executable, str(ML_DIR / "train_model.py")],
            capture_output=True,
            text=True,
            check=True
        )
        print("[ML PIPELINE] Training completed successfully.")

        # Step 4: Reload the model in memory
        print("[ML PIPELINE] Hot-reloading model in FastAPI...")
        ml_engine.load_model()
        print("[ML PIPELINE] Pipeline finished. Model is live.")

    except subprocess.CalledProcessError as e:
        print(f"[ML PIPELINE ERROR] Subprocess failed: {e.cmd}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
    except Exception as e:
        print(f"[ML PIPELINE ERROR] Unknown error: {e}")


@router.post("/retrain", response_model=RetrainResponse)
async def trigger_retraining(background_tasks: BackgroundTasks):
    """
    Trigger the ML retraining pipeline asynchronously.
    It fetches new `training_samples` from the DB, merges them into the training
    dataset, trains a new model, and hot-reloads it in memory.
    """
    background_tasks.add_task(run_retraining_pipeline)
    return RetrainResponse(
        status="ok",
        message="Retraining pipeline triggered in the background. Check server logs."
    )


@router.get("/drift")
async def get_drift_metrics():
    """Fetch weekly ML drift monitoring statistics."""
    return db.get_drift_monitor()


@router.get("/stats")
async def get_training_dataset_stats():
    """Fetch breakdown of training dataset sources and counts."""
    return db.get_training_stats()
