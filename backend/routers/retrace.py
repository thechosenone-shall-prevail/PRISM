"""
APTrace API — Malware Retracing Endpoint
POST /api/retrace — malware file/hash attribution
"""

import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from engine import run_malware_retracing  # type: ignore
import engine

import db
import ml_engine
import intel_pipeline

router = APIRouter()


@router.post("/retrace")
async def retrace(
    hash_value: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    """
    Run malware retracing analysis.
    Accepts a malware file upload and/or hash value.
    Scores against known malware families in Supabase.
    """
    file_bytes = None
    filename = ""

    if file:
        file_bytes = await file.read()
        filename = file.filename or "sample.bin"
        if len(file_bytes) == 0:
            raise HTTPException(status_code=422, detail="Uploaded file is empty")

    if not file_bytes and not hash_value.strip():
        raise HTTPException(
            status_code=422,
            detail="Provide a malware file or a hash value"
        )

    # Fetch malware families from Supabase
    try:
        family_db = db.get_families_as_engine_format()
    except Exception:
        # Fallback to local file
        from engine import load_malware_family_db  # type: ignore
        family_db = load_malware_family_db()

    # Run static extraction (via legacy engine but ignoring rule-scores)
    try:
        extraction = run_malware_retracing(
            file_bytes=file_bytes,
            filename=filename,
            hash_value=hash_value,
            family_db=family_db,
            top_k=5,
        )
        
        # Extract NLP features from the raw file strings for the ML model
        # The legacy run_malware_retracing only extracts static indicators (hashes, IPs, raw strings)
        file_strings = "\n".join(extraction.get("extracted_static", {}).get("strings", []))
        if hash_value and not file_strings:
            file_strings = hash_value  # Fallback if just hash testing
            
        nlp_features = engine.extract_ttps_from_text(file_strings)
        
        # ML ATTRIBUTION Overhaul
        # Prepare feature dict for ML
        observed = {
            "techniques": nlp_features.get("techniques", []),
            "context_signals": nlp_features.get("context_signals", []), 
            "extracted_static": extraction.get("extracted_static"),
            "technique_count": nlp_features.get("technique_count", 0),
        }
        
        ml_res = ml_engine.predict(observed)
        
        # Explain top match
        shap_exp = []
        if ml_res.get("top_group"):
            # Map group name to index if needed, or find in class_names
            try:
                class_names = ml_engine._feature_schema.get("class_names", [])
                idx = class_names.index(ml_res["top_group"])
                exp = ml_engine.explain_prediction(observed, idx)
                shap_exp = exp.get("top_contributors", [])
            except Exception:
                pass

        # Unify results
        result = extraction
        result["verdict"] = ml_res["top_confidence"] > 0.7 and "HIGH" or ml_res["top_confidence"] > 0.4 and "MODERATE" or "LOW"
        result["top_match"] = {
            "family": ml_res["top_group"], # In ML mode, group is the family
            "cluster": ml_res["top_group"], # Default to group
            "confidence_pct": ml_res["confidence_pct"],
            "matched_indicators": [f"{c['feature']}: {c['contribution']}" for c in shap_exp[:5]],
            "shap_explanation": shap_exp
        }
        # Update ranked matches
        result["ranked_matches"] = [
            {"family": p["group"], "cluster": p["group"], "confidence_pct": p["probability"]*100}
            for p in ml_res["predictions"][:5]
        ]
        result["ml_metadata"] = {
            "version": ml_res["model_version"],
            "features": ml_res["feature_vector_size"]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Upload to Supabase Storage if file was provided
    storage_path = None
    if file_bytes:
        sha256 = result["extracted_static"]["hashes"]["sha256"]
        storage_path = f"{sha256}/{filename}"
        try:
            db.upload_sample(file_bytes, storage_path)
            result["storage_path"] = storage_path
        except Exception as e:
            print(f"Warning: Failed to upload sample to storage: {e}")

    # Persist
    top_match = result.get("top_match")
    analysis_record = {
        "analysis_type": "malware_retracing",
        "input_mode": "file" if file_bytes else "hash",
        "input_summary": f"{filename or hash_value[:32]}",
        "top_group": top_match.get("family") if top_match else None,
        "top_confidence": (top_match.get("confidence_pct", 0) / 100.0) if top_match else 0,
        "confidence_tier": result.get("verdict", "LOW"),
        "gate_passed": result.get("verdict") in ("HIGH", "MODERATE"),
        "artifact_path": storage_path,
        "full_result": result,
        "model_version": ml_res.get("model_version")
    }

    try:
        stored = db.insert_analysis(analysis_record)
        result["analysis_id"] = stored.get("id", "unknown")
    except Exception:
        result["analysis_id"] = "not_persisted"

    return result
