"""
APTrace API — Attribution Endpoint
POST /api/analyze — runs ML-powered APT attribution
POST /api/analyze/feedback — analyst feedback for continuous learning
"""

import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# Engine imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from engine import extract_ttps_from_text, extract_ttps_from_log  # type: ignore

import db
import ml_engine

router = APIRouter()


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=10, description="Analyst observations or log content")
    input_mode: str = Field("analyst_text", description="Input mode: analyst_text or log_file")


class FeedbackRequest(BaseModel):
    analysis_id: str
    feedback: str = Field(..., description="confirmed, corrected, or rejected")
    corrected_group: Optional[str] = Field(None, description="Correct APT group if feedback is 'corrected'")
    notes: Optional[str] = None


class AnalyzeResponse(BaseModel):
    analysis_id: str
    model_version: str
    top_group: Optional[str]
    top_confidence: float
    confidence_pct: float
    predictions: list[dict]
    observed_techniques: list[str]
    context_signals: list[str]
    matched_keywords: list[str]
    technique_count: int
    iocs: dict
    gate_passed: bool = False
    confidence_tier: str = "INSUFFICIENT DATA"
    shap_explanation: list[dict] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    """
    Run APT attribution analysis using the ML model.
    
    1. Extract TTPs from analyst text
    2. Run ML model inference (primary)
    3. Persist result to Supabase
    4. Return ranked attribution
    """
    # Step 1: Extract features
    if req.input_mode == "log_file":
        features = extract_ttps_from_log(req.text)
    else:
        features = extract_ttps_from_text(req.text)

    if features.get("technique_count", 0) == 0:
        raise HTTPException(
            status_code=422,
            detail="No techniques or behavioral indicators extracted from input. Provide more detailed observations."
        )

    # Step 2: ML model inference
    ml_result = ml_engine.predict(features)

    # Determine confidence tier
    top_conf = ml_result.get("confidence_pct", 0)
    if top_conf >= 70:
        tier = "HIGH"
    elif top_conf >= 45:
        tier = "MEDIUM"
    elif top_conf >= 20:
        tier = "LOW"
    else:
        tier = "INSUFFICIENT DATA"

    gate_passed = top_conf >= 35 and features.get("technique_count", 0) >= 4

    # Step 3: Persist to Supabase
    analysis_record = {
        "analysis_type": "attribution",
        "input_mode": req.input_mode,
        "input_summary": req.text[:500],
        "top_group": ml_result.get("top_group"),
        "top_confidence": ml_result.get("top_confidence", 0),
        "confidence_tier": tier,
        "gate_passed": gate_passed,
        "observed_techniques": features.get("techniques", []),
        "context_signals": features.get("context_signals", []),
        "model_version": ml_result.get("model_version", "none"),
        "model_confidence": ml_result.get("top_confidence", 0),
        "full_result": {
            "ml_predictions": ml_result.get("predictions", []),
            "extracted_features": {
                "techniques": features.get("techniques", []),
                "matched_keywords": features.get("matched_keywords", []),
                "context_signals": features.get("context_signals", []),
                "iocs": features.get("iocs", {}),
                "technique_count": features.get("technique_count", 0),
                "motive_clues": features.get("motive_clues", {}),
            },
        },
    }

    try:
        stored = db.insert_analysis(analysis_record)
        analysis_id = stored.get("id", "unknown")
    except Exception:
        analysis_id = "not_persisted"

    # Step 3.5: Generate SHAP explanation
    shap_explanation = []
    if ml_result.get("predictions"):
        # top prediction is first element
        top_pred = ml_result["predictions"][0]["group"]
        
        # We need the index of the predicted class in the class schema
        schema = ml_engine._feature_schema
        if schema and "class_names" in schema and top_pred in schema["class_names"]:
            class_idx = schema["class_names"].index(top_pred)
            explanation = ml_engine.explain_prediction(features, class_idx)
            if "top_contributors" in explanation:
                shap_explanation = explanation["top_contributors"]

    # Step 4: Return response
    return AnalyzeResponse(
        analysis_id=analysis_id,
        model_version=ml_result.get("model_version", "none"),
        top_group=ml_result.get("top_group"),
        top_confidence=ml_result.get("top_confidence", 0),
        confidence_pct=ml_result.get("confidence_pct", 0),
        predictions=ml_result.get("predictions", []),
        observed_techniques=features.get("techniques", []),
        context_signals=features.get("context_signals", []),
        matched_keywords=features.get("matched_keywords", []),
        technique_count=features.get("technique_count", 0),
        iocs=features.get("iocs", {}),
        gate_passed=gate_passed,
        confidence_tier=tier,
        shap_explanation=shap_explanation,
    )


@router.post("/analyze/feedback")
async def submit_feedback(req: FeedbackRequest):
    """
    Submit analyst feedback on an attribution result.
    Used for continuous learning — corrections become training samples.
    """
    if req.feedback not in ("confirmed", "corrected", "rejected"):
        raise HTTPException(status_code=422, detail="feedback must be: confirmed, corrected, or rejected")

    if req.feedback == "corrected" and not req.corrected_group:
        raise HTTPException(status_code=422, detail="corrected_group is required when feedback is 'corrected'")

    # Update analysis with feedback
    updated = db.update_analysis_feedback(
        analysis_id=req.analysis_id,
        feedback=req.feedback,
        corrected_group=req.corrected_group,
        notes=req.notes,
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # If corrected or confirmed → create training sample
    if req.feedback in ("confirmed", "corrected"):
        analysis = db.get_analysis(req.analysis_id)
        if analysis and analysis.get("full_result"):
            label = req.corrected_group if req.feedback == "corrected" else analysis.get("top_group")
            extracted = analysis["full_result"].get("extracted_features", {})

            training_sample = {
                "source": "analyst_feedback",
                "label": label,
                "features": extracted,
                "source_analysis_id": req.analysis_id,
                "source_description": f"Analyst {req.feedback}: {req.notes or 'no notes'}",
                "confidence": 1.0 if req.feedback == "confirmed" else 0.9,
                "validated": True,
            }
            try:
                db.insert_training_sample(training_sample)
            except Exception:
                pass  # Non-critical — don't fail the feedback

    return {"status": "ok", "analysis_id": req.analysis_id, "feedback": req.feedback}
