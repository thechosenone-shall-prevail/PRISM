"""
PRISM API — Attribution Endpoint
POST /api/analyze — runs ML-powered APT attribution
POST /api/analyze/feedback — analyst feedback for continuous learning
"""

import asyncio
import concurrent.futures
import json
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

# Load APT profiles for enrichment
_apt_profiles: dict = {}
def _load_apt_profiles():
    global _apt_profiles
    profiles_path = Path(__file__).resolve().parent.parent.parent / "data" / "apt_profiles.json"
    try:
        with open(profiles_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for group in data.get("apt_groups", []):
            name = group.get("name", "")
            _apt_profiles[name] = group
            for alias in group.get("aliases", []):
                _apt_profiles[alias] = group
    except Exception:
        pass

_load_apt_profiles()

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _merge_features(feature_list: list[dict]) -> dict:
    """
    Merge multiple feature extraction results into a single comprehensive feature set.
    Deduplicates techniques, keywords, and context signals.
    """
    merged = {
        "techniques": set(),
        "matched_keywords": set(),
        "context_signals": set(),
        "iocs": {
            "ips": set(),
            "domains": set(),
            "hashes_md5": set(),
            "hashes_sha256": set(),
            "cve": set(),
        },
        "motive_clues": {},
        "technique_count": 0,
    }
    
    for features in feature_list:
        # Merge techniques
        merged["techniques"].update(features.get("techniques", []))
        
        # Merge keywords
        merged["matched_keywords"].update(features.get("matched_keywords", []))
        
        # Merge context signals
        merged["context_signals"].update(features.get("context_signals", []))
        
        # Merge IOCs
        iocs = features.get("iocs", {})
        for key in ["ips", "domains", "hashes_md5", "hashes_sha256", "cve"]:
            if key in iocs:
                merged["iocs"][key].update(iocs[key])
        
        # Merge motive clues (sum counts)
        for motive, count in features.get("motive_clues", {}).items():
            merged["motive_clues"][motive] = merged["motive_clues"].get(motive, 0) + count
    
    # Convert sets back to sorted lists
    merged["techniques"] = sorted(merged["techniques"])
    merged["matched_keywords"] = sorted(merged["matched_keywords"])
    merged["context_signals"] = sorted(merged["context_signals"])
    merged["technique_count"] = len(merged["techniques"])
    
    for key in merged["iocs"]:
        merged["iocs"][key] = sorted(merged["iocs"][key])
    
    return merged


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    text: Optional[str] = Field(None, min_length=10, description="Analyst observations or log content")
    input_mode: str = Field("analyst_text", description="Input mode: analyst_text, log_file, or multi_file")
    # Multi-file support for comprehensive attack chain analysis
    attack_scenarios: Optional[list[str]] = Field(None, description="List of attack scenario descriptions")
    ttps: Optional[list[str]] = Field(None, description="List of TTP descriptions or MITRE technique IDs")
    iocs: Optional[dict] = Field(None, description="IOCs dict with keys: ips, domains, hashes, cves")
    log_files: Optional[list[str]] = Field(None, description="List of log file contents")


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
    nation: Optional[str] = None
    runner_up: Optional[dict] = None
    behavioral_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _run_analyze_sync(
    text: Optional[str],
    input_mode: str,
    attack_scenarios: Optional[list[str]],
    ttps: Optional[list[str]],
    iocs: Optional[dict],
    log_files: Optional[list[str]],
) -> dict:
    """All heavy/blocking analyze work runs here, off the event loop."""

    # Step 1: Extract features from all inputs
    all_features = []

    if text:
        if input_mode == "log_file":
            features = extract_ttps_from_log(text)
        else:
            features = extract_ttps_from_text(text)
        all_features.append(features)

    if attack_scenarios:
        for scenario in attack_scenarios:
            if scenario and len(scenario.strip()) >= 10:
                features = extract_ttps_from_text(scenario)
                all_features.append(features)

    if ttps:
        combined_ttps = "\n".join(ttps)
        if combined_ttps.strip():
            features = extract_ttps_from_text(combined_ttps)
            all_features.append(features)

    if log_files:
        for log_content in log_files:
            if log_content and len(log_content.strip()) >= 10:
                features = extract_ttps_from_log(log_content)
                all_features.append(features)

    if not all_features:
        return {"error": 422, "detail": "No input provided. Please provide at least one of: text, attack_scenarios, ttps, iocs, or log_files."}

    features = _merge_features(all_features)

    if iocs:
        existing_iocs = features.get("iocs", {})
        for key in ["ips", "domains", "hashes_md5", "hashes_sha256", "cve"]:
            if key in iocs and iocs[key]:
                existing_iocs.setdefault(key, []).extend(iocs[key])
                existing_iocs[key] = list(set(existing_iocs[key]))
        features["iocs"] = existing_iocs

    if features.get("technique_count", 0) == 0:
        return {"error": 422, "detail": "No techniques or behavioral indicators extracted from input. Provide more detailed observations."}

    # Step 2: ML model inference
    ml_result = ml_engine.predict(features)

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
    input_summary_parts = []
    if text:
        input_summary_parts.append(text[:200])
    if attack_scenarios:
        input_summary_parts.append(f"[{len(attack_scenarios)} attack scenarios]")
    if ttps:
        input_summary_parts.append(f"[{len(ttps)} TTP descriptions]")
    if log_files:
        input_summary_parts.append(f"[{len(log_files)} log files]")
    if iocs:
        ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
        input_summary_parts.append(f"[{ioc_count} IOCs]")

    input_summary = " | ".join(input_summary_parts)[:500]

    analysis_record = {
        "analysis_type": "attribution",
        "input_mode": input_mode,
        "input_summary": input_summary,
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
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(db.insert_analysis, analysis_record)
            stored = future.result(timeout=10)
        analysis_id = stored.get("id", "unknown")
    except concurrent.futures.TimeoutError:
        print("Warning: Supabase insert_analysis timed out (10s)")
        analysis_id = "not_persisted"
    except Exception:
        analysis_id = "not_persisted"

    # SHAP explanation
    shap_explanation = []
    if ml_result.get("predictions"):
        top_pred = ml_result["predictions"][0]["group"]
        schema = ml_engine._feature_schema
        if schema and "class_names" in schema and top_pred in schema["class_names"]:
            class_idx = schema["class_names"].index(top_pred)
            explanation = ml_engine.explain_prediction(features, class_idx)
            if "top_contributors" in explanation:
                shap_explanation = explanation["top_contributors"]

    # Enrich with APT profile data
    top_group_name = ml_result.get("top_group")
    nation = None
    behavioral_notes = None
    runner_up = None

    if top_group_name and top_group_name in _apt_profiles:
        profile = _apt_profiles[top_group_name]
        nation = profile.get("nation")
        motives = profile.get("motivation", [])
        sectors = profile.get("target_sectors", [])[:5]
        behavioral_notes = f"Known for targeting {', '.join(sectors)}" if sectors else ""
        if motives:
            behavioral_notes += f". Primary motivation: {', '.join(motives)}"

    preds = ml_result.get("predictions", [])
    if len(preds) >= 2:
        runner_up = {
            "group": preds[1].get("group"),
            "confidence": round(preds[1].get("probability", 0) * 100, 1),
        }

    return {
        "analysis_id": analysis_id,
        "model_version": ml_result.get("model_version", "none"),
        "top_group": top_group_name,
        "top_confidence": ml_result.get("top_confidence", 0),
        "confidence_pct": ml_result.get("confidence_pct", 0),
        "predictions": ml_result.get("predictions", []),
        "observed_techniques": features.get("techniques", []),
        "context_signals": features.get("context_signals", []),
        "matched_keywords": features.get("matched_keywords", []),
        "technique_count": features.get("technique_count", 0),
        "iocs": features.get("iocs", {}),
        "gate_passed": gate_passed,
        "confidence_tier": tier,
        "shap_explanation": shap_explanation,
        "nation": nation,
        "runner_up": runner_up,
        "behavioral_notes": behavioral_notes,
    }


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    """Run APT attribution — all heavy work offloaded to a thread."""
    result = await asyncio.to_thread(
        _run_analyze_sync,
        text=req.text,
        input_mode=req.input_mode,
        attack_scenarios=req.attack_scenarios,
        ttps=req.ttps,
        iocs=req.iocs,
        log_files=req.log_files,
    )

    if "error" in result:
        raise HTTPException(status_code=result["error"], detail=result["detail"])

    return AnalyzeResponse(**result)


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
