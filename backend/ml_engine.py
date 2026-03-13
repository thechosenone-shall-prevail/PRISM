"""
APTrace Backend — ML Engine Module
Loads the trained model (.pkl) and runs inference for APT attribution.
"""

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np

from config import ML_MODEL_PATH, FEATURE_SCHEMA_PATH

import shap

logger = logging.getLogger("aptrace.ml")

_model = None
_explainer = None
_feature_schema: dict | None = None
_model_version: str = "none"


def _load_model():
    """Load the ML model and feature schema from disk."""
    global _model, _feature_schema, _model_version

    model_path = Path(ML_MODEL_PATH)
    schema_path = Path(FEATURE_SCHEMA_PATH)

    if not model_path.exists():
        logger.warning(f"ML model not found at {model_path}. Inference disabled.")
        return False

    if not schema_path.exists():
        logger.warning(f"Feature schema not found at {schema_path}. Inference disabled.")
        return False

    try:
        import joblib
        _model = joblib.load(model_path)
        _explainer = shap.TreeExplainer(_model)
        with open(schema_path, encoding="utf-8") as f:
            _feature_schema = json.load(f)
        _model_version = _feature_schema.get("model_version", model_path.stem)
        logger.info(f"ML model loaded: {_model_version} ({len(_feature_schema.get('features', []))} features)")
        return True
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        _model = None
        _explainer = None
        _feature_schema = None
        return False


def is_model_loaded() -> bool:
    """Check if the ML model is loaded and ready for inference."""
    return _model is not None and _feature_schema is not None


def get_model_version() -> str:
    """Return the current model version string."""
    return _model_version


def build_feature_vector(observed: dict) -> np.ndarray:
    """
    Convert extracted TTP features into a numeric feature vector
    matching the trained model's expected input.
    
    Args:
        observed: Output from engine.extract_ttps_from_text() containing
                  techniques, context_signals, matched_keywords, etc.
    
    Returns:
        numpy array of shape (1, n_features) ready for model.predict()
    """
    if _feature_schema is None:
        raise RuntimeError("Feature schema not loaded")

    feature_names = _feature_schema["features"]
    n_features = len(feature_names)
    vector = np.zeros(n_features, dtype=np.float32)

    observed_techniques = set(observed.get("techniques", []))
    observed_contexts = set(observed.get("context_signals", []))
    observed_keywords = set(observed.get("matched_keywords", []))

    for i, feat_name in enumerate(feature_names):
        if feat_name.startswith("ttp_"):
            # TTP binary feature: ttp_T1566.001 → check if T1566.001 in techniques
            tech_id = feat_name[4:]  # Strip "ttp_" prefix
            if tech_id in observed_techniques:
                vector[i] = 1.0
            # Also check parent technique match
            elif "." in tech_id and tech_id.split(".")[0] in observed_techniques:
                vector[i] = 0.5  # Partial match for parent technique
        elif feat_name.startswith("ctx_"):
            # Context signal feature: ctx_cryptocurrency → check context_signals
            ctx_name = feat_name[4:]
            if ctx_name in observed_contexts:
                vector[i] = 1.0
        elif feat_name.startswith("kw_"):
            # Keyword presence feature
            kw_name = feat_name[3:]
            if kw_name in observed_keywords:
                vector[i] = 1.0
        elif feat_name == "technique_count":
            vector[i] = float(observed.get("technique_count", 0))
        elif feat_name == "context_count":
            vector[i] = float(len(observed_contexts))
        elif feat_name == "keyword_count":
            vector[i] = float(len(observed_keywords))
        elif feat_name == "overall_entropy":
            vector[i] = float(observed.get("extracted_static", {}).get("overall_entropy", 0.0) or observed.get("overall_entropy", 0.0))
        elif feat_name == "export_count":
            vector[i] = float(observed.get("extracted_static", {}).get("export_count", 0) or observed.get("export_count", 0))
        elif feat_name == "imphash_match":
            pass # Reserved for future clustering logic

    return vector.reshape(1, -1)


def predict(observed: dict) -> dict[str, Any]:
    """
    Run ML inference on extracted features.
    
    Args:
        observed: Output from engine.extract_ttps_from_text()
    
    Returns:
        {
            "model_version": "v1.0.0",
            "predictions": [
                {"group": "Lazarus Group", "probability": 0.87},
                {"group": "APT28", "probability": 0.05},
                ...
            ],
            "top_group": "Lazarus Group",
            "top_confidence": 0.87,
            "confidence_pct": 87.0,
            "feature_vector_size": 400
        }
    """
    if not is_model_loaded():
        # Try loading once
        if not _load_model():
            return {
                "model_version": "none",
                "error": "ML model not loaded. Run training pipeline first.",
                "predictions": [],
                "top_group": None,
                "top_confidence": 0.0,
                "confidence_pct": 0.0,
            }

    try:
        feature_vector = build_feature_vector(observed)
        class_names = _feature_schema.get("class_names", [])

        # Get probability predictions
        probabilities = _model.predict_proba(feature_vector)[0]

        # Build ranked predictions
        predictions = []
        for i, class_name in enumerate(class_names):
            predictions.append({
                "group": class_name,
                "probability": round(float(probabilities[i]), 4),
            })

        predictions.sort(key=lambda x: x["probability"], reverse=True)

        top = predictions[0] if predictions else {"group": None, "probability": 0.0}

        return {
            "model_version": _model_version,
            "predictions": predictions,
            "top_group": top["group"],
            "top_confidence": top["probability"],
            "confidence_pct": round(top["probability"] * 100, 1),
            "feature_vector_size": feature_vector.shape[1],
        }

    except Exception as e:
        logger.error(f"ML inference failed: {e}")
        return {
            "model_version": _model_version,
            "error": str(e),
            "predictions": [],
            "top_group": None,
            "top_confidence": 0.0,
            "confidence_pct": 0.0,
            "feature_vector_size": 0,
        }


def explain_prediction(observed: dict, predicted_class_idx: int) -> dict[str, Any]:
    """
    Generate SHAP values explaining why the model predicted the given class.
    
    Args:
        observed: The observed TTPs dict from the engine.
        predicted_class_idx: The integer index of the predicted class.
        
    Returns:
        Dict mapping feature name to its SHAP contribution value.
    """
    if not is_model_loaded() or _explainer is None:
        return {"error": "Model or explainer not loaded."}
        
    try:
        feature_vector = build_feature_vector(observed)
        shap_values = _explainer.shap_values(feature_vector)
        
        # Binary classification returns 1D array of values, multi-class returns list of arrays
        if isinstance(shap_values, list):
            class_shap_values = shap_values[predicted_class_idx][0]
        else:
            # If shap_values has shape (classes, samples, features)
            if len(shap_values.shape) == 3:
                class_shap_values = shap_values[predicted_class_idx, 0, :]
            else:
                class_shap_values = shap_values[0]
                
        feature_names = _feature_schema["features"]
        
        # Combine feature names with their absolute SHAP contributions
        contributions = []
        for i, val in enumerate(class_shap_values):
            if feature_vector[0][i] > 0 and abs(val) > 0.001:  # Only show present features that influenced the model
                contributions.append({
                    "feature": feature_names[i],
                    "contribution": round(float(val), 4),
                    "importance": round(abs(float(val)), 4)
                })
                
        # Sort by absolute importance
        contributions.sort(key=lambda x: x["importance"], reverse=True)
        
        return {
            "top_contributors": contributions[:15]
        }
    except Exception as e:
        logger.error(f"SHAP explanation failed: {e}")
        return {"error": str(e)}


def startup():
    """Called at FastAPI startup to pre-load the model."""
    _load_model()
