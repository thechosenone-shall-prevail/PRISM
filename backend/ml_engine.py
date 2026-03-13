"""
PRISM Backend — ML Engine Module
Loads the trained model (.pkl) and runs inference for APT attribution.
"""

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np

from config import ML_MODEL_PATH, FEATURE_SCHEMA_PATH

import shap

logger = logging.getLogger("PRISM.ml")

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

    # Normalize contexts: spaces → underscores to match feature names like ctx_south_korea
    observed_contexts_norm = {c.replace(" ", "_") for c in observed_contexts}

    for i, feat_name in enumerate(feature_names):
        if feat_name.startswith("ttp_"):
            # TTP binary feature: ttp_T1566.001 → check if T1566.001 in techniques
            tech_id = feat_name[4:]  # Strip "ttp_" prefix
            if tech_id in observed_techniques:
                vector[i] = 1.0
        elif feat_name.startswith("ctx_"):
            # Context signal feature: ctx_cryptocurrency → check context_signals
            ctx_name = feat_name[4:]
            if ctx_name in observed_contexts_norm:
                vector[i] = 1.0
        elif feat_name.startswith("kw_"):
            # Keyword presence feature
            kw_name = feat_name[3:]
            if kw_name in observed_keywords:
                vector[i] = 1.0
        elif feat_name == "technique_count":
            vector[i] = float(observed.get("technique_count", len(observed_techniques)))
        elif feat_name == "context_count":
            vector[i] = float(len(observed_contexts))
        elif feat_name == "tactic_coverage":
            vector[i] = float(observed.get("tactic_coverage", 0))
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

    For sparse inputs (typical of static-only malware analysis where only a
    handful of TTPs can be extracted), we return honest low-confidence results
    labelled "Unattributed" or "Emerging Threat Actor" rather than a
    misleadingly confident attribution.  When a malware-family→APT mapping
    exists we surface it as a secondary hint.

    Rich text-based observations (many TTPs + context signals) go through the
    real XGBoost model as before.
    """
    if not is_model_loaded():
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
        class_names = _feature_schema.get("class_names", [])
        # Filter out "Unknown" from display — we use our own labels
        real_groups = [g for g in class_names if g != "Unknown"]

        n_techniques = len(observed.get("techniques", []))
        n_contexts   = len(observed.get("context_signals", []))
        n_keywords   = len(observed.get("matched_keywords", []))
        total_signal = n_techniques + n_contexts + n_keywords

        # Detect family → APT hint
        family_apt = None
        malware_family = None
        for sig in observed.get("context_signals", []):
            if sig.startswith("known_apt:"):
                family_apt = sig.split(":", 1)[1]
            if sig.startswith("malware_family:"):
                malware_family = sig.split(":", 1)[1]

        # ── SPARSE PATH: ≤ 8 total signals ──
        # Typical for real EXE static analysis — only a few imports/strings
        # matched.  An honest model can't attribute with so little evidence.
        if total_signal <= 8:
            return _sparse_prediction(
                observed, real_groups, total_signal,
                n_techniques, family_apt, malware_family,
            )

        # ── RICH PATH: > 8 signals — use the real model ──
        feature_vector = build_feature_vector(observed)
        probabilities = _model.predict_proba(feature_vector)[0]

        # Map class_names → probabilities, collapse "Unknown" into the spread
        unknown_mass = 0.0
        group_probs: dict[str, float] = {}
        for i, cn in enumerate(class_names):
            if cn == "Unknown":
                unknown_mass = float(probabilities[i])
            else:
                group_probs[cn] = float(probabilities[i])

        # Redistribute the Unknown mass proportionally
        if unknown_mass > 0 and group_probs:
            total_real = sum(group_probs.values())
            if total_real > 0:
                for g in group_probs:
                    group_probs[g] += unknown_mass * (group_probs[g] / total_real)

        # Family-to-APT boost
        if family_apt and family_apt in group_probs:
            boost = max(0.08, 0.25 - n_techniques * 0.015)
            group_probs[family_apt] = min(0.95, group_probs[family_apt] + boost)

        # Re-normalize
        total_p = sum(group_probs.values())
        if total_p > 0:
            group_probs = {g: p / total_p for g, p in group_probs.items()}

        # Build sorted predictions with reasoning
        ranked = sorted(group_probs.items(), key=lambda x: x[1], reverse=True)
        predictions = []
        for g, p in ranked:
            reasons = _build_reasons(g, observed, family_apt, malware_family, p)
            predictions.append({
                "group": g,
                "probability": round(p, 4),
                "reasoning": reasons,
            })

        top = predictions[0] if predictions else {"group": None, "probability": 0.0}
        conf_pct = round(top["probability"] * 100, 1)

        if conf_pct >= 70:
            tier = "HIGH"
        elif conf_pct >= 45:
            tier = "MODERATE"
        else:
            tier = "LOW"

        return {
            "model_version": _model_version,
            "predictions": predictions,
            "top_group": top["group"],
            "top_confidence": top["probability"],
            "confidence_pct": conf_pct,
            "confidence_tier": tier,
            "feature_vector_size": len(_feature_schema.get("features", [])),
            "signal_count": total_signal,
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


# ── helpers ────────────────────────────────────────────────────────────────

import random as _random

# Groups with known associations to certain TTP clusters
_GROUP_TTP_HINTS: dict[str, set[str]] = {
    "Lazarus Group":      {"T1055", "T1027", "T1059.003", "T1497.001", "T1140"},
    "APT28":              {"T1566.001", "T1059.001", "T1071.001", "T1003", "T1078"},
    "APT29":              {"T1195.002", "T1059.001", "T1071.001", "T1550.001"},
    "Sandworm":           {"T1059.001", "T1569.002", "T1112", "T1071.001"},
    "APT41":              {"T1195.002", "T1059.001", "T1055", "T1543.003"},
    "Volt Typhoon":       {"T1059.001", "T1078", "T1071.001"},
    "APT35":              {"T1566.001", "T1059.001", "T1071.001"},
    "Kimsuky":            {"T1566.001", "T1059.001", "T1071.001"},
    "Transparent Tribe":  {"T1566.001", "T1059.001", "T1055"},
    "MuddyWater":         {"T1059.001", "T1071.001", "T1055"},
    "OilRig":             {"T1566.001", "T1059.001", "T1071.001"},
    "Turla":              {"T1055", "T1071.001", "T1059.001"},
    "Salt Typhoon":       {"T1071.001", "T1059.001"},
}


def _sparse_prediction(
    observed: dict,
    real_groups: list[str],
    total_signal: int,
    n_techniques: int,
    family_apt: str | None,
    malware_family: str | None,
) -> dict[str, Any]:
    """
    Return honest, unbiased predictions when evidence is too thin for
    confident attribution.  Spreads probability across plausible groups
    with a slight bump for any family-hint match.
    """
    observed_techs = set(observed.get("techniques", []))

    # Score each group by how many of its signature TTPs overlap
    scores: dict[str, float] = {}
    for g in real_groups:
        sig_ttps = _GROUP_TTP_HINTS.get(g, set())
        overlap = len(observed_techs & sig_ttps) if sig_ttps else 0
        # Small base + overlap bonus — keeps things spread out
        scores[g] = 1.0 + overlap * 1.5

    # Family → APT boost
    if family_apt and family_apt in scores:
        scores[family_apt] += 4.0

    total_score = sum(scores.values())
    probs = {g: s / total_score for g, s in scores.items()}

    # Sort by probability
    ranked = sorted(probs.items(), key=lambda x: x[1], reverse=True)

    # Cap the top prediction to a realistic range for sparse input
    # With ≤3 TTPs there's genuinely not enough to say much
    max_conf = min(0.42, 0.12 + n_techniques * 0.04 + (0.15 if family_apt else 0.0))
    # Scale everything so top = max_conf
    top_raw = ranked[0][1]
    if top_raw > 0:
        scale = max_conf / top_raw
        ranked = [(g, p * scale) for g, p in ranked]
    # Remaining mass goes to "spread"
    used = sum(p for _, p in ranked)
    leftover = max(0.0, 1.0 - used)
    if len(ranked) > 0:
        per_group_extra = leftover / len(ranked)
        ranked = [(g, p + per_group_extra) for g, p in ranked]

    # Determine display label
    if family_apt:
        display_group = f"Possible {family_apt} (via {malware_family or 'family match'})"
        top_reasoning = (
            f"Malware family '{malware_family}' historically linked to {family_apt}. "
            f"Only {n_techniques} TTP(s) extracted from static analysis — "
            f"insufficient for high-confidence ML attribution."
        )
    elif n_techniques == 0:
        display_group = "Unattributed"
        top_reasoning = (
            "No MITRE ATT&CK techniques could be extracted from this sample. "
            "Attribution requires behavioral indicators — consider dynamic analysis."
        )
    else:
        display_group = "Emerging / Unattributed Threat"
        top_reasoning = (
            f"Only {n_techniques} technique(s) detected from static analysis. "
            f"These TTPs are shared across many threat actors and don't point "
            f"to a single group with confidence."
        )

    predictions = []
    for i, (g, p) in enumerate(ranked):
        reasons = _build_reasons(g, observed, family_apt, malware_family, p)
        entry = {
            "group": g,
            "probability": round(p, 4),
            "reasoning": reasons,
        }
        predictions.append(entry)

    # Insert our display label at position 0
    conf_pct = round(ranked[0][1] * 100, 1) if ranked else 0.0

    return {
        "model_version": _model_version,
        "predictions": predictions,
        "top_group": display_group,
        "top_confidence": ranked[0][1] if ranked else 0.0,
        "confidence_pct": conf_pct,
        "confidence_tier": "LOW",
        "feature_vector_size": len(_feature_schema.get("features", [])),
        "signal_count": total_signal,
        "sparse_mode": True,
        "reasoning": top_reasoning,
    }


def _build_reasons(
    group: str,
    observed: dict,
    family_apt: str | None,
    malware_family: str | None,
    probability: float,
) -> str:
    """Return a short human-readable explanation for why this group appears."""
    parts: list[str] = []
    observed_techs = set(observed.get("techniques", []))
    sig = _GROUP_TTP_HINTS.get(group, set())
    overlap = observed_techs & sig

    if group == family_apt:
        parts.append(f"Malware family '{malware_family}' historically linked to {group}")
    if overlap:
        parts.append(f"Matched TTPs: {', '.join(sorted(overlap))}")
    if not parts:
        pct = round(probability * 100, 1)
        if pct > 5:
            parts.append("Partial TTP overlap with this group's known toolset")
        else:
            parts.append("Low overlap — included for completeness")
    return "; ".join(parts)


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
