"""
APTrace — Feature Engineering Module
Converts raw TTP observations into ML-ready feature vectors.

This module bridges the engine's text extraction output and the ML model's
expected input format. Used both during training (offline) and inference (real-time).

Usage:
    from feature_engineering import FeatureBuilder

    builder = FeatureBuilder.from_schema("ml/data/feature_schema.json")
    vector = builder.build(observed_ttps)
"""

import json
import numpy as np
from pathlib import Path
from typing import Any


class FeatureBuilder:
    """
    Builds numerical feature vectors from extracted TTP observations.

    Feature categories:
      - ttp_*       : Binary presence of MITRE ATT&CK techniques
      - ctx_*       : Binary presence of context signals (sector, region, etc.)
      - technique_count  : Total number of observed techniques
      - context_count    : Total number of context signals
      - tactic_coverage  : Number of distinct MITRE tactics covered
    """

    def __init__(self, feature_names: list[str], class_names: list[str], model_version: str = "v1.0.0"):
        self.feature_names = feature_names
        self.class_names = class_names
        self.model_version = model_version
        self.n_features = len(feature_names)

        # Pre-index for fast lookup
        self._feature_index = {name: i for i, name in enumerate(feature_names)}
        self._ttp_features = [f for f in feature_names if f.startswith("ttp_")]
        self._ctx_features = [f for f in feature_names if f.startswith("ctx_")]
        self._meta_features = [f for f in feature_names if not f.startswith("ttp_") and not f.startswith("ctx_")]

    @classmethod
    def from_schema(cls, schema_path: str | Path) -> "FeatureBuilder":
        """Load feature configuration from a saved schema JSON file."""
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        return cls(
            feature_names=schema["features"],
            class_names=schema["class_names"],
            model_version=schema.get("model_version", "unknown"),
        )

    def build(self, observed: dict[str, Any]) -> np.ndarray:
        """
        Convert extracted observation dict into a feature vector.

        Args:
            observed: Dict with keys like:
                - techniques: list[str]     — Observed MITRE technique IDs
                - context_signals: list[str] — Context keywords found
                - matched_keywords: list[str] — Matched keyword list
                - technique_count: int
                - iocs: dict

        Returns:
            np.ndarray of shape (1, n_features)
        """
        vector = np.zeros(self.n_features, dtype=np.float32)

        techniques = set(observed.get("techniques", []))
        contexts = set(observed.get("context_signals", []))
        keywords = set(observed.get("matched_keywords", []))

        for feat_name, idx in self._feature_index.items():
            if feat_name.startswith("ttp_"):
                tech_id = feat_name[4:]
                if tech_id in techniques:
                    vector[idx] = 1.0
                # Partial match: parent technique (e.g., T1059 matches T1059.001)
                elif "." in tech_id:
                    parent = tech_id.split(".")[0]
                    if parent in techniques:
                        vector[idx] = 0.5
            elif feat_name.startswith("ctx_"):
                ctx_name = feat_name[4:].replace("_", " ")
                if ctx_name in contexts:
                    vector[idx] = 1.0
            elif feat_name == "technique_count":
                vector[idx] = float(observed.get("technique_count", len(techniques)))
            elif feat_name == "context_count":
                vector[idx] = float(len(contexts))
            elif feat_name == "tactic_coverage":
                vector[idx] = float(observed.get("tactic_coverage", 0))

        return vector.reshape(1, -1)

    def build_batch(self, observations: list[dict[str, Any]]) -> np.ndarray:
        """
        Build feature vectors for multiple observations.

        Returns:
            np.ndarray of shape (n_observations, n_features)
        """
        vectors = [self.build(obs).flatten() for obs in observations]
        return np.vstack(vectors)

    def explain_vector(self, vector: np.ndarray) -> dict[str, float]:
        """
        Convert a feature vector back into a human-readable dict
        of active features and their values (non-zero only).
        """
        flat = vector.flatten()
        active = {}
        for i, val in enumerate(flat):
            if val != 0.0:
                active[self.feature_names[i]] = float(val)
        return active

    def get_active_techniques(self, vector: np.ndarray) -> list[str]:
        """Extract technique IDs that are active (>0) in a feature vector."""
        flat = vector.flatten()
        return [
            self.feature_names[i][4:]  # strip "ttp_" prefix
            for i in range(len(flat))
            if flat[i] > 0 and self.feature_names[i].startswith("ttp_")
        ]

    def get_active_contexts(self, vector: np.ndarray) -> list[str]:
        """Extract context signals that are active (>0) in a feature vector."""
        flat = vector.flatten()
        return [
            self.feature_names[i][4:].replace("_", " ")
            for i in range(len(flat))
            if flat[i] > 0 and self.feature_names[i].startswith("ctx_")
        ]

    @property
    def summary(self) -> dict[str, Any]:
        """Return a summary of this feature schema."""
        return {
            "model_version": self.model_version,
            "total_features": self.n_features,
            "ttp_features": len(self._ttp_features),
            "context_features": len(self._ctx_features),
            "meta_features": len(self._meta_features),
            "classes": len(self.class_names),
            "class_names": self.class_names,
        }


def compute_tactic_coverage(techniques: list[str], ttp_mapping: dict[str, list[str]]) -> int:
    """
    Compute how many MITRE tactics are covered by the observed techniques.

    Args:
        techniques: list of technique IDs observed
        ttp_mapping: dict mapping tactic_name -> list of technique IDs

    Returns:
        Number of distinct tactics that have at least one observed technique
    """
    tech_set = set(techniques)
    covered = 0
    for tactic, tactic_techs in ttp_mapping.items():
        if tech_set & set(tactic_techs):
            covered += 1
    return covered


def compute_co_occurrence_features(
    techniques: list[str],
    known_pairs: list[tuple[str, str]],
) -> dict[str, int]:
    """
    Check for known technique co-occurrence pairs that are diagnostic of
    specific APT groups.

    Args:
        techniques: list of observed technique IDs
        known_pairs: list of (tech_a, tech_b) tuples that are significant

    Returns:
        Dict mapping pair key -> 1 if both present, 0 otherwise
    """
    tech_set = set(techniques)
    results = {}
    for a, b in known_pairs:
        key = f"pair_{a}_{b}"
        results[key] = 1 if (a in tech_set and b in tech_set) else 0
    return results
