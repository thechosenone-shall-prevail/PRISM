"""
Persistent storage for unattributed/emerging PRISM clusters.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "data" / "emerging_clusters.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_db() -> dict[str, Any]:
    if not DB_PATH.exists():
        return {"clusters": []}
    with open(DB_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        return {"clusters": []}
    if "clusters" not in data or not isinstance(data["clusters"], list):
        data["clusters"] = []
    return data


def _save_db(data: dict[str, Any]) -> None:
    with open(DB_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def upsert_emerging_cluster(
    cluster_id: str,
    observed_features: dict,
    top_hypotheses: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Create/update an emerging cluster in local JSON memory.
    """
    db = _load_db()
    now = _utc_now()
    techniques = sorted(set(observed_features.get("techniques", [])))
    contexts = sorted(set(observed_features.get("context_signals", [])))
    matched_keywords = sorted(set(observed_features.get("matched_keywords", [])))

    existing = next((c for c in db["clusters"] if c.get("cluster_id") == cluster_id), None)
    if existing:
        existing["last_seen"] = now
        existing["sightings"] = int(existing.get("sightings", 0)) + 1
        existing["techniques"] = sorted(set(existing.get("techniques", [])) | set(techniques))
        existing["context_signals"] = sorted(set(existing.get("context_signals", [])) | set(contexts))
        existing["matched_keywords"] = sorted(set(existing.get("matched_keywords", [])) | set(matched_keywords))
        existing["latest_hypotheses"] = top_hypotheses
        cluster = existing
    else:
        cluster = {
            "cluster_id": cluster_id,
            "status": "EMERGING",
            "created_at": now,
            "first_seen": now,
            "last_seen": now,
            "sightings": 1,
            "techniques": techniques,
            "context_signals": contexts,
            "matched_keywords": matched_keywords,
            "latest_hypotheses": top_hypotheses,
        }
        db["clusters"].append(cluster)

    _save_db(db)
    return cluster
