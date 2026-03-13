"""
PRISM API — Intel Pipeline Endpoints
GET  /api/intel          — list intel queue items
POST /api/intel          — ingest new intel item
POST /api/intel/process  — process queued intel into training samples
GET  /api/intel/stats    — intel pipeline statistics
"""

from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import db

router = APIRouter()


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class IntelItem(BaseModel):
    id: str = Field(..., description="Unique identifier for the intel item")
    title: str
    source_name: str = Field("manual", description="Source: vendor, official, research, etc.")
    source_tier: str = Field("community", description="official, vendor, research, media, community, unknown")
    url: Optional[str] = None
    groups: list[str] = Field(default_factory=list, description="APT groups mentioned")
    summary: Optional[str] = None
    content: Optional[str] = None
    published_at: Optional[str] = None


class ProcessRequest(BaseModel):
    intel_id: str
    label: str = Field(..., description="APT group label for the training sample")
    confidence: float = Field(0.8, ge=0.0, le=1.0, description="Confidence weight for training")
    techniques: list[str] = Field(default_factory=list, description="Extracted TTPs from intel")
    context_signals: list[str] = Field(default_factory=list, description="Context signals from intel")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/intel")
async def list_intel(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    processed: Optional[bool] = Query(None, description="Filter by processed status"),
):
    """List intel queue items, most recent first."""
    items = db.get_intel_queue(limit=limit, offset=offset, processed=processed)
    return {
        "count": len(items),
        "offset": offset,
        "limit": limit,
        "items": items,
    }


@router.post("/intel")
async def ingest_intel(item: IntelItem):
    """
    Ingest a new intel item into the queue.
    This is used to add threat intelligence reports for later processing.
    """
    if item.source_tier not in ("official", "vendor", "research", "media", "community", "unknown"):
        raise HTTPException(status_code=422, detail="Invalid source_tier")

    record = {
        "id": item.id,
        "title": item.title,
        "source_name": item.source_name,
        "source_tier": item.source_tier,
        "url": item.url,
        "groups": item.groups,
        "summary": item.summary,
        "content": item.content,
        "processed": False,
    }

    if item.published_at:
        record["published_at"] = item.published_at

    try:
        stored = db.upsert_intel(record)
        return {"status": "ok", "id": item.id, "stored": stored}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store intel item: {e}")


@router.post("/intel/process")
async def process_intel(req: ProcessRequest):
    """
    Process a queued intel item into a training sample.
    Marks the intel item as processed and creates a labeled training sample
    for the continuous learning pipeline.
    """
    # Verify intel item exists
    intel = db.get_intel_item(req.intel_id)
    if not intel:
        raise HTTPException(status_code=404, detail=f"Intel item '{req.intel_id}' not found")

    # Build features dict for training sample
    features = {
        "techniques": req.techniques,
        "context_signals": req.context_signals,
        "technique_count": len(req.techniques),
    }

    training_sample = {
        "source": "intel_report",
        "label": req.label,
        "features": features,
        "source_intel_id": req.intel_id,
        "source_description": f"Intel: {intel.get('title', 'unknown')} ({intel.get('source_name', 'unknown')})",
        "confidence": req.confidence,
        "validated": req.confidence >= 0.9,
    }

    try:
        # Insert training sample
        sample = db.insert_training_sample(training_sample)

        # Mark intel item as processed
        db.mark_intel_processed(req.intel_id)

        return {
            "status": "ok",
            "intel_id": req.intel_id,
            "training_sample_id": sample.get("id", "unknown"),
            "label": req.label,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process intel: {e}")


@router.get("/intel/stats")
async def intel_stats():
    """Pipeline statistics: queue counts, processed counts, breakdown by source tier."""
    stats = db.get_intel_stats()
    return stats


@router.post("/intel/sync-mitre")
async def sync_mitre_attack():
    """
    Trigger a synchronization of MITRE ATT&CK techniques with APT profiles in Supabase.
    This pulls the latest mappings from the ATT&CK STIX data.
    """
    import intel_pipeline
    try:
        res = intel_pipeline.sync_attack_to_profiles(to_supabase=True)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MITRE sync failed: {e}")
