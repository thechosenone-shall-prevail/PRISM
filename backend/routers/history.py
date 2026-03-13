"""
APTrace API — History Endpoints
GET /api/history — paginated analysis history
GET /api/history/{id} — single analysis detail
"""

from fastapi import APIRouter, HTTPException, Query

import db

router = APIRouter()


@router.get("/history")
async def list_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List past analyses, most recent first."""
    analyses = db.get_analyses_history(limit=limit, offset=offset)
    return {
        "count": len(analyses),
        "offset": offset,
        "limit": limit,
        "analyses": analyses,
    }


@router.get("/history/{analysis_id}")
async def get_analysis_detail(analysis_id: str):
    """Get full analysis detail including all results."""
    analysis = db.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis
