"""
PRISM API — Profiles Endpoints
GET /api/profiles — list APT groups
GET /api/profiles/{name} — get single group
GET /api/families — list malware families
"""

from fastapi import APIRouter, HTTPException

import db

router = APIRouter()


@router.get("/profiles")
async def list_profiles():
    """List all APT group profiles."""
    profiles = db.get_all_profiles()
    return {
        "count": len(profiles),
        "profiles": [
            {
                "id": p["id"],
                "name": p["name"],
                "nation": p["nation"],
                "aliases": p.get("aliases", []),
                "motivation": p.get("motivation", []),
                "active_since": p.get("active_since"),
                "last_seen": p.get("last_seen"),
            }
            for p in profiles
        ]
    }


@router.get("/profiles/{name}")
async def get_profile(name: str):
    """Get a single APT group profile by name."""
    profile = db.get_profile_by_name(name)
    if not profile:
        raise HTTPException(status_code=404, detail=f"APT group '{name}' not found")
    return profile


@router.get("/families")
async def list_families():
    """List all malware families."""
    families = db.get_all_families()
    return {
        "count": len(families),
        "families": [
            {
                "family": f["family"],
                "cluster": f["cluster"],
                "summary": f.get("summary", ""),
                "file_types": f.get("file_types", []),
            }
            for f in families
        ]
    }


@router.get("/families/{name}")
async def get_family(name: str):
    """Get a single malware family by name with full intelligence."""
    families = db.get_all_families()
    for f in families:
        if f.get("family", "").lower() == name.lower():
            return f
    raise HTTPException(status_code=404, detail=f"Malware family '{name}' not found")
