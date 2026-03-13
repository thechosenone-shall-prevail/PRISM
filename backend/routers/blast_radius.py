"""
PRISM API — Blast Radius Endpoints
POST /api/blast-radius — expands an IOC into a full behavioral attack graph
GET /api/blast-radius/node/{node_id} — get detailed information for a specific node
POST /api/blast-radius/expand — expand a node to reveal its relationships
"""

import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from blast_radius import (  # type: ignore
    build_blast_radius,
    classify_ioc,
    get_node_details,
    expand_node,
)

router = APIRouter()


class BlastRadiusRequest(BaseModel):
    ioc: str = Field(..., min_length=1, description="File hash (SHA256/MD5/SHA1), IP address, or domain")
    depth: int = Field(2, ge=1, le=3, description="Relationship hops to follow (1-3)")
    max_children: int = Field(10, ge=1, le=40, description="Max related items per relationship per node")


class ExpandNodeRequest(BaseModel):
    node_id: str = Field(..., description="Node ID to expand")
    node_type: str = Field(..., description="Node type (file, ip, domain, url)")
    max_children: int = Field(10, ge=1, le=40, description="Max related items per relationship")


class BlastRadiusResponse(BaseModel):
    seed: str
    ioc_type: str
    nodes: list[dict]
    edges: list[dict]
    node_count: int
    edge_count: int
    depth: int
    kill_chain_summary: dict
    attribution_hint: dict
    metadata: dict


@router.post("/blast-radius", response_model=BlastRadiusResponse)
async def blast_radius(req: BlastRadiusRequest):
    """
    Expand an IOC (file hash, IP, domain) into a comprehensive behavioral attack graph.
    
    Features:
    - Multi-hop relationship expansion via VirusTotal API
    - Kill-chain stage classification
    - Risk level assessment
    - APT attribution hints
    - Comprehensive metadata (detection ratios, tags, threat names)
    
    Returns nodes + edges suitable for 3D force-graph rendering with expandable nodes.
    """
    ioc = req.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=422, detail="IOC value is required.")

    ioc_type = classify_ioc(ioc)
    if ioc_type == "unknown":
        raise HTTPException(
            status_code=422,
            detail="Unrecognised IOC format. Provide a SHA256/MD5/SHA1 hash, IPv4 address, or domain.",
        )

    graph = build_blast_radius(ioc, depth=req.depth, max_children=req.max_children)
    return graph


@router.get("/blast-radius/node/{node_id}")
async def get_node_info(
    node_id: str,
    node_type: str = Query(..., description="Node type: file, ip, domain, or url")
):
    """
    Get comprehensive details for a specific node in the blast radius graph.
    
    Called when user clicks on a node to view detailed information.
    
    Returns:
    - Full VirusTotal report (for files)
    - Extracted TTPs
    - Malware family classification
    - APT attribution hints
    - Relationship summary
    - Threat intelligence
    """
    if not node_id:
        raise HTTPException(status_code=422, detail="Node ID is required")
    
    try:
        details = get_node_details(node_id, node_type)
        return details
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch node details: {str(e)}")


@router.post("/blast-radius/expand")
async def expand_node_relationships(req: ExpandNodeRequest):
    """
    Expand a single node to reveal its relationships.
    
    Called when user clicks "expand" button on a node in the graph.
    Returns new nodes and edges to add to the existing graph.
    
    Only file nodes can be expanded (they have relationships in VirusTotal).
    """
    try:
        expansion = expand_node(req.node_id, req.node_type, req.max_children)
        return expansion
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to expand node: {str(e)}")
