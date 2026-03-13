"""
PRISM Blast-Radius Engine — ENHANCED
Comprehensive behavioral graph intelligence that expands IOCs into full attack chains.

Features:
- Multi-hop relationship expansion (VT API)
- Detailed node metadata (detection ratios, tags, threat names)
- Kill-chain stage classification
- APT attribution hints
- Expandable nodes with comprehensive information
- Real-time threat intelligence correlation
"""

from __future__ import annotations

import re
import hashlib
from typing import Any, Dict, List, Optional
from datetime import datetime

import vt_client
from engine import extract_ttps_from_text, load_profiles, run_attribution
import sandbox_bridge


# ── IOC classification ──────────────────────────────────────────────

_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z]{2,})+$")


def classify_ioc(value: str) -> str:
    """Return 'hash', 'ip', 'domain', or 'unknown'."""
    v = value.strip()
    if _SHA256_RE.match(v) or _MD5_RE.match(v) or _SHA1_RE.match(v):
        return "hash"
    if _IPV4_RE.match(v):
        return "ip"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# ── Enhanced node enrichment ────────────────────────────────────────

def _enrich_node(node: Dict[str, Any], vt_report: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Add comprehensive metadata to nodes:
    - Kill-chain stage classification
    - Threat intelligence tags
    - Detection ratios
    - Malware family hints
    - APT group associations
    """
    ntype = node.get("type", "")
    label = node.get("label", "").lower()
    meta = node.get("meta", {})

    # Kill-chain stage classification
    stage = "unknown"
    if ntype == "file":
        if any(kw in label for kw in ("loader", "dropper", "stage1", "initial")):
            stage = "delivery"
        elif any(kw in label for kw in ("rat", "backdoor", "stage2", "implant", "beacon")):
            stage = "c2-implant"
        elif any(kw in label for kw in ("persist", "svc", "service", "startup", "run")):
            stage = "persistence"
        elif any(kw in label for kw in ("cred", "mimikatz", "harvest", "dump", "lsass")):
            stage = "credential-access"
        elif any(kw in label for kw in ("exfil", "upload", "steal", "data")):
            stage = "exfiltration"
        elif any(kw in label for kw in ("lateral", "spread", "wmi", "psexec", "smb")):
            stage = "lateral-movement"
        elif any(kw in label for kw in ("keylog", "screen", "capture", "monitor")):
            stage = "collection"
        elif any(kw in label for kw in ("recon", "scan", "enum", "discovery")):
            stage = "discovery"
        else:
            stage = "payload"
    elif ntype == "ip":
        stage = "infrastructure"
    elif ntype == "domain":
        stage = "infrastructure"
    elif ntype == "url":
        stage = "delivery"

    node["stage"] = stage

    # Add VirusTotal intelligence if available
    if vt_report:
        meta["vt_detection"] = vt_report.get("detection_ratio", "N/A")
        meta["vt_tags"] = vt_report.get("tags", [])
        meta["threat_names"] = vt_report.get("threat_names", [])
        meta["first_seen"] = vt_report.get("first_submission", "Unknown")
        meta["file_type"] = vt_report.get("type_description", "Unknown")
        
        # Try to map to malware family
        tags = vt_report.get("tags", [])
        for tag in tags:
            family = sandbox_bridge.map_malware_family_to_apt(tag)
            if family:
                meta["apt_hint"] = family
                break
    
    # Add comprehensive metadata
    meta["expandable"] = ntype == "file"  # Files can be expanded for more relationships
    meta["risk_level"] = _calculate_risk_level(node, meta)
    
    node["meta"] = meta
    return node


def _calculate_risk_level(node: Dict, meta: Dict) -> str:
    """Calculate risk level based on detection ratio and stage."""
    detection = meta.get("vt_detection", "0/0")
    if "/" in detection:
        try:
            detected, total = map(int, detection.split("/"))
            ratio = detected / total if total > 0 else 0
            
            if ratio >= 0.6:
                return "critical"
            elif ratio >= 0.3:
                return "high"
            elif ratio >= 0.1:
                return "medium"
            else:
                return "low"
        except:
            pass
    
    # Fallback to stage-based risk
    stage = node.get("stage", "unknown")
    if stage in ("credential-access", "exfiltration", "c2-implant"):
        return "high"
    elif stage in ("persistence", "lateral-movement"):
        return "medium"
    else:
        return "low"


# ── Node detail fetching ────────────────────────────────────────────

def get_node_details(node_id: str, node_type: str) -> Dict[str, Any]:
    """
    Fetch comprehensive details for a specific node.
    Called when user clicks on a node in the 3D graph.
    
    Returns detailed information including:
    - Full VirusTotal report
    - Extracted TTPs
    - Malware family classification
    - APT attribution hints
    - Relationship summary
    """
    details = {
        "id": node_id,
        "type": node_type,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if node_type == "file":
        # Get full VT report
        vt_report = vt_client.get_file_report(node_id)
        if vt_report and vt_report.get("found"):
            details["virustotal"] = {
                "detection_ratio": vt_report.get("detection_ratio"),
                "malicious_count": vt_report.get("malicious"),
                "total_engines": vt_report.get("total"),
                "tags": vt_report.get("tags", []),
                "threat_names": vt_report.get("threat_names", []),
                "file_type": vt_report.get("type_description"),
                "first_seen": vt_report.get("first_submission"),
                "meaningful_name": vt_report.get("meaningful_name"),
            }
            
            # Try to extract TTPs from tags and threat names
            context = " ".join(vt_report.get("tags", []) + vt_report.get("threat_names", []))
            if context:
                try:
                    features = extract_ttps_from_text(context)
                    details["extracted_ttps"] = features.get("techniques", [])[:10]
                except:
                    details["extracted_ttps"] = []
            
            # Map to malware family and APT
            for tag in vt_report.get("tags", []):
                apt_group = sandbox_bridge.map_malware_family_to_apt(tag)
                if apt_group:
                    details["apt_attribution"] = {
                        "group": apt_group,
                        "confidence": "medium",
                        "source": "malware_family_mapping",
                        "family": tag
                    }
                    break
        else:
            details["virustotal"] = {"status": "not_found"}
        
        # Get relationship counts
        relationship_summary = {}
        for rel_type in vt_client.RELATIONSHIP_TYPES:
            rel_data = vt_client.get_file_relationships(node_id, rel_type, limit=1)
            if rel_data:
                relationship_summary[rel_type] = len(rel_data.get("items", []))
        details["relationships"] = relationship_summary
        
    elif node_type == "ip":
        details["info"] = {
            "type": "IP Address",
            "value": node_id,
            "note": "Infrastructure node - may be C2 server, staging server, or exfiltration endpoint"
        }
        # Could add IP geolocation, ASN lookup, etc.
        
    elif node_type == "domain":
        details["info"] = {
            "type": "Domain",
            "value": node_id,
            "note": "Infrastructure node - may be used for C2 communication or payload hosting"
        }
        # Could add WHOIS, DNS records, etc.
        
    elif node_type == "url":
        details["info"] = {
            "type": "URL",
            "value": node_id,
            "note": "Delivery mechanism - may host malicious payloads or phishing content"
        }
    
    return details


# ── Graph expansion ─────────────────────────────────────────────────

def expand_node(node_id: str, node_type: str, max_children: int = 10) -> Dict[str, Any]:
    """
    Expand a single node to reveal its relationships.
    Called when user clicks "expand" on a node.
    
    Returns new nodes and edges to add to the graph.
    """
    if node_type != "file":
        return {"nodes": [], "edges": [], "message": "Only file nodes can be expanded"}
    
    new_nodes = []
    new_edges = []
    
    # Get all relationships for this file
    for rel_type in vt_client.RELATIONSHIP_TYPES:
        rel_data = vt_client.get_file_relationships(node_id, rel_type, limit=max_children)
        if not rel_data:
            continue
            
        for item in rel_data.get("items", []):
            child_id = item.get("id", "")
            child_type = item.get("type", "unknown")
            child_attr = item.get("attributes", {})
            
            # Determine label
            if child_type == "file":
                child_label = child_attr.get("meaningful_name", child_id[:12])
            elif child_type == "domain":
                child_label = child_id
            elif child_type == "ip_address":
                child_label = child_id
            elif child_type == "url":
                child_label = child_attr.get("url", child_id[:40])
            else:
                child_label = child_id[:16]
            
            mapped_type = {
                "file": "file",
                "domain": "domain",
                "ip_address": "ip",
                "url": "url",
            }.get(child_type, "unknown")
            
            # Create node with metadata
            node = {
                "id": child_id,
                "type": mapped_type,
                "label": child_label,
                "meta": {
                    "detection": child_attr.get("last_analysis_stats", {}),
                    "relationship_source": rel_type,
                }
            }
            
            # Enrich node
            if child_type == "file":
                vt_report = vt_client.get_file_report(child_id)
                _enrich_node(node, vt_report)
            else:
                _enrich_node(node)
            
            new_nodes.append(node)
            
            # Create edge
            new_edges.append({
                "source": node_id,
                "target": child_id,
                "relationship": rel_type,
            })
    
    return {
        "nodes": new_nodes,
        "edges": new_edges,
        "node_count": len(new_nodes),
        "edge_count": len(new_edges),
    }


# ── Main blast radius builder ───────────────────────────────────────

def build_blast_radius(
    ioc: str,
    depth: int = 2,
    max_children: int = 10,
) -> Dict[str, Any]:
    """
    Main entry: expand an IOC into a comprehensive behavioral attack graph.

    Returns:
        {
            seed, ioc_type, nodes[], edges[],
            node_count, edge_count, depth,
            kill_chain_summary, attribution_hint,
            metadata: {total_files, total_ips, total_domains, risk_distribution}
        }
    """
    ioc = ioc.strip()
    ioc_type = classify_ioc(ioc)

    # For now, graph expansion only supports file hashes
    if ioc_type == "hash":
        graph = vt_client.expand_blast_radius(ioc, depth=depth, max_children=max_children)
    else:
        # Wrap IP/domain as a single-node stub
        graph = {
            "seed": ioc,
            "nodes": [{"id": ioc, "type": ioc_type, "label": ioc, "meta": {}}],
            "edges": [],
            "depth": 0,
            "node_count": 1,
            "edge_count": 0,
        }

    # Enrich every node with comprehensive metadata
    for node in graph["nodes"]:
        if node["type"] == "file":
            vt_report = vt_client.get_file_report(node["id"])
            _enrich_node(node, vt_report)
        else:
            _enrich_node(node)

    # Build kill-chain summary
    stage_counts: Dict[str, int] = {}
    for node in graph["nodes"]:
        s = node.get("stage", "unknown")
        stage_counts[s] = stage_counts.get(s, 0) + 1

    graph["kill_chain_summary"] = stage_counts
    graph["ioc_type"] = ioc_type

    # Calculate metadata statistics
    type_counts = {"file": 0, "ip": 0, "domain": 0, "url": 0}
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for node in graph["nodes"]:
        ntype = node.get("type", "unknown")
        if ntype in type_counts:
            type_counts[ntype] += 1
        
        risk = node.get("meta", {}).get("risk_level", "low")
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    graph["metadata"] = {
        "total_files": type_counts["file"],
        "total_ips": type_counts["ip"],
        "total_domains": type_counts["domain"],
        "total_urls": type_counts["url"],
        "risk_distribution": risk_counts,
        "analysis_timestamp": datetime.utcnow().isoformat(),
    }

    # Attribution hint: run engine on node labels + relationships
    graph["attribution_hint"] = _attribution_hint(graph)

    return graph


def _attribution_hint(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Try to auto-attribute the blast radius using PRISM engine.
    Builds a synthetic report from all node labels, tags, and edge types.
    """
    parts: List[str] = []
    
    # Collect all labels
    for node in graph.get("nodes", []):
        parts.append(node.get("label", ""))
        # Add VT tags if available
        tags = node.get("meta", {}).get("vt_tags", [])
        parts.extend(tags)
    
    # Add relationship types
    for edge in graph.get("edges", []):
        parts.append(edge.get("relationship", "").replace("_", " "))

    synopsis = " ".join(parts)
    if len(synopsis.strip()) < 20:
        return {"group": None, "confidence": 0, "method": "insufficient_data"}

    try:
        features = extract_ttps_from_text(synopsis)
        if features.get("technique_count", 0) == 0:
            return {"group": None, "confidence": 0, "method": "no_ttps_extracted"}
        
        profiles = load_profiles()
        result = run_attribution(features, profiles)
        ranked = result.get("ranked_results", [])
        top = ranked[0] if ranked else {}
        
        return {
            "group": top.get("group"),
            "confidence": round(top.get("final_score", 0) * 100, 1),
            "method": "ml_attribution",
            "technique_count": features.get("technique_count", 0),
            "runner_up": ranked[1].get("group") if len(ranked) > 1 else None,
        }
    except Exception as e:
        return {"group": None, "confidence": 0, "method": "error", "error": str(e)}
