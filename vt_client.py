"""
VirusTotal API Client Integration
Supports both authenticated API v3 and free public API v2
"""
import os
import requests
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

# Load .env so VT_API_KEY is available regardless of import order
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent / "backend" / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass

VT_API_KEY = os.environ.get("VT_API_KEY") or None  # treat empty string as None
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_PUBLIC_URL = "https://www.virustotal.com/vtapi/v2"


def _vt_headers() -> Dict[str, str]:
    return {"accept": "application/json", "x-apikey": VT_API_KEY}


def query_virustotal(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Query VirusTotal using free public API (no key required).
    Falls back to API v3 if key is available.
    
    Returns parsed intel or None if not found.
    """
    # Try API v3 first if key available
    if VT_API_KEY:
        return get_file_report(file_hash)
    
    # Use free public API v2 (no authentication required)
    url = f"{VT_PUBLIC_URL}/file/report"
    params = {"resource": file_hash, "apikey": "public"}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            if data.get("response_code") == 1:
                # File found
                positives = data.get("positives", 0)
                total = data.get("total", 0)
                
                return {
                    "found": True,
                    "malicious": positives,
                    "total": total,
                    "detection_ratio": f"{positives}/{total}",
                    "scan_date": data.get("scan_date", ""),
                    "permalink": data.get("permalink", ""),
                    "tags": data.get("tags", []),
                    "names": list(set([
                        scan.get("result", "") 
                        for scan in data.get("scans", {}).values() 
                        if scan.get("detected")
                    ]))[:10],  # Top 10 unique names
                }
            else:
                return {"found": False, "message": "Hash not found in VirusTotal."}
    except Exception as e:
        print(f"[VT Public API Error] {e}")
    
    return None


def get_file_report(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Query the VirusTotal API v3 for a file hash (requires API key).
    Returns parsed intel or None if not found/no API key.
    """
    if not VT_API_KEY or not file_hash:
        return None
        
    url = f"{VT_BASE_URL}/files/{file_hash}"
    try:
        response = requests.get(url, headers=_vt_headers(), timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            attr = data.get("attributes", {})
            
            # Extract key intel for the PRISM platform
            stats = attr.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            
            return {
                "found": True,
                "malicious": malicious,
                "total": total,
                "detection_ratio": f"{malicious}/{total}",
                "meaningful_name": attr.get("meaningful_name"),
                "tags": attr.get("tags", []),
                "type_description": attr.get("type_description"),
                "first_submission": attr.get("first_submission_date"),
                "threat_names": attr.get("popular_threat_classification", {}).get("popular_threat_category", []),
                "scan_date": attr.get("last_analysis_date"),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        elif response.status_code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal."}
    except Exception as e:
        print(f"[VT API Error] {e}")
        
    return None


# ---------------------------------------------------------------------------
# Blast-Radius: VT Relationship Expansion
# ---------------------------------------------------------------------------

# Full list (used when caller explicitly requests a specific type)
RELATIONSHIP_TYPES = [
    "contacted_ips",
    "contacted_domains",
    "contacted_urls",
    "dropped_files",
    "execution_parents",
    "bundled_files",
    "itw_urls",
    "communicating_files",
]

# Subset used for blast-radius expansion (keeps within free-tier 4 req/min)
_BLAST_RADIUS_RELS = [
    "contacted_ips",
    "contacted_domains",
    "dropped_files",
    "execution_parents",
]


def get_file_relationships(
    file_hash: str,
    relationship: str,
    limit: int = 20,
) -> Optional[Dict[str, Any]]:
    """
    Fetch a single relationship type for a file from VT v3.
    Returns {type, items: [{id, type, attributes}, ...]}.
    """
    if not VT_API_KEY or not file_hash:
        return None
    if relationship not in RELATIONSHIP_TYPES:
        return None

    url = f"{VT_BASE_URL}/files/{file_hash}/{relationship}"
    params = {"limit": min(limit, 40)}
    try:
        resp = requests.get(url, headers=_vt_headers(), params=params, timeout=30)
        if resp.status_code == 429:
            # Rate limited — wait and retry once
            print(f"[VT Rate Limited] {relationship} — waiting 60s")
            time.sleep(60)
            resp = requests.get(url, headers=_vt_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            payload = resp.json()
            return {
                "type": relationship,
                "items": payload.get("data", []),
            }
    except Exception as e:
        print(f"[VT Relationships Error] {relationship}: {e}")
    return None


def expand_blast_radius(
    file_hash: str,
    depth: int = 2,
    max_children: int = 10,
) -> Dict[str, Any]:
    """
    Recursively expand VT relationships starting from a seed hash.
    Returns a graph of {nodes: [...], edges: [...]} suitable for
    3D rendering on the dashboard.

    depth       — how many hops to follow (1 = direct, 2 = two hops)
    max_children — max related items per relationship per node
    
    Works with:
    - API v3 with key (full relationship data)
    - No key: builds graph from static analysis cache (real file indicators)
    """
    # Try to get basic file info first (works with free API)
    file_info = query_virustotal(file_hash)
    
    # If API key available, use full relationship expansion
    if VT_API_KEY:
        # Free keys: cap depth at 1 to stay within rate limits
        effective_depth = min(depth, 1)
        return _expand_with_api_key(file_hash, effective_depth, max_children, file_info)
    
    # No VT key — build graph from static analysis if available
    return _build_graph_from_static_analysis(file_hash, file_info)


def _expand_with_api_key(
    file_hash: str,
    depth: int,
    max_children: int,
    initial_info: Optional[Dict] = None
) -> Dict[str, Any]:
    """Expand using authenticated API v3 (requires key)."""
    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []
    visited: set = set()

    def _add_node(nid: str, ntype: str, label: str, meta: Dict | None = None):
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "type": ntype,      # file, ip, domain, url
                "label": label,
                "meta": meta or {},
            }

    def _walk(current_hash: str, current_depth: int):
        if current_depth > depth or current_hash in visited:
            return
        visited.add(current_hash)

        # Add seed node
        report = get_file_report(current_hash) if current_hash != file_hash else initial_info
        if not report:
            report = get_file_report(current_hash)
        
        name = (report or {}).get("meaningful_name", current_hash[:12])
        detection = (report or {}).get("detection_ratio", "?")
        tags = (report or {}).get("tags", [])
        
        _add_node(current_hash, "file", str(name), {
            "detection": detection,
            "tags": tags,
        })

        for rel in _BLAST_RADIUS_RELS:
            # Rate-limit delay: free tier allows 4 req/min
            time.sleep(16)
            result = get_file_relationships(current_hash, rel, limit=max_children)
            if not result:
                continue
            for item in result["items"]:
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
                    "file": "file", "domain": "domain",
                    "ip_address": "ip", "url": "url",
                }.get(child_type, "unknown")

                _add_node(child_id, mapped_type, child_label, {
                    "detection": child_attr.get("last_analysis_stats", {}),
                })

                edges.append({
                    "source": current_hash,
                    "target": child_id,
                    "relationship": rel,
                })

                # Recurse into child files only
                if child_type == "file" and current_depth + 1 <= depth:
                    _walk(child_id, current_depth + 1)

    _walk(file_hash, 1)

    return {
        "seed": file_hash,
        "nodes": list(nodes.values()),
        "edges": edges,
        "depth": depth,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def _build_graph_from_static_analysis(seed: str, vt_info: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Build a blast-radius graph from static analysis cache.
    Uses real indicators (IPs, domains, URLs, imports) extracted from the uploaded file.
    Returns an empty graph with a message if the hash was never analyzed.
    """
    from sandbox_bridge import get_cached_analysis

    analysis = get_cached_analysis(seed)

    nodes: List[Dict] = []
    edges: List[Dict] = []

    # --- Seed node ---
    seed_label = seed[:12] + "..."
    seed_meta: Dict[str, Any] = {}

    if vt_info and vt_info.get("found"):
        seed_meta["detection"] = vt_info.get("detection_ratio", "?")
        seed_meta["tags"] = vt_info.get("tags", []) or vt_info.get("names", [])[:3]
        if vt_info.get("names"):
            seed_label = vt_info["names"][0]

    if analysis:
        seed_label = analysis.get("filename", seed_label)
        seed_meta["entropy"] = analysis.get("entropy", 0)
        seed_meta["is_pe"] = analysis.get("is_pe", False)
        seed_meta["imphash"] = analysis.get("imphash")
        seed_meta["file_size"] = analysis.get("file_size", 0)
        seed_meta["ttps"] = analysis.get("extracted_ttps", [])
        seed_meta["source"] = "static_analysis"

    nodes.append({"id": seed, "type": "file", "label": seed_label, "meta": seed_meta})

    if not analysis:
        # No cached analysis — return single-node graph with instructions
        return {
            "seed": seed,
            "nodes": nodes,
            "edges": [],
            "depth": 0,
            "node_count": 1,
            "edge_count": 0,
            "source": "no_data",
            "message": "Upload this file through Sandbox first, or add a VT_API_KEY for remote expansion.",
        }

    # --- Build real graph from static analysis indicators ---
    extracted_ips = analysis.get("extracted_ips", [])
    extracted_domains = analysis.get("extracted_domains", [])
    extracted_urls = analysis.get("extracted_urls", [])
    ttps = analysis.get("extracted_ttps", [])

    # Add IP nodes
    for ip in extracted_ips[:15]:
        if ip.startswith(("0.", "127.", "255.", "224.")):
            continue
        nid = f"ip_{ip}"
        nodes.append({
            "id": nid, "type": "ip", "label": ip,
            "meta": {"source": "static_extraction"},
        })
        edges.append({"source": seed, "target": nid, "relationship": "contacted_ips"})

    # Add domain nodes
    for domain in extracted_domains[:15]:
        nid = f"dom_{domain}"
        nodes.append({
            "id": nid, "type": "domain", "label": domain,
            "meta": {"source": "static_extraction"},
        })
        edges.append({"source": seed, "target": nid, "relationship": "contacted_domains"})

    # Add URL nodes
    for url in extracted_urls[:10]:
        nid = f"url_{hash(url) & 0xFFFFFFFF:08x}"
        nodes.append({
            "id": nid, "type": "url", "label": url[:60],
            "meta": {"full_url": url, "source": "static_extraction"},
        })
        edges.append({"source": seed, "target": nid, "relationship": "contacted_urls"})

    # Add TTP capability nodes (grouped by kill-chain phase)
    _ttp_phases = {
        "T1055": ("Process Injection", "defense_evasion"),
        "T1003": ("Credential Access", "credential-access"),
        "T1547.001": ("Registry Persistence", "persistence"),
        "T1071.001": ("Web C2 Communication", "c2-implant"),
        "T1059.001": ("PowerShell Execution", "execution"),
        "T1059.003": ("Command Shell", "execution"),
        "T1027": ("Obfuscation/Encryption", "defense_evasion"),
        "T1027.002": ("Software Packing", "defense_evasion"),
        "T1106": ("Native API Usage", "execution"),
        "T1497.001": ("Anti-Debug/Analysis", "defense_evasion"),
        "T1543.003": ("Service Installation", "persistence"),
        "T1056.001": ("Keylogging", "collection"),
        "T1112": ("Registry Modification", "defense_evasion"),
        "T1105": ("File Download", "c2-implant"),
        "T1041": ("Data Exfiltration", "exfiltration"),
    }
    for ttp in ttps:
        info = _ttp_phases.get(ttp)
        if info:
            label, stage = info
            nid = f"ttp_{ttp}"
            nodes.append({
                "id": nid, "type": "file", "label": f"[{ttp}] {label}",
                "stage": stage, "meta": {"ttp": ttp, "source": "static_analysis"},
            })
            edges.append({"source": seed, "target": nid, "relationship": "has_capability"})

    # Link domains to IPs where both exist (heuristic: shared via same binary)
    ip_ids = [f"ip_{ip}" for ip in extracted_ips[:15] if not ip.startswith(("0.", "127.", "255.", "224."))]
    dom_ids = [f"dom_{d}" for d in extracted_domains[:15]]
    # Connect first domain to first IP as a plausible resolution
    if ip_ids and dom_ids:
        edges.append({"source": dom_ids[0], "target": ip_ids[0], "relationship": "resolves_to"})

    return {
        "seed": seed,
        "nodes": nodes,
        "edges": edges,
        "depth": 1,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "source": "static_analysis",
    }
