"""
VirusTotal API Client Integration
"""
import os
import requests
from typing import Optional, Dict, Any

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def get_file_report(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Query the VirusTotal API v3 for a file hash.
    Returns parsed intel or None if not found/no API key.
    """
    if not VT_API_KEY or not file_hash:
        return None
        
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    url = f"{VT_BASE_URL}/files/{file_hash}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            attr = data.get("attributes", {})
            
            # Extract key intel for the APTrace platform
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
                "threat_names": attr.get("popular_threat_classification", {}).get("popular_threat_category", [])
            }
        elif response.status_code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal."}
    except Exception as e:
        print(f"[VT API Error] {e}")
        
    return None
