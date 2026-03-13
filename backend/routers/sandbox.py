"""
Sandbox Timeline API Router
Provides malware behavior timeline visualization via real static analysis.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from sandbox_bridge import analyze_uploaded_file, generate_timeline_events

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


@router.post("/analyze")
async def analyze_sample(
    file: Optional[UploadFile] = File(None),
):
    """
    Analyze a malware sample via real static analysis.

    Accepts a file upload (multipart/form-data).
    Returns full static-analysis results: hashes, entropy, imports, TTPs,
    embedded IOCs, and a timeline generated from real file content.
    """

    if not file:
        raise HTTPException(
            status_code=400,
            detail="File upload required. Upload a PE binary or suspicious file for real static analysis.",
        )

    file_bytes = await file.read()
    filename = file.filename or "unknown"

    # Run REAL static analysis
    report = analyze_uploaded_file(file_bytes, filename)

    # Calculate event-type stats
    stats = {"process": 0, "registry": 0, "file": 0, "network": 0, "defense_evasion": 0}
    for event in report.get("timeline", []):
        etype = event.get("type", "unknown")
        if etype in stats:
            stats[etype] += 1

    return {
        # Core identification
        "filename": report["filename"],
        "hash": report["file_hash"],
        "hashes": report["hashes"],
        "file_size": report["file_size"],
        "analysis_type": report["analysis_type"],  # "static"
        # PE metadata
        "is_pe": report["is_pe"],
        "imphash": report.get("imphash"),
        "entropy": report.get("entropy", 0),
        "compile_timestamp": report.get("compile_timestamp"),
        "section_names": report.get("section_names", []),
        # Extracted indicators
        "extracted_ttps": report.get("extracted_ttps", []),
        "extracted_urls": report.get("extracted_urls", []),
        "extracted_domains": report.get("extracted_domains", []),
        "extracted_ips": report.get("extracted_ips", []),
        "imports": report.get("imports", []),
        # Behavioural indicators from strings
        "processes": report.get("processes", []),
        "registry": report.get("registry", []),
        "files": report.get("files", []),
        "network": report.get("network", []),
        # Timeline + stats
        "timeline": report.get("timeline", []),
        "stats": stats,
    }
