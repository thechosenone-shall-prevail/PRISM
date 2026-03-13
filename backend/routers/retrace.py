"""
PRISM API — Malware Retracing Endpoint
POST /api/retrace — malware file/hash attribution with sandbox integration
"""

import asyncio
import sys
import concurrent.futures
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from engine import run_malware_retracing  # type: ignore
import engine
import sandbox_bridge

import db
import ml_engine
import intel_pipeline

router = APIRouter()


def _run_retrace_sync(
    file_bytes: Optional[bytes],
    filename: str,
    input_hash: str,
    enable_sandbox: bool,
    enable_vt_lookup: bool,
    enable_threat_intel: bool,
) -> dict:
    """All heavy/blocking retrace work runs here, off the event loop."""
    import time as _time
    _t0 = _time.perf_counter()
    def _elapsed():
        return f"{_time.perf_counter() - _t0:.1f}s"

    file_size_mb = len(file_bytes) / (1024 * 1024) if file_bytes else 0
    print(f"[retrace] START {filename} ({file_size_mb:.1f} MB)")

    # Fetch malware families
    try:
        family_db = db.get_families_as_engine_format()
    except Exception:
        from engine import load_malware_family_db  # type: ignore
        family_db = load_malware_family_db()

    print(f"[retrace] {_elapsed()} running malware retracing...")
    extraction = run_malware_retracing(
        file_bytes=file_bytes,
        filename=filename,
        hash_value=input_hash,
        family_db=family_db,
        top_k=5,
    )
    print(f"[retrace] {_elapsed()} malware retracing done")

    static_features = extraction.get("extracted_static", {})

    # VT enrichment (with timeout)
    if enable_vt_lookup:
        try:
            lookup_hash = input_hash
            if not lookup_hash and static_features.get("hashes"):
                lookup_hash = static_features["hashes"].get("sha256", "")
            if lookup_hash:
                from vt_client import query_virustotal  # type: ignore
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(query_virustotal, lookup_hash)
                    vt_data = future.result(timeout=12)
                if vt_data:
                    extraction["virustotal"] = {
                        "detection_ratio": vt_data.get("detection_ratio", "0/0"),
                        "scan_date": vt_data.get("scan_date", ""),
                        "permalink": vt_data.get("permalink", ""),
                        "tags": vt_data.get("tags", []),
                        "names": vt_data.get("names", []),
                    }
                    if vt_data.get("tags"):
                        extraction["vt_tags"] = vt_data["tags"]
        except concurrent.futures.TimeoutError:
            print("VirusTotal lookup timed out (12s)")
            extraction["virustotal"] = {"status": "timed_out"}
        except Exception as e:
            print(f"VirusTotal lookup failed: {e}")
            extraction["virustotal"] = {"status": "unavailable"}

    # Sandbox — reuse static_features to avoid re-parsing the whole file
    sandbox_report = None
    if enable_sandbox and file_bytes:
        print(f"[retrace] {_elapsed()} running sandbox (static analysis reuse)...")
        sandbox_report = sandbox_bridge.simulate_sandbox_execution_with_static(
            file_bytes, filename, static_features
        )
        extraction["sandbox_report"] = sandbox_report
        extraction["sandbox_executed"] = True
        print(f"[retrace] {_elapsed()} sandbox done")

    # TTPs
    print(f"[retrace] {_elapsed()} extracting TTPs...")
    static_ttps = sandbox_bridge.extract_ttps_from_static_analysis(static_features)
    sandbox_ttps = []
    if sandbox_report:
        sandbox_ttps = sandbox_bridge.extract_ttps_from_sandbox_report(sandbox_report)
    all_ttps = sorted(list(set(static_ttps + sandbox_ttps)))
    extraction["extracted_ttps"] = all_ttps
    extraction["ttp_count"] = len(all_ttps)
    print(f"[retrace] {_elapsed()} TTPs done: {len(all_ttps)} techniques")

    # Family match
    top_family = None
    if extraction.get("ranked_matches") and len(extraction["ranked_matches"]) > 0:
        top_family = extraction["ranked_matches"][0].get("family")

    # APT hint
    apt_hint = None
    if top_family:
        apt_hint = sandbox_bridge.map_malware_family_to_apt(top_family)
        if apt_hint:
            extraction["apt_hint_from_family"] = apt_hint

    # Threat intel correlation
    print(f"[retrace] {_elapsed()} running threat intel...")
    threat_intel_signals = []
    if enable_threat_intel:
        try:
            intel_matches = intel_pipeline.correlate_with_campaigns(
                ttps=all_ttps,
                malware_family=top_family,
                iocs={
                    "hashes": [static_features.get("hashes", {}).get("sha256", "")],
                    "imphash": static_features.get("hashes", {}).get("imphash", ""),
                },
            )
            if intel_matches:
                extraction["threat_intel_matches"] = intel_matches
                threat_intel_signals = [m.get("campaign_name", "") for m in intel_matches[:3]]
        except Exception as e:
            print(f"Threat intel correlation failed: {e}")

    # ML attribution
    print(f"[retrace] {_elapsed()} running ML attribution...")
    attribution_payload = sandbox_bridge.create_attribution_payload_from_malware(
        static_features=static_features,
        sandbox_report=sandbox_report,
        malware_family=top_family,
    )
    if threat_intel_signals:
        attribution_payload.setdefault("context_signals", []).extend(
            [f"campaign:{sig}" for sig in threat_intel_signals]
        )
    ml_result = ml_engine.predict(attribution_payload)
    print(f"[retrace] {_elapsed()} ML done: {ml_result.get('top_group')} @ {ml_result.get('confidence_pct', 0)}%")

    # Merge results
    extraction["apt_attribution"] = {
        "top_group": ml_result.get("top_group"),
        "confidence_pct": ml_result.get("confidence_pct", 0),
        "confidence_tier": ml_result.get("confidence_tier", "LOW"),
        "predictions": ml_result.get("predictions", [])[:8],
        "ml_model_version": ml_result.get("model_version"),
        "technique_count": len(all_ttps),
        "family_hint": apt_hint,
        "sparse_mode": ml_result.get("sparse_mode", False),
        "reasoning": ml_result.get("reasoning", ""),
        "signal_count": ml_result.get("signal_count", 0),
    }

    ml_conf = ml_result.get("confidence_pct", 0)
    if ml_conf >= 70:
        extraction["verdict"] = "HIGH"
    elif ml_conf >= 45:
        extraction["verdict"] = "MODERATE"
    else:
        extraction["verdict"] = "LOW"

    extraction["top_match"] = {
        "apt_group": ml_result.get("top_group"),
        "malware_family": top_family,
        "confidence_pct": ml_conf,
        "matched_ttps": all_ttps[:10],
        "static_indicators": len(static_features.get("imports", [])),
        "runtime_behaviors": len(sandbox_report.get("processes", [])) if sandbox_report else 0,
    }

    extraction["attribution_reasoning"] = {
        "primary_indicators": {
            "malware_family": top_family,
            "apt_mapping": apt_hint,
            "ttp_count": len(all_ttps),
            "static_features": len(static_features.get("imports", [])),
            "runtime_behaviors": len(sandbox_report.get("processes", [])) if sandbox_report else 0,
        },
        "supporting_evidence": {
            "matched_ttps": all_ttps[:5],
            "threat_intel_campaigns": threat_intel_signals,
            "vt_detection": extraction.get("virustotal", {}).get("detection_ratio", "N/A"),
            "family_similarity": extraction.get("ranked_matches", [{}])[0].get("similarity", 0) if extraction.get("ranked_matches") else 0,
        },
        "confidence_factors": {
            "ml_confidence": ml_conf,
            "family_match_score": extraction.get("ranked_matches", [{}])[0].get("similarity", 0) if extraction.get("ranked_matches") else 0,
            "ttp_coverage": len(all_ttps),
            "intel_correlation": len(threat_intel_signals),
        },
    }

    # Supabase upload (best-effort, timeout) — skip for large files
    storage_path = None
    if file_bytes:
        sha256 = extraction["extracted_static"]["hashes"]["sha256"]
        storage_path = f"{sha256}/{filename}"
        if file_size_mb > 10:
            print(f"[retrace] {_elapsed()} skipping Supabase upload ({file_size_mb:.0f} MB > 10 MB limit)")
        else:
            try:
                print(f"[retrace] {_elapsed()} uploading to Supabase...")
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(db.upload_sample, file_bytes, storage_path)
                    future.result(timeout=10)
                extraction["storage_path"] = storage_path
            except concurrent.futures.TimeoutError:
                print(f"Warning: Supabase upload timed out for {filename}")
            except Exception as e:
                print(f"Warning: Failed to upload sample to storage: {e}")

    # Persist analysis (best-effort, timeout)
    apt_result = extraction.get("apt_attribution", {})
    analysis_record = {
        "analysis_type": "malware_retracing",
        "input_mode": "file" if file_bytes else "hash",
        "input_summary": f"{filename or input_hash[:32]}",
        "top_group": apt_result.get("top_group"),
        "top_confidence": apt_result.get("confidence_pct", 0) / 100.0,
        "confidence_tier": extraction.get("verdict", "LOW"),
        "gate_passed": extraction.get("verdict") in ("HIGH", "MODERATE"),
        "artifact_path": storage_path,
        "observed_techniques": all_ttps,
        "full_result": extraction,
        "model_version": apt_result.get("ml_model_version"),
    }
    try:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(db.insert_analysis, analysis_record)
            stored = future.result(timeout=10)
        extraction["analysis_id"] = stored.get("id", "unknown")
    except concurrent.futures.TimeoutError:
        print("Warning: Supabase insert_analysis timed out")
        extraction["analysis_id"] = "not_persisted"
    except Exception:
        extraction["analysis_id"] = "not_persisted"

    print(f"[retrace] {_elapsed()} DONE — {filename}")
    return extraction


@router.post("/retrace")
async def retrace(
    hash_value: str = Form(""),
    file: Optional[UploadFile] = File(None),
    enable_sandbox: bool = Form(True),
    enable_vt_lookup: bool = Form(True),
    enable_threat_intel: bool = Form(True),
):
    """
    Run malware retracing analysis with full APT attribution pipeline.
    Heavy work runs in a thread to avoid blocking the event loop.
    """
    file_bytes = None
    filename = ""
    input_hash = hash_value.strip()

    if file:
        file_bytes = await file.read()
        filename = file.filename or "sample.bin"
        if len(file_bytes) == 0:
            raise HTTPException(status_code=422, detail="Uploaded file is empty")

    if not file_bytes and not input_hash:
        raise HTTPException(
            status_code=422,
            detail="Provide either a malware file or a hash value (MD5/SHA1/SHA256)",
        )

    try:
        result = await asyncio.to_thread(
            _run_retrace_sync,
            file_bytes, filename, input_hash,
            enable_sandbox, enable_vt_lookup, enable_threat_intel,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return result
