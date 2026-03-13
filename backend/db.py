"""
PRISM Backend — Supabase Database Client
Provides a singleton Supabase client and helper functions.
"""

from supabase import create_client, Client  # type: ignore
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY

_client: Client | None = None


def get_client() -> Client:
    """Get or create the Supabase client (service role for backend)."""
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env"
            )
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


def upload_sample(file_bytes: bytes, destination_path: str) -> str:
    """Upload a file to the 'samples' bucket and return the path."""
    client = get_client()
    client.storage.from_("samples").upload(
        path=destination_path,
        file=file_bytes,
        file_options={"upsert": "true"}
    )
    return destination_path


# ---------------------------------------------------------------------------
# APT Profiles
# ---------------------------------------------------------------------------

def get_all_profiles() -> list[dict]:
    """Fetch all APT group profiles from Supabase."""
    client = get_client()
    result = client.table("apt_groups").select("*").execute()
    return result.data or []


def get_profile_by_name(name: str) -> dict | None:
    """Fetch a single APT group profile by name."""
    client = get_client()
    result = client.table("apt_groups").select("*").eq("name", name).execute()
    return result.data[0] if result.data else None


def get_profiles_as_engine_format() -> dict:
    """Fetch profiles in the format engine.py expects: {'apt_groups': [...]}."""
    profiles = get_all_profiles()
    return {"apt_groups": profiles}


def update_profile_ttps(profile_name: str, ttps: dict) -> dict | None:
    """Update the TTPs for a specific APT group."""
    client = get_client()
    result = (
        client.table("apt_groups")
        .update({"ttps": ttps, "updated_at": "now()"})
        .eq("name", profile_name)
        .execute()
    )
    return result.data[0] if result.data else None


# ---------------------------------------------------------------------------
# Malware Families
# ---------------------------------------------------------------------------

def get_all_families() -> list[dict]:
    """Fetch all malware families from Supabase."""
    client = get_client()
    result = client.table("malware_families").select("*").execute()
    return result.data or []


def get_families_as_engine_format() -> dict:
    """Fetch families in the format engine.py expects: {'families': [...]}."""
    families = get_all_families()
    return {"families": families}


# ---------------------------------------------------------------------------
# Analyses
# ---------------------------------------------------------------------------

def insert_analysis(analysis: dict) -> dict:
    """Insert a new analysis result."""
    client = get_client()
    result = client.table("analyses").insert(analysis).execute()
    return result.data[0] if result.data else {}


def get_analysis(analysis_id: str) -> dict | None:
    """Fetch a single analysis by ID."""
    client = get_client()
    result = client.table("analyses").select("*").eq("id", analysis_id).execute()
    return result.data[0] if result.data else None


def get_analyses_history(limit: int = 50, offset: int = 0) -> list[dict]:
    """Fetch analysis history, most recent first."""
    client = get_client()
    result = (
        client.table("analyses")
        .select("id, analysis_type, input_mode, input_summary, top_group, top_confidence, confidence_tier, gate_passed, model_version, analyst_feedback, created_at")
        .order("created_at", desc=True)
        .range(offset, offset + limit - 1)
        .execute()
    )
    return result.data or []


def update_analysis_feedback(
    analysis_id: str,
    feedback: str,
    corrected_group: str | None = None,
    notes: str | None = None,
) -> dict | None:
    """Update analyst feedback on an analysis."""
    from datetime import datetime, timezone

    client = get_client()
    update_data: dict = {
        "analyst_feedback": feedback,
        "feedback_at": datetime.now(timezone.utc).isoformat(),
    }
    if corrected_group:
        update_data["corrected_group"] = corrected_group
    if notes:
        update_data["feedback_notes"] = notes

    result = (
        client.table("analyses")
        .update(update_data)
        .eq("id", analysis_id)
        .execute()
    )
    return result.data[0] if result.data else None


# ---------------------------------------------------------------------------
# Emerging Clusters
# ---------------------------------------------------------------------------

def upsert_cluster(cluster: dict) -> dict:
    """Upsert an emerging cluster."""
    client = get_client()
    result = (
        client.table("emerging_clusters")
        .upsert(cluster, on_conflict="cluster_id")
        .execute()
    )
    return result.data[0] if result.data else {}


def get_all_clusters() -> list[dict]:
    """Fetch all emerging clusters."""
    client = get_client()
    result = (
        client.table("emerging_clusters")
        .select("*")
        .order("last_seen", desc=True)
        .execute()
    )
    return result.data or []


# ---------------------------------------------------------------------------
# Intel Queue
# ---------------------------------------------------------------------------

def get_intel_queue(
    limit: int = 50,
    offset: int = 0,
    processed: bool | None = None,
) -> list[dict]:
    """Fetch intel queue items with optional filter."""
    client = get_client()
    query = client.table("intel_queue").select("*")
    if processed is not None:
        query = query.eq("processed", processed)
    result = query.order("ingested_at", desc=True).range(offset, offset + limit - 1).execute()
    return result.data or []


def upsert_intel(item: dict) -> dict:
    """Upsert an intel item into the queue."""
    client = get_client()
    result = client.table("intel_queue").upsert(item, on_conflict="id").execute()
    return result.data[0] if result.data else {}


def get_intel_item(intel_id: str) -> dict | None:
    """Fetch a single intel item by ID."""
    client = get_client()
    result = client.table("intel_queue").select("*").eq("id", intel_id).execute()
    return result.data[0] if result.data else None


def mark_intel_processed(intel_id: str) -> dict | None:
    """Mark an intel item as processed."""
    client = get_client()
    result = (
        client.table("intel_queue")
        .update({"processed": True})
        .eq("id", intel_id)
        .execute()
    )
    return result.data[0] if result.data else None


def get_intel_stats() -> dict:
    """Get intel pipeline statistics."""
    client = get_client()
    all_items = client.table("intel_queue").select("id, processed, source_tier").execute()
    items = all_items.data or []

    total = len(items)
    processed = sum(1 for i in items if i.get("processed"))
    pending = total - processed

    tier_counts: dict[str, int] = {}
    for item in items:
        tier = item.get("source_tier", "unknown")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    return {
        "total": total,
        "processed": processed,
        "pending": pending,
        "by_source_tier": tier_counts,
    }


# ---------------------------------------------------------------------------
# Training Samples
# ---------------------------------------------------------------------------

def insert_training_sample(sample: dict) -> dict:
    """Insert a new training sample for continuous learning."""
    client = get_client()
    result = client.table("training_samples").insert(sample).execute()
    return result.data[0] if result.data else {}


def get_training_samples(
    source: str | None = None,
    label: str | None = None,
    limit: int = 10000,
) -> list[dict]:
    """Fetch training samples with optional filters."""
    client = get_client()
    query = client.table("training_samples").select("*")
    if source:
        query = query.eq("source", source)
    if label:
        query = query.eq("label", label)
    result = query.order("sample_date", desc=True).limit(limit).execute()
    return result.data or []


def get_drift_monitor() -> list[dict]:
    """Fetch weekly drift monitoring statistics."""
    client = get_client()
    result = client.table("drift_monitor").select("*").order("week", desc=True).limit(12).execute()
    return result.data or []


def get_training_stats() -> list[dict]:
    """Fetch breakdown of training data sources and counts."""
    client = get_client()
    result = client.table("training_stats").select("*").execute()
    return result.data or []


# ---------------------------------------------------------------------------
# ML Models
# ---------------------------------------------------------------------------

def get_active_model() -> dict | None:
    """Fetch the currently active ML model metadata."""
    client = get_client()
    result = (
        client.table("ml_models")
        .select("*")
        .eq("status", "active")
        .order("deployed_at", desc=True)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def register_model(model_info: dict) -> dict:
    """Register a new ML model version."""
    client = get_client()
    result = client.table("ml_models").insert(model_info).execute()
    return result.data[0] if result.data else {}
