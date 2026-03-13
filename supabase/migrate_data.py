"""
APTrace — Data Migration Script
Migrates existing JSON data files into Supabase PostgreSQL.

Usage:
    cd c:\Projects\hack2
    pip install supabase python-dotenv
    python supabase/migrate_data.py
"""

import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / "backend" / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("ERROR: Set SUPABASE_URL and SUPABASE_SERVICE_KEY in backend/.env")
    sys.exit(1)

from supabase import create_client, Client  # type: ignore

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def _read_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def migrate_apt_groups():
    """Migrate apt_profiles.json → apt_groups table."""
    path = PROJECT_ROOT / "apt_profiles.json"
    data = _read_json(path)
    groups = data.get("apt_groups", [])

    print(f"\n[apt_groups] Migrating {len(groups)} APT groups...")

    for g in groups:
        row = {
            "id": g["id"],
            "name": g["name"],
            "aliases": g.get("aliases", []),
            "nation": g["nation"],
            "nation_code": g.get("nation_code"),
            "flag": g.get("flag"),
            "motivation": g.get("motivation", []),
            "target_sectors": g.get("target_sectors", []),
            "target_regions": g.get("target_regions", []),
            "active_since": g.get("active_since"),
            "last_seen": g.get("last_seen"),
            "description": g.get("description", ""),
            "known_campaigns": g.get("known_campaigns", []),
            "known_tools": g.get("known_tools", []),
            "ttps": g.get("ttps", {}),
            "behavioral_dna": g.get("behavioral_dna", {}),
            "operational_hours": g.get("operational_hours", {}),
        }
        try:
            supabase.table("apt_groups").upsert(row, on_conflict="id").execute()
            print(f"  ✓ {g['name']}")
        except Exception as e:
            print(f"  ✗ {g['name']}: {e}")

    # Verify
    result = supabase.table("apt_groups").select("id", count="exact").execute()
    print(f"  → Verified: {result.count} rows in apt_groups")


def migrate_malware_families():
    """Migrate malware_family_db.json → malware_families table."""
    path = PROJECT_ROOT / "malware_family_db.json"
    data = _read_json(path)
    families = data.get("families", [])

    print(f"\n[malware_families] Migrating {len(families)} families...")

    for f in families:
        row = {
            "family": f["family"],
            "cluster": f["cluster"],
            "summary": f.get("summary", ""),
            "geo_context": f.get("geo_context", ""),
            "known_hashes": f.get("known_hashes", []),
            "known_hash_prefixes": f.get("known_hash_prefixes", []),
            "known_imphashes": f.get("known_imphashes", []),
            "file_types": f.get("file_types", []),
            "import_keywords": f.get("import_keywords", []),
            "string_keywords": f.get("string_keywords", []),
            "behavior_keywords": f.get("behavior_keywords", []),
        }
        try:
            supabase.table("malware_families").upsert(
                row, on_conflict="family"
            ).execute()
            print(f"  ✓ {f['family']}")
        except Exception as e:
            print(f"  ✗ {f['family']}: {e}")

    result = supabase.table("malware_families").select("id", count="exact").execute()
    print(f"  → Verified: {result.count} rows in malware_families")


def migrate_emerging_clusters():
    """Migrate emerging_clusters.json → emerging_clusters table."""
    path = PROJECT_ROOT / "emerging_clusters.json"
    if not path.exists():
        print("\n[emerging_clusters] No file found, skipping.")
        return

    data = _read_json(path)
    clusters = data.get("clusters", [])

    print(f"\n[emerging_clusters] Migrating {len(clusters)} clusters...")

    for c in clusters:
        row = {
            "cluster_id": c["cluster_id"],
            "status": c.get("status", "EMERGING"),
            "techniques": c.get("techniques", []),
            "context_signals": c.get("context_signals", []),
            "matched_keywords": c.get("matched_keywords", []),
            "latest_hypotheses": c.get("latest_hypotheses", []),
            "sightings": c.get("sightings", 1),
            "first_seen": c.get("first_seen"),
            "last_seen": c.get("last_seen"),
        }
        try:
            supabase.table("emerging_clusters").upsert(
                row, on_conflict="cluster_id"
            ).execute()
            print(f"  ✓ {c['cluster_id']}")
        except Exception as e:
            print(f"  ✗ {c['cluster_id']}: {e}")

    result = supabase.table("emerging_clusters").select("cluster_id", count="exact").execute()
    print(f"  → Verified: {result.count} rows in emerging_clusters")


def migrate_intel_queue():
    """Migrate intel/raw_queue.jsonl → intel_queue table."""
    path = PROJECT_ROOT / "intel" / "raw_queue.jsonl"
    if not path.exists():
        print("\n[intel_queue] No queue file found, skipping.")
        return

    items = _read_jsonl(path)
    print(f"\n[intel_queue] Migrating {len(items)} intel items...")

    batch_size = 50
    migrated = 0
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        rows = []
        for item in batch:
            rows.append({
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "source_name": item.get("source_name", ""),
                "source_tier": item.get("source_tier", "unknown"),
                "published_at": item.get("published_at"),
                "url": item.get("url", ""),
                "groups": item.get("groups", []),
                "summary": item.get("summary", ""),
                "content": item.get("content", ""),
                "ingested_at": item.get("ingested_at"),
            })
        try:
            supabase.table("intel_queue").upsert(
                rows, on_conflict="id"
            ).execute()
            migrated += len(rows)
            print(f"  ✓ Batch {i // batch_size + 1}: {len(rows)} items")
        except Exception as e:
            print(f"  ✗ Batch {i // batch_size + 1}: {e}")

    result = supabase.table("intel_queue").select("id", count="exact").execute()
    print(f"  → Verified: {result.count} rows in intel_queue")


def main():
    print("=" * 60)
    print("APTrace — Data Migration to Supabase")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Supabase URL: {SUPABASE_URL}")
    print()

    migrate_apt_groups()
    migrate_malware_families()
    migrate_emerging_clusters()
    migrate_intel_queue()

    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
