"""
PRISM — Real-World Dataset Acquisition Utility
Helps download and label genuine malware samples for Phase 5 training.

Note: This script requires a MalwareBazaar API key for downloads.
For labeling only (using existing hashes), use:
    python ml/fetch_aptracker_data.py --label-only
"""

import os
import json
import csv
import requests
from pathlib import Path

# Mapping MalwareBazaar tags to internal group names
TAG_TO_GROUP = {
    "lazarus": "Lazarus Group",
    "apt28": "APT28",
    "fancy bear": "APT28",
    "apt29": "APT29",
    "cozy bear": "APT29",
    "sandworm": "Sandworm",
    "apt41": "APT41",
    "double dragon": "APT41",
    "volt typhoon": "Volt Typhoon",
    "kimsuky": "Kimsuky",
    "muddywater": "MuddyWater",
    "oilrig": "OilRig",
    "turla": "Turla",
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_CSV = PROJECT_ROOT / "ml" / "data" / "real_apt_data.csv"

def fetch_malwarebazaar_hashes(tag: str, limit: int = 100):
    """Fetch hashes from MalwareBazaar for a specific tag."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        'query': 'get_taginfo',
        'tag': tag,
        'limit': limit
    }
    try:
        response = requests.post(url, data=data, timeout=15)
        if response.status_code == 200:
            res_json = response.json()
            if res_json.get('query_status') == 'ok':
                return res_json.get('data', [])
    except Exception as e:
        print(f"Error fetching {tag}: {e}")
    return []

def main():
    print("PRISM Real-World Data Acquisition")
    print("-" * 40)
    
    all_real_samples = []
    
    for tag, group_name in TAG_TO_GROUP.items():
        print(f"Fetching hashes for {group_name} (tag: {tag})...")
        samples = fetch_malwarebazaar_hashes(tag)
        print(f"  Found {len(samples)} samples.")
        
        for s in samples:
            all_real_samples.append({
                "sha256": s.get("sha256_hash"),
                "file_name": s.get("file_name"),
                "label": group_name,
                "source": "MalwareBazaar",
                "tag": tag
            })

    if not all_real_samples:
        print("No samples found. Check your connection or tags.")
        return

    # Save to CSV for labeling phase
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sha256", "file_name", "label", "source", "tag"])
        writer.writeheader()
        writer.writerows(all_real_samples)
    
    print(f"\n✓ Saved {len(all_real_samples)} raw labels to {OUTPUT_CSV}")
    print("\nNEXT STEPS:")
    print("1. Use a malware downloader (e.g., via VirusTotal or MalwareBazaar API) to get these files.")
    print("2. Run them through engine.extract_static_indicators to build the full feature vector.")
    print("3. Appending to existing training_data.csv for a hybrid training session.")

if __name__ == "__main__":
    main()
