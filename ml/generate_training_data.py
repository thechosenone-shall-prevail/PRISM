"""
APTrace — Synthetic Training Data Generator
Generates labeled training samples from APT profiles for ML model training.

Usage:
    python ml/generate_training_data.py
    
Output:
    ml/data/training_data.csv
    ml/data/feature_schema.json
"""

import csv
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

OUTPUT_DIR = Path(__file__).resolve().parent / "data"
PROFILES_PATH = PROJECT_ROOT / "apt_profiles.json"

# How many synthetic samples per APT group
SAMPLES_PER_GROUP = 500
# Additional "unknown" / noise samples
UNKNOWN_SAMPLES = 0


def load_profiles() -> dict:
    import db
    return db.get_profiles_as_engine_format()


def get_all_techniques(profiles: dict) -> list[str]:
    """Collect all unique techniques across all APT groups."""
    techs = set()
    for group in profiles["apt_groups"]:
        for tactic, tech_list in group.get("ttps", {}).items():
            for t in tech_list:
                techs.add(t)
    return sorted(techs)


# -- Context signals used in the engine
CONTEXT_SIGNALS = [
    "cryptocurrency", "financial", "nuclear", "dissident", "human rights",
    "journalist", "israel", "ukraine", "india", "south korea", "nato",
    "election", "middle east", "supply chain", "critical infrastructure",
    "lotl", "living off the land", "soho router", "rmm tool", "wiper",
    "telecom", "taiwan", "pacific", "southeast asia", "government",
    "military", "defense", "healthcare", "energy", "academic",
    "university", "ngo", "oil and gas", "think tank", "policy research",
]

# Context signals that strongly associate with specific groups
GROUP_CONTEXT_MAP: dict[str, list[str]] = {
    "Lazarus Group": ["cryptocurrency", "financial", "south korea", "southeast asia"],
    "APT28": ["nato", "election", "ukraine", "government", "military", "defense"],
    "APT29": ["supply chain", "government", "think tank", "ngo", "healthcare"],
    "Sandworm": ["ukraine", "energy", "critical infrastructure", "wiper"],
    "APT41": ["supply chain", "southeast asia", "taiwan", "healthcare"],
    "Volt Typhoon": ["critical infrastructure", "lotl", "living off the land", "soho router", "pacific", "taiwan"],
    "Salt Typhoon": ["telecom"],
    "APT35": ["israel", "nuclear", "dissident", "journalist", "middle east", "academic"],
    "MuddyWater": ["middle east", "rmm tool", "telecom", "oil and gas", "government"],
    "OilRig": ["middle east", "oil and gas", "government"],
    "Kimsuky": ["south korea", "think tank", "policy research", "nuclear", "academic"],
    "Transparent Tribe": ["india", "military", "defense", "government"],
    "Turla": ["nato", "government", "defense", "military"],
}


def generate_sample_for_group(
    group: dict,
    all_techniques: list[str],
    sample_idx: int,
) -> dict[str, Any]:
    """
    Generate a single synthetic attack observation for one APT group.
    Simulates realistic partial observations with noise.
    """
    group_name = group["name"]
    
    # Collect all techniques for this group
    group_techs: list[str] = []
    for tactic, techs in group.get("ttps", {}).items():
        group_techs.extend(techs)
    group_tech_set = set(group_techs)
    
    # Sampling rate: observe 30-85% of the group's techniques
    # (simulates partial visibility into an attack)
    sample_rate = random.uniform(0.30, 0.85)
    n_sample = max(3, int(len(group_techs) * sample_rate))
    sampled_techs = set(random.sample(group_techs, min(n_sample, len(group_techs))))
    
    # Add noise: 0-15% false positive techniques from other groups
    all_other = [t for t in all_techniques if t not in group_tech_set]
    noise_rate = random.uniform(0, 0.15)
    n_noise = int(len(sampled_techs) * noise_rate)
    if n_noise > 0 and all_other:
        noise_techs = random.sample(all_other, min(n_noise, len(all_other)))
        sampled_techs.update(noise_techs)
    
    # Context signals: sample from group-associated contexts
    group_contexts = GROUP_CONTEXT_MAP.get(group_name, [])
    n_ctx = random.randint(0, min(4, len(group_contexts)))
    sampled_contexts = set(random.sample(group_contexts, n_ctx)) if group_contexts and n_ctx > 0 else set()
    
    # Occasionally add a random context signal (noise)
    if random.random() < 0.1:
        sampled_contexts.add(random.choice(CONTEXT_SIGNALS))
    
    # Build feature dict
    feature = {}
    
    # TTP binary features
    for tech in all_techniques:
        feature[f"ttp_{tech}"] = 1 if tech in sampled_techs else 0
    
    # Context signal features
    for ctx in CONTEXT_SIGNALS:
        feature[f"ctx_{ctx.replace(' ', '_')}"] = 1 if ctx in sampled_contexts else 0
    
    # Meta features
    feature["technique_count"] = len(sampled_techs)
    feature["context_count"] = len(sampled_contexts)
    
    # Tactic coverage count
    tactic_covered = set()
    for tactic, techs in group.get("ttps", {}).items():
        if sampled_techs & set(techs):
            tactic_covered.add(tactic)
    feature["tactic_coverage"] = len(tactic_covered)
    
    # NEW Structural parameters (synthetic for now)
    feature["overall_entropy"] = random.uniform(4.0, 7.8)
    feature["export_count"] = random.randint(0, 150)
    
    # Label
    feature["label"] = group_name
    
    return feature


def generate_unknown_sample(all_techniques: list[str]) -> dict[str, Any]:
    """Generate a sample that doesn't cleanly map to any APT group (noise/unknown)."""
    # Random selection of 3-12 techniques
    n = random.randint(3, 12)
    sampled = set(random.sample(all_techniques, min(n, len(all_techniques))))
    
    # Random contexts
    n_ctx = random.randint(0, 3)
    sampled_contexts = set(random.sample(CONTEXT_SIGNALS, n_ctx)) if n_ctx > 0 else set()
    
    feature: dict[str, Any] = {}
    for tech in all_techniques:
        feature[f"ttp_{tech}"] = 1 if tech in sampled else 0
    for ctx in CONTEXT_SIGNALS:
        feature[f"ctx_{ctx.replace(' ', '_')}"] = 1 if ctx in sampled_contexts else 0
    
    feature["technique_count"] = len(sampled)
    feature["context_count"] = len(sampled_contexts)
    feature["tactic_coverage"] = random.randint(1, 4)
    feature["overall_entropy"] = random.uniform(3.0, 6.0)
    feature["export_count"] = random.randint(0, 50)
    feature["label"] = "Unknown"
    
    return feature


def main():
    random.seed(42)  # Reproducible
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    profiles = load_profiles()
    all_techniques = get_all_techniques(profiles)
    groups = profiles["apt_groups"]
    
    print(f"APT Groups: {len(groups)}")
    print(f"Unique Techniques: {len(all_techniques)}")
    print(f"Context Signals: {len(CONTEXT_SIGNALS)}")
    print(f"Samples per group: {SAMPLES_PER_GROUP}")
    print(f"Unknown samples: {UNKNOWN_SAMPLES}")
    print()
    
    # Generate samples
    all_samples: list[dict] = []
    
    for group in groups:
        for i in range(SAMPLES_PER_GROUP):
            sample = generate_sample_for_group(group, all_techniques, i)
            all_samples.append(sample)
        print(f"  ✓ {group['name']}: {SAMPLES_PER_GROUP} samples")
    
    for i in range(UNKNOWN_SAMPLES):
        all_samples.append(generate_unknown_sample(all_techniques))
    print(f"  ✓ Unknown: {UNKNOWN_SAMPLES} samples")
    
    # Shuffle
    random.shuffle(all_samples)
    
    # Get feature column names (excluding label)
    feature_names = [k for k in all_samples[0].keys() if k != "label"]
    class_names = sorted(set(s["label"] for s in all_samples))
    
    # Write CSV
    csv_path = OUTPUT_DIR / "training_data.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=feature_names + ["label"])
        writer.writeheader()
        for sample in all_samples:
            writer.writerow(sample)
    
    print(f"\n✓ Training data: {csv_path}")
    print(f"  Rows: {len(all_samples)}")
    print(f"  Features: {len(feature_names)}")
    print(f"  Classes: {len(class_names)}")
    
    # Write feature schema
    schema = {
        "model_version": "v1.0.0",
        "features": feature_names,
        "feature_count": len(feature_names),
        "class_names": class_names,
        "class_count": len(class_names),
        "technique_features": [f for f in feature_names if f.startswith("ttp_")],
        "context_features": [f for f in feature_names if f.startswith("ctx_")],
        "meta_features": ["technique_count", "context_count", "tactic_coverage", "overall_entropy", "export_count"],
        "generation_config": {
            "samples_per_group": SAMPLES_PER_GROUP,
            "unknown_samples": UNKNOWN_SAMPLES,
            "total_samples": len(all_samples),
        },
    }
    
    schema_path = OUTPUT_DIR / "feature_schema.json"
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    
    print(f"✓ Feature schema: {schema_path}")
    
    # Print class distribution
    print("\nClass distribution:")
    from collections import Counter
    dist = Counter(s["label"] for s in all_samples)
    for cls, count in sorted(dist.items()):
        print(f"  {cls}: {count}")


if __name__ == "__main__":
    main()
