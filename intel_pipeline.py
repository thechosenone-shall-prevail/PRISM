"""
PRISM staged intel pipeline (no AI required).

Stages:
1) Ingest raw intel into local queue
2) Extract deterministic candidates (TTP proposals)
3) Prepare review sheet for human approval
4) Apply approved updates to apt_profiles.json with regression guard
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from engine import extract_ttps_from_text, load_profiles, run_attribution

ROOT = Path(__file__).resolve().parent
INTEL_DIR = ROOT / "intel"
BACKUP_DIR = ROOT / "backups"
QUEUE_FILE = INTEL_DIR / "raw_queue.jsonl"
CANDIDATES_FILE = INTEL_DIR / "candidate_updates.json"
REVIEW_FILE = INTEL_DIR / "review_sheet.json"
CHANGELOG_FILE = INTEL_DIR / "change_log.jsonl"
PROFILES_FILE = ROOT / "data" / "apt_profiles.json"
ATTACK_CACHE_FILE = INTEL_DIR / "attack_stix_cache.json"

SOURCE_TIER_WEIGHTS = {
    "official": 1.00,
    "vendor": 0.90,
    "research": 0.80,
    "media": 0.60,
    "community": 0.50,
    "unknown": 0.40,
}

LIVE_FEEDS = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisa_advisories_rss": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().replace(microsecond=0).isoformat()


def _ensure_dirs() -> None:
    INTEL_DIR.mkdir(exist_ok=True)
    BACKUP_DIR.mkdir(exist_ok=True)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _item_id(item: dict[str, Any]) -> str:
    stable = "|".join(
        [
            str(item.get("title", "")),
            str(item.get("source_name", "")),
            str(item.get("published_at", "")),
            str(item.get("url", "")),
            str(item.get("content", "")),
        ]
    )
    return hashlib.sha1(stable.encode("utf-8")).hexdigest()[0:16]


def _http_get_json(url: str, timeout: int = 25, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read().decode("utf-8", errors="ignore")
    return json.loads(payload)


def _http_get_text(url: str, timeout: int = 25, headers: dict[str, str] | None = None) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _normalize_name(value: str) -> str:
    return " ".join((value or "").strip().lower().split())


def _stix_external_attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return None


def _tactic_key_from_phase(phase_name: str) -> str:
    return phase_name.strip().lower().replace("-", "_").replace(" ", "_")


def _load_attack_stix_cached(max_age_hours: int = 24) -> dict[str, Any]:
    if ATTACK_CACHE_FILE.exists():
        cached = _read_json(ATTACK_CACHE_FILE, {})
        fetched_at = _parse_date(cached.get("fetched_at"))
        if fetched_at and (_utc_now() - fetched_at) < timedelta(hours=max_age_hours):
            return cached.get("stix", {})

    stix = _http_get_json(ATTACK_STIX_URL)
    _write_json(
        ATTACK_CACHE_FILE,
        {
            "fetched_at": _iso_now(),
            "source": ATTACK_STIX_URL,
            "stix": stix,
        },
    )
    return stix


def _build_attack_group_alias_map(profiles: dict[str, Any]) -> dict[str, str]:
    alias_map: dict[str, str] = {}
    for g in profiles.get("apt_groups", []):
        canonical = g["name"]
        alias_map[_normalize_name(canonical)] = canonical
        for a in g.get("aliases", []):
            alias_map[_normalize_name(a)] = canonical
    return alias_map


def sync_attack_to_profiles(
    max_age_hours: int = 24,
    force_refresh: bool = False,
    max_changed_hyp: int = 4,
    force: bool = False,
    to_supabase: bool = True,
) -> dict[str, Any]:
    """
    Sync ATT&CK intrusion-set -> technique relationships into apt_profiles.json or Supabase.
    """
    import db
    _ensure_dirs()
    
    if to_supabase:
        profiles = db.get_profiles_as_engine_format()
    else:
        profiles = _read_json(PROFILES_FILE, {})
    if not profiles:
        return {"updated": False, "reason": "profiles_missing"}

    if force_refresh and ATTACK_CACHE_FILE.exists():
        ATTACK_CACHE_FILE.unlink()

    stix = _load_attack_stix_cached(max_age_hours=max_age_hours)
    objects = stix.get("objects", []) if isinstance(stix, dict) else []
    if not objects:
        return {"updated": False, "reason": "stix_empty"}

    intrusion_sets: dict[str, dict[str, Any]] = {}
    attack_patterns: dict[str, dict[str, Any]] = {}
    for obj in objects:
        otype = obj.get("type")
        if otype == "intrusion-set":
            intrusion_sets[obj["id"]] = obj
        elif otype == "attack-pattern":
            attack_patterns[obj["id"]] = obj

    alias_map = _build_attack_group_alias_map(profiles)
    group_to_techniques: dict[str, set[tuple[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref")
        dst = obj.get("target_ref")
        if src not in intrusion_sets or dst not in attack_patterns:
            continue

        grp_obj = intrusion_sets[src]
        technique_obj = attack_patterns[dst]
        t_id = _stix_external_attack_id(technique_obj)
        if not t_id:
            continue
        phases = [
            _tactic_key_from_phase(p.get("phase_name", ""))
            for p in technique_obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        if not phases:
            continue
        tactic = phases[0]

        candidate_names = [grp_obj.get("name", ""), *grp_obj.get("aliases", [])]
        matched_group = None
        for nm in candidate_names:
            key = _normalize_name(str(nm))
            if key in alias_map:
                matched_group = alias_map[key]
                break
        if not matched_group:
            continue

        group_to_techniques.setdefault(matched_group, set()).add((tactic, t_id))

    if not group_to_techniques:
        return {"updated": False, "reason": "no_group_overlap"}

    before_eval = _evaluate_profiles(profiles)
    updated = deepcopy(profiles)
    updated_groups = _index_groups(updated)

    additions: list[dict[str, str]] = []
    for group_name, tuples in group_to_techniques.items():
        if group_name not in updated_groups:
            continue
        group_ref = updated_groups[group_name]
        ttps = group_ref.setdefault("ttps", {})
        for tactic, tech in sorted(tuples):
            ttps.setdefault(tactic, [])
            if tech not in ttps[tactic]:
                ttps[tactic].append(tech)
                ttps[tactic] = sorted(set(ttps[tactic]))
                additions.append({"group": group_name, "tactic": tactic, "technique": tech})

    if not additions:
        return {"updated": False, "reason": "no_new_techniques"}

    after_eval = _evaluate_profiles(updated)
    regression = _regression_delta(before_eval, after_eval)
    if regression["changed_top_hypothesis"] > max_changed_hyp and not force:
        return {
            "updated": False,
            "reason": "regression_guard",
            "regression": regression,
        }

    stamp = _utc_now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"apt_profiles.attack_sync.{stamp}.json"
    _write_json(backup_path, profiles)
    
    if to_supabase:
        # Batch update groups that have additions
        changed_groups = {a["group"] for a in additions}
        for gname in changed_groups:
            g_ref = updated_groups[gname]
            db.update_profile_ttps(gname, g_ref["ttps"])
    else:
        _write_json(PROFILES_FILE, updated)
    _append_jsonl(
        CHANGELOG_FILE,
        [
            {
                "timestamp": _iso_now(),
                "kind": "attack_sync",
                "source": ATTACK_STIX_URL,
                "backup_path": str(backup_path),
                "applied_count": len(additions),
                "applied_sample": additions[:200],
                "regression": regression,
            }
        ],
    )
    return {
        "updated": True,
        "applied_count": len(additions),
        "backup_path": str(backup_path),
        "regression": regression,
    }


def _technique_to_tactic_map(profiles: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for group in profiles.get("apt_groups", []):
        for tactic, techniques in group.get("ttps", {}).items():
            for tech in techniques:
                mapping[tech] = tactic
                if "." in tech:
                    mapping[tech.split(".")[0]] = tactic
    return mapping


def _group_name_set(profiles: dict[str, Any]) -> set[str]:
    return {g["name"] for g in profiles.get("apt_groups", [])}


def _discover_groups_from_text(text: str, profiles: dict[str, Any]) -> list[str]:
    text_l = text.lower()
    found: set[str] = set()
    for group in profiles.get("apt_groups", []):
        names = [group["name"], *group.get("aliases", [])]
        for n in names:
            if n and n.lower() in text_l:
                found.add(group["name"])
                break
    return sorted(found)


def _recency_weight(published_at: str | None) -> float:
    parsed = _parse_date(published_at)
    if not parsed:
        return 0.35
    age_days = (_utc_now() - parsed).days
    return max(0.10, min(1.00, math.exp(-age_days / 120.0)))


def _source_weight(source_tier: str | None) -> float:
    return SOURCE_TIER_WEIGHTS.get((source_tier or "unknown").lower(), SOURCE_TIER_WEIGHTS["unknown"])


def _evidence_weight(features: dict[str, Any]) -> float:
    ttp_score = min(features.get("technique_count", 0) / 12.0, 1.0)
    iocs = features.get("iocs", {})
    ioc_count = len(iocs.get("ips", [])) + len(iocs.get("domains", [])) + len(iocs.get("cve", []))
    ioc_score = min(ioc_count / 8.0, 1.0)
    return (0.70 * ttp_score) + (0.30 * ioc_score)


def _item_confidence(item: dict[str, Any], features: dict[str, Any]) -> float:
    return (
        (0.45 * _source_weight(item.get("source_tier")))
        + (0.30 * _recency_weight(item.get("published_at")))
        + (0.25 * _evidence_weight(features))
    )


def _source_token(source_name: str) -> str:
    return source_name.strip().lower().replace(" ", "_")


def _fetch_cisa_kev(limit: int) -> list[dict[str, Any]]:
    data = _http_get_json(LIVE_FEEDS["cisa_kev"])
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    rows: list[dict[str, Any]] = []
    for vuln in vulns[0:limit]:
        cve = vuln.get("cveID", "")
        title = f"CISA KEV: {cve} {vuln.get('vulnerabilityName', '')}".strip()
        content = "\n".join(
            [
                f"Vendor: {vuln.get('vendorProject', '')}",
                f"Product: {vuln.get('product', '')}",
                f"Vulnerability: {vuln.get('vulnerabilityName', '')}",
                f"Description: {vuln.get('shortDescription', '')}",
                f"Required Action: {vuln.get('requiredAction', '')}",
                f"Known Ransomware: {vuln.get('knownRansomwareCampaignUse', '')}",
            ]
        )
        rows.append(
            {
                "id": f"cisa_kev:{cve}",
                "title": title,
                "source_name": "CISA KEV",
                "source_tier": "official",
                "published_at": vuln.get("dateAdded"),
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "groups": [],
                "summary": vuln.get("shortDescription", ""),
                "content": content,
            }
        )
    return rows


def _fetch_cisa_advisories_rss(limit: int, profiles: dict[str, Any]) -> list[dict[str, Any]]:
    xml_payload = _http_get_text(LIVE_FEEDS["cisa_advisories_rss"])
    root = ET.fromstring(xml_payload)
    rows: list[dict[str, Any]] = []
    for item in root.findall(".//item")[0:limit]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = (item.findtext("description") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        content = f"{title}\n{desc}"
        groups = _discover_groups_from_text(content, profiles)
        uid = hashlib.sha1(f"{title}|{link}|{pub}".encode("utf-8")).hexdigest()[0:16]
        rows.append(
            {
                "id": f"cisa_adv:{uid}",
                "title": title,
                "source_name": "CISA Advisories RSS",
                "source_tier": "official",
                "published_at": pub,
                "url": link,
                "groups": groups,
                "summary": desc,
                "content": content,
            }
        )
    return rows


def _fetch_nvd_recent(days: int, limit: int, profiles: dict[str, Any]) -> list[dict[str, Any]]:
    now = _utc_now()
    start = now - timedelta(days=max(1, days))
    params = {
        "resultsPerPage": str(max(1, min(limit, 2000))),
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    query = urllib.parse.urlencode(params)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
    headers: dict[str, str] = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY", "")
    data = _http_get_json(url, headers=headers)
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    rows: list[dict[str, Any]] = []
    for wrapper in vulns[0:limit]:
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        refs = cve.get("references", [])
        first_ref = refs[0].get("url") if refs else ""
        published = cve.get("published", "")
        content = f"{cve_id}\n{desc}"
        groups = _discover_groups_from_text(content, profiles)
        rows.append(
            {
                "id": f"nvd:{cve_id}",
                "title": f"NVD {cve_id}",
                "source_name": "NVD CVE API",
                "source_tier": "official",
                "published_at": published,
                "url": first_ref or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "groups": groups,
                "summary": desc[:500],
                "content": content,
            }
        )
    return rows


def _ingest_items(incoming: list[dict[str, Any]], source_name: str | None, source_tier: str | None) -> tuple[int, int]:
    _ensure_dirs()
    existing = _load_jsonl(QUEUE_FILE)
    known_ids = {row.get("id") for row in existing}
    new_rows: list[dict[str, Any]] = []

    for row in incoming:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        item.setdefault("source_name", source_name or item.get("source_name", "manual"))
        item.setdefault("source_tier", source_tier or item.get("source_tier", "unknown"))
        item.setdefault("ingested_at", _iso_now())
        item.setdefault("title", "")
        item.setdefault("summary", "")
        item.setdefault("content", "")
        item.setdefault("groups", [])
        item["id"] = item.get("id") or _item_id(item)
        if item["id"] in known_ids:
            continue
        known_ids.add(item["id"])
        new_rows.append(item)

    _append_jsonl(QUEUE_FILE, new_rows)
    return len(new_rows), len(existing) + len(new_rows)


def ingest(input_path: Path, source_name: str | None, source_tier: str | None) -> None:
    if input_path.suffix.lower() == ".jsonl":
        incoming = _load_jsonl(input_path)
    else:
        data = _read_json(input_path, [])
        incoming = data if isinstance(data, list) else [data]
    added, total = _ingest_items(incoming, source_name, source_tier)
    print(f"Ingested {added} new intel item(s). Queue size: {total}")


def build_candidates(min_item_conf: float = 0.45) -> None:
    _ensure_dirs()
    profiles = load_profiles()
    known_groups = _group_name_set(profiles)
    tactic_map = _technique_to_tactic_map(profiles)
    queue = _load_jsonl(QUEUE_FILE)

    aggregate: dict[str, dict[str, Any]] = {}
    skipped = 0
    for item in queue:
        text = "\n".join(
            [
                str(item.get("title", "")),
                str(item.get("summary", "")),
                str(item.get("content", "")),
            ]
        ).strip()
        if not text:
            skipped += 1
            continue

        features = extract_ttps_from_text(text)
        item_conf = _item_confidence(item, features)
        if item_conf < min_item_conf:
            skipped += 1
            continue

        explicit_groups = [g for g in item.get("groups", []) if g in known_groups]
        inferred_groups = _discover_groups_from_text(text, profiles)
        groups = sorted(set(explicit_groups + inferred_groups))
        if not groups:
            skipped += 1
            continue

        for group in groups:
            for tech in features.get("techniques", []):
                tactic = tactic_map.get(tech) or tactic_map.get(tech.split(".")[0]) if "." in tech else tactic_map.get(tech)
                if not tactic:
                    continue
                key = f"{group}|{tactic}|{tech}"
                rec = aggregate.setdefault(
                    key,
                    {
                        "group": group,
                        "tactic": tactic,
                        "technique": tech,
                        "candidate_id": hashlib.sha1(key.encode("utf-8")).hexdigest()[0:16],
                        "support_count": 0,
                        "source_names": set(),
                        "item_ids": set(),
                        "evidence_scores": [],
                        "examples": [],
                    },
                )
                rec["support_count"] += 1
                rec["source_names"].add(item.get("source_name", "unknown"))
                rec["item_ids"].add(item.get("id"))
                rec["evidence_scores"].append(round(item_conf, 4))
                if len(rec["examples"]) < 3:
                    rec["examples"].append(
                        {
                            "title": item.get("title", ""),
                            "url": item.get("url", ""),
                            "published_at": item.get("published_at"),
                        }
                    )

    proposals: list[dict[str, Any]] = []
    for rec in aggregate.values():
        avg_score = sum(rec["evidence_scores"]) / len(rec["evidence_scores"])
        proposals.append(
            {
                "candidate_id": rec["candidate_id"],
                "group": rec["group"],
                "tactic": rec["tactic"],
                "technique": rec["technique"],
                "support_count": rec["support_count"],
                "source_count": len(rec["source_names"]),
                "evidence_score": round(avg_score, 4),
                "item_ids": sorted(rec["item_ids"]),
                "sources": sorted(rec["source_names"]),
                "examples": rec["examples"],
            }
        )

    proposals.sort(key=lambda x: (x["support_count"], x["source_count"], x["evidence_score"]), reverse=True)
    output = {
        "generated_at": _iso_now(),
        "queue_items": len(queue),
        "skipped_items": skipped,
        "min_item_confidence": min_item_conf,
        "proposal_count": len(proposals),
        "proposals": proposals,
    }
    _write_json(CANDIDATES_FILE, output)
    print(f"Generated {len(proposals)} candidate update(s).")


def prepare_review() -> None:
    _ensure_dirs()
    candidates = _read_json(CANDIDATES_FILE, {})
    proposals = candidates.get("proposals", [])
    existing = _read_json(REVIEW_FILE, {"review_items": []})
    prior_by_id = {x.get("candidate_id"): x for x in existing.get("review_items", [])}

    review_items: list[dict[str, Any]] = []
    for p in proposals:
        prior = prior_by_id.get(p["candidate_id"], {})
        review_items.append(
            {
                "candidate_id": p["candidate_id"],
                "group": p["group"],
                "tactic": p["tactic"],
                "technique": p["technique"],
                "support_count": p["support_count"],
                "source_count": p["source_count"],
                "evidence_score": p["evidence_score"],
                "decision": prior.get("decision", "pending"),  # approve | reject | pending
                "reviewer_notes": prior.get("reviewer_notes", ""),
            }
        )

    out = {
        "generated_at": _iso_now(),
        "instructions": "Set decision per row: approve | reject | pending",
        "review_items": review_items,
    }
    _write_json(REVIEW_FILE, out)
    print(f"Prepared review sheet with {len(review_items)} row(s): {REVIEW_FILE}")


def _index_groups(profiles: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {g["name"]: g for g in profiles.get("apt_groups", [])}


def _evaluate_profiles(profiles: dict[str, Any]) -> dict[str, dict[str, Any]]:
    res: dict[str, dict[str, Any]] = {}
    for key, scenario in DEMO_SCENARIOS.items():
        feats = extract_ttps_from_text(scenario["input_text"])
        scored = run_attribution(feats, profiles, persist_emerging=False)
        top_attr = scored.get("top_attribution")
        top_hyp = scored.get("top_hypothesis")
        res[key] = {
            "name": scenario["name"],
            "tier": scored["confidence_tier"],
            "top_attribution": top_attr["group"] if top_attr else None,
            "top_hypothesis": top_hyp["group"] if top_hyp else None,
        }
    return res


def _regression_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changed_top_attr = 0
    changed_top_hyp = 0
    details = []
    for key in before:
        b = before[key]
        a = after.get(key, {})
        if b.get("top_attribution") != a.get("top_attribution"):
            changed_top_attr += 1
        if b.get("top_hypothesis") != a.get("top_hypothesis"):
            changed_top_hyp += 1
        if b != a:
            details.append({"scenario": key, "before": b, "after": a})
    return {
        "changed_top_attribution": changed_top_attr,
        "changed_top_hypothesis": changed_top_hyp,
        "changed_scenarios": details,
    }


def apply_approved(
    min_support: int = 2,
    min_evidence: float = 0.60,
    max_changed_hyp: int = 4,
    force: bool = False,
    dry_run: bool = False,
) -> None:
    _ensure_dirs()
    profiles = _read_json(PROFILES_FILE, {})
    review = _read_json(REVIEW_FILE, {"review_items": []})
    if not profiles or not review.get("review_items"):
        print("Nothing to apply. Ensure apt_profiles.json and review_sheet.json exist.")
        return

    group_index = _index_groups(profiles)
    approved = [
        r for r in review["review_items"]
        if r.get("decision") == "approve"
        and int(r.get("support_count", 0)) >= min_support
        and float(r.get("evidence_score", 0.0)) >= min_evidence
    ]
    if not approved:
        print("No approved rows met thresholds.")
        return

    before_eval = _evaluate_profiles(profiles)
    updated = deepcopy(profiles)
    updated_group_index = _index_groups(updated)

    additions: list[dict[str, str]] = []
    for row in approved:
        group = row["group"]
        tactic = row["tactic"]
        technique = row["technique"]
        if group not in updated_group_index:
            continue
        group_ref = updated_group_index[group]
        group_ref.setdefault("ttps", {}).setdefault(tactic, [])
        if technique not in group_ref["ttps"][tactic]:
            group_ref["ttps"][tactic].append(technique)
            group_ref["ttps"][tactic] = sorted(set(group_ref["ttps"][tactic]))
            additions.append({"group": group, "tactic": tactic, "technique": technique})

    if not additions:
        print("No new techniques to add (all already present).")
        return

    after_eval = _evaluate_profiles(updated)
    regression = _regression_delta(before_eval, after_eval)
    if regression["changed_top_hypothesis"] > max_changed_hyp and not force:
        print(
            "Regression guard blocked apply: "
            f"changed_top_hypothesis={regression['changed_top_hypothesis']} > {max_changed_hyp}. "
            "Use --force to override."
        )
        return

    if dry_run:
        print(
            f"Dry-run: {len(additions)} update(s) would be applied. "
            f"Regression delta: top_attr={regression['changed_top_attribution']}, "
            f"top_hyp={regression['changed_top_hypothesis']}"
        )
        return

    stamp = _utc_now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"apt_profiles.{stamp}.json"
    _write_json(backup_path, profiles)
    _write_json(PROFILES_FILE, updated)

    changelog = {
        "timestamp": _iso_now(),
        "backup_path": str(backup_path),
        "applied_count": len(additions),
        "applied": additions,
        "thresholds": {
            "min_support": min_support,
            "min_evidence": min_evidence,
            "max_changed_hyp": max_changed_hyp,
            "force": force,
        },
        "regression": regression,
    }
    _append_jsonl(CHANGELOG_FILE, [changelog])
    print(f"Applied {len(additions)} updates to {PROFILES_FILE.name}. Backup: {backup_path.name}")


def status() -> None:
    _ensure_dirs()
    queue = _load_jsonl(QUEUE_FILE)
    candidates = _read_json(CANDIDATES_FILE, {"proposals": []})
    review = _read_json(REVIEW_FILE, {"review_items": []})
    pending = sum(1 for r in review.get("review_items", []) if r.get("decision") == "pending")
    approved = sum(1 for r in review.get("review_items", []) if r.get("decision") == "approve")
    rejected = sum(1 for r in review.get("review_items", []) if r.get("decision") == "reject")
    print(f"Queue items: {len(queue)}")
    print(f"Candidate proposals: {len(candidates.get('proposals', []))}")
    print(f"Review rows: {len(review.get('review_items', []))}")
    print(f"Review decisions: pending={pending} approve={approved} reject={rejected}")


def fetch_live(
    source: str,
    limit: int = 25,
    nvd_days: int = 7,
) -> None:
    """
    Fetch real intel from public sources and ingest directly into raw queue.
    """
    _ensure_dirs()
    profiles = load_profiles()
    source = source.lower()
    incoming: list[dict[str, Any]]
    if source == "cisa-kev":
        incoming = _fetch_cisa_kev(limit)
    elif source == "cisa-advisories":
        incoming = _fetch_cisa_advisories_rss(limit, profiles)
    elif source == "nvd-recent":
        incoming = _fetch_nvd_recent(nvd_days, limit, profiles)
    else:
        raise ValueError("Unsupported source. Use: cisa-kev | cisa-advisories | nvd-recent")

    added, total = _ingest_items(incoming, source_name=None, source_tier=None)
    print(f"Fetched {len(incoming)} item(s) from {source}; added {added}; queue size {total}")


def _autofill_review(
    min_support: int,
    min_evidence: float,
    min_source_count: int,
) -> int:
    candidates = _read_json(CANDIDATES_FILE, {"proposals": []})
    proposals = candidates.get("proposals", [])
    review_items: list[dict[str, Any]] = []
    approved = 0
    for p in proposals:
        decision = "approve" if (
            int(p.get("support_count", 0)) >= min_support
            and float(p.get("evidence_score", 0.0)) >= min_evidence
            and int(p.get("source_count", 0)) >= min_source_count
        ) else "reject"
        if decision == "approve":
            approved += 1
        review_items.append(
            {
                "candidate_id": p["candidate_id"],
                "group": p["group"],
                "tactic": p["tactic"],
                "technique": p["technique"],
                "support_count": p["support_count"],
                "source_count": p["source_count"],
                "evidence_score": p["evidence_score"],
                "decision": decision,
                "reviewer_notes": "auto-approved by autopilot" if decision == "approve" else "auto-rejected by autopilot thresholds",
            }
        )
    _write_json(
        REVIEW_FILE,
        {
            "generated_at": _iso_now(),
            "instructions": "Auto-generated by autopilot.",
            "review_items": review_items,
        },
    )
    return approved


def autopilot_once(
    kev_limit: int = 50,
    advisories_limit: int = 40,
    nvd_limit: int = 80,
    nvd_days: int = 7,
    min_item_conf: float = 0.45,
    min_support: int = 2,
    min_evidence: float = 0.60,
    min_source_count: int = 1,
    max_changed_hyp: int = 4,
    force: bool = False,
    sync_attack: bool = True,
    attack_cache_hours: int = 24,
) -> None:
    """
    One-shot automatic run:
    fetch live sources -> build candidates -> auto-approve -> apply updates.
    """
    print("Autopilot: fetching live sources...")
    for source, limit in [
        ("cisa-kev", kev_limit),
        ("cisa-advisories", advisories_limit),
        ("nvd-recent", nvd_limit),
    ]:
        try:
            fetch_live(source, limit=limit, nvd_days=nvd_days)
        except Exception as exc:
            print(f"Autopilot warning: fetch failed for {source}: {exc}")

    build_candidates(min_item_conf=min_item_conf)
    approved_count = _autofill_review(
        min_support=min_support,
        min_evidence=min_evidence,
        min_source_count=min_source_count,
    )
    print(f"Autopilot: auto-approved {approved_count} candidate(s).")
    apply_approved(
        min_support=min_support,
        min_evidence=min_evidence,
        max_changed_hyp=max_changed_hyp,
        force=force,
        dry_run=False,
    )
    if sync_attack:
        try:
            sync_result = sync_attack_to_profiles(
                max_age_hours=attack_cache_hours,
                max_changed_hyp=max_changed_hyp,
                force=force,
            )
            if sync_result.get("updated"):
                print(
                    "Autopilot: ATT&CK sync applied "
                    f"{sync_result.get('applied_count', 0)} technique update(s)."
                )
            else:
                print(f"Autopilot: ATT&CK sync skipped ({sync_result.get('reason', 'n/a')}).")
        except Exception as exc:
            print(f"Autopilot warning: ATT&CK sync failed: {exc}")
    status()


def autopilot_watch(
    interval_minutes: int = 120,
    cycles: int = 0,
    kev_limit: int = 50,
    advisories_limit: int = 40,
    nvd_limit: int = 80,
    nvd_days: int = 7,
    min_item_conf: float = 0.45,
    min_support: int = 2,
    min_evidence: float = 0.60,
    min_source_count: int = 1,
    max_changed_hyp: int = 4,
    force: bool = False,
    sync_attack: bool = True,
    attack_cache_hours: int = 24,
) -> None:
    """
    Continuous autopilot loop.
    cycles=0 means run forever.
    """
    run_no = 0
    while True:
        run_no += 1
        print(f"\n=== Autopilot cycle {run_no} at {_iso_now()} ===")
        autopilot_once(
            kev_limit=kev_limit,
            advisories_limit=advisories_limit,
            nvd_limit=nvd_limit,
            nvd_days=nvd_days,
            min_item_conf=min_item_conf,
            min_support=min_support,
            min_evidence=min_evidence,
            min_source_count=min_source_count,
            max_changed_hyp=max_changed_hyp,
            force=force,
            sync_attack=sync_attack,
            attack_cache_hours=attack_cache_hours,
        )
        if cycles > 0 and run_no >= cycles:
            break
        sleep_seconds = max(1, int(interval_minutes) * 60)
        print(f"Autopilot sleeping for {interval_minutes} minute(s)...")
        time.sleep(sleep_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="PRISM automatic intel pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_auto = sub.add_parser("autopilot-once", help="Fetch all live sources and auto-apply signature updates")
    p_auto.add_argument("--kev-limit", type=int, default=50)
    p_auto.add_argument("--advisories-limit", type=int, default=40)
    p_auto.add_argument("--nvd-limit", type=int, default=80)
    p_auto.add_argument("--nvd-days", type=int, default=7)
    p_auto.add_argument("--min-item-conf", type=float, default=0.45)
    p_auto.add_argument("--min-support", type=int, default=2)
    p_auto.add_argument("--min-evidence", type=float, default=0.60)
    p_auto.add_argument("--min-source-count", type=int, default=1)
    p_auto.add_argument("--max-changed-hyp", type=int, default=4)
    p_auto.add_argument("--force", action="store_true")
    p_auto.add_argument("--no-attack-sync", action="store_true")
    p_auto.add_argument("--attack-cache-hours", type=int, default=24)

    p_watch = sub.add_parser("autopilot-watch", help="Run autopilot repeatedly on a schedule")
    p_watch.add_argument("--interval-min", type=int, default=120)
    p_watch.add_argument("--cycles", type=int, default=0)
    p_watch.add_argument("--kev-limit", type=int, default=50)
    p_watch.add_argument("--advisories-limit", type=int, default=40)
    p_watch.add_argument("--nvd-limit", type=int, default=80)
    p_watch.add_argument("--nvd-days", type=int, default=7)
    p_watch.add_argument("--min-item-conf", type=float, default=0.45)
    p_watch.add_argument("--min-support", type=int, default=2)
    p_watch.add_argument("--min-evidence", type=float, default=0.60)
    p_watch.add_argument("--min-source-count", type=int, default=1)
    p_watch.add_argument("--max-changed-hyp", type=int, default=4)
    p_watch.add_argument("--force", action="store_true")
    p_watch.add_argument("--no-attack-sync", action="store_true")
    p_watch.add_argument("--attack-cache-hours", type=int, default=24)

    sub.add_parser("status", help="Show pipeline status")

    args = parser.parse_args()
    if args.cmd == "status":
        status()
    elif args.cmd == "autopilot-once":
        autopilot_once(
            kev_limit=args.kev_limit,
            advisories_limit=args.advisories_limit,
            nvd_limit=args.nvd_limit,
            nvd_days=args.nvd_days,
            min_item_conf=args.min_item_conf,
            min_support=args.min_support,
            min_evidence=args.min_evidence,
            min_source_count=args.min_source_count,
            max_changed_hyp=args.max_changed_hyp,
            force=args.force,
            sync_attack=not args.no_attack_sync,
            attack_cache_hours=args.attack_cache_hours,
        )
    elif args.cmd == "autopilot-watch":
        autopilot_watch(
            interval_minutes=args.interval_min,
            cycles=args.cycles,
            kev_limit=args.kev_limit,
            advisories_limit=args.advisories_limit,
            nvd_limit=args.nvd_limit,
            nvd_days=args.nvd_days,
            min_item_conf=args.min_item_conf,
            min_support=args.min_support,
            min_evidence=args.min_evidence,
            min_source_count=args.min_source_count,
            max_changed_hyp=args.max_changed_hyp,
            force=args.force,
            sync_attack=not args.no_attack_sync,
            attack_cache_hours=args.attack_cache_hours,
        )


if __name__ == "__main__":
    main()


# ═══════════════════════════════════════════════════════════════════════════
# Campaign Correlation for Malware Attribution
# ═══════════════════════════════════════════════════════════════════════════

def correlate_with_campaigns(
    ttps: list[str],
    malware_family: str | None = None,
    iocs: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """
    Correlate malware indicators with known APT campaigns.
    
    Args:
        ttps: List of MITRE technique IDs
        malware_family: Identified malware family name
        iocs: Dict with hashes, imphash, etc.
    
    Returns:
        List of matching campaigns with confidence scores
    """
    matches = []
    
    # Load APT profiles
    try:
        profiles = load_profiles()
    except Exception:
        return []
    
    # Known campaign signatures (simplified - in production, load from threat intel DB)
    CAMPAIGN_SIGNATURES = {
        "Operation Dream Job": {
            "apt_group": "Lazarus Group",
            "ttps": ["T1566.001", "T1059.001", "T1055", "T1003.001"],
            "malware_families": ["manuscrypt", "fallchill"],
            "timeframe": "2020-2024"
        },
        "SolarWinds Supply Chain": {
            "apt_group": "APT29",
            "ttps": ["T1195.002", "T1071.001", "T1027", "T1078"],
            "malware_families": ["sunburst", "teardrop"],
            "timeframe": "2020"
        },
        "NotPetya Wiper": {
            "apt_group": "Sandworm",
            "ttps": ["T1486", "T1490", "T1021.002", "T1003.001"],
            "malware_families": ["notpetya", "industroyer"],
            "timeframe": "2017"
        },
        "APT28 Credential Harvesting": {
            "apt_group": "APT28",
            "ttps": ["T1566.002", "T1003.001", "T1078", "T1071.001"],
            "malware_families": ["x-agent", "sofacy"],
            "timeframe": "2015-2024"
        }
    }
    
    # Score each campaign
    for campaign_name, campaign_data in CAMPAIGN_SIGNATURES.items():
        score = 0.0
        matched_indicators = []
        
        # TTP overlap
        campaign_ttps = set(campaign_data["ttps"])
        input_ttps = set(ttps)
        ttp_overlap = len(campaign_ttps & input_ttps)
        if ttp_overlap > 0:
            ttp_score = ttp_overlap / len(campaign_ttps)
            score += ttp_score * 0.6
            matched_indicators.append(f"{ttp_overlap} TTPs matched")
        
        # Malware family match
        if malware_family:
            family_lower = malware_family.lower()
            if any(fam in family_lower for fam in campaign_data["malware_families"]):
                score += 0.4
                matched_indicators.append(f"Malware family: {malware_family}")
        
        # Only include campaigns with meaningful matches
        if score > 0.2:
            matches.append({
                "campaign_name": campaign_name,
                "apt_group": campaign_data["apt_group"],
                "confidence": round(score * 100, 1),
                "matched_indicators": matched_indicators,
                "timeframe": campaign_data["timeframe"]
            })
    
    # Sort by confidence
    matches.sort(key=lambda x: x["confidence"], reverse=True)
    
    return matches
