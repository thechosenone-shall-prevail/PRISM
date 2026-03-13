"""
APTrace Core Attribution Engine
Extracts behavioral features from inputs and scores against APT profiles.
"""

import json
import re
import math
import hashlib
import collections
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import streamlit as st

from cluster_memory import upsert_emerging_cluster
import vt_client

# -- Load profiles -----------------------------------------------------------

_BASE_DIR = Path(__file__).resolve().parent
_PROFILE_CANDIDATES = (
    _BASE_DIR / "apt_profiles.json",
    _BASE_DIR.parent / "data" / "apt_profiles.json",
)
DATA_PATH = next(
    (path for path in _PROFILE_CANDIDATES if path.exists()),
    _PROFILE_CANDIDATES[0],
)
_MALWARE_DB_CANDIDATES = (
    _BASE_DIR / "malware_family_db.json",
    _BASE_DIR.parent / "data" / "malware_family_db.json",
)


@st.cache_data
def load_profiles(data_path: Optional[Path] = None) -> dict:
    profile_path = Path(data_path) if data_path else DATA_PATH
    if not profile_path.exists():
        searched = ", ".join(str(path) for path in _PROFILE_CANDIDATES)
        raise FileNotFoundError(
            f"APT profile file not found. Looked for: {searched}"
        )
    with open(profile_path, encoding="utf-8") as fh:
        return json.load(fh)


# -- TTP Keyword Maps --------------------------------------------------------

TTP_KEYWORD_MAP = {
    # Initial Access
    "spearphish": ["T1566.001", "T1566.002"],
    "phishing": ["T1566.001", "T1566.002"],
    "phish": ["T1566.001", "T1566.002"],
    "spear phish": ["T1566.001", "T1566.002"],
    "malicious attachment": ["T1566.001"],
    "malicious link": ["T1566.002", "T1204.001"],
    "watering hole": ["T1189"],
    "drive-by": ["T1189"],
    "drive-by compromise": ["T1189"],
    "supply chain": ["T1195.002"],
    "supply chain compromise": ["T1195.002"],
    "software supply chain": ["T1195.002"],
    "exploit public": ["T1190"],
    "exploit public-facing": ["T1190"],
    "rce exploit": ["T1190"],
    "valid accounts": ["T1078"],
    "stolen credentials": ["T1078"],
    "compromised credentials": ["T1078"],
    "vpn access": ["T1133"],
    "external remote": ["T1133"],
    "trusted relationship": ["T1199"],
    "hardware additions": ["T1200"],

    # Execution
    "powershell": ["T1059.001"],
    "ps1": ["T1059.001"],
    "invoke-expression": ["T1059.001"],
    "invoke-command": ["T1059.001"],
    "iex(": ["T1059.001"],
    "cmd": ["T1059.003"],
    "command shell": ["T1059.003"],
    "cmd.exe": ["T1059.003"],
    "python script": ["T1059.006"],
    "python payload": ["T1059.006"],
    "vbscript": ["T1059.005"],
    "vba macro": ["T1059.005"],
    "macro": ["T1059.005", "T1566.001"],
    "embedded macro": ["T1059.005", "T1566.001"],
    "embedded macros": ["T1059.005", "T1566.001"],
    "microsoft word": ["T1566.001", "T1204.002"],
    "word document": ["T1566.001", "T1204.002"],
    "javascript execution": ["T1059.007"],
    "jscript": ["T1059.007"],
    "wmi": ["T1047"],
    "wmic": ["T1047"],
    "scheduled task": ["T1053.005"],
    "schtasks": ["T1053.005"],
    "cron job": ["T1053.003"],
    "at job": ["T1053.002"],
    "service execution": ["T1569.002"],
    "native api": ["T1106"],
    "ntcreatethread": ["T1106"],
    "user execution": ["T1204.002"],
    "malicious file": ["T1204.002"],
    "exploitation for client execution": ["T1203"],
    "software deployment tools": ["T1072"],
    "shared modules": ["T1129"],

    # Persistence
    "registry run": ["T1547.001"],
    "registry run key": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "windows service": ["T1543.003"],
    "new service": ["T1543.003"],
    "scheduled task persist": ["T1053.005"],
    "browser extension": ["T1176"],
    "new account": ["T1136.001"],
    "create local account": ["T1136.001"],
    "bootkit": ["T1542.003"],
    "system firmware": ["T1542.001"],
    "uefi implant": ["T1542.001"],
    "account manipulation": ["T1098"],
    "office application startup": ["T1137"],
    "pre-os boot": ["T1542"],
    "hijack execution flow": ["T1574"],
    "dll search order hijacking": ["T1574.001"],
    "dll side-loading": ["T1574.002"],
    "com hijack": ["T1546.015"],
    "image file execution options": ["T1546.012"],
    "logon script": ["T1037"],
    "winlogon helper": ["T1547.004"],
    "bits job": ["T1197"],
    "server software component": ["T1505"],
    "web shell": ["T1505.003"],

    # Privilege Escalation
    "uac bypass": ["T1548.002"],
    "access token manipulation": ["T1134"],
    "exploitation for privilege escalation": ["T1068"],
    "sudo exploit": ["T1548.003"],
    "setuid": ["T1548.001"],

    # Defense Evasion
    "obfuscation": ["T1027"],
    "obfuscated": ["T1027"],
    "encoded payload": ["T1027", "T1140"],
    "base64": ["T1027", "T1140"],
    "xor encoding": ["T1027"],
    "packed": ["T1027.002"],
    "packing": ["T1027.002"],
    "software packing": ["T1027.002"],
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "process hollowing": ["T1055.012"],
    "thread execution hijacking": ["T1055.003"],
    "reflective dll": ["T1620"],
    "reflective code loading": ["T1620"],
    "masquerade": ["T1036.005"],
    "masquerading": ["T1036.005"],
    "renamed binary": ["T1036.005"],
    "disable av": ["T1562.001"],
    "disable antivirus": ["T1562.001"],
    "tamper protection": ["T1562.001"],
    "disable edr": ["T1562.001"],
    "file deletion": ["T1070.004"],
    "timestomp": ["T1070.006"],
    "clear logs": ["T1070.001"],
    "event log": ["T1070.001"],
    "indicator removal": ["T1070"],
    "living off the land": ["T1218", "T1059.001", "T1059.003"],
    "lolbin": ["T1218"],
    "lotl": ["T1218", "T1059.001"],
    "rundll32": ["T1218.011"],
    "regsvr32": ["T1218.010"],
    "certutil": ["T1218.003"],
    "mshta": ["T1218.005"],
    "cmstp": ["T1218.003"],
    "installutil": ["T1218.004"],
    "signed binary": ["T1553"],
    "code signing": ["T1553.002"],
    "subvert trust controls": ["T1553"],
    "rootkit": ["T1014"],
    "virtualization evasion": ["T1497"],
    "sandbox evasion": ["T1497.001"],
    "vm detection": ["T1497.001"],
    "anti-debug": ["T1622"],
    "debugger detection": ["T1622"],
    "time-based evasion": ["T1497.003"],
    "deobfuscate": ["T1140"],
    "decode files": ["T1140"],
    "indirect command execution": ["T1202"],
    "ntfs file attributes": ["T1564.004"],
    "hidden files": ["T1564.001"],
    "modify registry": ["T1112"],
    "impair defenses": ["T1562"],
    "disable windows event logging": ["T1562.002"],

    # Credential Access
    "lsass": ["T1003.001"],
    "lsass memory": ["T1003.001"],
    "credential dump": ["T1003"],
    "credential dumping": ["T1003"],
    "mimikatz": ["T1003.001"],
    "procdump": ["T1003.001"],
    "pass the hash": ["T1550.002"],
    "pth": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "kerberoast": ["T1558.003"],
    "kerberoasting": ["T1558.003"],
    "as-rep roasting": ["T1558.004"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558.002"],
    "dcsync": ["T1003.006"],
    "keylog": ["T1056.001"],
    "keylogger": ["T1056.001"],
    "keylogging": ["T1056.001"],
    "brute force": ["T1110"],
    "password spray": ["T1110.003"],
    "credential stuffing": ["T1110.004"],
    "cookie theft": ["T1539"],
    "steal web session cookie": ["T1539"],
    "session token": ["T1528", "T1539"],
    "mfa bypass": ["T1111"],
    "mfa interception": ["T1111"],
    "oauth token": ["T1528"],
    "oauth abuse": ["T1528"],
    "unsecured credentials": ["T1552"],
    "credentials in files": ["T1552.001"],
    "sam database": ["T1003.002"],
    "ntds.dit": ["T1003.003"],
    "lsa secrets": ["T1003.004"],
    "web portal capture": ["T1056.003"],
    "forced authentication": ["T1187"],
    "steal application access token": ["T1528"],

    # Discovery
    "system info": ["T1082"],
    "sysinfo": ["T1082"],
    "systeminfo": ["T1082"],
    "whoami": ["T1033"],
    "ipconfig": ["T1016"],
    "ifconfig": ["T1016"],
    "network scan": ["T1046"],
    "port scan": ["T1046"],
    "nmap": ["T1046"],
    "file enumeration": ["T1083"],
    "directory listing": ["T1083"],
    "dir /s": ["T1083"],
    "process list": ["T1057"],
    "tasklist": ["T1057"],
    "ps -ef": ["T1057"],
    "network share": ["T1135"],
    "smb share": ["T1135"],
    "net share": ["T1135"],
    "account enumeration": ["T1087"],
    "net user": ["T1087"],
    "group enumeration": ["T1069"],
    "net group": ["T1069"],
    "domain trust": ["T1482"],
    "nltest": ["T1482"],
    "bloodhound": ["T1087", "T1069", "T1482"],
    "ad enumeration": ["T1087", "T1069"],
    "active directory enumeration": ["T1087", "T1069"],
    "remote system discovery": ["T1018"],
    "network sniffing": ["T1040"],
    "packet capture": ["T1040"],
    "software discovery": ["T1518"],
    "security software discovery": ["T1518.001"],
    "cloud infrastructure discovery": ["T1580"],

    # Lateral Movement
    "rdp": ["T1021.001"],
    "remote desktop": ["T1021.001"],
    "smb": ["T1021.002"],
    "admin share": ["T1021.002"],
    "psexec": ["T1021.002"],
    "wmi lateral": ["T1021.003"],
    "winrm": ["T1021.006"],
    "ssh": ["T1021.004"],
    "lateral movement": ["T1021.001", "T1021.002"],
    "lateral tool transfer": ["T1570"],
    "internal spearphishing": ["T1534"],
    "remote service exploitation": ["T1210"],
    "taint shared content": ["T1080"],

    # Collection
    "screenshot": ["T1113"],
    "screen capture": ["T1113"],
    "email collection": ["T1114.001", "T1114.002"],
    "outlook": ["T1114.001"],
    "email forwarding rule": ["T1114.003"],
    "archive": ["T1560.001"],
    "zip compress": ["T1560.001"],
    "rar compress": ["T1560.001"],
    "7z compress": ["T1560.001"],
    "stage data": ["T1074.001"],
    "data staging": ["T1074.001"],
    "audio capture": ["T1123"],
    "video capture": ["T1125"],
    "clipboard": ["T1115"],
    "clipboard data": ["T1115"],
    "cloud storage access": ["T1530"],
    "input capture": ["T1056"],
    "man in the browser": ["T1185"],
    "browser session hijacking": ["T1185"],
    "automated collection": ["T1119"],

    # C2
    "https c2": ["T1071.001"],
    "http beacon": ["T1071.001"],
    "http c2": ["T1071.001"],
    "command and control": ["T1071.001"],
    "command-and-control": ["T1071.001"],
    "c2 server": ["T1071.001"],
    "c2 beacon": ["T1071.001"],
    "beaconed": ["T1071.001"],
    "dns tunnel": ["T1071.004"],
    "dns c2": ["T1071.004"],
    "dns over https": ["T1071.004"],
    "doh c2": ["T1071.004"],
    "encrypted channel": ["T1573.001"],
    "tls c2": ["T1573.001"],
    "ssl c2": ["T1573.001"],
    "tor": ["T1090.003"],
    "tor c2": ["T1090.003"],
    "proxy chain": ["T1090.003"],
    "multi-hop": ["T1090.003"],
    "multi-hop proxy": ["T1090.003"],
    "soho router": ["T1090.002"],
    "compromised router": ["T1090.002"],
    "cloud c2": ["T1102"],
    "dropbox c2": ["T1102.002"],
    "onedrive c2": ["T1102.002"],
    "google drive c2": ["T1102.002"],
    "telegram bot": ["T1102.002"],
    "telegram c2": ["T1102.002"],
    "rmm tool": ["T1219"],
    "anydesk": ["T1219"],
    "teamviewer": ["T1219"],
    "screenconnect": ["T1219"],
    "atera": ["T1219"],
    "simplehelp": ["T1219"],
    "cobalt strike": ["T1071.001", "T1573.001"],
    "beacon interval": ["T1071.001"],
    "long dwell": ["T1029"],
    "jitter": ["T1029"],
    "domain fronting": ["T1090.004"],
    "protocol tunneling": ["T1572"],
    "non-standard port": ["T1571"],
    "custom protocol": ["T1095"],
    "dead drop resolver": ["T1102.001"],
    "fallback channel": ["T1008"],
    "dynamic resolution": ["T1568"],
    "fast flux": ["T1568.001"],
    "downloaded": ["T1105"],
    "second-stage": ["T1105"],
    "second stage": ["T1105"],
    "stage-2": ["T1105"],
    "stage two": ["T1105"],

    # Exfiltration
    "data exfil": ["T1041"],
    "exfiltration": ["T1041"],
    "exfil": ["T1041"],
    "exfil over c2": ["T1041"],
    "upload to cloud": ["T1567.002"],
    "exfil to cloud": ["T1567.002"],
    "dns exfil": ["T1048.003"],
    "ftp exfil": ["T1048.003"],
    "exfil over alternative protocol": ["T1048"],
    "scheduled transfer": ["T1029"],
    "data transfer size limits": ["T1030"],
    "automated exfiltration": ["T1020"],
    "exfil over web service": ["T1567"],
    "exfil over physical medium": ["T1052"],

    # Impact
    "wiper": ["T1485"],
    "wiper malware": ["T1485"],
    "data destruction": ["T1485"],
    "ransomware": ["T1486"],
    "encrypt files": ["T1486"],
    "data encrypted for impact": ["T1486"],
    "delete backups": ["T1490"],
    "shadow copy": ["T1490"],
    "vssadmin": ["T1490"],
    "inhibit system recovery": ["T1490"],
    "dos attack": ["T1498"],
    "ddos": ["T1498"],
    "defacement": ["T1491"],
    "web defacement": ["T1491.002"],
    "ics attack": ["T1498", "T1499"],
    "scada": ["T1498"],
    "power grid": ["T1498", "T1499"],
    "disk wipe": ["T1561"],
    "firmware corruption": ["T1495"],
    "account access removal": ["T1531"],
    "resource hijacking": ["T1496"],
    "cryptojacking": ["T1496"],
    "system shutdown": ["T1529"],

    # Targeting context (no technique IDs, used for context boosting only)
    "financial": [],
    "cryptocurrency": [],
    "crypto exchange": [],
    "crypto wallet": [],
    "swift": [],
    "swift network": [],
    "government": [],
    "military": [],
    "defense": [],
    "defense contractor": [],
    "nuclear": [],
    "nuclear research": [],
    "energy": [],
    "energy sector": [],
    "critical infrastructure": [],
    "healthcare": [],
    "telecom": [],
    "telecommunications": [],
    "think tank": [],
    "policy research": [],
    "journalist": [],
    "dissident": [],
    "human rights": [],
    "ngo": [],
    "academic": [],
    "university": [],
    "israel": [],
    "ukraine": [],
    "india": [],
    "south korea": [],
    "nato": [],
    "middle east": [],
    "taiwan": [],
    "pacific": [],
    "southeast asia": [],
    "election": [],
    "election infrastructure": [],
}

# Context keywords that boost certain APT groups
CONTEXT_BOOST_MAP = {
    "cryptocurrency": {"Lazarus Group": 0.30, "Kimsuky": 0.15},
    "crypto exchange": {"Lazarus Group": 0.35, "Kimsuky": 0.15},
    "crypto wallet": {"Lazarus Group": 0.30},
    "swift": {"Lazarus Group": 0.40},
    "swift network": {"Lazarus Group": 0.40},
    "financial": {"Lazarus Group": 0.25, "APT41": 0.15},
    "nuclear": {"APT35": 0.30, "Kimsuky": 0.25},
    "nuclear research": {"APT35": 0.30, "Kimsuky": 0.25},
    "dissident": {"APT35": 0.35, "MuddyWater": 0.20},
    "human rights": {"APT35": 0.25},
    "journalist": {"APT35": 0.25, "Kimsuky": 0.15},
    "israel": {"APT35": 0.40, "MuddyWater": 0.20},
    "ukraine": {"Sandworm": 0.40, "APT28": 0.30, "Gamaredon": 0.45, "Turla": 0.15},
    "power grid": {"Sandworm": 0.45},
    "ics": {"Sandworm": 0.40},
    "scada": {"Sandworm": 0.40},
    "nato": {"APT28": 0.35, "APT29": 0.30, "Turla": 0.25},
    "election": {"APT28": 0.40},
    "election infrastructure": {"APT28": 0.40},
    "think tank": {"APT29": 0.30, "Kimsuky": 0.25, "Turla": 0.15},
    "policy research": {"Kimsuky": 0.30, "APT29": 0.20},
    "supply chain": {"APT29": 0.35, "APT41": 0.30},
    "india": {"Transparent Tribe": 0.50, "SideCopy": 0.40},
    "south korea": {"Kimsuky": 0.35, "Lazarus Group": 0.20},
    "middle east": {"MuddyWater": 0.30, "APT35": 0.25, "OilRig": 0.25},
    "critical infrastructure": {"Volt Typhoon": 0.40, "Sandworm": 0.30},
    "lotl": {"Volt Typhoon": 0.50},
    "living off the land": {"Volt Typhoon": 0.50},
    "soho router": {"Volt Typhoon": 0.55},
    "rmm tool": {"MuddyWater": 0.40},
    "wiper": {"Sandworm": 0.40, "Lazarus Group": 0.20},
    "telegram": {"APT35": 0.25},
    "telecom": {"Salt Typhoon": 0.45, "MuddyWater": 0.15},
    "telecommunications": {"Salt Typhoon": 0.45, "MuddyWater": 0.15},
    "taiwan": {"Volt Typhoon": 0.30, "APT41": 0.20},
    "pacific": {"Volt Typhoon": 0.35},
    "southeast asia": {"Lazarus Group": 0.15, "APT41": 0.20},
    "government": {"APT28": 0.10, "APT29": 0.10, "Turla": 0.10},
    "military": {"APT28": 0.15, "Transparent Tribe": 0.25},
    "defense": {"APT28": 0.10, "Transparent Tribe": 0.20},
    "defense contractor": {"APT28": 0.15, "Lazarus Group": 0.10},
    "healthcare": {"APT29": 0.15, "APT41": 0.15},
    "energy": {"Sandworm": 0.25, "Volt Typhoon": 0.15},
    "energy sector": {"Sandworm": 0.25, "Volt Typhoon": 0.15},
    "academic": {"Kimsuky": 0.20, "APT35": 0.15},
    "university": {"Kimsuky": 0.15, "APT35": 0.15},
    "ngo": {"APT29": 0.15, "APT35": 0.10},
    "oil and gas": {"OilRig": 0.40, "MuddyWater": 0.15},
}

CONTEXT_SYNONYM_MAP = {
    "energy sector": "energy",
    "telecommunications": "telecom",
    "swift network": "swift",
    "nuclear research": "nuclear",
    "crypto exchange": "cryptocurrency",
    "crypto wallet": "cryptocurrency",
    "election infrastructure": "election",
}

SECTOR_CONTEXT_MAP = {
    "financial": {"financial"},
    "cryptocurrency": {"financial", "cryptocurrency"},
    "government": {"government"},
    "military": {"military", "defense"},
    "defense": {"defense"},
    "defense contractor": {"defense"},
    "nuclear": {"nuclear"},
    "energy": {"energy", "critical infrastructure"},
    "critical infrastructure": {"critical infrastructure"},
    "healthcare": {"healthcare"},
    "telecom": {"telecom"},
    "think tank": {"think tank"},
    "policy research": {"think tank"},
    "journalist": {"media"},
    "academic": {"academic"},
    "university": {"academic"},
    "ngo": {"ngo"},
    "oil and gas": {"energy"},
}

REGION_CONTEXT_MAP = {
    "israel": {"israel", "middle east"},
    "ukraine": {"ukraine", "eastern europe"},
    "india": {"india", "south asia"},
    "south korea": {"south korea", "east asia"},
    "nato": {"europe", "nato"},
    "middle east": {"middle east"},
    "taiwan": {"taiwan", "east asia"},
    "pacific": {"pacific", "indo-pacific"},
    "southeast asia": {"southeast asia"},
}

ATTRIBUTION_GATES = {
    "min_techniques": 6,
    "min_tactic_coverage": 3,
    "min_top_confidence_pct": 35.0,
    "min_top_raw_score": 0.22,
    "min_lead_pct": 8.0,
    "novelty_similarity_threshold": 0.30,
}

MOTIVE_CANONICAL_MAP = {
    "financial": "financial",
    "crypto theft": "financial",
    "espionage": "espionage",
    "intelligence collection": "espionage",
    "strategic intelligence": "espionage",
    "communications intelligence": "espionage",
    "military intelligence": "espionage",
    "destruction": "disruption",
    "disruption": "disruption",
    "critical infrastructure disruption": "disruption",
    "political influence": "influence",
    "information operations": "influence",
    "surveillance": "surveillance",
    "counter-dissidence": "surveillance",
    "pre-positioning": "prepositioning",
    "intellectual property theft": "ip_theft",
}

MOTIVE_SIGNAL_MAP = {
    "financial": {
        "contexts": {"financial", "cryptocurrency", "swift"},
        "techniques": {"T1567.002", "T1041", "T1555", "T1550.002", "T1539"},
        "keywords": {"crypto", "wallet", "bank", "payment", "swift"},
    },
    "espionage": {
        "contexts": {"government", "defense", "military", "telecom", "think tank"},
        "techniques": {"T1082", "T1083", "T1046", "T1114.001", "T1114.002", "T1071.001", "T1071.004"},
        "keywords": {"reconnaissance", "collection", "intelligence", "long dwell", "beacon"},
    },
    "disruption": {
        "contexts": {"energy", "critical infrastructure"},
        "techniques": {"T1485", "T1486", "T1490", "T1498", "T1499"},
        "keywords": {"wiper", "destruction", "disrupt", "outage", "sabotage"},
    },
    "prepositioning": {
        "contexts": {"critical infrastructure", "telecom", "energy"},
        "techniques": {"T1547.001", "T1053.005", "T1090.002", "T1021.001"},
        "keywords": {"pre-position", "persistence", "foothold"},
    },
    "surveillance": {
        "contexts": {"dissident", "journalist", "human rights"},
        "techniques": {"T1113", "T1056", "T1115", "T1539"},
        "keywords": {"surveillance", "monitoring", "tracking"},
    },
    "influence": {
        "contexts": {"election"},
        "techniques": {"T1566.001", "T1566.002", "T1583.001"},
        "keywords": {"election", "influence", "disinformation"},
    },
    "ip_theft": {
        "contexts": {"academic", "university", "healthcare"},
        "techniques": {"T1530", "T1567", "T1041"},
        "keywords": {"source code", "intellectual property", "r&d"},
    },
}

MOTIVE_TEXT_PATTERNS = {
    "financial": [
        "financial gain",
        "financial theft",
        "crypto heist",
        "banking credentials",
        "payment systems",
        "fund transfer",
        "wire transfer",
        "wallet theft",
        "exchange compromise",
        "swift transaction",
    ],
    "espionage": [
        "intelligence collection",
        "strategic intelligence",
        "surveillance objective",
        "long-term access",
        "persistent access",
        "sensitive communications",
        "classified information",
        "policy documents",
        "government intelligence",
    ],
    "disruption": [
        "service disruption",
        "critical outage",
        "destructive payload",
        "operational disruption",
        "infrastructure sabotage",
        "availability impact",
        "system destruction",
    ],
    "prepositioning": [
        "pre-positioning",
        "prepositioning",
        "future access",
        "latent access",
        "strategic foothold",
        "wait and hold",
        "dormant persistence",
    ],
    "surveillance": [
        "monitor dissidents",
        "track journalists",
        "target activists",
        "covert monitoring",
        "human rights monitoring",
    ],
    "influence": [
        "influence operation",
        "information operation",
        "disinformation",
        "election interference",
        "public opinion manipulation",
    ],
    "ip_theft": [
        "intellectual property",
        "source code theft",
        "research data theft",
        "trade secrets",
        "proprietary data",
        "r and d theft",
    ],
}


# -- Feature Extraction ------------------------------------------------------

def _keyword_in_text(text_lower: str, keyword: str) -> bool:
    """Word-boundary match for short single-token keywords to cut false positives."""
    if " " in keyword or len(keyword) > 4:
        return keyword in text_lower
    return re.search(rf"\b{re.escape(keyword)}\b", text_lower) is not None


def _normalize_context_signals(context_signals: list[str]) -> list[str]:
    normalized: set[str] = set()
    for signal in context_signals:
        canonical = CONTEXT_SYNONYM_MAP.get(signal, signal)
        normalized.add(canonical)
    return sorted(normalized)


def _normalize_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def _collect_observed_context_domains(observed_contexts: list[str]) -> tuple[set[str], set[str]]:
    observed_sectors: set[str] = set()
    observed_regions: set[str] = set()
    for ctx in observed_contexts:
        for label in SECTOR_CONTEXT_MAP.get(ctx, set()):
            observed_sectors.add(_normalize_label(label))
        for label in REGION_CONTEXT_MAP.get(ctx, set()):
            observed_regions.add(_normalize_label(label))
    return observed_sectors, observed_regions


def _collect_group_context_domains(apt_group: dict) -> tuple[set[str], set[str]]:
    sectors = {_normalize_label(s) for s in apt_group.get("target_sectors", [])}
    regions = {_normalize_label(r) for r in apt_group.get("target_regions", [])}
    return sectors, regions


def _compute_context_contradiction_penalty(observed_contexts: list[str], apt_group: dict) -> tuple[float, list[str]]:
    observed_sectors, observed_regions = _collect_observed_context_domains(observed_contexts)
    group_sectors, group_regions = _collect_group_context_domains(apt_group)
    contradiction_signals: list[str] = []
    penalty = 0.0

    if observed_sectors and group_sectors and observed_sectors.isdisjoint(group_sectors):
        penalty += 0.10
        contradiction_signals.append("sector_mismatch")
    if observed_regions and group_regions and observed_regions.isdisjoint(group_regions):
        penalty += 0.10
        contradiction_signals.append("region_mismatch")

    return min(penalty, 0.20), contradiction_signals


def _canonicalize_group_motives(motivation_list: list[str]) -> set[str]:
    canonical: set[str] = set()
    for motive in motivation_list:
        key = _normalize_label(motive)
        mapped = MOTIVE_CANONICAL_MAP.get(key)
        if mapped:
            canonical.add(mapped)
    return canonical


def _infer_observed_motives(observed: dict) -> dict[str, float]:
    contexts = set(observed.get("context_signals", []))
    techniques = set(observed.get("techniques", []))
    keywords = {str(k).lower() for k in observed.get("matched_keywords", [])}
    motive_clues = observed.get("motive_clues", {}) or {}

    inferred: dict[str, float] = {}
    for motive, signals in MOTIVE_SIGNAL_MAP.items():
        ctx_hits = len(contexts & signals["contexts"])
        tech_hits = len(techniques & signals["techniques"])
        key_hits = len({k for k in signals["keywords"] if any(k in observed_kw for observed_kw in keywords)})
        clue_hits = int(motive_clues.get(motive, 0))

        ctx_score = min(ctx_hits / 2.0, 1.0)
        tech_score = min(tech_hits / 3.0, 1.0)
        key_score = min(key_hits / 2.0, 1.0)
        clue_score = min(clue_hits / 3.0, 1.0)
        score = (0.40 * ctx_score) + (0.25 * tech_score) + (0.15 * key_score) + (0.20 * clue_score)
        if score > 0:
            inferred[motive] = round(float(score), 3)
    return inferred


def _compute_motivation_alignment(observed: dict, apt_group: dict) -> tuple[float, float, list[str], list[str], dict[str, float]]:
    inferred = _infer_observed_motives(observed)
    strong_inferred = {m: s for m, s in inferred.items() if s >= 0.30}
    group_motives = _canonicalize_group_motives(apt_group.get("motivation", []))
    matched = sorted([m for m in strong_inferred if m in group_motives])
    mismatched = sorted([m for m in strong_inferred if m not in group_motives])

    boost = 0.0
    penalty = 0.0
    if matched:
        align_strength = sum(strong_inferred[m] for m in matched) / len(matched)
        boost = min(0.12, 0.05 + (0.07 * align_strength))

    if strong_inferred and not matched:
        penalty = 0.08
    elif mismatched:
        mismatch_strength = sum(strong_inferred[m] for m in mismatched) / len(mismatched)
        penalty = min(0.05, 0.02 + (0.04 * mismatch_strength))

    return boost, penalty, matched, mismatched, inferred


def _extract_motive_clues(text_lower: str) -> dict[str, int]:
    clues: dict[str, int] = {}
    for motive, patterns in MOTIVE_TEXT_PATTERNS.items():
        hits = 0
        for pattern in patterns:
            if pattern in text_lower:
                hits += 1
        if hits:
            clues[motive] = hits
    return clues


def extract_ttps_from_text(text: str) -> dict:
    """
    Extract MITRE ATT&CK technique IDs and context signals from free text.
    Returns matched techniques, raw keywords, context boosts, and IOCs.
    """
    text_lower = text.lower()
    matched_techniques = set()
    matched_keywords = []
    context_signals = []
    direct_ttp_matches = []

    # 1. Direct T-code extraction  (T1566.001 or T1566)
    ttp_pattern = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.IGNORECASE)
    for t in ttp_pattern:
        normalized = t.upper()
        matched_techniques.add(normalized)
        direct_ttp_matches.append(normalized)

    # 2. Keyword-based TTP extraction
    for keyword, techniques in TTP_KEYWORD_MAP.items():
        if _keyword_in_text(text_lower, keyword):
            matched_keywords.append(keyword)
            for t in techniques:
                matched_techniques.add(t)

    # 3. Context signal extraction
    for context in CONTEXT_BOOST_MAP:
        if context in text_lower:
            context_signals.append(context)

    # 4. Extract IOC-like patterns
    iocs = {
        "ips": re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
        "domains": re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|ir|kp|onion|biz|info|xyz|top)\b",
            text,
        ),
        "hashes_md5": re.findall(r"\b[a-fA-F0-9]{32}\b", text),
        "hashes_sha256": re.findall(r"\b[a-fA-F0-9]{64}\b", text),
        "cve": re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE),
    }
    motive_clues = _extract_motive_clues(text_lower)

    return {
        "techniques": sorted(matched_techniques),
        "matched_keywords": sorted(set(matched_keywords)),
        "context_signals": sorted(set(_normalize_context_signals(context_signals))),
        "direct_ttp_matches": sorted(set(direct_ttp_matches)),
        "motive_clues": motive_clues,
        "iocs": iocs,
        "technique_count": len(matched_techniques),
    }


def extract_ttps_from_log(log_content: str) -> dict:
    """
    Extract TTPs from log file content (Windows Event Log, Sysmon, EDR).
    Adds log-specific pattern recognition on top of text extraction.
    """
    base = extract_ttps_from_text(log_content)

    # Sysmon Event ID mappings
    sysmon_patterns = {
        "EventID: 1": ["T1059"],
        "EventID: 3": ["T1071"],
        "EventID: 7": ["T1574"],
        "EventID: 8": ["T1055"],
        "EventID: 10": ["T1003.001"],
        "EventID: 11": ["T1074"],
        "EventID: 12": ["T1547.001"],
        "EventID: 13": ["T1547.001"],
        "EventID: 15": ["T1071.001"],
        "EventID: 22": ["T1071.004"],
        "EventID: 23": ["T1070.004"],
        "EventID: 25": ["T1055"],
        "EventID: 26": ["T1070.004"],
    }

    # Windows Security Event mappings
    security_events = {
        "EventID: 4624": ["T1078"],
        "EventID: 4625": ["T1110"],
        "EventID: 4648": ["T1078"],
        "EventID: 4672": ["T1134"],
        "EventID: 4688": ["T1059"],
        "EventID: 4698": ["T1053.005"],
        "EventID: 4702": ["T1053.005"],
        "EventID: 4720": ["T1136.001"],
        "EventID: 4732": ["T1136.001"],
        "EventID: 4776": ["T1550.002"],
        "EventID: 5136": ["T1098"],
        "EventID: 5156": ["T1071"],
        "EventID: 7045": ["T1543.003"],
    }

    log_lower = log_content.lower()
    log_techniques = set(base["techniques"])

    for pattern, techs in {**sysmon_patterns, **security_events}.items():
        if pattern.lower() in log_lower:
            log_techniques.update(techs)

    # Suspicious command line patterns
    suspicious_cmds = {
        "lsass": ["T1003.001"],
        "vssadmin delete": ["T1490"],
        "wscript": ["T1059.005"],
        "cscript": ["T1059.005"],
        "mshta": ["T1218.005"],
        "regsvr32": ["T1218.010"],
        "certutil -decode": ["T1140", "T1218.003"],
        "certutil -urlcache": ["T1105", "T1218.003"],
        "bitsadmin /transfer": ["T1197", "T1105"],
        "net user /add": ["T1136.001"],
        "net localgroup administrators": ["T1136.001"],
        "sc create": ["T1543.003"],
        "schtasks /create": ["T1053.005"],
        "whoami /all": ["T1033"],
        "nltest /domain_trusts": ["T1482"],
        "procdump": ["T1003.001"],
        "sekurlsa": ["T1003.001"],
        "invoke-mimikatz": ["T1003.001"],
        "-enc ": ["T1059.001", "T1027"],
        "-encodedcommand": ["T1059.001", "T1027"],
        "downloadstring": ["T1105"],
        "downloadfile": ["T1105"],
        "webclient": ["T1105"],
        "invoke-webrequest": ["T1105"],
        "curl.exe": ["T1105"],
        "wget": ["T1105"],
        "net view": ["T1135"],
        "arp -a": ["T1016"],
        "route print": ["T1016"],
        "netstat -an": ["T1049"],
        "quser": ["T1033"],
        "query user": ["T1033"],
        "reg query": ["T1012"],
        "reg add": ["T1112"],
        "wevtutil cl": ["T1070.001"],
        "bcdedit": ["T1490"],
        "wbadmin delete": ["T1490"],
    }

    for cmd_pattern, techs in suspicious_cmds.items():
        if cmd_pattern in log_lower:
            log_techniques.update(techs)
            if cmd_pattern not in base["matched_keywords"]:
                base["matched_keywords"].append(cmd_pattern)

    base["techniques"] = sorted(log_techniques)
    base["matched_keywords"] = sorted(set(base["matched_keywords"]))
    base["technique_count"] = len(log_techniques)
    base["source_type"] = "log_file"
    return base


# -- Scoring Engine -----------------------------------------------------------

TACTIC_WEIGHTS = {
    "initial_access":      0.10,
    "execution":           0.09,
    "persistence":         0.11,
    "privilege_escalation": 0.06,
    "defense_evasion":     0.14,
    "credential_access":   0.10,
    "discovery":           0.07,
    "lateral_movement":    0.10,
    "collection":          0.07,
    "command_and_control": 0.14,
    "exfiltration":        0.07,
    "impact":              0.05,
}


def recall_similarity(observed: set, reference: set) -> float:
    """Fraction of the reference set that was observed."""
    if not reference:
        return 0.0
    return len(observed & reference) / len(reference)


def precision_similarity(observed: set, reference: set) -> float:
    """Fraction of observed set that overlaps the reference set."""
    if not observed:
        return 0.0
    return len(observed & reference) / len(observed)


def jaccard_similarity(set_a: set, set_b: set) -> float:
    """Jaccard index between two sets."""
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def cosine_similarity_sets(set_a: set, set_b: set, universe: set) -> float:
    """Cosine similarity treating technique presence as binary vectors."""
    if not set_a or not set_b or not universe:
        return 0.0
    vec_a = [1 if t in set_a else 0 for t in universe]
    vec_b = [1 if t in set_b else 0 for t in universe]
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _expand_techniques(observed: set, group_techs: set) -> set:
    """Expand observed techniques to also match parent/sub-technique variants."""
    expanded = set(observed)
    for obs in observed:
        if "." in obs:
            expanded.add(obs.split(".")[0])
        for gt in group_techs:
            if "." in gt and gt.startswith(obs + "."):
                expanded.add(gt)
    return expanded


def score_against_profile(observed: dict, apt_group: dict) -> dict:
    """
    Score observed TTPs against a single APT group profile.
    Returns detailed scoring breakdown.
    """
    observed_techniques = set(observed.get("techniques", []))
    observed_contexts = observed.get("context_signals", [])
    tactic_scores = {}
    matched_per_tactic = {}
    total_matched = []

    all_group_techniques = set()
    for tactic, techs in apt_group["ttps"].items():
        all_group_techniques.update(techs)

    weighted_score = 0.0
    tactic_hits = 0
    for tactic, weight in TACTIC_WEIGHTS.items():
        group_techs = set(apt_group["ttps"].get(tactic, []))
        if not group_techs:
            continue

        expanded_observed = _expand_techniques(observed_techniques, group_techs)

        # Blend recall/precision to avoid biasing toward smaller profiles.
        tactic_recall = recall_similarity(expanded_observed, group_techs)
        tactic_precision = precision_similarity(expanded_observed, group_techs)
        tactic_blend = (0.6 * tactic_recall) + (0.4 * tactic_precision)
        tactic_scores[tactic] = round(float(tactic_blend), 3)  # type: ignore[call-overload]
        weighted_score += weight * tactic_blend

        matched = sorted(expanded_observed & group_techs)
        matched_per_tactic[tactic] = matched
        total_matched.extend(matched)
        if matched:
            tactic_hits += 1

    # Overall cosine similarity
    all_observed_expanded = _expand_techniques(observed_techniques, all_group_techniques)
    overall_recall = recall_similarity(all_observed_expanded, all_group_techniques)
    overall_precision = precision_similarity(all_observed_expanded, all_group_techniques)
    overall_sim = cosine_similarity_sets(
        all_observed_expanded,
        all_group_techniques,
        all_group_techniques | all_observed_expanded,
    )

    global_overlap = (0.4 * overall_recall) + (0.4 * overall_precision) + (0.2 * overall_sim)
    base_score = (weighted_score * 0.55) + (global_overlap * 0.45)

    # Context boosts
    context_boost: float = 0.0
    triggered_contexts = []
    for signal in observed_contexts:
        if signal in CONTEXT_BOOST_MAP:
            group_name = apt_group["name"]
            boost = CONTEXT_BOOST_MAP[signal].get(group_name, 0)
            if boost > 0:
                context_boost += float(boost)  # type: ignore[operator]
                triggered_contexts.append(signal)

    context_boost = float(min(context_boost, 0.25))
    contradiction_penalty, contradiction_signals = _compute_context_contradiction_penalty(
        observed_contexts,
        apt_group,
    )
    motivation_boost, motivation_penalty, matched_motives, mismatched_motives, inferred_motives = (
        _compute_motivation_alignment(observed, apt_group)
    )
    final_score: float = float(
        min(
            max(
                base_score
                + (context_boost * 0.25)
                + motivation_boost
                - contradiction_penalty
                - motivation_penalty,
                0.0,
            ),
            1.0,
        )
    )  # type: ignore[operator]

    # Confidence adjustment favors broad, multi-tactic evidence.
    technique_completeness = min(len(observed_techniques) / 10.0, 1.0)
    tactic_coverage = min(tactic_hits / 5.0, 1.0)
    evidence_breadth = (technique_completeness * 0.6) + (tactic_coverage * 0.4)
    confidence_multiplier = 0.35 + (0.65 * evidence_breadth)
    adjusted_confidence = final_score * confidence_multiplier

    # Derive longevity from active_since
    active_since = apt_group.get("active_since", 2020)
    years_active = max(datetime.utcnow().year - active_since, 1)
    longevity = min(round(float(years_active) / 2.0, 1), 10)  # type: ignore[call-overload]

    behavioral_dna = apt_group.get("behavioral_dna", {})

    return {
        "group": apt_group["name"],
        "nation": apt_group["nation"],
        "flag": apt_group["flag"],
        "aliases": apt_group["aliases"],
        "raw_score": round(float(base_score), 4),  # type: ignore[call-overload]
        "context_boost": round(float(context_boost), 4),  # type: ignore[call-overload]
        "contradiction_penalty": round(float(contradiction_penalty), 4),  # type: ignore[call-overload]
        "motivation_boost": round(float(motivation_boost), 4),  # type: ignore[call-overload]
        "motivation_penalty": round(float(motivation_penalty), 4),  # type: ignore[call-overload]
        "final_score": round(float(final_score), 4),  # type: ignore[call-overload]
        "confidence": round(float(adjusted_confidence), 4),  # type: ignore[call-overload]
        "confidence_pct": round(float(adjusted_confidence) * 100, 1),  # type: ignore[call-overload]
        "tactic_scores": tactic_scores,
        "tactic_hit_count": tactic_hits,
        "matched_techniques": sorted(set(total_matched)),
        "matched_per_tactic": matched_per_tactic,
        "context_signals": triggered_contexts,
        "contradiction_signals": contradiction_signals,
        "matched_motives": matched_motives,
        "mismatched_motives": mismatched_motives,
        "inferred_motives": inferred_motives,
        "motivation": apt_group["motivation"],
        "target_sectors": apt_group["target_sectors"],
        "target_regions": apt_group["target_regions"],
        "known_campaigns": apt_group["known_campaigns"],
        "known_tools": apt_group["known_tools"],
        "behavioral_dna": behavioral_dna,
        "description": apt_group["description"],
        "longevity": longevity,
    }


def _build_tactic_index(profiles: dict) -> dict[str, str]:
    tactic_index: dict[str, str] = {}
    for apt in profiles.get("apt_groups", []):
        for tactic, techniques in apt.get("ttps", {}).items():
            for tech in techniques:
                tactic_index[tech] = tactic
                if "." in tech:
                    tactic_index[tech.split(".")[0]] = tactic
    return tactic_index


def _observed_tactic_coverage(observed_techniques: list[str], profiles: dict) -> int:
    tactic_index = _build_tactic_index(profiles)
    covered: set[str] = set()
    for tech in observed_techniques:
        if tech in tactic_index:
            covered.add(tactic_index[tech])
            continue
        parent = tech.split(".")[0] if "." in tech else tech
        if parent in tactic_index:
            covered.add(tactic_index[parent])
    return len(covered)


def _infer_emerging_cluster(observed_features: dict) -> dict:
    observed_techniques = sorted(set(observed_features.get("techniques", [])))
    observed_contexts = sorted(set(observed_features.get("context_signals", [])))
    signature = "|".join(observed_techniques + observed_contexts)
    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[0:8].upper()
    cluster_id = f"CLUSTER-{datetime.utcnow().strftime('%Y%m')}-{digest}"
    return {
        "cluster_id": cluster_id,
        "label": "EMERGING_CLUSTER",
        "summary": "Observed behavior does not cleanly map to any known APT profile.",
        "seed_techniques": observed_techniques[0:12],  # type: ignore[index]
        "seed_context": observed_contexts,
    }


def run_attribution(
    observed_features: dict,
    profiles: Optional[dict] = None,
    persist_emerging: bool = True,
) -> dict:
    """
    Main attribution function.  Scores observed features against all APT
    groups and returns ranked results with full analysis.
    """
    if profiles is None:
        profiles = load_profiles()

    results = []
    for apt in profiles["apt_groups"]:
        score = score_against_profile(observed_features, apt)
        results.append(score)

    results.sort(key=lambda x: x["confidence"], reverse=True)

    top_score = results[0]["confidence_pct"] if results else 0
    second_score = results[1]["confidence_pct"] if len(results) > 1 else 0
    top_raw = results[0]["raw_score"] if results else 0
    lead_pct = top_score - second_score

    observed_techniques = observed_features.get("techniques", [])
    observed_technique_count = observed_features.get("technique_count", 0)
    observed_tactic_coverage = _observed_tactic_coverage(observed_techniques, profiles)

    passes_gates = bool(results) and all([
        observed_technique_count >= ATTRIBUTION_GATES["min_techniques"],
        observed_tactic_coverage >= ATTRIBUTION_GATES["min_tactic_coverage"],
        top_score >= ATTRIBUTION_GATES["min_top_confidence_pct"],
        top_raw >= ATTRIBUTION_GATES["min_top_raw_score"],
        lead_pct >= ATTRIBUTION_GATES["min_lead_pct"],
    ])

    top_attribution = results[0] if passes_gates else None
    top_hypothesis = results[0] if results else None
    emerging_cluster = None

    top_similarity = results[0]["final_score"] if results else 0
    is_novel = (
        bool(results)
        and observed_technique_count >= 4
        and top_similarity < ATTRIBUTION_GATES["novelty_similarity_threshold"]
        and (lead_pct < ATTRIBUTION_GATES["min_lead_pct"] or observed_tactic_coverage <= 2)
    )
    if is_novel:
        emerging_cluster = _infer_emerging_cluster(observed_features)
        if persist_emerging:
            hypotheses = [
                {
                    "group": r["group"],
                    "nation": r["nation"],
                    "confidence_pct": r["confidence_pct"],
                }
                for r in results[0:3]
            ]
            persisted = upsert_emerging_cluster(
                emerging_cluster["cluster_id"],
                observed_features,
                hypotheses,
            )
            emerging_cluster["memory"] = {
                "status": persisted.get("status", "EMERGING"),
                "sightings": persisted.get("sightings", 1),
                "first_seen": persisted.get("first_seen"),
                "last_seen": persisted.get("last_seen"),
            }

    if top_attribution and top_score >= 70:
        tier = "HIGH"
        tier_color = "#22c55e"
    elif top_attribution and top_score >= 45:
        tier = "MEDIUM"
        tier_color = "#f59e0b"
    elif top_attribution and top_score >= 20:
        tier = "LOW"
        tier_color = "#ef4444"
    elif emerging_cluster:
        tier = "EMERGING CLUSTER"
        tier_color = "#60a5fa"
    else:
        tier = "INSUFFICIENT DATA"
        tier_color = "#6b7280"

    drift_warning = None
    if top_attribution and results[0]["raw_score"] < 0.25 and results[0]["context_boost"] > 0.15:
        drift_warning = (
            f"Attribution leans on behavioral context signals more than TTP overlap. "
            f"{results[0]['group']} may have rotated techniques. Consider TTP drift."
        )

    return {
        "top_attribution": top_attribution,
        "top_hypothesis": top_hypothesis,
        "ranked_results": results,
        "confidence_tier": tier,
        "confidence_color": tier_color,
        "drift_warning": drift_warning,
        "observed_technique_count": observed_technique_count,
        "observed_tactic_coverage": observed_tactic_coverage,
        "attribution_gate_passed": passes_gates,
        "attribution_gate_thresholds": ATTRIBUTION_GATES,
        "lead_pct": round(float(lead_pct), 1),
        "emerging_cluster": emerging_cluster,
        "observed_techniques": observed_techniques,
        "matched_keywords": observed_features.get("matched_keywords", []),
        "context_signals": observed_features.get("context_signals", []),
        "iocs": observed_features.get("iocs", {}),
        "technique_descriptions": profiles.get("technique_descriptions", {}),
    }


def get_technique_name(technique_id: str, descriptions: dict) -> str:
    """Get human-readable name for a technique ID."""
    if technique_id in descriptions:
        return descriptions[technique_id]
    parent = technique_id.split(".")[0] if "." in technique_id else technique_id
    if parent in descriptions:
        return descriptions[parent] + " (variant)"
    return technique_id


# -- Malware Retracing -------------------------------------------------------

@st.cache_data
def load_malware_family_db(data_path: Optional[Path] = None) -> dict:
    db_path = (
        Path(data_path)
        if data_path
        else next(
            (p for p in _MALWARE_DB_CANDIDATES if p.exists()),
            _MALWARE_DB_CANDIDATES[0],
        )
    )
    if not db_path.exists():
        searched = ", ".join(str(p) for p in _MALWARE_DB_CANDIDATES)
        raise FileNotFoundError(f"Malware family DB not found. Looked for: {searched}")
    with open(db_path, encoding="utf-8") as fh:
        return json.load(fh)


def _extract_ascii_strings(file_bytes: bytes, min_len: int = 5, limit: int = 600) -> list[str]:
    pattern = rb"[\x20-\x7E]{" + str(min_len).encode("ascii") + rb",}"
    strings: list[str] = [
        s.decode("utf-8", errors="ignore").strip()
        for s in re.findall(pattern, file_bytes)
    ]
    filtered: list[str] = [s for s in strings if s]
    return filtered[:limit]  # type: ignore[index]


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    counter = collections.Counter(data)
    len_data = len(data)
    entropy = -sum((count / len_data) * math.log2(count / len_data) for count in counter.values())
    return round(entropy, 4)


def _parse_pe_metadata(file_bytes: bytes) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "is_pe": False,
        "imports": [],
        "import_tokens": [],
        "imphash": None,
        "compile_timestamp": None,
        "section_names": [],
        "parse_error": None,
    }
    if not file_bytes.startswith(b"MZ"):
        return parsed

    parsed["is_pe"] = True
    try:
        import pefile  # type: ignore
    except ImportError:
        parsed["parse_error"] = "pefile not installed"
        return parsed

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imports = []
        import_tokens: set = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore").lower()
                imports.append(dll)
                import_tokens.add(dll)
                for imp in entry.imports:
                    if imp.name:
                        fn = imp.name.decode("utf-8", errors="ignore").lower()
                        token = f"{dll}:{fn}"
                        imports.append(token)
                        import_tokens.add(fn)
                        import_tokens.add(token)

        parsed["imports"] = sorted(set(imports))
        parsed["import_tokens"] = sorted(import_tokens)
        try:
            parsed["imphash"] = pe.get_imphash()
        except Exception:
            parsed["imphash"] = None
        try:
            ts = int(pe.FILE_HEADER.TimeDateStamp)
            parsed["compile_timestamp"] = ts if ts > 0 else None
        except Exception:
            parsed["compile_timestamp"] = None
        parsed["section_names"] = [
            s.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            for s in getattr(pe, "sections", [])
        ]
        parsed["sections"] = []
        for s in getattr(pe, "sections", []):
            name = s.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            s_data = s.get_data()
            parsed["sections"].append({
                "name": name,
                "size": s.SizeOfRawData,
                "entropy": _calculate_entropy(s_data) if s_data else 0.0,
                "is_executable": bool(s.Characteristics & 0x20000000),
            })
        
        # Exports
        parsed["export_count"] = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            parsed["export_count"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
        parsed["overall_entropy"] = _calculate_entropy(file_bytes)
    except Exception as exc:
        parsed["parse_error"] = str(exc)

    return parsed


def extract_static_indicators(file_bytes: bytes, filename: str = "sample.bin") -> dict[str, Any]:
    lowered_name = (filename or "sample.bin").lower()
    ext = lowered_name.rsplit(".", 1)[-1] if "." in lowered_name else "bin"
    ascii_strings = _extract_ascii_strings(file_bytes)
    pe_meta = _parse_pe_metadata(file_bytes)
    joined = "\n".join(ascii_strings).lower()

    url_re = r"https?://[a-zA-Z0-9./?\&=_:-]+"
    domain_re = r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|ir|kp|biz|info)\b"
    ip_re = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return {
        "filename": filename,
        "file_type": ext,
        "size_bytes": len(file_bytes),
        "hashes": {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        },
        "strings": ascii_strings,
        "strings_lower": [s.lower() for s in ascii_strings],
        "imports": pe_meta["imports"],
        "import_tokens": pe_meta["import_tokens"],
        "imphash": pe_meta["imphash"],
        "is_pe": pe_meta["is_pe"],
        "compile_timestamp": pe_meta["compile_timestamp"],
        "section_names": pe_meta["section_names"],
        "urls": list(sorted(set(re.findall(url_re, joined))))[0:20],  # type: ignore[index]
        "domains": list(sorted(set(re.findall(domain_re, joined))))[0:30],  # type: ignore[index]
        "ips": list(sorted(set(re.findall(ip_re, joined))))[0:30],  # type: ignore[index]
        "parse_error": pe_meta["parse_error"],
    }


def _normalize_hash(hash_value: str) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", hash_value or "").lower()


def _score_family(static_features: Optional[dict[str, Any]], normalized_hash: str, family: dict) -> dict:
    score = 0.0
    reasons = []

    known_hashes = [h.lower() for h in family.get("known_hashes", [])]
    known_prefixes = [p.lower() for p in family.get("known_hash_prefixes", [])]
    known_imphashes = [h.lower() for h in family.get("known_imphashes", [])]

    observed_hashes: set = set()
    if static_features:
        observed_hashes = {
            static_features["hashes"]["md5"],
            static_features["hashes"]["sha1"],
            static_features["hashes"]["sha256"],
        }

    hash_hit = None
    for h in observed_hashes:
        if h in known_hashes:
            hash_hit = h
            break
    if not hash_hit and normalized_hash:
        if normalized_hash in known_hashes:
            hash_hit = normalized_hash

    if hash_hit:
        score += 0.55
        reasons.append(f"Exact hash match ({str(hash_hit)[:12]}...)")  # type: ignore[index]
    elif normalized_hash and known_prefixes:
        prefix = next((p for p in known_prefixes if normalized_hash.startswith(p)), None)
        if prefix:
            score += 0.30
            reasons.append(f"Hash prefix match ({prefix})")

    if static_features:
        observed_imphash = (static_features.get("imphash") or "").lower()
        if observed_imphash and observed_imphash in known_imphashes:
            score += 0.25
            reasons.append(f"Import hash match ({str(observed_imphash)[:12]}...)")  # type: ignore[index]

        import_tokens = set(static_features.get("import_tokens", []))
        import_needles = {k.lower() for k in family.get("import_keywords", [])}
        if import_needles and import_tokens:
            hit = {k for k in import_needles if any(k in token for token in import_tokens)}
            if hit:
                ratio = len(hit) / len(import_needles)
                score += 0.20 * ratio
                hit_list = list(sorted(list(hit)))
                reasons.append(f"Import overlap: {', '.join(hit_list[0:6])}")  # type: ignore[index]

        strings_lower = set(static_features.get("strings_lower", []))
        string_needles = {k.lower() for k in family.get("string_keywords", [])}
        if string_needles and strings_lower:
            hit_strings = {
                k for k in string_needles if any(k in observed for observed in strings_lower)
            }
            if hit_strings:
                ratio = len(hit_strings) / len(string_needles)
                score += 0.18 * ratio
                hit_str_list = list(sorted(list(hit_strings)))
                reasons.append(f"String overlap: {', '.join(hit_str_list[0:6])}")  # type: ignore[index]

        behavior_needles = {k.lower() for k in family.get("behavior_keywords", [])}
        if behavior_needles and strings_lower:
            hit_behavior = {
                k for k in behavior_needles if any(k in observed for observed in strings_lower)
            }
            if hit_behavior:
                ratio = len(hit_behavior) / len(behavior_needles)
                score += 0.07 * ratio
                hit_beh_list = list(sorted(list(hit_behavior)))
                reasons.append(
                    f"Behavioral trait overlap: {', '.join(hit_beh_list[0:6])}"  # type: ignore[index]
                )

        file_type = static_features.get("file_type")
        if file_type and file_type in family.get("file_types", []):
            score += 0.05
            reasons.append(f"File type aligned ({file_type})")

    score = min(score, 1.0)
    return {
        "family": family["family"],
        "cluster": family["cluster"],
        "summary": family.get("summary", ""),
        "geo_context": family.get("geo_context", ""),
        "confidence": round(float(score), 4),  # type: ignore[call-overload]
        "confidence_pct": round(float(score) * 100, 1),  # type: ignore[call-overload]
        "matched_indicators": reasons,
    }


def run_malware_retracing(
    file_bytes: Optional[bytes] = None,
    filename: str = "",
    hash_value: str = "",
    family_db: Optional[dict] = None,
    top_k: int = 5,
) -> dict:
    """
    Malware retracing pipeline:
    - Accepts a malware file and/or hash
    - Extracts static indicators
    - Compares against known family fingerprints
    - Returns explainable attribution ranking
    """
    normalized_hash = _normalize_hash(hash_value)
    if not file_bytes and not normalized_hash:
        raise ValueError("Provide a malware file or a hash value.")

    if family_db is None:
        family_db = load_malware_family_db()

    static_features = None
    hash_mismatch = None
    if file_bytes:
        static_features = extract_static_indicators(file_bytes, filename=filename or "sample.bin")
        if normalized_hash and normalized_hash not in set(static_features["hashes"].values()):
            hash_mismatch = (
                "Provided hash does not match uploaded file hashes (MD5/SHA1/SHA256). "
                "Using file-derived hashes for scoring."
            )
        normalized_hash = static_features["hashes"]["sha256"]

    vt_report = None
    if normalized_hash:
        vt_report = vt_client.get_file_report(normalized_hash)

    ranked = []
    for family in family_db.get("families", []):
        ranked.append(_score_family(static_features, normalized_hash, family))
    ranked.sort(key=lambda x: x["confidence"], reverse=True)
    ranked_list: list[dict] = list(ranked)
    ranked_list = ranked_list[0: max(1, int(top_k))]  # type: ignore[index]
    top = ranked_list[0] if ranked_list else None

    mode = "file+hash" if file_bytes and hash_value else "file" if file_bytes else "hash"
    verdict = "UNATTRIBUTED"
    if top:
        if top["confidence_pct"] >= 70:
            verdict = "HIGH CONFIDENCE"
        elif top["confidence_pct"] >= 45:
            verdict = "MODERATE CONFIDENCE"
        elif top["confidence_pct"] >= 20:
            verdict = "LOW CONFIDENCE"

    return {
        "analysis_mode": mode,
        "verdict": verdict,
        "hash_input": hash_value,
        "hash_mismatch": hash_mismatch,
        "top_match": top,
        "ranked_matches": ranked,
        "extracted_static": static_features,
        "external_intel": {"virustotal": vt_report} if vt_report else None,
    }
