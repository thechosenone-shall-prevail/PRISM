"""
PRISM Sandbox Bridge Module
Connects malware sandbox analysis to APT attribution engine

Supports:
- Static analysis → TTP extraction
- Sandbox report parsing → MITRE techniques
- Malware family → APT group mapping
"""

from typing import Dict, List, Optional, Any
import re
import json
from pathlib import Path

# In-memory cache of recent static analysis results.
# Key = sha256 hash, value = full analysis report dict.
# Used by blast_radius to build real graphs from uploaded files.
_analysis_cache: Dict[str, Dict[str, Any]] = {}


def get_cached_analysis(sha256: str) -> Optional[Dict[str, Any]]:
    """Return cached static analysis for a hash, or None."""
    return _analysis_cache.get(sha256.lower())

# Malware Family → APT Group Mapping
MALWARE_FAMILY_TO_APT = {
    # Lazarus Group (North Korea)
    "fallchill": "Lazarus Group",
    "manuscrypt": "Lazarus Group",
    "hoplight": "Lazarus Group",
    "bistromath": "Lazarus Group",
    "dacls": "Lazarus Group",
    "bankshot": "Lazarus Group",
    
    # APT28 (Russia)
    "x-agent": "APT28",
    "sofacy": "APT28",
    "zebrocy": "APT28",
    "cannon": "APT28",
    
    # APT29 (Russia)
    "wellmess": "APT29",
    "sunburst": "APT29",
    "teardrop": "APT29",
    "raindrop": "APT29",
    "cobalt strike": "APT29",
    
    # Sandworm (Russia)
    "industroyer": "Sandworm",
    "industroyer2": "Sandworm",
    "notpetya": "Sandworm",
    "olympicdestroyer": "Sandworm",
    
    # APT41 (China)
    "shadowpad": "APT41",
    "dustpan": "APT41",
    "speculoos": "APT41",
    "crosswalk": "APT41",
    
    # APT35 (Iran)
    "charming kitten": "APT35",
    "powerless": "APT35",
    "hyperscrape": "APT35",
    
    # Kimsuky (North Korea)
    "babyshark": "Kimsuky",
    "appleseed": "Kimsuky",
    "kimsuky": "Kimsuky",
    
    # Transparent Tribe (Pakistan)
    "crimsonrat": "Transparent Tribe",
    "obliquerat": "Transparent Tribe",
    
    # Turla (Russia)
    "kazuar": "Turla",
    "carbon": "Turla",
    "snake": "Turla",
}

# Behavioral Indicators → MITRE Techniques
BEHAVIOR_TO_TTP = {
    # Process Creation
    "powershell.exe": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "wscript.exe": ["T1059.005"],
    "cscript.exe": ["T1059.005"],
    "python.exe": ["T1059.006"],
    "wmic.exe": ["T1047"],
    "schtasks.exe": ["T1053.005"],
    "at.exe": ["T1053.002"],
    "sc.exe": ["T1569.002"],
    "net.exe": ["T1087", "T1069"],
    "reg.exe": ["T1112"],
    "rundll32.exe": ["T1218.011"],
    "regsvr32.exe": ["T1218.010"],
    "mshta.exe": ["T1218.005"],
    "certutil.exe": ["T1218.003"],
    
    # Registry Operations
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": ["T1547.001"],
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": ["T1547.001"],
    "CurrentVersion\\Run": ["T1547.001"],
    "\\Services\\": ["T1543.003"],
    "\\Winlogon\\": ["T1547.004"],
    
    # File Operations
    "\\AppData\\Roaming\\": ["T1105", "T1074.001"],
    "\\Temp\\": ["T1105", "T1074.001"],
    "\\ProgramData\\": ["T1105"],
    ".exe": ["T1105"],
    ".dll": ["T1574.002"],
    ".bat": ["T1059.003"],
    ".ps1": ["T1059.001"],
    ".vbs": ["T1059.005"],
    
    # Network Operations
    "http://": ["T1071.001"],
    "https://": ["T1071.001"],
    "tcp": ["T1071.001"],
    "dns": ["T1071.004"],
    "443": ["T1071.001"],
    "8080": ["T1071.001"],
    "4444": ["T1071.001"],
    
    # Credential Access
    "lsass.exe": ["T1003.001"],
    "mimikatz": ["T1003.001"],
    "procdump": ["T1003.001"],
    "sam": ["T1003.002"],
    "ntds.dit": ["T1003.003"],
    
    # Defense Evasion
    "vssadmin": ["T1490"],
    "bcdedit": ["T1490"],
    "wbadmin": ["T1490"],
    "shadowcopy": ["T1490"],
    "taskkill": ["T1562.001"],
    "disable": ["T1562.001"],
    
    # Discovery
    "ipconfig": ["T1016"],
    "systeminfo": ["T1082"],
    "whoami": ["T1033"],
    "tasklist": ["T1057"],
    "netstat": ["T1049"],
    "net view": ["T1018"],
    "net user": ["T1087"],
    "net group": ["T1069"],
    
    # Lateral Movement
    "psexec": ["T1021.002"],
    "wmiexec": ["T1021.003"],
    "rdp": ["T1021.001"],
    "smb": ["T1021.002"],
    
    # Collection
    "screenshot": ["T1113"],
    "keylog": ["T1056.001"],
    "clipboard": ["T1115"],
    
    # Exfiltration
    "upload": ["T1041"],
    "exfil": ["T1041"],
    "ftp": ["T1048.003"],
}


def extract_ttps_from_static_analysis(static_features: Dict[str, Any]) -> List[str]:
    """
    Extract MITRE TTPs from static malware analysis features.
    
    Args:
        static_features: Dict containing hashes, imports, strings, etc.
    
    Returns:
        List of MITRE technique IDs
    """
    ttps = set()
    
    # Check imports against the comprehensive _SUSPICIOUS_IMPORTS categories
    imports = static_features.get("imports", [])
    for imp in imports:
        imp_lower = imp.lower()
        for category in _SUSPICIOUS_IMPORTS.values():
            for api in category["apis"]:
                if api in imp_lower:
                    ttps.add(category["ttp"])
                    break  # one match per category per import is enough
        # Additional import-level checks not covered by _SUSPICIOUS_IMPORTS
        if "regcreatekeyex" in imp_lower or "regsetvalueex" in imp_lower:
            ttps.add("T1112")  # Modify Registry (direct value modification)
        if "createprocess" in imp_lower:
            ttps.add("T1106")  # Native API (process creation)
    
    # Check strings
    strings = static_features.get("strings", [])
    for string in strings:
        string_lower = string.lower()
        for pattern, techniques in BEHAVIOR_TO_TTP.items():
            if pattern.lower() in string_lower:
                ttps.update(techniques)
    
    # Check entropy (packed/encrypted)
    entropy = static_features.get("entropy", 0)
    if entropy > 7.0:
        ttps.add("T1027.002")  # Software Packing
    
    return sorted(list(ttps))


def extract_ttps_from_sandbox_report(sandbox_report: Dict[str, Any]) -> List[str]:
    """
    Extract MITRE TTPs from sandbox execution report.
    
    Args:
        sandbox_report: Dict containing process tree, network, registry, file operations
    
    Returns:
        List of MITRE technique IDs
    """
    ttps = set()
    
    # Process creation
    processes = sandbox_report.get("processes", [])
    for proc in processes:
        proc_name = proc.get("name", "").lower()
        for pattern, techniques in BEHAVIOR_TO_TTP.items():
            if pattern.lower() in proc_name:
                ttps.update(techniques)
    
    # Registry operations
    registry_ops = sandbox_report.get("registry", [])
    for reg_op in registry_ops:
        reg_path = reg_op.get("path", "").lower()
        for pattern, techniques in BEHAVIOR_TO_TTP.items():
            if pattern.lower() in reg_path:
                ttps.update(techniques)
    
    # File operations
    file_ops = sandbox_report.get("files", [])
    for file_op in file_ops:
        file_path = file_op.get("path", "").lower()
        for pattern, techniques in BEHAVIOR_TO_TTP.items():
            if pattern.lower() in file_path:
                ttps.update(techniques)
    
    # Network operations
    network_ops = sandbox_report.get("network", [])
    for net_op in network_ops:
        dest = net_op.get("destination", "").lower()
        protocol = net_op.get("protocol", "").lower()
        
        if "http" in protocol or "http" in dest:
            ttps.add("T1071.001")
        if "dns" in protocol:
            ttps.add("T1071.004")
        if net_op.get("port") in [443, 8080, 4444]:
            ttps.add("T1071.001")
    
    return sorted(list(ttps))


def map_malware_family_to_apt(family_name: str) -> Optional[str]:
    """
    Map malware family to APT group.
    
    Args:
        family_name: Malware family name (e.g., "Manuscrypt")
    
    Returns:
        APT group name or None
    """
    family_lower = family_name.lower()
    return MALWARE_FAMILY_TO_APT.get(family_lower)


def create_attribution_payload_from_malware(
    static_features: Dict[str, Any],
    sandbox_report: Optional[Dict[str, Any]] = None,
    malware_family: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create attribution engine payload from malware analysis.
    
    Args:
        static_features: Static analysis results
        sandbox_report: Optional sandbox execution report
        malware_family: Optional identified malware family
    
    Returns:
        Payload dict for attribution engine
    """
    # Extract TTPs from static analysis
    static_ttps = extract_ttps_from_static_analysis(static_features)
    
    # Extract TTPs from sandbox if available
    sandbox_ttps = []
    if sandbox_report:
        sandbox_ttps = extract_ttps_from_sandbox_report(sandbox_report)
    
    # Combine all TTPs
    all_ttps = sorted(list(set(static_ttps + sandbox_ttps)))
    
    # Build context signals
    context_signals = []
    
    # Add malware family as context
    if malware_family:
        apt_group = map_malware_family_to_apt(malware_family)
        if apt_group:
            context_signals.append(f"malware_family:{malware_family}")
            context_signals.append(f"known_apt:{apt_group}")
    
    # Build attribution payload
    payload = {
        "techniques": all_ttps,
        "context_signals": context_signals,
        "technique_count": len(all_ttps),
        "source": "malware_analysis",
        "malware_family": malware_family,
        "static_features": {
            "entropy": static_features.get("entropy", 0),
            "imphash": static_features.get("hashes", {}).get("imphash", ""),
            "imports_count": len(static_features.get("imports", [])),
            "strings_count": len(static_features.get("strings", []))
        }
    }
    
    if sandbox_report:
        payload["sandbox_executed"] = True
        payload["runtime_behaviors"] = {
            "processes": len(sandbox_report.get("processes", [])),
            "registry_ops": len(sandbox_report.get("registry", [])),
            "file_ops": len(sandbox_report.get("files", [])),
            "network_ops": len(sandbox_report.get("network", []))
        }
    
    return payload


def analyze_uploaded_file(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Perform REAL static analysis on an uploaded file and generate timeline events
    based on actual indicators found in the binary.

    This does NOT execute the malware. It performs:
    - PE header parsing (imports, sections, compile timestamp, entropy)
    - String extraction (URLs, IPs, domains, registry keys, commands)
    - TTP mapping from found indicators
    - Timeline generation from real discovered artifacts

    Returns a sandbox-compatible report dict with real data.
    """
    import hashlib
    from datetime import datetime

    # --- Step 1: Compute hashes ---
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()

    # --- Step 2: Run engine's static analysis ---
    try:
        from engine import extract_static_indicators, _calculate_entropy
        static = extract_static_indicators(file_bytes, filename)
    except Exception as e:
        static = {
            "filename": filename, "file_type": "bin",
            "size_bytes": len(file_bytes), "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
            "strings": [], "imports": [], "import_tokens": [],
            "imphash": None, "is_pe": False, "compile_timestamp": None,
            "section_names": [], "urls": [], "domains": [], "ips": [],
            "parse_error": str(e),
        }

    # --- Step 3: Extract TTPs from static indicators ---
    static_ttps = extract_ttps_from_static_analysis(static)

    # --- Step 4: Build timeline from REAL indicators ---
    timeline = _build_real_timeline(static, static_ttps, filename)

    # --- Step 5: Build structured sandbox report ---
    # Extract process-like indicators from strings
    processes = []
    registry_ops = []
    file_ops = []
    network_ops = []

    for s in static.get("strings", []):
        sl = s.lower()
        # Process indicators
        for proc in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
                      "regsvr32", "certutil", "schtasks", "wmic", "net.exe", "sc.exe"]:
            if proc in sl:
                processes.append({"name": proc, "source": "string_extraction", "raw": s[:200]})
        # Registry indicators
        for reg in ["currentversion\\run", "\\services\\", "\\winlogon\\", "hklm\\", "hkcu\\"]:
            if reg in sl:
                registry_ops.append({"operation": "referenced", "path": s[:300], "source": "string_extraction"})
        # File path indicators
        for fp in ["\\appdata\\", "\\temp\\", "\\programdata\\", ".exe", ".dll", ".bat", ".ps1"]:
            if fp in sl and len(s) > 5:
                file_ops.append({"operation": "referenced", "path": s[:300], "source": "string_extraction"})
        # Network indicators
        if s.startswith(("http://", "https://", "ftp://")):
            network_ops.append({"protocol": "http", "destination": s[:200], "source": "string_extraction"})

    for ip in static.get("ips", []):
        network_ops.append({"protocol": "tcp", "destination": ip, "source": "static_extraction"})
    for domain in static.get("domains", []):
        network_ops.append({"protocol": "dns", "destination": domain, "source": "static_extraction"})
    for url in static.get("urls", []):
        network_ops.append({"protocol": "http", "destination": url[:200], "source": "static_extraction"})

    report = {
        "status": "static_analysis",
        "analysis_type": "static",
        "filename": filename,
        "file_hash": sha256,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "file_size": len(file_bytes),
        "is_pe": static.get("is_pe", False),
        "imphash": static.get("imphash"),
        "entropy": static.get("overall_entropy", 0) if "overall_entropy" in static else 0,
        "compile_timestamp": static.get("compile_timestamp"),
        "section_names": static.get("section_names", []),
        "processes": processes,
        "registry": registry_ops,
        "files": file_ops,
        "network": network_ops,
        "extracted_ttps": static_ttps,
        "extracted_urls": static.get("urls", []),
        "extracted_domains": static.get("domains", []),
        "extracted_ips": static.get("ips", []),
        "imports": static.get("imports", [])[:50],
        "timeline": timeline,
    }

    # Cache for blast-radius reuse
    _analysis_cache[sha256.lower()] = report
    return report


def analyze_uploaded_file_with_static(
    file_bytes: bytes, filename: str, static: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Like analyze_uploaded_file but reuses pre-computed static analysis results.
    Skips the expensive hashing, string extraction, and PE parsing.
    """
    sha256 = static.get("hashes", {}).get("sha256", "")
    md5 = static.get("hashes", {}).get("md5", "")
    sha1 = static.get("hashes", {}).get("sha1", "")

    # Extract TTPs from static indicators (lightweight)
    static_ttps = extract_ttps_from_static_analysis(static)

    # Build timeline from REAL indicators
    timeline = _build_real_timeline(static, static_ttps, filename)

    # Build structured sandbox report (same logic, just reuses static)
    processes = []
    registry_ops = []
    file_ops = []
    network_ops = []

    for s in static.get("strings", []):
        sl = s.lower()
        for proc in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
                      "regsvr32", "certutil", "schtasks", "wmic", "net.exe", "sc.exe"]:
            if proc in sl:
                processes.append({"name": proc, "source": "string_extraction", "raw": s[:200]})
        for reg in ["currentversion\\run", "\\services\\", "\\winlogon\\", "hklm\\", "hkcu\\"]:
            if reg in sl:
                registry_ops.append({"operation": "referenced", "path": s[:300], "source": "string_extraction"})
        for fp in ["\\appdata\\", "\\temp\\", "\\programdata\\", ".exe", ".dll", ".bat", ".ps1"]:
            if fp in sl and len(s) > 5:
                file_ops.append({"operation": "referenced", "path": s[:300], "source": "string_extraction"})
        if s.startswith(("http://", "https://", "ftp://")):
            network_ops.append({"protocol": "http", "destination": s[:200], "source": "string_extraction"})

    for ip in static.get("ips", []):
        network_ops.append({"protocol": "tcp", "destination": ip, "source": "static_extraction"})
    for domain in static.get("domains", []):
        network_ops.append({"protocol": "dns", "destination": domain, "source": "static_extraction"})
    for url in static.get("urls", []):
        network_ops.append({"protocol": "http", "destination": url[:200], "source": "static_extraction"})

    report = {
        "status": "static_analysis",
        "analysis_type": "static",
        "filename": filename,
        "file_hash": sha256,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "file_size": len(file_bytes),
        "is_pe": static.get("is_pe", False),
        "imphash": static.get("imphash"),
        "entropy": static.get("overall_entropy", 0) if "overall_entropy" in static else 0,
        "compile_timestamp": static.get("compile_timestamp"),
        "section_names": static.get("section_names", []),
        "processes": processes,
        "registry": registry_ops,
        "files": file_ops,
        "network": network_ops,
        "extracted_ttps": static_ttps,
        "extracted_urls": static.get("urls", []),
        "extracted_domains": static.get("domains", []),
        "extracted_ips": static.get("ips", []),
        "imports": static.get("imports", [])[:50],
        "timeline": timeline,
    }

    _analysis_cache[sha256.lower()] = report
    return report


# ── Suspicious import categories for timeline generation ──
_SUSPICIOUS_IMPORTS = {
    "process_injection": {
        "apis": ["createremotethread", "writeprocessmemory", "virtualallocex",
                 "ntwritevirtualmemory", "rtlcreateuserthread", "queueuserapc"],
        "ttp": "T1055", "title": "Process Injection Capability",
        "desc": "Imports indicate ability to inject code into remote processes"
    },
    "credential_access": {
        "apis": ["credreadw", "lsaenumeratelogonsessions", "samiconnect",
                 "credenumeratea", "cryptunprotectdata"],
        "ttp": "T1003", "title": "Credential Access Capability",
        "desc": "Imports suggest credential harvesting functionality"
    },
    "registry_persistence": {
        "apis": ["regcreatekeyex", "regsetvalueex", "regopenkeyex",
                 "regcreatekeyexw", "regsetvalueexw"],
        "ttp": "T1547.001", "title": "Registry Modification Capability",
        "desc": "Imports for registry key creation/modification"
    },
    "networking": {
        "apis": ["internetopena", "internetopenw", "internetconnecta",
                 "httpsendrequesta", "urldownloadtofilea", "winhttp",
                 "wsastartup", "connect", "send", "recv", "gethostbyname"],
        "ttp": "T1071.001", "title": "Network Communication Capability",
        "desc": "Imports for HTTP/network communication"
    },
    "crypto": {
        "apis": ["cryptencrypt", "cryptdecrypt", "cryptcreatehash",
                 "cryptgenrandom", "bcryptencrypt", "bcryptdecrypt"],
        "ttp": "T1027", "title": "Cryptographic Operations",
        "desc": "Imports for encryption/decryption routines"
    },
    "anti_debug": {
        "apis": ["isdebuggerpresent", "checkremotedebuggerpresent",
                 "ntqueryinformationprocess", "outputdebugstringa"],
        "ttp": "T1497.001", "title": "Anti-Debug / Anti-Analysis",
        "desc": "Imports commonly used to detect analysis environments"
    },
    "file_operations": {
        "apis": ["createfilea", "createfilew", "writefile", "readfile",
                 "deletefilea", "movefileex", "copyfile"],
        "ttp": "T1105", "title": "File System Operations",
        "desc": "Imports for file creation, writing, and manipulation"
    },
    "service_manipulation": {
        "apis": ["openscmanager", "createservice", "startservice",
                 "controlservice", "changeserviceconfig"],
        "ttp": "T1543.003", "title": "Service Installation Capability",
        "desc": "Imports for Windows service creation/manipulation"
    },
    "screenshot_keylog": {
        "apis": ["getasynckeystate", "getforegroundwindow", "bitblt",
                 "setwindowshookex", "getdc", "getwindowtext"],
        "ttp": "T1056.001", "title": "Input Capture / Screen Capture",
        "desc": "Imports suggest keylogging or screenshot capability"
    },
    "native_api": {
        "apis": ["ntcreatefile", "ntreadfile", "ntwritefile",
                 "ntclose", "ntdeviceiocontrolfile", "ntcreatesection"],
        "ttp": "T1106", "title": "Direct NT API Usage",
        "desc": "Uses low-level NT APIs to bypass higher-level monitoring"
    },
}


def _build_real_timeline(static: Dict[str, Any], ttps: List[str], filename: str) -> List[Dict[str, Any]]:
    """
    Build timeline events from REAL static analysis results.
    Each event represents an actual artifact found in the file.
    """
    from datetime import datetime
    timeline = []
    t = 0.0
    base_clock = datetime.now().strftime("%H:%M:%S")

    def _clock(offset):
        h, m, s = base_clock.split(":")
        total_s = int(h)*3600 + int(m)*60 + int(s) + int(offset)
        return f"{(total_s//3600)%24:02d}:{(total_s%3600)//60:02d}:{total_s%60:02d}"

    # --- Event 1: File metadata ---
    size_kb = static.get("size_bytes", len(b"")) / 1024
    entropy_val = static.get("overall_entropy", 0) if "overall_entropy" in static else 0
    is_pe = static.get("is_pe", False)
    file_type = static.get("file_type", "unknown")

    details_parts = [f"Size: {size_kb:.1f} KB", f"Type: {file_type.upper()}"]
    if is_pe:
        details_parts.append("Format: PE (Portable Executable)")
    if static.get("imphash"):
        details_parts.append(f"Imphash: {static['imphash']}")
    hashes = static.get("hashes", {})
    if hashes.get("sha256"):
        details_parts.append(f"SHA256: {hashes['sha256']}")
    if hashes.get("md5"):
        details_parts.append(f"MD5: {hashes['md5']}")
    if static.get("compile_timestamp"):
        import time as _time
        try:
            ct = _time.strftime("%Y-%m-%d %H:%M:%S UTC", _time.gmtime(static["compile_timestamp"]))
            details_parts.append(f"Compile Time: {ct}")
        except Exception:
            pass

    timeline.append({
        "timestamp": t, "clock": _clock(t),
        "type": "file", "title": "File Metadata Analysis",
        "description": f"Static analysis of {filename}",
        "details": " | ".join(details_parts),
        "ttp": "T1204.002"
    })

    # --- Event 2: Entropy analysis ---
    if entropy_val > 0:
        t += 0.3
        if entropy_val >= 7.5:
            ent_label = "PACKED/ENCRYPTED — Very high entropy suggests packing or encryption"
        elif entropy_val >= 6.5:
            ent_label = "COMPRESSED/OBFUSCATED — Elevated entropy indicates compression or obfuscation"
        else:
            ent_label = "NORMAL — Entropy within expected range for standard binaries"

        section_details = []
        for sec in static.get("sections", []):
            if isinstance(sec, dict):
                sec_ent = sec.get("entropy", 0)
                sec_name = sec.get("name", "?")
                sec_size = sec.get("size", 0)
                flag = " ⚠ HIGH" if sec_ent > 7.0 else ""
                section_details.append(f"{sec_name}: entropy={sec_ent:.2f} size={sec_size}{flag}")

        details_str = f"Overall Entropy: {entropy_val:.4f}/8.0 — {ent_label}"
        if section_details:
            details_str += " | Sections: " + " | ".join(section_details)

        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "defense_evasion" if entropy_val >= 7.0 else "file",
            "title": "Entropy Analysis",
            "description": ent_label.split("—")[0].strip(),
            "details": details_str,
            "ttp": "T1027.002" if entropy_val >= 7.0 else None
        })

    # --- Event 3: Import analysis (PE files) ---
    imports = static.get("imports", [])
    import_tokens = set(t_str.lower() for t_str in static.get("import_tokens", []))
    if imports:
        t += 0.5
        import_dlls = [i for i in imports if ":" not in i and i.endswith(".dll")]
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "file", "title": "Import Table Analysis",
            "description": f"Found {len(imports)} imports across {len(import_dlls)} DLLs",
            "details": "DLLs: " + ", ".join(import_dlls[:15]) + (" ..." if len(import_dlls) > 15 else ""),
            "ttp": None
        })

        # --- Events 4+: Suspicious import categories ---
        for cat_name, cat_info in _SUSPICIOUS_IMPORTS.items():
            hits = [api for api in cat_info["apis"] if api in import_tokens]
            if hits:
                t += 0.4
                timeline.append({
                    "timestamp": t, "clock": _clock(t),
                    "type": "process" if "injection" in cat_name or "credential" in cat_name else "defense_evasion",
                    "title": cat_info["title"],
                    "description": cat_info["desc"],
                    "details": f"Matched APIs: {', '.join(hits)} | Category: {cat_name.replace('_',' ').title()}",
                    "ttp": cat_info["ttp"]
                })

    # --- Network indicators from strings ---
    urls = static.get("urls", [])
    domains = static.get("domains", [])
    ips = static.get("ips", [])

    if urls:
        t += 0.5
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "network", "title": f"Embedded URLs Found ({len(urls)})",
            "description": "URLs extracted from binary strings — potential C2 or download endpoints",
            "details": " | ".join(urls[:10]) + (" | ..." if len(urls) > 10 else ""),
            "ttp": "T1071.001"
        })

    if domains:
        t += 0.3
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "network", "title": f"Embedded Domains Found ({len(domains)})",
            "description": "Domain names extracted from binary strings",
            "details": " | ".join(domains[:15]) + (" | ..." if len(domains) > 15 else ""),
            "ttp": "T1071.004"
        })

    if ips:
        t += 0.3
        # Filter out common non-malicious IPs
        suspicious_ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255.", "224."))]
        if suspicious_ips:
            timeline.append({
                "timestamp": t, "clock": _clock(t),
                "type": "network", "title": f"Embedded IP Addresses Found ({len(suspicious_ips)})",
                "description": "IP addresses extracted from binary strings — potential C2 infrastructure",
                "details": " | ".join(suspicious_ips[:10]) + (" | ..." if len(suspicious_ips) > 10 else ""),
                "ttp": "T1071.001"
            })

    # --- Registry references in strings ---
    reg_refs = []
    for s in static.get("strings", []):
        sl = s.lower()
        if any(reg in sl for reg in ["hklm\\", "hkcu\\", "hkey_local_machine", "hkey_current_user",
                                       "currentversion\\run", "\\services\\", "\\winlogon\\"]):
            reg_refs.append(s[:200])
    if reg_refs:
        t += 0.4
        unique_regs = list(dict.fromkeys(reg_refs))[:8]
        is_persist = any("run" in r.lower() or "services" in r.lower() for r in unique_regs)
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "registry", "title": f"Registry References Found ({len(reg_refs)})",
            "description": "Registry paths found in strings — " + ("indicates persistence mechanism" if is_persist else "registry interaction detected"),
            "details": " | ".join(unique_regs),
            "ttp": "T1547.001" if is_persist else "T1112"
        })

    # --- Command-line patterns in strings ---
    cmd_refs = []
    for s in static.get("strings", []):
        sl = s.lower()
        if any(cmd in sl for cmd in ["powershell", "cmd /c", "cmd.exe", "schtasks",
                                       "wmic", "certutil", "bitsadmin", "-enc ", "-encoded"]):
            cmd_refs.append(s[:200])
    if cmd_refs:
        t += 0.4
        unique_cmds = list(dict.fromkeys(cmd_refs))[:6]
        has_ps = any("powershell" in c.lower() for c in unique_cmds)
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "process", "title": f"Command Patterns Found ({len(cmd_refs)})",
            "description": "Command-line execution patterns found in strings" + (" — PowerShell usage detected" if has_ps else ""),
            "details": " | ".join(unique_cmds),
            "ttp": "T1059.001" if has_ps else "T1059.003"
        })

    # --- File path references in strings ---
    path_refs = []
    for s in static.get("strings", []):
        sl = s.lower()
        if any(p in sl for p in ["\\appdata\\", "\\temp\\", "\\programdata\\", "\\system32\\",
                                   "\\syswow64\\", "\\startup\\"]):
            path_refs.append(s[:200])
    if path_refs:
        t += 0.3
        unique_paths = list(dict.fromkeys(path_refs))[:8]
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "file", "title": f"Suspicious File Paths ({len(path_refs)})",
            "description": "File system paths found in strings — potential drop locations or targets",
            "details": " | ".join(unique_paths),
            "ttp": "T1074.001"
        })

    # --- TTP summary event ---
    if ttps:
        t += 0.5
        timeline.append({
            "timestamp": t, "clock": _clock(t),
            "type": "process", "title": f"TTP Extraction Complete ({len(ttps)} techniques)",
            "description": "MITRE ATT&CK techniques identified from static analysis indicators",
            "details": "Techniques: " + ", ".join(ttps),
            "ttp": None
        })

    # --- Final: Analysis complete ---
    t += 0.3
    timeline.append({
        "timestamp": t, "clock": _clock(t),
        "type": "file", "title": "Static Analysis Complete",
        "description": f"Analysis finished — {len(timeline)} events generated from real file content",
        "details": f"File: {filename} | SHA256: {static.get('hashes', {}).get('sha256', 'N/A')[:16]}... | PE: {'Yes' if is_pe else 'No'} | TTPs: {len(ttps)} | IOCs: {len(urls)+len(domains)+len(ips)} network indicators",
        "ttp": None
    })

    return timeline


def simulate_sandbox_execution(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Perform real static analysis on uploaded files.
    For backwards compatibility, returns the same dict structure.
    """
    return analyze_uploaded_file(file_bytes, filename)


def simulate_sandbox_execution_with_static(
    file_bytes: bytes, filename: str, static_features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Like simulate_sandbox_execution but reuses pre-computed static_features
    from the retrace pipeline to avoid re-hashing and re-parsing the file.
    """
    return analyze_uploaded_file_with_static(file_bytes, filename, static_features)


def generate_timeline_events(filename: str) -> List[Dict[str, Any]]:
    """
    Generate DEMO timeline events for visualization when no file is uploaded.
    These are clearly marked as demonstration data.
    """
    return [
        {
            "timestamp": 0.0, "clock": "14:32:00",
            "type": "process",
            "title": "[DEMO] Initial Execution",
            "description": f"{filename} started",
            "details": f"PID: 2048 | Parent: explorer.exe",
            "ttp": "T1204.002"
        },
        {
            "timestamp": 0.3,
            "type": "defense_evasion",
            "title": "Anti-Analysis Check",
            "description": "Detected VM environment checks",
            "details": "Queried registry for VMware/VirtualBox artifacts",
            "ttp": "T1497.001"
        },
        {
            "timestamp": 0.8,
            "type": "process",
            "title": "Process Injection",
            "description": "Injected into svchost.exe",
            "details": "PID: 3124 | Method: CreateRemoteThread",
            "ttp": "T1055.001"
        },
        {
            "timestamp": 1.2,
            "type": "file",
            "title": "Dropped Payload",
            "description": "Created C:\\Users\\User\\AppData\\Roaming\\sysupdate.dll",
            "details": "Size: 248 KB | Entropy: 7.8",
            "ttp": "T1105"
        },
        {
            "timestamp": 1.5,
            "type": "registry",
            "title": "Persistence Established",
            "description": "Modified Run key",
            "details": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate",
            "ttp": "T1547.001"
        },
        {
            "timestamp": 2.1,
            "type": "process",
            "title": "PowerShell Execution",
            "description": "Spawned powershell.exe with encoded command",
            "details": "PID: 4512 | Args: -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
            "ttp": "T1059.001"
        },
        {
            "timestamp": 2.8,
            "type": "network",
            "title": "DNS Query",
            "description": "Resolved update.microsoft-cdn.cc",
            "details": "Response: 185.29.8.52 | Suspicious TLD",
            "ttp": "T1071.004"
        },
        {
            "timestamp": 3.2,
            "type": "network",
            "title": "C2 Connection",
            "description": "HTTPS connection to 185.29.8.52:443",
            "details": "TLS handshake | Beacon interval: 60s",
            "ttp": "T1071.001"
        },
        {
            "timestamp": 4.5,
            "type": "process",
            "title": "Credential Dumping",
            "description": "Accessed lsass.exe memory",
            "details": "PID: 624 | Method: MiniDumpWriteDump",
            "ttp": "T1003.001"
        },
        {
            "timestamp": 5.2,
            "type": "file",
            "title": "Data Collection",
            "description": "Enumerated cryptocurrency wallet files",
            "details": "Searched for *.wallet, *.dat in user directories",
            "ttp": "T1005"
        },
        {
            "timestamp": 6.1,
            "type": "registry",
            "title": "Security Bypass",
            "description": "Disabled Windows Defender",
            "details": "Set DisableAntiSpyware = 1",
            "ttp": "T1562.001"
        },
        {
            "timestamp": 7.3,
            "type": "process",
            "title": "Scheduled Task",
            "description": "Created persistence task",
            "details": "schtasks.exe /create /tn SystemUpdate /tr C:\\...\\sysupdate.dll",
            "ttp": "T1053.005"
        },
        {
            "timestamp": 8.9,
            "type": "network",
            "title": "Data Exfiltration",
            "description": "Uploaded 2.4 MB to C2 server",
            "details": "POST /api/upload | Encrypted payload",
            "ttp": "T1041"
        },
        {
            "timestamp": 10.2,
            "type": "file",
            "title": "Log Cleanup",
            "description": "Deleted Windows event logs",
            "details": "wevtutil.exe cl Security",
            "ttp": "T1070.001"
        },
        {
            "timestamp": 11.5,
            "type": "process",
            "title": "Self-Deletion",
            "description": "Removed original executable",
            "details": "cmd.exe /c del /f /q " + filename,
            "ttp": "T1070.004"
        }
    ]
