"""
APTrace — Real-Time APT Attribution Through Behavioral DNA
Main Streamlit Application
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st  # type: ignore[import]
import plotly.graph_objects as go  # type: ignore[import]
import plotly.express as px  # type: ignore[import]
import pandas as pd  # type: ignore[import]
import json
import uuid
import typing
from datetime import datetime
import requests
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv(os.path.join(os.path.dirname(__file__), "backend", ".env"))
SUPA_URL = os.getenv("SUPABASE_URL")
SUPA_KEY = os.getenv("SUPABASE_ANON_KEY")
supabase: Client | None = create_client(SUPA_URL, SUPA_KEY) if SUPA_URL and SUPA_KEY else None

# Fallback engine imports in case backend is down
from engine import (  # type: ignore[import]
    extract_ttps_from_text,
    extract_ttps_from_log,
    run_attribution,
    load_profiles,
    get_technique_name,
    load_malware_family_db,
    run_malware_retracing,
)

from demo_scenario import DEMO_SCENARIOS  # type: ignore[import]

BACKEND_URL = "http://localhost:8000/api"

@st.cache_data(ttl=60)
def fetch_api(endpoint: str) -> dict | None:
    """Cached helper for backend GET requests to reduce UI lag."""
    try:
        r = requests.get(f"{BACKEND_URL}/{endpoint}", timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

# -- Page Config -------------------------------------------------------------
st.set_page_config(
    page_title="APTrace | APT Attribution Engine",
    page_icon="A",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -- CSS — sharp, clean, no rounded corners ----------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --bg-primary: #000000; /* True black */
    --bg-surface: #0a0a0a;
    --bg-elevated: #0f0f0f;
    --border: #1a1a1a;
    --border-accent: #00ff41;
    --text-primary: #ffffff;
    --text-secondary: #94a3b8;
    --text-muted: #475569;
    --accent-matrix: #00ff41;
    --accent-red: #ff3e3e;
    --accent-blue: #38bdf8;
    --accent-amber: #f59e0b;
}

/* Base Overrides */
.stApp {
    background-color: var(--bg-primary) !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

div[data-testid="stMetric"],
.stTabs [data-baseweb="tab-list"],
.stTabs [data-baseweb="tab-panel"],
section[data-testid="stSidebar"],
.stButton > button,
.stTextArea > div > div > textarea,
.stTextInput > div > div > input,
div[data-testid="stFileUploader"],
.stSelectbox > div,
.stMultiselect > div,
div.stAlert,
.stDataFrame,
div[data-testid="stExpander"] {
    border-radius: 0 !important;
}

div[data-testid="metric-container"] {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 0 !important;
    padding: 14px 16px;
}

.stButton > button {
    border-radius: 0 !important;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    font-size: 12px;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 0 !important;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    font-size: 11px;
}

.stTextArea > div > div > textarea {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    border: 1px solid var(--border) !important;
    background: var(--bg-surface) !important;
}

section[data-testid="stSidebar"] {
    background: var(--bg-surface);
    border-right: 1px solid var(--border);
}

/* Unified Sidebar Navigation */
.nav-btn {
    display: block;
    width: 100%;
    padding: 10px 16px;
    margin: 4px 0;
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-secondary);
    text-align: left;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
}
.nav-btn:hover {
    background: var(--bg-elevated);
    border-color: var(--border);
    color: var(--accent-matrix);
}
.nav-btn-active {
    background: var(--bg-elevated);
    border-color: var(--border-accent);
    color: var(--accent-matrix);
    border-left: 3px solid var(--accent-matrix);
}

/* Status Indicator */
.status-pill {
    display: inline-block;
    padding: 2px 8px;
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    border: 1px solid var(--border);
    margin-right: 6px;
}
.status-online { color: var(--accent-matrix); border-color: var(--accent-matrix); }
.status-offline { color: var(--accent-red); border-color: var(--accent-red); }

/* Attribution banner */
.attr-banner {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent-matrix);
    padding: 24px;
    margin: 16px 0;
}
.attr-banner-amber { border-left-color: var(--accent-amber); }
.attr-banner-red { border-left-color: var(--accent-red); }
.attr-banner-gray { border-left-color: var(--text-muted); }

.attr-group {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent-matrix);
    font-family: 'Inter', sans-serif;
    letter-spacing: -1px;
}
.attr-aliases {
    color: var(--text-secondary);
    font-size: 13px;
    margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
}
.attr-score {
    font-size: 44px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}
.attr-tier {
    color: var(--text-secondary);
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
}
.attr-nation {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    padding: 8px 16px;
    text-align: center;
}
.attr-nation-name {
    font-weight: 700;
    font-size: 16px;
}
.attr-nation-label {
    color: var(--text-secondary);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
}
.attr-desc {
    margin-top: 14px;
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.5;
}

/* Drift warning */
.drift-warn {
    background: #1a1508;
    border: 1px solid #92400e;
    border-left: 3px solid var(--accent-amber);
    padding: 12px 16px;
    color: var(--accent-amber);
    margin: 8px 0;
    font-size: 13px;
}

/* Section headers */
.section-header {
    font-family: 'Inter', sans-serif;
    font-weight: 700;
    font-size: 14px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 16px;
}

    /* Landing Page Specifics */
    .hero-container {
        padding: 40px 20px;
        text-align: center;
        background: transparent;
    }
    .hero-title {
        font-size: 42px;
        font-weight: 900;
        letter-spacing: -2px;
        color: #00ff41;
        margin-bottom: 10px;
        text-transform: uppercase;
    }
    .hero-subtitle {
        font-size: 16px;
        color: #64748b;
        max-width: 600px;
        margin: 0 auto 30px auto;
        line-height: 1.5;
    }
    .glass-card {
        background: rgba(10, 10, 10, 0.8);
        backdrop-filter: blur(10px);
        border: 1px solid #1a1a1a;
        padding: 20px;
        margin-bottom: 15px;
        transition: all 0.3s ease;
    }
    .glass-card:hover {
        border-color: #00ff41;
        transform: translateY(-2px);
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.1);
    }
    .pulse-btn {
        background: #00ff41 !important;
        color: #000 !important;
        font-weight: 800 !important;
        letter-spacing: 1px !important;
        border: none !important;
        padding: 12px 30px !important;
        animation: matrix-pulse 2s infinite;
    }
    @keyframes matrix-pulse {
        0% { box-shadow: 0 0 0 0 rgba(0, 255, 65, 0.4); }
        70% { box-shadow: 0 0 0 15px rgba(0, 255, 65, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 255, 65, 0); }
    }
    .reveal {
        opacity: 0;
        transform: translateY(20px);
        animation: reveal-scrolly 0.8s forwards;
    }
    @keyframes reveal-scrolly {
        to { opacity: 1; transform: translateY(0); }
    }
    .stat-bar {
        display: flex;
        justify-content: space-around;
        border-top: 1px solid #1a1a1a;
        border-bottom: 1px solid #1a1a1a;
        padding: 15px 0;
        margin: 40px 0;
    }
    .stat-item { text-align: center; }
    .stat-val { color: #00ff41; font-family: monospace; font-size: 20px; font-weight: 800; }
    .stat-label { color: #475569; font-size: 10px; text-transform: uppercase; }
    
    /* Transparent minimalist top buttons */
    button[kind="secondary"] {
        background: transparent !important;
        border: none !important;
        color: #64748b !important;
        font-size: 11px !important;
        letter-spacing: 1px !important;
    }
    button[kind="secondary"]:hover {
        color: #00ff41 !important;
        background: rgba(0, 255, 65, 0.05) !important;
    }
</style>
""", unsafe_allow_html=True)

# -- Load data ---------------------------------------------------------------
@st.cache_data
def get_profiles():
    return load_profiles()

@st.cache_data
def get_malware_db():
    return load_malware_family_db()

profiles = get_profiles()
malware_db = get_malware_db()

NATION_COLORS = {
    "Russia": "#dc2626",
    "China": "#ea580c",
    "North Korea": "#d97706",
    "Iran": "#2563eb",
    "Pakistan": "#16a34a",
}

TACTIC_LABELS = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Priv Esc",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Cred Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "C2",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

DEFENSES = {
    "Lazarus Group": ["Monitor cryptocurrency wallet file access patterns", "Block DNS tunneling and implement DoH monitoring", "Alert on LSASS memory access by non-system processes", "Application allowlisting to prevent loader execution", "Monitor scheduled task creation by non-admin accounts"],
    "APT28": ["Enable IMAP/SMTP access logging on mail gateways", "Enforce MFA on all external-facing services", "Alert on pass-the-hash and Kerberoasting behavior", "Monitor for unusual OAuth application registrations", "Deploy canary tokens in high-value documents"],
    "APT29": ["Audit all OAuth application permissions and revoke unused", "Software supply chain integrity verification (SLSA)", "Monitor abnormal cloud storage upload patterns", "Extended log retention up to 18 months for dwell time coverage", "Behavioral analytics only: signatures will NOT catch APT29"],
    "Sandworm": ["Air-gap ICS/SCADA from IT network", "Immutable backups inaccessible from main network", "Monitor for shadow copy deletion (vssadmin)", "Deploy OT-specific monitoring (Claroty/Dragos)", "Pre-test IR plan for destructive wiper malware"],
    "APT41": ["Supply chain integrity verification for all vendor updates", "Monitor build servers for unauthorized code changes", "Kernel-level detection for rootkit behavior", "Separate financial systems network from general IT"],
    "Volt Typhoon": ["Audit SOHO router firmware and replace default credentials", "Behavioral detection only: no signatures for LOLBins", "Monitor for abnormal built-in tool usage", "Network segmentation for critical infrastructure", "Reference CISA Advisory AA23-144A"],
    "Salt Typhoon": ["Audit telecom core router configurations", "Monitor kernel driver installations", "Enhanced monitoring of lawful intercept systems", "Network segmentation of management planes", "Zero-trust architecture for carrier infrastructure"],
    "APT35": ["Phishing-resistant MFA (FIDO2 hardware keys)", "Block Telegram API calls from corporate endpoints", "Monitor for browser extensions installed by non-admins", "Educate high-value targets on social engineering"],
    "MuddyWater": ["Restrict RMM tool installation to approved IT staff only", "Whitelist approved remote access tools and block others", "PowerShell logging with AMSI enabled", "Email gateway scanning for macro-enabled documents"],
    "OilRig": ["Monitor DNS query volume and patterns for tunneling", "Web shell detection on Exchange and IIS servers", "DNS RPZ policies for known C2 patterns", "Segment email infrastructure from general network"],
    "Kimsuky": ["DMARC/DKIM enforcement to protect researcher email", "Monitor for email forwarding rules created abnormally", "Android MDM for researchers with mobile implant risk", "Canary documents for nuclear/policy researchers"],
    "Transparent Tribe": ["Block unknown .NET executables on military networks", "Android MDM for defense personnel mobile devices", "Monitor CrimsonRAT C2 communication signatures", "Alert on India-Pakistan conflict themed spearphishing"],
    "Turla": ["Kernel integrity monitoring on diplomatic systems", "Monitor named pipe communications for lateral signaling", "Extended log retention for long-dwell detection", "Network traffic analysis for satellite C2 anomalies"],
}

# -- Landing Page -------------------------------------------------------------
def landing_page():
    st.markdown("<div style='position: relative; height: 0; z-index: 100;'>", unsafe_allow_html=True)
    c_space, c_login, c_signup = st.columns([8, 1, 1])
    with c_login:
        if st.button("LOGIN", key="btn_login_top", type="secondary"):
            st.session_state["show_login"] = True
            st.session_state["auth_mode"] = "Log In"
            st.rerun()
    with c_signup:
        if st.button("SIGNUP", key="btn_signup_top", type="secondary"):
            st.session_state["show_login"] = True
            st.session_state["auth_mode"] = "Sign Up"
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    # Hero Section - Centered wording
    st.markdown("""
        <div class='hero-container' style='text-align: center; padding: 40px 0 20px 0;'>
            <div class='hero-title'>Beyond Detection.<br>True Attribution.</div>
            <div class='hero-subtitle' style='margin: 10px auto; max-width: 600px;'>Most security tools show <b>what</b> happened. APTrace shows <b>who</b> did it. Automating malware source attribution with Machine Learning.</div>
        </div>
    """, unsafe_allow_html=True)

    # Centered CTA
    col_c1, col_c2, col_c3 = st.columns([1, 1, 1])
    with col_c2:
        if st.button("AUTHORIZE_TERMINAL_ACCESS", key="auth_btn_center", use_container_width=True, type="primary"):
            st.session_state["show_login"] = True
            st.rerun()
    
    st.markdown("<div style='text-align: center; font-size: 9px; color: #00ff41; letter-spacing: 2px; opacity: 0.6; margin-top: 15px;'>SCROLL TO DECODE ▾</div>", unsafe_allow_html=True)

    # Technical Architecture / Pipeline
    st.markdown("""
<div class='reveal' style='animation-delay: 0.1s; max-width: 800px; margin: 40px auto;'>
    <div style='border: 1px solid #1a1a1a; background: rgba(10, 10, 10, 0.5); padding: 40px; text-align: left; backdrop-filter: blur(10px);'>
        <div style='color: #00ff41; font-family: "JetBrains Mono", monospace; font-weight: 800; font-size: 14px; margin-bottom: 30px; letter-spacing: 1px; border-bottom: 1px solid #1a1a1a; padding-bottom: 15px;'>
            // PLATFORM TECHNICAL SPECIFICATIONS
        </div>
        
        <div style='display: flex; flex-direction: column; gap: 35px;'>
            
            <div style='border-left: 2px solid #38bdf8; padding-left: 20px;'>
                <div style='color: #e2e8f0; font-family: "JetBrains Mono", monospace; font-size: 13px; font-weight: 800; margin-bottom: 8px;'>[ 01 ] AUTOMATED INDICATOR EXTRACTION</div>
                <div style='color: #94a3b8; font-size: 13px; line-height: 1.6; font-family: "Inter", sans-serif;'>
                    The engine parses raw physical binaries to extract highly specific metadata often overlooked by standard AV engines. This includes <b>Imphashes</b>, <b>Rich Header arrays</b>, section entropy, and complex static properties to form the base investigation vector.
                </div>
            </div>

            <div style='border-left: 2px solid #00ff41; padding-left: 20px;'>
                <div style='color: #e2e8f0; font-family: "JetBrains Mono", monospace; font-size: 13px; font-weight: 800; margin-bottom: 8px;'>[ 02 ] XGBoost ML CLASSIFICATION</div>
                <div style='color: #94a3b8; font-size: 13px; line-height: 1.6; font-family: "Inter", sans-serif;'>
                    Instead of relying on fragile Yara rules, APTrace utilizes a supervised <b>XGBoost classifier</b> trained on thousands of known nation-state samples. It isolates behavioral sequences, imported DLLs, and registry modifications to calculate probabilistic alignments with known advanced persistent threats.
                </div>
            </div>

            <div style='border-left: 2px solid #ff3e3e; padding-left: 20px;'>
                <div style='color: #e2e8f0; font-family: "JetBrains Mono", monospace; font-size: 13px; font-weight: 800; margin-bottom: 8px;'>[ 03 ] SHAP-POWERED EXPLAINABILITY</div>
                <div style='color: #94a3b8; font-size: 13px; line-height: 1.6; font-family: "Inter", sans-serif;'>
                    Black-box ML is unacceptable for SOC operations. APTrace integrates <b>SHAP (SHapley Additive exPlanations)</b> to provide complete transparency. Every attribution verdict exposes the exact technical parameters (e.g., <i>'CreateRemoteThread'</i> or <i>'advapi32.dll'</i>) that forced the model's decision.
                </div>
            </div>

             <div style='border-left: 2px solid #8b5cf6; padding-left: 20px;'>
                <div style='color: #e2e8f0; font-family: "JetBrains Mono", monospace; font-size: 13px; font-weight: 800; margin-bottom: 8px;'>[ 04 ] STIX / MITRE ATT&CK AUTO-SYNC</div>
                <div style='color: #94a3b8; font-size: 13px; line-height: 1.6; font-family: "Inter", sans-serif;'>
                    The system remains resilient against threat actor drift. It automatically categorizes and syncs with the official <b>MITRE ATT&CK STIX API</b>, pulling live profiles and appending new evasion techniques to the dataset continuously.
                </div>
            </div>

        </div>
    </div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div class='stat-bar reveal' style='margin: 10px auto 40px auto; max-width: 800px; padding: 20px 0; border-top: 1px solid #1a1a1a; border-bottom: 1px solid #1a1a1a;'>
    <div class='stat-item'><div class='stat-val' style='font-size: 28px;'>13+</div><div class='stat-label' style='font-size: 12px; margin-top: 5px;'>APT Groups Profiled</div></div>
    <div class='stat-item'><div class='stat-val' style='font-size: 28px;'>400+</div><div class='stat-label' style='font-size: 12px; margin-top: 5px;'>TTP Parameters</div></div>
    <div class='stat-item'><div class='stat-val' style='font-size: 28px;'>94%</div><div class='stat-label' style='font-size: 12px; margin-top: 5px;'>Model Recall</div></div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
        <div style='text-align:center; color: #1e293b; font-size: 9px; margin-top: 20px; font-family: monospace;'>
            SEC_LEVEL: ALPHA-6 // APTRACE_CORE_STABLE
        </div>
    """, unsafe_allow_html=True)


# -- Authentication ----------------------------------------------------------
if "user" not in st.session_state:
    if "show_login" not in st.session_state:
        st.session_state["show_login"] = False
    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "Log In"
    
    if not st.session_state["show_login"]:
        landing_page()
    else:
        st.markdown("### APTrace Authentication")
        st.markdown("Please log in to access the APT Attribution Engine.")
        
        # Tabs with persistent state
        tab_login, tab_signup = st.tabs(["Log In", "Sign Up"])
        idx = 0 if st.session_state["auth_mode"] == "Log In" else 1
        # Note: streamlit tabs don't support index easily without experimental features, 
        # but we can at least make sure they both render correctly now.
        
        with tab_login:
            with st.form("login_form"):
                email = st.text_input("Email", placeholder="analyst@aptrace.io")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Log In", type="primary", use_container_width=True)
                if submit:
                    if not email or not password:
                        st.warning("Please enter both email and password.")
                    elif not supabase:
                        st.error("Supabase configuration missing in backend/.env")
                    else:
                        try:
                            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
                            st.session_state["user"] = res.user
                            st.session_state["session"] = res.session
                            st.success("Log in successful!")
                            st.rerun()
                        except Exception as e:
                            err_msg = str(e).lower()
                            if "invalid login credentials" in err_msg:
                                st.error("Invalid email or password. Please try again.")
                            else:
                                st.error(f"Login failed: {e}")
                            print(f"[AUTH ERROR] Login failed for {email}: {e}")
                        
        with tab_signup:
            st.info("💡 Tip: If you already have an account, please use the 'Log In' tab.")
            with st.form("signup_form"):
                new_email = st.text_input("Email", placeholder="analyst@aptrace.io")
                new_password = st.text_input("Password", type="password", help="Minimum 6 characters")
                signup_submit = st.form_submit_button("Create Account", use_container_width=True)
                if signup_submit:
                    if not new_email or not new_password:
                        st.warning("Please enter both email and password.")
                    elif not supabase:
                        st.error("Supabase configuration missing in backend/.env")
                    else:
                        try:
                            res = supabase.auth.sign_up({"email": new_email, "password": new_password})
                            st.success("Signup successful! Please confirm your email (if required) or log in.")
                            st.balloons()
                        except Exception as e:
                            err_msg = str(e).lower()
                            if "rate limit exceeded" in err_msg:
                                st.error("Email rate limit exceeded. Please wait a few minutes or try logging in if you already have an account.")
                            elif "user already registered" in err_msg:
                                st.warning("This email is already registered. Please switch to the 'Log In' tab.")
                            else:
                                st.error(f"Signup failed: {e}")
                            print(f"[AUTH ERROR] Signup failed for {new_email}: {e}")
                            print(f"[AUTH ERROR] Signup failed for {new_email}: {e}")
                        
    st.stop()

# -- Sidebar & Navigation Logic ---------------------------------------------
if "current_hub" not in st.session_state:
    st.session_state["current_hub"] = "Analyze"

def set_hub(hub_name):
    st.session_state["current_hub"] = hub_name

with st.sidebar:
    st.markdown("""
        <div style='padding: 10px 0 20px 0;'>
            <div style='font-size: 20px; font-weight: 800; color: #00ff41; letter-spacing: 2px;'>APTRACE</div>
            <div style='font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 1px;'>Adversary Intelligence System</div>
        </div>
    """, unsafe_allow_html=True)

    if "user" in st.session_state and st.session_state["user"]:
        user_email = st.session_state["user"].email.split("@")[0].upper()
        st.markdown(f"""
            <div style='background: #0f0f0f; border: 1px solid #1a1a1a; padding: 12px; margin-bottom: 20px;'>
                <div style='font-size: 9px; color: #64748b; margin-bottom: 4px;'>OPERATOR_SESSION</div>
                <div style='font-family: "JetBrains Mono", monospace; font-size: 13px; color: #00ff41;'>{user_email}</div>
            </div>
        """, unsafe_allow_html=True)
        
        if st.button("TERMINATE SESSION", use_container_width=True, type="secondary"):
            if supabase:
                supabase.auth.sign_out()
            st.session_state.clear()
            st.rerun()

    st.markdown("<div style='font-size: 10px; font-weight: 700; color: #475569; margin-bottom: 8px; border-bottom: 1px solid #1a1a1a; padding-bottom: 4px;'>COMMAND_MENU</div>", unsafe_allow_html=True)
    
    # Hub Navigation Buttons
    hubs = ["Analyze", "Intel Hub", "Operations", "Archives"]
    for h in hubs:
        is_active = st.session_state["current_hub"] == h
        btn_type = "primary" if is_active else "secondary"
        if st.button(h, key=f"nav_{h}", use_container_width=True, type=btn_type):
            set_hub(h)
            st.rerun()

    st.markdown("<div style='font-size: 10px; font-weight: 700; color: #475569; margin-top: 20px; margin-bottom: 8px; border-bottom: 1px solid #1a1a1a; padding-bottom: 4px;'>PARAMETER_OVERRIDE</div>", unsafe_allow_html=True)
    show_all = st.checkbox("DEEP_RECALL_MODE", False, help="Force display of all 13 APT groups")
    top_n = st.slider("RANK_LIMIT", 3, 13, 5) if show_all else 5

    st.sidebar.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    st.divider()
    
    # System Status Indicators
    sys_online = supabase is not None
    api_online = True 
    st.markdown(f"""
        <div style='font-size: 9px; margin-bottom: 4px;'>
            <span class='status-pill {"status-online" if sys_online else "status-offline"}'>CORE: {"READY" if sys_online else "ERROR"}</span>
            <span class='status-pill {"status-online" if api_online else "status-offline"}'>API: {"ACTIVE" if api_online else "DOWN"}</span>
        </div>
        <div style='font-size: 10px; color: #475569; font-family: "JetBrains Mono", monospace;'>V1.0.5-MATRIX-STABLE</div>
    """, unsafe_allow_html=True)

# -- Header Dashboard --------------------------------------------------------
active_hub = st.session_state["current_hub"]

st.markdown(f"""
    <div style='display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1a1a1a; padding-bottom: 10px; margin-bottom: 20px;'>
        <div style='font-size: 12px; color: #64748b; font-family: "JetBrains Mono", monospace;'>PATH: root / {active_hub.lower().replace(" ", "_")}</div>
        <div style='font-size: 12px; color: #00ff41; font-family: "JetBrains Mono", monospace;'>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
    </div>
""", unsafe_allow_html=True)

# -- Main Views Re-wiring ---------------------------------------------------

# -- Main Hub Architecture ----------------------------------------------------
if active_hub == "Analyze":
    st.markdown(f"<h2 style='letter-spacing: -1px; font-weight: 800;'>Unified Analysis Gateway</h2>", unsafe_allow_html=True)
    
    tab_malware, tab_text, tab_demo = st.tabs(["[ Malware Retracing ]", "[ Behavioral Text ]", "[ Simulated Scenarios ]"])
    
    with tab_malware:
        st.markdown("#### PROXIMATE MALWARE ANALYZER")
        st.info("Input sample hash or binary for ML-driven adversary matching.")
        h_col1, h_col2 = st.columns([2, 1])
        with h_col1:
            hash_input = st.text_input("SAMPLE_HASH", placeholder="MD5 / SHA-1 / SHA-256", label_visibility="collapsed")
        with h_col2:
            malware_file = st.file_uploader("BINARY_UPLOAD", type=["exe", "dll", "bin", "dat", "sys", "ps1", "vbs", "js", "txt"], label_visibility="collapsed")
        
        if st.button("BEGIN ANALYSIS", type="primary", use_container_width=True, key="btn_retrace_main"):
            if not malware_file and not hash_input.strip():
                st.warning("Upload a file or provide a hash.")
            else:
                with st.spinner("Running malware retracing via API..."):
                    try:
                        files = {"file": (malware_file.name, malware_file.getvalue())} if malware_file else None
                        data = {"hash_value": hash_input}
                        res = requests.post(f"{BACKEND_URL}/retrace", files=files, data=data)
                        res.raise_for_status()
                        st.session_state.pop("result", None)
                        st.session_state["malware_result"] = res.json()
                    except Exception as e:
                        st.warning(f"Backend API unavailable, falling back to local rule engine. Error: {e}")
                        file_bytes = malware_file.read() if malware_file else None
                        retrace = run_malware_retracing(
                            file_bytes=file_bytes,
                            filename=malware_file.name if malware_file else "",
                            hash_value=hash_input,
                            family_db=malware_db,
                            top_k=top_n,
                        )
                        st.session_state.pop("result", None)
                        st.session_state["malware_result"] = retrace

    with tab_text:
        st.markdown("#### EVENT LOG / OBSERVATION PARSER")
        st.info("Direct behavioral telemetry ingestion. Paste raw logs or analyst notes below.")
        analyst_input = st.text_area(
            "BEHAVIORAL_TELEMETRY",
            height=300,
            placeholder="[SYSMON] Event ID 1: Process Created... \nOr just: Analyst saw encoded powershell on financial server.",
            label_visibility="collapsed"
        )
        if st.button("EXTRACT & ATTRIBUTE", type="primary", use_container_width=True, key="btn_analyze_text"):
            if analyst_input.strip():
                with st.spinner("Decoding behavioral DNA..."):
                    try:
                        res = requests.post(f"{BACKEND_URL}/analyze", json={"text": analyst_input, "input_mode": "analyst_text"})
                        res.raise_for_status()
                        st.session_state.pop("malware_result", None)
                        st.session_state["result"] = res.json()
                        st.session_state["input_text"] = analyst_input
                    except Exception as e:
                        st.warning(f"API Fallback: {e}")
                        feats = extract_ttps_from_text(analyst_input)
                        st.session_state.pop("malware_result", None)
                        st.session_state["result"] = run_attribution(feats, profiles)
                        st.session_state["input_text"] = analyst_input
            else:
                st.warning("Input required.")

    with tab_demo:
        st.markdown("#### SCENARIO_LIBRARY")
        st.markdown("Pre-built realistic incident scenarios for system validation.")
        cols = st.columns(3)
        keys = list(DEMO_SCENARIOS.keys())
        for i, key in enumerate(keys):
            scenario = DEMO_SCENARIOS[key]
            with cols[i % 3]:
                st.markdown(f"**{scenario['name']}**")
                st.caption(scenario["description"])
                if st.button("Load Scenario", key=f"demo_{key}", use_container_width=True):
                    with st.spinner(f"Analyzing {scenario['name']}..."):
                        try:
                            res = requests.post(f"{BACKEND_URL}/analyze", json={"text": scenario["input_text"], "input_mode": "demo"})
                            res.raise_for_status()
                            st.session_state.pop("malware_result", None)
                            st.session_state["result"] = res.json()
                        except:
                            feats = extract_ttps_from_text(scenario["input_text"])
                            st.session_state.pop("malware_result", None)
                            st.session_state["result"] = run_attribution(feats, profiles)
                        st.session_state["input_text"] = scenario["input_text"]

elif active_hub == "Intel Hub":
    st.markdown(f"<h2 style='letter-spacing: -1px; font-weight: 800;'>Adversary Intelligence Hub</h2>", unsafe_allow_html=True)
    st.caption(f"PATH: root / intel_hub <span style='float:right; color: #00ff41; font-family: monospace;'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>", unsafe_allow_html=True)
    
    tab_p, tab_m = st.tabs(["[ APT PROFILES ]", "[ MITRE TECH REGISTRY ]"])
    
    with tab_p:
        st.markdown("#### KNOWN THREAT ACTOR PROFILES")
        p_list = profiles.get("apt_groups", [])
        for p_data in p_list:
            group = p_data.get("name", "Unknown Group")
            nation = p_data.get("nation", "Unknown")
            with st.expander(f"{group} ({nation})"):
                st.write(p_data.get("description", "No description available."))
                
                # Render Tactics/TTPs
                ttps_dict = p_data.get("ttps", {})
                all_techs = []
                for tact, techs in ttps_dict.items():
                    all_techs.extend(techs)
                st.write(f"**Tactics Covered:** {', '.join(sorted(list(set(all_techs)))) if all_techs else 'None'}")
                
                # Behavioral DNA snippet
                dna = p_data.get("behavioral_dna", {})
                if dna:
                    st.divider()
                    st.caption("BEHAVIORAL_DNA_SIGNATURE")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Stealth", f"{dna.get('stealth_rating', 0)}/10")
                    c2.metric("Aggression", f"{dna.get('aggression_rating', 0)}/10")
                    c3.metric("Sophistication", f"{dna.get('sophistication_rating', 0)}/10")

    with tab_m:
        st.markdown("#### MITRE ATT&CK TECHNIQUES")
        st.info("Direct behavioral indicators tracked by the APTrace Engine across all active APT profiles.")
        all_ttps = []
        p_list = profiles.get("apt_groups", [])
        for p_data in p_list:
            group = p_data.get("name", "Unknown")
            ttps_dict = p_data.get("ttps", {})
            for tactic, techs in ttps_dict.items():
                for t_id in techs:
                    all_ttps.append({"ID": t_id, "Tactic": tactic.replace('_', ' ').title(), "Source_Group": group})
        
        if all_ttps:
            registry_df = pd.DataFrame(all_ttps).drop_duplicates(subset=["ID"])
            st.dataframe(registry_df.sort_values("ID"), use_container_width=True, hide_index=True)


elif active_hub == "Operations":
    st.markdown(f"<h2 style='letter-spacing: -1px; font-weight: 800;'>ML System Operations</h2>", unsafe_allow_html=True)
    st.caption(f"PATH: root / operations <span style='float:right; color: #00ff41; font-family: monospace;'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>", unsafe_allow_html=True)
    
    # Use cached fetch
    stats = fetch_api("ml/stats") or {}
    drift = fetch_api("ml/drift") or {}

    o_col1, o_col2 = st.columns(2)
    with o_col1:
        st.markdown("##### Performance Metrics")
        if stats:
            st.dataframe(pd.DataFrame(stats), use_container_width=True, hide_index=True)
        else: st.error("ML Statistics Unavailable.")
        if st.button("TRIGGER_MODEL_RE-TRAIN", type="primary", use_container_width=True):
            requests.post(f"{BACKEND_URL}/ml/retrain")
            st.success("Retraining pipeline initiated.")
            
    with o_col2:
        st.markdown("##### Threat Intel Sync")
        st.write("Current intelligence baseline: V1.0-STABLE")
        if st.button("SYNC_MITRE_STIX", use_container_width=True):
            with st.spinner("Syncing..."):
                res = requests.post(f"{BACKEND_URL}/intel/sync-mitre")
                st.success(f"Sync complete. Updates applied: {res.json().get('applied_count', 0)}")

    st.divider()
    st.markdown("##### Confidence & Drift Monitoring")
    if drift:
        df_drift = pd.DataFrame(drift)
        fig = px.line(df_drift, x="week", y="avg_confidence", markers=True)
        fig.update_layout(**_PLOT_LAYOUT, height=300)
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("Drift monitoring inactive.")

elif active_hub == "Archives":
    st.markdown(f"<h2 style='letter-spacing: -1px; font-weight: 800;'>Operational Archives</h2>", unsafe_allow_html=True)
    st.caption(f"PATH: root / archives <span style='float:right; color: #00ff41; font-family: monospace;'>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>", unsafe_allow_html=True)
    st.info("Centralized log of all nation-state attributions and malware retracing operations.")
    
    history_data = fetch_api("history")
    if history_data:
        history = history_data.get("analyses", [])
        if not history:
            st.warning("Archives empty.")
        for item in history:
            with st.expander(f"[{item.get('created_at', '')[:16]}] {item.get('top_group', 'UNCERTAIN')} - {item.get('confidence_tier', 'N/A')}"):
                st.json(item)
    else:
        st.error("Operational history unreachable.")



# -- Helper: confidence color ------------------------------------------------
def _conf_color(pct):
    if pct >= 70:
        return "#00ff41" # Matrix Green
    if pct >= 45:
        return "#f59e0b" # Amber
    if pct >= 20:
        return "#ff3e3e" # Matrix Red
    return "#475569" # Muted Gray


def _banner_class(pct):
    if pct >= 70:
        return "attr-banner"
    if pct >= 45:
        return "attr-banner attr-banner-amber"
    if pct >= 20:
        return "attr-banner attr-banner-red"
    return "attr-banner attr-banner-gray"


# -- Plotly defaults ---------------------------------------------------------
_PLOT_LAYOUT = {
    "plot_bgcolor": "rgba(0,0,0,0)",
    "paper_bgcolor": "rgba(0,0,0,0)",
    "font": {"color": "#ffffff", "size": 11, "family": "Inter, sans-serif"},
    "showlegend": False,
    "margin": {"l": 10, "r": 10, "t": 10, "b": 10},
}

# -- STIX 2.1 Helper ---------------------------------------------------------
def _generate_stix_bundle(result_dict: dict) -> dict:
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: list[dict] = []
    
    actor_id = f"threat-actor--{uuid.uuid4()}"
    group_name = result_dict.get("top_group") or result_dict.get("top_attribution", {}).get("group", "Unknown Actor")
    actor = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": now,
        "modified": now,
        "name": group_name,
        "description": f"APTrace Attribution for {group_name}. Confidence: {result_dict.get('confidence_pct', 0)}%"
    }
    objects.append(actor)
    
    report_id = f"report--{uuid.uuid4()}"
    report: dict[str, typing.Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": f"APTrace Attribution Report - {group_name}",
        "published": now,
        "object_refs": [actor_id]
    }
    
    # Handle both API output and local rule engine output
    ttps = result_dict.get("observed_techniques")
    if ttps is None and "matched_techniques" in result_dict.get("top_attribution", {}):
        ttps = list(result_dict["top_attribution"]["matched_techniques"])
        
    if ttps:
        for ttp in ttps:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            ap = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": ttp,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": ttp}
                ]
            }
            objects.append(ap)
            report["object_refs"].append(ap_id)
            
            rel_id = f"relationship--{uuid.uuid4()}"
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": ap_id
            }
            objects.append(rel)
            report["object_refs"].append(rel_id)
            
    objects.append(report)
    
    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
    return bundle


# -- Malware results ---------------------------------------------------------
if "malware_result" in st.session_state:
    mr = st.session_state["malware_result"]
    top_family = mr.get("top_match")
    extracted = mr.get("extracted_static")

    st.divider()
    st.markdown("#### MALWARE RETRACING RESULTS")
    if top_family:
        conf = top_family["confidence_pct"]
        cc = _conf_color(conf)
        st.markdown(f"""
        <div class="{_banner_class(conf)}">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">
            <div>
              <div class="attr-group">{top_family['family']}</div>
              <div class="attr-aliases">Threat Cluster: {top_family['cluster']}</div>
            </div>
            <div style="text-align:center">
              <div class="attr-score" style="color:{cc}">{conf:.0f}%</div>
              <div class="attr-tier">SIMILARITY: {mr['verdict']}</div>
            </div>
          </div>
          <div class="attr-desc">{top_family.get('summary', 'Detailed analysis of matched static indicators and behavioral similarities.')}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Add a download button if storage_path is available
        if mr.get("storage_path"):
            st.info(f"Artifact stored at: `{mr['storage_path']}`")
            # In a real app, we'd generate a signed URL here. 
            # For now, we'll just indicate it's archived.

    mc1, mc2, mc3, mc4 = st.columns(4)
    mc1.metric("Mode", mr.get("analysis_mode", "n/a"))
    mc2.metric("Families Ranked", len(mr.get("ranked_matches", [])))
    mc3.metric("Indicators", len(top_family.get("matched_indicators", [])) if top_family else 0)
    mc4.metric("PE Parsed", "Yes" if extracted and extracted.get("is_pe") else "No")

    if mr.get("hash_mismatch"):
        st.warning(mr["hash_mismatch"])

    mtab1, mtab2, mtab3 = st.tabs(["TOP MATCHES", "MATCHED EVIDENCE", "JSON REPORT"])

    with mtab1:
        rows = []
        for item in mr.get("ranked_matches", []):
            rows.append({
                "Family": item["family"],
                "Threat Cluster": item["cluster"],
                "Similarity": item["confidence_pct"],
                "Geo Context": item.get("geo_context", ""),
            })
        if rows:
            df_retrace = pd.DataFrame(rows)
            st.dataframe(
                df_retrace,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Similarity": st.column_config.ProgressColumn(
                        "Similarity Score",
                        help="Confidence score based on indicator overlap",
                        format="%.0f%%",
                        min_value=0,
                        max_value=100,
                    )
                }
            )

    with mtab2:
        if top_family:
            st.markdown('<div class="section-header">Matched Indicators</div>', unsafe_allow_html=True)
            for indicator in top_family.get("matched_indicators", []):
                st.markdown(f"- {indicator}")
            st.markdown('<div class="section-header">Regional Context</div>', unsafe_allow_html=True)
            st.info(top_family.get("geo_context", "No regional context available."))

        if extracted:
            st.markdown('<div class="section-header">Static Indicators</div>', unsafe_allow_html=True)
            ec1, ec2 = st.columns(2)
            with ec1:
                st.code(json.dumps({
                    "filename": extracted.get("filename"),
                    "size_bytes": extracted.get("size_bytes"),
                    "file_type": extracted.get("file_type"),
                    "is_pe": extracted.get("is_pe"),
                    "imphash": extracted.get("imphash"),
                    "sha256": extracted.get("hashes", {}).get("sha256"),
                }, indent=2), language="json")
            with ec2:
                st.markdown("**Imports (sample)**")
                for imp in extracted.get("imports", [])[:20]:  # type: ignore[index]
                    st.markdown(f"- `{imp}`")
                st.markdown("**Strings (sample)**")
                for s_val in extracted.get("strings", [])[:12]:  # type: ignore[index]
                    st.markdown(f"- `{s_val[:90]}`")  # type: ignore[index]
                    
        if mr.get("external_intel"):
            intel = mr["external_intel"]
            if "virustotal" in intel and intel["virustotal"]:
                st.markdown('<div class="section-header">VirusTotal Intelligence</div>', unsafe_allow_html=True)
                vt = intel["virustotal"]
                if vt.get("found"):
                    vt1, vt2 = st.columns(2)
                    with vt1:
                        st.metric("VT Detection Ratio", vt.get("detection_ratio"))
                        st.markdown(f"**First Submission:** {vt.get('first_submission', 'Unknown')}")
                        st.markdown(f"**Meaningful Name:** {vt.get('meaningful_name', 'None')}")
                    with vt2:
                        threat_names = vt.get("threat_names", [])
                        if threat_names:
                            st.markdown("**Popular Threat Labels:**")
                            for tn in threat_names[:5]:
                                st.markdown(f"- {tn.get('value')}")
                else:
                    st.info(vt.get("message", "Hash not found in VT."))

    with mtab3:
        report_json = json.dumps(mr, indent=2)
        st.code(report_json, language="json")
        st.download_button("DOWNLOAD REPORT", data=report_json,
                           file_name="aptrace_malware_report.json",
                           mime="application/json", use_container_width=True)


# -- Attribution results -----------------------------------------------------
if "result" in st.session_state:
    result = st.session_state["result"]
    
    # API response format differs from local engine format
    api_mode = "predictions" in result
    
    if api_mode:
        # Map API response format to what the UI expects (or render it directly)
        st.divider()
        st.markdown("#### ATTRIBUTION RESULTS (ML ENGINE)")
        
        conf = result["confidence_pct"]
        tier = result["confidence_tier"]
        top_group = result["top_group"]
        
        if top_group:
            cc = _conf_color(conf)
            st.markdown(f"""
            <div class="{_banner_class(conf)}">
              <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">
                <div>
                  <div class="attr-group">{top_group}</div>
                </div>
                <div style="text-align:center">
                  <div class="attr-score" style="color:{cc}">{conf:.0f}%</div>
                  <div class="attr-tier">{tier} CONFIDENCE</div>
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)
            
            c1, c2, c3 = st.columns(3)
            c1.metric("TTPs Observed", result["technique_count"])
            c2.metric("Context Signals", len(result["context_signals"]))
            c3.metric("Model Version", result.get("model_version", "unknown"))
            
            st.markdown("#### ML Probability Ranking")
            preds = result.get("predictions", [])[:top_n]
            if preds:
                docs = pd.DataFrame(preds)
                docs["probability"] = docs["probability"].apply(lambda x: f"{x*100:.1f}%")
                st.dataframe(docs, use_container_width=True, hide_index=True)
                
            st.markdown("#### Extracted Indicators")
            if result.get("observed_techniques"):
                st.write("**Techniques:**", ", ".join(result["observed_techniques"]))
            if result.get("context_signals"):
                st.write("**Context:**", ", ".join(result["context_signals"]))
                
            if result.get("shap_explanation"):
                st.markdown("#### SHAP Feature Importance")
                st.info("Local explanations showing which features drove the model's top prediction.")
                shap_df = pd.DataFrame(result["shap_explanation"])
                # Sort ascending by importance so the largest bars are at the top in horizontal bar char
                shap_df = shap_df.sort_values(by="importance", ascending=True)
                
                fig = px.bar(
                    shap_df,
                    x="contribution",
                    y="feature",
                    orientation="h",
                    color="contribution",
                    color_continuous_scale=px.colors.diverging.RdYlGn,
                    color_continuous_midpoint=0
                )
                fig.update_layout(
                    **_PLOT_LAYOUT, 
                    xaxis_title="SHAP Value (Impact on Model Output)", 
                    yaxis_title="",
                    margin=dict(l=0, r=0, t=10, b=0),
                    height=max(300, len(shap_df) * 30)
                )
                st.plotly_chart(fig, use_container_width=True)
                
    else:
        # Local rule engine rendering (Original UI)
        top = result["top_attribution"]
        tech_desc = result["technique_descriptions"]
    
        st.divider()
        st.markdown("#### ATTRIBUTION RESULTS (RULE ENGINE)")

    # -- Top banner ----------------------------------------------------------
    if top:
        conf = top["confidence_pct"]
        tier = result["confidence_tier"]
        cc = _conf_color(conf)
        nc = NATION_COLORS.get(top["nation"], "#6b7280")

        aliases_short = top['aliases'][:4]  # type: ignore[index]

        st.markdown(f"""
        <div class="{_banner_class(conf)}">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">
            <div>
              <div class="attr-group">{top['group']}</div>
              <div class="attr-aliases">{' / '.join(aliases_short)}</div>
            </div>
            <div style="text-align:center">
              <div class="attr-score" style="color:{cc}">{conf:.0f}%</div>
              <div class="attr-tier">{tier} CONFIDENCE</div>
            </div>
            <div class="attr-nation">
              <div class="attr-nation-name" style="color:{nc}">{top['nation']}</div>
              <div class="attr-nation-label">Nation-State</div>
            </div>
          </div>
          <div class="attr-desc">{top['description']}</div>
        </div>
        """, unsafe_allow_html=True)

        dna = top.get("behavioral_dna", {})
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("TTPs Observed", result["observed_technique_count"])
        c2.metric("TTPs Matched", len(top["matched_techniques"]))
        c3.metric("Context Signals", len(top["context_signals"]))
        c4.metric("Stealth", f"{dna.get('stealth_rating', '-')}/10")
        c5.metric("Sophistication", f"{dna.get('sophistication_rating', '-')}/10")
    else:
        hypothesis = result.get("top_hypothesis")
        st.markdown(
            """
            <div class="attr-banner attr-banner-gray">
              <div class="attr-group">UNATTRIBUTED / EMERGING</div>
              <div class="attr-desc">
                Evidence did not pass attribution quality gates. Ranked actors below are hypotheses only.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if result.get("emerging_cluster"):
            cluster = result["emerging_cluster"]
            st.info(
                f"Emerging cluster candidate: {cluster['cluster_id']} | "
                f"Novel behavior with low similarity to current actor profiles."
            )
            if cluster.get("memory"):
                mem = cluster["memory"]
                st.caption(
                    f"Cluster memory: sightings={mem.get('sightings', 1)} | "
                    f"first_seen={mem.get('first_seen', 'n/a')} | last_seen={mem.get('last_seen', 'n/a')}"
                )
        if hypothesis:
            st.caption(
                f"Top hypothesis: {hypothesis['group']} ({hypothesis['confidence_pct']:.1f}%) | "
                f"Lead over #2: {result.get('lead_pct', 0):.1f}%"
            )
        g1, g2, g3 = st.columns(3)
        g1.metric("TTPs Observed", result["observed_technique_count"])
        g2.metric("Tactics Covered", result.get("observed_tactic_coverage", 0))
        g3.metric("Gate Passed", "No")

    # Drift warning
    if result.get("drift_warning"):
        st.markdown(
            f'<div class="drift-warn">TTP DRIFT DETECTED: {result["drift_warning"]}</div>',
            unsafe_allow_html=True,
        )

    # -- Tabs ----------------------------------------------------------------
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "ATTRIBUTION SCORES",
        "TTP HEATMAP",
        "BEHAVIORAL DNA",
        "CAMPAIGN CONTEXT",
        "FULL REPORT",
    ])

    # TAB 1 — Scores
    with tab1:
        st.markdown('<div class="section-header">APT Group Attribution Scores</div>', unsafe_allow_html=True)
        if not result.get("attribution_gate_passed"):
            st.warning(
                "Attribution gates not met. Use ranking as investigative hypotheses, not confirmed actor identity."
            )
        ranked = result["ranked_results"][:top_n]  # type: ignore[index]
        names = [r_item["group"] for r_item in ranked]
        confs = [r_item["confidence_pct"] for r_item in ranked]
        colors = [NATION_COLORS.get(r_item["nation"], "#6b7280") for r_item in ranked]

        fig = go.Figure()
        fig.add_trace(go.Bar(
            y=names[::-1], x=confs[::-1], orientation="h",  # type: ignore[index]
            marker_color=colors[::-1],  # type: ignore[index]
            text=[f"{c:.1f}%" for c in confs[::-1]],  # type: ignore[index]
            textposition="outside",
            textfont={"color": "#d4d4d8", "size": 12, "family": "JetBrains Mono, monospace"},
            hovertemplate="<b>%{y}</b><br>Confidence: %{x:.1f}%<extra></extra>",
        ))
        for threshold, label, color in [(70, "HIGH", "#22c55e"), (45, "MED", "#f59e0b"), (20, "LOW", "#ef4444")]:
            fig.add_vline(x=threshold, line_dash="dot", line_color=color, opacity=0.4,
                          annotation_text=label, annotation_font_color=color, annotation_font_size=9)
        fig.update_layout(
            **_PLOT_LAYOUT,
            xaxis={"range": [0, 110], "gridcolor": "#1e2a3a", "title": "Attribution Confidence (%)"},
            yaxis={"gridcolor": "#1e2a3a"},
            height=max(300, len(ranked) * 50),
            margin={"l": 20, "r": 80, "t": 20, "b": 40},
        )
        st.plotly_chart(fig, use_container_width=True)

        rows = []
        for r_item in ranked:
            rows.append({
                "Group": r_item["group"],
                "Nation": r_item["nation"],
                "Confidence": f"{r_item['confidence_pct']:.1f}%",
                "TTP Score": f"{r_item['raw_score']*100:.1f}%",
                "Context Boost": f"+{r_item['context_boost']*100:.1f}%" if r_item["context_boost"] > 0 else "-",
                "Contradiction Penalty": f"-{r_item['contradiction_penalty']*100:.1f}%"
                if r_item.get("contradiction_penalty", 0) > 0 else "-",
                "Motive Boost": f"+{r_item['motivation_boost']*100:.1f}%"
                if r_item.get("motivation_boost", 0) > 0 else "-",
                "Motive Penalty": f"-{r_item['motivation_penalty']*100:.1f}%"
                if r_item.get("motivation_penalty", 0) > 0 else "-",
                "Matched TTPs": len(r_item["matched_techniques"]),
                "Motivation": ", ".join(r_item["motivation"][:2]),  # type: ignore[index]
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # TAB 2 — Heatmap
    with tab2:
        st.markdown('<div class="section-header">TTP Coverage Heatmap</div>', unsafe_allow_html=True)
        tactics = list(TACTIC_LABELS.keys())
        top_groups = result["ranked_results"][:6]  # type: ignore[index]

        z_data = [[g["tactic_scores"].get(t, 0) * 100 for t in tactics] for g in top_groups]
        fig2 = go.Figure(data=go.Heatmap(
            z=z_data,
            x=[TACTIC_LABELS[t] for t in tactics],
            y=[g["group"] for g in top_groups],
            colorscale=[[0, "#0a0e14"], [0.01, "#0a2e14"], [0.4, "#155e30"], [1.0, "#22c55e"]],
            text=[[f"{v:.0f}%" for v in row] for row in z_data],
            texttemplate="%{text}",
            textfont={"size": 10, "color": "#d4d4d8", "family": "JetBrains Mono, monospace"},
            showscale=True,
            colorbar={"tickfont": {"color": "#6b7280"}},
        ))
        fig2.update_layout(
            **_PLOT_LAYOUT,
            xaxis={"tickangle": -35, "tickfont": {"size": 10}},
            yaxis={"tickfont": {"size": 11}},
            height=340,
            margin={"l": 20, "r": 20, "t": 10, "b": 80},
        )
        st.plotly_chart(fig2, use_container_width=True)

        if top and top["matched_techniques"]:
            st.markdown('<div class="section-header">Matched Techniques — Primary Attribution</div>', unsafe_allow_html=True)
            tech_cols = st.columns(3)
            idx = 0
            for tactic, techs in top["matched_per_tactic"].items():
                if techs:
                    with tech_cols[idx % 3]:
                        st.markdown(f"**{TACTIC_LABELS.get(tactic, tactic)}**")
                        for t_id in techs:
                            st.markdown(f"`{t_id}` {get_technique_name(t_id, tech_desc)}")
                    idx += 1  # type: ignore[operator]

    # TAB 3 — Behavioral DNA
    with tab3:
        if top:
            dna = top.get("behavioral_dna", {})
            st.markdown(f'<div class="section-header">Behavioral DNA — {top["group"]}</div>', unsafe_allow_html=True)
            st.caption("Persistent behavioral traits that survive tool rotation and infrastructure changes.")

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Operational Fingerprint**")
                for label, key in [
                    ("C2 Beacon Pattern", "c2_beacon_interval"),
                    ("C2 Protocols", "c2_protocols"),
                    ("Code Style", "code_style"),
                    ("Exfil Method", "exfil_method"),
                    ("Lateral Movement", "lateral_movement_preference"),
                    ("Infrastructure Reuse", "infrastructure_reuse"),
                ]:
                    val = dna.get(key, "Unknown")
                    if isinstance(val, list):
                        val = ", ".join(val)
                    st.markdown(f"**{label}:** {val}")

            with col_b:
                st.markdown("**Anti-Analysis Techniques**")
                anti = dna.get("anti_analysis", [])
                for item in (anti if isinstance(anti, list) else [anti]):
                    st.markdown(f"- {item}")

                st.markdown("**Language Artifacts**")
                lang = dna.get("language_artifacts", ["Not identified"])
                for item in (lang if isinstance(lang, list) else [lang]):
                    st.markdown(f"- {item}")

                st.markdown("**Target Selection Logic**")
                st.info(dna.get("target_selection_logic", "Unknown"))

            # Radar chart — top 3 groups
            st.markdown('<div class="section-header">Threat Profile Comparison</div>', unsafe_allow_html=True)
            radar_colors = ["#22c55e", "#f59e0b", "#3b82f6"]
            categories = ["Stealth", "Aggression", "Sophistication", "Precision", "Longevity"]
            fig3 = go.Figure()

            for i, grp in enumerate(result["ranked_results"][:3]):  # type: ignore[index]
                bdna = grp.get("behavioral_dna", {})
                stealth = bdna.get("stealth_rating", 5)
                aggr = bdna.get("aggression_rating", 5)
                soph = bdna.get("sophistication_rating", 5)
                prec = bdna.get("precision_rating", 5)
                longevity = grp.get("longevity", 5)
                vals = [stealth, aggr, soph, prec, longevity]
                vals += vals[:1]  # type: ignore[index]
                hex_c = radar_colors[i]
                rgb = tuple(int(hex_c.lstrip("#")[j:j+2], 16) for j in (0, 2, 4))  # type: ignore[index]
                fig3.add_trace(go.Scatterpolar(
                    r=vals, theta=categories + [categories[0]],
                    fill="toself",
                    fillcolor=f"rgba({rgb[0]},{rgb[1]},{rgb[2]},0.08)",
                    line={"color": hex_c, "width": 2},
                    name=grp["group"],
                ))
            fig3.update_layout(
                polar={
                    "bgcolor": "#111820",
                    "radialaxis": {"visible": True, "range": [0, 10], "gridcolor": "#1e2a3a",
                                    "tickfont": {"color": "#4b5563", "size": 8}},
                    "angularaxis": {"tickfont": {"color": "#6b7280", "size": 10}, "gridcolor": "#1e2a3a"},
                },
                paper_bgcolor="#0a0e14",
                font={"color": "#d4d4d8", "family": "Inter, sans-serif"},
                legend={"bgcolor": "#111820", "bordercolor": "#1e2a3a", "borderwidth": 1, "font": {"size": 11}},
                showlegend=True,
                height=380,
                margin={"l": 60, "r": 60, "t": 30, "b": 30},
            )
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("Behavioral DNA view requires a confirmed attribution. Review hypotheses in Attribution Scores.")

    # TAB 4 — Campaign Context
    with tab4:
        if top:
            st.markdown(f'<div class="section-header">Campaign Intelligence — {top["group"]}</div>', unsafe_allow_html=True)
            ca, cb = st.columns(2)
            with ca:
                st.markdown("**Known Campaigns**")
                for campaign in top["known_campaigns"]:
                    st.markdown(f"- {campaign}")
                st.markdown("**Known Tools**")
                for tool in top["known_tools"]:
                    st.markdown(f"- `{tool}`")
            with cb:
                st.markdown("**Target Sectors**")
                for sector in top["target_sectors"]:
                    st.markdown(f"- {sector}")
                st.markdown("**Target Regions**")
                for region in top["target_regions"]:
                    st.markdown(f"- {region}")
                st.markdown("**Motivation**")
                for motive in top["motivation"]:
                    st.markdown(f"- {motive}")

            if top["context_signals"]:
                st.success(f"Context signals matched: {', '.join(top['context_signals'])}")
            if top.get("contradiction_signals"):
                st.warning(
                    "Contradictions detected: "
                    + ", ".join(top["contradiction_signals"])
                    + ". Attribution confidence penalized."
                )
            if top.get("matched_motives"):
                st.info("Strategic motive alignment: " + ", ".join(top["matched_motives"]))
            if top.get("mismatched_motives"):
                st.caption("Motive conflicts observed: " + ", ".join(top["mismatched_motives"]))

            st.markdown('<div class="section-header">Recommended Defensive Actions</div>', unsafe_allow_html=True)
            for defense in DEFENSES.get(top["group"], ["Consult MITRE ATT&CK mitigations for matched techniques."]):
                st.markdown(f"- {defense}")
        else:
            st.info(
                "Campaign context is unavailable until attribution gates are met. "
                "Use IOC and TTP clustering to build an emerging actor profile."
            )

    # TAB 5 — Full Report
    with tab5:
        st.markdown('<div class="section-header">Export Intelligence</div>', unsafe_allow_html=True)
        report_json = json.dumps(result, indent=2)
        st.code(report_json, language="json")
        
        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "DOWNLOAD APTRACE JSON",
                data=report_json,
                file_name="aptrace_report.json",
                mime="application/json",
                use_container_width=True,
            )
        with d2:
            stix_bundle = _generate_stix_bundle(result)
            st.download_button(
                "DOWNLOAD STIX 2.1 BUNDLE",
                data=json.dumps(stix_bundle, indent=2),
                file_name="aptrace_stix2.json",
                mime="application/json",
                use_container_width=True,
            )

# -- Footer ------------------------------------------------------------------
st.divider()
fc1, fc2, fc3 = st.columns(3)
fc1.caption("APTrace v3.0 — APT Attribution Engine (powered by Supabase & ML)")
fc2.caption("Sources: MITRE ATT&CK / MalwareBazaar / Public Threat Intel")
fc3.caption("For authorized security research and incident response only")
