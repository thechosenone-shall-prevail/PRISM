"""
APTrace SIGINT Kiosk Dashboard
Run:
  python -m streamlit run dashboard.py --server.port 8502
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timedelta, timezone

import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="APTrace SIGINT Kiosk",
    page_icon="AP",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;700&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
  --bg: #070b11;
  --panel: #0f1722;
  --panel-2: #111d2a;
  --line: #1f3147;
  --text: #d8e1ea;
  --muted: #7d93a8;
  --green: #20e486;
  --amber: #f8b84e;
  --red: #ff5a72;
  --blue: #54a8ff;
}

.stApp {
  background:
    radial-gradient(circle at 8% 8%, rgba(32, 228, 134, 0.10), transparent 35%),
    radial-gradient(circle at 92% 12%, rgba(84, 168, 255, 0.10), transparent 38%),
    var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  height: 100vh;
  overflow: hidden !important;
}
html, body, [data-testid="stAppViewContainer"] { height: 100vh; overflow: hidden !important; }
.block-container { padding-top: 0.5rem !important; padding-bottom: 0.2rem !important; }

#MainMenu, footer { visibility: hidden; }

[data-testid="stHeader"] { background: transparent; }

.topbar {
  background: linear-gradient(90deg, rgba(32, 228, 134, 0.08), rgba(84, 168, 255, 0.08));
  border: 1px solid var(--line);
  border-left: 4px solid var(--green);
  padding: 14px 18px;
  margin-bottom: 12px;
}
.title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 34px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--text);
}
.subtitle {
  color: var(--muted);
  font-size: 12px;
  letter-spacing: 1px;
}
.clock {
  margin-top: 6px;
  font-size: 15px;
  color: var(--muted);
  display: flex;
  gap: 20px;
}
.clock b { color: var(--green); }

.panel-title {
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 2px;
  font-size: 11px;
  margin: 8px 0;
}

.feed-box {
  height: 335px;
  overflow: hidden;
  border: 1px solid var(--line);
  background: var(--panel);
  padding: 8px;
  display: grid;
  grid-auto-rows: 58px;
  gap: 6px;
}
.feed-item {
  border-left: 3px solid var(--blue);
  background: var(--panel-2);
  padding: 7px 10px 6px 10px;
  min-height: 58px;
  max-height: 58px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
}
.feed-item-crit { border-left-color: var(--red); }
.feed-item-high { border-left-color: var(--amber); }

.item-h {
  color: var(--text);
  font-size: 12px;
  line-height: 1.2;
  white-space: normal;
  overflow-wrap: anywhere;
  margin-bottom: 3px;
  display: -webkit-box;
  -webkit-line-clamp: 1;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.item-m {
  color: var(--muted);
  font-size: 10px;
  line-height: 1.15;
  white-space: normal;
  overflow-wrap: anywhere;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  margin: 0;
}

div[data-testid="metric-container"] {
  border: 1px solid var(--line);
  background: var(--panel);
}
div[data-testid="metric-container"] [data-testid="stMetricLabel"] {
  color: var(--muted);
}
div[data-testid="metric-container"] [data-testid="stMetricValue"] {
  color: var(--green);
  font-family: 'Rajdhani', sans-serif;
  font-size: 32px;
}
</style>
""",
    unsafe_allow_html=True,
)

UA = {"User-Agent": "APTrace-SIGINT-Kiosk/1.0"}
AUTO_REFRESH_MS = 60 * 60 * 1000


def _get_json(url: str, timeout: int = 25) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def _get_text(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


@st.cache_data(ttl=300, show_spinner=False)
def fetch_cisa_kev() -> tuple[list[dict], str | None]:
    try:
        data = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        vulns = data.get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        return vulns, None
    except Exception as exc:
        return [], str(exc)


@st.cache_data(ttl=300, show_spinner=False)
def fetch_nvd_recent() -> tuple[list[dict], str | None]:
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        base = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            "&resultsPerPage=25"
        )
        critical = _get_json(base + "&cvssV3Severity=CRITICAL").get("vulnerabilities", [])
        high = _get_json(base + "&cvssV3Severity=HIGH").get("vulnerabilities", [])
        return critical + high, None
    except Exception as exc:
        return [], str(exc)


@st.cache_data(ttl=1800, show_spinner=False)
def fetch_mitre() -> tuple[list[dict], list[dict], str | None]:
    try:
        stix = _get_json(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        )
        groups: list[dict] = []
        techniques: list[dict] = []
        for obj in stix.get("objects", []):
            if obj.get("type") == "intrusion-set" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                groups.append(
                    {
                        "name": obj.get("name", ""),
                        "modified": obj.get("modified", ""),
                    }
                )
            if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                tid = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id", "")
                        break
                techniques.append(
                    {
                        "id": tid,
                        "name": obj.get("name", ""),
                        "modified": obj.get("modified", ""),
                    }
                )
        groups.sort(key=lambda x: x["modified"], reverse=True)
        techniques.sort(key=lambda x: x["modified"], reverse=True)
        return groups, techniques, None
    except Exception as exc:
        return [], [], str(exc)


def _cvss(v: dict) -> float | None:
    try:
        c = v.get("cve", {})
        metrics = c.get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in metrics and metrics[k]:
                return float(metrics[k][0]["cvssData"]["baseScore"])
    except Exception:
        return None
    return None


def _sev_class(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "feed-item-crit"
    if score >= 7.0:
        return "feed-item-high"
    return ""


with st.spinner("Loading live intelligence feeds..."):
    kev, kev_err = fetch_cisa_kev()
    nvd, nvd_err = fetch_nvd_recent()
    groups, techs, mitre_err = fetch_mitre()

now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
components.html(
    f"""
<script>
setTimeout(function() {{
  window.parent.location.reload();
}}, {AUTO_REFRESH_MS});
</script>
""",
    height=0,
)
components.html(
    """
<script>
function pad(n){ return String(n).padStart(2, '0'); }
function renderClock(){
  const now = new Date();
  const utc = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
  const istStr = now.toLocaleTimeString('en-GB', { timeZone: 'Asia/Kolkata', hour12: false });
  const utcEl = window.parent.document.getElementById('clock-utc');
  const istEl = window.parent.document.getElementById('clock-ist');
  if (utcEl) utcEl.textContent = utc;
  if (istEl) istEl.textContent = istStr;
}
renderClock();
setInterval(renderClock, 1000);
</script>
""",
    height=0,
)

st.markdown(
    f"""
<div class="topbar">
  <div class="title">APTRACE SIGINT KIOSK</div>
  <div class="subtitle">LIVE THREAT INTELLIGENCE SURFACE | LAST UPDATE: {now}</div>
  <div class="clock">
    <span><b>IST</b> <span id="clock-ist">--:--:--</span></span>
    <span><b>UTC</b> <span id="clock-utc">--:--:--</span></span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
col_m1.metric("CISA KEV", len(kev))
col_m2.metric("NVD CVEs (7d)", len(nvd))
col_m3.metric("Critical CVEs", len([x for x in nvd if (_cvss(x) or 0) >= 9.0]))
col_m4.metric("MITRE Groups", len(groups))
col_m5.metric("MITRE Techniques", len(techs))
st.caption("Snapshot refresh: every 60 minutes (automatic kiosk cycle).")

e1, e2, e3 = st.columns(3)
with e1:
    st.markdown('<div class="panel-title">CISA KEV (Recent)</div>', unsafe_allow_html=True)
    if kev_err:
        st.error(kev_err)
    else:
        html = '<div class="feed-box">'
        for item in kev[:10]:
            html += (
                '<div class="feed-item">'
                f'<div class="item-h">{item.get("cveID", "")} | {item.get("vulnerabilityName", "")}</div>'
                f'<div class="item-m">{item.get("vendorProject", "")} / {item.get("product", "")} | Added: {item.get("dateAdded", "")}</div>'
                "</div>"
            )
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)

with e2:
    st.markdown('<div class="panel-title">NVD High/Critical (7d)</div>', unsafe_allow_html=True)
    if nvd_err:
        st.error(nvd_err)
    else:
        html = '<div class="feed-box">'
        for wrap in nvd[:10]:
            c = wrap.get("cve", {})
            cve_id = c.get("id", "")
            score = _cvss(wrap)
            sev = _sev_class(score)
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            html += (
                f'<div class="feed-item {sev}">'
                f'<div class="item-h">{cve_id} | CVSS: {score if score is not None else "n/a"}</div>'
                f'<div class="item-m">{desc}</div>'
                "</div>"
            )
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)

with e3:
    st.markdown('<div class="panel-title">MITRE ATT&CK Updates</div>', unsafe_allow_html=True)
    if mitre_err:
        st.error(mitre_err)
    else:
        html = '<div class="feed-box">'
        for g in groups[:6]:
            html += (
                '<div class="feed-item">'
                f'<div class="item-h">GROUP | {g["name"]}</div>'
                f'<div class="item-m">Modified: {g["modified"][:10]}</div>'
                "</div>"
            )
        for t in techs[:4]:
            html += (
                '<div class="feed-item">'
                f'<div class="item-h">TECHNIQUE | {t["id"]} {t["name"]}</div>'
                f'<div class="item-m">Modified: {t["modified"][:10]}</div>'
                "</div>"
            )
        html += "</div>"
        st.markdown(html, unsafe_allow_html=True)

st.caption("Kiosk mode: static one-screen snapshot. Auto-refresh runs hourly.")
