"""
PRISM Backend — Report Generation Router
Generates comprehensive threat reports using DeepSeek Chat API.
"""

import json
import logging
import os
import httpx
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("PRISM.report")

router = APIRouter()

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


def _get_api_key() -> str:
    key = os.getenv("DEEPSEEK_API_KEY", "")
    if not key:
        raise HTTPException(
            status_code=500,
            detail="DEEPSEEK_API_KEY not set in backend/.env",
        )
    return key


# ── Request / Response models ──────────────────────────────────────────

class ReportRequest(BaseModel):
    """All the data collected from every dashboard tab."""
    # Attribution
    attribution: dict = Field(default_factory=dict)
    # TTP Analysis
    ttp_analysis: dict = Field(default_factory=dict)
    # ML Engine results
    ml_results: dict = Field(default_factory=dict)
    # Sandbox timeline
    sandbox: dict = Field(default_factory=dict)
    # Blast radius graph
    blast_radius: dict = Field(default_factory=dict)
    # Threat intel
    threat_intel: dict = Field(default_factory=dict)
    # Malware sample metadata
    malware_info: dict = Field(default_factory=dict)
    # User notes / context
    analyst_notes: str = ""


class ReportResponse(BaseModel):
    report_id: str
    generated_at: str
    title: str
    executive_summary: str
    sections: list[dict]
    raw_data: dict
    charts_data: dict


# ── Prompt builder ─────────────────────────────────────────────────────

def _build_prompt(data: ReportRequest) -> str:
    """Build a detailed prompt for DeepSeek with all the analysis data."""

    sections = []

    # Attribution
    attr = data.attribution
    if attr:
        top = attr.get("top_group", "Unknown")
        conf = attr.get("confidence_pct", 0)
        preds = attr.get("predictions", [])
        reasoning = attr.get("reasoning", "")
        ttps = attr.get("observed_techniques", [])
        sections.append(f"""## Attribution Data
- Top attribution: {top} at {conf}% confidence
- Confidence tier: {attr.get('confidence_tier', 'N/A')}
- Reasoning: {reasoning}
- Observed MITRE ATT&CK techniques ({len(ttps)}): {', '.join(ttps[:30]) if ttps else 'None'}
- Runner-up predictions: {json.dumps(preds[:5], default=str) if preds else 'None'}
- Behavioral notes: {attr.get('behavioral_notes', 'N/A')}
- Context signals: {json.dumps(attr.get('context_signals', []), default=str)}""")

    # TTP Analysis
    ttp = data.ttp_analysis
    if ttp:
        techniques = ttp.get("techniques", [])
        tactics = ttp.get("tactic_breakdown", {})
        sections.append(f"""## TTP Analysis
- Total techniques identified: {len(techniques)}
- Techniques: {', '.join(techniques[:40]) if techniques else 'None'}
- Tactic breakdown: {json.dumps(tactics, default=str) if tactics else 'N/A'}
- Key observations: {ttp.get('notes', 'N/A')}""")

    # ML Engine
    ml = data.ml_results
    if ml:
        sections.append(f"""## ML Engine Results
- Model version: {ml.get('model_version', 'N/A')}
- Top prediction: {ml.get('top_group', 'Unknown')} at {ml.get('confidence_pct', 0)}%
- Confidence tier: {ml.get('confidence_tier', 'N/A')}
- Signal count: {ml.get('signal_count', 0)}
- All predictions: {json.dumps(ml.get('predictions', [])[:5], default=str)}
- SHAP explanation: {json.dumps(ml.get('shap_explanation', [])[:10], default=str)}""")

    # Sandbox
    sb = data.sandbox
    if sb:
        timeline = sb.get("timeline", [])
        sections.append(f"""## Sandbox Analysis
- Analysis type: {sb.get('analysis_type', 'N/A')}
- Processes observed: {sb.get('process_count', 0)}
- Registry operations: {sb.get('registry_count', 0)}
- File operations: {sb.get('file_count', 0)}
- Network connections: {sb.get('network_count', 0)}
- Entropy: {sb.get('entropy', 'N/A')}
- Timeline events ({len(timeline)}): {json.dumps(timeline[:10], default=str) if timeline else 'None'}""")

    # Blast radius
    br = data.blast_radius
    if br:
        nodes = br.get("nodes", [])
        edges = br.get("edges", [])
        sections.append(f"""## Blast Radius / Attack Graph
- Total nodes: {len(nodes)}
- Total edges: {len(edges)}
- Node types: {json.dumps(br.get('node_type_counts', {}), default=str)}
- Kill-chain stages: {json.dumps(br.get('kill_chain', {}), default=str)}
- Seed IOC: {br.get('seed_ioc', 'N/A')}
- Attribution signal: {br.get('attribution_signal', 'N/A')}""")

    # Threat intel
    ti = data.threat_intel
    if ti:
        sections.append(f"""## Threat Intelligence Correlation
- Matched campaigns: {json.dumps(ti.get('campaigns', []), default=str)}
- CISA KEV matches: {ti.get('kev_matches', 0)}
- Related CVEs: {json.dumps(ti.get('cves', [])[:10], default=str)}""")

    # Malware info
    mw = data.malware_info
    if mw:
        sections.append(f"""## Malware Sample Information
- Filename: {mw.get('filename', 'N/A')}
- File size: {mw.get('file_size', 'N/A')}
- File hashes: SHA256={mw.get('sha256', 'N/A')}, MD5={mw.get('md5', 'N/A')}
- Malware family: {mw.get('family', 'N/A')}
- VirusTotal detection: {mw.get('vt_detection', 'N/A')}
- Compile timestamp: {mw.get('compile_timestamp', 'N/A')}
- Imphash: {mw.get('imphash', 'N/A')}
- Section names: {json.dumps(mw.get('section_names', []), default=str)}""")

    # Analyst notes
    if data.analyst_notes:
        sections.append(f"""## Analyst Notes
{data.analyst_notes}""")

    data_block = "\n\n".join(sections) if sections else "No analysis data was provided."

    prompt = f"""You are an expert cybersecurity threat intelligence analyst. Generate a comprehensive threat analysis report based on the following data collected from the PRISM APT attribution platform.

{data_block}

---

Generate a COMPREHENSIVE threat intelligence report with the following structure. Use markdown formatting. Be thorough, technical, and analytical. If some data sections are missing, note the gap and work with what's available.

**IMPORTANT FORMAT REQUIREMENTS:**
1. Start with a clear TITLE (# Title)
2. Include an EXECUTIVE SUMMARY (2-3 paragraphs for leadership)
3. For each major section, provide detailed technical analysis
4. Include a CHART_DATA JSON block (wrapped in ```chart_data ... ```) with visualization data:
   - "threat_level_gauge": number 0-100 representing overall threat severity
   - "ttp_tactic_distribution": object mapping MITRE tactic names to counts
   - "confidence_breakdown": array of {{name, value}} for attribution confidence per group
   - "kill_chain_coverage": object mapping kill-chain phases to boolean coverage
   - "risk_scores": array of {{category, score}} for different risk dimensions
   - "timeline_events": array of {{time, event, severity}} for key events
5. Provide MITRE ATT&CK mapping details with technique descriptions
6. Analyze the threat actor's INTENT, CAPABILITY, and OPPORTUNITY
7. Include RECOMMENDATIONS for defenders
8. End with IOC SUMMARY table if available

Write at MINIMUM 2000 words. Be exhaustive — this is a formal incident report."""

    return prompt


# ── Endpoint ───────────────────────────────────────────────────────────

@router.post("/report/generate", response_model=ReportResponse)
async def generate_report(req: ReportRequest):
    """Generate a comprehensive AI-powered threat intelligence report."""

    api_key = _get_api_key()
    prompt = _build_prompt(req)

    report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # Call DeepSeek Chat API
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                DEEPSEEK_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": DEEPSEEK_MODEL,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are PRISM AI — an advanced cyber threat intelligence "
                                "report generator. You produce formal, detailed, publication-"
                                "quality threat analysis reports with technical depth. "
                                "Always include a chart_data JSON code block for visualizations."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.4,
                    "max_tokens": 8192,
                    "stream": False,
                },
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="DeepSeek API timed out (120s)")
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Cannot connect to DeepSeek API")

    if resp.status_code != 200:
        logger.error(f"DeepSeek API error {resp.status_code}: {resp.text[:500]}")
        raise HTTPException(
            status_code=502,
            detail=f"DeepSeek API returned {resp.status_code}",
        )

    body = resp.json()
    ai_text = body.get("choices", [{}])[0].get("message", {}).get("content", "")

    if not ai_text:
        raise HTTPException(status_code=502, detail="Empty response from DeepSeek")

    # Parse chart_data block if present
    charts_data = _extract_chart_data(ai_text)

    # Parse into sections
    sections = _parse_sections(ai_text)

    # Extract title
    title = "PRISM Threat Intelligence Report"
    if sections and sections[0].get("heading"):
        title = sections[0]["heading"]

    # Extract executive summary
    exec_summary = ""
    for sec in sections:
        h = (sec.get("heading") or "").lower()
        if "executive" in h or "summary" in h:
            exec_summary = sec.get("content", "")
            break
    if not exec_summary and sections:
        exec_summary = sections[0].get("content", "")[:600]

    return ReportResponse(
        report_id=report_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        title=title,
        executive_summary=exec_summary,
        sections=sections,
        raw_data={
            "full_markdown": re.sub(r"```(?:chart_data|json)\s*\n.*?```", "", ai_text, flags=re.DOTALL).strip(),
            "input_summary": {
                "has_attribution": bool(req.attribution),
                "has_ttp": bool(req.ttp_analysis),
                "has_ml": bool(req.ml_results),
                "has_sandbox": bool(req.sandbox),
                "has_blast_radius": bool(req.blast_radius),
                "has_threat_intel": bool(req.threat_intel),
                "has_malware_info": bool(req.malware_info),
            },
            "model_used": DEEPSEEK_MODEL,
            "usage": body.get("usage", {}),
        },
        charts_data=charts_data,
    )


@router.post("/report/generate-offline")
async def generate_report_offline(req: ReportRequest):
    """Generate a report without LLM — pure template-based fallback."""

    report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    attr = req.attribution
    top_group = attr.get("top_group", "Unknown")
    conf = attr.get("confidence_pct", 0)
    ttps = attr.get("observed_techniques", [])
    mw = req.malware_info
    sb = req.sandbox

    title = f"Threat Report — {top_group}"

    exec_summary = (
        f"This report summarizes the analysis of a suspected cyber threat attributed to "
        f"**{top_group}** with {conf}% confidence. "
        f"A total of {len(ttps)} MITRE ATT&CK techniques were identified during analysis. "
    )
    if mw.get("family"):
        exec_summary += f"The malware sample belongs to the **{mw['family']}** family. "
    if mw.get("vt_detection"):
        exec_summary += f"VirusTotal detection ratio: {mw['vt_detection']}. "

    sections = [
        {"heading": title, "content": exec_summary},
        {
            "heading": "Attribution Analysis",
            "content": (
                f"Primary attribution: **{top_group}** ({conf}% confidence, "
                f"tier: {attr.get('confidence_tier', 'LOW')}).\n\n"
                f"Reasoning: {attr.get('reasoning', 'Automated ML attribution.')}\n\n"
                + (
                    "### Alternative Candidates\n"
                    + "\n".join(
                        f"- {p.get('group','?')}: {round(p.get('probability',0)*100,1)}% — {p.get('reasoning','')}"
                        for p in attr.get("predictions", [])[:5]
                    )
                    if attr.get("predictions") else ""
                )
            ),
        },
        {
            "heading": "MITRE ATT&CK Mapping",
            "content": (
                f"**{len(ttps)} techniques** identified:\n\n"
                + ", ".join(f"`{t}`" for t in ttps[:50])
                if ttps else "No techniques extracted."
            ),
        },
    ]

    if sb:
        sections.append({
            "heading": "Sandbox Analysis",
            "content": (
                f"Processes: {sb.get('process_count', 0)} | "
                f"Registry ops: {sb.get('registry_count', 0)} | "
                f"File ops: {sb.get('file_count', 0)} | "
                f"Network: {sb.get('network_count', 0)}"
            ),
        })

    # Build chart data from available info
    charts_data = _build_offline_charts(req)

    sections.append({
        "heading": "Recommendations",
        "content": (
            "1. Block IOCs identified in this report at network perimeter\n"
            "2. Hunt for listed MITRE techniques in SIEM / EDR\n"
            "3. Brief SOC team on the TTPs associated with this threat actor\n"
            "4. Review access controls for targeted asset types\n"
            "5. Consider engaging threat intelligence partner for deeper analysis"
        ),
    })

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "title": title,
        "executive_summary": exec_summary,
        "sections": sections,
        "raw_data": {
            "full_markdown": "\n\n".join(
                f"# {s['heading']}\n\n{s['content']}" for s in sections
            ),
            "input_summary": {
                "has_attribution": bool(req.attribution),
                "has_ttp": bool(req.ttp_analysis),
                "has_ml": bool(req.ml_results),
                "has_sandbox": bool(req.sandbox),
                "has_blast_radius": bool(req.blast_radius),
                "has_threat_intel": bool(req.threat_intel),
                "has_malware_info": bool(req.malware_info),
            },
            "model_used": "offline-template",
        },
        "charts_data": charts_data,
    }


# ── Helpers ────────────────────────────────────────────────────────────

def _extract_chart_data(text: str) -> dict:
    """Extract the ```chart_data JSON block from the AI response."""
    import re
    m = re.search(r"```chart_data\s*\n(.*?)```", text, re.DOTALL)
    if not m:
        m = re.search(r"```json\s*\n(\{[^`]*\"threat_level_gauge\"[^`]*\})```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            logger.warning("Failed to parse chart_data JSON from AI response")
    return {}


def _parse_sections(text: str) -> list[dict]:
    """Split markdown text into heading/content sections."""
    import re
    # Remove chart_data blocks from display
    cleaned = re.sub(r"```chart_data\s*\n.*?```", "", text, flags=re.DOTALL)
    # Split on markdown headings
    parts = re.split(r"^(#{1,3}\s+.+)$", cleaned, flags=re.MULTILINE)
    sections = []
    current_heading = ""
    current_content = ""

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if re.match(r"^#{1,3}\s+", part):
            if current_heading or current_content:
                sections.append({
                    "heading": current_heading.lstrip("# ").strip(),
                    "content": current_content.strip(),
                })
            current_heading = part
            current_content = ""
        else:
            current_content += part + "\n"

    if current_heading or current_content:
        sections.append({
            "heading": current_heading.lstrip("# ").strip(),
            "content": current_content.strip(),
        })

    return sections


def _build_offline_charts(req: ReportRequest) -> dict:
    """Build chart data from raw analysis data without LLM."""
    attr = req.attribution
    preds = attr.get("predictions", [])
    ttps = attr.get("observed_techniques", [])

    # Tactic distribution
    tactic_map = {
        "T1566": "initial-access", "T1190": "initial-access", "T1133": "initial-access",
        "T1189": "initial-access", "T1195": "initial-access",
        "T1059": "execution", "T1106": "execution", "T1204": "execution",
        "T1053": "execution", "T1047": "execution",
        "T1547": "persistence", "T1543": "persistence", "T1098": "persistence",
        "T1055": "defense-evasion", "T1027": "defense-evasion", "T1140": "defense-evasion",
        "T1112": "defense-evasion", "T1497": "defense-evasion",
        "T1003": "credential-access", "T1110": "credential-access",
        "T1071": "command-and-control", "T1105": "command-and-control",
        "T1041": "exfiltration", "T1567": "exfiltration",
        "T1486": "impact", "T1489": "impact", "T1529": "impact",
    }
    tactic_counts: dict[str, int] = {}
    for t in ttps:
        base = t.split(".")[0]
        tactic = tactic_map.get(base, "unknown")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    # Confidence breakdown
    conf_breakdown = [
        {"name": p.get("group", "?"), "value": round(p.get("probability", 0) * 100, 1)}
        for p in preds[:8]
    ]

    # Risk scores
    ttp_count = len(ttps)
    conf_pct = attr.get("confidence_pct", 0)
    risk_scores = [
        {"category": "Technical Sophistication", "score": min(100, ttp_count * 5)},
        {"category": "Attribution Confidence", "score": conf_pct},
        {"category": "Impact Potential", "score": min(100, ttp_count * 4 + 20)},
        {"category": "Evasion Capability", "score": min(100, tactic_counts.get("defense-evasion", 0) * 25)},
        {"category": "Persistence Risk", "score": min(100, tactic_counts.get("persistence", 0) * 30)},
    ]

    return {
        "threat_level_gauge": min(100, int(conf_pct * 0.4 + ttp_count * 2 + 20)),
        "ttp_tactic_distribution": tactic_counts,
        "confidence_breakdown": conf_breakdown,
        "kill_chain_coverage": {
            "Reconnaissance": False,
            "Initial Access": tactic_counts.get("initial-access", 0) > 0,
            "Execution": tactic_counts.get("execution", 0) > 0,
            "Persistence": tactic_counts.get("persistence", 0) > 0,
            "Defense Evasion": tactic_counts.get("defense-evasion", 0) > 0,
            "C2": tactic_counts.get("command-and-control", 0) > 0,
            "Exfiltration": tactic_counts.get("exfiltration", 0) > 0,
            "Impact": tactic_counts.get("impact", 0) > 0,
        },
        "risk_scores": risk_scores,
    }
