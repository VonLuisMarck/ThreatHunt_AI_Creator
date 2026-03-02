"""
ThreatHunt AI Creator — Streamlit Web Interface
Run with: streamlit run app.py
"""

import os
# Load .env before anything else so API keys are available to all providers
from dotenv import load_dotenv
load_dotenv()

import streamlit as st
import tempfile
import json
import pandas as pd
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────
#  Page config (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatHunt AI Creator",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────
#  Custom CSS — premium dark theme with CrowdStrike red accents
# ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ═══════════════════════════════════════════════════════════════
   BASE — force dark everywhere Streamlit might inject light
   ═══════════════════════════════════════════════════════════════ */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
[data-testid="block-container"],
section.main,
.main .block-container,
[class*="css"] {
    background-color: #0d0d0d !important;
    color: #e2e2e2 !important;
    font-family: 'Segoe UI', 'Inter', system-ui, sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #111117 !important;
    border-right: 1px solid #1e1e28 !important;
}
[data-testid="stSidebar"] * { color: #c8c8d8 !important; }

/* ═══════════════════════════════════════════════════════════════
   HEADER BANNER
   ═══════════════════════════════════════════════════════════════ */
.cs-header {
    background: linear-gradient(120deg, #100000 0%, #1a0000 40%, #0d0d0d 100%);
    padding: 1.6rem 2.2rem;
    border-radius: 14px;
    margin-bottom: 1.8rem;
    border: 1px solid #2a0000;
    border-left: 5px solid #CC0000;
    box-shadow: 0 4px 24px rgba(204,0,0,0.12), 0 1px 4px rgba(0,0,0,0.6);
}
.cs-header h1 {
    color: #ffffff;
    margin: 0;
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    text-shadow: 0 0 30px rgba(204,0,0,0.3);
}
.cs-header p {
    color: #888899;
    margin: 0.35rem 0 0 0;
    font-size: 0.88rem;
    letter-spacing: 0.2px;
}

/* ═══════════════════════════════════════════════════════════════
   METRIC CARDS
   ═══════════════════════════════════════════════════════════════ */
.metric-card {
    background: linear-gradient(145deg, #161620, #111118);
    border: 1px solid #222230;
    border-radius: 12px;
    padding: 1.1rem 1rem;
    text-align: center;
    border-top: 3px solid #CC0000;
    box-shadow: 0 2px 12px rgba(0,0,0,0.4);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(204,0,0,0.15);
}
.metric-card .value {
    font-size: 2rem;
    font-weight: 700;
    color: #e03030;
    line-height: 1;
}
.metric-card .label {
    font-size: 0.68rem;
    color: #555566;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-top: 0.4rem;
    font-weight: 600;
}

/* ═══════════════════════════════════════════════════════════════
   SECTION TITLES
   ═══════════════════════════════════════════════════════════════ */
.section-title {
    font-size: 0.7rem;
    font-weight: 700;
    color: #cc3333;
    text-transform: uppercase;
    letter-spacing: 2px;
    border-bottom: 1px solid #1e1e28;
    padding-bottom: 0.45rem;
    margin-bottom: 0.9rem;
}

/* ═══════════════════════════════════════════════════════════════
   IOC BADGES
   ═══════════════════════════════════════════════════════════════ */
.ioc-badge {
    display: inline-block;
    background: #1a0a0a;
    border: 1px solid #3a1010;
    color: #e06060;
    font-family: 'Consolas', 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    padding: 0.15rem 0.55rem;
    border-radius: 5px;
    margin: 2px;
    letter-spacing: 0.2px;
}

/* ═══════════════════════════════════════════════════════════════
   TACTIC PILLS & RISK BADGES
   ═══════════════════════════════════════════════════════════════ */
.tactic-pill {
    display: inline-block;
    padding: 0.22rem 0.65rem;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 600;
    margin: 2px;
    letter-spacing: 0.2px;
}
.risk-low    { background: #0a1f0a; color: #50d050; border: 1px solid #204020; border-radius: 5px; padding: 2px 8px; }
.risk-medium { background: #1f1400; color: #e09020; border: 1px solid #402800; border-radius: 5px; padding: 2px 8px; }
.risk-high   { background: #1f0000; color: #e04040; border: 1px solid #400000; border-radius: 5px; padding: 2px 8px; }

/* ═══════════════════════════════════════════════════════════════
   STATUS BADGES (library / llm)
   ═══════════════════════════════════════════════════════════════ */
.badge-library { background: #0a1525; color: #5588cc; border: 1px solid #1a3055;
                 border-radius: 4px; padding: 1px 7px; font-size: 0.68rem; font-weight: 600; }
.badge-llm     { background: #150a25; color: #9966dd; border: 1px solid #301555;
                 border-radius: 4px; padding: 1px 7px; font-size: 0.68rem; font-weight: 600; }

/* ═══════════════════════════════════════════════════════════════
   NARRATIVE SUMMARY BOX
   ═══════════════════════════════════════════════════════════════ */
.summary-box {
    background: #0e0e14;
    border: 1px solid #1e1e2c;
    border-left: 4px solid #CC0000;
    border-radius: 10px;
    padding: 1.6rem 1.8rem;
    line-height: 1.8;
    font-size: 0.88rem;
    color: #c0c0d0;
    white-space: pre-wrap;
    box-shadow: inset 0 1px 8px rgba(0,0,0,0.3);
}

/* ═══════════════════════════════════════════════════════════════
   STREAMLIT COMPONENT OVERRIDES
   ═══════════════════════════════════════════════════════════════ */

/* Tabs */
[data-testid="stTabs"] [role="tablist"] {
    background: #111118 !important;
    border-bottom: 1px solid #1e1e28 !important;
    border-radius: 8px 8px 0 0;
    gap: 2px;
    padding: 0 0.5rem;
}
[data-testid="stTabs"] [role="tab"] {
    color: #666677 !important;
    font-weight: 600 !important;
    font-size: 0.82rem !important;
    border-radius: 6px 6px 0 0 !important;
    padding: 0.6rem 1rem !important;
    border-bottom: 2px solid transparent !important;
    transition: color 0.15s ease !important;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: #CC0000 !important;
    border-bottom: 2px solid #CC0000 !important;
    background: transparent !important;
}
[data-testid="stTabs"] [role="tab"]:hover {
    color: #cc4444 !important;
    background: #1a0808 !important;
}

/* Expanders */
[data-testid="stExpander"] {
    background: #111118 !important;
    border: 1px solid #1e1e28 !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"] summary {
    color: #c0c0d0 !important;
    font-weight: 600 !important;
}

/* Dataframes */
[data-testid="stDataFrame"] {
    border: 1px solid #1e1e28 !important;
    border-radius: 8px !important;
    overflow: hidden;
}
[data-testid="stDataFrame"] th {
    background: #111118 !important;
    color: #888899 !important;
    font-size: 0.75rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.8px !important;
    border-bottom: 1px solid #2a2a38 !important;
}
[data-testid="stDataFrame"] td {
    background: #0d0d0d !important;
    color: #c8c8d8 !important;
    border-bottom: 1px solid #181820 !important;
    font-size: 0.83rem !important;
}
[data-testid="stDataFrame"] tr:hover td {
    background: #151520 !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #CC0000, #990000) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    letter-spacing: 0.5px !important;
    padding: 0.55rem 1.5rem !important;
    width: 100% !important;
    box-shadow: 0 2px 12px rgba(204,0,0,0.25) !important;
    transition: all 0.15s ease !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #e00000, #bb0000) !important;
    box-shadow: 0 4px 18px rgba(204,0,0,0.4) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:disabled {
    background: #1e1e28 !important;
    color: #444455 !important;
    box-shadow: none !important;
    transform: none !important;
}

/* Download buttons */
.stDownloadButton > button {
    background: #0a1f0a !important;
    color: #50d050 !important;
    border: 1px solid #204020 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    transition: all 0.15s ease !important;
}
.stDownloadButton > button:hover {
    background: #0f2a0f !important;
    border-color: #50d050 !important;
    box-shadow: 0 2px 12px rgba(80,208,80,0.2) !important;
}

/* File uploader */
[data-testid="stFileUploader"] {
    background: #111118 !important;
    border: 2px dashed #2a2a38 !important;
    border-radius: 10px !important;
    padding: 0.8rem !important;
    transition: border-color 0.2s ease !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: #CC0000 !important;
}

/* Selectboxes & inputs */
[data-testid="stSelectbox"] > div > div,
[data-testid="stMultiSelect"] > div > div {
    background: #111118 !important;
    border: 1px solid #2a2a38 !important;
    border-radius: 7px !important;
    color: #e2e2e2 !important;
}

/* Alerts */
[data-testid="stAlert"] {
    border-radius: 8px !important;
    border: 1px solid;
}

/* Code blocks */
[data-testid="stCode"] {
    background: #090912 !important;
    border: 1px solid #1a1a28 !important;
    border-radius: 8px !important;
}
[data-testid="stCode"] code {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace !important;
    font-size: 0.82rem !important;
}

/* Progress bar */
[data-testid="stProgressBar"] > div > div {
    background: linear-gradient(90deg, #990000, #CC0000) !important;
    border-radius: 4px !important;
}

/* Info / Success / Error boxes */
div[data-testid="stAlert"][kind="info"]    { background: #0a0f1f !important; border-color: #1a3060 !important; }
div[data-testid="stAlert"][kind="success"] { background: #0a1a0a !important; border-color: #204020 !important; }
div[data-testid="stAlert"][kind="error"]   { background: #1a0505 !important; border-color: #400000 !important; }
div[data-testid="stAlert"][kind="warning"] { background: #1a1000 !important; border-color: #402800 !important; }

/* Scrollbar */
::-webkit-scrollbar       { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d0d0d; }
::-webkit-scrollbar-thumb { background: #2a2a38; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #CC0000; }

/* HR divider */
hr { border-color: #1e1e28 !important; margin: 1rem 0 !important; }

/* ═══════════════════════════════════════════════════════════════
   AGENT GRAPH
   ═══════════════════════════════════════════════════════════════ */
.agent-detail-box {
    background: #090912;
    border: 1px solid #1a1a28;
    border-left: 3px solid #CC0000;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.79rem;
    color: #b0b0c8;
    white-space: pre-wrap;
    line-height: 1.7;
    max-height: 300px;
    overflow-y: auto;
}
.graph-section {
    background: #0a0a12;
    border: 1px solid #1a1a28;
    border-radius: 12px;
    padding: 1.2rem 1.4rem 1rem;
    margin-bottom: 1.2rem;
}
.graph-section-title {
    font-size: 0.68rem;
    font-weight: 700;
    color: #cc3333;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 0.8rem;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

TACTIC_COLORS = {
    "Initial Access":        "#8b1a1a",
    "Execution":             "#8b4a1a",
    "Persistence":           "#6b6b1a",
    "Privilege Escalation":  "#1a6b6b",
    "Defense Evasion":       "#1a3a8b",
    "Credential Access":     "#4a1a8b",
    "Discovery":             "#1a6b1a",
    "Lateral Movement":      "#8b1a6b",
    "Collection":            "#1a5a8b",
    "Command And Control":   "#8b5a1a",
    "Exfiltration":          "#5a8b1a",
    "Impact":                "#8b0000",
}

RISK_COLORS = {"low": "🟢", "medium": "🟡", "high": "🔴"}


def metric_card(value, label):
    return f"""
    <div class="metric-card">
        <div class="value">{value}</div>
        <div class="label">{label}</div>
    </div>"""


def risk_badge(risk: str) -> str:
    cls = f"risk-{risk.lower()}" if risk.lower() in ("low", "medium", "high") else "risk-medium"
    return f'<span class="tactic-pill {cls}">{risk.upper()}</span>'


def tactic_pill(tactic: str) -> str:
    color = TACTIC_COLORS.get(tactic, "#555")
    return f'<span class="tactic-pill" style="background:{color}22;color:{color};border:1px solid {color}">{tactic}</span>'


# ── Multi-agent graph helpers ─────────────────────────────────────

_GRAPH_NODES = [
    ("recon",              "🔍", "Recon",     "Haiku",  75),
    ("threat_intel",       "🧠", "Intel",      "Opus",   220),
    ("attack_planner",     "⚔️",  "Planner",    "Opus",   365),
    ("payload_crafter",    "💻", "Crafter",    "Sonnet", 510),
    ("playbook_assembler", "📋", "Assembler",  "Sonnet", 655),
    ("validator",          "✅", "Validator",  "Sonnet", 800),
]
_KEY_TO_AGENT_NAME = {
    "recon": "ReconAgent", "threat_intel": "ThreatIntelAgent",
    "attack_planner": "AttackPlannerAgent", "payload_crafter": "PayloadCrafterAgent",
    "playbook_assembler": "PlaybookAssemblerAgent", "validator": "ValidatorAgent",
}


def _agent_graph_svg(statuses: dict = None, selected: str = None) -> str:
    """
    Renders the 6-agent pipeline as an SVG graph.

    statuses: dict  {agent_key: "idle"|"done"|"active"|"error"|"skipped"}
    selected: str   agent_key of the currently selected node (highlighted)
    """
    statuses = statuses or {}
    S = {
        "idle":    ("#111118", "#2a2a38", "#555566"),
        "done":    ("#0a1a0a", "#2a8a2a", "#88cc88"),
        "active":  ("#1a1408", "#cc8800", "#ccaa44"),
        "error":   ("#1a0505", "#cc3030", "#cc8080"),
        "skipped": ("#0d0d1a", "#303060", "#606080"),
    }
    W, H, NW, NH, CY = 920, 215, 110, 65, 104

    def node_svg(key, icon, name, model, cx):
        status = statuses.get(key, "idle")
        fill, stroke, tc = S.get(status, S["idle"])
        sw = "2.5" if selected == key else "1.5"
        if selected == key:
            stroke, fill = "#CC0000", ("#1a0505" if fill == "#111118" else fill)
        x, y = cx - NW // 2, CY - NH // 2
        dot = ""
        if status == "done":
            dot = f'<circle cx="{cx + NW//2 - 8}" cy="{y+8}" r="4" fill="#2a8a2a"/>'
        elif status == "active":
            dot = f'<circle cx="{cx + NW//2 - 8}" cy="{y+8}" r="4" fill="#cc8800"/>'
        elif status == "error":
            dot = f'<circle cx="{cx + NW//2 - 8}" cy="{y+8}" r="4" fill="#cc3030"/>'
        return (
            f'<rect x="{x+2}" y="{y+2}" width="{NW}" height="{NH}" rx="8" fill="rgba(0,0,0,0.45)"/>'
            f'<rect x="{x}" y="{y}" width="{NW}" height="{NH}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
            f'{dot}'
            f'<text x="{cx}" y="{y+19}" text-anchor="middle" font-size="15">{icon}</text>'
            f'<text x="{cx}" y="{y+33}" text-anchor="middle" font-size="10" fill="{tc}" font-weight="bold" font-family="sans-serif">{name}</text>'
            f'<text x="{cx}" y="{y+47}" text-anchor="middle" font-size="8.5" fill="#4a4a5a" font-family="monospace">{model}</text>'
        )

    arrows = [(130,165), (275,310), (420,455), (565,600), (710,745)]
    p = [
        f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;background:#0a0a12;border-radius:10px;display:block">',
        # Arrow markers
        '<defs>'
        '<marker id="ah"  markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#3a3a4a"/></marker>'
        '<marker id="ahl" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#5a5a2a"/></marker>'
        '<marker id="ahr" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#2a3a5a"/></marker>'
        '</defs>',
        # Main flow arrows
        *[f'<line x1="{x1}" y1="{CY}" x2="{x2}" y2="{CY}" stroke="#2e2e3e" stroke-width="1.5" marker-end="url(#ah)"/>'
          for x1, x2 in arrows],
        # intel→recon clarification (back arrow, above)
        f'<path d="M 220,{CY-NH//2} C 220,18 75,18 75,{CY-NH//2}" fill="none" stroke="#4a4a2a" stroke-width="1.3" stroke-dasharray="5,3" marker-end="url(#ahl)"/>',
        f'<text x="148" y="13" fill="#5a5a2a" font-size="8.5" font-family="monospace" text-anchor="middle">clarification?</text>',
        # validator→planner retry (back arrow, below)
        f'<path d="M 800,{CY+NH//2} C 800,190 365,190 365,{CY+NH//2}" fill="none" stroke="#2a3a5a" stroke-width="1.3" stroke-dasharray="5,3" marker-end="url(#ahr)"/>',
        f'<text x="585" y="205" fill="#2a3a5a" font-size="8.5" font-family="monospace" text-anchor="middle">retry on validation issues</text>',
        # intel→END (not demonstrable)
        f'<line x1="220" y1="{CY+NH//2}" x2="220" y2="167" stroke="#2e2e3e" stroke-width="1.2" stroke-dasharray="4,3" marker-end="url(#ah)"/>',
        f'<text x="220" y="178" fill="#3a3a4a" font-size="8" font-family="monospace" text-anchor="middle">not demo</text>',
        # validator→END
        f'<line x1="856" y1="{CY}" x2="882" y2="{CY}" stroke="#2e2e3e" stroke-width="1.2" marker-end="url(#ah)"/>',
        f'<text x="898" y="{CY+4}" fill="#3a3a4a" font-size="8" font-family="monospace">END</text>',
        # Nodes
        *[node_svg(k, ic, nm, md, cx) for k, ic, nm, md, cx in _GRAPH_NODES],
        '</svg>',
    ]
    return '\n'.join(p)


def _agent_detail_panel(key: str, res: dict):
    """Renders the detail panel for a selected agent node."""
    agent_name = _KEY_TO_AGENT_NAME.get(key, key)
    icon  = next((ic for k, ic, *_ in _GRAPH_NODES if k == key), "🤖")
    model = next((md for k, _, __, md, *_ in _GRAPH_NODES if k == key), "")

    msgs = res.get("_agent_messages", [])
    agent_msg = next((m for m in reversed(msgs) if m["agent"] == agent_name), None)

    st.markdown(
        f'<div class="section-title" style="margin-top:0.8rem">'
        f'{icon} {agent_name}'
        f'<span style="color:#444;font-size:0.7rem;font-weight:400;margin-left:6px">({model})</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    col_msg, col_data = st.columns([1, 1])

    with col_msg:
        st.markdown('<div style="font-size:0.75rem;color:#666;margin-bottom:0.3rem">OUTPUT MESSAGE</div>', unsafe_allow_html=True)
        if agent_msg:
            st.markdown(f'<div class="agent-detail-box">{agent_msg["content"]}</div>', unsafe_allow_html=True)
        else:
            st.caption("No message recorded (agent may have been skipped)")

    with col_data:
        st.markdown('<div style="font-size:0.75rem;color:#666;margin-bottom:0.3rem">OUTPUTS</div>', unsafe_allow_html=True)
        if key == "recon":
            iocs = res.get("iocs", {})
            ttps = res.get("ttps", [])
            st.markdown(f"**IOCs:** {sum(len(v) for v in iocs.values())} total")
            for k, v in iocs.items():
                if v: st.markdown(f"&nbsp;&nbsp;`{k}`: {len(v)}", unsafe_allow_html=True)
            st.markdown(f"**TTPs:** {len(ttps)}")
            for t in ttps[:6]:
                st.markdown(f"&nbsp;&nbsp;`{t.get('id')}` {t.get('name','')[:35]}", unsafe_allow_html=True)
            if len(ttps) > 6: st.caption(f"  +{len(ttps)-6} more")

        elif key == "threat_intel":
            a = res.get("analysis", {})
            if a:
                for k, v in [("Actor", a.get("threat_actor","?")), ("Type", a.get("threat_actor_type","?")),
                              ("Campaign", a.get("campaign_name","?")), ("Demonstrable", "✅ Yes" if a.get("demonstrable") else "❌ No"),
                              ("Risk", a.get("demo_risk","?")), ("Confidence", a.get("confidence_level","?"))]:
                    st.markdown(f"**{k}:** {v}")

        elif key == "attack_planner":
            for s in res.get("attack_sequence", []):
                st.markdown(f"`{s.get('technique_id')}` {s.get('description','')[:55]}")

        elif key == "payload_crafter":
            snips = res.get("snippets", [])
            lib = sum(1 for s in snips if s.get("source") == "static_library")
            st.markdown(f"**{len(snips)} snippets** — 📚 {lib} library / 🧠 {len(snips)-lib} LLM")
            for s in snips:
                src_ico = "📚" if s.get("source") == "static_library" else "🧠"
                st.markdown(f"{src_ico} `{s.get('technique_id')}` {s.get('name','')[:40]}")

        elif key == "playbook_assembler":
            pb = res.get("playbook", {})
            if pb:
                evs = pb.get("events", [])
                attack_ev = [e for e in evs if "cleanup" not in e.get("event_id","")]
                st.markdown(f"**ID:** `{pb.get('playbook_id','N/A')}`")
                st.markdown(f"**Attack events:** {len(attack_ev)}")
                st.markdown(f"**Cleanup events:** {len(evs)-len(attack_ev)}")
                for a in pb.get("mandatory_agents", []):
                    st.markdown(f"&nbsp;&nbsp;`{a['agent_id']}` ({a['agent_type']})", unsafe_allow_html=True)

        elif key == "validator":
            val = res.get("_validation", {})
            retries = res.get("_retry_count", 0)
            st.markdown(f"**Result:** {'✅ Valid' if val.get('valid') else '⚠️ Issues found'}")
            st.markdown(f"**Retries used:** {retries}")
            for issue in val.get("issues", []):
                st.markdown(f"&nbsp;&nbsp;✗ {issue}", unsafe_allow_html=True)
            if val.get("feedback"):
                st.caption(f"Feedback: {val['feedback'][:120]}")


def run_pipeline(pdf_bytes: bytes, model: str, platform: str, provider: str = "ollama") -> dict:
    """Runs the full analysis pipeline and returns all results."""
    from src.pdf_processor import PDFProcessor
    from src.ioc_extractor import IOCExtractor
    from src.ttp_mapper import TTPMapper
    from src.llm_analyzer import LLMAnalyzer
    from src.playbook_generator import PlaybookGenerator

    results = {}
    errors = {}

    # Write PDF to temp file
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    # ── Step 1: PDF ──────────────────────────────────────────────
    yield "step", 1, "Analyzing PDF structure..."
    try:
        processor = PDFProcessor()
        content = processor.extract_text(tmp_path)
        results["content"] = content
        yield "done", 1, f"PDF analyzed — {content['metadata']['page_count']} pages, {content['metadata']['word_count']:,} words"
    except Exception as e:
        errors["pdf"] = str(e)
        yield "error", 1, f"PDF error: {e}"
        return

    # ── Step 2: IOCs ─────────────────────────────────────────────
    yield "step", 2, "Extracting Indicators of Compromise..."
    try:
        extractor = IOCExtractor()
        iocs = extractor.extract_all(content["full_text"])
        results["iocs"] = iocs
        total = sum(len(v) for v in iocs.values())
        yield "done", 2, f"{total} IOCs extracted across {len(iocs)} types"
    except Exception as e:
        errors["iocs"] = str(e)
        results["iocs"] = {}
        yield "error", 2, f"IOC extraction error: {e}"

    # ── Step 3: TTPs ─────────────────────────────────────────────
    yield "step", 3, "Mapping MITRE ATT&CK techniques..."
    try:
        mapper = TTPMapper()
        ttps = mapper.extract_techniques(content["full_text"])
        results["ttps"] = ttps
        yield "done", 3, f"{len(ttps)} techniques identified"
    except Exception as e:
        errors["ttps"] = str(e)
        results["ttps"] = []
        yield "error", 3, f"TTP mapping error: {e}"

    # ── Step 4: LLM Analysis ─────────────────────────────────────
    yield "step", 4, "Running deep LLM analysis (this may take 1-2 min)..."
    try:
        llm = LLMAnalyzer(model_name=model, provider=provider)
        analysis = llm.analyze_report(content, results["iocs"], results["ttps"])
        results["analysis"] = analysis

        if not analysis.get("demonstrable", False):
            yield "warn", 4, f"Report assessed as NOT demonstrable — {analysis.get('reasoning', '')[:80]}"
            results["attack_sequence"] = []
            results["snippets"] = []
            results["playbook"] = {}
            results["summary"] = analysis.get("reasoning", "")
            results["demo_brief_md"] = ""
            yield "final", results
            return

        yield "done", 4, f"Analysis complete — Actor: {analysis.get('threat_actor', 'Unknown')}"

        # ── Step 4b: Attack Sequence ─────────────────────────────
        yield "step", 4, "Generating attack sequence..."
        attack_sequence = llm.generate_attack_sequence(analysis, results["ttps"])
        results["attack_sequence"] = attack_sequence
        yield "done", 4, f"{len(attack_sequence)} attack stages generated"

    except Exception as e:
        errors["llm"] = str(e)
        results["analysis"] = {"threat_actor": "Unknown", "demonstrable": False,
                               "reasoning": f"LLM unavailable: {e}"}
        results["attack_sequence"] = []
        results["snippets"] = []
        results["playbook"] = {}
        results["summary"] = f"LLM error: {e}"
        results["demo_brief_md"] = ""
        yield "error", 4, f"LLM error (is Ollama running?): {e}"
        yield "final", results
        return

    # ── Step 5: Emulation Snippets ───────────────────────────────
    yield "step", 5, "Generating emulation code snippets..."
    try:
        snippets = llm.suggest_emulation_snippets(
            results["ttps"], results["iocs"], attack_sequence, platform=platform
        )
        results["snippets"] = snippets
        yield "done", 5, f"{len(snippets)} emulation snippets ready"
    except Exception as e:
        errors["snippets"] = str(e)
        results["snippets"] = []
        yield "error", 5, f"Snippet generation error: {e}"

    # ── Step 6: Playbook ─────────────────────────────────────────
    yield "step", 6, "Generating playbook JSON and demo brief..."
    try:
        gen = PlaybookGenerator()
        # Clean JSON — only what Shadow-Replay needs to execute
        playbook = gen.generate(
            results["analysis"], attack_sequence, results["iocs"], results["ttps"]
        )
        # Narrative summary (used in the .md brief only)
        summary = llm.generate_playbook_summary(playbook, results["analysis"])
        # Full demo brief as Markdown (separate output)
        demo_brief_md = gen.generate_demo_brief(
            playbook, results["analysis"], results["ttps"], results["snippets"], summary
        )
        results["playbook"] = playbook
        results["summary"] = summary
        results["demo_brief_md"] = demo_brief_md
        yield "done", 6, f"Playbook ready — {len(playbook.get('events', []))} events"
    except Exception as e:
        errors["playbook"] = str(e)
        results["playbook"] = {}
        results["summary"] = ""
        results["demo_brief_md"] = ""
        yield "error", 6, f"Playbook generation error: {e}"

    results["errors"] = errors
    yield "final", results


def run_graph_pipeline(pdf_bytes: bytes, platform: str, config_path: str = "config.yaml",
                       agent_models: dict = None):
    """
    Multi-agent LangGraph pipeline.
    Yields the same (kind, step, msg) event format as run_pipeline() for
    UI compatibility, then ("final", results_dict) at the end.

    agent_models: dict  {"recon": {"provider": "anthropic", "model": "claude-..."}, ...}
                        Overrides from the sidebar per-agent config.
    """
    from src.graph import build_graph
    from src.agents.state import initial_state as graph_initial_state

    _AGENT_INFO = {
        "recon":              (1, "🔍 Recon Agent",          "Extracting IOCs, TTPs, writing briefing"),
        "threat_intel":       (2, "🧠 Threat Intel Agent",   "Deep analysis — Claude Opus"),
        "attack_planner":     (3, "⚔️ Attack Planner",       "Designing attack sequence — Claude Opus"),
        "payload_crafter":    (4, "💻 Payload Crafter",      "Generating emulation snippets — Claude Sonnet"),
        "playbook_assembler": (5, "📋 Playbook Assembler",   "Assembling Shadow-Replay JSON"),
        "validator":          (6, "✅ Validator",             "Validating playbook"),
    }

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    try:
        graph = build_graph(config_path, agent_overrides=agent_models or {})
        state = graph_initial_state(pdf_path=tmp_path, platform=platform)
    except Exception as e:
        yield "error", 0, f"Failed to build multi-agent graph: {e}"
        yield "final", {}
        return

    yield "step", 1, "Launching multi-agent pipeline (6 specialized agents)..."

    accumulated = dict(state)
    last_step = 0

    try:
        for chunk in graph.stream(dict(state), stream_mode="updates"):
            for node_name, partial_update in chunk.items():
                if node_name == "__end__":
                    continue
                # Merge partial update into accumulated state
                for k, v in partial_update.items():
                    accumulated[k] = v

                step, label, desc = _AGENT_INFO.get(node_name, (last_step, f"🤖 {node_name}", "processing"))
                last_step = step
                yield "done", step, f"{label}: {desc} — complete"
    except Exception as e:
        yield "error", last_step, f"Multi-agent pipeline error: {e}"

    # ── Normalize to the same results dict shape as run_pipeline() ──
    final_results = {
        "content":         accumulated.get("content", {}),
        "iocs":            accumulated.get("iocs", {}),
        "ttps":            accumulated.get("ttps", []),
        "analysis":        accumulated.get("analysis", {}),
        "attack_sequence": accumulated.get("attack_sequence", []),
        "snippets":        accumulated.get("snippets", []),
        "playbook":        accumulated.get("playbook", {}),
        "summary":         accumulated.get("narrative_summary", ""),
        "demo_brief_md":   "",
        "errors":          {},
        # Multi-agent extras (used in Agent Log tab)
        "_agent_messages": accumulated.get("messages", []),
        "_validation":     accumulated.get("validation", {}),
        "_retry_count":    max(0, accumulated.get("retry_count", 1) - 1),
        "_pipeline":       "multi_agent",
    }
    yield "final", final_results


# ─────────────────────────────────────────────────────────────────
#  Sidebar
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0 1.5rem">
        <div style="font-size:2.5rem">🎯</div>
        <div style="font-size:1.1rem;font-weight:700;color:#CC0000;">ThreatHunt AI</div>
        <div style="font-size:0.75rem;color:#666;">Intelligence → Playbook</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**Upload Threat Report**")
    uploaded_file = st.file_uploader(
        label="PDF threat intelligence report",
        type=["pdf"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("**Configuration**")

    # Provider selector
    _PROVIDER_MODELS = {
        "ollama":    ["llama3", "llama3.1:70b", "llama3.2", "llama3.3:70b", "mixtral:8x7b", "mistral"],
        "anthropic": ["claude-sonnet-4-6", "claude-opus-4-6", "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"],
        "openai":    ["gpt-4o", "gpt-4-turbo", "gpt-4"],
    }
    _PROVIDER_LABELS = {
        "ollama":    "🖥️ Ollama (local)",
        "anthropic": "🤖 Claude (Anthropic API)",
        "openai":    "🟢 OpenAI API",
    }

    llm_provider = st.selectbox(
        "LLM Provider",
        options=list(_PROVIDER_MODELS.keys()),
        format_func=lambda p: _PROVIDER_LABELS[p],
        index=0,
    )

    # Pipeline mode
    pipeline_mode = st.selectbox(
        "Pipeline Mode",
        ["classic", "multi_agent"],
        format_func=lambda m: "⚙️  Classic (single model)" if m == "classic" else "🤖  Multi-Agent (specialized)",
        index=0,
        help="Classic: single LLM, 6 steps.  Multi-Agent: 6 specialized agents with per-task models (requires Anthropic API).",
    )

    col1, col2 = st.columns(2)
    with col1:
        llm_model = st.selectbox(
            "Model",
            _PROVIDER_MODELS[llm_provider],
            index=0,
            disabled=pipeline_mode == "multi_agent",
            help="Ignored in Multi-Agent mode — each agent uses its own model from config.yaml",
        )
    with col2:
        platform = st.selectbox(
            "Platform",
            ["windows", "linux"],
            index=0,
        )

    # ── Per-agent model configuration (multi-agent mode only) ────────
    _ALL_CLAUDE = ["claude-sonnet-4-6", "claude-opus-4-6", "claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"]
    _ALL_GPT    = ["gpt-4o", "gpt-4-turbo", "gpt-4"]
    _ALL_OLLAMA = ["llama3", "llama3.1:70b", "llama3.2", "mixtral:8x7b", "mistral", "codellama"]
    _AGENT_MODEL_OPTIONS = {
        "anthropic": _ALL_CLAUDE,
        "openai":    _ALL_GPT,
        "ollama":    _ALL_OLLAMA,
    }
    _PROVIDER_ICONS = {"anthropic": "🤖", "openai": "🟢", "ollama": "🖥️"}
    # (key, label, default_model, default_provider)
    _AGENT_SIDEBAR_DEFS = [
        ("recon",              "🔍 Recon",       "claude-haiku-4-5-20251001",   "anthropic"),
        ("threat_intel",       "🧠 Threat Intel", "claude-opus-4-6",             "anthropic"),
        ("attack_planner",     "⚔️  Planner",     "claude-opus-4-6",             "anthropic"),
        ("payload_crafter",    "💻 Crafter",      "claude-sonnet-4-6",           "anthropic"),
        ("playbook_assembler", "📋 Assembler",    "claude-sonnet-4-6",           "anthropic"),
        ("validator",          "✅ Validator",    "claude-sonnet-4-6",           "anthropic"),
    ]
    agent_models = {}
    if pipeline_mode == "multi_agent":
        with st.expander("🔧 Agent Models", expanded=False):
            st.markdown(
                '<div style="font-size:0.7rem;color:#555;margin-bottom:0.6rem">'
                'Provider → Model per agent. Ollama runs locally (no API key).</div>',
                unsafe_allow_html=True,
            )
            for akey, alabel, adefault_model, adefault_prov in _AGENT_SIDEBAR_DEFS:
                st.markdown(f"**{alabel}**")
                c_prov, c_model = st.columns([1, 2])
                with c_prov:
                    prov_opts = list(_AGENT_MODEL_OPTIONS.keys())
                    sel_prov  = st.selectbox(
                        "Provider",
                        prov_opts,
                        index=prov_opts.index(adefault_prov),
                        format_func=lambda p: _PROVIDER_ICONS[p],
                        key=f"ap_{akey}",
                        label_visibility="collapsed",
                    )
                with c_model:
                    model_opts = _AGENT_MODEL_OPTIONS[sel_prov]
                    # If default model is from a different provider, pick first
                    def_idx = model_opts.index(adefault_model) if (
                        sel_prov == adefault_prov and adefault_model in model_opts
                    ) else 0
                    sel_model = st.selectbox(
                        "Model",
                        model_opts,
                        index=def_idx,
                        key=f"am_{akey}",
                        label_visibility="collapsed",
                    )
                agent_models[akey] = {"provider": sel_prov, "model": sel_model}

    # ── API Keys ────────────────────────────────────────────────────────────
    # Collect which providers are in use
    _providers_in_use = set()
    if pipeline_mode == "multi_agent":
        _providers_in_use = {v["provider"] for v in agent_models.values()}
    else:
        _providers_in_use = {llm_provider}

    def _save_key_to_env(env_var: str, value: str):
        """Persist a key to .env and set it in os.environ for the current session."""
        os.environ[env_var] = value
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        try:
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    lines = f.readlines()
                new_lines, found = [], False
                for line in lines:
                    if line.startswith(f"{env_var}="):
                        new_lines.append(f"{env_var}={value}\n")
                        found = True
                    else:
                        new_lines.append(line)
                if not found:
                    new_lines.append(f"{env_var}={value}\n")
                with open(env_path, "w") as f:
                    f.writelines(new_lines)
            else:
                with open(env_path, "w") as f:
                    f.write(f"{env_var}={value}\n")
        except OSError:
            pass  # read-only filesystem — key is still set for this session

    with st.expander("🔑 API Keys", expanded=not bool(os.environ.get("ANTHROPIC_API_KEY"))):
        if "anthropic" in _providers_in_use or True:  # always show Anthropic field
            _ant_current = os.environ.get("ANTHROPIC_API_KEY", "")
            _ant_placeholder = "sk-ant-…  (already set)" if _ant_current else "Paste your Anthropic key"
            _ant_input = st.text_input(
                "Anthropic API Key",
                value="",
                type="password",
                placeholder=_ant_placeholder,
                help="Your key is used only in this session and saved to .env",
                key="sidebar_anthropic_key",
            )
            if _ant_input and _ant_input != _ant_current:
                _save_key_to_env("ANTHROPIC_API_KEY", _ant_input.strip())
                st.success("✓ Anthropic key saved", icon=None)
            elif _ant_current:
                st.success("✅ Anthropic key active", icon=None)
            else:
                st.caption("Required when using Claude models.")

        if "openai" in _providers_in_use:
            _oai_current = os.environ.get("OPENAI_API_KEY", "")
            _oai_placeholder = "sk-…  (already set)" if _oai_current else "Paste your OpenAI key"
            _oai_input = st.text_input(
                "OpenAI API Key",
                value="",
                type="password",
                placeholder=_oai_placeholder,
                help="Required when using GPT models",
                key="sidebar_openai_key",
            )
            if _oai_input and _oai_input != _oai_current:
                _save_key_to_env("OPENAI_API_KEY", _oai_input.strip())
                st.success("✓ OpenAI key saved", icon=None)
            elif _oai_current:
                st.success("✅ OpenAI key active", icon=None)
            else:
                st.caption("Required when using GPT models.")

        if "ollama" in _providers_in_use:
            st.info("🖥️ Ollama: no key needed — run `ollama serve` locally", icon=None)

    st.markdown("---")
    analyze_btn = st.button("🚀 Analyze Report", disabled=uploaded_file is None)

    st.markdown("---")
    if pipeline_mode == "classic":
        st.markdown("""
        <div style="font-size:0.75rem;color:#555;line-height:1.6">
        <b style="color:#888">Classic pipeline:</b><br>
        1️⃣ PDF Structural Analysis<br>
        2️⃣ IOC Extraction<br>
        3️⃣ MITRE ATT&CK Mapping<br>
        4️⃣ LLM Deep Analysis<br>
        5️⃣ Emulation Code Generation<br>
        6️⃣ Playbook + Summary
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="font-size:0.75rem;color:#555;line-height:1.6">
        <b style="color:#888">Multi-Agent pipeline:</b><br>
        🔍 Recon Agent <span style="color:#444">(Haiku)</span><br>
        🧠 Threat Intel Agent <span style="color:#444">(Opus)</span><br>
        ⚔️ Attack Planner <span style="color:#444">(Opus)</span><br>
        💻 Payload Crafter <span style="color:#444">(Sonnet)</span><br>
        📋 Playbook Assembler <span style="color:#444">(Sonnet)</span><br>
        ✅ Validator + retry loop
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    _req_line = {
        "ollama": "Requires Ollama running locally",
        "anthropic": "Requires ANTHROPIC_API_KEY",
        "openai": "Requires OPENAI_API_KEY",
    }
    st.markdown(f"""
    <div style="font-size:0.7rem;color:#444;text-align:center">
    {_req_line[llm_provider]}<br>
    All simulation code is safe
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
#  Main area — Header
# ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="cs-header">
    <h1>🎯 ThreatHunt AI Creator</h1>
    <p>Intelligence-to-Playbook Generator — Convert threat reports into safe attack simulations</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────
#  Welcome state (no file uploaded)
# ─────────────────────────────────────────────────────────────────

if not uploaded_file and "results" not in st.session_state:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="value">📄</div>
            <div class="label">Upload a PDF</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="value">🧠</div>
            <div class="label">AI Analyzes It</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="value">🎮</div>
            <div class="label">Get Playbook</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.info("👈 Upload a threat intelligence PDF report in the sidebar to get started.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        1. **Upload** a CrowdStrike or any threat intelligence PDF
        2. The tool **extracts** IOCs, maps MITRE ATT&CK techniques, and runs **deep LLM analysis**
        3. It generates **safe simulation code** for each technique found
        4. You get a complete **playbook** with narrative summary, ready to demo in a lab

        **Requirements:**
        - Ollama running locally with `llama3` model downloaded
        - Python dependencies installed (`pip install -r requirements.txt`)
        - Optional: MITRE ATT&CK data file (`enterprise-attack.json`)
        """)

# ─────────────────────────────────────────────────────────────────
#  Run analysis
# ─────────────────────────────────────────────────────────────────

if analyze_btn and uploaded_file:
    st.session_state.pop("results", None)
    pdf_bytes = uploaded_file.read()

    progress_placeholder = st.empty()
    log_placeholder = st.empty()

    _classic_labels = {
        1: "PDF Analysis", 2: "IOC Extraction", 3: "TTP Mapping",
        4: "LLM Analysis", 5: "Emulation Code", 6: "Playbook",
    }
    _agent_labels = {
        1: "Recon Agent", 2: "Threat Intel", 3: "Attack Planner",
        4: "Payload Crafter", 5: "Playbook Assembler", 6: "Validator",
    }
    step_labels = _agent_labels if pipeline_mode == "multi_agent" else _classic_labels
    total_steps = 6

    logs = []
    final_results = None

    with progress_placeholder.container():
        progress_bar = st.progress(0, text="Starting analysis...")

    pipeline_fn = (
        lambda: run_graph_pipeline(pdf_bytes, platform, agent_models=agent_models)
        if pipeline_mode == "multi_agent"
        else run_pipeline(pdf_bytes, llm_model, platform, provider=llm_provider)
    )

    for event in pipeline_fn():
        kind = event[0]

        if kind == "step":
            _, step_num, msg = event
            label = step_labels.get(step_num, f"Step {step_num}")
            pct = max(0, int(((step_num - 1) / total_steps) * 100))
            progress_bar.progress(pct, text=f"{label}: {msg}")
            logs.append(f"⏳ {msg}")

        elif kind in ("done", "agent_done"):
            _, step_num, msg = event
            pct = int((step_num / total_steps) * 100)
            progress_bar.progress(pct, text=f"✓ {msg}")
            logs.append(f"✅ {msg}")

        elif kind == "warn":
            _, step_num, msg = event
            logs.append(f"⚠️ {msg}")

        elif kind == "error":
            _, step_num, msg = event
            logs.append(f"❌ {msg}")

        elif kind == "final":
            _, final_results = event

        log_placeholder.markdown("\n".join(f"- {l}" for l in logs[-6:]))

    progress_placeholder.empty()
    log_placeholder.empty()

    if final_results:
        final_results["_pipeline"] = final_results.get("_pipeline", "classic")
        st.session_state["results"] = final_results
        st.session_state["filename"] = uploaded_file.name
        st.rerun()


# ─────────────────────────────────────────────────────────────────
#  Display results
# ─────────────────────────────────────────────────────────────────

if "results" in st.session_state:
    res = st.session_state["results"]
    content = res.get("content", {})
    iocs = res.get("iocs", {})
    ttps = res.get("ttps", [])
    analysis = res.get("analysis", {})
    attack_sequence = res.get("attack_sequence", [])
    snippets = res.get("snippets", [])
    playbook = res.get("playbook", {})
    summary = res.get("summary", "")
    demo_brief_md = res.get("demo_brief_md", "")
    filename = st.session_state.get("filename", "report.pdf")

    meta = content.get("metadata", {})
    kf = content.get("key_findings", {})
    total_iocs = sum(len(v) for v in iocs.values())

    # ── Overview metric cards ────────────────────────────────────
    st.markdown(f"**Report:** `{filename}` — analyzed {datetime.now().strftime('%H:%M:%S')}")
    st.markdown("<br>", unsafe_allow_html=True)

    cols = st.columns(6)
    metrics = [
        (meta.get("page_count", 0), "Pages"),
        (f"{meta.get('word_count', 0):,}", "Words"),
        (total_iocs, "IOCs"),
        (len(ttps), "Techniques"),
        (len(snippets), "Snippets"),
        (len(playbook.get("events", [])), "Events"),
    ]
    for col, (val, label) in zip(cols, metrics):
        with col:
            st.markdown(metric_card(val, label), unsafe_allow_html=True)

    # Demonstrability banner
    st.markdown("<br>", unsafe_allow_html=True)
    if analysis.get("demonstrable"):
        risk = analysis.get("demo_risk", "medium")
        icon = RISK_COLORS.get(risk, "🟡")
        st.success(f"✅ **Demonstrable** — Risk level: {icon} **{risk.upper()}** | "
                   f"Complexity: **{analysis.get('demo_complexity', 'N/A')}** | "
                   f"Setup time: **{analysis.get('setup_time', 'N/A')}**")
    else:
        st.error(f"❌ **Not demonstrable** — {analysis.get('reasoning', '')[:120]}")

    # ── Agent Graph (multi-agent mode only) ───────────────────────
    _is_multiagent = res.get("_pipeline") == "multi_agent"

    if _is_multiagent:
        agent_messages_graph = res.get("_agent_messages", [])

        # Compute which agents completed from the messages log
        _completed_names = {m["agent"] for m in agent_messages_graph}
        _name_to_key = {v: k for k, v in _KEY_TO_AGENT_NAME.items()}
        _statuses = {_name_to_key[n]: "done" for n in _completed_names if n in _name_to_key}

        # Selected agent (persisted in session_state)
        if "selected_agent_view" not in st.session_state:
            st.session_state["selected_agent_view"] = None

        st.markdown('<div class="graph-section">', unsafe_allow_html=True)
        st.markdown('<div class="graph-section-title">Pipeline — Agent Interaction Graph</div>', unsafe_allow_html=True)

        # SVG graph (visual only)
        svg_html = _agent_graph_svg(
            statuses=_statuses,
            selected=st.session_state["selected_agent_view"],
        )
        st.markdown(svg_html, unsafe_allow_html=True)

        # Clickable agent selector row (maps to node positions)
        st.markdown("<div style='margin-top:0.6rem'>", unsafe_allow_html=True)
        _btn_cols = st.columns(6)
        _btn_keys = [k for k, *_ in _GRAPH_NODES]
        _btn_icons = {k: ic for k, ic, *_ in _GRAPH_NODES}
        _btn_names = {k: nm for k, _, nm, *_ in _GRAPH_NODES}
        _btn_models = {k: md for k, _, __, md, *_ in _GRAPH_NODES}

        for col, key in zip(_btn_cols, _btn_keys):
            with col:
                is_done = _statuses.get(key) == "done"
                is_sel  = st.session_state["selected_agent_view"] == key
                status_dot = "🟢 " if is_done else ""
                lbl = f"{status_dot}{_btn_icons[key]} {_btn_names[key]}"
                btn_type = "primary" if is_sel else "secondary"
                if st.button(lbl, key=f"gnode_{key}", use_container_width=True, type=btn_type):
                    new_val = None if is_sel else key   # toggle off if already selected
                    st.session_state["selected_agent_view"] = new_val
                    st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

        # Agent detail panel (appears when a node is clicked)
        _sel = st.session_state.get("selected_agent_view")
        if _sel:
            st.markdown("<hr>", unsafe_allow_html=True)
            _agent_detail_panel(_sel, res)

        st.markdown('</div>', unsafe_allow_html=True)  # end .graph-section

    # ── Tabs ─────────────────────────────────────────────────────
    _tab_names = [
        "📄 PDF Analysis",
        "🔍 IOCs",
        "🗺️ TTPs",
        "🧠 Threat Analysis",
        "💻 Emulation Code",
        "📋 Playbook",
    ]
    if _is_multiagent:
        _tab_names.append("🤖 Agent Log")
    tabs = st.tabs(_tab_names)

    # ════════════════════════════════════════════════════════════
    # TAB 1 — PDF Analysis
    # ════════════════════════════════════════════════════════════
    with tabs[0]:
        col_l, col_r = st.columns([1, 1])

        with col_l:
            st.markdown('<div class="section-title">Document Metadata</div>', unsafe_allow_html=True)
            meta_items = {
                "Title": meta.get("title") or "—",
                "Author": meta.get("author") or "—",
                "Pages": meta.get("page_count"),
                "Word count": f"{meta.get('word_count', 0):,}",
                "Characters": f"{meta.get('char_count', 0):,}",
                "Headings found": meta.get("heading_count", 0),
                "Sections found": meta.get("section_count", 0),
                "Contains tables": "✅ Yes" if meta.get("has_tables") else "❌ No",
            }
            df_meta = pd.DataFrame(list(meta_items.items()), columns=["Field", "Value"])
            st.dataframe(df_meta, hide_index=True, use_container_width=True)

            st.markdown('<div class="section-title" style="margin-top:1rem">Sections Detected</div>', unsafe_allow_html=True)
            sections_found = list(content.get("sections", {}).keys())
            if sections_found:
                for s in sections_found:
                    st.markdown(f"✓ {s.replace('_', ' ').title()}")
            else:
                st.caption("No named sections detected")

        with col_r:
            st.markdown('<div class="section-title">Key Entities Found</div>', unsafe_allow_html=True)
            entity_map = {
                "🌍 Countries": kf.get("mentioned_countries", []),
                "🏭 Sectors": kf.get("mentioned_sectors", []),
                "🛠️ Tools": kf.get("mentioned_tools", []),
                "🦠 Malware types": kf.get("mentioned_malware_types", []),
                "👤 Threat actors": kf.get("mentioned_threat_actors", []),
                "🔒 CVEs": kf.get("cves", []),
                "🎯 MITRE IDs": kf.get("mitre_ids_explicit", []),
            }
            for label, items in entity_map.items():
                if items:
                    st.markdown(f"**{label}**")
                    st.markdown(" ".join(f'<span class="ioc-badge">{i}</span>' for i in items), unsafe_allow_html=True)
                    st.markdown("")

        # Document headings
        headings = content.get("headings", [])
        if headings:
            st.markdown('<div class="section-title" style="margin-top:1rem">Document Structure (Headings)</div>', unsafe_allow_html=True)
            h_data = [
                {
                    "Page": h["page"],
                    "Heading": h["text"][:80],
                    "Font size": f"{h['font_size']:.1f}",
                    "Bold": "✅" if h.get("is_bold") else "",
                }
                for h in headings
            ]
            st.dataframe(pd.DataFrame(h_data), hide_index=True, use_container_width=True)

        # Section previews
        if content.get("sections"):
            st.markdown('<div class="section-title" style="margin-top:1rem">Section Previews</div>', unsafe_allow_html=True)
            for sec_name, sec_text in content["sections"].items():
                with st.expander(f"📑 {sec_name.replace('_', ' ').title()} ({len(sec_text):,} chars)"):
                    st.text(sec_text[:800] + ("..." if len(sec_text) > 800 else ""))

    # ════════════════════════════════════════════════════════════
    # TAB 2 — IOCs
    # ════════════════════════════════════════════════════════════
    with tabs[1]:
        if not iocs:
            st.info("No IOCs extracted from this report.")
        else:
            # Summary row
            ioc_type_labels = {
                "ipv4": "IPv4", "ipv6": "IPv6", "domains": "Domains",
                "urls": "URLs", "emails": "Emails", "md5": "MD5",
                "sha1": "SHA1", "sha256": "SHA256", "cves": "CVEs",
                "registry_keys": "Registry Keys", "file_paths": "File Paths",
                "named_pipes": "Named Pipes", "mutex_names": "Mutexes",
                "commands": "Commands", "service_names": "Services",
                "user_agents": "User Agents",
            }
            summary_cols = st.columns(4)
            priority_types = ["ipv4", "domains", "sha256", "cves"]
            for col, ioc_key in zip(summary_cols, priority_types):
                with col:
                    count = len(iocs.get(ioc_key, []))
                    st.markdown(metric_card(count, ioc_type_labels.get(ioc_key, ioc_key)), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Full IOC tables per type
            for ioc_key, label in ioc_type_labels.items():
                values = iocs.get(ioc_key, [])
                if not values:
                    continue
                with st.expander(f"**{label}** — {len(values)} found", expanded=ioc_key in ("ipv4", "domains", "sha256", "cves")):
                    # Show as table or badges depending on type
                    if ioc_key in ("commands",):
                        for cmd in values:
                            st.code(cmd, language="powershell")
                    elif ioc_key in ("sha256", "sha1", "md5"):
                        df = pd.DataFrame(values, columns=["Hash"])
                        st.dataframe(df, hide_index=True, use_container_width=True)
                    else:
                        df = pd.DataFrame(values, columns=[label])
                        st.dataframe(df, hide_index=True, use_container_width=True)

    # ════════════════════════════════════════════════════════════
    # TAB 3 — TTPs
    # ════════════════════════════════════════════════════════════
    with tabs[2]:
        if not ttps:
            st.info("No MITRE ATT&CK techniques identified.")
        else:
            # Group by tactic
            by_tactic: dict = {}
            for t in ttps:
                for tactic in (t.get("tactics") or ["Unknown"]):
                    by_tactic.setdefault(tactic, []).append(t)

            tactic_order = [
                "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access",
                "Discovery", "Lateral Movement", "Collection",
                "Command And Control", "Exfiltration", "Impact", "Unknown",
            ]

            # Coverage pills
            st.markdown(f"**{len(ttps)} techniques identified across {len(by_tactic)} tactics**")
            pill_html = " ".join(
                tactic_pill(t) + f" <span style='color:#666;font-size:0.75rem'>×{len(by_tactic[t])}</span>"
                for t in tactic_order if t in by_tactic
            )
            st.markdown(pill_html, unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)

            # Full table
            all_rows = []
            for tactic in tactic_order:
                for t in by_tactic.get(tactic, []):
                    all_rows.append({
                        "ID": t["id"],
                        "Name": t["name"],
                        "Tactic": tactic,
                        "Sub-technique": "✅" if t.get("is_subtechnique") else "",
                        "Triggered by tool": t.get("triggered_by_tool", ""),
                        "Platforms": ", ".join(t.get("platforms", [])),
                    })

            df_ttps = pd.DataFrame(all_rows)
            st.dataframe(df_ttps, hide_index=True, use_container_width=True,
                         column_config={
                             "ID": st.column_config.TextColumn("ID", width=90),
                             "Sub-technique": st.column_config.TextColumn("Sub-tech", width=70),
                         })

            # Per-tactic expanders
            for tactic in tactic_order:
                techs = by_tactic.get(tactic, [])
                if not techs:
                    continue
                color = TACTIC_COLORS.get(tactic, "#555")
                with st.expander(f"**{tactic}** — {len(techs)} technique(s)"):
                    for t in techs:
                        tool_badge = f" 🛠️ `{t['triggered_by_tool']}`" if t.get("triggered_by_tool") else ""
                        st.markdown(f"**`{t['id']}`** — {t['name']}{tool_badge}")
                        if t.get("description"):
                            st.caption(t["description"][:200])
                        st.markdown("")

    # ════════════════════════════════════════════════════════════
    # TAB 4 — Threat Analysis
    # ════════════════════════════════════════════════════════════
    with tabs[3]:
        if not analysis:
            st.info("LLM analysis not available.")
        else:
            col_l, col_r = st.columns([1, 1])

            with col_l:
                st.markdown('<div class="section-title">Threat Identification</div>', unsafe_allow_html=True)
                info_rows = {
                    "Threat Actor": analysis.get("threat_actor", "Unknown"),
                    "Actor Type": analysis.get("threat_actor_type", "Unknown"),
                    "Campaign Name": analysis.get("campaign_name", "Unknown"),
                    "Attack Vector": analysis.get("attack_vector", "Unknown"),
                    "Confidence": analysis.get("confidence_level", "N/A"),
                    "Attribution": analysis.get("attribution_confidence", "N/A"),
                }
                for k, v in info_rows.items():
                    st.markdown(f"**{k}:** {v}")

                st.markdown('<div class="section-title" style="margin-top:1.5rem">Targets</div>', unsafe_allow_html=True)
                if analysis.get("platforms"):
                    st.markdown("**Platforms:** " + " ".join(f"`{p}`" for p in analysis["platforms"]))
                if analysis.get("target_industries"):
                    st.markdown("**Industries:** " + ", ".join(analysis["target_industries"]))
                if analysis.get("target_geography"):
                    st.markdown("**Geography:** " + ", ".join(analysis["target_geography"]))
                if analysis.get("crowdstrike_products"):
                    st.markdown("**CrowdStrike Products:**")
                    for p in analysis["crowdstrike_products"]:
                        st.markdown(f"  - {p}")

            with col_r:
                st.markdown('<div class="section-title">Demonstrability Assessment</div>', unsafe_allow_html=True)
                demo = analysis.get("demonstrable", False)
                risk = analysis.get("demo_risk", "medium")

                demo_data = {
                    "Demonstrable": "✅ Yes" if demo else "❌ No",
                    "Risk Level": f"{RISK_COLORS.get(risk, '🟡')} {risk.upper()}",
                    "Complexity": analysis.get("demo_complexity", "N/A"),
                    "Setup Time": analysis.get("setup_time", "N/A"),
                    "Expertise Needed": analysis.get("required_expertise", "N/A"),
                }
                for k, v in demo_data.items():
                    st.markdown(f"**{k}:** {v}")

                if analysis.get("reasoning"):
                    st.markdown('<div class="section-title" style="margin-top:1.5rem">Assessment Reasoning</div>', unsafe_allow_html=True)
                    st.info(analysis["reasoning"])

                if analysis.get("demo_modifications"):
                    st.markdown('<div class="section-title">Suggested Modifications</div>', unsafe_allow_html=True)
                    st.warning(analysis["demo_modifications"])

            # Attack stages
            if analysis.get("attack_stages"):
                st.markdown('<div class="section-title" style="margin-top:1.5rem">Attack Stages (LLM Structured)</div>', unsafe_allow_html=True)
                for i, stage in enumerate(analysis["attack_stages"], 1):
                    tools = stage.get("key_tools", [])
                    tools_str = f" — Tools: `{'`, `'.join(tools)}`" if tools else ""
                    with st.expander(f"**{i}. {stage.get('stage_name', '?').replace('_', ' ').title()}** "
                                     f"({stage.get('tactic', '')}) — "
                                     f"{', '.join(stage.get('techniques', []))}"):
                        st.markdown(stage.get("description", ""))
                        if tools:
                            st.markdown(f"**Tools:** " + ", ".join(f"`{t}`" for t in tools))

            # Detection points
            if analysis.get("key_detection_points"):
                st.markdown('<div class="section-title" style="margin-top:1.5rem">CrowdStrike Detection Points</div>', unsafe_allow_html=True)
                for dp in analysis["key_detection_points"]:
                    st.markdown(f"◉ {dp}")

    # ════════════════════════════════════════════════════════════
    # TAB 5 — Emulation Code
    # ════════════════════════════════════════════════════════════
    with tabs[4]:
        if not snippets:
            st.info("No emulation snippets generated (LLM may be unavailable).")
        else:
            st.markdown(f"**{len(snippets)} safe simulation snippets** — "
                        "all code uses `[SIMULATION]` markers, no real malicious actions")
            st.markdown("")

            # Filter controls
            col_f1, col_f2 = st.columns([2, 2])
            with col_f1:
                tactic_filter = st.multiselect(
                    "Filter by tactic",
                    options=sorted(set(s.get("tactic", "Unknown") for s in snippets)),
                )
            with col_f2:
                source_filter = st.multiselect(
                    "Filter by source",
                    options=["static_library", "llm_generated"],
                    format_func=lambda x: "📚 Static Library" if x == "static_library" else "🧠 LLM Generated",
                )

            filtered = snippets
            if tactic_filter:
                filtered = [s for s in filtered if s.get("tactic") in tactic_filter]
            if source_filter:
                filtered = [s for s in filtered if s.get("source") in source_filter]

            st.markdown(f"Showing **{len(filtered)}** snippets")
            st.markdown("---")

            for snippet in filtered:
                src = snippet.get("source", "unknown")
                src_label = "📚 Static Library" if src == "static_library" else "🧠 LLM Generated"

                # Header
                col_h1, col_h2, col_h3 = st.columns([3, 2, 1])
                with col_h1:
                    st.markdown(f"**`{snippet['technique_id']}`** — {snippet['name']}")
                with col_h2:
                    st.markdown(f"{tactic_pill(snippet.get('tactic', 'Unknown'))}", unsafe_allow_html=True)
                with col_h3:
                    st.markdown(f"<small>{src_label}</small>", unsafe_allow_html=True)

                if snippet.get("stage_context"):
                    st.caption(f"Context: {snippet['stage_context'][:100]}")

                notes = snippet.get("detection_notes", "")
                if notes:
                    notes_str = notes if isinstance(notes, str) else " | ".join(str(n) for n in notes[:3])
                    st.caption(f"🔴 CrowdStrike detects: {notes_str[:150]}")

                # Code
                lang = "powershell" if snippet.get("platform") == "windows" else "python"
                st.code(snippet.get("code", ""), language=lang)
                st.markdown("---")

    # ════════════════════════════════════════════════════════════
    # TAB 6 — Playbook
    # ════════════════════════════════════════════════════════════
    with tabs[5]:
        col_l, col_r = st.columns([2, 1])

        with col_l:
            # Narrative summary
            if summary:
                st.markdown('<div class="section-title">Narrative Summary</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="summary-box">{summary}</div>', unsafe_allow_html=True)

        with col_r:
            if playbook:
                st.markdown('<div class="section-title">Playbook Info</div>', unsafe_allow_html=True)
                st.markdown(f"**ID:** `{playbook.get('playbook_id', 'N/A')}`")
                st.markdown(f"**Name:** {playbook.get('name', 'N/A')}")
                st.markdown(f"**Generated:** {playbook.get('generated_at', 'N/A')}")

                meta_pb = playbook.get("metadata", {})
                st.markdown(f"**Risk:** {RISK_COLORS.get(meta_pb.get('risk_level', ''), '🟡')} {meta_pb.get('risk_level', 'N/A').upper()}")
                st.markdown(f"**Platforms:** {', '.join(meta_pb.get('platforms', []))}")
                st.markdown(f"**TTPs:** {', '.join(meta_pb.get('ttps', []))}")

                # Download buttons — two separate outputs
                st.markdown("<br>", unsafe_allow_html=True)
                pid = playbook.get("playbook_id", "playbook")

                # Output 1: clean JSON (only what Shadow-Replay needs to run)
                playbook_json = json.dumps(playbook, indent=2, default=str)
                st.download_button(
                    label="⬇️ Playbook JSON (runner)",
                    data=playbook_json,
                    file_name=f"{pid}.json",
                    mime="application/json",
                    help="Clean JSON for Shadow-Replay — agents + events + payloads only",
                )

                # Output 2: demo brief markdown
                if demo_brief_md:
                    st.download_button(
                        label="⬇️ Demo Brief (.md)",
                        data=demo_brief_md,
                        file_name=f"{pid}_demo_brief.md",
                        mime="text/markdown",
                        help="Full demo guide — threat briefing, infra requirements, TTPs, snippets",
                    )

        # Agents
        if playbook.get("mandatory_agents"):
            st.markdown('<div class="section-title" style="margin-top:1.5rem">Required Agents</div>', unsafe_allow_html=True)
            cols = st.columns(len(playbook["mandatory_agents"]))
            for col, agent in zip(cols, playbook["mandatory_agents"]):
                with col:
                    icon = "🪟" if agent["agent_type"] == "windows" else ("🐧" if agent["agent_type"] == "linux" else "☁️")
                    st.markdown(metric_card(icon, agent["agent_type"].upper()), unsafe_allow_html=True)
                    st.caption(agent.get("description", "")[:60])

        # Events table
        if playbook.get("events"):
            st.markdown('<div class="section-title" style="margin-top:1.5rem">Playbook Events</div>', unsafe_allow_html=True)
            events_data = []
            for ev in playbook["events"]:
                is_cleanup = "cleanup" in ev.get("event_id", "")
                events_data.append({
                    "Event ID": ev.get("event_id", ""),
                    "Name": ev.get("name", "")[:50],
                    "Agent": ev.get("agent_id", ""),
                    "Type": ev.get("payload_type", ""),
                    "Technique": ev.get("mitre_technique", ""),
                    "Next": ev.get("success_trigger") or "END",
                    "Kind": "🧹 Cleanup" if is_cleanup else "⚔️ Attack",
                })
            st.dataframe(pd.DataFrame(events_data), hide_index=True, use_container_width=True)

            # Event detail expanders
            with st.expander("📋 View event payloads"):
                for ev in playbook["events"]:
                    if "cleanup" not in ev.get("event_id", ""):
                        st.markdown(f"**{ev.get('event_id')}** — {ev.get('name', '')} (`{ev.get('mitre_technique', '')}`)")
                        lang = "powershell" if ev.get("payload_type") == "powershell" else "python"
                        st.code(ev.get("payload", ""), language=lang)

        # Demo Brief preview
        if demo_brief_md:
            with st.expander("📄 Demo Brief preview (.md)"):
                st.markdown(demo_brief_md)

        # Raw JSON — clean runner payload
        if playbook:
            with st.expander("🔧 Raw Playbook JSON (runner)"):
                st.json(playbook)

    # ════════════════════════════════════════════════════════════
    # TAB 7 — Agent Log (multi-agent mode only)
    # ════════════════════════════════════════════════════════════
    if _is_multiagent:
        with tabs[6]:
            agent_messages = res.get("_agent_messages", [])
            validation     = res.get("_validation", {})
            retry_count    = res.get("_retry_count", 0)

            # ── Validation summary ────────────────────────────
            v_col1, v_col2, v_col3 = st.columns(3)
            with v_col1:
                v_valid = validation.get("valid", False)
                st.markdown(metric_card(
                    "✓ VALID" if v_valid else "⚠ ISSUES",
                    "Validation"
                ), unsafe_allow_html=True)
            with v_col2:
                st.markdown(metric_card(retry_count, "Retries"), unsafe_allow_html=True)
            with v_col3:
                st.markdown(metric_card(len(agent_messages), "Agent Messages"), unsafe_allow_html=True)

            if validation.get("issues"):
                st.markdown('<div class="section-title" style="margin-top:1rem">Validation Issues</div>', unsafe_allow_html=True)
                for issue in validation["issues"]:
                    st.markdown(f"  ✗ {issue}")
            elif v_valid:
                st.success("Playbook passed all validation checks (structural + semantic).")

            # ── Agent conversation log ────────────────────────
            st.markdown('<div class="section-title" style="margin-top:1.5rem">Agent Conversation Log</div>', unsafe_allow_html=True)

            _AGENT_ICONS = {
                "ReconAgent":              "🔍",
                "ThreatIntelAgent":        "🧠",
                "AttackPlannerAgent":      "⚔️",
                "PayloadCrafterAgent":     "💻",
                "PlaybookAssemblerAgent":  "📋",
                "ValidatorAgent":          "✅",
            }
            _AGENT_MODELS = {
                "ReconAgent":              "Haiku",
                "ThreatIntelAgent":        "Opus",
                "AttackPlannerAgent":      "Opus",
                "PayloadCrafterAgent":     "Sonnet",
                "PlaybookAssemblerAgent":  "Sonnet",
                "ValidatorAgent":          "Sonnet",
            }

            if not agent_messages:
                st.info("No agent messages recorded.")
            else:
                for i, msg in enumerate(agent_messages):
                    agent  = msg.get("agent", "Unknown")
                    ts     = msg.get("timestamp", "")[:19].replace("T", " ")
                    icon   = _AGENT_ICONS.get(agent, "🤖")
                    model  = _AGENT_MODELS.get(agent, "")
                    model_badge = f' <span style="color:#555;font-size:0.7rem">({model})</span>' if model else ""

                    with st.expander(
                        f"{icon} **{agent}**{model_badge}  —  {ts}",
                        expanded=(i == 0),
                    ):
                        st.markdown(
                            f'<div style="font-family:monospace;font-size:0.82rem;'
                            f'background:#0a0a12;border:1px solid #1a1a28;border-radius:8px;'
                            f'padding:1rem;white-space:pre-wrap;color:#c0c0d0;line-height:1.6">'
                            f'{msg["content"]}</div>',
                            unsafe_allow_html=True,
                        )
