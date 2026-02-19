"""
ThreatHunt AI Creator — Streamlit Web Interface
Run with: streamlit run app.py
"""

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
#  Custom CSS — dark theme with CrowdStrike red accents
# ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
html, body, [class*="css"] {
    font-family: 'Segoe UI', 'Inter', sans-serif;
}

/* ── Header ── */
.cs-header {
    background: linear-gradient(135deg, #1a1a1a 0%, #2d0000 100%);
    padding: 1.5rem 2rem;
    border-radius: 12px;
    margin-bottom: 1.5rem;
    border-left: 5px solid #CC0000;
}
.cs-header h1 {
    color: #ffffff;
    margin: 0;
    font-size: 1.8rem;
    font-weight: 700;
    letter-spacing: -0.5px;
}
.cs-header p {
    color: #aaaaaa;
    margin: 0.3rem 0 0 0;
    font-size: 0.9rem;
}

/* ── Metric cards ── */
.metric-card {
    background: #1e1e1e;
    border: 1px solid #333;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    text-align: center;
    border-top: 3px solid #CC0000;
}
.metric-card .value {
    font-size: 2rem;
    font-weight: 700;
    color: #CC0000;
    line-height: 1;
}
.metric-card .label {
    font-size: 0.75rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 0.3rem;
}

/* ── Section headings ── */
.section-title {
    font-size: 1rem;
    font-weight: 600;
    color: #CC0000;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid #333;
    padding-bottom: 0.4rem;
    margin-bottom: 0.8rem;
}

/* ── IOC badges ── */
.ioc-badge {
    display: inline-block;
    background: #2a1a1a;
    border: 1px solid #CC0000;
    color: #ff6666;
    font-family: monospace;
    font-size: 0.8rem;
    padding: 0.1rem 0.5rem;
    border-radius: 4px;
    margin: 2px;
}

/* ── TTP pill by tactic ── */
.tactic-pill {
    display: inline-block;
    padding: 0.25rem 0.6rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 2px;
}

/* ── Risk badge ── */
.risk-low    { background: #1a3a1a; color: #66ff66; border: 1px solid #66ff66; }
.risk-medium { background: #3a2a00; color: #ffaa00; border: 1px solid #ffaa00; }
.risk-high   { background: #3a0000; color: #ff4444; border: 1px solid #ff4444; }

/* ── Snippet card ── */
.snippet-header {
    background: #1e1e1e;
    border: 1px solid #444;
    border-left: 4px solid #CC0000;
    border-radius: 8px 8px 0 0;
    padding: 0.6rem 1rem;
    font-size: 0.85rem;
}
.snippet-meta {
    display: flex;
    gap: 1.5rem;
    font-size: 0.8rem;
    color: #888;
    margin-top: 0.3rem;
}

/* ── Sidebar ── */
.sidebar-section {
    background: #1e1e1e;
    border-radius: 8px;
    padding: 0.8rem;
    margin-bottom: 1rem;
    border: 1px solid #2d2d2d;
}

/* ── Status badges ── */
.badge-library { background: #1a2a3a; color: #66aaff; border: 1px solid #3366aa;
                 border-radius: 4px; padding: 0 6px; font-size: 0.7rem; }
.badge-llm     { background: #2a1a3a; color: #aa66ff; border: 1px solid #6633aa;
                 border-radius: 4px; padding: 0 6px; font-size: 0.7rem; }

/* ── Demonstrable indicator ── */
.demo-yes { color: #66ff66; font-weight: 700; font-size: 1.1rem; }
.demo-no  { color: #ff4444; font-weight: 700; font-size: 1.1rem; }

/* ── Summary box ── */
.summary-box {
    background: #141414;
    border: 1px solid #333;
    border-radius: 10px;
    padding: 1.5rem;
    line-height: 1.7;
    font-size: 0.9rem;
    color: #ccc;
    white-space: pre-wrap;
}

/* ── Streamlit overrides ── */
div[data-testid="stTab"] button { font-weight: 600; }
div[data-testid="stExpander"] { border: 1px solid #333 !important; border-radius: 8px; }
.stButton > button {
    background: #CC0000 !important;
    color: white !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    padding: 0.5rem 2rem !important;
    width: 100%;
}
.stButton > button:hover { background: #aa0000 !important; }
.stDownloadButton > button {
    background: #1e3a1e !important;
    color: #66ff66 !important;
    border: 1px solid #66ff66 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
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


def run_pipeline(pdf_bytes: bytes, model: str, platform: str) -> dict:
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
        llm = LLMAnalyzer(model_name=model)
        analysis = llm.analyze_report(content, results["iocs"], results["ttps"])
        results["analysis"] = analysis

        if not analysis.get("demonstrable", False):
            yield "warn", 4, f"Report assessed as NOT demonstrable — {analysis.get('reasoning', '')[:80]}"
            results["attack_sequence"] = []
            results["snippets"] = []
            results["playbook"] = {}
            results["summary"] = analysis.get("reasoning", "")
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
    yield "step", 6, "Generating playbook and narrative summary..."
    try:
        gen = PlaybookGenerator()
        playbook = gen.generate(
            results["analysis"], attack_sequence, results["iocs"], results["ttps"]
        )
        summary = llm.generate_playbook_summary(playbook, results["analysis"])
        playbook["emulation_snippets"] = results["snippets"]
        playbook["narrative_summary"] = summary
        results["playbook"] = playbook
        results["summary"] = summary
        yield "done", 6, f"Playbook ready — {len(playbook.get('events', []))} events"
    except Exception as e:
        errors["playbook"] = str(e)
        results["playbook"] = {}
        results["summary"] = ""
        yield "error", 6, f"Playbook generation error: {e}"

    results["errors"] = errors
    yield "final", results


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

    col1, col2 = st.columns(2)
    with col1:
        llm_model = st.selectbox(
            "LLM Model",
            ["llama3", "llama3.1", "llama3.2", "llama2", "mistral", "mixtral"],
            index=0,
        )
    with col2:
        platform = st.selectbox(
            "Platform",
            ["windows", "linux"],
            index=0,
        )

    st.markdown("---")
    analyze_btn = st.button("🚀 Analyze Report", disabled=uploaded_file is None)

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.75rem;color:#555;line-height:1.6">
    <b style="color:#888">Pipeline steps:</b><br>
    1️⃣ PDF Structural Analysis<br>
    2️⃣ IOC Extraction<br>
    3️⃣ MITRE ATT&CK Mapping<br>
    4️⃣ LLM Deep Analysis<br>
    5️⃣ Emulation Code Generation<br>
    6️⃣ Playbook + Summary
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.7rem;color:#444;text-align:center">
    Requires Ollama + llama3<br>
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

    step_labels = {
        1: "PDF Analysis",
        2: "IOC Extraction",
        3: "TTP Mapping",
        4: "LLM Analysis",
        5: "Emulation Code",
        6: "Playbook",
    }

    logs = []
    final_results = None

    with progress_placeholder.container():
        progress_bar = st.progress(0, text="Starting analysis...")
        status_container = st.empty()

    for event in run_pipeline(pdf_bytes, llm_model, platform):
        kind = event[0]

        if kind == "step":
            _, step_num, msg = event
            pct = int(((step_num - 1) / 6) * 100)
            progress_bar.progress(pct, text=f"Step {step_num}/6 — {step_labels[step_num]}: {msg}")
            logs.append(f"⏳ {msg}")

        elif kind == "done":
            _, step_num, msg = event
            pct = int((step_num / 6) * 100)
            progress_bar.progress(pct, text=f"Step {step_num}/6 — ✓ {msg}")
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

    # ── Tabs ─────────────────────────────────────────────────────
    tabs = st.tabs([
        "📄 PDF Analysis",
        "🔍 IOCs",
        "🗺️ TTPs",
        "🧠 Threat Analysis",
        "💻 Emulation Code",
        "📋 Playbook",
    ])

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

                # Download buttons
                st.markdown("<br>", unsafe_allow_html=True)
                playbook_json = json.dumps(playbook, indent=2, default=str)
                st.download_button(
                    label="⬇️ Download Playbook JSON",
                    data=playbook_json,
                    file_name=f"{playbook.get('playbook_id', 'playbook')}.json",
                    mime="application/json",
                )

                if snippets:
                    snippets_json = json.dumps(snippets, indent=2, default=str)
                    st.download_button(
                        label="⬇️ Download Emulation Snippets",
                        data=snippets_json,
                        file_name=f"{playbook.get('playbook_id', 'playbook')}_snippets.json",
                        mime="application/json",
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

        # Raw JSON
        if playbook:
            with st.expander("🔧 Raw Playbook JSON"):
                st.json(playbook)
