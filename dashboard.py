"""
SentinelAI - Streamlit Security Dashboard
Run with: streamlit run dashboard.py
"""
import streamlit as st
import json
import subprocess
import os
import sys
import time
from pathlib import Path
from collections import defaultdict

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Inter:wght@300;400;500&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #080c12;
    color: #c9d4e0;
}

.stApp {
    background: #080c12;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1e2d40;
}

section[data-testid="stSidebar"] * {
    color: #8ba5c0 !important;
}

/* Hide default streamlit header */
header[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer { visibility: hidden; }

/* Title */
.sentinel-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 2.8rem;
    font-weight: 700;
    letter-spacing: 4px;
    color: #00d4ff;
    text-transform: uppercase;
    text-shadow: 0 0 30px rgba(0,212,255,0.4);
    margin: 0;
}

.sentinel-sub {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #3d6b8a;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 2px;
}

/* Risk score card */
.risk-card {
    background: linear-gradient(135deg, #0d1825 0%, #0a1520 100%);
    border: 1px solid #1e3a52;
    border-radius: 12px;
    padding: 28px;
    text-align: center;
    position: relative;
    overflow: hidden;
}

.risk-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00d4ff, transparent);
}

.risk-score-num {
    font-family: 'Rajdhani', sans-serif;
    font-size: 5rem;
    font-weight: 700;
    line-height: 1;
}

.risk-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #3d6b8a;
    margin-top: 8px;
}

.risk-level-text {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.1rem;
    font-weight: 600;
    margin-top: 12px;
    letter-spacing: 1px;
}

/* Stat cards */
.stat-card {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}

.stat-num {
    font-family: 'Rajdhani', sans-serif;
    font-size: 2.6rem;
    font-weight: 700;
    line-height: 1;
}

.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #3d6b8a;
    margin-top: 6px;
}

/* Finding cards */
.finding-card {
    background: #0d1117;
    border-left: 3px solid;
    border-radius: 0 8px 8px 0;
    padding: 16px 20px;
    margin-bottom: 10px;
    transition: all 0.2s;
}

.finding-card:hover {
    background: #111820;
    transform: translateX(2px);
}

.finding-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.05rem;
    font-weight: 600;
    color: #e2eaf2;
    margin-bottom: 4px;
}

.finding-meta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.68rem;
    color: #3d6b8a;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.finding-desc {
    font-size: 0.82rem;
    color: #7a9ab5;
    line-height: 1.5;
    margin-bottom: 10px;
}

.finding-rec {
    font-size: 0.78rem;
    color: #5a8a6a;
    line-height: 1.4;
    padding: 8px 12px;
    background: rgba(0,180,100,0.05);
    border-left: 2px solid #2a6a3a;
    border-radius: 0 4px 4px 0;
}

.code-block {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    background: #050810;
    border: 1px solid #1a2535;
    border-radius: 6px;
    padding: 10px 14px;
    color: #e07a5f;
    margin: 8px 0;
    overflow-x: auto;
    white-space: pre;
}

/* Severity badges */
.badge {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 2px;
    padding: 3px 10px;
    border-radius: 3px;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-CRITICAL { background: rgba(255,50,50,0.15); color: #ff4444; border: 1px solid rgba(255,50,50,0.3); }
.badge-HIGH     { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
.badge-MEDIUM   { background: rgba(255,210,0,0.12); color: #ffd200; border: 1px solid rgba(255,210,0,0.3); }
.badge-LOW      { background: rgba(0,200,120,0.12); color: #00c878; border: 1px solid rgba(0,200,120,0.3); }

/* CWE tag */
.cwe-tag {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    background: rgba(0,150,255,0.08);
    color: #3a8abf;
    border: 1px solid rgba(0,150,255,0.15);
    border-radius: 3px;
    margin-left: 8px;
}

/* Section headers */
.section-header {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.3rem;
    font-weight: 700;
    color: #8ab4cc;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 1px solid #1e2d40;
    padding-bottom: 10px;
    margin: 28px 0 18px 0;
}

/* Agent pill */
.agent-pill {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    padding: 2px 8px;
    background: rgba(100,180,255,0.07);
    color: #4a7a9a;
    border: 1px solid rgba(100,180,255,0.12);
    border-radius: 3px;
    margin-left: 6px;
}

/* Progress bars */
.sev-bar-wrap {
    margin-bottom: 14px;
}
.sev-bar-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 4px;
    display: flex;
    justify-content: space-between;
}
.sev-bar {
    height: 6px;
    border-radius: 3px;
    background: #1a2535;
    overflow: hidden;
}
.sev-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.8s ease;
}

/* Scan form */
.scan-box {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
}

/* Terminal output */
.terminal {
    background: #050810;
    border: 1px solid #1a2535;
    border-radius: 8px;
    padding: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #3aff8a;
    line-height: 1.6;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
}

/* Divider */
.divider {
    border: none;
    border-top: 1px solid #1e2d40;
    margin: 24px 0;
}

/* File path */
.filepath {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    color: #3d6b8a;
}

/* Streamlit overrides */
.stSelectbox label, .stTextInput label, .stCheckbox label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: #3d6b8a !important;
}

div[data-baseweb="select"] {
    background: #0d1117 !important;
    border-color: #1e2d40 !important;
}

.stButton button {
    background: linear-gradient(135deg, #003d5c, #005a80) !important;
    color: #00d4ff !important;
    border: 1px solid #007aaa !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 1rem !important;
    font-weight: 600 !important;
    letter-spacing: 3px !important;
    text-transform: uppercase !important;
    padding: 10px 28px !important;
    border-radius: 6px !important;
    transition: all 0.2s !important;
}

.stButton button:hover {
    background: linear-gradient(135deg, #004d70, #006a94) !important;
    box-shadow: 0 0 20px rgba(0,180,255,0.2) !important;
}

.stTextInput input {
    background: #050810 !important;
    border-color: #1e2d40 !important;
    color: #c9d4e0 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd200",
    "LOW":      "#00c878",
}

RISK_COLORS = {
    "SAFE":     "#00c878",
    "LOW":      "#00c878",
    "MEDIUM":   "#ffd200",
    "HIGH":     "#ff8c00",
    "CRITICAL": "#ff4444",
}

def get_risk_color(risk_level: str) -> str:
    for key, color in RISK_COLORS.items():
        if key in risk_level.upper():
            return color
    return "#888"

def load_report(path: str) -> dict:
    with open(path) as f:
        return json.load(f)

def render_finding_card(f: dict):
    sev = f.get("severity", "LOW")
    color = SEVERITY_COLORS.get(sev, "#888")
    cwe = f.get("cwe_id", "")
    agent = f.get("agent", "")
    lineno = f.get("lineno", "?")
    filepath = f.get("filepath", "")

    cwe_html = f'<span class="cwe-tag">{cwe}</span>' if cwe else ""
    agent_html = f'<span class="agent-pill">{agent}</span>'

    snippet = f.get("code_snippet", "")
    snippet_html = ""
    if snippet:
        import html
        snippet_html = f'<div class="code-block">{html.escape(snippet[:200])}</div>'

    rec = f.get("recommendation", "")
    rec_html = f'<div class="finding-rec">💡 {rec}</div>' if rec else ""

    st.markdown(f"""
    <div class="finding-card" style="border-left-color: {color};">
        <div class="finding-title">
            <span class="badge badge-{sev}">{sev}</span>
            {cwe_html}
            &nbsp;&nbsp;{f.get('title', '')}
        </div>
        <div class="finding-meta">
            {agent_html}
            &nbsp;·&nbsp;
            <span class="filepath">{filepath}</span>
            &nbsp;·&nbsp; Line {lineno}
        </div>
        <div class="finding-desc">{f.get('description', '')}</div>
        {snippet_html}
        {rec_html}
    </div>
    """, unsafe_allow_html=True)


def render_sev_bar(label, count, total, color):
    pct = int((count / max(total, 1)) * 100)
    st.markdown(f"""
    <div class="sev-bar-wrap">
        <div class="sev-bar-label">
            <span style="color:{color}">{label}</span>
            <span style="color:#5a7a90">{count}</span>
        </div>
        <div class="sev-bar">
            <div class="sev-bar-fill" style="width:{pct}%; background:{color};"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0 24px 0;">
        <div style="font-family:'Rajdhani',sans-serif; font-size:1.4rem; font-weight:700;
                    color:#00d4ff; letter-spacing:3px;">🛡️ SENTINEL<span style="color:#3d6b8a">AI</span></div>
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem;
                    color:#2a4a6a; letter-spacing:2px; margin-top:2px;">SECURITY AUDIT SYSTEM</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    mode = st.radio(
        "MODE",
        ["📊  View Report", "🔍  Run New Scan"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem;
                color:#1e3a52; letter-spacing:1px; margin-top:20px;">
        AGENTS ACTIVE<br><br>
        <span style="color:#1a5a3a">●</span> Agent A · Pattern<br>
        <span style="color:#1a5a3a">●</span> Agent B · Auth LLM<br>
        <span style="color:#1a5a3a">●</span> Agent C · Data Flow<br>
        <span style="color:#1a5a3a">●</span> Agent D · Risk Score
    </div>
    """, unsafe_allow_html=True)


# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="display:flex; align-items:flex-end; gap:16px; padding: 10px 0 24px 0;">
    <div>
        <div class="sentinel-title">🛡️ SentinelAI</div>
        <div class="sentinel-sub">Multi-Agent AI Security Auditor · Python Web Applications</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MODE: VIEW REPORT
# ══════════════════════════════════════════════════════════════════════════════
if "📊" in mode:

    # Find available reports
    report_files = list(Path(".").rglob("sentinel_report.json"))
    if not report_files:
        st.markdown("""
        <div style="text-align:center; padding:60px; color:#2a4a6a;
                    font-family:'Share Tech Mono',monospace; font-size:0.8rem; letter-spacing:2px;">
            NO REPORTS FOUND<br><br>
            <span style="font-size:0.65rem; color:#1a2e42;">
            Run a scan first using the sidebar → Run New Scan<br>
            or run: python main.py sample_app/ --no-llm
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    report_options = {str(p): str(p) for p in report_files}
    selected = st.selectbox("SELECT REPORT", list(report_options.keys()), label_visibility="collapsed")

    data = load_report(selected)
    summary = data.get("summary", {})
    findings = data.get("findings", [])

    risk_score = summary.get("risk_score", 0)
    risk_level = summary.get("risk_level", "UNKNOWN")
    risk_color = get_risk_color(risk_level)
    total = summary.get("total_findings", 0)
    sev_breakdown = summary.get("severity_breakdown", {})
    duration = summary.get("scan_duration_seconds", 0)
    target = summary.get("target_path", "unknown")

    # ── Top metrics row ────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 1, 1])

    with col1:
        risk_short = risk_level.split(" - ")[0] if " - " in risk_level else risk_level
        st.markdown(f"""
        <div class="risk-card">
            <div class="risk-label">OVERALL RISK SCORE</div>
            <div class="risk-score-num" style="color:{risk_color};">{risk_score}</div>
            <div class="risk-level-text" style="color:{risk_color};">{risk_short}</div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem;
                        color:#2a4a6a; margin-top:8px;">
                Target: {target} · {duration}s
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-num" style="color:#e2eaf2;">{total}</div>
            <div class="stat-label">Total Issues</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        c = sev_breakdown.get("CRITICAL", 0)
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-num" style="color:#ff4444;">{c}</div>
            <div class="stat-label">Critical</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        h = sev_breakdown.get("HIGH", 0)
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-num" style="color:#ff8c00;">{h}</div>
            <div class="stat-label">High</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        m = sev_breakdown.get("MEDIUM", 0)
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-num" style="color:#ffd200;">{m}</div>
            <div class="stat-label">Medium</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<hr class="divider">', unsafe_allow_html=True)

    # ── Charts row ─────────────────────────────────────────────────────────────
    col_left, col_right = st.columns([1, 2])

    with col_left:
        st.markdown('<div class="section-header">Severity Breakdown</div>', unsafe_allow_html=True)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_breakdown.get(sev, 0)
            if count > 0:
                render_sev_bar(sev, count, total, SEVERITY_COLORS[sev])

        st.markdown('<div class="section-header">By Agent</div>', unsafe_allow_html=True)
        agents_data = summary.get("findings_by_agent", {})
        for agent, count in agents_data.items():
            short = agent.split("·")[0].replace("Agent", "Agt").strip()
            render_sev_bar(short[:30], count, total, "#3a7aaa")

    with col_right:
        st.markdown('<div class="section-header">All Findings</div>', unsafe_allow_html=True)

        # Filter controls
        fc1, fc2 = st.columns(2)
        with fc1:
            sev_filter = st.multiselect(
                "FILTER SEVERITY",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        with fc2:
            agent_names = list({f.get("agent", "") for f in findings})
            agent_filter = st.multiselect(
                "FILTER AGENT",
                agent_names,
                default=agent_names
            )

        filtered = [
            f for f in findings
            if f.get("severity") in sev_filter
            and f.get("agent") in agent_filter
        ]

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        filtered.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))

        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                    color:#3d6b8a; letter-spacing:1px; margin-bottom:14px;">
            SHOWING {len(filtered)} OF {total} FINDINGS
        </div>
        """, unsafe_allow_html=True)

        for f in filtered:
            render_finding_card(f)


# ══════════════════════════════════════════════════════════════════════════════
# MODE: RUN NEW SCAN
# ══════════════════════════════════════════════════════════════════════════════
else:
    st.markdown('<div class="section-header">Run a New Scan</div>', unsafe_allow_html=True)

    st.markdown('<div class="scan-box">', unsafe_allow_html=True)

    target_path = st.text_input(
        "TARGET PATH",
        value="sample_app/",
        placeholder="e.g. sample_app/ or C:/path/to/your/project/"
    )

    c1, c2 = st.columns(2)
    with c1:
        use_llm = st.checkbox("Enable LLM Analysis (Agent B)", value=False)
    with c2:
        output_dir = st.text_input("OUTPUT DIR", value="output")

    st.markdown('</div>', unsafe_allow_html=True)

    if st.button("⚡  LAUNCH SCAN"):
        if not os.path.exists(target_path):
            st.error(f"Path not found: {target_path}")
        else:
            cmd = [sys.executable, "main.py", target_path, "--output-dir", output_dir]
            if not use_llm:
                cmd.append("--no-llm")

            st.markdown("""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.7rem;
                        color:#3d6b8a; letter-spacing:2px; margin: 16px 0 8px 0;">
                SCAN OUTPUT
            </div>
            """, unsafe_allow_html=True)

            output_placeholder = st.empty()
            full_output = ""

            with st.spinner("Scanning..."):
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                for line in process.stdout:
                    full_output += line
                    output_placeholder.markdown(
                        f'<div class="terminal">{full_output}</div>',
                        unsafe_allow_html=True
                    )
                process.wait()

            if process.returncode == 0:
                st.success("✅ Scan complete! Switch to 'View Report' mode to see results.")
                report_path = os.path.join(output_dir, "sentinel_report.json")
                if os.path.exists(report_path):
                    with open(report_path) as f:
                        report_data = json.load(f)
                    summary = report_data.get("summary", {})
                    risk = summary.get("risk_level", "")
                    score = summary.get("risk_score", 0)
                    total_f = summary.get("total_findings", 0)
                    color = get_risk_color(risk)
                    st.markdown(f"""
                    <div class="risk-card" style="margin-top:20px;">
                        <div class="risk-label">SCAN COMPLETE</div>
                        <div class="risk-score-num" style="color:{color}; font-size:3rem;">{score}</div>
                        <div class="risk-level-text" style="color:{color};">{risk.split(' - ')[0]}</div>
                        <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#3d6b8a; margin-top:8px;">
                            {total_f} findings detected
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.error("Scan encountered an error. Check the output above.")

    # Quick info
    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#1e3a52; line-height:2;">
        USAGE NOTES<br><br>
        · Point target at any Python file or folder<br>
        · LLM Analysis requires ANTHROPIC_API_KEY to be set<br>
        · Results auto-save to output/sentinel_report.json<br>
        · Switch to View Report mode after scan completes
    </div>
    """, unsafe_allow_html=True)
