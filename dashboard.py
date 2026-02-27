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
    font-size: 0.72rem;
    background: #050810;
    border: 1px solid #1a2535;
    border-radius: 6px;
    padding: 10px 14px;
    color: #e07a5f;
    margin: 8px 0;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-width: 100%;
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
    # Shorten agent name for display
    agent_short = agent.split(" - ")[0].split(" [")[0].strip()
    agent_html = f'<span class="agent-pill">{agent_short}</span>'

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
        <span style="color:#1a5a3a">●</span> Agent D · Risk Score<br>
        <span style="color:#1a5a3a">●</span> Agent E · Dependencies<br>
        <span style="color:#1a5a3a">●</span> Agent F · Git History<br>
        <span style="color:#1a5a3a">●</span> Agent G · CORS/Headers<br>
        <span style="color:#1a5a3a">●</span> Agent H · Cryptography
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
    import datetime, os as _os, html as _html

    def risk_plain_english(risk_level, score):
        r = risk_level.upper()
        if "CRITICAL" in r:
            return {"emoji": "🚨", "headline": "Your code has serious security problems",
                "detail": "Several critical vulnerabilities were found that could allow hackers to steal data, bypass logins, or take control of your application. Do NOT deploy this code without fixing these issues first.",
                "action": "Fix CRITICAL and HIGH issues immediately before going live.",
                "color": "#ff4444", "bg": "rgba(255,50,50,0.06)", "border": "#5a1a1a"}
        elif "HIGH" in r:
            return {"emoji": "⚠️", "headline": "Your code has significant security risks",
                "detail": "Important vulnerabilities were found that need attention. These could be exploited by attackers if your application is publicly accessible.",
                "action": "Review and fix HIGH severity issues before deploying.",
                "color": "#ff8c00", "bg": "rgba(255,140,0,0.06)", "border": "#5a3a0a"}
        elif "MEDIUM" in r:
            return {"emoji": "⚡", "headline": "Your code has some security concerns",
                "detail": "A few security issues were found. They are not immediately dangerous but should be addressed.",
                "action": "Plan to fix these issues in your next update.",
                "color": "#ffd200", "bg": "rgba(255,210,0,0.06)", "border": "#4a4a0a"}
        else:
            return {"emoji": "✅", "headline": "Your code looks reasonably secure",
                "detail": "Only minor issues were found. Your application appears to follow reasonable security practices.",
                "action": "Review the low-severity findings at your convenience.",
                "color": "#00c878", "bg": "rgba(0,200,120,0.06)", "border": "#0a4a2a"}

    def severity_info(sev):
        return {
            "CRITICAL": {"label": "Must Fix Now",       "color": "#ff4444", "bg": "rgba(255,50,50,0.1)",   "icon": "🚨", "meaning": "Can lead to hacking or data theft"},
            "HIGH":     {"label": "Fix Before Launch",  "color": "#ff8c00", "bg": "rgba(255,140,0,0.1)",   "icon": "🔴", "meaning": "Serious vulnerability"},
            "MEDIUM":   {"label": "Fix Soon",           "color": "#ffd200", "bg": "rgba(255,210,0,0.1)",   "icon": "🟡", "meaning": "Moderate security concern"},
            "LOW":      {"label": "Fix When Possible",  "color": "#00c878", "bg": "rgba(0,200,120,0.1)",   "icon": "🟢", "meaning": "Minor issue"},
        }.get(sev, {"label": sev, "color": "#888", "bg": "rgba(0,0,0,0.1)", "icon": "⚪", "meaning": ""})

    def what_it_means(title):
        t = title.lower()
        if "hardcoded secret" in t or "api key" in t or "exposed" in t:
            return "A password or secret key is written directly in the code. Anyone who sees your code can steal it."
        elif "sql injection" in t:
            return "Hackers could manipulate your database to steal, delete, or modify all your data."
        elif "eval()" in t or "code execution" in t:
            return "Your app can be tricked into running malicious code sent by an attacker."
        elif "debug mode" in t:
            return "Debug mode is on — this shows detailed error info to attackers."
        elif "plaintext password" in t:
            return "Passwords are stored without encryption — easily stolen if your database is breached."
        elif "bypass" in t:
            return "A flaw in the login logic means anyone can access protected areas without a password."
        elif "privilege escalation" in t:
            return "A regular user could trick the system into giving them admin access."
        elif "unauthenticated" in t:
            return "This page has no login check — anyone on the internet can access it."
        elif "unsanitized" in t:
            return "User input flows directly into dangerous operations without any safety checks."
        elif "dependency" in t or "vulnerable" in t:
            return "You are using an outdated library with known security holes attackers can exploit."
        elif "cors" in t or "wildcard" in t:
            return "Any website on the internet can make requests to your app and steal user data."
        elif "missing security header" in t:
            return "A browser security protection is not configured, making your users vulnerable."
        elif "weak hash" in t or "md5" in t or "sha1" in t:
            return "You are using an outdated encryption method that can be cracked by modern computers."
        elif "ssl" in t or "tls" in t or "certificate" in t:
            return "Your encrypted connection can be intercepted — attackers can read private data."
        elif "insecure random" in t:
            return "The random number generator is predictable — attackers could guess tokens or passwords."
        elif "git history" in t:
            return "A secret was found in your code history. Even if deleted, it is visible to anyone who downloads your repo."
        return "A security vulnerability was detected in your code."

    # Find reports
    report_files = list(Path(".").rglob("sentinel_report.json"))
    if not report_files:
        st.markdown("""
        <div style="text-align:center; padding:80px 40px;">
            <div style="font-size:3rem; margin-bottom:16px;">📂</div>
            <div style="font-size:1.2rem; color:#4a7a9a; font-weight:600; margin-bottom:8px;">
                No scan results yet
            </div>
            <div style="font-size:0.85rem; color:#4a6a7a;">
                Go to <b>Run New Scan</b> in the sidebar, upload your Python file or ZIP,
                and click Launch Scan.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    report_files_sorted = sorted(report_files, key=lambda p: p.stat().st_mtime, reverse=True)
    def make_label(p):
        mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime)
        return f"Scanned on {mtime.strftime('%d %b %Y at %H:%M')}  —  {p.name}"
    report_map = {make_label(p): str(p) for p in report_files_sorted}

    if len(report_files_sorted) > 1:
        selected_label = st.selectbox("Choose a scan report:", list(report_map.keys()))
        selected = report_map[selected_label]
    else:
        selected = str(report_files_sorted[0])

    data      = load_report(selected)
    summary   = data.get("summary", {})
    findings  = data.get("findings", [])
    risk_score   = summary.get("risk_score", 0)
    risk_level   = summary.get("risk_level", "UNKNOWN")
    risk_color   = get_risk_color(risk_level)
    total        = summary.get("total_findings", 0)
    sev_breakdown= summary.get("severity_breakdown", {})
    duration     = summary.get("scan_duration_seconds", 0)
    target       = summary.get("target_path", "unknown")
    scanned_files= summary.get("files_scanned", [])
    report_mtime = datetime.datetime.fromtimestamp(_os.path.getmtime(selected))
    scan_time_str= report_mtime.strftime("%d %b %Y at %H:%M")

    # Plain English headline banner
    risk_info  = risk_plain_english(risk_level, risk_score)
    n_critical = sev_breakdown.get("CRITICAL", 0)
    n_high     = sev_breakdown.get("HIGH", 0)
    n_medium   = sev_breakdown.get("MEDIUM", 0)
    n_low      = sev_breakdown.get("LOW", 0)
    fname = (scanned_files[0].replace("\\", "/").split("/")[-1]
             if scanned_files else target.replace("\\", "/").split("/")[-1])

    st.markdown(f"""
    <div style="background:{risk_info['bg']}; border:1px solid {risk_info['border']};
                border-radius:12px; padding:24px 28px; margin-bottom:24px;">
        <div style="display:flex; align-items:flex-start; gap:14px; margin-bottom:12px;">
            <span style="font-size:2.2rem; line-height:1;">{risk_info['emoji']}</span>
            <div>
                <div style="font-size:1.3rem; font-weight:700; color:{risk_info['color']}; margin-bottom:4px;">
                    {risk_info['headline']}
                </div>
                <div style="font-size:0.8rem; color:#5a8a9a;">
                    File: <b style="color:#8abacc;">{fname}</b>
                    &nbsp;·&nbsp; {scan_time_str}
                    &nbsp;·&nbsp; {len(scanned_files)} file(s) scanned &nbsp;·&nbsp; {duration}s
                </div>
            </div>
        </div>
        <div style="font-size:0.9rem; color:#a0bac8; line-height:1.7; margin-bottom:14px;">
            {risk_info['detail']}
        </div>
        <div style="background:rgba(0,0,0,0.25); border-radius:8px; padding:11px 16px;
                    font-size:0.85rem; color:{risk_info['color']}; font-weight:600;">
            What to do: &nbsp;{risk_info['action']}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Export buttons ────────────────────────────────────────────────────
    btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 4])
    with btn_col1:
        # PDF Export button — find project root inline (works in both modes)
        def _find_root():
            check = os.getcwd()
            for _ in range(5):
                if os.path.exists(os.path.join(check, "main.py")):
                    return check
                check = os.path.dirname(check)
            return os.getcwd()

        export_pdf_path = selected.replace(".json", ".pdf")
        if st.button("📄  Export PDF"):
            try:
                import importlib.util, sys as _sys
                pdf_script = os.path.join(_find_root(), "export_pdf.py")
                if os.path.exists(pdf_script):
                    spec = importlib.util.spec_from_file_location("export_pdf", pdf_script)
                    mod  = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    mod.build_pdf(selected, export_pdf_path)
                    st.success(f"PDF saved to: {export_pdf_path}")
                else:
                    st.error("export_pdf.py not found in project root.")
            except Exception as e:
                st.error(f"PDF export failed: {e}")

        # Show download button if PDF exists
        if os.path.exists(export_pdf_path):
            with open(export_pdf_path, "rb") as pdf_f:
                st.download_button(
                    label="⬇  Download PDF",
                    data=pdf_f.read(),
                    file_name=f"sentinelai_report_{report_mtime.strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf"
                )
    with btn_col2:
        # JSON download
        with open(selected, "rb") as jf:
            st.download_button(
                label="⬇  Download JSON",
                data=jf.read(),
                file_name=f"sentinelai_report_{report_mtime.strftime('%Y%m%d_%H%M')}.json",
                mime="application/json"
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # Issue summary row
    cols = st.columns(4)
    for col, (sev, count, icon, lbl) in zip(cols, [
        ("CRITICAL", n_critical, "🚨", "Must Fix Now"),
        ("HIGH",     n_high,     "🔴", "Fix Before Launch"),
        ("MEDIUM",   n_medium,   "🟡", "Fix Soon"),
        ("LOW",      n_low,      "🟢", "Fix When Possible"),
    ]):
        si = severity_info(sev)
        col.markdown(f"""
        <div style="background:{si['bg']}; border:1px solid {si['color']}33;
                    border-radius:10px; padding:18px 12px; text-align:center; margin-bottom:8px;">
            <div style="font-size:1.6rem;">{icon}</div>
            <div style="font-size:2rem; font-weight:800; color:{si['color']}; line-height:1.1;">{count}</div>
            <div style="font-size:0.8rem; font-weight:600; color:{si['color']}; margin:4px 0 2px 0;">{lbl}</div>
            <div style="font-size:0.68rem; color:#4a6a7a;">{si['meaning']}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Filter bar
    st.markdown("""
    <div style="font-size:1.05rem; font-weight:700; color:#8ab4cc;
                border-bottom:1px solid #1e2d40; padding-bottom:8px; margin-bottom:16px;">
        Security Issues Found
    </div>
    """, unsafe_allow_html=True)

    col_f1, col_f2, col_f3 = st.columns([2, 1, 1])
    with col_f1:
        sev_opts = ["🚨 Critical", "🔴 High", "🟡 Medium", "🟢 Low"]
        sev_sel  = st.multiselect("Show:", sev_opts, default=sev_opts)
        sev_map  = {"🚨 Critical": "CRITICAL", "🔴 High": "HIGH", "🟡 Medium": "MEDIUM", "🟢 Low": "LOW"}
        sev_codes= [sev_map[s] for s in sev_sel if s in sev_map]
    with col_f2:
        search = st.text_input("Search:", placeholder="e.g. password, SQL...")
    with col_f3:
        sort_by = st.selectbox("Sort by:", ["Severity (worst first)", "Line number"])

    filtered = [f for f in findings
        if f.get("severity") in sev_codes
        and (not search or search.lower() in
             (f.get("title","") + f.get("description","") + f.get("code_snippet","")).lower())]

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    filtered.sort(key=lambda x: x.get("lineno") or 0 if sort_by == "Line number"
                  else sev_order.get(x.get("severity","LOW"), 4))

    st.markdown(f'<div style="font-size:0.8rem; color:#4a6a7a; margin-bottom:12px;">Showing {len(filtered)} of {total} issues</div>',
                unsafe_allow_html=True)

    # Friendly finding cards as expandable sections
    for i, f in enumerate(filtered):
        sev     = f.get("severity", "LOW")
        si      = severity_info(sev)
        title   = f.get("title", "Unknown Issue")
        rec     = f.get("recommendation", "")
        snippet = f.get("code_snippet", "")
        lineno  = f.get("lineno")
        filepath= f.get("filepath", "")
        cwe     = f.get("cwe_id", "")
        plain   = what_it_means(title)
        filename= filepath.replace("\\", "/").split("/")[-1] if filepath else ""

        with st.expander(f"{si['icon']}  {title}  —  {si['label']}", expanded=(i < 3 and sev == "CRITICAL")):
            st.markdown(f"""
            <div style="background:rgba(255,255,255,0.03); border-radius:8px; padding:14px 16px; margin-bottom:12px;">
                <div style="font-size:0.72rem; color:#4a7a9a; font-weight:600; letter-spacing:1px; margin-bottom:6px;">
                    WHAT THIS MEANS
                </div>
                <div style="font-size:0.95rem; color:#c9d4e0; line-height:1.6;">{plain}</div>
            </div>
            """, unsafe_allow_html=True)

            loc_parts = []
            if filename: loc_parts.append(f"<b>File:</b> {filename}")
            if lineno:   loc_parts.append(f"<b>Line:</b> {lineno}")
            if cwe:      loc_parts.append(f"<b>Reference:</b> {cwe}")
            if loc_parts:
                st.markdown('<div style="font-size:0.78rem; color:#4a7a9a; margin-bottom:10px;">' +
                            " &nbsp;·&nbsp; ".join(loc_parts) + "</div>", unsafe_allow_html=True)

            if snippet:
                st.markdown(f"""
                <div style="margin-bottom:10px;">
                    <div style="font-size:0.72rem; color:#3d6b8a; margin-bottom:4px;">The problematic code:</div>
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.78rem;
                                background:#050810; border:1px solid #1a2535; border-radius:6px;
                                padding:10px 14px; color:#e07a5f; white-space:pre-wrap; word-break:break-all;">
{_html.escape(snippet[:300])}</div>
                </div>
                """, unsafe_allow_html=True)

            if rec:
                st.markdown(f"""
                <div style="background:rgba(0,180,100,0.06); border-left:3px solid #2a7a4a;
                            border-radius:0 8px 8px 0; padding:12px 16px;">
                    <div style="font-size:0.72rem; color:#2a8a4a; font-weight:600;
                                letter-spacing:1px; margin-bottom:6px;">HOW TO FIX IT</div>
                    <div style="font-size:0.85rem; color:#7abf8a; line-height:1.6;">{rec}</div>
                </div>
                """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODE: RUN NEW SCAN
# ══════════════════════════════════════════════════════════════════════════════
else:
    import zipfile
    import tempfile
    import shutil

    def find_project_root() -> str:
        check = os.getcwd()
        for _ in range(5):
            if os.path.exists(os.path.join(check, "main.py")):
                return check
            check = os.path.dirname(check)
        for c in [os.getcwd(), os.path.dirname(os.path.abspath(sys.argv[0]))]:
            if os.path.exists(os.path.join(c, "main.py")):
                return c
        return os.getcwd()

    PROJECT_ROOT = find_project_root()
    MAIN_PY = os.path.join(PROJECT_ROOT, "main.py")

    st.markdown('<div class="section-header">Run a New Scan</div>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["  Upload ZIP / .py File  ", "  Local Path  "])

    scan_target = None
    cleanup_dir = None

    with tab1:
        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                    color:#3d6b8a; letter-spacing:1px; margin:12px 0 16px 0; line-height:1.8;">
            Upload a ZIP of your Python project or a single .py file.<br>
            The file will be extracted and scanned automatically.
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "DROP YOUR FILE HERE",
            type=["zip", "py"],
            label_visibility="collapsed",
            help="Upload a .zip of your project folder or a single .py file"
        )

        if uploaded_file is not None:
            file_size_kb = round(uploaded_file.size / 1024, 1)
            st.markdown(f"""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                        color:#2a6a3a; padding:10px 14px; background:rgba(0,100,50,0.1);
                        border:1px solid #1a4a2a; border-radius:6px; margin-bottom:12px;">
                FILE RECEIVED: {uploaded_file.name} &nbsp;|&nbsp; {file_size_kb} KB
            </div>
            """, unsafe_allow_html=True)

            tmp_dir = tempfile.mkdtemp(prefix="sentinelai_")
            cleanup_dir = tmp_dir

            if uploaded_file.name.endswith(".zip"):
                zip_path = os.path.join(tmp_dir, uploaded_file.name)
                with open(zip_path, "wb") as zf:
                    zf.write(uploaded_file.getbuffer())
                extract_dir = os.path.join(tmp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                try:
                    with zipfile.ZipFile(zip_path, "r") as z:
                        z.extractall(extract_dir)
                    items = os.listdir(extract_dir)
                    if len(items) == 1:
                        inner = os.path.join(extract_dir, items[0])
                        if os.path.isdir(inner):
                            extract_dir = inner
                    scan_target = extract_dir
                    py_count = len(list(Path(extract_dir).rglob("*.py")))
                    st.markdown(f"""
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem; color:#2a8a4a;">
                        [OK] ZIP extracted - {py_count} Python file(s) found
                    </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"Failed to extract ZIP: {e}")

            elif uploaded_file.name.endswith(".py"):
                py_path = os.path.join(tmp_dir, uploaded_file.name)
                with open(py_path, "wb") as pf:
                    pf.write(uploaded_file.getbuffer())
                scan_target = py_path
                st.markdown("""
                <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem; color:#2a8a4a;">
                    [OK] Python file ready to scan
                </div>
                """, unsafe_allow_html=True)

    with tab2:
        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem;
                    color:#2a5a3a; letter-spacing:1px; margin-bottom:12px; padding:8px 12px;
                    background:rgba(0,80,40,0.1); border:1px solid #1a4a2a; border-radius:6px;">
            PROJECT ROOT: {PROJECT_ROOT} &nbsp;|&nbsp;
            MAIN.PY: {"[OK]" if os.path.exists(MAIN_PY) else "[NOT FOUND]"}
        </div>
        """, unsafe_allow_html=True)

        local_path = st.text_input(
            "TARGET PATH",
            value=os.path.join(PROJECT_ROOT, "sample_app"),
            placeholder="C:/path/to/your/project/"
        )
        if local_path and os.path.exists(local_path):
            py_count = len(list(Path(local_path).rglob("*.py"))) if os.path.isdir(local_path) else 1
            st.markdown(f"""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem; color:#2a8a4a;">
                [OK] Path found - {py_count} Python file(s) detected
            </div>
            """, unsafe_allow_html=True)
            scan_target = local_path
        elif local_path:
            st.markdown("""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem; color:#8a2a2a;">
                [X] Path not found - check the path is correct
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        use_llm = st.checkbox("Enable LLM Analysis (Agent B)", value=False)
    with c2:
        output_dir = os.path.join(PROJECT_ROOT, "output")
        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem;
                    color:#3d6b8a; margin-top:8px;">
            OUTPUT -> {output_dir}
        </div>
        """, unsafe_allow_html=True)

    launch_disabled = scan_target is None
    if st.button("* LAUNCH SCAN", disabled=launch_disabled):
        if not os.path.exists(MAIN_PY):
            st.error(f"Cannot find main.py at: {MAIN_PY}")
        else:
            os.makedirs(output_dir, exist_ok=True)
            cmd = [sys.executable, MAIN_PY, scan_target, "--output-dir", output_dir]
            if not use_llm:
                cmd.append("--no-llm")

            st.markdown("""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.7rem;
                        color:#3d6b8a; letter-spacing:2px; margin:16px 0 8px 0;">
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
                    bufsize=1,
                    encoding="utf-8",
                    errors="replace",
                    cwd=PROJECT_ROOT
                )
                for line in process.stdout:
                    full_output += line
                    output_placeholder.markdown(
                        f'<div class="terminal">{full_output}</div>',
                        unsafe_allow_html=True
                    )
                process.wait()

            if cleanup_dir and os.path.exists(cleanup_dir):
                try:
                    shutil.rmtree(cleanup_dir)
                except Exception:
                    pass

            if process.returncode == 0:
                # Save a timestamped copy so history is preserved
                import datetime, shutil as _shutil
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = os.path.join(output_dir, "sentinel_report.json")
                if os.path.exists(report_path):
                    archive_path = os.path.join(output_dir, f"sentinel_report_{ts}.json")
                    _shutil.copy2(report_path, archive_path)

                st.success(f"[OK] Scan complete! Report saved. Switch to View Report mode.")
                if os.path.exists(report_path):
                    with open(report_path) as rf:
                        report_data = json.load(rf)
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
                        <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                                    color:#3d6b8a; margin-top:8px;">
                            {total_f} findings detected
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.error("Scan encountered an error. Check the output above.")

    if launch_disabled:
        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem;
                    color:#2a4a6a; margin-top:8px; letter-spacing:1px;">
            [!] Upload a file or enter a local path above to enable scanning
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#1e3a52; line-height:2;">
        USAGE NOTES<br><br>
        · Upload Tab: drag and drop a .zip of your project or a single .py file<br>
        · Local Tab: type the full path to any Python file or folder<br>
        · LLM Analysis requires ANTHROPIC_API_KEY environment variable<br>
        · Results auto-save and appear in View Report mode
    </div>
    """, unsafe_allow_html=True)
