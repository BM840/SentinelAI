"""
SentinelAI - Redesigned Dashboard
Run with: streamlit run dashboard.py
"""
import streamlit as st
import json, os, sys, subprocess, time, datetime, tempfile, zipfile, shutil, html as _html
from pathlib import Path
from collections import defaultdict, Counter

st.set_page_config(
    page_title="SentinelAI · Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── PROJECT ROOT ───────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MAIN_PY      = os.path.join(PROJECT_ROOT, "main.py")

# ── GLOBAL CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Syne:wght@700;800&display=swap');

:root {
    --bg:       #060a0f;
    --surface:  #0b1119;
    --card:     #0f1822;
    --border:   #1a2535;
    --border2:  #243548;
    --text:     #cdd6e0;
    --muted:    #4a6275;
    --accent:   #00c8ff;
    --accent2:  #0078aa;
    --crit:     #ff3d3d;
    --high:     #ff8800;
    --med:      #f5c400;
    --low:      #00d68f;
}

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif;
    background: var(--bg);
    color: var(--text);
}
.stApp { background: var(--bg); }
header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer { visibility: hidden; }
.block-container { padding-top: 1.5rem !important; max-width: 1400px; }

/* ── SIDEBAR ── */
section[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
    padding-top: 0 !important;
}
section[data-testid="stSidebar"] > div:first-child { padding-top: 0; }

/* ── RADIO BUTTONS → nav pills ── */
div[data-testid="stRadio"] > div { gap: 0 !important; }
div[data-testid="stRadio"] label {
    background: transparent !important;
    border: none !important;
    border-radius: 0 !important;
    padding: 10px 16px !important;
    margin: 0 !important;
    width: 100% !important;
    cursor: pointer !important;
    transition: all 0.15s !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    color: var(--muted) !important;
    letter-spacing: 0.3px !important;
}
div[data-testid="stRadio"] label:hover { background: rgba(0,200,255,0.05) !important; color: var(--accent) !important; }
div[data-testid="stRadio"] label[data-checked="true"] {
    background: rgba(0,200,255,0.08) !important;
    color: var(--accent) !important;
    border-left: 2px solid var(--accent) !important;
}
div[data-testid="stRadio"] p { font-size: 0.82rem !important; font-weight: 500 !important; }

/* ── INPUTS ── */
.stTextInput input, .stSelectbox div[data-baseweb="select"] {
    background: var(--card) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 8px !important;
    color: var(--text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
}
.stTextInput input:focus { border-color: var(--accent) !important; box-shadow: 0 0 0 2px rgba(0,200,255,0.15) !important; }

/* ── BUTTONS ── */
.stButton button {
    background: linear-gradient(135deg, #003d5c 0%, #00527a 100%) !important;
    color: var(--accent) !important;
    border: 1px solid rgba(0,200,255,0.3) !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 0.85rem !important;
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    padding: 10px 24px !important;
    border-radius: 8px !important;
    transition: all 0.2s !important;
}
.stButton button:hover {
    background: linear-gradient(135deg, #004d70 0%, #006694 100%) !important;
    box-shadow: 0 4px 24px rgba(0,200,255,0.2) !important;
    transform: translateY(-1px) !important;
}

/* ── EXPANDER ── */
details { border: 1px solid var(--border) !important; border-radius: 10px !important; margin-bottom: 8px !important; overflow: hidden; }
details summary {
    padding: 14px 18px !important;
    background: var(--card) !important;
    cursor: pointer !important;
    font-family: 'Space Grotesk', sans-serif !important;
    font-size: 0.88rem !important;
    font-weight: 600 !important;
    list-style: none !important;
}
details[open] summary { border-bottom: 1px solid var(--border); }
details > div { background: var(--surface) !important; padding: 16px !important; }

/* ── MULTISELECT ── */
.stMultiSelect span[data-baseweb="tag"] {
    background: rgba(0,200,255,0.12) !important;
    border: 1px solid rgba(0,200,255,0.25) !important;
    border-radius: 4px !important;
    font-size: 0.72rem !important;
}

/* ── DIVIDER ── */
hr { border-color: var(--border) !important; margin: 12px 0 !important; }

/* ── UPLOAD ── */
.stFileUploader { border-color: var(--border2) !important; }
section[data-testid="stFileUploadDropzone"] {
    background: rgba(0,200,255,0.03) !important;
    border: 1.5px dashed var(--border2) !important;
    border-radius: 10px !important;
    transition: all 0.2s !important;
}
section[data-testid="stFileUploadDropzone"]:hover { border-color: var(--accent) !important; }

/* ── SPINNER ── */
.stSpinner > div { border-top-color: var(--accent) !important; }

/* ── TABS ── */
button[data-baseweb="tab"] {
    font-family: 'Space Grotesk', sans-serif !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px !important;
    color: var(--muted) !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
}

/* ── CHECKBOX ── */
.stCheckbox label p { font-size: 0.82rem !important; color: var(--text) !important; }

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent2); }
</style>
""", unsafe_allow_html=True)

# ── HELPERS ────────────────────────────────────────────────────────────────
SEV_CFG = {
    "CRITICAL": {"color": "#ff3d3d", "bg": "rgba(255,61,61,0.08)",   "border": "rgba(255,61,61,0.25)",  "icon": "⬛", "label": "Critical"},
    "HIGH":     {"color": "#ff8800", "bg": "rgba(255,136,0,0.08)",   "border": "rgba(255,136,0,0.25)",  "icon": "🟧", "label": "High"},
    "MEDIUM":   {"color": "#f5c400", "bg": "rgba(245,196,0,0.08)",   "border": "rgba(245,196,0,0.25)",  "icon": "🟨", "label": "Medium"},
    "LOW":      {"color": "#00d68f", "bg": "rgba(0,214,143,0.08)",   "border": "rgba(0,214,143,0.25)",  "icon": "🟩", "label": "Low"},
}

def sev(s): return SEV_CFG.get(s, {"color":"#888","bg":"transparent","border":"#333","icon":"⬜","label":s})

def risk_color(rl):
    rl = rl.upper()
    if "CRITICAL" in rl: return "#ff3d3d"
    if "HIGH" in rl:     return "#ff8800"
    if "MEDIUM" in rl:   return "#f5c400"
    return "#00d68f"

def plain_english(title):
    t = title.lower()
    m = {
        "hardcoded secret":   "A password or API key is written directly in the code — anyone who reads it can steal access.",
        "api key":            "A live API key is exposed in your code and visible to anyone with repo access.",
        "sql injection":      "Attackers can manipulate your database to steal, modify, or delete all your data.",
        "eval()":             "Your app can be tricked into running any code an attacker sends it.",
        "debug mode":         "Debug mode leaks stack traces and internal info directly to attackers.",
        "plaintext password": "Passwords are stored without hashing — one database breach exposes them all.",
        "bypass":             "A logic flaw lets attackers skip authentication entirely.",
        "privilege":          "A regular user can trick the app into granting them admin access.",
        "unauthenticated":    "This route has no login check — any internet user can access it.",
        "unsanitized":        "Raw user input flows into a dangerous function without any safety checks.",
        "dependency":         "A library you use has a known security flaw attackers can exploit.",
        "cors":               "Any website can make requests to your API and steal your users' data.",
        "header":             "A browser security protection is missing, leaving users exposed.",
        "weak hash":          "MD5/SHA1 are broken — modern hardware cracks them in seconds.",
        "md5":                "MD5 is cryptographically broken and unsuitable for passwords or sensitive data.",
        "sha1":               "SHA1 is deprecated and vulnerable to collision attacks.",
        "ssl":                "SSL verification is disabled — attackers can intercept encrypted traffic.",
        "insecure random":    "The random generator is predictable — attackers can guess tokens and reset codes.",
        "git history":        "A secret was committed to git history. Even if deleted, it's visible forever.",
        "webhook":            "Webhook requests aren't verified — attackers can forge payment or event data.",
        "csrf":               "Missing CSRF protection allows attackers to make requests on behalf of your users.",
    }
    for k, v in m.items():
        if k in t: return v
    return "A security vulnerability was detected that could be exploited by attackers."

def load_report(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

# ── SIDEBAR ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:28px 20px 20px 20px; border-bottom:1px solid #1a2535;">
        <div style="font-family:'Syne',sans-serif; font-size:1.5rem; font-weight:800;
                    color:#00c8ff; letter-spacing:1px; line-height:1;">🛡️ SentinelAI</div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.6rem;
                    color:#2a4a62; letter-spacing:2.5px; margin-top:5px; text-transform:uppercase;">
            Multi-Agent Security Auditor
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='padding:8px 0;'>", unsafe_allow_html=True)
    mode = st.radio("NAV", ["🔍  New Scan", "📊  View Results"], label_visibility="collapsed")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # Agent status panel
    agents = [
        ("A", "Pattern Detector",   True),
        ("B", "Auth Logic · LLM",   True),
        ("C", "Data Flow",          True),
        ("D", "Risk Scorer",        True),
        ("E", "Dependencies",       True),
        ("F", "Git History",        True),
        ("G", "CORS & Headers",     True),
        ("H", "Cryptography",       True),
        ("I", "Auto-Fix · LLM",     True),
    ]
    agent_rows = "".join(
        f'<div style="display:flex;align-items:center;gap:8px;padding:5px 0;">'
        f'<div style="width:6px;height:6px;border-radius:50%;background:{"#00d68f" if active else "#2a3a4a"};flex-shrink:0;"></div>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.67rem;color:#3a5a72;font-weight:500;">Agent {letter}</span>'
        f'<span style="font-size:0.67rem;color:#2a4255;">{name}</span>'
        f'</div>'
        for letter, name, active in agents
    )
    st.markdown(f"""
    <div style="padding:4px 4px 12px 4px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;color:#1e3a52;
                    letter-spacing:2px;text-transform:uppercase;padding:8px 0 10px 0;">
            Agents Online
        </div>
        {agent_rows}
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style="padding:8px 4px;font-family:'JetBrains Mono',monospace;font-size:0.6rem;color:#1a3040;line-height:2;">
        v2.0 · Python · Ollama/phi3<br>
        GPU-accelerated · Local LLM<br>
        <a href="https://github.com/BM840/SentinelAI" style="color:#1e4060;text-decoration:none;">github.com/BM840/SentinelAI</a>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════
#  MODE: NEW SCAN
# ══════════════════════════════════════════════════════════════════════════
if "🔍" in mode:
    import tempfile, zipfile as _zip

    scan_target  = None
    cleanup_dir  = None

    # Page header
    st.markdown("""
    <div style="margin-bottom:32px;">
        <div style="font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;
                    color:#00c8ff;letter-spacing:-0.5px;line-height:1.1;">
            Run Security Scan
        </div>
        <div style="font-size:0.85rem;color:#3a5a72;margin-top:6px;">
            Upload your Python project or point to a local path · All 9 agents run automatically
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Agent preview cards ─────────────────────────────────────────────
    agent_preview = [
        ("A", "Pattern Detector",  "#00c8ff", "Regex + AST — secrets, eval(), SQL patterns"),
        ("B", "Auth Logic LLM",    "#a78bfa", "phi3 semantic — login bypass, access control"),
        ("C", "Data Flow",         "#34d399", "Traces user input to dangerous sinks"),
        ("E", "Dependencies",      "#fb923c", "CVE lookup via OSV.dev API"),
        ("F", "Git History",       "#f472b6", "Secrets in deleted commits"),
        ("G", "CORS & Headers",    "#60a5fa", "Security header configuration"),
        ("H", "Cryptography",      "#fbbf24", "Weak hashes, ciphers, RNG"),
        ("I", "Auto-Fix Engine",   "#4ade80", "phi3 generates corrected code"),
    ]
    cols = st.columns(4)
    for i, (letter, name, color, desc) in enumerate(agent_preview):
        cols[i % 4].markdown(f"""
        <div style="background:#0f1822;border:1px solid #1a2535;border-radius:10px;
                    padding:14px 16px;margin-bottom:10px;transition:all 0.2s;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                <div style="width:24px;height:24px;border-radius:6px;background:{color}18;
                            border:1px solid {color}40;display:flex;align-items:center;justify-content:center;">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                                 color:{color};font-weight:700;">{letter}</span>
                </div>
                <span style="font-size:0.78rem;font-weight:600;color:#8aacbe;">{name}</span>
            </div>
            <div style="font-size:0.68rem;color:#2a4a5e;line-height:1.5;">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin:8px 0 24px 0;'>", unsafe_allow_html=True)

    # ── Scan input ──────────────────────────────────────────────────────
    col_left, col_right = st.columns([3, 2], gap="large")

    with col_left:
        tab1, tab2 = st.tabs(["📁  Upload File / ZIP", "📂  Local Path"])

        with tab1:
            uploaded = st.file_uploader(
                "Drop your Python file or ZIP archive here",
                type=["py", "zip"],
                label_visibility="collapsed"
            )
            if uploaded:
                size_kb = round(uploaded.size / 1024, 1)
                st.markdown(f"""
                <div style="background:rgba(0,214,143,0.06);border:1px solid rgba(0,214,143,0.2);
                            border-radius:8px;padding:10px 14px;margin-top:8px;
                            font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#00d68f;">
                    ✓ &nbsp;{uploaded.name} &nbsp;·&nbsp; {size_kb} KB received
                </div>
                """, unsafe_allow_html=True)
                tmp = tempfile.mkdtemp(prefix="sentinel_")
                cleanup_dir = tmp
                if uploaded.name.endswith(".zip"):
                    zpath = os.path.join(tmp, uploaded.name)
                    with open(zpath, "wb") as zf:
                        zf.write(uploaded.getbuffer())
                    xdir = os.path.join(tmp, "extracted")
                    os.makedirs(xdir, exist_ok=True)
                    try:
                        with _zip.ZipFile(zpath) as z:
                            z.extractall(xdir)
                        items = os.listdir(xdir)
                        if len(items) == 1 and os.path.isdir(os.path.join(xdir, items[0])):
                            xdir = os.path.join(xdir, items[0])
                        scan_target = xdir
                        py_count = len(list(Path(xdir).rglob("*.py")))
                        st.markdown(f"""
                        <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                                    color:#2a8a5a;margin-top:6px;">
                            ✓ Extracted · {py_count} Python file(s) found
                        </div>""", unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"ZIP extraction failed: {e}")
                elif uploaded.name.endswith(".py"):
                    pypath = os.path.join(tmp, uploaded.name)
                    with open(pypath, "wb") as pf:
                        pf.write(uploaded.getbuffer())
                    scan_target = pypath

        with tab2:
            st.markdown(f"""
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                        color:#1e4060;padding:8px 0 12px 0;">
                Project root: {PROJECT_ROOT}
            </div>""", unsafe_allow_html=True)
            local_path = st.text_input(
                "Path", value="",
                placeholder="C:/path/to/your/project/",
                label_visibility="collapsed"
            )
            if local_path and os.path.exists(local_path):
                n = len(list(Path(local_path).rglob("*.py"))) if os.path.isdir(local_path) else 1
                st.markdown(f"""
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                            color:#2a8a5a;margin-top:4px;">✓ Path found · {n} Python file(s)</div>
                """, unsafe_allow_html=True)
                scan_target = local_path
            elif local_path:
                st.markdown("""
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                            color:#8a2a2a;margin-top:4px;">✗ Path not found</div>
                """, unsafe_allow_html=True)

    with col_right:
        st.markdown("""
        <div style="background:#0f1822;border:1px solid #1a2535;border-radius:12px;
                    padding:22px 20px;height:100%;">
            <div style="font-size:0.78rem;font-weight:600;color:#4a7a9a;
                        text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;">
                Scan Options
            </div>
        """, unsafe_allow_html=True)

        use_llm = st.checkbox("⚡ Enable LLM Analysis", value=True,
            help="Uses Ollama/phi3 on GPU for Agent B (auth logic) and Agent I (auto-fix). Requires Ollama running.")
        use_autofix = st.checkbox("🔧 Generate Auto-Fixes", value=True,
            help="Agent I will generate corrected code for every finding and save a patched file.")

        output_dir = os.path.join(PROJECT_ROOT, "output")
        st.markdown(f"""
        <div style="margin-top:16px;font-family:'JetBrains Mono',monospace;
                    font-size:0.62rem;color:#1e3a52;line-height:2;">
            Output → {output_dir}
        </div>""", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:24px;'>", unsafe_allow_html=True)

    launch_disabled = scan_target is None
    if launch_disabled:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                    color:#2a4a5e;padding:4px 0 16px 0;">
            ↑ Upload a file or enter a local path to enable scanning
        </div>""", unsafe_allow_html=True)


    if st.button("🚀  LAUNCH SCAN", disabled=launch_disabled):
        if not os.path.exists(MAIN_PY):
            st.error(f"Cannot find main.py at: {MAIN_PY}")
        else:
            os.makedirs(output_dir, exist_ok=True)
            cmd = [sys.executable, MAIN_PY, scan_target, "--output-dir", output_dir]
            if not use_llm:
                cmd.append("--no-llm")

            AGENTS = [
                ("A", "Pattern Detector",  "Regex + AST — secrets, eval(), SQL patterns"),
                ("B", "Auth Logic · LLM",  "phi3 semantic analysis of auth functions"),
                ("C", "Data Flow",         "Tracing user input to dangerous sinks"),
                ("E", "Dependencies",      "CVE lookup via OSV.dev API"),
                ("F", "Git History",       "Scanning commits for leaked secrets"),
                ("G", "CORS & Headers",    "Auditing security header configuration"),
                ("H", "Cryptography",      "Detecting weak hashes, ciphers, RNG"),
                ("D", "Risk Scorer",       "Calculating weighted risk score"),
                ("I", "Auto-Fix · LLM",    "Generating corrected code for findings"),
            ]

            st.markdown("""
            <style>
            @keyframes pulse  {0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.4;transform:scale(0.8)}}
            @keyframes sweep  {0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
            @keyframes fadein {from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:translateX(0)}}
            </style>""", unsafe_allow_html=True)

            col_left, col_right = st.columns([1, 1], gap="large")
            with col_left:
                st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#2a6a8a;letter-spacing:2px;text-transform:uppercase;padding-bottom:10px;">⬡ Agent Pipeline</div>', unsafe_allow_html=True)
                tracker_ph = st.empty()
            with col_right:
                st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#2a6a8a;letter-spacing:2px;text-transform:uppercase;padding-bottom:10px;">▶ Live Output</div>', unsafe_allow_html=True)
                term_ph = st.empty()

            agent_states = {a[0]: "waiting" for a in AGENTS}
            agent_counts = {a[0]: None for a in AGENTS}
            full_out = ""
            current_phase = None

            def render_tracker(states, counts):
                rows = ""
                for letter, name, desc in AGENTS:
                    st8 = states[letter]
                    cnt = counts[letter]
                    if st8 == "done":
                        dot   = "#00d68f"
                        anim  = ""
                        bg    = "background:rgba(0,214,143,0.04);border-color:rgba(0,214,143,0.15);"
                        nc    = "#00d68f"
                        right = ('<span style="font-size:0.72rem;font-weight:700;color:#00d68f;">'
                                 + (str(cnt)+" found" if cnt is not None else "✓") + "</span>")
                        bar   = '<div style="height:2px;background:linear-gradient(90deg,#00d68f50,#00d68f20);border-radius:2px;margin-top:4px;"></div>'
                    elif st8 == "running":
                        dot   = "#00c8ff"
                        anim  = "animation:pulse 0.9s ease infinite;"
                        bg    = "background:rgba(0,200,255,0.06);border-color:rgba(0,200,255,0.25);"
                        nc    = "#00c8ff"
                        right = '<span style="font-size:0.65rem;color:#1a6a8a;">scanning...</span>'
                        bar   = ('<div style="height:2px;background:#0a1525;border-radius:2px;margin-top:4px;overflow:hidden;">'
                                 '<div style="height:100%;width:40%;background:linear-gradient(90deg,transparent,#00c8ff,transparent);'
                                 'animation:sweep 1.4s ease infinite;"></div></div>')
                    else:
                        dot   = "#1a2d3a"
                        anim  = ""
                        bg    = "opacity:0.3;"
                        nc    = "#2a4a5e"
                        right = ""
                        bar   = ""

                    rows += (
                        f'<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 12px;'
                        f'border-radius:8px;border:1px solid transparent;margin-bottom:5px;{bg}">'
                        f'<div style="width:7px;height:7px;border-radius:50%;background:{dot};'
                        f'flex-shrink:0;margin-top:5px;{anim}"></div>'
                        f'<div style="flex:1;min-width:0;">'
                        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                        f'<span style="font-size:0.78rem;font-weight:600;color:{nc};">Agent {letter} · {name}</span>'
                        f'{right}</div>'
                        f'<div style="font-size:0.62rem;color:#1e3a4a;margin-top:1px;">{desc}</div>'
                        f'{bar}</div></div>'
                    )
                tracker_ph.markdown(rows, unsafe_allow_html=True)

            render_tracker(agent_states, agent_counts)

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, encoding="utf-8", errors="replace",
                cwd=PROJECT_ROOT
            )

            import re as _re
            for line in proc.stdout:
                full_out += line
                stripped  = line.strip()

                for letter, name, _ in AGENTS:
                    if f"Agent {letter}" in stripped and "Running" in stripped:
                        if current_phase and current_phase != letter:
                            if agent_states[current_phase] == "running":
                                agent_states[current_phase] = "done"
                        current_phase = letter
                        agent_states[letter] = "running"

                m = _re.search(r"Agent ([A-Z]) found (\d+)", stripped)
                if m:
                    ltr, cnt = m.group(1), int(m.group(2))
                    agent_states[ltr] = "done"
                    agent_counts[ltr] = cnt

                if "Agent I generated" in stripped:
                    agent_states["I"] = "done"
                    m2 = _re.search(r"(\d+) fix", stripped)
                    if m2: agent_counts["I"] = int(m2.group(1))

                if "OWASP mapping" in stripped:
                    m3 = _re.search(r"(\d+)/(\d+)", stripped)
                    if m3: agent_counts["D"] = int(m3.group(1))

                render_tracker(agent_states, agent_counts)

                lines_list = full_out.strip().split("\n")
                recent     = "\n".join(lines_list[-28:])
                term_ph.markdown(
                    '<div style="background:#040810;border:1px solid #1a2535;border-radius:8px;'
                    'padding:14px 16px;font-family:JetBrains Mono,monospace;font-size:0.68rem;'
                    'color:#3aff8a;line-height:1.75;height:460px;overflow:hidden;white-space:pre-wrap;">'
                    + _html.escape(recent) + '</div>',
                    unsafe_allow_html=True
                )

            proc.wait()
            for letter in agent_states:
                if agent_states[letter] == "running":
                    agent_states[letter] = "done"
            render_tracker(agent_states, agent_counts)

            # Mark any still-running as done
            for letter in agent_states:
                if agent_states[letter] == "running":
                    agent_states[letter] = "done"
            render_tracker(agent_states, agent_counts)

            if cleanup_dir and os.path.exists(cleanup_dir):
                try: shutil.rmtree(cleanup_dir)
                except: pass

            if proc.returncode == 0:
                # Archive report
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                rpath = os.path.join(output_dir, "sentinel_report.json")
                if os.path.exists(rpath):
                    shutil.copy2(rpath, os.path.join(output_dir, f"sentinel_report_{ts}.json"))

                # Results summary card
                if os.path.exists(rpath):
                    rd = load_report(rpath)
                    sm = rd.get("summary", {})
                    score = sm.get("risk_score", 0)
                    rl    = sm.get("risk_level", "")
                    total = sm.get("total_findings", 0)
                    rc    = risk_color(rl)
                    sev_b = sm.get("severity_breakdown", {})

                    st.markdown(f"""
                    <div style="background:#0f1822;border:1px solid {rc}33;border-radius:12px;
                                padding:24px;margin-top:20px;">
                        <div style="display:flex;align-items:flex-start;gap:24px;">
                            <div style="text-align:center;flex-shrink:0;">
                                <div style="font-family:'Syne',sans-serif;font-size:3.5rem;
                                            font-weight:800;color:{rc};line-height:1;">{score}</div>
                                <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                                            color:{rc};letter-spacing:1px;opacity:0.7;">RISK SCORE</div>
                            </div>
                            <div style="flex:1;">
                                <div style="font-size:1.1rem;font-weight:700;color:{rc};margin-bottom:6px;">
                                    {rl.split(" - ")[0]}
                                </div>
                                <div style="font-size:0.8rem;color:#4a6a7a;margin-bottom:14px;">
                                    {total} findings detected
                                </div>
                                <div style="display:flex;gap:12px;flex-wrap:wrap;">
                                    {''.join(f'<div style="background:{SEV_CFG[s]["bg"]};border:1px solid {SEV_CFG[s]["border"]};border-radius:6px;padding:6px 12px;"><span style="font-size:1rem;font-weight:700;color:{SEV_CFG[s]["color"]};">{sev_b.get(s,0)}</span><span style="font-size:0.65rem;color:#3a5a72;display:block;">{SEV_CFG[s]["label"]}</span></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
                                </div>
                            </div>
                        </div>
                        <div style="margin-top:16px;padding:12px 16px;background:rgba(0,200,255,0.05);
                                    border-radius:8px;font-size:0.8rem;color:#4a8aaa;">
                            ✓ Scan complete · Switch to <b>View Results</b> in the sidebar to explore findings
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.error("Scan encountered an error. Review the output above.")


# ══════════════════════════════════════════════════════════════════════════
#  MODE: VIEW RESULTS
# ══════════════════════════════════════════════════════════════════════════
else:
    import glob

    # Find reports
    report_files = sorted(
        list(Path(PROJECT_ROOT).rglob("sentinel_report*.json")),
        key=lambda p: p.stat().st_mtime, reverse=True
    )
    # Exclude archived timestamped ones from the picker (keep only latest + archives)
    main_report = [p for p in report_files if p.name == "sentinel_report.json"]
    archived    = [p for p in report_files if p.name != "sentinel_report.json"]
    all_reports = main_report + archived

    if not all_reports:
        st.markdown("""
        <div style="text-align:center;padding:100px 40px;">
            <div style="font-size:3rem;margin-bottom:20px;opacity:0.3;">🛡️</div>
            <div style="font-family:'Syne',sans-serif;font-size:1.4rem;font-weight:700;
                        color:#2a4a5e;margin-bottom:10px;">No scans yet</div>
            <div style="font-size:0.85rem;color:#1e3a4a;">
                Go to <b>New Scan</b> in the sidebar, upload a Python file and click Launch Scan.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    def report_label(p):
        mt = datetime.datetime.fromtimestamp(p.stat().st_mtime)
        try:
            with open(str(p), encoding="utf-8") as _rf:
                _rd = json.load(_rf)
            _sm   = _rd.get("summary", {})
            _tgt  = _sm.get("target_path", "")
            parts = _tgt.replace("\\", "/").replace("\\\\", "/").rstrip("/").split("/")
            tname = parts[-1] if parts else ""
            if tname.startswith("sentinel_") or tname in ("extracted", ""):
                tname = parts[-2] if len(parts) > 1 else tname
            _sc   = _sm.get("risk_score", 0)
            _n    = len(_sm.get("files_scanned", []))
            extra = f"  |  {tname}  |  {_n} file(s)  |  score {_sc}" if tname else ""
        except Exception:
            extra = ""
        return f"{mt.strftime('%d %b %Y  %H:%M')}{extra}"

    report_map = {report_label(p): str(p) for p in all_reports}

    if len(all_reports) > 1:
        st.markdown('<div style="font-size:0.7rem;font-weight:600;color:#2a5a72;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Select Scan Report</div>', unsafe_allow_html=True)
        selected = report_map[st.selectbox("Select report", list(report_map.keys()), label_visibility="collapsed")]
        st.markdown("<div style='margin-bottom:12px;'></div>", unsafe_allow_html=True)
    else:
        selected = str(all_reports[0])

    data     = load_report(selected)
    summary  = data.get("summary", {})
    findings = data.get("findings", [])

    score    = summary.get("risk_score", 0)
    rl       = summary.get("risk_level", "UNKNOWN")
    total    = summary.get("total_findings", 0)
    sev_b    = summary.get("severity_breakdown", {})
    dur      = summary.get("scan_duration_seconds", 0)
    target   = summary.get("target_path", "")
    files    = summary.get("files_scanned", [])
    rc       = risk_color(rl)
    rmt      = datetime.datetime.fromtimestamp(os.path.getmtime(selected))
    fname    = (files[0].replace("\\","/").split("/")[-1] if files
                else target.replace("\\","/").split("/")[-1])

    n_c = sev_b.get("CRITICAL", 0)
    n_h = sev_b.get("HIGH", 0)
    n_m = sev_b.get("MEDIUM", 0)
    n_l = sev_b.get("LOW", 0)

    # ── OWASP breakdown from findings ──────────────────────────────────
    owasp_counts = Counter(
        f"{f.get('owasp_id','')} — {f.get('owasp_name','')}"
        for f in findings if f.get("owasp_id")
    )
    owasp_tagged = sum(1 for f in findings if f.get("owasp_id"))

    # ── TOP SUMMARY BAR — native Streamlit (avoids HTML render issues) ────
    rl_short = rl.split(" - ")[0]
    st.markdown(f"""
    <div style="background:#0b1520;border:1px solid {rc}30;border-radius:12px;
                padding:6px 0 4px 0;margin-bottom:16px;
                border-top:2px solid {rc};">
    </div>""", unsafe_allow_html=True)

    sb1, sb2, sb3, sb4, sb5, sb6 = st.columns([1.2, 0.05, 2.5, 0.05, 1, 0.05])
    with sb1:
        st.markdown(f"""
        <div style="text-align:center;padding:16px 8px;">
            <div style="font-size:3.2rem;font-weight:800;color:{rc};
                        line-height:1;font-family:sans-serif;">{score}</div>
            <div style="font-size:0.58rem;color:{rc};opacity:0.6;letter-spacing:2px;
                        text-transform:uppercase;margin-top:4px;">RISK SCORE</div>
        </div>""", unsafe_allow_html=True)
    with sb2:
        st.markdown(f'<div style="height:80px;background:#1a2535;width:1px;margin:auto;"></div>',
                    unsafe_allow_html=True)
    with sb3:
        st.markdown(f"""
        <div style="padding:16px 12px;">
            <div style="font-size:1.15rem;font-weight:700;color:{rc};margin-bottom:6px;">{rl_short}</div>
            <div style="font-size:0.75rem;color:#3a5a72;margin-bottom:12px;">
                {fname} &nbsp;·&nbsp; {rmt.strftime("%d %b %Y at %H:%M")} &nbsp;·&nbsp; {dur}s
            </div>
        </div>""", unsafe_allow_html=True)
        sev_cols = st.columns(4)
        for col, s in zip(sev_cols, ["CRITICAL","HIGH","MEDIUM","LOW"]):
            cfg = SEV_CFG[s]
            col.markdown(f"""
            <div style="background:{cfg['bg']};border:1px solid {cfg['border']};
                        border-radius:7px;padding:8px 4px;text-align:center;">
                <div style="font-size:1.4rem;font-weight:800;color:{cfg['color']};">
                    {sev_b.get(s,0)}</div>
                <div style="font-size:0.6rem;color:{cfg['color']};opacity:0.7;">
                    {cfg['label']}</div>
            </div>""", unsafe_allow_html=True)
    with sb4:
        st.markdown(f'<div style="height:80px;background:#1a2535;width:1px;margin:auto;"></div>',
                    unsafe_allow_html=True)
    with sb5:
        st.markdown(f"""
        <div style="padding:16px 8px;">
            <div style="font-size:0.62rem;color:#2a4a5e;text-transform:uppercase;
                        letter-spacing:1px;margin-bottom:8px;">OWASP Coverage</div>
            <div style="font-size:2rem;font-weight:700;color:#00c8ff;line-height:1;">
                {owasp_tagged}<span style="font-size:1rem;color:#2a5a7a;">/{total}</span>
            </div>
            <div style="font-size:0.62rem;color:#2a4a5e;margin-top:4px;">findings tagged</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-bottom:8px;'></div>", unsafe_allow_html=True)

    # ── ACTION BAR ─────────────────────────────────────────────────────
    exp_col1, exp_col2, exp_col3, exp_col4 = st.columns([1,1,1,3])
    with exp_col1:
        export_path = selected.replace(".json", ".pdf")
        if st.button("📄 Export PDF"):
            try:
                import importlib.util
                pdf_script = os.path.join(PROJECT_ROOT, "export_pdf.py")
                spec = importlib.util.spec_from_file_location("export_pdf", pdf_script)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                mod.build_pdf(selected, export_path)
                st.success("PDF ready!")
            except Exception as e:
                st.error(f"PDF failed: {e}")
        if os.path.exists(export_path):
            with open(export_path, "rb") as pf:
                st.download_button("⬇ Download PDF", pf.read(),
                    file_name=f"sentinelai_{rmt.strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf")
    with exp_col2:
        with open(selected, "rb") as jf:
            st.download_button("⬇ Download JSON", jf.read(),
                file_name=f"sentinelai_{rmt.strftime('%Y%m%d_%H%M')}.json",
                mime="application/json")
    with exp_col3:
        patched = summary.get("patched_file_paths", [])
        for pp in patched:
            if os.path.exists(pp):
                with open(pp, "rb") as pf:
                    fname_p = os.path.basename(pp)
                    st.download_button(f"⬇ {fname_p}", pf.read(),
                        file_name=fname_p, mime="text/plain", key=f"dl_{fname_p}")

    st.markdown("<div style='margin:20px 0;'>", unsafe_allow_html=True)

    # ── TWO COLUMN LAYOUT: findings left, OWASP right ──────────────────
    col_main, col_side = st.columns([3, 1], gap="large")

    with col_side:
        # OWASP panel
        if owasp_counts:
            owasp_colors = {
                "A01": "#f87171", "A02": "#fb923c", "A03": "#f59e0b",
                "A04": "#a3e635", "A05": "#34d399", "A06": "#22d3ee",
                "A07": "#818cf8", "A08": "#e879f9", "A09": "#f472b6", "A10": "#94a3b8"
            }
            st.markdown("""
            <div style="background:#0f1822;border:1px solid #1a2535;border-radius:12px;padding:18px;margin-bottom:16px;">
                <div style="font-size:0.72rem;font-weight:600;color:#2a5a72;text-transform:uppercase;
                            letter-spacing:1.5px;margin-bottom:14px;">🛡️ OWASP Top 10 Breakdown</div>
            """, unsafe_allow_html=True)
            total_owasp = sum(owasp_counts.values())
            for cat, cnt in sorted(owasp_counts.items()):
                code = cat.split(":")[0] if ":" in cat else cat[:3]
                bar_w = int((cnt / max(total_owasp, 1)) * 100)
                color = owasp_colors.get(code.replace("A0","A0").replace("A","A"), "#4a7a9a")
                label = cat.split(" — ")[1] if " — " in cat else cat
                oid   = cat.split(" — ")[0] if " — " in cat else cat
                st.markdown(f"""
                <div style="margin-bottom:12px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <div>
                            <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                                         color:{color};font-weight:600;">{oid}</span>
                            <span style="font-size:0.65rem;color:#2a4a5e;margin-left:4px;">{label}</span>
                        </div>
                        <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                                     color:{color};font-weight:600;">{cnt}</span>
                    </div>
                    <div style="height:3px;background:#1a2535;border-radius:2px;overflow:hidden;">
                        <div style="height:100%;width:{bar_w}%;background:{color};border-radius:2px;
                                    transition:width 0.5s ease;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # Agent breakdown
        agent_counts = Counter(
            f.get("agent","").split(" - ")[0].strip()
            for f in findings
        )
        if agent_counts:
            agent_color_map = {
                "Agent A": "#00c8ff", "Agent B": "#a78bfa", "Agent C": "#34d399",
                "Agent D": "#94a3b8", "Agent E": "#fb923c", "Agent F": "#f472b6",
                "Agent G": "#60a5fa", "Agent H": "#fbbf24", "Agent I": "#4ade80",
            }
            st.markdown("""
            <div style="background:#0f1822;border:1px solid #1a2535;border-radius:12px;padding:18px;">
                <div style="font-size:0.72rem;font-weight:600;color:#2a5a72;text-transform:uppercase;
                            letter-spacing:1.5px;margin-bottom:14px;">🤖 Findings by Agent</div>
            """, unsafe_allow_html=True)
            for ag, cnt in sorted(agent_counts.items(), key=lambda x: -x[1]):
                color = agent_color_map.get(ag, "#4a7a9a")
                st.markdown(f"""
                <div style="display:flex;align-items:center;justify-content:space-between;
                            padding:6px 0;border-bottom:1px solid #0d1520;">
                    <div style="display:flex;align-items:center;gap:6px;">
                        <div style="width:5px;height:5px;border-radius:50%;background:{color};"></div>
                        <span style="font-size:0.72rem;color:#3a5a72;">{ag}</span>
                    </div>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                                 color:{color};font-weight:600;">{cnt}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    with col_main:
        # ── FILTER BAR ────────────────────────────────────────────────
        st.markdown("""
        <div style="font-family:'Syne',sans-serif;font-size:1.1rem;font-weight:700;
                    color:#5a8aaa;margin-bottom:14px;">Security Findings</div>
        """, unsafe_allow_html=True)

        fc1, fc2, fc3 = st.columns([2, 1, 1])
        with fc1:
            sev_opts = ["🚨 Critical", "🔴 High", "🟡 Medium", "🟢 Low"]
            sev_sel  = st.multiselect("Severity", sev_opts, default=sev_opts, label_visibility="collapsed")
            sev_map  = {"🚨 Critical":"CRITICAL","🔴 High":"HIGH","🟡 Medium":"MEDIUM","🟢 Low":"LOW"}
            sev_codes= [sev_map[s] for s in sev_sel if s in sev_map]
        with fc2:
            search = st.text_input("Search", placeholder="SQL, password…", label_visibility="collapsed")
        with fc3:
            sort_by = st.selectbox("Sort", ["Severity", "Line number", "Agent"], label_visibility="collapsed")

        filtered = [f for f in findings
                    if f.get("severity","") in sev_codes
                    and (not search or search.lower() in json.dumps(f).lower())]
        if sort_by == "Severity":
            sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            filtered.sort(key=lambda x: sev_order.get(x.get("severity","LOW"),4))
        elif sort_by == "Line number":
            filtered.sort(key=lambda x: x.get("lineno") or 0)
        else:
            filtered.sort(key=lambda x: x.get("agent",""))

        st.markdown(f"""
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#2a4a5e;
                    padding:6px 0 14px 0;">Showing {len(filtered)} of {total} findings</div>
        """, unsafe_allow_html=True)

        # ── FINDING CARDS ──────────────────────────────────────────────
        for i, f in enumerate(filtered):
            s       = f.get("severity","LOW")
            sc      = sev(s)
            title   = f.get("title","Unknown Issue")
            desc    = f.get("description","")
            rec     = f.get("recommendation","")
            snippet = f.get("code_snippet","")
            lineno  = f.get("lineno")
            fpath   = f.get("filepath","")
            cwe     = f.get("cwe_id","")
            agent   = f.get("agent","").split(" - ")[0].split(" [")[0].strip()
            owasp_id   = f.get("owasp_id","")
            owasp_name = f.get("owasp_name","")
            owasp_url  = f.get("owasp_url","https://owasp.org/Top10/")
            fix     = f.get("fix_suggestion")
            fname_f = fpath.replace("\\","/").split("/")[-1] if fpath else ""
            plain   = plain_english(title)

            expanded = i < 3 and s == "CRITICAL"

            with st.expander(
                f"{'🚨' if s=='CRITICAL' else '🔴' if s=='HIGH' else '🟡' if s=='MEDIUM' else '🟢'}  "
                f"**{title}**  —  `Line {lineno}`",
                expanded=expanded
            ):
                # Meta row
                meta_parts = []
                if fname_f: meta_parts.append(f"📄 {fname_f}")
                if lineno:  meta_parts.append(f"Line {lineno}")
                if cwe:     meta_parts.append(f"🔖 {cwe}")
                if agent:   meta_parts.append(f"🤖 {agent}")

                badges_html = ""
                if owasp_id and owasp_name:
                    badges_html += f'<a href="{owasp_url}" target="_blank" style="text-decoration:none;"><span style="display:inline-block;background:rgba(0,214,143,0.1);border:1px solid rgba(0,214,143,0.25);border-radius:5px;padding:2px 9px;font-size:0.65rem;color:#00d68f;font-weight:600;letter-spacing:0.5px;margin-right:6px;">🛡️ {owasp_id} — {owasp_name}</span></a>'

                sev_badge = f'<span style="display:inline-block;background:{sc["bg"]};border:1px solid {sc["border"]};border-radius:5px;padding:2px 9px;font-size:0.65rem;color:{sc["color"]};font-weight:700;letter-spacing:0.5px;margin-right:6px;">{s}</span>'

                st.markdown(f"""
                <div style="margin-bottom:12px;">
                    <div style="font-size:0.72rem;color:#2a4a5e;margin-bottom:6px;">
                        {"  ·  ".join(meta_parts)}
                    </div>
                    {sev_badge}{badges_html}
                </div>
                """, unsafe_allow_html=True)

                # What it means
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.02);border-left:3px solid {sc['color']};
                            border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:12px;">
                    <div style="font-size:0.65rem;font-weight:600;color:{sc['color']}80;
                                text-transform:uppercase;letter-spacing:1px;margin-bottom:5px;">
                        What this means
                    </div>
                    <div style="font-size:0.85rem;color:#a0b8c8;line-height:1.6;">{plain}</div>
                </div>
                """, unsafe_allow_html=True)

                # Code snippet
                if snippet:
                    st.markdown(f"""
                    <div style="margin-bottom:12px;">
                        <div style="font-size:0.65rem;color:#2a5a72;margin-bottom:5px;
                                    font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">
                            Vulnerable code
                        </div>
                        <div style="background:#050810;border:1px solid #1a2535;border-radius:8px;
                                    padding:12px 14px;font-family:'JetBrains Mono',monospace;
                                    font-size:0.75rem;color:#e07a5f;white-space:pre-wrap;
                                    word-break:break-all;line-height:1.6;">
{_html.escape(snippet[:350])}</div>
                    </div>
                    """, unsafe_allow_html=True)

                # Auto-fix
                if fix and fix.get("after"):
                    fix_type  = fix.get("type","rule")
                    fix_label = "AI-Generated Fix (Ollama)" if fix_type == "ollama" else "Rule-Based Fix"
                    fix_color = "#a78bfa" if fix_type == "ollama" else "#60a5fa"
                    st.markdown(f"""
                    <div style="background:rgba(0,214,143,0.04);border:1px solid rgba(0,214,143,0.15);
                                border-radius:8px;padding:14px 16px;margin-bottom:12px;">
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
                            <span style="font-size:0.65rem;font-weight:600;color:#00d68f;
                                         text-transform:uppercase;letter-spacing:1px;">⚡ {fix_label}</span>
                        </div>
                        <div style="background:#050810;border:1px solid #1a3525;border-radius:8px;
                                    padding:12px 14px;font-family:'JetBrains Mono',monospace;
                                    font-size:0.75rem;color:#4ade80;white-space:pre-wrap;
                                    word-break:break-all;line-height:1.6;margin-bottom:8px;">
{_html.escape(str(fix.get("after",""))[:450])}</div>
                        {f'<div style="font-size:0.75rem;color:#2a6a4a;line-height:1.5;">{_html.escape(str(fix.get("explanation",""))[:250])}</div>' if fix.get("explanation") else ""}
                    </div>
                    """, unsafe_allow_html=True)
                elif rec:
                    st.markdown(f"""
                    <div style="background:rgba(0,200,255,0.04);border-left:3px solid rgba(0,200,255,0.3);
                                border-radius:0 8px 8px 0;padding:12px 16px;">
                        <div style="font-size:0.65rem;font-weight:600;color:#2a7a9a;
                                    text-transform:uppercase;letter-spacing:1px;margin-bottom:5px;">
                            How to fix it
                        </div>
                        <div style="font-size:0.8rem;color:#3a8aaa;line-height:1.6;">{rec}</div>
                    </div>
                    """, unsafe_allow_html=True)

