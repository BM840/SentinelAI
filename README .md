# 🛡️ SentinelAI — Multi-Agent AI Security Auditor

> Automatically scan Python web applications for security vulnerabilities using a pipeline of 9 specialized AI agents — powered by a local LLM (Ollama/phi3) running on GPU.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Ollama](https://img.shields.io/badge/Ollama-phi3-green?style=flat-square)
![Agents](https://img.shields.io/badge/Agents-9-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## What is SentinelAI?

SentinelAI is an AI-powered security auditing tool that scans Python web applications (Flask, Django) for vulnerabilities. It runs a pipeline of 9 specialized agents — each responsible for a different category of security analysis — and produces a detailed report with findings, risk scores, and **auto-generated fixes**.

Unlike traditional static analysis tools that only match patterns, SentinelAI uses a **local LLM (phi3 on Ollama)** to semantically understand authentication logic and generate context-aware fixes — the same way a human security engineer would review code.

---

## Demo — Scanning a Flask Banking API

```
============================================================
  SentinelAI - Multi-Agent Security Auditor
============================================================
[Agent A] Pattern Detector        →   8 findings
[Agent B] Auth Logic (LLM)        →   5 findings   ← LLM catches what patterns miss
[Agent C] Data Flow Analyzer      →   1 finding
[Agent E] Dependency Scanner      →  13 findings
[Agent F] Git History Scanner     →   4 findings
[Agent G] CORS & Headers          →   6 findings
[Agent H] Cryptography Detector   →   3 findings
[Agent I] Auto-Fix Engine         →  38 fixes generated

  Total Issues  :  39
  Risk Score    :  257  (CRITICAL)
  Duration      :  ~107s  (GPU-accelerated)
  Patched File  :  output/patched/FIXED_app.py  ← ready to review
```

**Example findings on real-looking code:**

| Severity | Finding | Agent |
|----------|---------|-------|
| 🚨 CRITICAL | SQL Injection via string formatting in login | Agent B (LLM) |
| 🚨 CRITICAL | Hardcoded Stripe live key `sk_live_...` | Agent A |
| 🚨 CRITICAL | `eval()` on user input in budget calculator | Agent A |
| 🔴 HIGH | MD5 used for password hashing | Agent H |
| 🔴 HIGH | `verify=False` disables SSL cert checking | Agent A |
| 🔴 HIGH | Insecure `random` used for password reset tokens | Agent H |
| 🔴 HIGH | Webhook accepts payments without signature verification | Agent B (LLM) |
| 🟡 MEDIUM | 6 missing browser security headers (CSP, HSTS, X-Frame-Options) | Agent G |

---

## Architecture

A sequential multi-agent pipeline where each agent specializes in one security domain:

```
  Your Code
      │
      ▼
 ┌──────────┐
 │ Ingestion │  Parses Python files, extracts functions, routes, imports
 └────┬─────┘
      │
      ├──▶ Agent A  Pattern Detector      regex + AST secret/vuln detection
      ├──▶ Agent B  Auth Logic Auditor    LLM semantic analysis (phi3/Ollama)
      ├──▶ Agent C  Data Flow Analyzer    tracks tainted user input to sinks
      ├──▶ Agent E  Dependency Scanner    CVE lookup via OSV.dev API
      ├──▶ Agent F  Git History Scanner   finds secrets in commit history
      ├──▶ Agent G  CORS & Headers        security header configuration audit
      ├──▶ Agent H  Cryptography          weak hashes, ciphers, RNG, SSL
      ├──▶ Agent D  Risk Scorer           weighted risk score (0–500)
      └──▶ Agent I  Auto-Fix Engine       generates fixes via Ollama
              │
              ▼
     JSON report  +  Markdown  +  PDF  +  FIXED_app.py
```

**What makes Agent B different:** Instead of matching patterns, it sends your actual authentication functions to a local LLM and asks "what could go wrong here?" — catching logic flaws like always-true conditions, missing auth checks, and broken access control that regex can never find.

---

## Features

- **9 specialized agents** — secrets, auth logic, data flow, dependencies, git history, CORS, cryptography, risk scoring, auto-fix
- **Local LLM** — phi3 on Ollama, no API key, runs fully offline, your code never leaves your machine
- **GPU accelerated** — CUDA inference on NVIDIA GPU (GTX 1650 / 4GB VRAM tested)
- **Auto-fix engine** — Agent I generates a corrected code snippet for every finding and saves a patched copy of your file
- **Streamlit dashboard** — file upload, plain-English explanations, scan history, dark theme
- **PDF export** — one-click professional security report with all findings
- **CLI** — scan any directory or file from the terminal

---

## Quickstart

**Requirements:** Python 3.10+, [Ollama](https://ollama.ai), NVIDIA GPU (optional but recommended)

```bash
# 1. Clone
git clone https://github.com/yourusername/sentinelai.git
cd sentinelai

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Pull the LLM
ollama pull phi3

# 4. Scan the included demo app
python main.py demo_app/

# 5. Or launch the dashboard
streamlit run dashboard.py
```

---

## Usage

### CLI
```bash
python main.py my_flask_app/          # scan a directory
python main.py app.py                 # scan a single file
python main.py my_flask_app/ --no-llm # skip LLM (faster, no Ollama needed)
```

### Dashboard
```bash
streamlit run dashboard.py
```
Upload a `.py` file, click **Launch Scan**, view findings, export PDF, download the auto-fixed file.

### Export PDF
```bash
python export_pdf.py output/sentinel_report.json
```

---

## Agent Reference

| Agent | Method | Detects |
|-------|--------|---------|
| **A** — Pattern Detector | Regex + AST | Hardcoded secrets, API keys, `eval()`, SQL injection, debug mode |
| **B** — Auth Logic Auditor | LLM (phi3) | Login bypass, privilege escalation, missing auth, broken access control |
| **C** — Data Flow Analyzer | Static analysis | Unsanitized user input reaching dangerous functions |
| **D** — Risk Scorer | Weighted scoring | Overall risk score 0–500, severity breakdown |
| **E** — Dependency Scanner | OSV.dev API | Known CVEs in installed packages |
| **F** — Git History Scanner | Git log analysis | Secrets committed then deleted from history |
| **G** — CORS & Headers | Config audit | Wildcard CORS, missing CSP/HSTS/X-Frame headers, insecure cookies |
| **H** — Cryptography | Pattern + AST | MD5/SHA1, ECB mode, insecure RNG, disabled SSL verification |
| **I** — Auto-Fix Engine | LLM (phi3) | Generates fixed code for every finding, saves patched file |

---

## Project Structure

```
sentinelai/
├── main.py                 # CLI entry point
├── dashboard.py            # Streamlit dashboard
├── export_pdf.py           # PDF report generator
├── requirements.txt
│
├── core/
│   ├── ingestion.py        # AST-based code parser
│   ├── models.py           # Finding, Severity models
│   └── orchestrator.py     # Agent pipeline coordinator
│
├── agents/
│   ├── agent_a_pattern_detector.py
│   ├── agent_b_auth_auditor.py      ← LLM-powered
│   ├── agent_c_dataflow.py
│   ├── agent_d_risk_scorer.py
│   ├── agent_e_dependency_scanner.py
│   ├── agent_f_git_history.py
│   ├── agent_g_cors_headers.py
│   ├── agent_h_cryptography.py
│   └── agent_i_autofix.py           ← LLM-powered
│
├── demo_app/               # Realistic intentionally-vulnerable Flask app
│   ├── app.py              # SecureBank banking API
│   └── requirements.txt
│
└── output/                 # Scan results (auto-created)
    ├── sentinel_report.json
    ├── sentinel_report.md
    ├── sentinel_report.pdf
    ├── fix_suggestions.json
    └── patched/
        └── FIXED_app.py
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| LLM Engine | Ollama + phi3 (local, GPU-accelerated) |
| Dashboard | Streamlit |
| PDF Reports | ReportLab |
| CVE Data | OSV.dev API |
| Code Analysis | Python `ast` module |
| Git Analysis | subprocess + git CLI |

---

## Why Local LLM?

Most AI security tools send your code to a cloud API. SentinelAI runs entirely on your machine:

- **Private** — your source code never leaves your computer
- **Free** — no API costs after setup
- **Fast** — GPU inference with NVIDIA CUDA
- **Offline** — works without internet (except CVE lookups)

---

## Roadmap

- [ ] OWASP Top 10 mapping on all findings
- [ ] Django and FastAPI support
- [ ] GitHub Actions CI/CD integration
- [ ] Docker container
- [ ] Web deployment

---

*Built to demonstrate multi-agent AI architecture applied to real-world security engineering.*
