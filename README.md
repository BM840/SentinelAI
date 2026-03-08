# 🛡️ SentinelAI — Multi-Agent AI Security Auditor

> Automatically scan Python web applications for vulnerabilities using 9 specialized agents — powered by a local LLM (Ollama/phi3) running fully offline on GPU.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Ollama](https://img.shields.io/badge/Ollama-phi3-green?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=flat-square)
![Agents](https://img.shields.io/badge/Agents-9-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**▶ [Watch Demo Video](https://youtu.be/W8bhxYdgS4A)**

---

## What is SentinelAI?

SentinelAI is a security auditing tool that scans Python web applications for vulnerabilities. It runs a pipeline of 9 specialized agents and produces a detailed report with findings, OWASP tags, risk grades, and auto-generated fixes.

Unlike traditional static analysis tools, SentinelAI uses a **local LLM (phi3 on Ollama)** to semantically understand authentication logic and generate context-aware fixes — the same way a human security engineer would review code.

**No API keys. No cloud. Your code never leaves your machine.**

---

## ✨ Key Features

- **9-Agent Pipeline** — each agent specialises in a different vulnerability category
- **Local LLM** — phi3 via Ollama for semantic auth analysis and auto-fix generation
- **100% OWASP Top 10 Coverage** — every finding tagged to OWASP 2021 + CWE ID
- **AI Code Generator** — describe code → AI writes it → SentinelAI scans → auto-fixes critical issues
- **Risk Grade A-F** — human-readable security score with percentage
- **Colored Diff View** — see exactly which lines changed to fix vulnerabilities
- **Shannon Entropy Detection** — catches secrets that bypass pattern matching
- **AST-Validated Fixes** — patches verified as valid Python before saving
- **CI/CD Integration** — `--ci-mode` for GitHub Actions / GitLab CI
- **PDF + JSON Export** — professional security report

---

## 🤖 The 9 Agents

| Agent | Name | Method | What it finds |
|---|---|---|---|
| A | Pattern Detector | Regex + AST + Entropy | Hardcoded secrets, SQL injection, eval(), debug flags |
| B | Auth Logic Auditor | **LLM (phi3)** | Auth bypass, broken session logic, logic bugs |
| C | Data Flow Analyzer | AST taint tracking | User input flowing into dangerous sinks |
| D | Risk Scorer | Weighted formula | Deduplication + risk score calculation |
| E | Dependency Scanner | OSV.dev API | CVE lookup on all requirements.txt dependencies |
| F | Git History Scanner | git log -G | Secrets deleted from code but still in git history |
| G | CORS & Headers | HTTP header analysis | Wildcard CORS, missing security headers |
| H | Cryptography Auditor | Pattern matching | MD5/SHA1 passwords, disabled SSL, weak algorithms |
| I | Auto-Fix Engine | **LLM (phi3)** | Generates and AST-validates code fixes |

---

## 🔄 AI Code Generator

```
1. You describe the code you need
          ↓
2. phi3 generates complete Python code
          ↓
3. All 9 agents scan it for vulnerabilities
          ↓
4. Critical issues found? phi3 rewrites with fixes, then scans again
          ↓
5. Download production-ready secure code
```

**Real result:** Flask login system → Risk Grade **F (18%)** → after 2 fix loops → **A- (91%)**

---

## 📊 Sample Results

Scanning a vulnerable Flask banking API:

```
Risk Grade:  F (18%)
Risk Score:  242/500
Findings:    41 total — 10 CRITICAL, 19 HIGH, 8 MEDIUM, 4 LOW

OWASP Coverage:
  A01 Broken Access Control       2
  A02 Cryptographic Failures      4
  A03 Injection                   7
  A04 Insecure Design             6
  A05 Security Misconfiguration   4
  A06 Vulnerable Components      12
  A07 Auth & Identity Failures    4
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.ai) with phi3 model
- NVIDIA GPU recommended (runs on CPU too, slower)

### 1. Clone and install
```bash
git clone https://github.com/BM840/SentinelAI.git
cd SentinelAI
pip install -r requirements.txt
```

### 2. Start Ollama
```bash
ollama pull phi3
ollama serve
```

### 3. Run a scan
```bash
python main.py /path/to/your/project
```

### 4. Launch dashboard
```bash
streamlit run dashboard.py
```

Open http://localhost:8501

---

## 🖥️ CLI Usage

```bash
# Basic scan
python main.py /path/to/project

# Fast scan (skip LLM agents)
python main.py /path/to/project --no-llm

# CI/CD mode
python main.py /path/to/project --ci-mode --fail-on critical

# Differential scan — only files changed since last commit
python main.py /path/to/project --ci-mode --diff HEAD~1
```

### GitHub Actions
```yaml
- name: SentinelAI Security Scan
  run: |
    pip install -r requirements.txt
    python main.py . --ci-mode --fail-on high
```

---

## 📁 Project Structure

```
SentinelAI/
├── main.py                           # CLI + CI/CD flags
├── dashboard.py                      # Streamlit dashboard
├── requirements.txt
├── core/
│   ├── ingestion.py                  # AST parser
│   ├── models.py                     # Finding dataclass + Confidence enum
│   ├── orchestrator.py               # Agent pipeline
│   └── owasp.py                      # CWE-to-OWASP mapping (200+ entries)
├── agents/
│   ├── agent_a_pattern_detector.py
│   ├── agent_b_auth_auditor.py       # LLM
│   ├── agent_c_dataflow.py
│   ├── agent_d_risk_scorer.py
│   ├── agent_e_dependency_scanner.py # OSV API + caching
│   ├── agent_f_git_history.py        # git log -G
│   ├── agent_g_cors_headers.py
│   ├── agent_h_cryptography.py
│   └── agent_i_autofix.py            # LLM + AST validation
└── demo_app/                         # Intentionally vulnerable Flask app
```

---

## 🔧 Architecture Decisions

**Why local LLM?**
Security tools process sensitive source code. Sending code to a third-party API is itself a security risk. phi3 on Ollama runs entirely offline.

**Why only 2 LLM agents out of 9?**
LLM inference is slow on a 4GB GPU. Deterministic analysis is faster and more accurate for pattern-based detection. LLM is used only where semantic understanding genuinely adds value: auth logic and fix generation.

**Why deterministic CWE-to-OWASP mapping?**
Keyword matching fails when the LLM rephrases descriptions. A 200+ entry CWE lookup table gives 100% deterministic OWASP tagging regardless of wording.

---

## 🎯 Resume Bullet Points

> - Built a 9-module automated security pipeline detecting SQL injection, hardcoded secrets, CVEs, and auth bypass across Python web apps
> - Integrated local LLM (phi3/Ollama) for semantic code analysis and auto-fix generation — runs fully offline on GPU
> - Achieved 100% OWASP Top 10 coverage via deterministic CWE mapping; Risk Grade A-F scoring system
> - Built AI Code Generator: describe → generate → scan → auto-fix loop reducing risk from F to A- in 2 iterations
> - Optimised LLM scan from 351s to 95s (3.7x speedup); added CI/CD integration for GitHub Actions

---

## 👤 Author

**Bharat Maheshwari** — 4th Year CSE, Bennett University
- GitHub: [BM840](https://github.com/BM840)
- LinkedIn: [Bharat Maheshwari](https://linkedin.com/in/bharat-maheshwari)

---

## 📄 License

MIT License
