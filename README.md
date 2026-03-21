# SecurePipe

> Open-source AI-augmented security testing platform — SAST · DAST · VAPT · Secrets · MCP security scanner · LLM prompt-injection detector · zero cost

## Features

- **Multi-target ingestion** — GitHub repos, live URLs, MCP server endpoints, ZIP uploads, package names, and raw AI-generated code
- **Unified scanner pipeline** — Semgrep, Bandit, Gitleaks, OWASP ZAP, Nuclei, Trivy (phase 2)
- **MCP security scanner** — dedicated checks for Model Context Protocol server endpoints
- **LLM-based prompt injection detector** — Groq, NVIDIA Build, OpenRouter, Google AI Studio
- **Normalised findings** — every scanner maps output to the same `ScanFinding` schema
- **Risk score 0-100** — weighted aggregation across all findings
- **Async-first** — FastAPI + aiosqlite, all I/O non-blocking

## Architecture

```
Client ──► POST /scan ──► detect_input_type()
                       ──► background asyncio task
                              ├─ BanditScanner
                              ├─ GitleaksScanner
                              └─ SemgrepScanner  (+ ZAP / Nuclei / Trivy in phase 2)
                       ──► save_findings() ──► SQLite
Client ──► GET /scan/{id}   ──► ScanResult
Client ──► GET /report/{id} ──► structured report sorted by severity
```

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/5h1Vm/Secure-Pipe.git
cd Secure-Pipe
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env and add your API keys

# 3. Run
uvicorn main:app --reload

# 4. Submit a scan
curl -X POST http://localhost:8000/scan \
     -H "Content-Type: application/json" \
     -d '{"input_str": "https://github.com/owner/repo"}'
```

Or with Docker Compose:

```bash
docker compose up --build
```

## Adding to GitHub Actions

```yaml
- name: SecurePipe scan
  run: |
    curl -X POST ${{ secrets.SECUREPIPE_URL }}/scan \
         -H "Content-Type: application/json" \
         -d "{\"input_str\": \"${{ github.repositoryUrl }}\"}"
```

## Research Contributions

SecurePipe is designed as an open research platform. Contributions welcome:

- New scanner adapters (inherit `BaseScanner`)
- LLM-based false-positive reduction models
- MCP attack-surface analysis techniques
- Prompt injection detection benchmarks

See [AGENTS.md](AGENTS.md) for coding conventions.

## License

[MIT](LICENSE)


# SecurePipe 🔒

> **Scan before you run.** The security scanner built for the AI-agent era.

[![Tests](https://img.shields.io/badge/tests-23%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue)]()
[![Docker](https://img.shields.io/badge/docker-ready-blue)]()

Before you clone that repo. Before you install that AI-recommended package.  
Before you connect your AI agent to that MCP server — **run SecurePipe**.

## What it scans

| Input | What runs |
|-------|-----------|
| `github.com/owner/repo` | SAST (Semgrep + Bandit) + Secrets (Gitleaks) + Supply chain |
| `https://your-app.com` | DAST (ZAP) + VAPT (Nuclei) |
| `http://your-mcp-server/mcp` | OWASP MCP Top 10 + Prompt injection detection |
| `package-name` | Slopsquat + typosquat + abandoned package detection |

## Why SecurePipe exists

AI coding assistants generate code with vulnerabilities. AI agents connect 
to MCP servers that may be malicious. Developers install packages that AI 
hallucinated. SecurePipe is the security layer that should exist between 
"AI recommended this" and "I ran it".

## 60-second quickstart
```bash
docker compose up -d

# Scan a repo before cloning it
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input_str": "https://github.com/owner/suspicious-repo"}'

# Scan an MCP server before connecting your AI agent
curl -X POST http://localhost:8000/scan \
  -d '{"input_str": "http://some-mcp-server.com/mcp"}'
```

## Research contributions

SecurePipe implements three original security research contributions:

**1. First open-source OWASP MCP Top 10 scanner**  
OWASP published the MCP vulnerability spec in 2025. No automated scanner 
existed. SecurePipe is the first.

**2. LLM-vs-LLM adversarial prompt injection detector**  
An attacker LLM generates injection variants. A detector LLM scores 
susceptibility. No pattern matching — dynamic adversarial generation.

**3. Multi-model AI consensus triage**  
Multiple free LLMs vote on each finding's severity. Reduces false positives 
below any single model. Self-improving weights.