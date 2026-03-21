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
