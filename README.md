# SecurePipe 🔒

> **Scan before you run.** The security scanner built for the AI-agent era.

[![Tests](https://img.shields.io/badge/tests-25%20passing-brightgreen)]()
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

AI coding assistants generate code riddled with security vulnerabilities that
developers unknowingly deploy to production. AI agents connect to MCP servers
that may be malicious, exfiltrate data, or manipulate agent behaviour.
SecurePipe is the security layer that must exist between "AI recommended this"
and "I ran it in production".

## 60-second quickstart

```bash
# Start with Docker Compose
docker compose up -d

# Scan a GitHub repo before cloning it
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input_str": "https://github.com/owner/suspicious-repo"}'

# Scan an MCP server before connecting your AI agent
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"input_str": "http://some-mcp-server.com/mcp"}'

# Open the web dashboard
open http://localhost:8000
```

## Adding to GitHub Actions

```yaml
- name: SecurePipe scan
  run: |
    curl -s -X POST ${{ secrets.SECUREPIPE_URL }}/scan \
      -H "Content-Type: application/json" \
      -d "{\"input_str\": \"${{ github.repositoryUrl }}\"}"
```

## Research contributions

SecurePipe implements three original security research contributions:

1. **First open-source OWASP MCP Top 10 scanner** — automated detection of
   all ten vulnerability classes defined in the 2025 OWASP MCP spec; no other
   open-source tool existed at the time of writing.

2. **LLM-vs-LLM adversarial prompt injection detector** — an attacker LLM
   dynamically generates injection variants while a detector LLM scores
   susceptibility, replacing brittle pattern-matching with adversarial
   generation.

3. **Multi-model AI consensus triage** — multiple free LLMs vote on each
   finding's severity and false-positive probability, with self-improving
   weights, reducing false positives below any single-model baseline.

## License

[MIT](LICENSE)
