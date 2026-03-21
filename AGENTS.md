# SecurePipe — Codex Agent Context

## Project
Open-source AI-augmented security testing platform. Accepts GitHub repos, live
URLs, MCP server endpoints, ZIPs, and package names. Runs
SAST + DAST + VAPT + SCA + Secrets + MCP scanning. Returns unified risk score
0-100.

## Stack
- Backend: Python 3.11, FastAPI, uvicorn, pydantic v2, aiosqlite
- Scanners: Semgrep, Bandit, Gitleaks, OWASP ZAP, Nuclei, Trivy
- AI: Groq (Llama 3.3, Mixtral), NVIDIA Build (DeepSeek R1, DeepSeek Coder),
  OpenRouter (Mistral), Google AI Studio (Gemma 3)
- All scanner output normalises to `ScanFinding` in `schemas/finding.py`
- Scanners run in Docker containers via asyncio subprocess
- MCP exposure via fastmcp library

## Repository layout
```
main.py                         FastAPI app entry point
schemas/
  finding.py                    ScanFinding model + SeverityLevel enum
  scan.py                       ScanRequest / ScanResult / InputType
services/
  base_scanner.py               Abstract BaseScanner
  input_router.py               detect_input_type()
  scanners/
    semgrep_scanner.py          Semgrep SAST
    bandit_scanner.py           Bandit Python SAST
    gitleaks_scanner.py         Gitleaks secrets scanner
db/
  database.py                   Async SQLite helpers (aiosqlite)
routers/
  scan.py                       POST /scan, GET /scan/{scan_id}
  report.py                     GET /report/{scan_id}
```

## Rules
- All async, type hints everywhere, no bare excepts
- Scanners inherit `BaseScanner` from `services/base_scanner.py`
- Never hardcode keys — `os.getenv()` only
- Docstrings on all public methods
- `ScanFinding` is the only output format — every scanner maps to it
