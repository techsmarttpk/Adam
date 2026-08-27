# ADAM: Automated Dynamic Deception & Malware Analysis Platform

ADAM is an automated malware detonation and dynamic deception analysis system designed to elicit deeper adversary behavior through reactive environment mutation, MITRE ATT&CK® telemetry fusion, and automated IOC extraction.

---

## 🏗️ Architectural Overview

- **`adam/fusion/`**: Multi-source telemetry event correlation, process trees, and MITRE ATT&CK intent detection.
- **`adam/policy/`**: YAML-driven rule engine, condition evaluator, budget/cooldown enforcement, and execution verdicts.
- **`adam/deception/`**: Dynamic deception primitives (process lures, registry lures, filesystem lures, credential lures, network lures).
- **`adam/sandbox/`**: VirtualBox VM lifecycle controller, snapshot rollback, and in-guest HTTP agent communication.
- **`adam/collectors/`**: Sysmon EVTX, Procmon CSV, and PCAP/EK telemetry stream ingestion.
- **`adam/pipeline/`**: Async event bus wiring and live orchestration pipeline.
- **`adam/reporting/`**: Forensic report generation (HTML, Markdown, JSON) and statistical yield aggregation.
- **`adam/api/`**: FastAPI REST API and Server-Sent Events (SSE) live streaming endpoints.
- **`adam/cli/`**: Typer-powered CLI suite (`run`, `replay`, `benchmark`).
- **`frontend/`**: Streamlit SOC & Threat Intelligence analyst dashboard.

---

## 🚀 Getting Started

### 1. Environment Setup
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-frontend.txt
```

### 2. Running Automated Tests
```powershell
pytest
```

### 3. Launching the Threat Intelligence Dashboard
```powershell
streamlit run frontend/app.py
```

### 4. Running the API Server
```powershell
uvicorn adam.api.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Using the CLI
```powershell
python -m adam.cli.main --help
```


