# ADAM

Adaptive Deception Sandbox for Advanced Malware Analysis.

ADAM is a single-host malware analysis platform. The host runs the Python
orchestrator, event bus, policy engine, deception engine, persistence layer,
API, dashboard, and reporting. The Windows guest runs inside QEMU and is treated
as hostile.

## Current Scope

- QEMU-backed Windows guest lifecycle through `adam/sandbox/`.
- Host-only or simulated networking by default.
- Telemetry contracts for raw events, semantic events, policy decisions,
  mutations, and analysis sessions.
- Replayable Fusion -> Policy -> Deception pipeline.
- SQLite metadata with JSON reports under `artifacts/`.

## Developer Ownership

- Dev A: `adam/common/`, `adam/sandbox/`, `adam/collectors/`,
  `adam/orchestrator/`, `config/`, and scripts.
- Dev B: `adam/fusion/`, semantic detectors, normalisation, and correlation.
- Dev C: `adam/policy/`, `rules/`, and `adam/deception/`.
- Dev D: `adam/db/`, `adam/api/`, `adam/dashboard/`, and `adam/reporting/`.

## Run Checks

```powershell
python -m pytest
```

Real malware samples belong in `samples/`, which is gitignored. The API will not
create fake sample binaries; a requested sample must already exist.

## QEMU Guest Work

The remaining manual Windows guest setup is intentionally separate from the host
code. Configure the guest agent, Sysmon, ProcMon, packet capture, firewall rules,
and rollback snapshot only inside the disposable QEMU image.
