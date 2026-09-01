# ADAM — Complete Project Context for AI Assistant

> **Purpose of this document**: Paste this entire document into ChatGPT (or any other LLM) to give it full architectural, contractual, and implementation-level knowledge of the ADAM project. After reading this, the AI should be able to answer questions about any module, debug code, suggest extensions, and understand all design decisions.

---

## 1. What ADAM Is

**ADAM** = **Adaptive Deception Sandbox for Advanced Malware Analysis**.

It is a single-host malware analysis platform where a Python 3.11 orchestrator process on the host manages a disposable QEMU Windows 10 x64 guest VM. ADAM observes malware behavior in real time, infers the malware's *intent* from correlated low-level telemetry, and **synthesizes the environment the malware is searching for — while it is still running**. This forces malware down code branches that a passive sandbox would never observe.

### The Core Research Claim

Traditional sandboxes (Cuckoo, CAPE, Any.Run, Joe Sandbox) are **open-loop**: they detonate passively and report what happened. If the malware checks for a domain controller, a crypto wallet, or a specific AV product and doesn't find it, the interesting branch never executes. ADAM **closes the loop** with three linked mechanisms:

1. **Event Fusion**: Noisy raw telemetry from Sysmon, ProcMon, Wireshark → correlated `SemanticEvent`s describing *intent* (e.g., `RECON_DOMAIN_CONTROLLER`).
2. **Policy Engine**: Declarative YAML rules + Python predicates that map semantic intents to deception responses, gated by confidence thresholds, per-session budgets, and cooldowns.
3. **Adaptive Deception**: Targeted, in-flight mutation of the live guest environment (fake DC artifacts, decoy documents, AV spoofing, etc.) and measurement of the **behavioral yield** delta.

### The Key Metric: Behavioral Yield

The publishable metric is **additional distinct semantic events, API calls, network endpoints, and code paths observed *after* a mutation, compared to a control run with deception disabled.** Every session carries a `deception_enabled` flag, and sessions are run in A/B pairs under a shared `experiment_id` with `arm` = `CONTROL` or `TREATMENT`.

---

## 2. Technology Stack & Constraints

| Aspect | Choice |
|---|---|
| Language | Python 3.11 (host orchestrator), PowerShell 5.1 (guest agent) |
| Framework | FastAPI + Uvicorn (async HTTP + SSE) |
| Database | SQLite with WAL mode, single writer task |
| Templating | Jinja2 (dashboard, reports) |
| Config | Pydantic Settings, TOML files, env vars |
| Logging | structlog (JSON to file, colored to console) |
| Data models | Pydantic v2 (frozen contracts in `adam/contracts/`) |
| Hypervisor | QEMU (commodity dependency, not a contribution) |
| Acceleration | WHPX on Windows, KVM on Linux |
| Telemetry | Sysmon ETW, ProcMon PML→CSV, Wireshark/tshark pcap |
| CLI | Typer + Rich |
| Testing | pytest, pytest-asyncio, hypothesis |
| Linting | ruff, mypy, import-linter |

### Hard Constraints

- **C1**: Single orchestrator process. No broker, no microservices.
- **C2**: SQLite with WAL. One writer task; all other components enqueue.
- **C3**: Python 3.11 minimum.
- **C4**: Guest agent is PowerShell 5.1 compatible.
- **C5**: No component may block the asyncio event loop for >10ms.

---

## 3. Architecture Layers

```
┌──────────────────────────────────────────────────────┐
│ L5: PRESENTATION — Dashboard (Jinja2) · REST API     │
├──────────────────────────────────────────────────────┤
│ L4: ANALYSIS — Report Generator · Session Orchestrator│
├──────────────────────────────────────────────────────┤
│ L3: RESEARCH CORE — Fusion → Policy → Deception      │
│     ★ contribution (closed adaptive loop lives here) │
├──────────────────────────────────────────────────────┤
│ L2: ACQUISITION — Collectors · Sandbox · Mutators     │
├──────────────────────────────────────────────────────┤
│ L1: FOUNDATION — Contracts · Event Bus · Config · DB  │
└──────────────────────────────────────────────────────┘

Dependency direction: strictly downward. L1 imports nothing from L2–L5.
```

### Runtime Topology

```
HOST (trusted)                          GUEST VM (hostile)
┌──────────────────────────┐         ┌──────────────────┐
│ ADAM Orchestrator Process │         │ Windows 10 x64   │
│ (Python 3.11)            │         │                  │
│                          │         │ adam_agent.ps1   │
│ FastAPI (uvicorn, async) │◀──HTTP──│  telemetry push  │
│  /api/* /dashboard/*     │ host    │  command poll    │
│                          │ only    │                  │
│ IN-PROCESS EVENT BUS     │         │ Sysmon (ETW)     │
│ (asyncio pub/sub)        │         │ ProcMon (PML)    │
│                          │         │ Wireshark/dumpcap│
│ Fusion·Policy·Deception  │         │                  │
│ DB Writer·Report Gen     │         │ SAMPLE (detonated│
│                          │  QEMU   │                  │
│ Sandbox Controller ──────┼────────▶│ snapshot·exec·mut│
│                          │         └──────────────────┘
│ SQLite · artifacts/ · logs/         
└──────────────────────────┘
```

### The Closed Adaptive Loop

```
Collector → [RawEvent] → Fusion → [SemanticEvent] → Policy → [PolicyDecision] → Deception
    ▲                                                                                │
    │                                                              [MutationResult] ◀┘
    │                                                                     │
    └──── malware reacts to environment change ◀──────── GUEST VM ◀──────┘
```

**Critical detail**: The Deception Engine publishes `MutationResult` back onto the bus as a first-class event. Without this, Fusion cannot distinguish malware-caused vs. ADAM-caused state changes, and behavioral yield is unmeasurable.

---

## 4. Frozen Data Contracts (`adam/contracts/`)

All data crossing module boundaries uses these Pydantic v2 models. Changes require all-hands review.

### 4.1 Enums (`adam/contracts/enums.py`)

```python
class SessionStatus(str, Enum):    PENDING, READY, RUNNING, COMPLETED, FAILED, PARTIAL
class EventSource(str, Enum):      SYSMON, PROCMON, WIRESHARK, AGENT, ADAM, VMI, AMTD
class EventCategory(str, Enum):    PROCESS, FILE, REGISTRY, NETWORK, MODULE, WMI, MUTATION, SYSTEM, VMI_TRAP, AMTD_MUTATION
class PolicyVerdict(str, Enum):    EXECUTE, SUPPRESSED_BUDGET, SUPPRESSED_COOLDOWN, SUPPRESSED_CONFIDENCE, SUPPRESSED_CONFLICT, DRY_RUN
class MutationStatus(str, Enum):   APPLIED, PARTIAL, FAILED, REVERTED, SKIPPED
class DeceptionArm(str, Enum):     CONTROL, TREATMENT
class NetworkMode(str, Enum):      HOST_ONLY, SIMULATED, INTERNET
```

### 4.2 `RawEvent` (`adam/contracts/raw_event.py`)

```python
class ProcessContext(BaseModel):
    pid: int
    ppid: Optional[int] = None
    image: Optional[str] = None
    command_line: Optional[str] = None
    integrity_level: Optional[str] = None
    user: Optional[str] = None
    guid: Optional[str] = None

class RawEvent(BaseModel):
    event_id: str
    session_id: str
    source: EventSource
    source_event_id: Optional[int] = None
    category: EventCategory
    occurred_at: datetime           # source clock, guest-time corrected. ORDERING KEY.
    observed_at: datetime           # host clock at ingest. Latency measurement only.
    process: Optional[ProcessContext] = None
    attributes: dict[str, Any]      # source-specific; deliberately open
    raw_ref: Optional[str] = None   # pointer to on-disk original
```

**Important**: `occurred_at` vs `observed_at` — Fusion orders on `occurred_at`. Mixing them up is the most likely subtle bug.

### 4.3 `SemanticEvent` (`adam/contracts/semantic_event.py`)

```python
class SemanticEvent(BaseModel):
    semantic_id: str
    session_id: str
    correlation_id: str
    intent: str                      # e.g. "RECON_DOMAIN_CONTROLLER"
    confidence: float                # 0.0–1.0
    severity: str
    window_start: datetime
    window_end: datetime
    actor: Optional[ActorContext]    # {pid, image, guid}
    evidence: list[str]              # list of raw_event_ids
    attck: Optional[AttckContext]    # {tactic, technique}
    detector: str                    # e.g. "DomainReconDetector@1.2"
    features: dict[str, Any]
    caused_by_mutation: Optional[str] = None  # ★ THE YIELD LINK
```

`caused_by_mutation` is how behavioral yield is measured: when Fusion produces a semantic event inside a mutation's causal window, it records the mutation_id here. Events where this is non-null = deception-attributable behavior.

### 4.4 `PolicyDecision` (`adam/contracts/policy_decision.py`)

```python
class PolicyDecision(BaseModel):
    decision_id: str
    session_id: str
    correlation_id: str
    triggered_by: str        # semantic_id that triggered this
    rule_id: str
    rule_version: str
    action: str              # e.g. "SPAWN_FAKE_DC_ARTIFACTS"
    verdict: PolicyVerdict
    priority: int
    parameters: dict[str, Any]
    rationale: str           # human-readable, always populated
    decided_at: datetime
    evaluation_ms: float
```

**Suppressed decisions are persisted, not discarded** — they are how the team tunes thresholds and how the paper reports on policy behavior.

### 4.5 `MutationResult` (`adam/contracts/mutation.py`)

```python
class MutationChange(BaseModel):
    kind: str       # REGISTRY, FILE, NETWORK
    target: str
    operation: str  # SET, CREATE, RESPOND
    value: Optional[str] = None

class MutationResult(BaseModel):
    mutation_id: str
    session_id: str
    correlation_id: str
    decision_id: str
    primitive: str
    status: MutationStatus
    applied_at: datetime
    latency_ms: float
    changes: list[MutationChange]
    plausibility_score: float     # self-assessed, 0.0–1.0
    plausibility_notes: Optional[str] = None
    revertible: bool = True
    causal_window_ms: int = 30000  # how long to attribute downstream behavior
    error: Optional[str] = None
```

### 4.6 `AnalysisSession` (`adam/contracts/session.py`)

```python
class SampleMetadata(BaseModel):
    sha256: str; md5: str; filename: str; size_bytes: int; file_type: str

class SessionConfig(BaseModel):
    deception_enabled: bool; policy_ruleset: str; vm_profile: str
    timeout_seconds: int; network_mode: NetworkMode

class SessionMetrics(BaseModel):
    raw_events: int = 0; semantic_events: int = 0
    decisions_total: int = 0; decisions_executed: int = 0
    mutations_applied: int = 0; semantic_events_post_mutation: int = 0

class AnalysisSession(BaseModel):
    session_id: str; experiment_id: str; arm: DeceptionArm
    sample: SampleMetadata; config: SessionConfig
    status: SessionStatus; started_at: datetime
    ended_at: Optional[datetime] = None; metrics: SessionMetrics
    error: Optional[str] = None
```

### 4.7 ABCs / Protocols (`adam/contracts/interfaces.py`)

```python
class ISandboxController(Protocol):
    async def prepare() -> None
    async def detonate(sample_path: str) -> None
    async def apply_mutation(decision: PolicyDecision) -> MutationResult
    async def collect_artifacts() -> None
    async def teardown() -> None

class ICollector(Protocol):
    async def start() -> None
    async def stop() -> None
    async def iter_events() -> AsyncIterator[RawEvent]

class IFusionEngine(Protocol):
    async def ingest(event: RawEvent) -> list[SemanticEvent]

class IPolicyEngine(Protocol):
    async def evaluate(event: SemanticEvent, context: Any) -> list[PolicyDecision]

class IDeceptionEngine(Protocol):
    async def execute(decision: PolicyDecision) -> MutationResult
```

---

## 5. Event Bus (`adam/common/bus.py`)

In-process asyncio pub/sub broker. Key design:

- **Per-publisher FIFO ordering**. At-most-once delivery.
- **Handler isolation**: exception in one subscriber never affects another or the publisher.
- **Bounded memory**: per-subscriber queues (default 1000). On overflow: `DROP_OLDEST` policy — drops, counts, logs.
- **Dropping > blocking**: Blocking a collector because the DB writer is slow would corrupt timing fidelity.

### Subscription Map

| Publisher | Message | Subscribers |
|---|---|---|
| Collectors | `RawEvent` | Fusion, DBWriter, RawLogWriter, LiveStream |
| Fusion | `SemanticEvent` | Policy, DBWriter, LiveStream |
| Policy | `PolicyDecision` | Deception, DBWriter, LiveStream |
| Deception | `MutationResult` | Fusion, DBWriter, LiveStream |
| Orchestrator | `SessionLifecycle` | all |

The Fusion → Policy → Deception → Fusion cycle is intentional (the adaptive loop). It is safe because it passes through the guest VM and the budget/cooldown mechanism in Policy formally bounds it.

---

## 6. Configuration (`adam/common/config.py`)

Pydantic Settings with nested models. Precedence: CLI flags > env vars (`ADAM__SANDBOX__VM_NAME`) > `config/<env>.toml` > `config/default.toml` > Pydantic defaults.

```python
class Settings(BaseSettings):
    sandbox: SandboxSettings    # hypervisor, qemu paths, vm image, boot timeout, network mode, memory, cpu, port forwarding, manage_vm, virtio serial
    fusion: FusionSettings      # window_seconds=5.0, max_window_events=10000, min_confidence_emit=0.40
    policy: PolicySettings      # ruleset_path, global_confidence_gate=0.60, max_mutations=15, default_cooldown=20s, dry_run
    deception: DeceptionSettings # causal_window_ms=30000, plausibility_warn_below=0.50
    bus: BusSettings            # queue_size=1000, overflow_policy=DROP_OLDEST
    db: DbSettings              # path=artifacts/adam.sqlite, batch_size=500
    logging: LoggingSettings    # level=INFO, format=json
```

---

## 7. Core Components (Implementation Details)

### 7.1 Sandbox Controller (`adam/sandbox/controller.py`)

`SandboxController(ISandboxController)`:
- **FSM states**: COLD → RESTORING → BOOTING → READY → ARMED → RUNNING → TEARDOWN → COLD (or FAILED).
- `prepare()`: Creates qcow2 overlay via `qemu-img create -f qcow2 -b <base> -F qcow2`, starts QEMU process, polls guest agent heartbeat (`GET /heartbeat`).
- `detonate(sample_path)`: Uploads sample via `POST /upload`, triggers execution via `POST /execute`.
- `apply_mutation(decision)`: Sends `POST /mutate` to guest agent with action + parameters. Returns `MutationResult`.
- `teardown()`: Stops QEMU process, deletes overlay. Idempotent, safe in `finally`.

### 7.2 QEMU Client (`adam/sandbox/qemu/client.py`)

Wraps `asyncio.create_subprocess_exec` for the QEMU system binary. Uses WHPX on Windows, KVM on Linux. Network is `user,restrict=on` with host port forwarding.

### 7.3 Guest Agent (`adam/sandbox/guest/agent/adam_agent.ps1`)

555-line PowerShell 5.1 script running inside the guest VM. Two concurrent threads:

**Main Thread (HTTP Listener on port 8443)**:
- `GET /heartbeat` → `{"status": "alive"}`
- `POST /upload` → receives sample binary
- `POST /execute` → triggers sample execution
- `POST /mutate` → executes deception mutations:
  - `SPAWN_FAKE_DC_ARTIFACTS`: Sets `HKLM\...\Domain` = `CORP.LOCAL`, appends to hosts file, creates SYSVOL directory
  - `SIMULATE_AV_PRESENCE`: Sets Defender registry flags
  - `PLANT_DECOY_DOCUMENTS`: Creates fake XLSX file in Documents

**Background Harvester Thread (VirtIO Serial / Named Pipe)**:
- Opens `\\.\Global\adam_stealth_port` (VirtIO serial device) for duplex communication
- Reads `PolicyDecision` JSON from host → executes mutations → writes `MutationResult` back
- Harvests Sysmon events via `Get-WinEvent` (real-time ETW tailing)
- Harvests ProcMon data periodically (every 10s) by terminating/re-exporting PML to CSV
- Converts events to `RawEvent` JSON and streams over VirtIO serial

### 7.4 Serial Listener (`adam/orchestrator/serial_listener.py`)

Host-side named pipe client (`\\.\pipe\adam_telemetry`) that connects to QEMU's VirtIO serial port. Uses Win32 `CreateFileW`, `PeekNamedPipe`, `ReadFile`, `WriteFile` via ctypes. Parses incoming JSONL: if payload has `mutation_id` → publishes as `MutationResult`, otherwise → publishes as `RawEvent`.

### 7.5 Fusion Engine (`adam/fusion/engine.py`)

`FusionEngine(IFusionEngine)`:
1. Normalizes raw event via `EventNormaliser.normalise()`
2. Adds to `EventCorrelator` sliding window
3. Runs all registered detectors from `DETECTOR_REGISTRY`
4. If there's an active mutation (`_current_mutation_id`), stamps `caused_by_mutation` on produced SemanticEvents
5. Publishes each SemanticEvent to the bus

### 7.6 Policy Engine (`adam/policy/engine.py`)

`PolicyEngine(IPolicyEngine)`:
- Loads YAML rules via `RuleLoader.load_rules(path)` at startup
- Per-session context tracks: rule execution counts, last execution times, total mutations
- Evaluation cascade: intent match → confidence gate (rule-level, then global) → budget check (per-rule, then global) → cooldown check → dry_run check
- **All decisions published to bus**, including suppressed ones (with rationale)

### 7.7 Deception Engine (`adam/deception/engine.py`)

`DeceptionEngine(IDeceptionEngine)`:
- Receives `PolicyDecision`, checks verdict == EXECUTE
- Delegates to `SandboxController.apply_mutation(decision)`
- Publishes resulting `MutationResult` back to bus

### 7.8 Session Orchestrator (`adam/orchestrator/session.py`)

`SessionRunner` — the autonomous execution loop:
1. Subscribes to all event types on the bus
2. Calls `sandbox.prepare()` then `sandbox.detonate(sample_path)`
3. Runs timed loop with **Dead Man's Switch**: if no events for `idle_timeout_seconds` (default 8s), triggers forced state mutation (syscall randomization, mitigation toggling, user simulation)
4. On each raw event: feeds to attention encoder buffer, ingests into fusion
5. On each semantic event: checks decoy tripwires, runs DRL policy for autonomous AMTD decisions (syscall randomization, kernel memory shuffle, C2 sinkhole activation)
6. On teardown: synthesizes YARA rules and STIX 2.1 bundles, saves final metrics

---

## 8. Autonomous AMTD Subsystems (V2 Layer)

### 8.1 VMI Engine (`adam/sandbox/vmi/`)

#### EPT Controller (`ept_controller.py`)
- Multi-view EPT memory shadowing: `create_view()`, `switch_view()` for atomic EPTP switching
- Page splitting: 2MB → 512 × 4KB for fine-grained trapping
- Shadow page execution traps: default view has RW-only (no-execute), shadow view has RX with redirected MFN
- EPT violation handler with TSC compensation (Anti-RDTSC)
- Copy-on-Write (CoW) dirty-page bitmap for sub-second state resets

#### Syscall Virtualizer (`syscall_virtualizer.py`)
- SSDT virtualization with dynamic index remapping
- Tracks 16 security-sensitive Windows NT syscalls (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, etc.)
- `randomize_syscall_indices()` shuffles virtual SSNs while maintaining shadow hooks
- Invocation counting per syscall for behavioral profiling

#### Kernel Polymorphism Engine (`kernel_polymorphism.py`)
- Transactional State Switch: coordinates atomic vCPU safe-points to prevent BSODs during live mutations
- Begin → Pause vCPUs → Apply mutation → Commit or Rollback → Resume vCPUs
- Dynamic mitigation toggles for Spectre V2 (CVE-2017-5715) and Meltdown KPTI (CVE-2017-5754)
- Kernel stack/memory offset shuffling with configurable entropy

#### DKOM Tracker (`dkom_tracker.py`)
- Allocation-driven kernel object tracking (EPROCESS, ETHREAD, FILE_OBJECT, DRIVER_OBJECT)
- Ground truth process list independent of guest doubly-linked lists
- `detect_dkom_hidden_processes()`: cross-references allocations vs. guest-reported PIDs to detect rootkits
- Dynamic memory map updates with listener pattern (notifies TLS Extractor)

#### Differential Memory Analyzer (`differential_memory.py`)
- Baseline snapshot capture → runtime memory diffing
- Detects PAGE_EXECUTE_READWRITE transitions and process hollowing primitives
- Shannon entropy calculation for identifying encrypted/packed payloads
- Extracts memory deltas as forensic artifacts

### 8.2 DRL Engine (`adam/policy/drl/`)

#### Attention Event Encoder (`encoder.py`)
- Converts variable-length security event streams into fixed-dimension (default 16) state vectors
- Built-in telemetry deduplication filter (sliding window, collapses repetitive API bursts)
- Scaled dot-product self-attention: `h = softmax(Q·K^T / √d) · V`
- Event type vocabulary: PROCESS_CREATE, MEM_INJECT_RWX, REG_QUERY, NET_CONNECT, EPT_TRAP, etc.

#### Dual-Stream Policy (`dual_stream.py`)
Two arbitrated streams:
1. **Immediate Tactical**: Reactive anti-evasion (user simulation on evasion detection, dormancy breaking via random syscall/mitigation/sinkhole selection after 3+ dormant cycles)
2. **Strategic Cognitive**: Long-term AMTD planning via heuristic Q-values computed from state embedding. Phase-aware prioritization (INITIAL_DETONATION → user sim, UNPACKING → EPT hooks, C2_INTERACTION → sinkhole)

#### Gymnasium Environment (`gym_env.py`)
- Standard `reset()` / `step(action)` interface
- 9 actions: NOOP, RANDOMIZE_SYSCALLS, SHUFFLE_KERNEL_MEMORY, TOGGLE_SPECTRE/MELTDOWN, ACTIVATE_EPT_SHADOW_HOOK, TRIGGER_USER_SIMULATION, ROTATE_SYNTHETIC_DECOYS, ENABLE_C2_SINKHOLE
- `reset()` uses CoW memory delta rollback for sub-second restoration
- Milestone progression: PROCESS_CREATION → MEMORY_INJECTION → PAYLOAD_DECRYPTION → C2_BEACON_TRANSMIT

#### Reward Shaper (`reward.py`)
- Novelty component: +5.0 per new behavior signature (×2.0 multiplier after 2+ milestones unlocked)
- Disclosure component: +15.0 per new IOC (C2 endpoint, unpacked stage hash)
- Milestone bonus: +3.0 × count of achieved milestones
- Time penalty: -0.05 × √step (prevents infinite waiting)
- Stability penalty: -50.0 for guest crash, -5.0 for dormancy, -1.0 for mutation with no new behavior
- Anti-reward-hacking: milestone gating before high-tier rewards

### 8.3 Synthetic Deception (`adam/deception/synthetic/`)

#### User Simulator (`user_simulator.py`)
- Cubic Bézier mouse trajectories with humanlike jitter (random control point angles ±0.5 rad)
- Random user sessions: move → dwell → click sequences over configurable duration
- Defeats mouse-dwell and human-interaction evasion checks

#### Synthetic Decoy Engine (`decoys.py`)
- Default canary files: Financial_Report.xlsx, VPN_Credentials.docx, id_rsa SSH key, wallet.dat, Chrome History, Corporate_Passcodes.pdf
- Default registry lures: WinSCP sessions, PuTTY configs, fake Run keys
- Canary token tracking per file/registry key
- Tripwire detection on access → generates intelligence alerts

#### Hardware Fingerprint Spoofing (`fingerprint.py`)
- Spoofs CPUID, BIOS serial, disk serial, MAC address, motherboard ID
- Defeats VM-aware malware checking hardware signatures

### 8.4 C2/Network Interception (`adam/deception/c2/`)

#### C2 Sinkhole (`sinkhole.py`)
- DNS sinkholing: redirects all DGA/fast-flux queries to local emulator IP
- Interactive C2 response emulation: Stage 1 = WHOAMI ack, Stage 2 = fake Cobalt Strike DOWNLOAD_EXEC with probe shellcode, Stage 3+ = SLEEP keep-alive
- Tracks intercepted beacons for forensic reporting

#### TLS Session Key Extractor (`tls_extractor.py`)
- Locates SSL_CTX / TLS session structures in lsass.exe memory via dynamic offsets from DKOM tracker
- Extracts master secrets and session keys for encrypted traffic decryption

#### Traffic Normalizer (`traffic_normalizer.py`)
- Normalizes network timing to defeat traffic-analysis detection of sandbox environments

### 8.5 Reporting & Intelligence (`adam/reporting/`)

#### Threat Intelligence Synthesizer (`intelligence.py`)
- Records C2 domains, IPs, mutexes, registry artifacts, payload hashes as `ThreatArtifact`s
- **YARA Rule Generator**: Auto-generates detection rules from extracted mutexes, C2 domains, hex byte signatures
- **STIX 2.1 Exporter**: Packages IOCs into standard STIX 2.1 bundles with Report SDO and Indicator SDOs

#### Report Generator (`generator.py`)
- Per-session reports: execution timeline, decision/mutation ledger, MITRE ATT&CK coverage, IOCs
- **Comparison reports**: behavioral yield delta between control and treatment arms of same experiment

---

## 9. API Surface (`adam/api/main.py`)

FastAPI app with composition root in `adam/api/deps.py`.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/sessions` | Create new analysis session (background worker) |
| `GET` | `/api/v1/sessions/{id}` | Get session details |
| `POST` | `/api/v1/sessions/{id}/telemetry` | Push guest telemetry |
| `GET` | `/api/v1/experiments/{id}/comparison` | Behavioral yield comparison |
| `GET` | `/api/v1/health` | Health check |

### Continuous Live Pipeline

On startup, the API creates a permanent `sess_continuous_live` session and subscribes to all bus events. This handles VirtIO serial telemetry from a manually managed guest VM. Decisions flow back to the guest via the serial named pipe for autonomous guest-side execution.

---

## 10. Database Schema

```
experiments ──1:N── sessions ──┬──1:N── raw_events (metadata only)
                                ├──1:N── semantic_events
                                ├──1:N── decisions
                                ├──1:N── mutations
                                ├──1:N── artifacts
                                └──1:1── session_metrics

semantic_events.evidence     → raw_events (JSON array of ids)
decisions.triggered_by       → semantic_events
mutations.decision_id        → decisions
semantic_events.caused_by_mutation → mutations (nullable — the yield link)
```

Raw event **bodies** live in `artifacts/<sid>/raw.jsonl` (10⁵–10⁶/session). SQLite holds metadata only.

---

## 11. Intent Taxonomy & Deception Catalogue

### Intents (Fusion produces these)

```
RECON_*     RECON_DOMAIN_CONTROLLER · RECON_NETWORK_SHARES · RECON_INSTALLED_AV
            RECON_VIRTUALISATION · RECON_USER_ARTIFACTS · RECON_LANGUAGE_LOCALE
            RECON_DEBUGGER · RECON_SYSTEM_UPTIME
CRED_*      CRED_BROWSER_STORE · CRED_LSASS_ACCESS · CRED_WALLET_SEARCH
            CRED_CONFIG_FILE_HARVEST
PERSIST_*   PERSIST_RUN_KEY · PERSIST_SCHEDULED_TASK · PERSIST_SERVICE
            PERSIST_WMI_SUBSCRIPTION
EVADE_*     EVADE_SANDBOX_DETECTED · EVADE_SLEEP_SKIP · EVADE_PROCESS_INJECTION
            EVADE_AMSI_BYPASS
IMPACT_*    IMPACT_MASS_FILE_ENCRYPT · IMPACT_SHADOW_COPY_DELETE
            IMPACT_RANSOM_NOTE_DROP
C2_*        C2_BEACON · C2_DNS_TUNNEL · C2_DEAD_DROP_RESOLVER
LATERAL_*   LATERAL_SMB_ENUM · LATERAL_REMOTE_EXEC · LATERAL_CREDENTIAL_REUSE
```

### Deception Primitives (each maps to one or more intents)

```
SPAWN_FAKE_DC_ARTIFACTS      ← RECON_DOMAIN_CONTROLLER
MOUNT_FAKE_NETWORK_SHARE     ← RECON_NETWORK_SHARES · LATERAL_SMB_ENUM
PLANT_DECOY_DOCUMENTS        ← RECON_USER_ARTIFACTS
PLANT_DECOY_WALLET           ← CRED_WALLET_SEARCH
INJECT_FAKE_BROWSER_CREDS    ← CRED_BROWSER_STORE
SIMULATE_AV_PRESENCE         ← RECON_INSTALLED_AV
HIDE_VM_ARTIFACTS            ← RECON_VIRTUALISATION · EVADE_SANDBOX_DETECTED
FABRICATE_C2_RESPONSE        ← C2_BEACON · C2_DEAD_DROP_RESOLVER
ACCELERATE_SYSTEM_CLOCK      ← EVADE_SLEEP_SKIP
SPAWN_DECOY_PROCESSES        ← RECON_SYSTEM_UPTIME · RECON_DEBUGGER
```

---

## 12. Folder Structure

```
project-adam/
├── ARCHITECTURE.md           # 1753-line authoritative architectural contract
├── README.md                 # Project overview and developer ownership
├── pyproject.toml            # pytest, ruff, mypy configuration
├── config/                   # TOML configuration files
│   ├── default.toml
│   └── vm_profiles/
├── rules/                    # YAML policy rules
│   ├── default/              # recon.yaml, credentials.yaml, persistence.yaml, etc.
│   └── schema/
├── adam/
│   ├── contracts/            # ★ FROZEN — Pydantic models, ABCs, enums
│   ├── common/               # Foundation — bus, config, logging, errors, timeutil
│   ├── sandbox/
│   │   ├── controller.py     # ISandboxController implementation
│   │   ├── state.py          # FSM (SandboxFSM, SandboxState)
│   │   ├── qemu/             # QEMU process wrapper, snapshot manager
│   │   ├── guest/agent/      # adam_agent.ps1 (runs inside guest)
│   │   └── vmi/              # ★ VMI layer: EPT, syscall virtualizer, kernel polymorphism, DKOM, differential memory
│   ├── collectors/           # Sysmon, ProcMon, network, agent collectors
│   ├── fusion/               # ★ Research core: engine, normalise, correlate, detectors/
│   ├── policy/
│   │   ├── engine.py         # ★ Research core: rule evaluation
│   │   ├── loader.py         # YAML rule loading
│   │   ├── predicates/       # Python escape hatch for complex conditions
│   │   └── drl/              # ★ DRL: attention encoder, dual-stream policy, gym env, reward shaper
│   ├── deception/
│   │   ├── engine.py         # ★ Research core: mutation dispatch
│   │   ├── primitives/       # registry_lures, filesystem_lures, network_lures, etc.
│   │   ├── synthetic/        # User simulator, decoy engine, hardware fingerprint
│   │   └── c2/               # C2 sinkhole, TLS extractor, traffic normalizer
│   ├── orchestrator/
│   │   ├── session.py        # ★ Autonomous SessionRunner with AMTD loop
│   │   └── serial_listener.py # VirtIO serial named pipe client
│   ├── db/                   # SQLite: connection, writer, schema, repositories
│   ├── api/
│   │   ├── main.py           # FastAPI app with continuous live pipeline
│   │   └── deps.py           # ★ Composition root
│   ├── reporting/
│   │   ├── generator.py      # Session and comparison reports
│   │   ├── intelligence.py   # YARA + STIX 2.1 synthesis
│   │   └── renderers/        # HTML, JSON, Markdown
│   ├── dashboard/            # Jinja2 templates, static assets
│   └── cli/                  # adam run, adam replay, adam validate-rules
├── tests/
│   ├── unit/                 # Per-module unit tests
│   ├── integration/          # Replay pipeline, API tests
│   └── e2e/                  # Full session with real VM (marked slow)
├── artifacts/                # gitignored, per-session output
├── samples/                  # gitignored, NEVER committed
└── logs/                     # gitignored
```

---

## 13. Design Principles

| # | Principle |
|---|---|
| P1 | **Contracts before code** — `adam/contracts/` is frozen |
| P2 | **Modules never import siblings** — communication via bus or injected interface |
| P3 | **Interface-driven** — every module exposes one ABC |
| P4 | **Pure core, impure edges** — Fusion and Policy are pure functions; all I/O at edges |
| P5 | **Type hints everywhere** — mypy --strict on contracts and core |
| P6 | **Fail visible, not silent** — no bare `except`, every swallow logs with correlation ID |
| P7 | **Deterministic replay** — any session's raw.jsonl can replay through Fusion→Policy without VM |
| P8 | **Config over code** — no magic numbers, no hardcoded paths |

---

## 14. Error Handling

**Principle: degrade, don't abort.** A detonation is expensive.

| Failure | Response |
|---|---|
| One detector raises | Log ERROR, skip detector for that event, continue |
| One collector dies | Log ERROR, mark source degraded, continue |
| Mutation fails | Record MutationResult with status=FAILED, continue |
| Bus queue overflows | Drop, count, log WARNING |
| DB write fails | Retry ×3, buffer to disk, shed low-value events |
| Rule file invalid | **Refuse to start** |
| VM unreachable at start | **Refuse to start** |
| VM lost mid-run | Abort, force rollback, mark PARTIAL |
| Rollback fails | CRITICAL, quarantine VM, block further sessions |

Exception hierarchy: `AdamError → ConfigError | ContractViolationError | SandboxError (VMOperationError, SandboxStateError, GuestTimeoutError) | CollectorError | FusionError | PolicyError | DeceptionError | PersistenceError | ReportingError`

---

## 15. Latency Budget

| Stage | Budget |
|---|---|
| Collector → bus | ≤ 150ms |
| Fusion correlation | ≤ 50ms |
| Policy evaluation | ≤ 20ms |
| Deception dispatch | ≤ 30ms |
| Guest mutation apply | ≤ 250ms |
| **Total** | **≤ 500ms** |

---

## 16. Testing Strategy

| Tier | Scope | Needs VM |
|---|---|---|
| Unit | One class, fakes for all collaborators | No |
| Contract | Every model round-trips JSON | No |
| Replay integration | raw.jsonl → Fusion → Policy → Deception (dry-run) | **No** |
| API integration | FastAPI TestClient over temp DB | No |
| End-to-end | Real VM, real sample, full session | Yes |

Replay is the workhorse — detector precision/recall, policy diff testing, latency verification all run deterministically from committed corpora.

---

## 17. Developer Ownership

| Dev | Owns |
|---|---|
| **A** | `adam/common/`, `adam/sandbox/`, `adam/collectors/`, `adam/orchestrator/`, `config/`, `scripts/` |
| **B** | `adam/fusion/`, `tests/fixtures/` |
| **C** | `adam/policy/`, `adam/deception/`, `rules/` |
| **D** | `adam/api/`, `adam/db/`, `adam/reporting/`, `adam/dashboard/` |

---

## 18. Key Design Decisions (ADRs)

1. **ADR-001**: In-process asyncio event bus (not Redis/RabbitMQ) — zero operational overhead, single process, swappable later.
2. **ADR-002**: Hybrid YAML + Python predicate policy — 95% in reviewable YAML, complex logic in tested Python predicates.
3. **ADR-003**: Mutations published as events — required for behavioral yield measurement and causal attribution.
4. **ADR-004**: Fusion and Policy are pure functions — enables deterministic replay, the highest-leverage property.
5. **ADR-005**: Raw events to JSONL, not SQLite — 10⁵–10⁶ rows/session would bottleneck SQLite.

---

## 19. Important Implementation Patterns

### Accessing event fields correctly
- Raw event process info: `event.process.pid` (not `event.process_id`)
- Raw event attributes: `event.attributes.get("target_object")`
- Semantic event features: `event.features.get("target_path")`

### Causal window management
After a mutation, `SessionRunner` sets `active_mutation_id` and calls `fusion.set_active_mutation(id)`. A background task clears it after 30 seconds (configurable `causal_window_ms`).

### VirtIO Serial duplex communication
Host writes `PolicyDecision` JSON + `\n` to named pipe / TCP socket stream (`127.0.0.1:8444`) → Guest reads via `adam_agent.ps1`, executes mutation, writes `MutationResult` JSON + `\n` back → Host reads via `serial_listener.py`, publishes to bus.

### Two execution modes
1. **Session-based**: `POST /api/v1/sessions` → background worker boots fresh VM, detonates sample, runs AMTD loop, tears down
2. **Continuous Live**: Permanent `sess_continuous_live` session with manually managed guest VM, VirtIO serial telemetry, autonomous policy execution (`deps.deception_engine.execute(decision)`)

---

## 20. Expanded Intent & Policy Mutation Matrix (14 Categories + Compound Campaigns)

The system supports a 14-category taxonomy with 179 default policy rules, strict severity classification, confidence gating, and category disambiguation between **MUTATE** (active deception lures), **OBSERVE** (passive high-fidelity telemetry), and **MEASUREMENT** (observation-preserving primitives).

| Category | Semantic Intent | ATT&CK Tactic / Technique | Severity | Confidence Threshold | Action / Primitive | Action Category |
|---|---|---|---|---|---|---|
| **Discovery** | `RECON_DOMAIN_CONTROLLER` | `TA0007` / `T1018` | HIGH | `0.75` | `SPAWN_FAKE_DC_ARTIFACTS` | **MUTATE** |
| **Discovery** | `RECON_SYSTEM_INFO` | `TA0007` / `T1082` | LOW | `0.60` | `NONE` | OBSERVE |
| **Discovery** | `RECON_NETWORK_CONFIG` | `TA0007` / `T1016` | LOW | `0.60` | `NONE` | OBSERVE |
| **Discovery** | `RECON_PROCESS_DISCOVERY` | `TA0007` / `T1057` | MEDIUM | `0.70` | `SPAWN_DECOY_PROCESSES` | **MUTATE** |
| **Discovery** | `RECON_USER_DISCOVERY` | `TA0007` / `T1033` | MEDIUM | `0.70` | `SYNTHESIZE_USER_PROFILE` | **MUTATE** |
| **Discovery** | `RECON_FILE_DIRECTORY` | `TA0007` / `T1083` | LOW | `0.70` | `PLANT_DECOY_DOCUMENTS` | **MUTATE** |
| **Discovery** | `RECON_SECURITY_TOOLS` / `RECON_INSTALLED_AV` | `TA0007` / `T1518.001` | HIGH | `0.75` | `SIMULATE_AV_PRESENCE` | **MUTATE** |
| **Discovery** | `RECON_RUNNING_SERVICES` | `TA0007` / `T1007` | HIGH | `0.75` | `SPAWN_DECOY_SERVICES` | **MUTATE** |
| **Discovery** | `RECON_INSTALLED_SOFTWARE` | `TA0007` / `T1518` | MEDIUM | `0.70` | `SYNTHESIZE_SOFTWARE_INVENTORY` | **MUTATE** |
| **Discovery** | `RECON_NETWORK_SHARES` | `TA0007` / `T1135` | HIGH | `0.75` | `MOUNT_FAKE_NETWORK_SHARE` | **MUTATE** |
| **Credentials** | `CRED_BROWSER_STORE` | `TA0006` / `T1555.003` | HIGH | `0.75` | `INJECT_FAKE_BROWSER_CREDS` | **MUTATE** |
| **Credentials** | `CRED_WALLET_SEARCH` | `TA0006` / `T1552.001` | HIGH | `0.75` | `PLANT_DECOY_WALLET` | **MUTATE** |
| **Credentials** | `CRED_PRIVATE_KEY_SEARCH` / `COLLECT_SSH_KEYS` | `TA0006` / `T1552.004` | HIGH | `0.75` | `PLANT_DECOY_PRIVATE_KEYS` | **MUTATE** |
| **Credentials** | `CRED_CLOUD_CREDENTIAL_SEARCH` | `TA0006` / `T1552.005` | CRITICAL | `0.85` | `PLANT_DECOY_CLOUD_CREDENTIALS` | **MUTATE** |
| **Credentials** | `CRED_LSASS_ACCESS` | `TA0006` / `T1003.001` | CRITICAL | `0.90` | `NONE` (Safe Containment) | OBSERVE |
| **Credentials** | `CRED_SAM_ACCESS` | `TA0006` / `T1003.002` | CRITICAL | `0.90` | `NONE` (Safe Containment) | OBSERVE |
| **Credentials** | `CRED_NTDS_ACCESS` | `TA0006` / `T1003.003` | CRITICAL | `0.90` | `NONE` (Safe Containment) | OBSERVE |
| **Evasion** | `EVADE_VM_ARTIFACT_CHECK` / `SANDBOX_HARDWARE_CHECK` | `TA0005` / `T1497.001` | CRITICAL | `0.85` | `SPOOF_HARDWARE_IDENTITY` | **MUTATE** |
| **Evasion** | `EVADE_AMSI_BYPASS` | `TA0005` / `T1562.001` | HIGH | `0.80` | `SIMULATE_AMSI_TARGET` | **MUTATE** |
| **Evasion** | `EVADE_DEFENDER_TAMPERING` | `TA0005` / `T1562.001` | HIGH | `0.80` | `SIMULATE_SECURITY_CONFIGURATION` | **MUTATE** |
| **Evasion** | `EVADE_PROCESS_HOLLOWING` | `TA0005` / `T1055.012` | CRITICAL | `0.90` | `ACTIVATE_EPT_SHADOW_HOOK` | **MEASUREMENT** |
| **Injection** | `INJECT_REMOTE_THREAD` | `TA0005` / `T1055.002` | CRITICAL | `0.85` | `ACTIVATE_MEMORY_MONITOR` | **MEASUREMENT** |
| **Injection** | `INJECT_PROCESS_HOLLOWING` | `TA0005` / `T1055.012` | CRITICAL | `0.90` | `ACTIVATE_EPT_SHADOW_HOOK` | **MEASUREMENT** |
| **Injection** | `INJECT_REFLECTIVE_DLL` | `TA0005` / `T1055.001` | CRITICAL | `0.90` | `ACTIVATE_EPT_SHADOW_HOOK` | **MEASUREMENT** |
| **Injection** | `MEM_ALLOC_RWX` / `MEM_PROTECT_RWX` | `TA0005` / `T1055` | HIGH | `0.80` | `ACTIVATE_MEMORY_MONITOR` | **MEASUREMENT** |
| **Payload/Unpack** | `PAYLOAD_DECRYPTION` / `PAYLOAD_UNPACKING` | `TA0005` / `T1140` | HIGH | `0.80` | `ACTIVATE_EPT_MEMORY_CAPTURE` | **MEASUREMENT** |
| **C2** | `C2_DGA_ACTIVITY` | `TA0011` / `T1568.002` | CRITICAL | `0.85` | `ACTIVATE_C2_SINKHOLE` | **MUTATE** |
| **C2** | `C2_BEACON` / `C2_HTTP_POLLING` | `TA0011` / `T1071.001` | HIGH | `0.80` | `FABRICATE_C2_RESPONSE` | **MUTATE** |
| **Lateral** | `LATERAL_ADMIN_SHARE_ENUM` / `LATERAL_SMB_ENUM` | `TA0008` / `T1135` | HIGH | `0.75` | `MOUNT_FAKE_NETWORK_SHARE` | **MUTATE** |
| **Lateral** | `LATERAL_RDP_CONNECTION` | `TA0008` / `T1021.001` | CRITICAL | `0.85` | `SYNTHESIZE_RDP_TARGETS` | **MUTATE** |
| **Lateral** | `LATERAL_DOMAIN_TRUST_DISCOVERY` | `TA0008` / `T1482` | CRITICAL | `0.85` | `SYNTHESIZE_DOMAIN_TOPOLOGY` | **MUTATE** |
| **Data Collection** | `COLLECT_DOCUMENTS` | `TA0009` / `T1005` | HIGH | `0.75` | `PLANT_DECOY_DOCUMENTS` | **MUTATE** |
| **Data Collection** | `COLLECT_FINANCIAL_FILES` | `TA0009` / `T1005` | HIGH | `0.75` | `PLANT_DECOY_FINANCIAL_DATA` | **MUTATE** |
| **Impact / Ransom** | `IMPACT_SHADOW_COPY_DELETE` | `TA0040` / `T1490` | CRITICAL | `0.85` | `CREATE_DECOY_RECOVERY_TARGET` | **MUTATE** |
| **Impact / Ransom** | `IMPACT_MASS_FILE_ENCRYPT` | `TA0040` / `T1486` | CRITICAL | `0.85` | `ACTIVATE_FILE_SYSTEM_SNAPSHOT` | **MEASUREMENT** |
| **Anti-Forensics** | `ANTI_FORENSICS_SELF_DELETE` | `TA0005` / `T1070.004` | CRITICAL | `0.85` | `PRESERVE_EXECUTION_ARTIFACT` | **MEASUREMENT** |
| **Anti-Forensics** | `ANTI_FORENSICS_EVENT_LOG_CLEAR` | `TA0005` / `T1070.001` | CRITICAL | `0.90` | `NONE` (Safe Containment) | OBSERVE |
| **Campaign Phase** | `CAMPAIGN_RANSOMWARE` | `TA0040` / `T1486` | CRITICAL | `0.90` | `ACTIVATE_FILE_SYSTEM_SNAPSHOT` | **MEASUREMENT** |
| **Campaign Phase** | `CAMPAIGN_LATERAL_MOVEMENT` | `TA0008` / `T1021` | CRITICAL | `0.90` | `SYNTHESIZE_DOMAIN_TOPOLOGY` | **MUTATE** |

---

## 21. Mutation Test Harness & Live Mutation Console

ADAM includes a dedicated, dashboard-driven research test harness that allows operators to safely exercise and visibly demonstrate the full closed-loop adaptive deception engine.

### Test Mode Isolation
- Sessions created from the test harness operate with `mutation_test_mode = True`.
- Regular autonomous analysis sessions execute with `mutation_test_mode = False`.
- The test harness exercises the real pipeline (`RawEvent` → `FusionEngine` → `PolicyEngine` → `DeceptionEngine` → `MutationResult` → causal attribution) with no bypassed confidence gates or budgets.

### Standalone Test Binary (`adam_mutation_test.exe`)
- Source: `tools/mutation_test/Program.cs`
- Build script: `tools/mutation_test/build.ps1`
- Compiled binary: `tools/mutation_test/dist/adam_mutation_test.exe` (14 KB standalone C# single binary, no guest Python dependency).
- Embedded banner: `[ADAM-MUTATION-TEST]`.
- Generates safe non-destructive deterministic telemetry patterns matching all detector signatures.

### API Endpoints
- `GET /api/v1/mutation-tests/commands`: Loads dynamic command manifest (`tools/mutation_test/manifest.json`).
- `POST /api/v1/mutation-tests/inject`: Uploads test binary into guest and marks session in test mode.
- `POST /api/v1/mutation-tests/{session_id}/execute`: Triggers selected test command.
- `POST /api/v1/mutation-tests/{session_id}/stop`: Stops test session and tears down test mode.
- `GET /api/v1/mutation-tests/{session_id}/results`: Computes validation verdict (`PASS`, `PARTIAL`, `FAILED`, `UNEXPECTED`).
- `GET /api/v1/mutation-tests/{session_id}/mutations`: Returns all mutations with structured synthetic environment explanations.
- `GET /api/v1/mutation-tests/{session_id}/stream`: Real-time Server-Sent Events (SSE) stream subscribing directly to `EventBus`.

### Dashboard Test Console UI
- **URL**: `http://127.0.0.1:8000/dashboard/mutation-test` (accessible via "Mutation Console" sidebar link).
- **Features**:
  1. **Control Panel**: Test session selector, executable injection trigger, severity pills (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `OBSERVE`), and live expected spec preview card.
  2. **Live Event Console**: Real-time chronological streaming of `RAW`, `SEMANTIC`, `POLICY`, and `MUTATION` events with auto-scroll and pause controls.
  3. **Mutation Inspector**: Selectable mutation cards rendering human-readable synthetic environment breakdowns (Domain Controllers, Chrome credentials, mock SMB shares, C2 sinkholes, Electrum wallets, etc.) and raw `MutationChange` entries.
  4. **Validation Card**: Real-time evaluation of intent matching, policy decision, mutation execution, and latency (`PASS` / `PARTIAL` / `FAILED` / `UNEXPECTED`).

---

## 22. Live Operations & Verification Reference

### Exact QEMU Launch Command (GUI + WHPX + Non-blocking VirtIO Socket)
```powershell
& "C:\Program Files\qemu\qemu-system-x86_64.exe" -m 4096 -smp 4 -accel whpx -rtc base=localtime,clock=host -drive file=C:\ADAM_Sandbox\images\win10-gold.qcow2,format=qcow2 -vga std -display sdl -netdev user,id=net0,hostfwd=tcp:127.0.0.1:8443-:8443 -device e1000,netdev=net0 -chardev socket,id=charmon0,port=8444,host=127.0.0.1,server=on,wait=off -device virtio-serial -device virtserialport,chardev=charmon0,name=adam_stealth_port
```

### Starting the Orchestrator Server
```powershell
python -m uvicorn adam.api.main:app --host 0.0.0.0 --port 8000
```
- **Operator Dashboard**: `http://127.0.0.1:8000/dashboard`
- **Mutation Test Console**: `http://127.0.0.1:8000/dashboard/mutation-test`
- **Continuous Live Session View**: `http://127.0.0.1:8000/dashboard/session/sess_continuous_live`
- **Live Event Feed Ordering**: Unified timeline arranged in reverse-chronological order (latest arrival first, oldest last).
- **Interactive Multi-Select Filters**: Independent toggles for Raw, Semantic, Decisions, and Mutations with persistent colored left accents and white glow states.

### Running Test Suite
```powershell
python -m pytest
```
Runs all 42+ unit tests, policy suppression, cooldown, budget, causal attribution, golden mutation suite, and replay integration tests.

---

## 23. Live Demonstration Commands & Verification Matrix

| Behavior Category | Run in VM (CMD/PowerShell) | Detected Semantic Intent | Policy Action Triggered | Target Verification in VM |
|---|---|---|---|---|
| **Document Discovery** | `cmd.exe /c dir /s /b *.docx` | `COLLECT_DOCUMENTS` (0.88, HIGH) | `PLANT_DECOY_DOCUMENTS` | `Get-Content "$env:USERPROFILE\Documents\payroll_2026.xlsx"` |
| **Crypto Wallet Recon** | `cmd.exe /c dir /s /b *wallet.dat*` | `CRED_WALLET_SEARCH` (0.92, HIGH) | `PLANT_DECOY_WALLET` | `Get-Content "$env:APPDATA\Electrum\wallets\default_wallet"` |
| **SSH Key Harvest** | `cmd.exe /c dir /s /b *id_rsa*` | `CRED_PRIVATE_KEY_SEARCH` (0.90, HIGH) | `PLANT_DECOY_PRIVATE_KEYS` | `Get-Content "$env:USERPROFILE\.ssh\id_rsa"` |
| **Cloud Credentials** | `type "$env:USERPROFILE\.aws\credentials"` | `CRED_CLOUD_CREDENTIAL_SEARCH` (0.95, CRITICAL) | `PLANT_DECOY_CLOUD_CREDENTIALS` | `Get-Content "$env:USERPROFILE\.aws\credentials"` |
| **Domain Recon** | `nltest /dclist:CORP` | `RECON_DOMAIN_CONTROLLER` (0.95, HIGH) | `SPAWN_FAKE_DC_ARTIFACTS` | `Test-Path "C:\Windows\SYSVOL\sysvol\CORP.LOCAL"` |
| **Share Enumeration** | `net view \\127.0.0.1` | `RECON_NETWORK_SHARES` (0.90, HIGH) | `MOUNT_FAKE_NETWORK_SHARE` | `Get-Content "C:\Corporate_Shares\Financials\Q3_Internal_Audit.xlsx"` |
| **Browser Creds Vault** | `type "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"` | `CRED_BROWSER_STORE` (0.88, HIGH) | `INJECT_FAKE_BROWSER_CREDS` | `Get-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"` |
| **Shadow Copy Deletion**| `vssadmin delete shadows /all /quiet` | `IMPACT_SHADOW_COPY_DELETE` (0.98, CRITICAL) | `CREATE_DECOY_RECOVERY_TARGET` | `Get-Item "C:\SystemRecovery\DecoyBackups\shadow_volume_copy_01.vhd"` |

---

## 24. Glossary

| Term | Definition |
|---|---|
| Raw event | One normalized record from one telemetry source. High volume, low meaning |
| Semantic event | Correlated, interpreted statement of malware *intent* with confidence score and phase tagging |
| Fusion | Raw → semantic transformation: normalise, correlate, interpret across sliding time window |
| Policy decision | Rule-derived judgement that a deception should (or should not) be applied |
| Deception primitive | One concrete, revertible environmental modification |
| Mutation | An applied primitive, recorded with latency, plausibility, and structured environment explanation |
| Causal window | Interval after mutation during which subsequent behavior is attributed to it (`caused_by_mutation`) |
| Behavioral yield | Additional behavior in treatment vs. control — the headline metric |
| Plausibility score | Self-assessed likelihood that a mutation is *not* detectable as synthetic |
| Control/Treatment arm | Deception-disabled vs. deception-enabled runs under one experiment_id |
| Replay | Re-running Fusion→Policy→Deception over recorded raw.jsonl with no VM |
| AMTD | Autonomous Moving Target Defense — proactive environment mutation |
| EPT | Extended Page Tables — hardware-assisted memory virtualization |
| SSDT | System Service Descriptor Table — Windows syscall dispatch table |
| DKOM | Direct Kernel Object Manipulation — rootkit technique of unlinking processes |
| CoW | Copy-on-Write — dirty-page tracking for sub-second state restoration |
| DRL | Deep Reinforcement Learning — autonomous sandbox orchestration policy |
| Mutation Test Mode | Isolated session configuration where deterministic research test stimuli are executed |

