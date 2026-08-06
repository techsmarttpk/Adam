# ADAM — Software Architecture Specification

**Adaptive Deception Sandbox for Advanced Malware Analysis**

| Field | Value |
|---|---|
| Document version | 1.0 |
| Status | Phase 1 — Architecture (finalised, pending team sign-off) |
| Target | Final-year engineering project + IEEE-style publication |
| Runtime | Python 3.11 |
| Team size | 4 developers |
| Author | Chief Software Architect |

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Research Positioning](#2-research-positioning)
3. [Architectural Overview](#3-architectural-overview)
4. [Design Principles and Constraints](#4-design-principles-and-constraints)
5. [Component Responsibilities](#5-component-responsibilities)
6. [Data Flow Diagrams](#6-data-flow-diagrams)
7. [Canonical Data Model and JSON Contracts](#7-canonical-data-model-and-json-contracts)
8. [The Event Bus](#8-the-event-bus)
9. [Folder Hierarchy](#9-folder-hierarchy)
10. [Module Ownership](#10-module-ownership)
11. [Inter-Module Communication Rules](#11-inter-module-communication-rules)
12. [Configuration Strategy](#12-configuration-strategy)
13. [Logging Strategy](#13-logging-strategy)
14. [Error Handling Strategy](#14-error-handling-strategy)
15. [Dependency Graph](#15-dependency-graph)
16. [Persistence Model](#16-persistence-model)
17. [Testing Strategy](#17-testing-strategy)
18. [Future Extensibility](#18-future-extensibility)
19. [Architecture Decision Record](#19-architecture-decision-record)
20. [Glossary](#20-glossary)

---

## 1. Purpose and Scope

### 1.1 What this document is

This is the authoritative architectural contract for ADAM. It defines module
boundaries, the data that crosses them, and who owns what. Every implementation
decision in Phase 2 and beyond must be traceable to a section of this document.

### 1.2 What is in scope

- A single-host analysis platform: one orchestrator process on the Linux/Windows
  host, one disposable Windows guest VM under VirtualBox.
- Ingestion of runtime telemetry from Sysmon, ProcMon, and Wireshark.
- Fusion of that telemetry into a semantic event stream.
- Policy-driven, closed-loop mutation of the guest environment during execution.
- Persistence, reporting, and a read-only operator dashboard.

### 1.3 What is explicitly out of scope

- Novel hypervisor or virtualisation work. VirtualBox is a commodity dependency,
  not a contribution.
- Anti-anti-VM hardening beyond a documented baseline. We acknowledge that
  VirtualBox is detectable; the research claim does not depend on evading
  detection.
- Multi-tenant, cloud-scale, or clustered operation. Section 18 shows the seams
  where this could be added; we do not build it.
- Static analysis, unpacking, or signature generation.
- Production security hardening of the API. This is a lab instrument.

### 1.4 Safety boundary

ADAM executes live malware. The architecture treats the guest VM as fully
hostile and the host as the trust boundary.

- The guest network is host-only or fully simulated by default. Internet access
  is opt-in per-session, gated by an explicit config flag, and logged.
- The guest agent channel is one-way-authenticated: the host issues commands,
  the guest never initiates a host-side action beyond posting telemetry.
- No shared folders, no clipboard sharing, no drag-and-drop. Sample transfer is
  by mounted read-only ISO or by the agent channel only.
- Every session ends with a snapshot rollback. Rollback is unconditional and
  happens even when the session errored.

---

## 2. Research Positioning

### 2.1 The gap

Conventional sandboxes (Cuckoo, CAPE, Any.Run, Joe Sandbox) implement an
**open loop**: detonate the sample, observe passively, dump a report. If the
sample looks for a domain controller, a mapped network drive, a cryptocurrency
wallet, or a specific security product and does not find it, the interesting
branch of its code never executes. The report records absence, and absence is
indistinguishable from benignity.

### 2.2 The ADAM claim

ADAM closes the loop. It observes the malware's *search behaviour*, infers
*intent* from correlated low-level events, and **synthesises the environment
the malware is looking for, while the malware is still running**. Execution then
continues down a branch that a passive sandbox would never have reached.

The contribution is therefore three linked mechanisms:

1. **Event Fusion** — many noisy, source-specific, low-level records are
   correlated into a small number of high-confidence *semantic* events that
   describe intent rather than syscalls.
2. **Policy** — a declarative, auditable mapping from semantic intent to
   deception response, with explicit confidence thresholds and budgets.
3. **Adaptive Deception** — targeted, in-flight mutation of the live guest
   environment, and measurement of the behavioural delta that mutation causes.

### 2.3 The measurable result

The metric that makes this publishable is **behavioural yield**: additional
distinct semantic events, API calls, network endpoints, and code paths observed
*after* a mutation, versus a control run of the same sample with deception
disabled.

This requires the architecture to support an **A/B execution mode** as a
first-class feature, not an afterthought. Every session therefore carries a
`deception_enabled` flag, and the Report Generator is required to be able to
diff two sessions of the same sample hash. This constraint is why the session
model in §16 stores control and treatment runs as sibling rows under a shared
`experiment_id`.

### 2.4 Threat to validity the architecture must not hide

A mutation can itself be a detection signal. Registry keys that appear mid-run,
processes that spawn from nowhere, and files with impossible timestamps are all
tells. The Deception Engine is therefore required to record a
**plausibility score** for every mutation it performs, and the report must
surface mutations that are likely to have been detected. Hiding this would
invalidate the results.

---

## 3. Architectural Overview

### 3.1 Layer model

```
┌───────────────────────────────────────────────────────────────────────────┐
│  L5  PRESENTATION          Dashboard (Jinja2)   ·   REST API (FastAPI)    │
├───────────────────────────────────────────────────────────────────────────┤
│  L4  ANALYSIS              Report Generator     ·   Session Orchestrator  │
├───────────────────────────────────────────────────────────────────────────┤
│  L3  RESEARCH CORE         Fusion  →  Policy  →  Deception                │
│      ★ contribution        (the closed adaptive loop lives here)          │
├───────────────────────────────────────────────────────────────────────────┤
│  L2  ACQUISITION           Collectors  ·  Sandbox Controller  ·  Mutators  │
├───────────────────────────────────────────────────────────────────────────┤
│  L1  FOUNDATION            Contracts · Event Bus · Config · Logging · DB  │
└───────────────────────────────────────────────────────────────────────────┘

Dependency direction is strictly downward. L1 imports nothing from L2–L5.
```

### 3.2 Runtime topology

```
   HOST (trusted)                                  GUEST VM (hostile)
 ┌────────────────────────────────────┐         ┌──────────────────────────┐
 │  ADAM Orchestrator Process         │         │  Windows 10 x64          │
 │  (single Python 3.11 process)      │         │                          │
 │                                    │         │  ┌────────────────────┐  │
 │  ┌──────────────────────────────┐  │         │  │  adam_agent.ps1    │  │
 │  │  FastAPI (uvicorn, async)    │  │◀────────┼──┤  telemetry push    │  │
 │  │   /api/*   /dashboard/*      │  │  HTTPS  │  │  command poll      │  │
 │  └──────────────┬───────────────┘  │ host-only└──┬─────────────────┘  │
 │                 │                  │         │     │                    │
 │  ┌──────────────▼───────────────┐  │         │  ┌──▼─────────────────┐  │
 │  │      IN-PROCESS EVENT BUS    │  │         │  │  Sysmon (ETW)      │  │
 │  │      (asyncio pub/sub)       │  │         │  │  ProcMon (/BACKING)│  │
 │  └──┬────┬────┬────┬────┬───────┘  │         │  │  Wireshark/dumpcap │  │
 │     │    │    │    │    │          │         │  └────────────────────┘  │
 │  ┌──▼─┐┌─▼──┐┌▼───┐┌▼──┐┌▼──────┐  │         │                          │
 │  │Fus ││Pol ││Dec ││DB ││Report │  │         │  ┌────────────────────┐  │
 │  │ion ││icy ││ept ││Wtr││ Gen   │  │         │  │  SAMPLE (detonated)│  │
 │  └────┘└────┘└─┬──┘└───┘└───────┘  │         │  └────────────────────┘  │
 │                │                   │         │                          │
 │  ┌─────────────▼────────────────┐  │  VBoxManage / guest agent          │
 │  │  Sandbox Controller          │──┼────────▶│  snapshot · exec · mutate│
 │  └──────────────────────────────┘  │         └──────────────────────────┘
 │                                    │
 │  SQLite  ·  artifacts/  ·  logs/   │
 └────────────────────────────────────┘
```

### 3.3 The closed loop, stated precisely

```
      ┌──────────────────────────────────────────────────────────────┐
      │                                                              │
      ▼                                                              │
 ┌─────────┐   raw    ┌─────────┐  semantic  ┌────────┐  decision ┌──┴─────┐
 │Collector│─────────▶│ Fusion  │───────────▶│ Policy │──────────▶│Deception│
 │  (L2)   │  events  │  (L3)   │   events   │  (L3)  │           │  (L3)   │
 └─────────┘          └─────────┘            └────────┘           └────┬────┘
      ▲                    ▲                                           │
      │                    │                                    mutation│
      │                    │  MutationApplied event                     │
      │                    │  (so fusion can attribute the delta)       │
      │                    └────────────────────────────────────────────┤
      │                                                                 │
      │                     environment changes                         ▼
      └──────────────────── malware reacts ◀──────────────── ┌──────────────┐
                                                             │  GUEST VM    │
                                                             └──────────────┘
```

The critical and easily-missed detail: **the Deception Engine publishes its own
mutation back onto the bus as a first-class event.** Without this, the Fusion
Engine cannot distinguish malware-caused state changes from ADAM-caused state
changes, and the behavioural-yield metric becomes unmeasurable. This is a hard
architectural requirement, not an optimisation.

### 3.4 Latency budget

Deception is only useful if it lands before the malware has moved past the
branch that triggered it. Budget from raw event arrival to mutation visible in
the guest:

| Stage | Budget | Notes |
|---|---|---|
| Collector → bus | ≤ 150 ms | Sysmon ETW tail, batched at 100 ms |
| Fusion correlation | ≤ 50 ms | in-memory sliding window |
| Policy evaluation | ≤ 20 ms | pre-compiled rules, no I/O |
| Deception dispatch | ≤ 30 ms | queue to agent |
| Guest mutation apply | ≤ 250 ms | registry/file write |
| **Total** | **≤ 500 ms** | design target |

Any component that cannot meet its budget must degrade by *dropping* work and
emitting a `BudgetExceeded` diagnostic, never by blocking the pipeline. Fusion
correlation windows are the one place where latency is deliberately traded for
accuracy, and that trade is configurable per rule.

---

## 4. Design Principles and Constraints

### 4.1 Principles

| # | Principle | Enforcement |
|---|---|---|
| P1 | **Contracts before code** | `adam/contracts/` is frozen; changes need a PR reviewed by all four devs |
| P2 | **Modules never import siblings** | Communication is via bus or injected interface only; enforced by import-linter in CI |
| P3 | **Interface-driven** | Every module exposes one ABC; consumers depend on the ABC, never the concrete class |
| P4 | **Pure core, impure edges** | Fusion and Policy are pure functions over events. All I/O lives in Collectors, Deception, DB, API |
| P5 | **Type hints everywhere** | `mypy --strict` on `adam/contracts` and `adam/core`; standard mode elsewhere. CI-blocking |
| P6 | **Fail visible, not silent** | No bare `except`. Every swallow logs with a correlation ID |
| P7 | **Deterministic replay** | Any session's raw event log can be replayed offline through Fusion→Policy without a VM |
| P8 | **Config over code** | No magic numbers, no hardcoded paths, no hardcoded rule thresholds |

### 4.2 Principle P7 deserves emphasis

**Replayability is the single most valuable property in this architecture for a
research project.** Because Fusion and Policy are pure functions over a raw
event stream, the team can:

- Tune correlation rules against a recorded corpus without re-detonating malware
  (which takes 5–15 minutes per run).
- Regression-test policy changes deterministically.
- Let three developers work productively while only one has a working VM.
- Reproduce every figure in the paper from committed artefacts.

The `adam-replay` CLI is therefore a Phase 2 deliverable, not a stretch goal.

### 4.3 Hard constraints

- **C1** — Single orchestrator process. No broker, no microservices. (ADR-001)
- **C2** — SQLite with WAL. One writer task; all other components enqueue.
- **C3** — Python 3.11 minimum (`asyncio.TaskGroup`, `Self`, `tomllib`).
- **C4** — The guest agent is PowerShell 5.1 compatible. No .NET Core assumption.
- **C5** — No component may block the asyncio event loop for more than 10 ms.
  Blocking work goes to `asyncio.to_thread` or a process pool.

---

## 5. Component Responsibilities

Each component below states what it **owns**, what it **must not** do, and the
single ABC it exposes. The "must not" column is where merge conflicts and
architectural drift actually get prevented.

### 5.1 Shared Utilities & Contracts (`adam/contracts`, `adam/common`)

**Owns.** The canonical dataclasses/Pydantic models for every event and message
that crosses a module boundary. Enum definitions. The event bus implementation.
Correlation-ID generation. Time normalisation (all timestamps UTC, ISO-8601,
microsecond precision). Config loading. Logger factory. The exception hierarchy.

**Must not.** Import anything from any other ADAM module. Contain business
logic. Perform I/O other than config file reads.

**Exposes.** `EventBus`, `Settings`, `get_logger()`, `AdamError` hierarchy, and
the contract models.

**Stability.** This is the most-imported and least-changed package in the repo.
Treat every change as a breaking change.

### 5.2 Sandbox Controller (`adam/sandbox`)

**Owns.** The full lifecycle of a guest VM: snapshot restore, boot, readiness
probe, sample injection, detonation, telemetry-collector startup, timed
teardown, snapshot rollback, artefact retrieval. Wraps `VBoxManage` behind an
interface. Owns the guest agent script and the host↔guest command channel.
Owns the retry/timeout semantics for every VM operation.

**Must not.** Interpret telemetry content. Decide what to mutate. Write to the
database directly. Know that a Policy Engine exists.

**Exposes.** `ISandboxController` — `prepare()`, `detonate()`, `apply_mutation()`,
`collect_artifacts()`, `teardown()`.

**Design note.** VM operations are slow (seconds) and flaky. Every method is
async, every method has a timeout from config, and `teardown()` is idempotent
and safe to call from a `finally` block after any failure. The controller is a
finite state machine with explicit states (`COLD`, `RESTORING`, `BOOTING`,
`READY`, `ARMED`, `RUNNING`, `COMPLETED`, `TEARDOWN`, `FAILED`) and illegal
transitions raise `SandboxStateError`. `COMPLETED` exists to distinguish "the
sample has finished executing" from `RUNNING`'s "the sample is executing right
now" -- a distinction that costs nothing today (the FSM's re-arm-only-after-a-
real-restore guarantee holds identically either way) but that later milestones
needing to act only while a sample is genuinely alive (concurrent collector
attachment, in-flight deception mutation) will depend on. `detonate()` moves
`ARMED -> RUNNING` on dispatch and `RUNNING -> COMPLETED` synchronously, right
before returning, so a caller polling `.state` from another task sees an
honest read throughout. `teardown()` remains callable from every state above,
including `COMPLETED`, and always ends in `COLD`.

### 5.3 Collectors (`adam/collectors`)

**Owns.** One adapter per telemetry source. Each adapter tails or parses its
source, normalises records into `RawEvent`, and publishes to the bus. Sysmon
(XML/EVTX), ProcMon (PML→CSV), Wireshark (pcap/tshark JSON), and the guest agent
heartbeat/telemetry endpoint.

**Must not.** Correlate across sources — that is Fusion's job, and this boundary
is the one most likely to be violated. A collector sees only its own source.

**Exposes.** `ICollector` — `start()`, `stop()`, `async iter_events()`.

**Design note.** Sources differ wildly in latency and fidelity. Sysmon is
near-real-time; ProcMon's backing file is only reliably readable after flush;
pcap is post-hoc for full fidelity. The `RawEvent` contract therefore carries
both `observed_at` (when ADAM saw it) and `occurred_at` (source timestamp), and
Fusion orders on `occurred_at`. Mixing these up is the most likely subtle bug in
the project.

### 5.4 Event Fusion Engine (`adam/fusion`) ★

**Owns.** Transformation of the multi-source `RawEvent` stream into
`SemanticEvent`. Three internal stages:

1. **Normalise** — canonicalise paths, resolve PIDs to process identities,
   deduplicate the same action seen by two sources.
2. **Correlate** — maintain a bounded sliding window and a process tree; join
   related raw events (e.g. `CreateFile` + `WriteFile` + `SetFileTime` on one
   handle → one `FILE_DROPPED`).
3. **Interpret** — apply detectors that map correlated clusters to a semantic
   intent with a confidence score and MITRE ATT&CK technique ID.

**Must not.** Decide any response. Touch the VM. Persist anything itself.

**Exposes.** `IFusionEngine` — `ingest(RawEvent)`, and a registry of
`ISemanticDetector` plugins.

**Design note.** The detector registry is the extension point that lets the
Fusion owner add intents without touching engine internals — and lets other
devs contribute detectors without merge conflicts. Every detector is a small
class with `matches()` and `build()`, registered by decorator, unit-testable
against a fixture list of `RawEvent`s with zero infrastructure.

Confidence is not decoration. Policy thresholds key off it, so detectors must
document how their score is derived.

### 5.5 Policy Engine (`adam/policy`) ★

**Owns.** The decision layer. Loads and validates the YAML rule corpus at
startup, compiles it into an evaluable form, and for each `SemanticEvent`
produces zero or more `PolicyDecision`s. Owns rule precedence, cooldowns,
per-session mutation budgets, and the confidence gate.

**Hybrid rule model (as selected).** Rules are authored in YAML. Conditions are
declarative expressions over `SemanticEvent` fields. For conditions the DSL
cannot express, a rule may reference a **registered Python predicate** by name:

```yaml
- id: RULE-014
  when:
    intent: RECON_DOMAIN_CONTROLLER
    confidence_gte: 0.75
    custom: "predicates.repeated_ldap_failure"   # escape hatch
  then:
    action: SPAWN_FAKE_DC_ARTIFACTS
    priority: 80
  budget:
    max_per_session: 1
    cooldown_seconds: 30
```

Predicates live in `adam/policy/predicates/`, are registered by decorator, take
`(event, context) -> bool`, and must be pure and side-effect free. This keeps
95% of the corpus in reviewable YAML (the paper-friendly property) while
preventing the DSL from ballooning into a badly-designed programming language.

**Must not.** Execute anything. Know how a mutation is performed. Import
`adam.deception`.

**Exposes.** `IPolicyEngine` — `evaluate(SemanticEvent) -> list[PolicyDecision]`,
`IRuleLoader`, `IPredicate`.

**Design note.** The engine must be a pure function of (event, session context).
Given identical inputs it produces identical decisions — this is what makes
policy changes reproducible for the paper. Session context (budget consumed,
cooldowns, prior decisions) is passed in explicitly rather than held as hidden
mutable state.

### 5.6 Adaptive Deception Engine (`adam/deception`) ★

**Owns.** Turning a `PolicyDecision` into an actual environmental change.
Maintains the catalogue of deception primitives, each implementing `IDeception`:
fake registry hives, synthetic domain/AD artefacts, decoy documents and wallet
files, fabricated network responses, simulated mapped drives, spoofed running
processes, fake security-product presence, forged browser credential stores.

Owns **plausibility**: consistent fake timestamps, believable file sizes,
internally consistent naming, and a self-assessed `plausibility_score` recorded
with every mutation (see §2.4).

**Must not.** Read policy YAML. Re-evaluate whether a mutation is warranted —
the decision has already been made. Call `VBoxManage` directly; it goes through
`ISandboxController`.

**Exposes.** `IDeceptionEngine` — `execute(PolicyDecision) -> MutationResult`,
and the `IDeception` primitive interface.

**Design note.** Every primitive must implement `revert()` alongside `apply()`.
Snapshot rollback makes revert technically unnecessary for cleanup, but revert
is required for *ablation experiments* — applying a lure, observing, withdrawing
it, and observing again is a strong experimental design that the paper can use.
Building revert in from day one costs little; retrofitting it costs a rewrite.

### 5.7 Database Layer (`adam/db`)

**Owns.** SQLite schema, migrations, the single writer task, and repository
classes. Subscribes to the bus and persists everything asynchronously so no
analysis component ever waits on disk.

**Must not.** Contain analysis logic. Be imported by Fusion or Policy.

**Exposes.** `IRepository` per aggregate: `SessionRepo`, `EventRepo`,
`DecisionRepo`, `MutationRepo`, `ArtifactRepo`.

**Design note.** WAL mode, one writer coroutine draining a bounded queue, batch
commits every N events or T milliseconds. If the queue saturates, the writer
sheds low-value raw events first (they remain in the on-disk JSONL log) and
never sheds decisions or mutations. Raw events are also always written to
`artifacts/<session>/raw.jsonl` — that file, not the database, is the source of
truth for replay.

### 5.8 Backend API (`adam/api`)

**Owns.** The FastAPI application: routers, request/response schemas, dependency
injection wiring, the app lifespan that constructs and starts every component,
and the SSE/WebSocket stream that pushes live events to the dashboard.

**Must not.** Contain analysis logic. Instantiate concrete classes inline —
everything comes from the composition root in `adam/api/deps.py`.

**Exposes.** HTTP surface, versioned under `/api/v1`.

**Design note.** `adam/api/deps.py` is the composition root and the single place
where interfaces are bound to implementations. It is also the file most likely
to conflict across four developers, so it is deliberately kept small,
alphabetically ordered, and one-binding-per-line.

### 5.9 Report Generator (`adam/reporting`)

**Owns.** Turning a completed session into artefacts: an execution timeline, the
decision/mutation ledger, MITRE ATT&CK coverage, IOC extraction, and — the
research-critical piece — the **behavioural yield comparison** between a control
run and a deception-enabled run of the same sample.

**Must not.** Query the VM. Recompute semantics. Read raw events directly
(it consumes persisted semantic events and mutations only).

**Exposes.** `IReportGenerator` — `generate(session_id, format)`; renderers for
HTML (Jinja2), JSON, and Markdown.

**Design note.** The yield comparison is a first-class report type
(`generate_comparison(experiment_id)`), not a bolt-on. It produces the tables
and figures the paper needs, and it should emit machine-readable JSON so figures
can be regenerated from committed data.

### 5.10 Dashboard (`adam/dashboard`)

**Owns.** Jinja2 templates, static assets, and the server-rendered operator UI:
session list, live event feed, decision ledger, mutation timeline, report views.

**Must not.** Contain business logic in templates. Query the database directly —
it consumes the same `/api/v1` surface as any other client.

**Design note.** Server-rendered with a light sprinkle of vanilla JS over SSE.
No SPA framework. A build toolchain would cost the team days and contribute
nothing to the research claim.

---

## 6. Data Flow Diagrams

### 6.1 Session lifecycle (happy path)

```
Operator            API           Orchestrator      Sandbox        Guest VM
   │                 │                 │               │              │
   │ POST /sessions  │                 │               │              │
   ├────────────────▶│                 │               │              │
   │                 │ create_session()│               │              │
   │                 ├────────────────▶│               │              │
   │ 202 + id        │                 │  prepare()    │              │
   │◀────────────────┤                 ├──────────────▶│ restore snap │
   │                 │                 │               ├─────────────▶│
   │                 │                 │               │  boot + probe│
   │                 │                 │               │◀─────────────┤
   │                 │                 │  READY        │              │
   │                 │                 │◀──────────────┤              │
   │                 │                 │ start collectors             │
   │                 │                 ├──────────────▶│─────────────▶│
   │                 │                 │  detonate()   │              │
   │                 │                 ├──────────────▶│─────────────▶│
   │                 │                 │               │   ┌──────────┴──┐
   │  SSE stream     │                 │               │   │ ADAPTIVE    │
   │◀════════════════╪═════════════════╪═══════════════╪══▶│ LOOP  §6.2  │
   │                 │                 │               │   └──────────┬──┘
   │                 │                 │ timeout / idle-quiet          │
   │                 │                 │  collect_artifacts()          │
   │                 │                 ├──────────────▶│◀─────────────┤
   │                 │                 │  teardown()   │  rollback    │
   │                 │                 ├──────────────▶├─────────────▶│
   │                 │                 │ generate_report()            │
   │  GET /report    │                 │               │              │
   ├────────────────▶│                 │               │              │
```

### 6.2 The adaptive loop (inner cycle)

```
 GUEST                    BUS                 FUSION           POLICY        DECEPTION
   │                       │                    │                 │              │
   │ malware queries       │                    │                 │              │
   │ HKLM\...\Domain       │                    │                 │              │
   │──▶ Sysmon ──────────▶ │ RawEvent#41        │                 │              │
   │ malware enumerates    │───────────────────▶│                 │              │
   │ net shares            │                    │ window buffer   │              │
   │──▶ ProcMon ─────────▶ │ RawEvent#42 ──────▶│ correlate       │              │
   │ LDAP to 0 hosts       │                    │                 │              │
   │──▶ Wireshark ───────▶ │ RawEvent#43 ──────▶│                 │              │
   │                       │                    │ ┌─────────────┐ │              │
   │                       │                    │ │ 41+42+43 →  │ │              │
   │                       │                    │ │ RECON_DOMAIN│ │              │
   │                       │                    │ │ conf 0.87   │ │              │
   │                       │                    │ └──────┬──────┘ │              │
   │                       │◀───SemanticEvent───┤        │        │              │
   │                       │─────────────────────────────▶ eval   │              │
   │                       │                    │        │ RULE-014 fires        │
   │                       │                    │        │ conf 0.87 ≥ 0.75 ✓    │
   │                       │                    │        │ budget 0/1  ✓         │
   │                       │◀───PolicyDecision──────────┤         │              │
   │                       │──────────────────────────────────────▶ execute      │
   │                       │                    │        │        │ ┌──────────┐ │
   │◀──────────────────────┼────────────────────┼────────┼────────┼─┤fake DC   │ │
   │  registry + DNS +     │                    │        │        │ │artifacts │ │
   │  fake SYSVOL appear   │                    │        │        │ └──────────┘ │
   │                       │◀──MutationApplied──┼────────┼────────┤              │
   │                       │───────────────────▶│ tag causal window             │
   │                       │                    │ (attribute what follows)      │
   │ malware now takes     │                    │                 │              │
   │ the domain branch:    │                    │                 │              │
   │ lateral movement      │                    │                 │              │
   │──▶ new telemetry ───▶ │ RawEvent#44.. ────▶│ ← BEHAVIOURAL YIELD           │
```

### 6.3 Event transformation pipeline

```
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
  │ Sysmon XML  │   │ ProcMon CSV │   │ pcap/tshark │   │ Agent JSON  │
  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
         │                 │                 │                 │
    ┌────▼─────────────────▼─────────────────▼─────────────────▼────┐
    │  COLLECTORS — parse · schema-map · stamp observed_at          │
    └────────────────────────────┬──────────────────────────────────┘
                                 │  RawEvent  (n ≈ 10⁴–10⁶ / session)
    ┌────────────────────────────▼──────────────────────────────────┐
    │  FUSION · stage 1  NORMALISE                                  │
    │    path canonicalisation · PID→identity · cross-source dedup  │
    ├───────────────────────────────────────────────────────────────┤
    │  FUSION · stage 2  CORRELATE                                  │
    │    sliding window (cfg) · process tree · handle tracking      │
    ├───────────────────────────────────────────────────────────────┤
    │  FUSION · stage 3  INTERPRET                                  │
    │    detector registry → intent · confidence · ATT&CK id        │
    └────────────────────────────┬──────────────────────────────────┘
                                 │  SemanticEvent  (n ≈ 10¹–10³)
                                 │  ~1000:1 reduction
    ┌────────────────────────────▼──────────────────────────────────┐
    │  POLICY   match → gate on confidence → budget → prioritise    │
    └────────────────────────────┬──────────────────────────────────┘
                                 │  PolicyDecision (n ≈ 10⁰–10¹)
    ┌────────────────────────────▼──────────────────────────────────┐
    │  DECEPTION  select primitive → apply → score plausibility     │
    └────────────────────────────┬──────────────────────────────────┘
                                 │  MutationResult → back to bus
                                 ▼
```

### 6.4 Fan-out from the bus

```
                        ┌──────────────────────────┐
                        │       EVENT BUS          │
                        └─┬────┬────┬────┬────┬────┘
       RawEvent ──────────┘    │    │    │    │
                    ┌──────────┘    │    │    └──────────┐
                    │               │    │               │
              ┌─────▼─────┐  ┌──────▼──┐ │        ┌──────▼──────┐
              │  Fusion   │  │ DB Writer│ │        │ SSE / live  │
              └───────────┘  └──────────┘ │        │  dashboard  │
                                          │        └─────────────┘
                                   ┌──────▼──────┐
                                   │  raw.jsonl  │  ← replay source of truth
                                   └─────────────┘
```

---

## 7. Canonical Data Model and JSON Contracts

These schemas are the **frozen boundary**. Fields may be added (backward
compatible); fields may not be removed or retyped without a version bump and
sign-off from all four owners.

Every model is a Pydantic v2 model in `adam/contracts/`, giving free validation,
JSON (de)serialisation, and schema export for the API docs.

### 7.1 Envelope

Every message on the bus is wrapped identically.

```json
{
  "envelope_version": "1.0",
  "message_id": "01J8X4K2M9P3QR7T",
  "message_type": "RawEvent",
  "session_id": "sess_2026_07_21_a3f9",
  "correlation_id": "corr_01J8X4K2M9",
  "emitted_at": "2026-07-21T14:32:11.482913Z",
  "emitter": "collector.sysmon",
  "payload": { }
}
```

`correlation_id` propagates from a raw event through every derived artefact.
It is the thread that lets a mutation in the report be traced back to the exact
Sysmon record that caused it. Losing it breaks the paper's traceability claim.

### 7.2 `RawEvent`

```json
{
  "event_id": "raw_01J8X4K2M9P3QR7T",
  "session_id": "sess_2026_07_21_a3f9",
  "source": "SYSMON",
  "source_event_id": 13,
  "category": "REGISTRY",
  "occurred_at": "2026-07-21T14:32:11.401220Z",
  "observed_at": "2026-07-21T14:32:11.482913Z",
  "process": {
    "pid": 4812,
    "ppid": 2204,
    "image": "C:\\Users\\analyst\\AppData\\Local\\Temp\\sample.exe",
    "command_line": "sample.exe -w hidden",
    "integrity_level": "Medium",
    "user": "WIN10\\analyst",
    "guid": "{a1b2c3d4-0000-0000-0000-000000000001}"
  },
  "attributes": {
    "target_object": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain",
    "details": "QueryValue",
    "result": "NAME_NOT_FOUND"
  },
  "raw_ref": "artifacts/sess_2026_07_21_a3f9/sysmon/000041.xml"
}
```

| Field | Type | Notes |
|---|---|---|
| `source` | enum | `SYSMON` · `PROCMON` · `WIRESHARK` · `AGENT` · `ADAM` |
| `category` | enum | `PROCESS` `FILE` `REGISTRY` `NETWORK` `MODULE` `WMI` `MUTATION` `SYSTEM` |
| `occurred_at` | datetime | source clock, guest-time corrected. **Ordering key.** |
| `observed_at` | datetime | host clock at ingest. Latency measurement only. |
| `attributes` | object | source-specific; deliberately open |
| `raw_ref` | string? | pointer to on-disk original, keeps DB rows small |

### 7.3 `SemanticEvent`

```json
{
  "semantic_id": "sem_01J8X4K3A1",
  "session_id": "sess_2026_07_21_a3f9",
  "correlation_id": "corr_01J8X4K2M9",
  "intent": "RECON_DOMAIN_CONTROLLER",
  "confidence": 0.87,
  "severity": "MEDIUM",
  "window_start": "2026-07-21T14:32:11.401220Z",
  "window_end":   "2026-07-21T14:32:13.902441Z",
  "actor": {
    "pid": 4812,
    "image": "C:\\...\\sample.exe",
    "guid": "{a1b2c3d4-0000-0000-0000-000000000001}"
  },
  "evidence": ["raw_01J8X4K2M9P3QR7T", "raw_01J8X4K2N4", "raw_01J8X4K2P8"],
  "attck": { "tactic": "TA0007", "technique": "T1018" },
  "detector": "DomainReconDetector@1.2",
  "features": {
    "distinct_registry_keys": 3,
    "ldap_attempts": 2,
    "all_failed": true
  },
  "caused_by_mutation": null
}
```

`caused_by_mutation` is the field that makes behavioural yield measurable: when
Fusion produces a semantic event inside the causal window of a mutation, it
records that mutation's ID here. Report Generator counts events where this is
non-null as *deception-attributable behaviour*.

`detector` carries a version suffix so results in the paper can be tied to the
exact detector logic that produced them.

### 7.4 `PolicyDecision`

```json
{
  "decision_id": "dec_01J8X4K3B7",
  "session_id": "sess_2026_07_21_a3f9",
  "correlation_id": "corr_01J8X4K2M9",
  "triggered_by": "sem_01J8X4K3A1",
  "rule_id": "RULE-014",
  "rule_version": "1.0.3",
  "action": "SPAWN_FAKE_DC_ARTIFACTS",
  "verdict": "EXECUTE",
  "priority": 80,
  "parameters": {
    "domain_name": "CORP.LOCAL",
    "dc_hostname": "DC01",
    "netbios": "CORP",
    "populate_sysvol": true
  },
  "rationale": "Domain recon at confidence 0.87 (gate 0.75); budget 0/1 used; no cooldown active.",
  "decided_at": "2026-07-21T14:32:13.921002Z",
  "evaluation_ms": 3.4
}
```

`verdict` ∈ `EXECUTE` · `SUPPRESSED_BUDGET` · `SUPPRESSED_COOLDOWN` ·
`SUPPRESSED_CONFIDENCE` · `SUPPRESSED_CONFLICT` · `DRY_RUN`.

**Suppressed decisions are persisted, not discarded.** They are how the team
tunes thresholds and how the paper reports on policy behaviour. A rule that
fires 400 times and is suppressed 399 times is a finding.

`rationale` is a human-readable string the engine must always populate. It is
what makes the dashboard and the report legible to an examiner.

### 7.5 `DeceptionAction` / `MutationResult`

```json
{
  "mutation_id": "mut_01J8X4K3C2",
  "session_id": "sess_2026_07_21_a3f9",
  "correlation_id": "corr_01J8X4K2M9",
  "decision_id": "dec_01J8X4K3B7",
  "primitive": "FakeDomainControllerDeception@1.0",
  "status": "APPLIED",
  "applied_at": "2026-07-21T14:32:14.118773Z",
  "latency_ms": 197,
  "changes": [
    { "kind": "REGISTRY", "target": "HKLM\\SYSTEM\\...\\Domain", "operation": "SET", "value": "CORP.LOCAL" },
    { "kind": "FILE",     "target": "C:\\Windows\\SYSVOL\\sysvol\\CORP.LOCAL\\", "operation": "CREATE" },
    { "kind": "NETWORK",  "target": "dns:DC01.CORP.LOCAL", "operation": "RESPOND", "value": "10.0.0.10" }
  ],
  "plausibility_score": 0.72,
  "plausibility_notes": "Registry key mtime is post-boot; a timestamp-aware sample could detect this.",
  "revertible": true,
  "causal_window_ms": 30000,
  "error": null
}
```

`status` ∈ `APPLIED` · `PARTIAL` · `FAILED` · `REVERTED` · `SKIPPED`.

`causal_window_ms` tells Fusion how long to attribute subsequent behaviour to
this mutation. It is per-primitive and configurable, because a dropped decoy
file may be opened seconds later while a fake DC may take a minute to matter.

### 7.6 `AnalysisSession`

```json
{
  "session_id": "sess_2026_07_21_a3f9",
  "experiment_id": "exp_lockbit_variant_7",
  "arm": "TREATMENT",
  "sample": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "filename": "invoice_urgent.exe",
    "size_bytes": 284672,
    "file_type": "PE32 executable"
  },
  "config": {
    "deception_enabled": true,
    "policy_ruleset": "rules/default@1.0.3",
    "vm_profile": "win10-x64-office",
    "timeout_seconds": 300,
    "network_mode": "SIMULATED"
  },
  "status": "COMPLETED",
  "started_at": "2026-07-21T14:30:02.000000Z",
  "ended_at":   "2026-07-21T14:35:07.000000Z",
  "metrics": {
    "raw_events": 184203,
    "semantic_events": 47,
    "decisions_total": 12,
    "decisions_executed": 5,
    "mutations_applied": 5,
    "semantic_events_post_mutation": 21
  },
  "error": null
}
```

`arm` ∈ `CONTROL` · `TREATMENT`. Two sessions sharing an `experiment_id` and
differing in `arm` are the unit of comparison for behavioural yield.

### 7.7 Intent taxonomy (initial)

Owned by the Fusion developer, extended by PR. Grouped by tactic.

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

### 7.8 Deception primitive catalogue (initial)

Owned by the Deception developer. Each maps to one or more intents.

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

## 8. The Event Bus

### 8.1 Model

An in-process asyncio publish/subscribe broker in `adam/common/bus.py`.

```python
class EventBus(Protocol):
    def subscribe(self, message_type: type[T], handler: Handler[T],
                  *, name: str, queue_size: int = 1000) -> Subscription: ...
    async def publish(self, message: Message) -> None: ...
    async def start(self) -> None: ...
    async def drain(self, timeout: float) -> None: ...
```

### 8.2 Guarantees and non-guarantees

**Guaranteed.** Per-publisher FIFO ordering. At-most-once delivery. Handler
isolation — an exception in one subscriber never affects another or the
publisher. Bounded memory via per-subscriber queues.

**Not guaranteed.** Cross-publisher global ordering (use `occurred_at`).
Durability (that is `raw.jsonl`'s job). Delivery under backpressure — a full
subscriber queue drops with a counted, logged `QueueOverflow`.

### 8.3 Why drop rather than block

Blocking a collector because the DB writer is slow would corrupt the timing
fidelity of the entire experiment and could let malware outrun the analysis.
Dropping is the correct failure mode for a real-time instrument. Drops are
counted per subscriber and surfaced in session metrics, so a session whose
results are affected by drops is visibly flagged rather than silently wrong.

### 8.4 Subscription map

| Publisher | Message | Subscribers |
|---|---|---|
| Collectors | `RawEvent` | Fusion, DBWriter, RawLogWriter, LiveStream |
| Fusion | `SemanticEvent` | Policy, DBWriter, LiveStream |
| Policy | `PolicyDecision` | Deception, DBWriter, LiveStream |
| Deception | `MutationResult` | Fusion, DBWriter, LiveStream |
| Orchestrator | `SessionLifecycle` | all |

Note the deliberate cycle Fusion → Policy → Deception → Fusion. This is the
adaptive loop and it is *intentional*. It is safe because it passes through the
guest VM and a mutation cannot itself produce a `SemanticEvent` that re-triggers
the same rule within its cooldown. The budget/cooldown mechanism in the Policy
Engine is what formally bounds this loop — that is a primary reason it exists.

---

## 9. Folder Hierarchy

```
project-adam/
├── ARCHITECTURE.md
├── README.md
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── .gitignore
├── .env.example
│
├── config/
│   ├── default.toml                 # base settings, committed
│   ├── development.toml             # overrides
│   ├── production.toml
│   ├── logging.yaml
│   └── vm_profiles/
│       └── win10-x64-office.toml
│
├── rules/
│   ├── default/
│   │   ├── recon.yaml
│   │   ├── credentials.yaml
│   │   ├── persistence.yaml
│   │   ├── evasion.yaml
│   │   └── impact.yaml
│   └── schema/
│       └── rule.schema.json
│
├── adam/
│   ├── __init__.py
│   ├── contracts/                   # ★ FROZEN — all-hands review to change
│   │   ├── __init__.py
│   │   ├── enums.py
│   │   ├── envelope.py
│   │   ├── raw_event.py
│   │   ├── semantic_event.py
│   │   ├── policy_decision.py
│   │   ├── mutation.py
│   │   ├── session.py
│   │   └── interfaces.py            # every ABC/Protocol in one place
│   │
│   ├── common/                      # foundation, imports nothing from adam.*
│   │   ├── __init__.py
│   │   ├── bus.py
│   │   ├── config.py
│   │   ├── logging.py
│   │   ├── errors.py
│   │   ├── ids.py
│   │   ├── timeutil.py
│   │   └── registry.py              # generic plugin registry
│   │
│   ├── sandbox/
│   │   ├── __init__.py
│   │   ├── controller.py
│   │   ├── state.py                 # FSM
│   │   ├── vbox/
│   │   │   ├── __init__.py
│   │   │   ├── client.py            # VBoxManage wrapper
│   │   │   └── snapshot.py
│   │   ├── guest/
│   │   │   ├── __init__.py
│   │   │   ├── channel.py           # host↔guest transport
│   │   │   └── agent/
│   │   │       ├── adam_agent.ps1
│   │   │       ├── install.ps1
│   │   │       └── collectors.ps1
│   │   └── profiles.py
│   │
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py                  # ICollector impl scaffolding
│   │   ├── sysmon.py
│   │   ├── procmon.py
│   │   ├── network.py
│   │   ├── agent.py
│   │   └── parsers/
│   │       ├── __init__.py
│   │       ├── evtx.py
│   │       ├── pml.py
│   │       └── pcap.py
│   │
│   ├── fusion/                      # ★ research core
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── normalise.py
│   │   ├── correlate.py
│   │   ├── window.py
│   │   ├── process_tree.py
│   │   └── detectors/               # one file per intent family
│   │       ├── __init__.py          # registry
│   │       ├── base.py
│   │       ├── recon.py
│   │       ├── credentials.py
│   │       ├── persistence.py
│   │       ├── evasion.py
│   │       ├── impact.py
│   │       └── c2.py
│   │
│   ├── policy/                      # ★ research core
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── loader.py
│   │   ├── compiler.py              # YAML → evaluable form
│   │   ├── conditions.py            # DSL primitives
│   │   ├── budget.py                # budgets + cooldowns
│   │   ├── context.py               # per-session evaluation context
│   │   └── predicates/              # Python escape hatch
│   │       ├── __init__.py          # registry
│   │       └── builtin.py
│   │
│   ├── deception/                   # ★ research core
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── catalogue.py             # registry
│   │   ├── plausibility.py
│   │   └── primitives/              # one file per primitive family
│   │       ├── __init__.py
│   │       ├── base.py
│   │       ├── registry_lures.py
│   │       ├── filesystem_lures.py
│   │       ├── network_lures.py
│   │       ├── process_lures.py
│   │       └── identity_lures.py
│   │
│   ├── orchestrator/
│   │   ├── __init__.py
│   │   ├── session.py               # lifecycle FSM
│   │   └── runner.py
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── connection.py
│   │   ├── writer.py                # single writer task
│   │   ├── schema.sql
│   │   ├── migrations/
│   │   │   └── 0001_initial.sql
│   │   └── repositories/
│   │       ├── __init__.py
│   │       ├── sessions.py
│   │       ├── events.py
│   │       ├── decisions.py
│   │       ├── mutations.py
│   │       └── artifacts.py
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py                  # app factory + lifespan
│   │   ├── deps.py                  # ★ composition root
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── requests.py
│   │   │   └── responses.py
│   │   └── routers/                 # one file per resource
│   │       ├── __init__.py
│   │       ├── health.py
│   │       ├── sessions.py
│   │       ├── events.py
│   │       ├── policy.py
│   │       ├── reports.py
│   │       └── stream.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py
│   │   ├── timeline.py
│   │   ├── yield_analysis.py        # ★ behavioural yield
│   │   ├── ioc.py
│   │   ├── attck.py
│   │   └── renderers/
│   │       ├── __init__.py
│   │       ├── html.py
│   │       ├── json.py
│   │       └── markdown.py
│   │
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── templates/
│   │   │   ├── base.html
│   │   │   ├── sessions.html
│   │   │   ├── session_detail.html
│   │   │   ├── live.html
│   │   │   └── report.html
│   │   └── static/
│   │       ├── css/adam.css
│   │       └── js/live.js
│   │
│   └── cli/
│       ├── __init__.py
│       ├── main.py                  # adam
│       ├── run.py                   # adam run <sample>
│       ├── replay.py                # adam replay <session>
│       └── validate.py              # adam validate-rules
│
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── raw_events/              # recorded corpora, committed
│   │   └── sessions/
│   ├── unit/
│   │   ├── test_contracts/
│   │   ├── test_fusion/
│   │   ├── test_policy/
│   │   ├── test_deception/
│   │   └── test_collectors/
│   ├── integration/
│   │   ├── test_replay_pipeline.py
│   │   └── test_api.py
│   └── e2e/
│       └── test_full_session.py     # requires VM, marked slow
│
├── scripts/
│   ├── setup_vm.md
│   ├── install_sysmon.ps1
│   └── seed_db.py
│
├── docs/
│   ├── adr/
│   ├── developer_guide.md
│   ├── rule_authoring.md
│   └── paper/
│       └── figures/
│
├── artifacts/                       # gitignored, per-session output
├── logs/                            # gitignored
└── samples/                         # gitignored, NEVER committed
```

---

## 10. Module Ownership

### 10.1 Allocation

The split is designed so each developer owns a **vertical slice with a stable
interface at each end**, and so that no two developers routinely edit the same
file.

| Dev | Role | Owns (exclusive write) | Primary deliverable |
|---|---|---|---|
| **A** | Infrastructure & Sandbox | `adam/common/`, `adam/sandbox/`, `adam/collectors/`, `adam/orchestrator/`, `adam/cli/` (except `replay.py`), `config/`, `scripts/` | A VM that boots, detonates, and emits `RawEvent`s |
| **B** | Fusion (research core) | `adam/fusion/`, `tests/fixtures/`, `adam/cli/replay.py` | `RawEvent[] → SemanticEvent[]` with measured precision |
| **C** | Policy & Deception (research core) | `adam/policy/`, `adam/deception/`, `rules/` | `SemanticEvent → PolicyDecision → MutationResult` |
| **D** | Platform & Presentation | `adam/api/`, `adam/db/`, `adam/reporting/`, `adam/dashboard/` | Persistence, REST surface, dashboard, reports |

### 10.2 Shared files and their protocol

Three areas are unavoidably shared. Each has an explicit rule.

| Path | Rule |
|---|---|
| `adam/contracts/` | **Architect-approved PR + all four reviewers.** No exceptions. Additive changes only after the freeze date |
| `adam/api/deps.py` | One binding per line, alphabetical. Each dev adds only their own binding |
| `requirements.txt` | Alphabetical, one per line, pinned. Same reason |
| `tests/conftest.py` | Shared fixtures only; module-specific fixtures live in the module's own conftest |

The alphabetical + one-per-line convention is not cosmetic: it turns almost
every concurrent edit into a non-overlapping diff that git merges automatically.

### 10.3 Why this split minimises conflict

- **Directory-exclusive ownership.** Four people, four disjoint top-level areas.
  The common case is zero overlap.
- **Registry pattern everywhere.** Detectors, predicates, primitives, routers,
  and repositories are all registered by decorator into an auto-discovering
  registry. Adding one means adding a *file*, never editing a central list —
  which is exactly where four-way conflicts normally occur.
- **Contracts frozen early.** The interfaces are agreed in Phase 1, so nobody is
  blocked waiting for someone else's implementation. Each dev codes against the
  ABC and tests against a fake.
- **Fixtures decouple B, C, D from A.** Only Dev A needs a working VM. Once a
  corpus of recorded `RawEvent`s is committed, B, C, and D develop and test
  entirely offline via replay. This is the highest-leverage decision in the plan
  — without it, three developers idle whenever the VM breaks.

### 10.4 Parallelisation plan

```
 WEEK   1     2     3     4     5     6     7     8     9    10    11    12
        │     │     │     │     │     │     │     │     │     │     │     │
 ALL   ╞═ contracts + skeleton ═╡
        │  frozen ▲
 DEV A  ╞══ VBox control ══╪══ collectors ══╪══ agent ══╪═ orchestrator ═╡
        │           corpus ▲ (unblocks B/C/D)
 DEV B        ╞═ fakes ═╪══ normalise ══╪══ correlate ══╪══ detectors ══╡
 DEV C        ╞═ fakes ═╪══ rule DSL ══╪══ primitives ══╪══ tuning ═════╡
 DEV D        ╞═ schema ═╪══ API ══╪══ dashboard ══╪══ reports ══╪ yield ╡
        │                                                   │           │
                                                integration ╞═══════════╡
                                                 experiments ╞══════════╡
```

The one true dependency is Dev A's recorded corpus in week 3. Until it lands,
B, C, and D work against hand-written fixture events — which they should write
anyway, since those become the unit test suite.

---

## 11. Inter-Module Communication Rules

### 11.1 The three permitted mechanisms

1. **Event bus** — for the analysis pipeline. Asynchronous, fire-and-forget,
   one-to-many. This is the default and covers the research core.
2. **Injected interface** — for request/response where a return value is needed
   (Deception → Sandbox, everything → Repository). The consumer receives an ABC
   through its constructor and never constructs the implementation.
3. **HTTP** — only between an external client (including the dashboard) and the
   API. Never internally.

### 11.2 Forbidden

- Importing a sibling module's concrete class. `from adam.fusion.engine import
  FusionEngine` inside `adam/policy/` is a build failure.
- Reaching into another module's database tables.
- Global mutable state, module-level singletons, or service locators.
- Synchronous blocking calls in the pipeline path.

### 11.3 CI enforcement

`import-linter` contracts in `pyproject.toml` encode §15's dependency graph as
layers. A violating import fails the build. This matters more than it sounds:
architectural erosion in student projects is almost always a series of
individually reasonable convenience imports, and the linter is the only thing
that reliably prevents it.

---

## 12. Configuration Strategy

### 12.1 Precedence

```
  CLI flags                    (highest — per-run experiment overrides)
      ▲
  Environment variables        (ADAM__SANDBOX__VM_NAME=win10-b)
      ▲
  config/<environment>.toml    (per-machine, gitignored if it has secrets)
      ▲
  config/default.toml          (committed baseline)
      ▲
  Pydantic Settings defaults   (lowest — always valid)
```

Everything resolves once at startup into a single frozen `Settings` object,
validated by Pydantic. Invalid config fails fast at boot with a readable
message; it never surfaces as a mystery `KeyError` twenty minutes into a
detonation.

### 12.2 Shape

```toml
[sandbox]
vm_name               = "ADAM-WIN10"
snapshot_name         = "clean"
boot_timeout_s        = 120
guest_ready_timeout_s = 150     # added Milestone 4 -- split from boot_timeout_s
                                 # once VM-power-on and Guest-Additions-ready
                                 # proved to be separately timed, separately
                                 # variable phases (see Milestone 3 investigation)
detonation_timeout_s  = 300
network_mode          = "SIMULATED"     # HOST_ONLY | SIMULATED | INTERNET
vbox_manage_path      = "/usr/bin/VBoxManage"
# guest_username / guest_password are intentionally NOT here -- see
# section 12.3. They resolve only from environment variables / .env
# (ADAM__SANDBOX__GUEST_USERNAME, ADAM__SANDBOX__GUEST_PASSWORD).

[fusion]
window_seconds       = 5.0
max_window_events    = 10000
min_confidence_emit  = 0.40
process_tree_depth   = 10

[policy]
ruleset_path            = "rules/default"
global_confidence_gate  = 0.60
max_mutations_per_session = 15
default_cooldown_s      = 20
dry_run                 = false

[deception]
default_causal_window_ms = 30000
plausibility_warn_below  = 0.50
enable_clock_manipulation = false

[bus]
default_queue_size = 1000
overflow_policy    = "DROP_OLDEST"

[db]
path             = "artifacts/adam.sqlite"
batch_size       = 500
batch_interval_ms = 250

[logging]
level      = "INFO"
format     = "json"
directory  = "logs"
```

### 12.3 Rules

- Each module reads only its own section, and receives it as a typed sub-model.
- `dry_run = true` runs the entire pipeline and records decisions with verdict
  `DRY_RUN` without touching the guest. This is the **control arm** of the
  experiment and also the safest way to develop policy.
- Secrets never enter TOML. `.env` only, and `.env` is gitignored. Concrete
  case (Milestone 4): `sandbox.guest_username` / `sandbox.guest_password` are
  required `SandboxSettings` fields with no TOML representation at all --
  they resolve exclusively from `ADAM__SANDBOX__GUEST_USERNAME` /
  `ADAM__SANDBOX__GUEST_PASSWORD`, sourced from real environment variables or
  `.env`. Config loading fails fast with a validation error if neither is
  set, rather than letting `SandboxController` fail later with a confusing
  guest authentication error.

---

## 13. Logging Strategy

### 13.1 Structure

Structured JSON to file, human-readable coloured text to console. Every record
carries `session_id`, `correlation_id`, `component`, and `event` (a stable
snake_case key), so logs can be queried like data rather than grepped like prose.

```json
{
  "ts": "2026-07-21T14:32:13.921Z",
  "level": "INFO",
  "component": "policy.engine",
  "event": "decision_emitted",
  "session_id": "sess_2026_07_21_a3f9",
  "correlation_id": "corr_01J8X4K2M9",
  "rule_id": "RULE-014",
  "verdict": "EXECUTE",
  "evaluation_ms": 3.4
}
```

Context is injected via `contextvars`, so no function needs to thread
`session_id` through its signature.

### 13.2 Levels — with meaning, not vibes

| Level | Meaning | Example |
|---|---|---|
| `DEBUG` | Per-event detail. Off by default; volume is enormous | every `RawEvent` ingested |
| `INFO` | Pipeline milestones and every decision/mutation | `decision_emitted`, `mutation_applied` |
| `WARNING` | Degraded but valid results | `queue_overflow`, `budget_exceeded`, `low_plausibility` |
| `ERROR` | A component failed; session continues degraded | `collector_crashed` |
| `CRITICAL` | Session cannot continue | `vm_unreachable`, `rollback_failed` |

### 13.3 Log streams

| Stream | Path | Purpose |
|---|---|---|
| Application | `logs/adam.jsonl` | rotating, all components |
| Per-session | `artifacts/<sid>/session.jsonl` | everything for one run, self-contained |
| Raw events | `artifacts/<sid>/raw.jsonl` | replay source of truth, never rotated |
| Audit | `logs/audit.jsonl` | every mutation applied to a guest, append-only |

The audit stream exists because ADAM deliberately modifies a system running live
malware. An append-only record of exactly what ADAM changed, when, and why is
both a safety requirement and a research artefact.

### 13.4 Sensitive data

Sample file contents are never logged, only hashes and paths. Extracted strings
are truncated to a configured length. Fake credentials generated by the
Deception Engine are logged in full and clearly tagged `synthetic: true` — they
are experimental data, and confusing them for real credentials later would be
its own problem.

---

## 14. Error Handling Strategy

### 14.1 Exception hierarchy

```
AdamError
├── ConfigError              invalid or missing configuration
├── ContractViolationError   a message failed schema validation
├── SandboxError
│   ├── VMOperationError     VBoxManage failed
│   ├── SandboxStateError    illegal FSM transition
│   ├── GuestTimeoutError    guest unresponsive
│   └── SampleTransferError
├── CollectorError
│   ├── ParserError          malformed source record
│   └── SourceUnavailableError
├── FusionError
│   └── DetectorError        a single detector raised
├── PolicyError
│   ├── RuleSyntaxError      caught at load, not at runtime
│   ├── RuleCompilationError
│   └── PredicateError
├── DeceptionError
│   ├── PrimitiveError
│   └── MutationFailedError
├── PersistenceError
└── ReportingError
```

### 14.2 The governing principle: degrade, don't abort

A malware detonation is expensive and unrepeatable in its exact timing. Throwing
away a session because one detector raised on one event is unacceptable. The
policy is therefore graduated by component:

| Failure | Response | Session outcome |
|---|---|---|
| One detector raises | Log `ERROR`, skip that detector for that event, continue | Complete, flagged |
| One collector dies | Log `ERROR`, mark source degraded, continue with remaining sources | Complete, `degraded_sources` recorded |
| A mutation fails | Record `MutationResult` with `status=FAILED`, continue | Complete; failed mutation is itself data |
| Bus queue overflows | Drop, count, log `WARNING` | Complete, drop count in metrics |
| DB write fails | Retry ×3, then buffer to disk, then shed | Complete; `raw.jsonl` remains authoritative |
| Rule file invalid | **Refuse to start** | Never begins |
| VM unreachable at start | **Refuse to start** | Never begins |
| VM lost mid-run | Abort, force rollback, mark `PARTIAL`, report what was captured | Partial |
| Rollback fails | `CRITICAL`, quarantine the VM, block further sessions | Aborted + operator alert |

The asymmetry is deliberate: **be permissive at runtime, strict at startup.**
Configuration and rule errors are cheap to catch before a detonation and
catastrophic to discover during one.

### 14.3 Isolation mechanics

- Every bus handler is wrapped so an exception is logged and contained; the
  publisher never sees it.
- Every detector, predicate, and primitive call is individually guarded. A
  contributed component cannot take down the pipeline.
- Repeated failure trips a **circuit breaker**: after N failures a detector or
  primitive is disabled for the remainder of the session and the fact is
  recorded in session metrics, so a silently-broken component shows up in the
  report rather than corrupting a week of results.

### 14.4 Guaranteed cleanup

Session teardown runs in a `finally` block under `asyncio.TaskGroup`. Snapshot
rollback is unconditional, idempotent, and independently retried. A session that
errored still produces a report — marked `PARTIAL`, with the error recorded.
Partial results are still evidence.

---

## 15. Dependency Graph

### 15.1 Layered view

```
 LAYER 5   ┌──────────────┐   ┌──────────────┐
           │  dashboard   │   │     cli      │
           └──────┬───────┘   └──────┬───────┘
                  │                  │
 LAYER 4   ┌──────▼──────────────────▼───────┐
           │              api                │
           └──┬────────┬─────────┬───────┬───┘
              │        │         │       │
 LAYER 3   ┌──▼──────┐ │  ┌──────▼────┐  │
           │reporting│ │  │orchestrator│ │
           └──┬──────┘ │  └──┬────┬───┘  │
              │        │     │    │      │
 LAYER 2   ┌──▼────┐ ┌─▼──┐┌─▼───┐│ ┌────▼─────┐
           │  db   │ │fus ││poli ││ │deception │
           │       │ │ion ││ cy  ││ └────┬─────┘
           └──┬────┘ └─┬──┘└──┬──┘│      │
              │        │      │   │      │
 LAYER 1.5    │        │      │ ┌─▼──────▼───┐  ┌────────────┐
              │        │      │ │  sandbox   │◀─┤ collectors │
              │        │      │ └─────┬──────┘  └─────┬──────┘
              │        │      │       │               │
 LAYER 1   ┌──▼────────▼──────▼───────▼───────────────▼──────┐
           │           common   (bus, config, log, errors)   │
           ├────────────────────────────────────────────────┤
           │           contracts   (models, ABCs)  ★ FROZEN  │
           └────────────────────────────────────────────────┘

  Arrows = "imports". All arrows point downward. Zero cycles at import time.
```

### 15.2 The one apparent cycle, resolved

Fusion → Policy → Deception → Fusion exists at **runtime**, via the bus, and via
the guest VM. It does not exist at **import time**: no module in that chain
imports another. Each publishes to and subscribes from `adam.common.bus` using
types from `adam.contracts`. This is exactly the decoupling the bus was chosen
to provide.

### 15.3 Third-party dependencies

| Package | Used by | Purpose |
|---|---|---|
| `fastapi`, `uvicorn[standard]` | api | HTTP + SSE |
| `pydantic`, `pydantic-settings` | contracts, common | models, validation, config |
| `jinja2` | dashboard, reporting | templating |
| `pyyaml` | policy | rule corpus |
| `aiosqlite` | db | async SQLite |
| `python-evtx`, `lxml` | collectors | Sysmon EVTX/XML |
| `scapy` *or* `tshark` subprocess | collectors | pcap |
| `structlog` | common | structured logging |
| `httpx` | sandbox | guest agent channel |
| `typer`, `rich` | cli | CLI + console output |

Dev-only: `pytest`, `pytest-asyncio`, `pytest-cov`, `mypy`, `ruff`,
`import-linter`, `hypothesis`.

Deliberately excluded: Celery, Redis, RabbitMQ, SQLAlchemy, Alembic, React,
Node. Each would add operational weight without advancing the research claim.
Raw SQL against SQLite is faster to reason about at this scale than an ORM, and
the schema is small enough that hand-written migrations are honest.

---

## 16. Persistence Model

### 16.1 Schema

```
experiments ──1:N── sessions ──┬──1:N── raw_events        (metadata only)
                               ├──1:N── semantic_events
                               ├──1:N── decisions
                               ├──1:N── mutations
                               ├──1:N── artifacts
                               └──1:1── session_metrics

  semantic_events.evidence   → raw_events        (JSON array of ids)
  decisions.triggered_by     → semantic_events
  mutations.decision_id      → decisions
  semantic_events.caused_by_mutation → mutations  (nullable — the yield link)
```

### 16.2 What lives where

| Data | Store | Rationale |
|---|---|---|
| Raw event **bodies** | `artifacts/<sid>/raw.jsonl` | 10⁵–10⁶/session; SQLite would bloat and slow |
| Raw event **metadata** | SQLite | indexed for timeline queries |
| Semantic events, decisions, mutations | SQLite | low volume, high query value |
| Sample binaries | `samples/`, gitignored | never in the DB, never in git |
| pcap, memory dumps, screenshots | `artifacts/<sid>/` | referenced by path |
| Reports | `artifacts/<sid>/report.*` | regenerable |

### 16.3 Indices

`sessions(experiment_id, arm)`, `semantic_events(session_id, window_start)`,
`semantic_events(session_id, caused_by_mutation)`, `decisions(session_id,
rule_id)`, `mutations(session_id, decision_id)`, `raw_events(session_id,
occurred_at)`.

The `caused_by_mutation` index exists specifically to make the behavioural yield
query cheap, since it runs for every comparison report and every figure.

---

## 17. Testing Strategy

### 17.1 Pyramid

| Tier | Scope | Speed | Needs VM | Owner |
|---|---|---|---|---|
| Unit | one class, fakes for all collaborators | ms | no | each dev |
| Contract | every model round-trips JSON; every ABC has a fake | ms | no | shared |
| Replay integration | `raw.jsonl` → Fusion → Policy → Deception (dry-run) | s | **no** | B + C |
| API integration | FastAPI TestClient over a temp DB | s | no | D |
| End-to-end | real VM, real sample, full session | min | yes | A |

### 17.2 Replay is the workhorse

The replay tier is where the research is actually validated. A committed corpus
of recorded sessions lets the team assert, deterministically and in seconds:

- Detector precision/recall against hand-labelled ground truth.
- That a rule change produces exactly the expected decision diff.
- That the pipeline meets its latency budget under realistic event volume.

These are also the numbers the paper reports. Making them a CI-run test rather
than a manual measurement is the difference between reproducible results and
remembered ones.

### 17.3 Standards

- Coverage gates: 90% on `contracts`, 85% on `fusion` and `policy`, 70%
  elsewhere. The gate is highest where the contribution is.
- `hypothesis` property tests on contract serialisation and on the correlation
  window (never exceeds bounds, never reorders on `occurred_at`).
- No test may require network access or a real sample.
- E2E tests are marked `@pytest.mark.slow` and excluded from the default run.

---

## 18. Future Extensibility

Each item names the seam that already exists, so none of these requires
re-architecting.

| Extension | Seam | Work required |
|---|---|---|
| New telemetry source (ETW, AMSI, kernel driver) | `ICollector` + registry | one new file |
| New semantic intent | `ISemanticDetector` + registry | one detector file + fixtures |
| New deception primitive | `IDeception` + catalogue | one primitive file + rule |
| ML-based intent inference | replace/augment stage 3 behind `ISemanticDetector` | model wrapper; contracts unchanged |
| Learned policy (RL over deception choice) | `IPolicyEngine` is an interface; suppressed-decision history is already persisted as training data | new engine implementation |
| Multi-VM / parallel sessions | orchestrator is per-session already; bus becomes per-session | session-scoped bus, VM pool |
| Distributed deployment | swap `EventBus` for a Redis/NATS-backed implementation | one class; no module changes (ADR-001 was chosen with this exit in mind) |
| Different hypervisor (QEMU/KVM, VMware) | `ISandboxController` | one implementation |
| Linux guest analysis | new controller + collectors; contracts are OS-agnostic by design | new profile + collectors |
| PostgreSQL backend | `IRepository` per aggregate | new repository implementations |
| STIX/MISP export | new renderer | one renderer file |

### 18.1 The most valuable near-term extension

Learned policy. Because every decision — **including suppressed ones** — is
persisted with its full rationale, confidence, and downstream behavioural
outcome, the system generates a labelled dataset of
`(semantic context, action taken, behavioural yield)` tuples as a *side effect
of normal operation*. That dataset is the natural second paper, and the
architecture produces it for free from day one. This is the main reason §7.4
mandates persisting suppressed decisions rather than discarding them.

---

## 19. Architecture Decision Record

### ADR-001 — In-process asyncio event bus

**Decision.** Modules communicate through an in-process async pub/sub bus rather
than a message broker or internal HTTP.

**Rationale.** The team is four people with one project. A broker adds
infrastructure to install, run, monitor, and debug, and would consume time that
belongs to the research core. The bus gives the same decoupling — publishers do
not know subscribers, and everything crosses a JSON-validated contract — with
zero operational cost. Latency stays well inside the 500 ms budget.

**Consequences.** Single process, so a hard crash loses the session (mitigated:
`raw.jsonl` is written continuously and sessions are replayable). Scaling beyond
one host requires swapping the bus implementation — which is a single class
behind a Protocol, deliberately.

**Rejected.** Redis/RabbitMQ (operational overhead); internal REST (latency and
boilerplate on a hot path).

### ADR-002 — Hybrid YAML + Python predicate policy

**Decision.** Rules are YAML; complex conditions call registered Python
predicates by name.

**Rationale.** A declarative corpus is auditable, diff-friendly, publishable as
a paper artefact, and editable without touching Python — so one developer can
own the rule corpus with near-zero merge conflicts. But every pure-DSL rules
engine eventually grows loops and arithmetic and becomes a poorly-specified
language. The named-predicate escape hatch caps that growth: complex logic goes
into tested Python, and the YAML stays simple on purpose.

**Consequences.** Two places to look when debugging a rule. Mitigated by
requiring predicates to be pure, and by `PolicyDecision.rationale` naming any
predicate that participated.

### ADR-003 — Mutations are published as events

**Decision.** The Deception Engine publishes `MutationResult` back onto the bus,
and Fusion consumes it.

**Rationale.** Without it, ADAM cannot distinguish behaviour caused by malware
from behaviour caused by ADAM, and behavioural yield — the central metric —
becomes unmeasurable. It also gives the dashboard a live mutation timeline for
free.

**Consequences.** A runtime cycle in the bus graph. Bounded by policy cooldowns
and per-session budgets.

### ADR-004 — Fusion and Policy are pure

**Decision.** No I/O in `adam/fusion/` or `adam/policy/`. Session state is passed
in explicitly.

**Rationale.** Purity is what makes replay possible, and replay is what makes
the results reproducible and the team parallel. It also makes these two
modules — the ones carrying the contribution — trivially unit-testable.

**Consequences.** Some parameter-passing verbosity. Worth it.

### ADR-005 — Raw events to JSONL, not SQLite

**Decision.** Raw event bodies go to append-only JSONL; SQLite holds metadata.

**Rationale.** 10⁵–10⁶ rows per session would make SQLite the bottleneck for
data that is almost never queried individually. JSONL appends are cheap, stream
well, compress well, and are the natural replay format.

**Consequences.** Two stores to keep consistent. Resolved by declaring JSONL
authoritative for raw events.

---

## 20. Glossary

| Term | Definition |
|---|---|
| **Raw event** | One normalised record from one telemetry source. High volume, low meaning |
| **Semantic event** | A correlated, interpreted statement of malware *intent* with a confidence score |
| **Fusion** | Raw → semantic transformation: normalise, correlate, interpret |
| **Policy decision** | A rule-derived judgement that a deception should (or should not) be applied |
| **Deception primitive** | One concrete, revertible environmental modification |
| **Mutation** | An applied primitive, recorded with latency and plausibility |
| **Causal window** | The interval after a mutation during which subsequent behaviour is attributed to it |
| **Behavioural yield** | Additional behaviour observed in a treatment run versus its control — the headline metric |
| **Plausibility score** | Self-assessed likelihood that a mutation is *not* detectable as synthetic |
| **Control / Treatment arm** | Deception-disabled vs deception-enabled runs of one sample under one `experiment_id` |
| **Replay** | Re-running Fusion→Policy→Deception over a recorded `raw.jsonl` with no VM |

---

## Sign-off

Phase 1 is complete when all four developers have reviewed this document and
`adam/contracts/` is agreed. **The contracts freeze is the gate for Phase 2** —
skeleton generation should not begin until the schemas in §7 are accepted,
because every placeholder file in the repository is shaped by them.

| Reviewer | Role | Status |
|---|---|---|
| Dev A | Infrastructure & Sandbox | ☐ |
| Dev B | Fusion | ☐ |
| Dev C | Policy & Deception | ☐ |
| Dev D | Platform & Presentation | ☐ |

**Next.** On approval, Phase 2 generates the repository skeleton described in
§9: folder hierarchy, `__init__.py` files, ABCs from §7 and `interfaces.py`,
docstring-only placeholder classes, config files, logging setup, README,
`.gitignore`, and `requirements.txt` — with no business logic.
