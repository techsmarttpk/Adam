# Remaining Work Plan

Derived entirely from `docs/implementation-audit.md`. Historical Milestone numbering (1–4) is ignored; ordering below is based purely on the audit's documented dependency evidence, blockers, and architecture cross-references. This is a planning document only — nothing described here has been implemented, and no repository files were modified in producing it.

Effort is given as a rough size (S / M / L / XL), not hours — the audit contains no basis for time estimates, and fabricating precision would violate its own "do not guess" standard.

---

## Immediate (must do now)

These are the items the audit names as currently, structurally blocking future work — not just valuable, but load-bearing.

### 1. Build `adam/contracts/` (Phase 2 — Contracts)

- **Priority:** Critical
- **Effort:** L — five files (`envelope.py`, `raw_event.py`, `session.py`, `enums.py`, `interfaces.py`), each shape fully specified in `ARCHITECTURE.md` §7.1–§7.6, plus the four-developer review process §10.2 requires before freeze.
- **Dependencies:** None. This is the one remaining phase with zero code prerequisites — every shape it needs is already fully specified in the frozen architecture document.
- **Why it's needed:** The audit names this as "the single most consequential gap" and "the shared, frozen boundary every other phase from 4 onward is specified to be built against." `Phase 4 has already proceeded without it,` meaning `SandboxController`'s claimed interface conformance is currently prose, not a checkable fact.
- **Files to create:** `adam/contracts/envelope.py`, `adam/contracts/raw_event.py`, `adam/contracts/session.py`, `adam/contracts/enums.py`, `adam/contracts/interfaces.py`
- **Risk:** Low technical risk (nothing to design, only to encode). **High process risk** if the §10.2 four-reviewer freeze step is skipped — the roadmap itself calls this "the one phase where 'done' means 'reviewed,' not just 'passes locally.'"

### 2. Reconcile `SandboxController` against `ISandboxController`

- **Priority:** Critical
- **Effort:** S–M — signature change plus one stub method.
- **Dependencies:** Item 1.
- **Why it's needed:** The audit is explicit that `detonate()`'s current signature (`guest_target_path: str`, returns `VMOperationResult`) will not satisfy `ISandboxController` (`sample: SampleRef`, returns `None`) once that Protocol is real code, and that "every additional phase built on top of the current `SandboxController` without first resolving Phase 2 compounds this gap." Doing this immediately after item 1 prevents that compounding.
- **Files to modify:** `adam/sandbox/controller.py` (change `detonate()`'s parameter to the real sample-reference type; add `apply_mutation()` as a stub — see Next, item 10, for full treatment); `scripts/manual_test_sandbox_controller.py` (update the call site to match).
- **Risk:** Medium — changes the signature of the most real-VM-tested method in the codebase. Every existing caller (currently just the manual test script) must move in lockstep.

### 3. `adam/common/bus.py` — `EventBus`

- **Priority:** Critical
- **Effort:** M — four methods per §8.1, but the guarantees in §8.2 (per-publisher FIFO, handler isolation, bounded per-subscriber queues) and §8.3 (drop-and-count under backpressure) need to be genuinely correct, not just present.
- **Dependencies:** None technically; sequencing after item 1 means bus messages can be typed against real contract models from the start instead of `Any`.
- **Why it's needed:** Named explicitly in the audit's "Current Blockers" section as blocking Phase 7 (collectors have nothing to publish to) and Phase 8 (`SessionLifecycle` events have no transport).
- **Files to create:** `adam/common/bus.py`
- **Risk:** Low — self-contained, fully specified, nothing existing depends on working around its absence.

---

## Next (becomes available immediately after Immediate)

High-value, low-blocker items that either close disclosed technical debt or complete phases the audit already scored as partially done, without waiting on anything beyond the Immediate bucket.

### 4. `adam/common/errors.py` — `AdamError` hierarchy

- **Priority:** High
- **Effort:** S — the hierarchy is fully enumerated in §14.1; the work is re-parenting three existing exception classes, not designing a new one.
- **Dependencies:** None blocking.
- **Why it's needed:** `VBoxCommandError`, `SandboxStateError`, and `SandboxOperationError` all explicitly self-document (per the audit's Deviations sections) that they need to fold into this hierarchy once it exists — three disclosed TODOs sitting in production code today.
- **Files to modify:** new `adam/common/errors.py`; `adam/sandbox/vbox/client.py` (re-parent `VBoxCommandError`); `adam/sandbox/state.py` (re-parent `SandboxStateError`, `SandboxOperationError`).
- **Risk:** Low if done as a pure re-parent — existing `except VBoxCommandError:` clauses in the manual test scripts match by class identity, not by hierarchy, so they keep working unchanged as long as class names are preserved.

### 5. `adam/common/logging.py` + `config/logging.yaml`

- **Priority:** High
- **Effort:** M — structured JSON-to-file plus coloured console output per §13.1, `contextvars`-based `session_id`/`correlation_id` injection.
- **Dependencies:** None blocking.
- **Why it's needed:** Directly retires the `TEMPORARY DIAGNOSTIC` print-block still live in `wait_for_guest_ready()` — the audit names this file and function by name as debt "explicitly commented as needing removal... once real structured logging lands."
- **Files to create:** `adam/common/logging.py`, `config/logging.yaml`. **Files to modify:** `adam/sandbox/vbox/client.py` (replace the diagnostic `print()` block with `get_logger(...)` calls).
- **Risk:** Low.

### 6. `adam/common/ids.py` and `adam/common/timeutil.py`

- **Priority:** Medium
- **Effort:** S — a `new_id(prefix)` generator and a `utcnow()` wrapper.
- **Dependencies:** None blocking; needed before anything constructs real `RawEvent`/`AnalysisSession` instances (Phase 7, Phase 8).
- **Why it's needed:** Both are named, unmet Phase 1 requirements. The audit's Phase 1 assessment states "ID generation, time utilities... are entirely unbuilt," and nothing currently generates IDs or timestamps in a standardized way since nothing instantiates contract models yet.
- **Files to create:** `adam/common/ids.py`, `adam/common/timeutil.py`
- **Risk:** Low.

### 7. `adam/sandbox/vbox/snapshot.py` — `SnapshotManager`

- **Priority:** Medium
- **Effort:** S — mostly extracting logic already working inside `SandboxController.prepare()` into its own `ensure_clean()` method.
- **Dependencies:** None.
- **Why it's needed:** Phase 3's intended two-layer split (`VBoxClient` primitives + `SnapshotManager` convenience layer) was never built; "snapshot discipline" currently lives inside the FSM controller rather than as its own reusable unit, per the audit's Phase 3 Overall Assessment.
- **Files to create:** `adam/sandbox/vbox/snapshot.py`. **Files to modify (optional):** `adam/sandbox/controller.py`, if `prepare()` is updated to call `ensure_clean()` instead of raw `restore_snapshot`.
- **Risk:** Low — refactor of already-working, already-tested logic; no behavior change required.

### 8. `take_snapshot()` and `is_running()` on `VirtualBoxClient`

- **Priority:** Low
- **Effort:** S — each is a thin wrapper matching the pattern every other method in the class already uses.
- **Dependencies:** None.
- **Why it's needed:** Named, unmet Phase 3 interfaces. `take_snapshot`'s absence specifically means the `clean` baseline can only ever be created by hand today.
- **Files to modify:** `adam/sandbox/vbox/client.py`
- **Risk:** Low.

### 9. `adam/sandbox/profiles.py` — `VMProfile`, `config/vm_profiles/win10-x64-office.toml`

- **Priority:** Medium
- **Effort:** M — requires deciding how `VMProfile` relates to the already-built `SandboxSettings` (most likely `SandboxSettings` gains a `vm_profile: str` field `VMProfile` resolves against).
- **Dependencies:** None blocking; touches the already-stable `adam/common/config.py`.
- **Why it's needed:** The architecture's intended separation — general sandbox settings vs. a named, swappable VM hardware/OS profile — is currently conflated into one flat `SandboxSettings`, per the audit's Phase 4 Missing section.
- **Files to create:** `adam/sandbox/profiles.py`, `config/vm_profiles/win10-x64-office.toml`. **Files to modify:** possibly `adam/common/config.py`, `adam/sandbox/controller.py`.
- **Risk:** Low if additive (doesn't require breaking `SandboxSettings`'s current shape).

### 10. `apply_mutation()` stub on `SandboxController`

- **Priority:** Low
- **Effort:** S — add the method per `ISandboxController`'s signature; return/raise a not-yet-implemented placeholder until the Deception Engine (Dev C, outside this roadmap) exists.
- **Dependencies:** Item 1 (needs the real `ISandboxController` signature to conform to).
- **Why it's needed:** The audit specifically flags this as the one part of `ISandboxController` whose absence is *not* self-documented anywhere in the code today, unlike `collect_artifacts()` — closing the stub removes the one undisclosed gap.
- **Files to modify:** `adam/sandbox/controller.py`
- **Risk:** Low.

### 11. `CollectorSettings` sub-model

- **Priority:** Low
- **Effort:** S
- **Dependencies:** None blocking; best sequenced just ahead of Phase 7 starting.
- **Why it's needed:** Named roadmap requirement alongside `SandboxSettings` (Phase 1), currently entirely absent.
- **Files to modify:** `adam/common/config.py`
- **Risk:** Low.

### 12. `adam/common/registry.py` — generic `Registry[T]`

- **Priority:** Low
- **Effort:** S
- **Dependencies:** None.
- **Why it's needed:** Named Phase 1 requirement, described as "used by later collector/detector/primitive registries across the whole team" — higher-value for Devs B/C/D's modules than for Dev A's own remaining phases, but cheap to build now while `adam.common` is already open.
- **Files to create:** `adam/common/registry.py`
- **Risk:** Low.

### 13. Phase 6 verification gaps that don't require Phase 5

- **Priority:** Medium
- **Effort:** S
- **Dependencies:** None — these test the *existing* `arm()`/`copy_to_guest` mechanism, not a rebuilt one.
- **Why it's needed:** Two of Phase 6's three roadmap manual-testing steps are unverified per the audit and don't actually require the ISO/agent rework to attempt: (a) demonstrate a config-driven timeout forcibly terminating a long-running benign binary *through `SandboxController.detonate()`* specifically, not just at the `VirtualBoxClient.run_in_guest` layer where it's currently proven; (b) run the full cycle twice and diff guest disk state across the two runs.
- **Files to modify:** `adam/sandbox/controller.py` (if wiring `detonate()`'s timeout to a `Settings` field), `scripts/manual_test_sandbox_controller.py` (add both missing scenarios).
- **Risk:** Low.

**Not planned, by design:** the audit explicitly assesses `SandboxController`'s lack of a standalone `_transition()` method as a *harmless* deviation (the same safety guarantee is achieved a different way via `_require_state()`), and `VMOperationError` as fully addressed by item 4's error-hierarchy work rather than needing its own task. Both are called out here so they aren't mistaken for overlooked gaps.

---

## Later (depends on collectors/orchestrator/agent/etc.)

### 14. Phase 5 — Guest Agent & HTTP Channel

- **Priority:** Critical (within this bucket — everything else here cascades from it)
- **Effort:** XL — a PowerShell HTTP listener with four endpoints (`heartbeat`, `execute-sample`, `start-collectors`, `fetch-artifacts`), an install/auto-start script, and a full `httpx`-based async client. The audit calls this "a substantial piece of remaining work... not a minor gap." This is the single largest remaining phase.
- **Dependencies:** Items 1 (contracts, for typing `CommandResult`-equivalent data) and 3 (bus, if agent telemetry should publish through it) should already be in place; otherwise self-contained.
- **Why it's needed:** Named blocker for an architecture-compliant Phase 6 completion and for Phase 7's `AgentCollector`. The current `guestcontrol`-based substitute is explicitly labeled temporary in the code, with an explicit instruction not to extend it further.
- **Files to create:** `adam/sandbox/guest/agent/adam_agent.ps1`, `.../install.ps1`, `.../collectors.ps1`, `adam/sandbox/guest/channel.py`. **Files to modify:** `requirements.txt` (add `httpx`), `adam/sandbox/controller.py` (switch `arm()`/`detonate()`/`prepare()`'s guest-communication calls from `VirtualBoxClient.run_in_guest`/`wait_for_guest_ready`/`copy_to_guest` to `GuestChannel`).
- **Risk:** High — this replaces the guest-communication mechanism that everything currently proven (Phases 3, 4, 6) is built on top of. It is the point in this plan most likely to surface regressions in code that has otherwise been the most solid part of the project.

### 15. Phase 6 true completion — ISO-based sample injection

- **Priority:** High
- **Effort:** M — an ISO-build helper script plus rewiring `arm()` to a mount-and-detect flow instead of `copyto`.
- **Dependencies:** Item 14 — the agent must exist to detect mounted media and signal readiness, per environment-checklist item 13's design.
- **Why it's needed:** Closes the specific, repeatedly-flagged architectural deviation the audit surfaces in three separate phase sections: `arm()`'s `copy_to_guest` as "a deliberate, temporary stand-in for the ISO-mount transfer path described in the roadmap doc."
- **Files to create:** an ISO-build helper under `scripts/`. **Files to modify:** `adam/sandbox/controller.py` (`arm()`).
- **Risk:** Medium — changes a currently-working, tested code path.

### 16. Phase 7 — Collectors

- **Priority:** Critical (within this bucket)
- **Effort:** XL — five collector classes plus three format-specific parsers (EVTX, PML→CSV, pcap), each with real-world parsing edge cases.
- **Dependencies:** Items 1 and 3 at minimum, for `SysmonCollector`/`ProcmonCollector`/`NetworkCollector`. Item 14 additionally, specifically for `AgentCollector`.
- **Why it's needed:** Named blocker for Phase 8 and Phase 9. Also explicitly the roadmap's own "highest-leverage deliverable" once it reaches Phase 9 — it is what unblocks three other developers.
- **Files to create:** `adam/collectors/base.py`, `sysmon.py`, `procmon.py`, `network.py`, `agent.py`, `adam/collectors/parsers/evtx.py`, `pml.py`, `pcap.py`
- **Risk:** Medium — high effort, but lower architectural risk than Phase 5, since the types collectors must conform to (`RawEvent`, `ICollector`) will already be frozen by this point.

### 17. `SandboxController.collect_artifacts()` — real implementation

- **Priority:** High
- **Effort:** S–M — primarily wiring, once collectors exist to retrieve artifacts from.
- **Dependencies:** Item 16. This is not this plan's inference — `controller.py`'s own docstring states real artifact retrieval "depends on Collector Orchestration, which doesn't exist yet."
- **Why it's needed:** The one `ISandboxController` method still deliberately, self-documented as deferred. Completing it finishes Phase 4.
- **Files to modify:** `adam/sandbox/controller.py`
- **Risk:** Low.

### 18. Phase 8 — Orchestrator & CLI

- **Priority:** High
- **Effort:** L — `SessionOrchestrator`, `Runner`, and a full CLI surface (`adam run <sample_path>`).
- **Dependencies:** Item 16 (something to orchestrate) and item 1 (`AnalysisSession`, the sample-reference type `run_session()`'s signature needs).
- **Why it's needed:** Named blocker for Phase 9's practical, repeatable use, and it is the point at which a full session becomes runnable end to end for the first time.
- **Files to create:** `adam/orchestrator/session.py`, `adam/orchestrator/runner.py`, `adam/cli/main.py`, `adam/cli/run.py`. **Files to modify:** `requirements.txt` (add `typer`, `rich`).
- **Risk:** Medium — this is where interface mismatches from earlier phases, if any remain, are most likely to surface, since it is the first point everything is wired together into one path.

### 19. Phase 9 — Recorded Corpus

- **Priority:** High
- **Effort:** M — not primarily code; running real/benign sessions and curating 3–5 labelled, documented recordings.
- **Dependencies:** Item 16 (collectors, to produce real events) and item 18 (orchestrator/CLI, for a repeatable, unattended way to produce sessions — technically possible by hand with just items 1+16, but far less reliable).
- **Why it's needed:** The roadmap's own stated "highest-leverage deliverable" — this is what unblocks Devs B, C, and D to work offline via replay.
- **Files to create:** `tests/fixtures/raw_events/*.jsonl`
- **Risk:** Low technical risk. **Medium schedule risk** — the audit is explicit that three other developers' ability to work in parallel depends on this landing.

---

## Technical Debt (safe to postpone until the project is feature-complete)

### 20. Automated `pytest` test suite

- **Priority:** Low, for now.
- **Effort:** L if retrofitted retroactively across everything already built; S if adopted per-file going forward from here.
- **Dependencies:** None structurally.
- **Why it can wait:** The audit confirms nothing currently depends on automated tests existing in order to proceed, and characterizes the current all-manual-verification approach as "consistent with how early-stage the project is."
- **Files to modify:** all of `tests/` (currently `.gitkeep`-only).
- **Risk of deferring further:** Grows over time — most acutely once item 14 (Phase 5) replaces the currently-tested `guestcontrol` bridge with something new and untested by any automated harness.

### 21. `pyproject.toml` + `mypy` / `ruff` / `import-linter` CI enforcement

- **Priority:** Low, for now.
- **Effort:** M
- **Dependencies:** None structurally; genuinely more valuable once Devs B/C/D's modules (Fusion, Policy, Deception) exist for `import-linter` to have real cross-module boundaries to enforce.
- **Why it can wait:** §11.3 names this as the mechanism preventing "architectural erosion" across a four-developer team. With only Dev A's modules currently existing, there is little for it to police yet.
- **Files to create:** `pyproject.toml`
- **Risk of deferring further:** Low now; should not be deferred past the point where other developers' modules land.

### 22. Full `requirements.txt` buildout

- **Priority:** N/A — not a single deferrable task.
- **Effort:** N/A
- **Dependencies:** Each remaining dependency (`fastapi`, `pyyaml`, `aiosqlite`, `python-evtx`, `lxml`, `structlog`, `typer`, `rich`, dev tooling) belongs to a specific future phase.
- **Why it can wait as a lump, but shouldn't be batched:** These should be added incrementally as each phase that needs them starts (`httpx` alongside item 14, `python-evtx`/`lxml` alongside item 16, `typer`/`rich` alongside item 18) — per §10.2's shared-file protocol for `requirements.txt` (alphabetical, one per line, one binding at a time), not added as one large batch.
- **Risk:** Low.

---

## Dependency Graph

```
Phase 2 (Contracts)
    │
    ├──→ SandboxController / ISandboxController reconciliation   [Immediate #2]
    │
    ↓
Phase 1 remaining (bus.py → errors.py, logging.py, ids.py, timeutil.py, registry.py)
    │
    ├──→ Phase 3 completion (SnapshotManager, take_snapshot, is_running)      [parallel, non-blocking]
    ├──→ Phase 4 completion (VMProfile, apply_mutation stub, CollectorSettings) [parallel, non-blocking]
    ├──→ Phase 6 verification gaps (config-driven timeout test, disk-diff)     [parallel, non-blocking]
    │
    ↓
Phase 5 (Guest Agent & HTTP Channel)
    │
    ↓
Phase 6 true completion (ISO-based injection, replaces arm()/copy_to_guest)
    │
    ↓
Phase 7 (Collectors)
    │
    ├──→ SandboxController.collect_artifacts() real implementation
    │
    ↓
Phase 8 (Orchestrator & CLI)
    │
    ↓
Phase 9 (Recorded Corpus)
```

**Adjustments made to the prompt's suggested graph, and why:**

- **`bus.py` is placed first within "Phase 1 remaining,"** ahead of `errors.py`/`logging.py`/`ids.py`/`timeutil.py`/`registry.py`, because it is the only one of the six named in the audit's "Current Blockers" section as a structural blocker for later phases (7 and 8). The other five are high-value but not named blockers for anything *starting* — they retire disclosed debt and complete Phase 1, but nothing downstream is gated on them specifically.
- **Phase 3 and Phase 4's remaining structural items are shown as parallel branches off "Phase 1 remaining," not part of the main spine.** The audit is explicit that none of these (`SnapshotManager`, `take_snapshot`, `is_running`, `VMProfile`) are currently blocking anything — they can happen at any point without affecting the critical path's timing, so forcing them into the linear sequence would misrepresent the audit's own evidence.
- **`SandboxController.collect_artifacts()` is shown as a distinct node after Phase 7**, not folded silently into Phase 7 itself, because the audit is explicit that this dependency comes from `controller.py`'s own docstring, not general inference — it deserves to be visible as its own step.
- **Phase 6's true completion (ISO-based injection) is shown as its own node between Phase 5 and Phase 7**, not merged into either, because the audit treats it as a distinct, currently-incomplete phase with its own specific blocker (Phase 5), separate from both "the agent existing" and "collectors existing."

---

## Closing Questions

**What is the single highest-priority task right now?**

Building `adam/contracts/` (Immediate #1). The audit's own "Ready For Next Phase?" section answers this directly: Phases 3 and 4 were built ahead of Phase 2, `SandboxController` cannot currently be verified against the interface it claims to implement, and every additional phase built without resolving this first compounds the gap rather than shrinking it.

**What is the smallest amount of work required to unblock future phases?**

Strictly by raw dependency count, the technical minimum is `raw_event.py` + `enums.py` + `interfaces.py` (just `RawEvent`, its enums, `ICollector`, and `ISandboxController`) — that alone would unblock Phase 4's reconciliation and let Phase 7's collector classes start. `envelope.py` and `session.py` (`AnalysisSession`) aren't strictly needed until Phase 8/9.

That said, the honest answer is that splitting Phase 2 this way undermines the exact guarantee it exists to provide: `ARCHITECTURE.md` §10.2 specifies `adam/contracts/` as a unit requiring "architect-approved PR + all four reviewers... no exceptions," precisely so it freezes once, coherently, rather than in pieces each of which might need to change again once the next piece is drafted. The smallest amount of work that doesn't create *new* rework risk is still all of Phase 2, reviewed and frozen together — plus `bus.py` immediately after, since it's the only other item the audit names as an explicit blocker.

**What should NOT be touched yet?**

Phase 7 (Collectors), Phase 8 (Orchestrator/CLI), and Phase 9 (Recorded Corpus) — each has a genuine, named structural blocker per the audit (missing contracts, missing bus, missing agent) that isn't a matter of effort but of a specific dependency not existing yet. Building any of these now means building against interfaces that don't exist and will very likely need to be redone. Similarly, Phase 6's ISO-based rework (item 15) should not start before Phase 5 (item 14), since the mechanism it depends on — the agent detecting mounted media — doesn't exist.

**Which technical debt can safely be postponed until the project is feature-complete?**

The automated `pytest` suite (item 20) and `mypy`/`ruff`/`import-linter` CI enforcement (item 21) — the audit confirms neither currently blocks any phase, and `import-linter` specifically is more valuable once Devs B/C/D's modules exist for it to actually police. The full `requirements.txt` buildout (item 22) isn't really a deferrable lump at all — it should track each phase's actual dependency as that phase starts, per the architecture's own shared-file protocol.
