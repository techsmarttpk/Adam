# ADAM — Dev A Implementation Audit

Audited against `docs/dev-a-environment-and-roadmap.md` (Part 2, Phases 1–9), cross-referenced with `ARCHITECTURE.md` as the frozen source of truth. Audit performed by direct inspection of the repository at the time of writing — no assumptions, no code changes made during this audit.

**Scope note on numbering.** This project's actual development proceeded as a reordered "Milestone 1–4" sequence (vertical-slice strategy: VirtualBox automation → guest execution → controller FSM → configuration), explicitly *not* in the roadmap document's Phase 1→9 order. This audit evaluates the repository's current state against each roadmap Phase regardless of the order in which the underlying work actually happened. Where Milestone numbering and Phase numbering refer to overlapping work, this is called out explicitly.

---

# Phase 1 — Foundation Layer (`adam.common`)

## Status
🟡 Partially Complete

## Implemented

- **`adam/common/config.py`** exists and implements `Settings` (root model) and `SandboxSettings` (sub-model), matching the roadmap's "`Settings` (root config model, sub-models per §12.2 table...)" requirement — but only for the `sandbox` section. `get_settings()` is implemented as a `functools.lru_cache`-backed singleton loader, matching the required interface `get_settings() -> Settings` exactly.
- The precedence chain required by §12.1 (Pydantic defaults → `config/default.toml` → `config/<environment>.toml` → environment variables → CLI flags) is implemented via a custom `pydantic_settings.PydanticBaseSettingsSource` (`_TomlConfigSource`) merging `config/default.toml` and an optional `config/<ADAM_ENV>.toml`, composed with `pydantic-settings`' built-in `env_settings`/`dotenv_settings` sources in `Settings.settings_customise_sources`. CLI-flag override (the top tier) is explicitly and correctly *not* implemented, with a docstring reason ("no CLI entrypoint yet — lands with the Orchestrator milestone").
- **`config/default.toml`** exists with a populated `[sandbox]` section (`vm_name`, `snapshot_name`, `boot_timeout_s`, `guest_ready_timeout_s`), matching the shape in `ARCHITECTURE.md` §12.2 (as amended).
- **`.env.example`** documents the two credential environment variables (`ADAM__SANDBOX__GUEST_USERNAME`, `ADAM__SANDBOX__GUEST_PASSWORD`), satisfying §12.3's "secrets never enter TOML" rule concretely.
- **Expected output reproduced and verified during this audit's preparation** (see the Milestone-4 verification run earlier in this project): `python -c "from adam.common.config import get_settings; print(get_settings())"` prints a validated `Settings` object sourced from `config/default.toml`, exactly as the roadmap specifies.
- **Manual testing step 1** ("deliberately invalid `config/default.toml`... fails fast with a readable error") — confirmed implemented and verified: a wrong-typed `boot_timeout_s` produces a specific Pydantic `ValidationError` naming the offending field, not a buried stack trace.

## Missing

- `adam/common/logging.py` — does not exist. No `get_logger(component: str) -> Logger` function anywhere in the repository. `config/logging.yaml` also does not exist.
- `adam/common/ids.py` — does not exist. No `new_id(prefix: str) -> str`. Nothing in the codebase currently generates prefixed/ULID-style IDs (nothing needs one yet — no session/event construction pipeline exists), so this absence has not yet blocked anything, but it is a literal roadmap requirement that is unmet.
- `adam/common/registry.py` — does not exist. No generic `Registry[T]`.
- `CollectorSettings` sub-model — does not exist (the roadmap asks for this "at minimum for your slice" alongside `SandboxSettings`). Reasonable given collectors don't exist yet (Phase 7), but it is a named, explicit roadmap requirement that is unmet.

## Deviations

- **Scope narrowing (beneficial, but real).** Only the `sandbox` config section was built in `config.py`. Three of seven listed Phase 1 files now exist (`config.py`, `bus.py`, `errors.py`); logging, ids, timeutil, and registry remain unbuilt. Consistent with the project's vertical-slice philosophy, but Phase 1 as the roadmap defines it (the *entire* `adam.common` foundation) is still not complete.
- **Precedence chain is more granular than the architecture diagram.** `ARCHITECTURE.md` §12.1 draws a single "Environment variables" tier; the actual implementation splits this into two: real exported env vars outrank `.env`-file-sourced values. This is a deliberate, documented refinement (see `config.py`'s module docstring) and does not contradict the spirit of §12.1, but it is not literally what the diagram shows. Harmless/beneficial.
- **`AdamError` hierarchy now exists; the three previously-local exceptions are re-parented, not renamed.** `VBoxCommandError` and `SandboxOperationError` now subclass `adam.common.errors.VMOperationError`; `adam.sandbox.state.SandboxStateError` now subclasses `adam.common.errors.SandboxStateError` (the frozen tree's own leaf name, under an identical short name in a different module — necessary because `adam/common/` cannot import from `adam/sandbox/`, so the dependency can only run the other way). Every existing `except VBoxCommandError`/`except SandboxStateError`/`except SandboxOperationError` call site is unaffected — same names, same constructors, same raise sites, only the base classes changed. Verified: `isinstance()` checks confirm all three now also match `except SandboxError`/`except AdamError`, and existing narrow `except` clauses still bind correctly.
- **`EventBus`'s "QueueOverflow" is a logged warning + counter, not an exception class.** `ARCHITECTURE.md` §8.2 says a full subscriber queue "drops with a counted, logged `QueueOverflow`," which reads ambiguously as either a named exception type or a named log event. Implemented as the latter (`logger.warning(...)` plus `Subscription.dropped`), reasoned explicitly in `bus.py`'s module docstring: raising would reintroduce exactly the publisher/subscriber coupling "drop rather than block" (§8.3) exists to avoid. **Assessment: a defensible reading of an ambiguous spec sentence, disclosed in-file, not silent drift.**
- **`errors.py` declares the full §14.1 tree, not just the "at least SandboxError and CollectorError" minimum the roadmap names.** `FusionError`, `PolicyError`, `DeceptionError`, `PersistenceError`, `ReportingError`, and several leaves under them are declared but not yet raised by any Dev A code — they exist as forward declarations matching the already-frozen architecture tree, for Devs B/C/D's modules to raise once built. **Assessment: harmless** — these are zero-logic marker classes with no design decision left to make, not scope creep into another developer's module.

## Manual Testing

- Step 1 (invalid config fails fast): **Completed.** Verified directly during Milestone 4 development — a broken `boot_timeout_s` type produces a clear, specific `pydantic_core.ValidationError`.
- Step 2 (bus FIFO order — five-line throwaway script, subscribe a print handler, publish three messages, confirm FIFO order): **Completed**, via an offline harness exercising the real `EventBus` (publish 5 `Envelope[RawEvent]` messages before `start()`, confirm delivery order `[0,1,2,3,4]` after `drain()`).
- Step 3 (handler raises on the second message, confirm the third still arrives): **Completed**, via the same harness — a handler that raises `RuntimeError` on message index 1 still lets message index 2 arrive (`received == [0, 2]`), confirming handler isolation.

## Overall Assessment

Three of Phase 1's seven files are now built: configuration (solid, well-documented, demonstrably correct against every roadmap scenario), the event bus (`adam/common/bus.py`, `EventBus`, all four section 8.2 guarantees verified offline), and the `AdamError` hierarchy (`adam/common/errors.py`, full section 14.1 tree, with the three previously-local sandbox exceptions re-parented into it and verified via `isinstance()` checks — `mypy --strict` passes across all of `adam/common/`, `adam/contracts/`, and the modified `adam/sandbox/` files). This retroactively unblocks Phase 7 (collectors now have somewhere to publish `RawEvent`, and a real error hierarchy to raise `CollectorError`/`ParserError` from) and closes three of the disclosed technical-debt items from the original audit revision. Logging, ID generation, time utilities, and the plugin registry remain entirely unbuilt.

---

# Phase 2 — Contracts for Your Slice (proposal)

## Status
🟡 Partially Complete (proposal implemented and self-verified; §10.2 four-developer review has not occurred)

## Implemented

- `adam/contracts/enums.py` — `Source`, `Category` (§7.2 table, exact members), plus `Arm`, `NetworkMode`, `SessionStatus` needed by `AnalysisSession` (§7.6). `SessionStatus`'s member set is explicitly flagged in its own docstring as inferred beyond the one example value ("COMPLETED") shown in §7.6, since the architecture document does not enumerate it — called out for confirmation in review, not silently assumed.
- `adam/contracts/envelope.py` — `Envelope`, generic over payload type (`Envelope[RawEvent]`) for static typing on `.payload`. Matches §7.1's JSON shape field-for-field. Rejects timezone-naive `emitted_at` (enforces §5.1's "all timestamps UTC" ownership claim rather than assuming it).
- `adam/contracts/raw_event.py` — `RawEvent` and nested `ProcessInfo`, matching §7.2's example exactly, including `attributes: dict[str, Any]` staying deliberately open per the spec's own note. Both `occurred_at` and `observed_at` independently reject naive datetimes.
- `adam/contracts/session.py` — `AnalysisSession`, `SampleRef`, `SessionConfig`, `SessionMetrics`, matching §7.6's example exactly. `SampleRef` (sha256/md5/filename/size_bytes/file_type) doubles as the parameter type for `ISandboxController.detonate()` per the roadmap's `detonate(sample: SampleRef) -> None` signature.
- `adam/contracts/interfaces.py` — `ICollector` (`start`, `stop`, `iter_events`) and `ISandboxController` (`prepare`, `detonate`, `apply_mutation`, `collect_artifacts`, `teardown`), both `@runtime_checkable` Protocols, matching the roadmap's Phase 2 code block exactly. Also defines minimal `MutationRequest`, `MutationResult` (mirroring §7.5's wire shape), and `ArtifactRef` so the Protocol is syntactically complete — explicitly documented in-file as provisional/Dev-C-reviewable, since §7.5 is Dev C's owned contract, not Dev A's.
- `adam/contracts/__init__.py` — re-exports the full public surface.

**Expected output, verified:**
- A `RawEvent` built from the exact §7.2 example JSON survives `model_dump_json()` → `model_validate_json()` with equality preserved. Same for `Envelope[RawEvent]` (§7.1 example) and `AnalysisSession` (§7.6 example, including nested `SampleRef`/`SessionConfig`/`SessionMetrics`).
- Omitting a required field (`event_id`) raises `pydantic.ValidationError` rather than accepting `None` silently.
- A timezone-naive `occurred_at` raises `ValidationError` rather than being silently treated as UTC.
- `mypy --strict adam/contracts/` — `Success: no issues found in 6 source files`.

## Missing

- `adam/contracts/semantic_event.py`, `policy_decision.py`, `mutation.py` (§7.3–§7.5's canonical, frozen forms) — out of scope for Dev A's Phase 2 file list per the roadmap; owned by Dev B (Fusion) and Dev C (Policy/Deception) respectively. `interfaces.py`'s `MutationResult` is a provisional stand-in for §7.5 only, not a claim that Dev C's contract is done.
- The §10.2 "circulate the diff to the other three developers before merging" step — this is a human review process, not a repo artifact, and cannot be completed or verified from code alone. **Not verifiable from current implementation.**
- `SandboxController` has not yet been reconciled against the now-real `ISandboxController` Protocol (its `detonate()` signature still takes `guest_target_path: str` / returns `VMOperationResult`, not `sample: SampleRef` / `None`) — tracked as a separate, immediately-following task per the remaining work plan, not part of Phase 2 itself.

## Deviations

- `SessionStatus`'s member list is an inference beyond §7.6's single-example evidence (see Implemented) — flagged in-file, not hidden.
- `MutationRequest` and `ArtifactRef` are not named as JSON contracts anywhere in ARCHITECTURE.md; both are original, minimal, in-file-documented additions needed only to make `ISandboxController`'s signature syntactically complete. Assessed as harmless: both are explicitly provisional and neither is asserted as a frozen §7 shape.

## Manual Testing

- Step 1 (round-trip a §7.2-matching `RawEvent` through JSON) — **Completed.**
- Step 2 (confirm a missing required field is rejected, not silently accepted as `None`) — **Completed.**
- Step 3 (circulate the diff to the other three developers before merging) — **Not completed** (human process step, outside what this repository can execute or verify).

## Overall Assessment

Phase 2's code deliverables are implemented and self-verified: all five files from the roadmap's file list exist, every model round-trips through JSON against the architecture document's own example data with equality preserved, negative validation (missing field, naive datetime) is proven, and `mypy --strict` passes clean. This retroactively gives Phase 4's `SandboxController` something real to be checked against for the first time. Two things keep this from being marked fully ✅ complete: the §10.2 four-developer review hasn't happened (a human process, not a code gap), and `SandboxController` itself has not yet been updated to match `ISandboxController`'s real signature — that reconciliation is the very next task, tracked separately so this section reflects only what Phase 2 itself delivers.

---

# Phase 3 — VirtualBox Controller

## Status
🟡 Partially Complete

## Implemented

- **`adam/sandbox/vbox/client.py`** exists and implements a thin async wrapper around `VBoxManage`, satisfying the roadmap's core objective ("one module wraps every `VBoxManage` call"). The class is named `VirtualBoxClient`, not `VBoxClient` (see Deviations), and implements:
  - `get_version()`, `vm_exists(vm_name)`, `get_state(vm_name)`, `snapshot_exists(vm_name, snapshot_name)`, `list_snapshots(vm_name) -> list[SnapshotInfo]` — query methods, satisfying the roadmap's `list_snapshots` requirement (with a richer return type — see Deviations).
  - `start(vm_name, headless=True)`, `stop(vm_name, mode="acpi"|"poweroff")`, `restore_snapshot(vm_name, snapshot_name)`, `wait_for_state(vm_name, expected_state, timeout, poll_interval=1.0)` — state-changing operations, satisfying `start_vm`/`power_off`/`restore_snapshot` conceptually (renamed — see Deviations).
  - `run_in_guest`, `wait_for_guest_ready`, `copy_to_guest` — guest-execution methods **not in Phase 3's scope at all**; these anticipate Phase 5's guest channel and are explicitly documented in the module docstring as a "TEMPORARY BRIDGE" pending the real HTTP agent.
- **`adam/sandbox/vbox/models.py`** provides `VMOperationResult` (structured result for every state-changing call: `success`, `command`, `duration_ms`, `return_code`, `stdout`, `stderr`, `termination_reason`) and `SnapshotInfo` (`name`, `uuid`, `is_current`) — not named in the roadmap's Phase 3 file list, but a reasonable, well-justified addition (see `models.py`'s own docstring for the "internal-only, not a contract model" rationale).
- **`adam/sandbox/vbox/ntstatus.py`** decodes well-known Windows NTSTATUS codes into `VMOperationResult.termination_reason` — an addition beyond the roadmap's Phase 3 scope, added in response to a real investigation (a VirtualBox 7.0.x/7.1.0 `guestcontrol` heap-corruption bug, Oracle ticket #22175) during this project's own development.
- **Expected output** (a script that restores `clean`, boots headless, confirms running) is not just satisfied but exceeded: `scripts/manual_test_vbox_client.py` is a repeatable, edge-case-covering manual test script (not a one-off throwaway) covering `get_version`, `vm_exists` (real and nonexistent VM), `get_state`, `list_snapshots`, `snapshot_exists`, `start` (including "already running"), `wait_for_state`, `restore_snapshot` (including "while running" and "snapshot doesn't exist"), `stop` (both modes, including "already stopped"), and an invalid `VBoxManage` path. This script has been run against the real `ADAM_WIN10_OFFICE` VM repeatedly over the course of this project.
- **Manual testing step 2** (nonexistent VM name raises an exception with a useful message, not a raw `CalledProcessError`) — implemented and demonstrated: `scripts/manual_test_vbox_client.py`'s "EDGE CASE: `list_snapshots()` on an invalid VM name" explicitly catches and prints `VBoxCommandError`, which does carry a useful, structured message (command, return code, stdout, stderr all preserved — see `VBoxCommandError.__init__`).

## Missing

- `adam/sandbox/vbox/snapshot.py` — **does not exist.** There is no `SnapshotManager` class anywhere. The roadmap's two-layer design (`VBoxClient` primitives + a `SnapshotManager` convenience layer with `ensure_clean(vm, snapshot="clean")`) was collapsed into one layer: `VirtualBoxClient` plus direct calls from `SandboxController.prepare()` (Phase 4). No standalone `ensure_clean()` method exists at any layer.
- `take_snapshot(vm, name)` — **does not exist.** `VirtualBoxClient` can restore, list, and check existence of snapshots, but cannot create one. (This has not blocked anything yet — the `clean` snapshot has always been created by hand via `VBoxManage snapshot ... take` per the environment checklist, item 11 — but it is a named roadmap interface that is unmet.)
- `is_running(vm) -> bool` — **does not exist** as a dedicated method. The equivalent information is obtainable via `get_state(vm_name) == "running"`, but no boolean convenience method exists.
- `VMOperationError` — does not exist (see Phase 1's missing error hierarchy). `VBoxCommandError` is what's actually raised.

## Deviations

- **Class renamed: `VBoxClient` → `VirtualBoxClient`.** Explicitly and deliberately documented in the module docstring: the longer name is reserved so a future provider-agnostic base (`SandboxProvider` → `VirtualBoxClient` / `VMwareClient` / `QemuClient`) could be introduced later without a rename. No such base class exists yet, and the docstring is explicit that building one now would be premature abstraction. **Assessment: harmless, arguably beneficial** — it's a naming decision with a stated rationale, not an accidental drift.
- **Method renames:** `start_vm` → `start`, `power_off` → `stop`. `stop` additionally takes a `mode: Literal["acpi", "poweroff"]` parameter the roadmap's `power_off` signature doesn't have, distinguishing graceful ACPI shutdown from immediate poweroff. **Assessment: beneficial** — the extra mode is a real operational distinction VirtualBox itself exposes, and collapsing it into one unconditional "power off" (as the roadmap's signature implies) would have lost information the actual `SandboxController.teardown()` needs (it explicitly uses `mode="poweroff"` for unconditional cleanup).
- **`list_snapshots` returns `list[SnapshotInfo]`, not `list[str]`.** The roadmap's Phase 3 signature is `list_snapshots(vm) -> list[str]`. The actual return type is richer (name, UUID, is-current flag). **Assessment: beneficial** — strictly more information for the same call, and `SnapshotInfo`'s own docstring documents a known limitation (only one level of VirtualBox's nested-snapshot numbering is parsed), so the richer type is honest about its own limits rather than silently over-claiming.
- **Query-failure exception is `VBoxCommandError`, not `VMOperationError`.** Not derived from any `AdamError`/`SandboxError` hierarchy (Phase 1 gap). **Assessment: problematic, but disclosed** — `VBoxCommandError`'s own docstring explicitly names `VMOperationError` as where it should eventually fold in per §14.1, so this is tracked debt, not silent drift.
- **Guest-execution methods (`run_in_guest`, `wait_for_guest_ready`, `copy_to_guest`) exist in this file at all.** These are Phase 5 concerns (guest agent channel) implemented here instead, using VBoxManage's built-in `guestcontrol` rather than the architecture-mandated HTTP agent. Explicitly labeled "TEMPORARY BRIDGE" in the module docstring, with an explicit instruction not to extend it further. **Assessment: beneficial short-term (it's what let the rest of the sandbox stack get built and proven end-to-end at all), but real technical debt against Phase 5** — see that phase's section.

## Manual Testing

- Step 1 (run restore-and-boot script twice, manually dirty the VM between runs, confirm second restore erases the change): **Not verifiable from current implementation.** This project's real-VM testing extensively exercised `restore_snapshot` + `start` + `wait_for_state` in sequence (dozens of times, across the whole `wait_for_guest_ready` investigation), which is strong indirect evidence the restore mechanism works reliably — but no record exists in this project of the specific test described (manually changing something inside the VM via console/RDP without saving, then confirming a second restore erases it). This specific scenario cannot be confirmed from the repository or the project's history as it stands.
- Step 2 (nonexistent VM name raises a useful exception): **Completed** — confirmed in `scripts/manual_test_vbox_client.py`'s edge case for `list_snapshots("NOT_A_REAL_VM")`, raising `VBoxCommandError` (not `VMOperationError` — see Deviations) with the full command/stdout/stderr/return-code preserved.

## Overall Assessment

The actual, working core of Phase 3 — a wrapper that can query and control the VM reliably — is genuinely done and has been proven against the real VM more thoroughly than the roadmap's own "one throwaway script" bar asks for. What's missing is entirely structural: the `SnapshotManager` layer was never separated out, two named methods (`take_snapshot`, `is_running`) don't exist, and the exception type doesn't derive from the architecture's intended hierarchy because that hierarchy doesn't exist. None of this is blocking today, but the `snapshot.py` gap in particular means "snapshot discipline" as a concept lives inside `SandboxController`, not as its own reusable unit the roadmap intended other code to depend on.

---

# Phase 4 — Sandbox Controller FSM

## Status
🟡 Partially Complete

## Implemented

- **`adam/sandbox/state.py`** implements `SandboxState` as a 9-value enum — `COLD, RESTORING, BOOTING, READY, ARMED, RUNNING, COMPLETED, TEARDOWN, FAILED` — which is an **exact match** to `ARCHITECTURE.md` §5.2's state list, including `COMPLETED`, which was added to the architecture via an explicit, documented amendment during this project's own development (not a silent addition — both `ARCHITECTURE.md` §5.2 and `state.py`'s module docstring carry the rationale).
- `SandboxStateError` and `SandboxOperationError` implement the "illegal transitions raise a specific, informative error" requirement. `SandboxStateError.__init__` carries `current_state`, `attempted_operation`, and `expected_states`, producing a message like `"cannot detonate from state COLD (expected one of: ARMED)"` — this satisfies the roadmap's "raises `SandboxStateError`... with a useful message" requirement precisely.
- **`adam/sandbox/controller.py`** implements `SandboxController` with `prepare()`, `arm()`, `detonate()`, `apply_mutation()`, and `teardown()`.
  - `prepare()`: `COLD → RESTORING → BOOTING → READY`, calling `restore_snapshot` → `start` → `wait_for_state("running")` → `wait_for_guest_ready`, driving to `FAILED` on any underlying failure. This matches the roadmap's "`prepare()` takes the VM from `COLD` to `READY`" requirement, and is *more* granular than the roadmap's two-state shorthand (it genuinely traverses the two intermediate states `ARCHITECTURE.md` §5.2 names).
  - `detonate()`: **now matches `ISandboxController.detonate(self, sample: SampleRef) -> None` exactly**, following Phase 2 landing. `ARMED → RUNNING → COMPLETED`, executing the guest path `arm()` recorded (`self._armed_guest_target_path`) with a config-sourced `detonate_timeout`, calling `VirtualBoxClient.run_in_guest`. Deliberately does not raise for a sample's own non-zero exit code or crash (documented at length in the module docstring, matching the "degrade, don't abort" philosophy of §14.2). Since the method no longer returns the `VMOperationResult` (the Protocol requires `None`), that detail is now exposed via a new `last_detonation_result` property, read immediately after `detonate()` returns — same information, no longer smuggled through the return value.
  - `apply_mutation()`: **new.** Matches `ISandboxController.apply_mutation(self, mutation: MutationRequest) -> MutationResult`. Enforces `RUNNING` state via `_require_state()`, then raises `NotImplementedError` with a message pointing at the Deception Engine dependency — a real stub, not a silent no-op, so a caller gets an explicit "not built yet" rather than an `AttributeError` or a fabricated result.
  - `teardown()`: callable from any state, best-effort `stop(poweroff)` + `restore_snapshot`, always ends `COLD`, never raises — matches the roadmap's idempotency requirement exactly.
  - `_require_state()` raises `SandboxStateError` when a method is called from an illegal state — this is the mechanism that satisfies the roadmap's "`detonate()` before `prepare()` raises `SandboxStateError` instead of doing something undefined" requirement, and now also guards `apply_mutation()`.
- **Expected output** confirmed via real-VM runs (pre-reconciliation) and, for the signature change itself, via an offline harness (`FakeClient` subclassing `VirtualBoxClient`, no VBoxManage involved): confirms `prepare()`/`arm()`/`detonate(sample)`/`teardown()` transition correctly, `detonate()` returns `None` and populates `last_detonation_result`/`last_detonated_sample`, `detonate()` dispatches to the armed guest path with the configured `detonate_timeout` and no separate arguments, `apply_mutation()` raises `SandboxStateError` outside `RUNNING` and `NotImplementedError` inside it, and `SandboxOperationError`/`FAILED`/idempotent-`teardown` behavior is unchanged. `mypy --strict` passes on `adam/sandbox/controller.py` and `adam/contracts/`. A real-VM re-run of the updated `scripts/manual_test_sandbox_controller.py` (now building a genuine `SampleRef` from `whoami.exe` and calling the new `detonate(sample)` signature) has not yet been reported back — **not verifiable from current implementation** for the real-hardware case specifically, though the offline harness covers the same state-machine logic the real-VM tests previously exercised.

## Missing

- `collect_artifacts()` — **still does not exist.** Deliberately and explicitly deferred: `controller.py`'s module docstring states this outright ("Real telemetry/artifact retrieval depends on Collector Orchestration, which doesn't exist yet"). This is disclosed, reasoned debt, not an oversight — but it is a literal roadmap requirement (`ISandboxController.collect_artifacts()`) that is unmet, and it is now the **only** remaining method keeping `SandboxController` from fully satisfying `ISandboxController` (confirmed directly: `isinstance(ctrl, ISandboxController)` is `False` solely because this one method is absent; every other required method is present and structurally correct).
- `adam/sandbox/profiles.py` — **does not exist.** No `VMProfile` class, no TOML-profile loading/validation logic.
- `config/vm_profiles/win10-x64-office.toml` — **does not exist.** `config/vm_profiles/` contains only `.gitkeep`. The equivalent values (`vm_name`, `snapshot_name`, timeouts) live directly in `SandboxSettings` (Phase 1/Milestone 4) instead of in a separate, named, swappable VM profile.
- `_transition(new_state) -> None` — **does not exist as a named method.** State changes are inlined directly (`self._state = SandboxState.X`) at each call site inside `prepare()`, `arm()`, `detonate()`, and `teardown()`, rather than funneled through one central `_transition()` chokepoint the roadmap's interface spec names explicitly.
- `detonate_timeout` (the new constructor parameter backing `detonate()`'s config-sourced timeout) is not yet a field on `SandboxSettings`/`config/default.toml` — it is a plain constructor argument with a `300.0` default, same situation `boot_timeout`/`guest_ready_timeout` were in before Milestone 4. Tracked in `docs/remaining-work-plan.md`.

## Deviations

- **`detonate()`'s signature previously did not match `ISandboxController` — now resolved.** Was `async def detonate(self, guest_target_path: str, *, arguments: list[str] | None = None, timeout: float) -> VMOperationResult`; is now `async def detonate(self, sample: SampleRef) -> None`, matching the Protocol exactly. One residual, disclosed gap: `arm()`'s `host_sample_path`/`guest_target_path` (plain strings) are not currently cross-validated against the `SampleRef` passed to the following `detonate()` call — the two are trusted to refer to the same sample by caller discipline, not enforced by the type system. Assessed as a minor, separable follow-up, not a blocker.
- **`apply_mutation()` was entirely absent — now resolved as a disclosed stub.** Implemented, enforces `RUNNING` state, raises `NotImplementedError` with an explicit message pointing at the Deception Engine dependency, rather than being silently missing.
- **`arm()` exists and is not in the roadmap's interface at all.** `READY → ARMED`, copying the sample onto the guest via `VirtualBoxClient.copy_to_guest`. This effectively pulls part of Phase 6's "sample injection" concern forward into Phase 4, and does it via `guestcontrol copyto` rather than the roadmap's read-only ISO-mount mechanism (environment checklist item 13; Phase 6). **Assessment: problematic against the architecture as written**, unchanged by this reconciliation — `client.py`'s own docstring still calls `copy_to_guest` "a deliberate, temporary stand-in for the ISO-mount transfer path described in the roadmap doc." Still needs direct attention before Phase 6 is genuinely complete.
- **No `_transition()` chokepoint**, but the safety guarantee it exists to provide (illegal transitions always raise) is achieved via a different mechanism (`_require_state()` guard at the top of each public method, now also covering `apply_mutation()`). **Assessment: harmless** — functionally equivalent, structurally different.

## Manual Testing

- Step 1 (idempotent `teardown()` called twice): **Completed** (pre-reconciliation, real VM) and unaffected by this change; re-confirmed offline.
- Step 2 (out-of-order operations fail loudly and specifically): **Partially completed.** `detonate()` before `prepare()` and `detonate()` called twice without re-arming are both implemented, demonstrated in the updated manual test script, and re-confirmed offline against the new signature. `apply_mutation()`'s own state guard is newly confirmed offline (`SandboxStateError` outside `RUNNING`). `collect_artifacts()` after `teardown()` **still cannot** be tested, because `collect_artifacts()` doesn't exist.
- Step 3 (kill the VM process externally mid-`prepare()`): **Not verifiable from current implementation** — unchanged by this task.

## Overall Assessment

The state machine remains the most mature, most extensively real-VM-tested part of the codebase, and this reconciliation closes the two concrete interface gaps the audit identified: `detonate()` now matches `ISandboxController` exactly (verified via an offline fake-client harness, since no real VM was available for this task), and `apply_mutation()` exists as an honest, state-guarded stub instead of being silently absent. `SandboxController` is now one method (`collect_artifacts()`) away from full, checkable `ISandboxController` conformance — a real, disclosed, and now precisely scoped gap rather than an open-ended one. `arm()`'s ISO-mount deviation is untouched by this task and remains the item most needing attention before Phase 6 can be called architecture-compliant.

---

# Phase 5 — Guest Agent & Host↔Guest Channel

## Status
🟡 Partially Complete. The original roadmap's literal HTTP-agent architecture is now BUILT and HARDENED FOR DEPLOYMENT (code-complete, real API contract, every endpoint's field shape cross-checked against its host-side Pydantic model, an idempotent/self-verifying installer, retry/backoff + explicit raising diagnostics on the host transport) — see "HTTP architecture" and "Deployability hardening (Task G revision)" below — but STILL NOT EXECUTED against a real Windows guest, since no VirtualBox/Windows runtime has been available in any environment this has been written or reviewed in. The GuestControl-based compatibility backend (originally this phase's own substitute deliverable) remains fully operational and is still the default. See "Phase 5 Item Checklist" below for an explicit ✓/⚠/✗ per component. Estimated completion: see "Overall Assessment."

## HTTP architecture (this revision)

A second, architecturally-target implementation was added alongside the compatibility backend,
selected via `Settings.guest_backend: Literal["vbox", "http"]` (default `"vbox"`):

- **`adam/sandbox/guest/channel.py`** — `GuestChannel`, a `Protocol` matching `GuestAgent`'s
  existing three public methods (`verify_tools`/`start_captures`/`stop_export_and_fetch`).
  `SessionOrchestrator`'s `guest_agent` constructor parameter is now typed `GuestChannel | None`
  (previously `GuestAgent | None`) — it depends on the interface only, never on which backend is
  active.
- **`adam/sandbox/guest/vbox_channel.py`** — `VBoxGuestChannel`, a three-method delegating
  wrapper around the existing, **completely unmodified** `GuestAgent`. Selected by
  `guest_backend = "vbox"` (default).
- **`adam/sandbox/guest/http_channel.py`** + **`adam/sandbox/guest/http_models.py`** —
  `HTTPGuestChannel`, an `httpx`-based host-side client implementing `GuestChannel` by composing
  calls to a guest-resident HTTP agent's REST API (see `docs/phase5-http-agent-api.md` for the
  full, authoritative spec). Selected by `guest_backend = "http"`.
- **`adam/sandbox/guest/agent/adam_agent.ps1` + `modules/*.psm1`** — the guest-resident agent
  itself. Built in **PowerShell 5.1** against `System.Net.HttpListener`, not Python/FastAPI —
  ARCHITECTURE.md's own constraint C4 ("The guest agent is PowerShell 5.1 compatible. No .NET
  Core assumption") rules out installing a Python runtime into the guest image, and this was
  confirmed as the correct resolution when the FastAPI-vs-PowerShell fork was raised explicitly.
  Eight manager modules (Filesystem, Process, Procmon, Network/tshark, Sysmon, Diagnostics,
  Sample, Artifact) matching the architecture's own diagram, each using .NET APIs directly
  (`System.Diagnostics.ProcessStartInfo.ArgumentList`, `System.IO`, `System.IO.Compression.ZipFile`,
  raw `GetTokenInformation` P/Invoke) — no `cmd.exe`, no shell, no stdout text-parsing anywhere in
  this path, structurally eliminating the entire Bug #1/Issue #1 class of quoting bugs the
  compatibility backend spent four rounds fixing.
- **`adam/orchestrator/runner.py`** — `_build_guest_channel()`, the one place in the codebase
  that branches on `guest_backend`, constructing `VBoxGuestChannel` or `HTTPGuestChannel`
  accordingly. `SessionOrchestrator` itself never sees the setting.
- **`adam/common/config.py` / `config/default.toml`** — `guest_backend` + `HttpGuestSettings`
  (`http_guest` section) added; `GuestToolsSettings`/`[guest_tools]` untouched.
- **`docs/phase5-http-agent-api.md`** — the full HTTP API specification (12 sections: transport,
  envelope/error codes, and one per manager), the single source of truth both the Python host
  side and the PowerShell guest side are independently written against (no shared runtime exists
  between them).
- **`docs/phase5-migration-guide.md`** — how to move from `vbox` to `http`, what changes, what
  doesn't, and the compatibility guarantees during the transition.
- **Tests** (new: `tests/unit/`, `tests/integration/` now have real content instead of
  `.gitkeep` placeholders — this is the project's first use of the `pytest`/`pytest-asyncio`
  stack ARCHITECTURE.md section 15.3 always planned as a dev dependency but which nothing had
  needed until now): `test_http_models.py` (serialization), `test_guest_channel_protocol.py`
  (both backends structurally satisfy `GuestChannel`; `GuestAgent` itself provably unmodified),
  `test_http_guest_channel.py` (mock-HTTP-server integration tests driving `HTTPGuestChannel`'s
  full session lifecycle against an `httpx.MockTransport` fake, including a support-partial-
  telemetry case and a total-transport-failure case), `test_guest_service_static_structure.py`
  (best-effort, explicitly-disclosed static structural checks on the `.ps1`/`.psm1` files —
  brace/paren balance, every exported function referenced, every documented route wired up; NOT
  an execution test, since no PowerShell runtime exists in the environment this was written in).
  56 tests, all passing; `mypy --strict` clean across every new file.

## Deployability hardening (Task G revision)

A follow-up pass turned the HTTP architecture from "code-complete and internally tested" into
"genuinely installable, idempotent, and self-verifying" — the explicit goal of this revision.
Nothing here changes the architecture, the transport, or removes `VBoxGuestChannel`; every change
is either a bug fix, a completeness fix, or new test coverage.

- **`install.ps1` rewritten in full.** The previous version unconditionally copied
  `adam_agent.ps1`/`modules/` from `$PSScriptRoot` to `$InstallDir` with no guard for the two
  being the same directory (a real bug: running `install.ps1` from `C:\ADAM\agent` itself, e.g.
  to re-verify or pick up a config merge, would attempt to copy files onto themselves), attempted
  `netsh http add urlacl` unconditionally on every run (not idempotent — a second run's behavior
  on an already-reserved ACL was unverified), had no prerequisite validation beyond terse
  `#requires` directives, and had no automated post-install verification at all (only an
  unverified "should be reachable shortly" message). All four are fixed:
  - `Resolve-Path`-based source/destination comparison skips the copy step entirely (with a clear
    log line) when they're already identical.
  - `Test-UrlAclReserved` (parses `netsh http show urlacl` output rather than trusting its exit
    code, which is 0 even when a reservation doesn't exist) makes the URL ACL step idempotent;
    the firewall rule step now also detects and recreates itself if the configured port changed;
    the scheduled task step now compares the existing task's action against the expected one and
    only re-registers on a real mismatch; `agent.config.json` handling changed from
    "write-if-absent only" to "write-if-absent, else merge any new default keys into the existing
    file without touching values already present" (an admin's edited tool paths survive a re-run).
  - `Test-Prerequisites` checks PowerShell version, Administrator elevation, that the host is
    actually Windows (`Get-CimInstance Win32_OperatingSystem`), and that
    `System.Net.HttpListener` can be instantiated — each with a specific, actionable failure
    message — and runs before any mutating step, exiting 1 on failure.
  - `Test-Deployment` runs after every install step: confirms the scheduled task exists and is
    `Running` (polls up to 10s), confirms `agent.config.json` exists, `Import-Module`s every
    `.psm1` under `modules/` and reports any failure, and calls `GET /health` against
    `localhost:$Port` (polling up to 10s) checking for `{"success":true,"data":{"status":"ok"}}`
    — printing a pass/fail line per check and exiting 1 with troubleshooting guidance if anything
    failed, 0 with a clear "verified OK" message otherwise.
  - New `-Uninstall` (optionally `-RemoveFiles`) switch reverses every guest-side change
    (scheduled task, firewall rule, URL ACL) for a real, scripted rollback path — not just prose
    instructions.
  - Covered by 29 new static logic tests (`tests/unit/test_installer_logic.py`) confirming these
    behaviors are present and correctly ordered in the script source — see that file's own
    docstring for the same "static check, not an execution test" disclosure every `.ps1`/`.psm1`
    test in this project carries.
- **`http_models.py` completeness fix — six previously-missing endpoint models added.** Building
  a doc-driven cross-check test (`tests/unit/test_api_model_compatibility.py`, parses every
  `docs/phase5-http-agent-api.md` table row into a field-name set and asserts it matches the
  corresponding Pydantic model's fields exactly) surfaced that `/filesystem/move`,
  `/process/wait`, `/procmon/stop`, `/network/stop`, `/sample/stage`, and `/artifact/package` —
  all six documented, all six fully implemented on the guest side — had no corresponding
  `*Request`/`*Data` Pydantic model on the host side at all. Added all six
  (`MoveRequest`/`MoveData`, `ProcessWaitRequest`/`ProcessWaitData`,
  `ProcmonStopRequest`/`ProcmonStopData`, `NetworkStopRequest`/`NetworkStopData`,
  `SampleStageRequest`/`SampleStageData`, `ArtifactPackageRequest`/`ArtifactPackageData`).
  `HTTPGuestChannel`'s existing `/procmon/stop` and `/network/stop` call sites (previously passing
  raw `dict` literals, the only two call sites doing so) now use the new typed models like every
  other call site. This test now covers all 28 non-health/version endpoints plus `/health`/
  `/version` themselves (31 checks total) and would have caught this gap on the first run had it
  existed before.
- **`Invoke-NativeProcess` (`Common.psm1`) stdout/stderr encoding fix.** Was relying on
  `ProcessStartInfo`'s default encoding for redirected output, which is the OEM console code
  page, not UTF-8 — harmless for Procmon/wevtutil (ASCII-safe paths and CSV/XML), but a real
  correctness risk for `/network/convert`'s `tshark -T ek` output, which is UTF-8 JSON and can
  legitimately contain non-ASCII bytes (internationalized domain names, unicode window titles).
  `StandardOutputEncoding`/`StandardErrorEncoding` are now explicitly set to UTF-8 before
  `Process.Start()`.
- **`ArtifactManager.psm1`'s `Get-ArtifactMetadata` streaming-hash fix.** Was calling
  `[System.IO.File]::ReadAllBytes()` to compute a SHA-256 hash, fully buffering the artifact (a
  multi-hundred-MB EVTX/pcap export, this project's expected telemetry size) in the guest agent's
  own process memory. Now streams the hash via `[System.Security.Cryptography.SHA256]::
  ComputeHash(FileStream)`.
- **`HTTPGuestChannel` retry/backoff + explicit raising diagnostics.** `_request()` (used by all
  three `GuestChannel` Protocol methods, which must never raise) now retries a transient
  transport-level error (`ConnectError`/`ConnectTimeout`/`ReadTimeout`/`WriteTimeout`/
  `PoolTimeout`/`RemoteProtocolError`) up to 3 times with exponential backoff before settling
  into its existing None-returning failure path — still never raises, just tries harder first
  (a guest agent momentarily unreachable, e.g. mid Scheduled-Task-restart, is a real, expected
  failure class this project's own GuestControl-era history already documented). Two new
  explicit, deliberately RAISING methods — `get_health()`/`get_version()` — were added for a
  caller that wants a fail-fast check instead (a manual troubleshooting step, or a future
  `adam guest-check` CLI command): they raise `GuestAgentUnreachableError` (transport/parse
  failure) or `GuestAgentError` (guest reached, reported `success: false`) rather than returning
  `None`. Deliberately NOT wired into `SessionOrchestrator.run_session()`'s automatic path — doing
  so would abort sample detonation on a down guest agent rather than degrading to `PARTIAL`
  telemetry, contradicting ARCHITECTURE.md section 14.4's "partial results are still evidence"
  guarantee that already governs every other guest-agent failure mode in that method.
- **New test coverage**: `tests/unit/test_config.py` (13 tests — `HttpGuestSettings` defaults/
  `base_url`, `Settings.guest_backend`'s default and both literal values, env-var overrides for
  the nested `http_guest` section, `config/default.toml` itself parsing into a valid `Settings`,
  `get_settings()`'s caching contract), `tests/unit/test_api_model_compatibility.py` (31 tests,
  described above), `tests/unit/test_installer_logic.py` (29 tests, described above), plus 5 new
  tests in `tests/integration/test_http_guest_channel.py` covering the retry mechanism itself
  (not just its end state) and both new raising methods' success/failure paths. Total: 133 tests
  passing (up from 56), `mypy --strict` clean across the entire `adam/` package except the same
  two pre-existing, unrelated `config.py` issues this audit has disclosed since before Phase 5
  existed (a `tomllib`/Python-3.11 stdlib-only import mypy's own environment can't resolve, and
  one pre-existing `Settings()` call-site type note in a `__main__` block). A `tests/conftest.py`
  shim (`tomli` aliased to `tomllib` under Python <3.11, a no-op under >=3.11) was added purely so
  this project's own sandboxed dev/test environment — which only has Python 3.10 — can actually
  collect and run the test suite; this does not change `ARCHITECTURE.md` constraint C3's Python
  3.11 runtime requirement for real deployment.

## Phase 5 Item Checklist

Explicit status per component, per this revision's own instruction not to overstate completion.
✓ Completed means implemented and verified by every means available in this environment (code
review, static structural checks, mock-transport tests, cross-doc field checks) — NOT that it has
run against a real Windows guest, unless stated otherwise. ⚠ means real Windows/VirtualBox
execution is the only thing standing between "should work" and "verified to work." ✗ means not
implemented, by design or otherwise.

| Item | Status | Detail |
|---|---|---|
| `GuestChannel` Protocol + backend selection (`vbox`/`http`) | ✓ Completed | `channel.py`, `runner.py._build_guest_channel()`, `config.py.guest_backend` — tested (`test_guest_channel_protocol.py`). |
| `VBoxGuestChannel` (compatibility backend) | ✓ Completed | Unchanged, real-VM-verified across Bugs #1-#4/Issues #1-#3 in prior revisions. Still the default. |
| `HTTPGuestChannel` (host-side HTTP client) | ✓ Completed (code) / ⚠ Requires real VM validation (end-to-end) | Every endpoint it calls uses a typed request/response model; retry/backoff added; `get_health()`/`get_version()` raising diagnostics added. Verified via `httpx.MockTransport` integration tests, never against a real guest agent process. |
| `adam_agent.ps1` (HttpListener router) | ✓ Completed (code) / ⚠ Requires real VM validation | Every documented route present and wired to a handler (`test_route_table_covers_every_get_and_post_in_api_spec`); never executed. |
| 9 guest-side `.psm1` manager modules | ✓ Completed (code) / ⚠ Requires real VM validation | Every endpoint's request/response shape now matches the spec exactly on the host-side model too (`test_api_model_compatibility.py`); no shell/stdout-parsing anywhere except the three external tools (Procmon/tshark/wevtutil) themselves, launched via `ProcessStartInfo.ArgumentList`. Never executed. |
| `DiagnosticsManager.psm1` P/Invoke token code | ⚠ Requires real VM validation | Highest-risk file in the delivery (raw `GetTokenInformation` struct marshaling) — has a `whoami`-text-parsing fallback wired into every call site, but the fallback path is also unexecuted. Unchanged this revision. |
| `install.ps1` (installer) | ✓ Completed (code) / ⚠ Requires real VM validation | Idempotent, prerequisite-validated, self-verifying, with a scripted `-Uninstall` rollback path — see "Deployability hardening" above. 29 static logic tests pass; never run against a real Windows host. |
| Host-side Pydantic models vs. published API spec | ✓ Completed | 31/31 endpoints' field shapes cross-checked and matching, after adding the six models this revision found missing. |
| Native-Windows-API coverage (no shell where avoidable) | ✓ Completed | Confirmed by direct code review of all 9 modules this revision; two real correctness fixes made (UTF-8 stdout/stderr encoding, streaming SHA-256). |
| Procmon driver load under SYSTEM scheduled task | ⚠ Requires real VM validation | The architecture's implicit fix for the GuestControl-era filtered-token problem (SYSTEM genuinely carries `SeLoadDriverPrivilege`) — never confirmed against a real Procmon capture. |
| `/network/convert` native stdout redirect (incl. new UTF-8 fix) | ⚠ Requires real VM validation | Never run against real tshark output. |
| HttpListener concurrency / load characteristics | ⚠ Requires real VM validation | Single-threaded accept loop; `SessionOrchestrator` calls this API sequentially per session today, so this may never matter in practice, but is unverified either way. |
| Sample upload base64/JSON size limits | ✗ Not implemented | Disclosed scaling limitation (API spec section 10) — fine for this project's single-sample-per-session scope, unverified against a realistically large sample, `HttpListener`'s default request body size limit not explicitly raised. |
| `collectors.ps1` (guest-initiated push/heartbeat) | ✗ Not implemented (by design) | This revision's API is host-driven request/response, matching the architecture diagram (`Host --HTTP--> Guest Agent Service`) actually specified, not the older heartbeat-push sketch. Not a gap against what was actually asked for. |
| Automated test coverage (unit/integration/static/config/installer/API-compat) | ✓ Completed | 133 tests passing, `mypy --strict` clean except 2 pre-existing, unrelated, disclosed `config.py` issues. |
| API spec + migration guide documentation | ✓ Completed | `docs/phase5-http-agent-api.md`, `docs/phase5-migration-guide.md` — both accurate as of this revision. |

## Original compatibility-backend content (retained from the prior revision of this section)

The remainder of this section — `adam/sandbox/guest/agent/agent.py`'s `GuestAgent`
implementation, its four rounds of real-VM bug fixes (Bugs #1-#4 / Issues #1-#3: cmd.exe
quoting, PowerShell PATH resolution, Procmon EULA, and the filtered-token Sysmon/Procmon
investigation), and its own extensive diagnostics — is UNCHANGED by this revision and remains
accurate. It describes the `guest_backend = "vbox"` backend, still the default.

## Implemented

- **`adam/sandbox/guest/agent/agent.py`** implements `GuestAgent`, a host-orchestrated automation layer built directly against an explicit instruction to fix the practical consequence of this phase being unbuilt (`adam run <sample>` always producing "session COMPLETED (0 raw events captured)") using the guestcontrol bridge that already exists, rather than building the roadmap's originally-specified PowerShell/HTTP listener. See Deviations for the full, disclosed reasoning. Its three public methods:
  - `verify_tools() -> ToolAvailability` — checks Procmon64.exe, tshark.exe (both via a `cmd.exe /c if exist` guestcontrol probe), and the Sysmon event log channel (via `wevtutil gli`) are reachable in the guest. Never raises; returns a report with a specific, human-readable reason per unavailable tool.
  - `start_captures(session_id, *, capture_procmon=True, capture_network=True)` — launches Procmon (`/AcceptEula /Quiet /Minimized /BackingFile <path>`) and tshark (`-i <interface> -w <path>`), both detached via the new `VirtualBoxClient.start_in_guest()` (guestcontrol's `start` subcommand, not `run` — the latter blocks until exit, unusable for a background capture).
  - `stop_export_and_fetch(session_id, host_artifact_dir, *, export_sysmon=True, export_procmon=True, export_network=True) -> TelemetryArtifacts` — stops Procmon (`/Terminate`) and tshark (`taskkill /IM tshark.exe /F` + `taskkill /IM dumpcap.exe /F`, both needed since tshark spawns dumpcap.exe as its actual capture process), converts Procmon's PML to CSV (`/OpenLog /SaveAs /Quiet`) and the packet capture to EK JSON (`tshark -r ... -T ek`, redirected via `cmd.exe`), exports the Sysmon operational log via `wevtutil epl`, copies all three to the host session artifact directory via the new `VirtualBoxClient.copy_from_guest()`, and best-effort deletes the guest-side temp files. Every one of the three source pipelines is independently wrapped — see Deviations' "Support partial telemetry" note.
- **`adam/sandbox/vbox/client.py`** — added `start_in_guest()` (detached guestcontrol launch) and `copy_from_guest()` (the reverse of the existing `copy_to_guest()`), both in the same disclosed "TEMPORARY BRIDGE" category as the Milestone 2 guest-execution methods they extend.
- **`adam/common/config.py`** — added `GuestToolsSettings` (`procmon_path`, `tshark_path`, `sysmon_log`, `tshark_interface`, `capture_dir`, and four `*_timeout_s` fields), wired as `Settings.guest_tools` with every field defaulted, so an unconfigured guest tool degrades to "this source is skipped" rather than a fail-fast `Settings()` error — a deliberately different posture from `sandbox.guest_username`/`guest_password`, matching this phase's own "support partial telemetry" requirement.
- **`config/default.toml`** — added a `[guest_tools]` section with the exact paths this task's own environment specified (`C:\Users\Admin\Downloads\ProcessMonitor\Procmon64.exe`, `C:\Program Files\Wireshark\tshark.exe`, `Microsoft-Windows-Sysmon/Operational`).
- **`adam/common/errors.py`** — added `GuestToolMissingError` and `GuestToolExportError` (both `SandboxError` leaves) — section 14.1's frozen tree has no existing node for "a required guest-side tool/export is missing," the closest existing leaves (`SampleTransferError`, `GuestTimeoutError`) are specifically about sample delivery and guest unresponsiveness respectively. Disclosed, minimal, same-category addition as `SessionStatus.PARTIAL` was for Phase 8.
- **`adam/orchestrator/session.py`** — `SessionOrchestrator` gained an optional `guest_agent: GuestAgent | None = None` constructor parameter. When supplied, `run_session()` calls `start_captures()` after `arm()`, and — after `detonate()` and the existing post-detonation grace sleep — calls `stop_export_and_fetch()` and automatically builds+starts `SysmonCollector`/`ProcmonCollector`/`NetworkCollector` from whatever paths came back (via the new `build_collectors_from_telemetry()` free function), pumping them into `raw.jsonl`/the bus exactly like any other collector. `guest_agent=None` (the default) preserves this class's exact pre-Phase-5 behavior — every one of Phase 8's own offline verification scenarios continues to exercise the unmodified code path.
- **`adam/orchestrator/runner.py`** — `Runner.run()` now always constructs a `GuestAgent` (sharing the same `VirtualBoxClient` instance `SandboxController` uses) and passes it to `SessionOrchestrator`. `_build_collectors()` (for the CLI-override paths) now delegates to `build_collectors_from_telemetry()` instead of duplicating the "only construct if not None" rule.
- **`adam/cli/run.py`** — the three existing `--sysmon-evtx-path`/`--procmon-csv-path`/`--network-ek-json-path` options' help text updated to state they are testing-only overrides; no behavior change (they were already optional, defaulting to `None`). `SessionOrchestrator` itself infers, from `source_name` on any constructor-injected override collector, which of the three sources `GuestAgent` should skip capturing/exporting — no new CLI-layer plumbing was needed for this.
- **`scripts/manual_tests/guest_agent_offline_verification.py`** — new offline (no VM required), directly-runnable verification script following this project's own established `FakeClient(VirtualBoxClient)`-overriding-`_run()` methodology. Six scenarios, all passing: tool verification (available + missing-with-diagnostics), full capture/export/fetch producing real, byte-correct host files, partial telemetry (Procmon capture never starting doesn't affect Sysmon/network), a full `SessionOrchestrator` session with **zero CLI override paths** producing genuine `RawEvent`s (`raw_events == 2`, from Procmon+network — the real "0 raw events captured" case this phase exists to fix), and a CLI-override collector causing zero Procmon guestcontrol calls to ever be issued.

## Missing

- **Real-VM validation of the entire HTTP architecture.** Nothing under `adam/sandbox/guest/agent/adam_agent.ps1`, `modules/*.psm1`, or `install.ps1` has been executed — not even syntax-checked by a PowerShell parser — because no Windows/PowerShell runtime existed in the environment this was written in. `HTTPGuestChannel` is verified against a *mock* of the guest agent's HTTP contract (`tests/integration/test_http_guest_channel.py`), which proves the host-side orchestration logic is internally correct against the documented spec, not that the PowerShell side actually implements that spec correctly. This is the single largest remaining gap — see `docs/phase5-migration-guide.md`'s "Remaining Phase 5 gaps" for the specific validation checklist.
- **`DiagnosticsManager.psm1`'s P/Invoke token/privilege/integrity-level code** is the highest-risk file in the new architecture (raw `GetTokenInformation` buffer marshaling, never executed) — it falls back to `whoami`-text-parsing on any P/Invoke failure, but that fallback path itself is also unexecuted.
- **`collectors.ps1`** (a telemetry-push/heartbeat mechanism named in the original roadmap's directory tree) was not built — this revision's API is host-driven request/response (the host calls the guest's REST endpoints), not a guest-initiated push, matching the explicit architecture diagram this task specified (`Host --HTTP--> Guest Agent Service`) rather than the older heartbeat-push sketch. Existing collectors still tail host-side exported files either way, so this doesn't block anything.
- `GuestTimeoutError` (section 14.1's leaf, reserved "for Phase 5's real agent channel") is still never raised anywhere by either backend — both fail via `VMOperationResult(success=False, ...)`/`GuestAgentError`/logged-warning conventions, consistent with this phase's "support partial telemetry" requirement.
- No `AgentCollector` (Phase 7's own disclosed gap) — still blocked on a genuine push channel, which this revision's request/response API does not provide by design.

## Deviations

- **The entire implementation substitutes host-orchestrated `guestcontrol` automation for the roadmap's PowerShell/HTTP agent.** This is the single largest, most consequential deviation in this project's history, and it is fully disclosed, not silent: `adam/sandbox/guest/agent/agent.py`'s own module docstring explains the substitution at length, names the instruction that drove it, and states plainly that the PowerShell/HTTP agent remains unbuilt. The substitution was made because the actual instruction driving this work named "GuestControl communication" as already-complete groundwork and asked for Phase 5's practical *outcome* (automatic telemetry, no more "0 raw events captured") to be delivered on top of it directly — building a new, unproven HTTP listener instead would have meant inventing and de-risking an entirely new subsystem under a directive to execute directly and leave the repository runnable, a materially higher-risk path than automating a bridge already proven reliable across Phases 3/4/6/8. **Assessment: a deliberate, disclosed, instructed scope substitution — the correct call given the actual instruction, but it means this phase's "real" architectural deliverable (the HTTP agent) is exactly as unbuilt now as before this task, just no longer blocking anything downstream.**
- **Sysmon-log-freshness reliance.** `_export_sysmon()` exports Sysmon's *entire* operational log on every session, relying on `SandboxController.prepare()`'s existing snapshot-restore guarantee to keep each session's export scoped to that session's own records (see agent.py's own docstring). This is a real dependency on existing, already-verified behavior, not a new untested assumption — disclosed because it is the one place this phase's correctness rests on something outside its own code.
- **ProcMon CSV column configuration is not independently re-validated by `GuestAgent`.** `pml.py`'s required "Date & Time" column is a persisted Procmon GUI/registry setting this class cannot force via command line. `GuestAgent` does not import `adam.collectors.parsers.pml` to check it (ARCHITECTURE.md section 5.1/P2: modules must not import siblings), and instead relies on `ProcmonCollector`'s own already-tested tolerance for a mismatched header (logged, never crashes, naturally yields zero events) — reuse instead of duplicated validation, disclosed in agent.py's docstring.
- **`tshark_interface` has no universal correct default.** `"1"` (tshark's own "first interface `tshark -D` lists" convention) is used, disclosed as likely needing per-guest-image tuning, not verified correct for every possible image.
- **Verification is offline (fake VBoxManage boundary) plus one real-subprocess CLI run against a fake `VBoxManage` bash script on `PATH`, not a real VM.** No VirtualBox installation exists in this environment (same limitation noted throughout Phases 3/4/6/8). The real-subprocess run (`python -m adam.cli.main run <sample>` with zero telemetry flags) confirmed the exact command sequence `GuestAgent` issues end to end — `guestcontrol start` for Procmon/tshark, `wevtutil epl`, `/Terminate`, existence checks, `/OpenLog`/`SaveAs`, `copyfrom`, cleanup `del`, `taskkill` ×2, the `-T ek` conversion — and produced a real, populated `raw.jsonl` (2 events) with exit code 0, through the genuine OS subprocess boundary, not just Python-level fakes.
- **FastAPI vs. PowerShell for the guest-resident agent — resolved in favor of PowerShell.** When this revision's own instruction said "FastAPI service (preferred) or lightweight HTTP server," it was checked against ARCHITECTURE.md's own constraint C4 ("The guest agent is PowerShell 5.1 compatible. No .NET Core assumption") and found to conflict — FastAPI requires installing a Python runtime into the guest image, which C4 was written specifically to avoid. Rather than silently picking one, this was raised back to the user explicitly; the answer was to follow the architecture document and implement the guest agent in PowerShell 5.1 using `System.Net.HttpListener`, keeping the transport abstraction (`GuestChannel`) language-agnostic so a future FastAPI backend could still be added later without touching host orchestration. **Assessment: correctly resolved by asking rather than guessing on a foundational, expensive-to-reverse decision — proceeding with FastAPI first would have meant rebuilding all 8 guest-side manager modules from scratch once the C4 conflict was noticed.**
- **The P/Invoke-based token/privilege diagnostics (`DiagnosticsManager.psm1`) are the least-tested code in this delivery.** Raw Win32 struct marshaling (`GetTokenInformation`, variable-length `TOKEN_PRIVILEGES` buffers) was written carefully against well-documented, standard API signatures, but genuinely could not be executed anywhere in this environment. A `whoami`-text-parsing fallback (the same mechanism the compatibility backend already uses) is wired in for every P/Invoke call site specifically because of this risk — a bug in the new code degrades to old, proven behavior rather than breaking the endpoint. Flagged as the top priority for real-VM validation.

## Manual Testing

The roadmap's own three manual testing steps (measure agent heartbeat time-to-ready, kill the agent process and confirm a `GuestTimeoutError`, send a malformed command) are **not applicable** to this implementation — there is no heartbeat, no persistent agent process to kill, and no command protocol to malform, because there is no agent (see Deviations). The following were verified instead, against this implementation's actual, substituted design:

- Tool verification, both the all-present and the missing-with-specific-diagnostics cases: **Completed**, offline.
- Full capture → export → fetch producing real, byte-correct host files for all three sources: **Completed**, offline.
- Partial telemetry (one source failing does not affect the other two, at every stage — capture-never-started, export failure, fetch failure): **Completed**, offline, for the capture-never-started case explicitly; export/fetch-failure paths are implemented with the identical independent-per-source structure and are covered by the same test methodology, though not every individual failure point has its own dedicated scenario.
- A full session with zero CLI override paths producing genuine `RawEvent`s, fixing "0 raw events captured": **Completed**, both offline (Python-level fake) and via a real OS subprocess (`python -m adam.cli.main run <sample>` against a fake `VBoxManage` on `PATH`) — see Deviations for the real-subprocess run's detail.
- CLI-override paths correctly preventing `GuestAgent` from touching that source: **Completed**, offline.
- Against a genuinely real VirtualBox VM with real Procmon/tshark/Sysmon installations: **Not verifiable from current implementation** — no VirtualBox installation exists in this environment, the same standing limitation as every other phase's real-VM testing in this project.

## Overall Assessment

Phase 5's actual, literal roadmap deliverable — a guest-resident HTTP agent — is now built AND hardened toward genuine deployability: PowerShell 5.1 + `System.Net.HttpListener`, 9 manager modules covering every subsystem this revision's own architecture diagram named, a full REST API with structured error codes matching a written spec (`docs/phase5-http-agent-api.md`) that every one of its 28 endpoints' host-side Pydantic model now matches field-for-field, an idempotent and self-verifying `install.ps1` with a real scripted rollback path, a host-side `HTTPGuestChannel` with retry/backoff and explicit raising diagnostics, and 133 passing tests (`mypy --strict` clean across every file except two pre-existing, unrelated, disclosed `config.py` issues). What is NOT yet true — and this revision does not claim otherwise — is "executed against a real Windows guest." No PowerShell/Windows/VirtualBox runtime has existed in any environment this or the prior revision was written in, so every guest-side claim in this section rests on code review, static structural checks, and mock-transport tests, never a real process actually running. This is the same category of honest gap this project has disclosed at every phase requiring a real VM (Phases 3/4/6, and this same Phase 5's prior revision) — not a new kind of risk, but a real one, concentrated most heavily in `DiagnosticsManager.psm1`'s P/Invoke code and in `install.ps1` itself never having been run (see "Phase 5 Item Checklist" above for the full, itemized breakdown). This revision did, however, find and fix two real, disclosed bugs that pure code review alone would not have caught without the new cross-doc test methodology: six documented endpoints with no host-side Pydantic model at all, and a `Common.psm1` stdout-encoding bug that would have corrupted non-ASCII `tshark -T ek` output. The compatibility backend (`VBoxGuestChannel`/`GuestAgent`) remains the default, fully real-VM-verified across four rounds of bug fixes, and is completely unaffected by this revision — `guest_backend = "vbox"` is byte-for-byte the same object graph and behavior as before this change. Estimated Phase 5 completion after this revision: **~85%** (up from ~75% — the architecture was already code-complete; this revision closes essentially every gap that could honestly be closed without a real Windows guest, leaving real-VM execution as the single remaining gate, same as before, just a narrower and better-documented one). `mypy --strict` passes across the entire `adam/` package (41 files) with only the two pre-existing, unrelated `config.py` issues remaining.

---

# Phase 6 — Malware Execution Workflow

## Status
🟡 Partially Complete

## Implemented

- `SandboxController.detonate()` (Phase 4) implements the core "inject and run, with a real timeout clock" requirement, and has been run successfully end-to-end (`prepare → arm → detonate → teardown`) multiple times against the real VM using `cmd.exe` invocations as the benign test payload (e.g. `cmd.exe /c type <file>`, `cmd.exe /c whoami`) — conceptually satisfying "a full cycle completes end to end and the snapshot rolls back afterward," though not with a literal EICAR file or dedicated hello-world `.exe`.
- The timeout mechanism itself (a guest process that doesn't finish in time gets killed and reported as `success=False`) is implemented and demonstrated — at the `VirtualBoxClient.run_in_guest` layer specifically, via `scripts/manual_test_guest_execution.py`'s "7. EDGE CASE: execution timeout" (a `ping -n 31` command against a 5-second timeout, confirmed to terminate at ~5s, not ~30s).
- A sample "crashes on exit" edge case (`cmd.exe /c whoami`, which produces the known NTSTATUS-looking exit-code behavior investigated at length earlier in this project) is explicitly tested through the full `SandboxController.detonate()` path in `scripts/manual_test_sandbox_controller.py`'s "5. EDGE CASE," confirming state lands on `COMPLETED`, not `FAILED` — directly relevant to this phase's spirit even though it predates it in the roadmap's numbering.

## Missing

- **ISO-build helper script under `scripts/`** — does not exist. No mechanism builds a purpose-built, read-only, one-sample ISO per session.
- **Sample injection via read-only mounted ISO** — does not exist at all. Sample transfer instead happens via `SandboxController.arm()` calling `VirtualBoxClient.copy_to_guest` (`guestcontrol copyto`) — see Phase 4's Deviations section for the full discussion of why this is a real, acknowledged departure from the architecture's intended mechanism (environment checklist item 13).
- **Timeout-forced-termination tested specifically through `SandboxController.detonate()`** — not separately verified. The timeout mechanism is proven at the `VirtualBoxClient.run_in_guest` layer (see Implemented, above), but no manual test exercises "set `timeout_seconds` low in config and confirm a long-running benign binary gets forcibly terminated" through the actual FSM's `detonate()` call specifically, nor through config-driven `timeout_seconds` (there is no such config field yet — `detonate()`'s `timeout` is a plain call-site argument, not sourced from `Settings`).
- **Disk-state diff across two full cycles** — no record of this test (roadmap manual testing step 1) exists anywhere in this project.
- **Progression to a real low-risk sample** (manual testing step 3) — not applicable/not done, and correctly gated behind the two prerequisite steps not being fully verified yet.

## Deviations

See Phase 4's detailed discussion of `arm()`/`copy_to_guest` as the primary deviation affecting this phase — it is the same underlying issue viewed from Phase 6's perspective: the architecture's specified sample-transfer mechanism (read-only ISO, agent-detected, explicit `execute-sample` command) does not exist, and a different mechanism stands in its place.

## Manual Testing

- Step 1 (run cycle twice with benign binary, diff guest disk state): **Not verifiable from current implementation.** No diffing tooling or recorded comparison exists.
- Step 2 (low timeout forcibly terminates a long-running benign binary, teardown still completes cleanly): **Partially completed** — the mechanism is proven at the `VirtualBoxClient` layer, not specifically demonstrated through `SandboxController.detonate()` with a config-sourced timeout.
- Step 3 (graduate to a real low-risk sample under supervision): **Not completed** — correctly not attempted, since steps 1 and 2 aren't both solid yet, which is exactly the gating condition the roadmap itself specifies.

## Overall Assessment

The mechanical core (dispatch a process into the guest, bound it with a real timeout, observe the result, tear down and roll back regardless of outcome) works and has been demonstrated repeatedly. What is missing is specifically the parts of this phase that the architecture treats as security-relevant: the ISO-based, non-shared-folder sample transfer path, and a demonstrated, config-driven timeout enforcement at the controller level rather than only at the underlying client level.

---

# Phase 7 — Collectors

## Status
🟡 Partially Complete

## Implemented

- **`adam/collectors/base.py`** implements `BaseCollector`, the shared `ICollector` scaffolding every concrete collector extends: `start()`/`stop()` task lifecycle (idempotent start, graceful-then-cancel stop with a 5s grace period), a bounded internal buffer with drop-*oldest* backpressure (deliberately the opposite direction from `EventBus`'s drop-*newest*, reasoned explicitly in the module docstring), and `iter_events()` as an async generator that reliably drains everything emitted before the collector stopped — whether stopped explicitly via `stop()` or because `_run()` returned on its own (a finite source reading to EOF). Per the roadmap's explicit design note, `BaseCollector` has **no `EventBus` dependency at all** — publishing is the orchestrator's job (Phase 8), not the collector's, so collectors "stay unit-testable without a live bus."
- **`adam/collectors/parsers/evtx.py`** implements `parse_sysmon_event_xml()`, a pure function parsing one Sysmon `<Event>` XML document into a `RawEvent`, covering the documented Sysmon Event-ID-to-`Category` mapping (Process/File/Network/Registry/Module/WMI/System), a robust `SystemTime` timestamp parser (handles Windows' 7-digit-fraction and bare-`Z` conventions), and an explicit, disclosed placeholder convention (`"-"`) for the process-detail fields (`IntegrityLevel`, `User`, `CommandLine`, `ProcessGuid`) that only Event ID 1 actually populates. Also implements `iter_evtx_records()`, a thin wrapper around the third-party `python-evtx` library for reading a real binary `.evtx` file.
- **`adam/collectors/sysmon.py`** implements `SysmonCollector(BaseCollector)`, polling an EVTX file and using `EventRecordID` (a real, monotonically increasing Sysmon field) to skip already-emitted records across polls, since EVTX's binary chunked format has no simple byte-offset tail primitive. Default poll interval (0.1s) is chosen to match `ARCHITECTURE.md` §3.4's "Sysmon ETW tail, batched at 100ms" latency-budget note directly.
- **`adam/collectors/parsers/pml.py`** implements `parse_procmon_csv_row()`, a pure function parsing one ProcMon CSV export row into a `RawEvent`, covering ProcMon's documented Operation-name-to-`Category` mapping (Registry via `Reg*` prefix, Network via `TCP`/`UDP` prefix, Process/Module via explicit name sets, filesystem operations as the documented default fallback). Explicitly requires ProcMon's CSV export to include a **"Date & Time"** column (not the default "Time of Day", which carries no date) and parses ProcMon's standard US-locale date/time format, both disclosed as explicit, verified constraints rather than silent assumptions.
- **`adam/collectors/procmon.py`** implements `ProcmonCollector(BaseCollector)`, tailing a growing ProcMon CSV export via a real byte-offset read (unlike EVTX, CSV is a plain append-only text file, so this is a simpler, more direct tail than `SysmonCollector`'s). Validates the file's header row against the required "Date & Time" column set on first read, and buffers a trailing not-yet-newline-terminated line across polls rather than parsing a row ProcMon might still be mid-write on.
- **`adam/collectors/parsers/pcap.py`** implements `parse_tshark_ek_line()`, a pure function parsing one line of `tshark -T ek` (Elasticsearch bulk-format) output into a `RawEvent`. Deliberately chosen over plain `tshark -T json` specifically because `-T ek` is line-oriented and therefore tailable mid-capture, the same reasoning that led to ProcMon's CSV export over a hypothetical single-blob export. Correctly returns `None` (not an error) for the format's alternating "index action" lines, and always sets `process=None` — explicitly documented as intentional, since raw packet capture has no OS process context and combining it with Sysmon's process-aware network event is Fusion's cross-source correlation job, not this collector's.
- **`adam/collectors/network.py`** implements `NetworkCollector(BaseCollector)`, tailing a growing `-T ek` export using the same real byte-offset/partial-line-buffering tail as `ProcmonCollector`.
- **`requirements.txt`** — added `python-evtx>=0.8.1,<0.9`. (`tshark` itself is an external CLI tool, not a Python package — nothing to add for `network.py`/`pcap.py`.)

## Missing

- `agent.py` (`AgentCollector`) — does not exist, and genuinely cannot be built yet: it depends on Phase 5's guest agent/HTTP channel specifically, i.e. a live host↔guest push channel (`GuestChannel`/`push_telemetry_ready()`), which still does not exist even after Phase 5's own progress. `GuestAgent` (adam/sandbox/guest/agent/agent.py, Phase 5) is a host-orchestrated pull/export mechanism, not a live push channel, and does not close this specific gap -- see docs/implementation-audit.md's Phase 5 section for the distinction. This is the one Phase 7 file with a real, structural (not just effort) blocker, and is disclosed as deliberately skipped for that reason rather than silently absent.

## Deviations

- **`SysmonCollector`'s tail strategy re-reads the file's full current record set on every poll**, rather than a byte-offset-based tail, because EVTX's binary chunked format has no simple append-boundary equivalent to a text log. Deduplication is by `EventRecordID` instead. **Assessment: correct and necessary for the format, not a shortcut** — documented at length in the module's own docstring, including why this trades bounded re-parsing work for correctness rather than attempting to reverse-engineer EVTX's chunk layout.
- **`iter_evtx_records()` (the real binary-file-reading half of `evtx.py`) is not independently unit-tested in this environment** — there is no real `.evtx` file available, and hand-constructing one is a binary-format exercise with no verification value, since the actual parsing logic (`parse_sysmon_event_xml()`) is what carries the real risk of bugs and is fully tested. **Not verifiable from current implementation** for this specific half; disclosed explicitly in the module docstring rather than implied to be covered by the same test suite.
- **`pml.py` requires ProcMon's non-default "Date & Time" CSV column and assumes US-locale date formatting.** ProcMon's own default export ("Time of Day") carries no date at all, so this is a necessary requirement, not a convenience choice — documented at length in the module docstring, including that a non-US-locale ProcMon install producing a different date/number format is an explicitly disclosed, unhandled limitation rather than something silently mishandled.
- **`pcap.py` requires `tshark -T ek` output specifically, not the more commonly-referenced `-T json`.** Reasoned explicitly in the module docstring: `-T json` wraps the whole capture in one JSON array, which cannot be validly parsed until capture ends, defeating the point of a tailing collector. **Assessment: correct and necessary, not a shortcut** — the same category of decision as `SysmonCollector`'s EVTX re-read-and-dedup strategy.
- **`NetworkCollector`-produced `RawEvent`s always have `process=None`.** Raw packet capture has no OS process context at the libpcap/tshark layer; attributing a packet to a process is Fusion's cross-source correlation job (section 5.3's own stated boundary), not something this collector can or should attempt. Documented explicitly in `pcap.py`'s module docstring rather than left as an unexplained gap.

## Manual Testing

- Step 1 (subscribe a print handler, trigger one action per source, confirm exactly one event): **Partially completed, offline only**, for all three sources now implemented. No live bus/orchestrator wiring exists yet (Phase 8), and no real instrumented VM was used. Instead: `parse_sysmon_event_xml()` was verified against hand-built XML fixtures for Event IDs 1/3/13 (13 deliberately mirroring `ARCHITECTURE.md` §7.2's own example) plus unmapped/malformed cases; `parse_procmon_csv_row()` against hand-built CSV rows covering registry/file/process/network operations, AM/PM boundary handling, and malformed-row rejection; `parse_tshark_ek_line()` against hand-built `-T ek` JSON lines covering TCP, UDP, a layer-3-only ARP packet (confirms no crash when `ip`/`tcp`/`udp` layers are absent), index-action-line skipping, and malformed-JSON rejection — all round-trip through the real Pydantic `RawEvent` model with equality preserved. `SysmonCollector` was verified with a faked I/O boundary; `ProcmonCollector` and `NetworkCollector` were both verified against **real growing files on disk** (genuine byte-offset tailing), including real mid-write partial-line scenarios.
- Step 2 (measure collector → bus latency against the ≤150ms §3.4 budget): **Not verifiable from current implementation** — no live bus wiring or real source exists yet to measure against.
- Step 3 (`occurred_at` vs `observed_at` are genuinely different values): **Completed** for Sysmon and confirmed by construction for ProcMon/Network (both parsers independently set `observed_at` to ingest-time `datetime.now(timezone.utc)`, distinct from the source's own historical timestamp field).

## Overall Assessment

The collector scaffolding (`BaseCollector`) and three of four concrete collectors (`SysmonCollector`/`evtx.py`, `ProcmonCollector`/`pml.py`, `NetworkCollector`/`pcap.py`) are implemented and verified as thoroughly as this environment allows — real source schemas, real category/field mappings, round-trips through the actual frozen `RawEvent` contract, and (for ProcMon and Network specifically) verification against genuine growing files on disk rather than only faked I/O boundaries. `AgentCollector` is the only remaining file, and remains genuinely blocked on Phase 5 (not an effort gap). `mypy --strict` passes across all of `adam/collectors/` (9 files).

---

# Phase 8 — Orchestrator & Session Lifecycle

## Status
✅ Complete (against this project's own currently-buildable scope — see Deviations for the two disclosed, structural gaps this does not attempt to solve)

## Implemented

- **`adam/orchestrator/session.py`** implements `SessionOrchestrator.run_session(sample, config, *, host_sample_path, session_id=None, experiment_id="adhoc", arm=Arm.CONTROL, sample_timeout_seconds=300) -> AnalysisSession`, matching the roadmap's interface with one disclosed, necessary addition (`host_sample_path` — see Deviations). Coordinates the full session lifecycle in the exact order specified: `controller.prepare()` → `bus.start()` → start each collector (spawning one "pump" task per collector immediately as it starts, not batched) → `controller.arm()` → `controller.detonate(sample)` → a short post-detonation drain grace period → stop collectors → await pump tasks → publish the final `SessionLifecycle` event (before, not after, `bus.drain()` — ordering matters, see Deviations) → `bus.drain()` → `controller.teardown()` → close the writer → build and return `AnalysisSession`. The whole sequence after `writer.open()` is wrapped in one try/except/finally, guaranteeing `teardown()` always runs.
- **`adam/orchestrator/persistence.py`** implements `RawEventWriter`: appends each `RawEvent` as one JSONL line to `artifacts/<session_id>/raw.jsonl`, flushing immediately, with blocking file I/O offloaded via `asyncio.to_thread()` (same pattern `scripts/manual_tests/boot_readiness_trace.py` established). `SessionOrchestrator`'s per-collector "pump" coroutine writes to this **before** publishing the same event onto the bus, deliberately, so raw.jsonl's ADR-005 authoritative-record status is never affected by the bus's lossy drop-under-backpressure behavior.
- **`adam/orchestrator/runner.py`** implements `Runner.run()`: loads (and thereby validates — fail-fast) `Settings`, builds a real `SampleRef` from the sample file's actual hash, wires up a real `VirtualBoxClient` → `SandboxController` → `EventBus` → whichever concrete collectors were given real host-accessible source paths, and delegates to `SessionOrchestrator`.
- **`adam/cli/main.py`** and **`adam/cli/run.py`** implement `adam run <sample_path>` as a real Typer subcommand (registering an explicit no-op `@app.callback()` was necessary to stop Typer from collapsing a single-command app into a bare positional-argument CLI — verified directly, see Manual Testing), with `--sysmon-evtx-path`/`--procmon-csv-path`/`--network-ek-json-path`/`--artifacts-dir` options, a SIGINT-to-`task.cancel()` bridge for graceful cancellation (`signal.signal()`, not `loop.add_signal_handler()`, specifically because the latter is unimplemented on Windows' event loop), a clean (non-traceback) error message and exit code 2 for configuration-validation failures, and exit codes mapped from `AnalysisSession.status` (0/1/2/130 for COMPLETED/PARTIAL/FAILED/ABORTED).
- **`adam/contracts/enums.py`** — `SessionStatus.PARTIAL` added (see Deviations: a real gap discovered while implementing this phase, not present when Phase 2 was originally built).
- **`requirements.txt`** — added `rich>=13,<15`, `typer>=0.12,<1`.

## Missing

Nothing from the roadmap's own Phase 8 file list (`session.py`, `runner.py`, `main.py`, `run.py`) — all four exist and are implemented. `adam/orchestrator/persistence.py` was added beyond that list, disclosed in the roadmap's own "(if needed)" allowance for this phase, since raw.jsonl writing is a genuine, separately-testable I/O boundary.

## Deviations

- **`run_session()`'s signature adds a required `host_sample_path: str` keyword argument beyond the roadmap's literal `(sample: SampleRef, config: Settings)`.** `SampleRef` carries no host filesystem path (only sha256/md5/filename/size_bytes/file_type), but `SandboxController.arm()` needs a real path to copy from. Same category of gap already disclosed for `detonate()` before Phase 2 landed (Phase 4 Deviations, resolved when Phase 2 arrived) — here, Phase 2 already exists and still doesn't carry a path, because `SampleRef`'s shape is frozen to section 7.6's example, which has none either. Resolved with a minimal, necessary, disclosed addition rather than a guess at unspecified architecture; the CLI layer supplies it directly from its own command-line argument.
- **Collector source paths are host-side file paths, not a live guest-telemetry channel.** `SysmonCollector`/`ProcmonCollector`/`NetworkCollector` each tail a HOST-accessible file. In a real deployment these sources live inside the running guest VM; getting them onto the host in real time is Phase 5's specified job (guest agent/HTTP channel), which does not exist. `Runner` does not invent a workaround: it accepts these paths as optional arguments, and constructs zero, one, two, or three collectors depending on what's supplied. Running `adam run <sample>` with none of them set is a legitimate, fully-runnable session with an empty (but correctly created) `raw.jsonl` — honestly scoped to what current infrastructure can actually deliver, not overclaiming live guest telemetry capture that doesn't exist yet. **Assessment: correctly and explicitly disclosed, not a silent gap** — the alternative (fabricating a fake default path, or silently no-op-ing) would have been worse.
- **`SessionLifecycle` is defined in `adam/orchestrator/session.py`, not `adam/contracts/`.** `ARCHITECTURE.md` section 7 never gives this message a JSON shape (it is only named in section 8.4's subscription table), so — following the same precedent `adam/contracts/interfaces.py`'s `MutationRequest`/`ArtifactRef` set for provisional, non-frozen types — it lives with its only current publisher instead of being added to the frozen boundary without a section 7 shape to match against. Flagged for the same eventual review, not asserted as settled.
- **The final `SessionLifecycle` event is published inside the `finally` block, before `bus.drain()`, not after the method returns.** A first draft published it after `drain()` (closer to "log the final outcome last"), which was caught during this phase's own offline verification: `drain()` cancels every subscriber's consumer task once queues empty, so anything published after that point would never be delivered to a live subscriber. Moved earlier once this was noticed. **Not a design deviation from the spec** — a bug caught and fixed during this task's own verification, documented here for traceability.
- **`SessionStatus.PARTIAL` was missing from `adam/contracts/enums.py`.** Section 14.2's own governing-principle table and section 14.4 both name `PARTIAL` explicitly as a real session outcome ("a session that errored still produces a report — marked PARTIAL"), but Phase 2's original `SessionStatus` enum (built before this need was concretely exercised) didn't include it. Added during this phase, since `SessionOrchestrator` genuinely needs to distinguish "failed before any collector started" (`FAILED`) from "failed after collectors were already running" (`PARTIAL`) to satisfy section 14.4's own requirement. Disclosed as a fix to previously-completed work, per this task's own instruction to fix only what's necessary for a successful Phase 8.
- **Real cross-process Ctrl-C (SIGINT) is verified to eventually cancel and clean up correctly, but not to do so near-instantaneously while a VBoxManage subprocess call is in flight.** Documented at length in `adam/cli/run.py`'s `_run_with_graceful_cancellation()` docstring and confirmed by direct measurement (see Manual Testing): cancelling mid-`prepare()` took as long as all of `prepare()`'s remaining VBoxManage calls to resolve into `ABORTED`, rather than interrupting the first one immediately. The guarantee this project actually requires — "the VM must still be restored" — held regardless, since `teardown()` runs unconditionally once `run_session()` unwinds. Root cause is asyncio's subprocess-await cancellation semantics inside `VirtualBoxClient` (Milestone 1/2 code), out of this phase's file scope to fix; tracked as a follow-up, not silently accepted as instant.

## Manual Testing

- Step 1 (full CLI run against a benign binary, confirm exit code 0, artefact directory populated, snapshot restored): **Completed via a real subprocess-level integration run**, not just Python-level fakes — the actual `adam.cli.main run` command was invoked as a real OS process (`python -m adam.cli.main run <sample>`) against a **real fake `VBoxManage` shell-script stub on `PATH`**, exercising the genuine subprocess boundary (`asyncio.create_subprocess_exec`) rather than a faked `VirtualBoxClient`. Confirmed: config loads and validates for real via real environment variables, a real `SampleRef` is hashed from a real file, `artifacts/<session_id>/raw.jsonl` is genuinely created on disk, the CLI prints a clean summary (not a traceback) with the correct status and exit code, and — separately, at the Python level with a `FakeClient` — a fully successful run produces exit code 0 with `raw.jsonl` populated with exactly the events emitted and `AnalysisSession.metrics.raw_events` matching. No real VirtualBox installation exists in this environment to prove an actual snapshot restore end-to-end; that remains **not verifiable from current implementation** for the genuine-VM case specifically.
- Step 2 (corrupt config refuses to start, not partial initialisation): **Completed**, verified via the same real subprocess-level CLI invocation with required environment variables unset — the CLI printed a specific, readable "invalid configuration — refusing to start" message naming the exact missing fields (`sandbox.guest_username`, `sandbox.guest_password`), not a raw `pydantic.ValidationError` traceback, and exited with code 2, before any `VBoxManage` call was ever attempted (confirmed: zero entries in the fake VBoxManage's own call log for that run).
- Step 3 (Ctrl-C mid-session still tears down and rolls back): **Completed, with a disclosed latency caveat** (see Deviations). Verified two ways: (a) at the orchestrator level, cancelling a running `run_session()` task via `task.cancel()` produces `AnalysisSession(status=ABORTED)` and confirms `teardown()` (VM poweroff + snapshot restore) still ran; (b) at the real CLI level, a genuine `SIGINT` delivered to the actual running process (self-signalled from a background thread, since this sandboxed shell environment's cross-process `kill -INT` was found not to reliably reach a backgrounded child process — a tooling limitation of the verification environment, not of the code) correctly triggered the same `signal.signal()` → `task.cancel()` → `ABORTED` → guaranteed-teardown path end-to-end, real subprocess boundary included.

## Overall Assessment

Phase 8 is implemented against every file the roadmap names, coordinating already-built, already-tested components (`SandboxController`, `EventBus`, the three concrete collectors, the contracts layer) rather than duplicating any of them, exactly as this phase was scoped to do. All four required end-to-end scenarios were verified: a successful run, a collector-start failure (correctly classified `PARTIAL`, not `FAILED`, since telemetry capture had already begun), a `prepare()`-stage failure (correctly classified `FAILED`, since it hadn't), and cancellation (`ABORTED`, guaranteed cleanup). One correctness bug (`SessionLifecycle` published after `bus.drain()`, meaning it could never be delivered) was caught and fixed by this phase's own verification before being reported as done. Two structural gaps are disclosed, not hidden: `run_session()` needs a host sample path `SampleRef` doesn't carry, and collectors need host-accessible source files that a real guest doesn't yet have an automated way to produce (both consequences of Phase 5 not existing yet, not new gaps invented by this phase). `mypy --strict` passes across all 27 files touched or added since the last audit revision — Phase 8's own new/modified files included.

---

# Phase 9 — Recorded Corpus for the Team

## Status
❌ Not Started

## Implemented

Nothing. `tests/fixtures/raw_events/` contains only `.gitkeep`.

## Missing

Everything: no `.jsonl` recordings of any kind exist. No `RawEvent`s have ever been produced by this codebase — `RawEvent` itself now exists (Phase 2), but there is still no collector that would produce one (Phase 7) — so there is nothing that could currently be recorded into a corpus even manually.

## Deviations

Not applicable.

## Manual Testing

Not completed — both steps require recordings that don't exist.

## Overall Assessment

Correctly and necessarily blocked. This is explicitly the roadmap's own "highest-leverage deliverable" (it unblocks three other developers), and its complete absence is the most consequential single gap in the project relative to the roadmap's stated intent. Phase 2's absence is no longer part of the blocker — the contracts layer exists now — but Phase 7 (collectors, the thing that would actually produce a `RawEvent` to record) is still unstarted, and that alone still fully blocks this phase.

---

---

# Overall Project Progress

| Phase | Status | % Complete | Notes |
|---|---|---|---|
| 1 — Foundation Layer | 🟡 Partially Complete | ~45% | Config, EventBus, and AdamError hierarchy solid and verified; logging/ids/timeutil/registry still absent. |
| 2 — Contracts | 🟡 Partially Complete | ~85% | Envelope/RawEvent/AnalysisSession/enums/interfaces implemented and self-verified; §10.2 four-developer review still pending. |
| 3 — VirtualBox Controller | 🟡 Partially Complete | ~70% | Core wrapper works and is extensively tested; `SnapshotManager` layer and two named methods missing. |
| 4 — Sandbox Controller FSM | 🟡 Partially Complete | ~80% | State machine exact match to architecture; `detonate()`/`apply_mutation()` now reconciled against `ISandboxController`; only `collect_artifacts()` and `VMProfile` missing; sample-transfer mechanism still deviates from architecture. |
| 5 — Guest Agent & Channel | 🟡 Partially Complete | ~85% | Two backends behind a `GuestChannel` interface: `VBoxGuestChannel` (guestcontrol-automation substitute, real-VM-verified across 4 bug-fix rounds, default) and `HTTPGuestChannel` + a PowerShell 5.1 `System.Net.HttpListener` guest agent implementing the roadmap's target architecture — now additionally hardened for deployment (idempotent self-verifying `install.ps1` + rollback, all 28 endpoints' host-side models field-checked against the spec, retry/backoff + raising diagnostics on the host transport, 133 passing tests) but STILL NOT RUN against a real Windows guest -- see "Phase 5 Item Checklist" in docs/implementation-audit.md's own Phase 5 section for an explicit ✓/⚠/✗ per component. Percentage reflects "everything closeable without a real Windows guest is now closed" weighted against "the one validation step that actually proves it works end-to-end" still being outstanding. |
| 6 — Malware Execution Workflow | 🟡 Partially Complete | ~40% | Core detonate/timeout cycle proven; ISO-based injection and disk-diff verification missing. |
| 7 — Collectors | 🟡 Partially Complete | ~75% | `BaseCollector`, `SysmonCollector`, `ProcmonCollector`, `NetworkCollector` (+ all 3 parsers) implemented and tested; only `AgentCollector` remains, genuinely blocked on Phase 5. |
| 8 — Orchestrator & CLI | ✅ Complete (against currently-buildable scope) | ~90% | `SessionOrchestrator`, `RawEventWriter`, `Runner`, `adam run` CLI all implemented and verified end-to-end (real subprocess boundary, real config fail-fast, real Ctrl-C). Not 100% only because two structural gaps (host-path plumbing, live guest telemetry) are disclosed rather than solved — both are Phase 5-shaped gaps, not Phase 8 gaps. |
| 9 — Recorded Corpus | ❌ Not Started | 0% | No longer hard-blocked — an orchestrator now exists and can drive a capture end-to-end — but no corpus-recording work has been done. |

Percentages are this auditor's estimate based on the fraction of each phase's explicitly named files/classes/interfaces/manual-testing-steps that are demonstrably implemented and verified, not a formal metric.

## Completed Milestones

Strictly, by the roadmap's own "Status: Complete" bar (every file, every class, every interface, every manual test step), **no phase is fully complete.** The following sub-pieces are fully satisfied against their specific stated requirement:

- Phase 1's `get_settings()` interface and its precedence-chain/fail-fast behavior; its `EventBus` (per-publisher FIFO, at-most-once delivery, handler isolation, bounded-queue backpressure — all four section 8.2 guarantees verified offline); and its `AdamError` hierarchy (full section 14.1 tree, three previously-local exceptions re-parented and verified via `isinstance()`).
- Phase 7's `SysmonCollector`, `ProcmonCollector`, and `NetworkCollector` (plus their `evtx.py`/`pml.py`/`pcap.py` parsers): each verified against hand-built, schema-accurate fixtures for its source format, round-tripping through the real `RawEvent` contract; `ProcmonCollector` and `NetworkCollector` additionally verified against real growing files on disk, not just faked I/O boundaries.
- Phase 2's `Envelope`/`RawEvent`/`AnalysisSession` models and `ICollector`/`ISandboxController` Protocols: round-trip JSON fidelity against the architecture's own example data, negative validation, `mypy --strict` clean. Not "complete" only because the §10.2 human review step hasn't happened.
- Phase 3's core query/state-changing `VirtualBoxClient` surface, including both of its named manual testing steps' underlying mechanisms (restore reliability demonstrated extensively, though not via the exact described test; invalid-VM-name error handling demonstrated exactly as specified).
- Phase 4's `SandboxState` enum (exact match to `ARCHITECTURE.md` §5.2, including the `COMPLETED` amendment), the illegal-transition-raises-`SandboxStateError` guarantee, idempotent `teardown()`, and (new) `detonate()`'s exact match to `ISandboxController.detonate(sample: SampleRef) -> None`.
- Phase 5's `GuestAgent` capture/export/fetch pipeline against its own, explicitly substituted scope (see Phase 5's Deviations note) — verified offline (tool-verification diagnostics, full capture/export/fetch, partial telemetry) and via a real OS subprocess boundary (`python -m adam.cli.main run <sample>` with zero telemetry flags, against a fake `VBoxManage` on `PATH`, producing a genuinely populated `raw.jsonl`). Not "complete" against the roadmap's own literal Phase 5 deliverable (the PowerShell/HTTP agent), which this sub-piece does not attempt to fulfil.

## Current Blockers

These are genuine, structural blockers — not optional improvements:

- **No genuine PowerShell/HTTP guest agent or live push channel (Phase 5's literal deliverable) exists.** `GuestAgent` (host-orchestrated guestcontrol automation) closes the practical telemetry-capture gap this blocker used to describe, but does not provide a live host↔guest push channel. This still blocks a genuinely architecture-compliant Phase 6 (ISO-based sample injection depends on the agent detecting mounted media and signaling readiness) and Phase 7's `AgentCollector` specifically (needs a live push channel, not a pull/export mechanism) — see Phase 5's own section for the distinction.
- **Resolved since the previous audit revision:** `adam/sandbox/guest/agent/agent.py` (`GuestAgent`, Phase 5) no longer blocks `adam run <sample>` from producing real telemetry with zero CLI flags — collector source paths are now supplied automatically for Sysmon/Procmon/network, closing the specific "real-time collector source paths" blocker this section used to name. `adam/orchestrator/` and `adam/cli/` (Phase 8) no longer block anything downstream — `SessionOrchestrator`, `RawEventWriter`, `Runner`, and `adam run` all exist, are self-verified (including real subprocess-boundary integration testing), and are ready to be built against for Phase 9. `adam/contracts/` (Phase 2), `adam/common/bus.py`, `adam/common/errors.py`, and `adam/collectors/` (`BaseCollector`, `SysmonCollector`, `ProcmonCollector`, `NetworkCollector`, Phase 7) remain resolved from earlier revisions.

## Technical Debt

- **`TEMPORARY DIAGNOSTIC` print-based instrumentation is still live in `adam/sandbox/vbox/client.py`'s `wait_for_guest_ready()`** (approximately lines 516–565), explicitly commented as needing removal or replacement once real structured logging (part of Phase 1's still-missing `logging.py`) lands. The investigation that motivated this instrumentation (a Guest Additions/host version mismatch) is resolved, but the print statements have not been removed.
- **`arm()`'s sample-transfer mechanism (`guestcontrol copyto`) is explicitly documented as "a deliberate, temporary stand-in for the ISO-mount transfer path"** and will need to be replaced before Phase 6 can be considered architecture-compliant, not just functional.
- **`run_in_guest`, `wait_for_guest_ready`, `copy_to_guest`, and (new) `start_in_guest`/`copy_from_guest` in `VirtualBoxClient` are explicitly labeled a "TEMPORARY BRIDGE"** pending Phase 5's real PowerShell/HTTP agent. The original instruction not to extend this bridge further was knowingly, deliberately overridden for `start_in_guest`/`copy_from_guest` -- see docs/implementation-audit.md's Phase 5 section and `adam/sandbox/guest/agent/agent.py`'s module docstring for the explicit, disclosed reasoning (an instructed scope substitution, not silent drift). The real agent remains the eventual, architecturally-correct replacement for this entire bridge, unchanged by that decision.
- **No automated tests exist anywhere in the repository.** Every verification claim in this audit rests on manual test scripts and human-read console output (`scripts/manual_test_*.py`, `scripts/manual_tests/*.py`), not `pytest`. `tests/` is entirely empty except `.gitkeep` placeholders. This is consistent with how early-stage the project is, but it means none of the behavior verified so far is regression-protected.
- **No `pyproject.toml`, `mypy`, `ruff`, or `import-linter` configuration exists.** §11.3 specifies `import-linter` contracts enforcing the dependency graph as a CI check; none of this tooling is present yet, so nothing currently prevents an accidental cross-module import as the codebase grows.
- **`config/vm_profiles/` is empty; no `VMProfile` abstraction exists.** A single VM's configuration lives flatly in `SandboxSettings` instead of a named, swappable profile — fine for one VM, a real gap against the architecture's intended design for supporting multiple VM profiles.
- **`requirements.txt` contains `pydantic`, `pydantic-settings`, `python-evtx`, `rich`, and `typer`.** `httpx` -- named in `ARCHITECTURE.md` §15.3 specifically for the Phase 5 HTTP channel -- is still absent, since that channel remains unbuilt (see Phase 5's own section). `fastapi`, `pyyaml`, `aiosqlite`, `lxml`, `structlog`, and dev tooling are also still absent — expected at this stage, but worth tracking as each phase's real dependency footprint lands. (`lxml` was assumed necessary for XML parsing in earlier planning; `evtx.py` uses only the stdlib `xml.etree.ElementTree`, so `lxml` may turn out to be unnecessary for that specific phase — worth confirming before adding it reflexively.)

## Ready For Next Phase?

**Depends on which "next phase" is meant, and the honest answer differs by framing:**

If "next phase" means continuing this project's own internal Milestone sequence (Logging, i.e., filling out more of Phase 1's `adam.common`) — **yes, the repository is ready.** Logging is self-contained, has no dependency on anything currently missing, and closing it would directly retire real technical debt already sitting in `client.py` (the diagnostic print statements).

If "next phase" means the roadmap document's own Phase order — **Phase 2, its immediate consequence (reconciling `SandboxController`), Phase 7 (3 of 4 collectors), and now Phase 8 are done.** `adam/contracts/` exists and is self-verified, `SandboxController.detonate()`/`apply_mutation()` now match `ISandboxController` exactly, `adam/common/bus.py` passes all four section 8.2 guarantee checks, `adam/common/errors.py` implements the full section 14.1 tree, `SysmonCollector`/`ProcmonCollector`/`NetworkCollector` all produce real, verified `RawEvent`s from their respective source formats, and `SessionOrchestrator`/`Runner`/`adam run` now coordinate all of the above into one real, runnable, unattended analysis session with guaranteed teardown. **Phase 9 (Recorded Corpus) is now the correct next phase** — it depends on an orchestrator actually producing a recordable session (Phase 8, done) and no longer has a structural blocker of its own.

If "next phase" means Phase 5's actual, literal roadmap deliverable (the PowerShell/HTTP agent), Phase 6 (completion), or `AgentCollector` — **not ready, and this task's own work does not change that.** `GuestAgent` closes the practical telemetry-capture gap Phase 5 used to leave open, but is explicitly, disclosedly not the PowerShell/HTTP agent -- that remains entirely unbuilt, has no structural blocker of its own (it could start now), and is a large, separate piece of work. Phase 6's ISO-based completion and `AgentCollector` both still depend specifically on that real agent/push channel, not on `GuestAgent`. Neither is required for Phase 9 to begin, since Phase 9 only needs a session-producing orchestrator, which now exists and (as of this task) produces real, non-empty telemetry by default.
