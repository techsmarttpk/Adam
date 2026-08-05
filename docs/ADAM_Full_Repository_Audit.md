# ADAM — Full Repository Audit & Review Readiness Report

Prepared as Lead Architect / Technical Reviewer pass, ahead of the project review/presentation. Read-only: no code was modified to produce this report. Grounded directly in the repository at `D:\Projects\ADAM\project-adam` as it exists today, cross-checked against `ARCHITECTURE.md` (the frozen spec) and verified where possible by running the real test suite and reading source files directly rather than trusting prior docs. Where an existing doc (`docs/implementation-audit.md`, `docs/known_limitations.md`) made a claim, it was checked against the actual code rather than repeated verbatim.

**Headline finding, stated up front because it should shape the whole presentation:** two of the four developer slices — Fusion (`adam/fusion/`) and the Platform/Presentation layer (`adam/api/`, `adam/db/`, `adam/reporting/`, `adam/dashboard/`) — are empty. Not "partial." Empty: only `.gitkeep` placeholders, zero lines of code. This means the "closed adaptive loop" that is ADAM's actual research contribution (§2.2 of the architecture) **cannot run end-to-end against a live VM today.** What *does* work, and works well, is two separate halves of that loop that have never yet been connected: real telemetry capture from a live guest (Dev A), and a real, tested Policy→Deception decision pipeline running offline against recorded/fixture data (Dev C). The presentation strategy that follows from this is in Part 6.

---

## Part 1 — Repository Audit

### 1.1 What's actually in the repository

216 tracked files outside `.venv`/caches. The real code lives in `adam/`, organized exactly along `ARCHITECTURE.md` §9's folder hierarchy. Walking it layer by layer (§3.1's L1→L5 model):

**L1 — Foundation (`adam/contracts/`, `adam/common/`).**
`adam/contracts/` is the frozen data model: `Envelope`, `RawEvent`, `SemanticEvent`, `PolicyDecision`, `MutationResult`/`Change`, `AnalysisSession`/`SampleRef`/`SessionConfig`/`SessionMetrics`, every enum (`Source`, `Category`, `Arm`, `NetworkMode`, `SessionStatus`, `Verdict`, `MutationStatus`, `ChangeKind`), and every ABC/Protocol (`ICollector`, `ISandboxController`, `IPolicyEngine`, `IRuleLoader`, `IPredicate`, `IDeceptionEngine`, `IDeception`, `SessionContextProtocol`) in one `interfaces.py`, per §9's own instruction. This package is now complete — it was just reconciled from two independently-built halves (yours and Dev C's) into one file set with zero duplicate definitions, verified with `mypy --strict` (clean) and the full test suite (see §1.3). `adam/common/` has `bus.py` (a real asyncio pub/sub `EventBus`), `config.py` (a real, fail-fast `Settings` loader), and `errors.py` (the full `AdamError` hierarchy from §14.1). It does **not** have `logging.py`, `ids.py`, `timeutil.py`, or `registry.py` — all four are named, unbuilt Phase-1 requirements. Nothing downstream is currently blocked by their absence (nothing generates its own IDs/timestamps yet outside what `datetime.now(timezone.utc)` already covers ad hoc), but structured logging specifically is worth having before a live demo, since today the only console output is whatever `logging.basicConfig` and `rich.Console.print` produce.

**L2 — Acquisition (`adam/sandbox/`, `adam/collectors/`).**
`adam/sandbox/controller.py` is a real finite-state-machine (`SandboxState`: COLD→RESTORING→BOOTING→READY→ARMED→RUNNING→COMPLETED→TEARDOWN→FAILED) driving `VirtualBoxClient` (a real async `VBoxManage` wrapper) through `prepare()`/`arm()`/`detonate()`/`teardown()`. `apply_mutation()` exists as a real, state-guarded, explicitly-disclosed `NotImplementedError` stub — this is the exact point where Policy/Deception's decisions are supposed to reach a live guest, and it's the one piece of Dev A's own slice still open (see Part 3). `collect_artifacts()` is also unimplemented (same reason: nothing to retrieve from until collectors exist to hand it something, though collectors now do exist — this is now just unwired, not blocked). Guest communication has **two working backends** behind one `GuestChannel` interface: `VBoxGuestChannel` (the default, wraps VirtualBox's own `guestcontrol` mechanism, real-VM-proven across four rounds of bug fixes) and `HTTPGuestChannel` (talks to a real PowerShell 5.1 HTTP agent — `adam_agent.ps1` + 9 manager modules — installed inside the guest). The HTTP path is the architecturally-intended one and, as of this session's bug-fixing work, its core capture path (health check, Procmon start/stop, Sysmon export) is now **real-VM-validated**, not just unit-tested against a mock — four real bugs were found and fixed against the actual Windows 10 guest this session (a PowerShell 5.1 `ProcessStartInfo.ArgumentList` incompatibility, a logging pipeline-pollution bug that corrupted every JSON response envelope, and two instances of a `$pid`-shadows-read-only-automatic-variable crash). `adam/collectors/` has real, tested parsers/tailers for Sysmon (EVTX/XML), ProcMon (CSV), and network (tshark `-T ek` JSON) — all three round-trip into real `RawEvent`s. The fourth named collector, `AgentCollector` (a live guest-push channel), does not exist; it's a genuine, structural gap (the current agent is pull/export, not push), not an effort gap.

**L3 — Research core (`adam/fusion/`, `adam/policy/`, `adam/deception/`) — the architecture's own ★-marked contribution layer.**
`adam/fusion/` — **does not exist.** `adam/fusion/detectors/` contains only a `.gitkeep`. No `engine.py`, no `normalise.py`/`correlate.py`/`window.py`/`process_tree.py`, no detector registry, not even an `__init__.py` for the package itself. This is Dev B's entire slice and it has not been started.
`adam/policy/` — fully implemented. `PolicyEngine.evaluate(event, context)` is a genuinely pure function (verified: no `subprocess`/`socket`/`httpx`/`adam.sandbox` imports anywhere in the package): it iterates a priority-sorted, YAML-loaded rule set, matches each rule's declarative `when:` block (intent/confidence/severity/feature-path equality, plus a named-Python-predicate escape hatch), and gates every match through confidence → budget → cooldown → dry-run, in that order, producing a `PolicyDecision` for every match (not just executed ones — suppressed decisions are recorded too, exactly as §7.4 requires). 14 rules across 5 YAML files cover 13 of the 24 intents named in §7.7's taxonomy.
`adam/deception/` — fully implemented at the primitive-logic level. 11 concrete deception primitives (one more than §7.8's own list of 10 — a reasonable addition for `PERSIST_RUN_KEY`), every one with real `apply_async`/`revert_async` bodies (not stubs), dispatched through a decorator-based catalogue. Plausibility scoring is a real `min()`-based combination formula, but every primitive currently feeds it **hardcoded boolean inputs** (`matches_locale_convention=True` in all 11, `is_post_boot_write` a fixed per-class constant) rather than anything measured at apply time — the arithmetic is real, the inputs are not yet dynamic. This directly overclaims against `docs/POLICY_DECEPTION_REFERENCE.md`'s own "computed, not hardcoded" line — worth being aware of if a reviewer reads that doc.

**L4 — Analysis (`adam/orchestrator/`; `adam/reporting/` is L4 in the layer diagram but empty).**
`adam/orchestrator/session.py`'s `SessionOrchestrator` coordinates a full session end to end — prepare → start collectors → arm → detonate → drain → teardown → build `AnalysisSession` — with guaranteed cleanup in a `finally` block. This is real, working, and the most thoroughly proven piece of glue code in the repo (verified via real OS-subprocess-level CLI runs, not just Python-level fakes). `adam/reporting/` — **does not exist.** No `generator.py`, no `yield_analysis.py` (the module that would compute the paper's headline "behavioural yield" metric), no renderers. There is currently no code anywhere that turns a session into a report of any kind.

**L5 — Presentation (`adam/api/`, `adam/dashboard/`; `adam/cli/`).**
`adam/api/` and `adam/dashboard/` — **both do not exist**, only `.gitkeep` scaffolding. No FastAPI app, no routers, no dashboard templates, no live SSE stream. `adam/db/` — **does not exist** either (no SQLite schema, no writer, no repositories); the only persistence today is `artifacts/<session_id>/raw.jsonl` (append-only, written directly by the orchestrator) plus whatever's in `artifacts/` from past runs. `adam/cli/` has a real, working `adam run <sample_path>` Typer command (invoked today as `python -m adam.cli.main run ...`, no installed console script yet); `adam/cli/replay.py` (Dev B's file, an `adam replay` command) and `adam/cli/validate.py` don't exist — there's a root-level `validate_rules.py` script that covers similar ground informally.

### 1.2 Actual data flow today, as opposed to the designed one

The designed loop (§3.3/§6.2): Collector → Fusion → Policy → Deception → guest mutation → Fusion (attributing the delta) → repeat.

What actually runs today, in two disconnected pieces:

1. **Live path (real VM, real telemetry, no decisions):** `adam run <sample>` → `SandboxController` restores the snapshot, boots, arms, detonates the sample, and the guest agent (either backend) captures Procmon/Sysmon/network output → three collectors parse that into real `RawEvent`s → each is written to `artifacts/<session_id>/raw.jsonl` and published on the `EventBus`. Nothing currently subscribes to that bus to turn a `RawEvent` into a `SemanticEvent` (Fusion doesn't exist), so the events just accumulate in the JSONL file and the session ends. `AnalysisSession.metrics.raw_events` is the only number this path currently reports.

2. **Offline path (real Policy/Deception logic, fake channel, no VM):** `tests/integration/test_replay_pipeline.py` loads hand-authored `SemanticEvent` fixtures (`tests/fixtures/semantic_events/*.json`, 12 files, one per intent), runs each through the real `PolicyEngine.evaluate()` against the real `rules/default/` corpus, and for every `EXECUTE` decision, runs the real `DeceptionEngine.execute_async()` against an `AsyncMock` "guest channel." This genuinely exercises `SemanticEvent → PolicyDecision → MutationResult` through real business logic — it is not faked at the Policy/Deception layer — but the channel at the very end is a bare mock with no shape verification, and the `SemanticEvent`s themselves are hand-written, not derived from anything a real Sysmon/ProcMon run produced.

**These two paths have never been run together.** No `RawEvent` produced by path 1 has ever become a `SemanticEvent` fed into path 2, because the component that would do that conversion (Fusion) doesn't exist, and even if it did, path 2's `DeceptionEngine` has no wiring to `SandboxController.apply_mutation()` (still a stub) to actually reach the guest — the two would need an adapter that also doesn't exist, since their method signatures don't even match today (`GuestMutationChannel.apply_mutation(kind, target, operation, value)` vs. `ISandboxController.apply_mutation(MutationRequest) -> MutationResult`, one call per `Change` vs. one call per whole decision).

### 1.3 Verified, not assumed

Ran directly against the current repository during this audit (not copied from prior docs):

- `pytest -q`: **232 passed, 1 skipped, 2 failed.** Both failures are pre-existing and unrelated to anything recent (`test_config.py`'s `TestGuestBackendSelector::test_defaults_to_vbox` and `TestDefaultTomlParses::test_default_toml_produces_valid_settings` — both assert the *old*, buggy `"vbox"`/`127.0.0.1` default that was fixed earlier this session; the tests themselves are stale, not the code). No failures relate to Policy/Deception or the contracts merge.
- `mypy --strict adam/contracts`: clean, 9 files.
- `mypy --strict adam`: 10 pre-existing errors, all in `adam/policy/` (missing `types-PyYAML` stub, a couple of lambda-inference notes) and `adam/common/config.py` (a `tomllib` stub-resolution quirk specific to this sandboxed dev environment's Python 3.10, plus one call-arg note) — none touch anything this audit is reporting on as "done."
- Full file inventory (`find`, excluding caches/`.venv`) confirms the empty-package claims above by direct listing, not inference: `adam/fusion/`, `adam/api/`, `adam/db/`, `adam/reporting/`, `adam/dashboard/` contain zero `.py` files with real content, only `.gitkeep`s.

---

## Part 2 — Comparison Against ARCHITECTURE.md

Scored per architecture component (§5.1–§5.10), not the old Milestone numbering, since the reviewers will have read the architecture doc, not your internal milestone history.

| Component (§) | Owner | Status | Est. % | Notes |
|---|---|---|---|---|
| Contracts & common (§5.1) | A (shared w/ all) | 🟡 | ~75% | Contracts themselves ~95% (content complete, only the formal §10.2 four-reviewer sign-off is unchecked-in-writing); `common/` is ~50% (bus+config+errors solid, logging/ids/timeutil/registry absent). |
| Sandbox Controller (§5.2) | A | 🟡 | ~80% | FSM exact match to spec; `apply_mutation()` and `collect_artifacts()` are the two still-stubbed methods, both now unblocked in principle (Deception exists; collectors exist) but not yet wired. |
| Collectors (§5.3) | A | 🟡 | ~80% | 3 of 4 collectors real and tested; `AgentCollector` structurally blocked (needs a push channel that doesn't exist). |
| Fusion Engine (§5.4) ★ | B | ❌ | **0%** | Not started. No files beyond a `.gitkeep`. This is the sole reason the closed loop can't run live. |
| Policy Engine (§5.5) ★ | C | ✅ | ~90% | Matches its spec closely: pure function, YAML+predicate DSL, budget/cooldown/confidence gate, suppressed decisions persisted. Gap: only 13/24 taxonomy intents have a rule; `rule.schema.json` exists but isn't actually enforced by the loader (the loader does its own hand-rolled check instead). |
| Deception Engine (§5.6) ★ | C | 🟡 | ~85% | 11 real primitives, real revert, real (if input-starved) plausibility scoring. Gap: never wired to a real `ISandboxController` — the channel is always a test double; the plausibility inputs are hardcoded, not measured. |
| Database (§5.7) | D | ❌ | **0%** | Not started. All persistence today is `raw.jsonl` only. |
| API (§5.8) | D | ❌ | **0%** | Not started. No FastAPI app exists. |
| Report Generator (§5.9) | D | ❌ | **0%** | Not started. No behavioural-yield computation exists anywhere — this is the paper's headline metric and there is currently no code that produces it, only the raw ingredients (`raw.jsonl`, and Policy/Deception's in-memory results if you wire a script around them). |
| Dashboard (§5.10) | D | ❌ | **0%** | Not started. |
| Orchestrator & CLI (§6.1, §9) | A | ✅ | ~90% | Full session lifecycle proven end-to-end via real subprocess-level runs; `adam replay`/`adam validate-rules` as named CLI subcommands don't exist yet (informal equivalents do). |

### Why each ❌ is missing, and what it blocks

- **Fusion (Dev B).** Not a matter of partial effort — it hasn't been started at all. **Blocks:** the entire live adaptive loop; `AgentCollector` indirectly (not really — that's a Dev A gap, unrelated); Phase 9's recorded corpus is *possible* without it (raw events can be recorded regardless) but the corpus's actual purpose (letting B/C/D develop offline against real data) is moot until Fusion exists to consume it. **Not** blocking: Policy/Deception, which develop fine against hand-written `SemanticEvent` fixtures, as already proven.
- **DB/API/Reporting/Dashboard (Dev D).** Also not started at all. **Blocks:** any persistence beyond a single session's JSONL file, any way to browse/compare sessions, and — most importantly for the actual research claim — any computation of behavioural yield (§2.3), since nothing currently diffs a control run against a treatment run. **Not** blocking: a single `adam run` completing and producing raw telemetry, or Policy/Deception being exercised via replay.
- Neither gap depends on the other or on anything in your own slice being different than it is today — they are genuinely orthogonal, parallel-safe work, exactly as §10.4's parallelisation plan intended, they just haven't happened yet.

### Updated overall completion estimate

Two honest ways to compute this give different pictures, and it's worth showing both to reviewers rather than picking the flattering one:

- **By developer-slice** (four equal quarters, per §10.1's own ownership split): Dev A ≈ 80%, Dev B ≈ 0%, Dev C ≈ 88%, Dev D ≈ 0%. **Simple average: ≈42%.**
- **By named file/module count** across all of §9's folder hierarchy (a rougher, file-existence-based metric, same style the prior `implementation-audit.md` used per-phase): roughly **50–55%** of all named files exist with real content.

**The honest headline number to use in the presentation is not either of these — it's this: 0% of the closed adaptive loop (the actual research contribution) currently executes end-to-end against a live guest.** Two of its three research-core components exist and are well-tested in isolation; the third doesn't exist at all; and even the two that do exist have never been connected to the live telemetry path. Reporting "~45% complete" without that caveat would materially overstate where the *contribution* — as opposed to the *infrastructure* — stands.

---

## Part 3 — Dev Contributions

### Yours (Dev A) — Infrastructure & Sandbox
`adam/common/` (bus, config, errors), `adam/sandbox/` (controller FSM, VirtualBox wrapper, both guest channel backends, the full PowerShell guest agent), `adam/collectors/` (3 of 4, plus all 3 parsers), `adam/orchestrator/` (session lifecycle, persistence), `adam/cli/run.py` + `main.py`, `config/`, `scripts/`. This is the largest single body of working, real-VM-tested code in the repository. It is also, not coincidentally, the only slice that has actually touched a real Windows guest — every other slice's correctness claims rest on unit tests and mocks.

### Dev C's work (just merged) — Policy & Deception
`adam/policy/`, `adam/deception/`, `rules/default/*.yaml`. Self-contained, offline-testable by design (ADR-004), and it shows: 37 tests across `tests/unit/test_policy/`, `tests/unit/test_deception/`, and the replay integration test (independently re-run for this audit — `docs/known_limitations.md`'s own claim of "51 tests... 100% coverage" was not independently re-verified and should be treated as their self-report, not confirmed here), `mypy --strict` clean on their own files, a real end-to-end replay test. It integrates with your work at exactly one seam today — `MutationResult`, which the merge just reconciled so both sides import the same canonical model from `adam/contracts/mutation.py` (your old inline duplicate is gone, replaced by a re-export; zero behavior change, since your own `SandboxController.apply_mutation()` never constructed the old one anyway). Beyond that one contract-level seam, **there is no runtime integration** — Dev C's `DeceptionEngine` has never been constructed with anything backed by your `SandboxController`, and their own `docs/known_limitations.md` says as much explicitly ("execution against a live VirtualBox VM... remains to be validated at the composition root").

### Dev B's work — absent
Nothing exists. Nothing in your slice or Dev C's slice is *blocked* by this in the sense of "code won't run" — your collectors run fine without Fusion, Policy/Deception run fine against fixtures without it too. What's blocked is the *demonstration* — there is no code path today, and won't be until Fusion exists, that takes a real Sysmon/ProcMon event from your capture and turns it into the kind of `SemanticEvent` that would make Policy fire for real, live, during an actual detonation.

### Dev D's work — absent
Same situation, different consequence: nothing you or Dev C built depends on a database, an API, or a dashboard to function (you write directly to `raw.jsonl`; Dev C's tests construct everything in-memory). What's blocked is anything the *paper* needs: no persisted session history to query, no comparison report, no way to show a live dashboard to the reviewers even if you wanted to (there's no server to run).

### What already works without Dev B or Dev D
The full live capture path (`adam run <sample>` against a real VM, real Procmon/Sysmon/network telemetry landing in `raw.jsonl`), and the full offline Policy→Deception replay path (real decisions, real primitive execution, real revert, against fixture data). Both are demoable today, independently, with zero changes needed to unblock them.

---

## Part 4 — End-to-End Execution Guide

This describes exactly what running ADAM today actually requires and produces — not the eventual, fully-wired version.

### 4.1 Prerequisites
- Host: Python 3.10/3.11, VirtualBox with `VBoxManage` on `PATH` (or configured via `sandbox.vbox_manage_path`).
- `pip install -r requirements.txt -r requirements-dev.txt`.
- A `.env` file (see `.env.example`) setting `ADAM__SANDBOX__GUEST_USERNAME` / `ADAM__SANDBOX__GUEST_PASSWORD` — `Settings()` refuses to start without both; there's no TOML fallback for these by design (§12.3).

### 4.2 Guest VM
- One Windows 10 x64 VM in VirtualBox, matching whatever `config/default.toml`'s `[sandbox].vm_name` says (currently `ADAM_WIN10_OFFICE` — change per-machine via `config/<ADAM_ENV>.toml`, not by editing the committed default).
- A snapshot named `clean` (matches `snapshot_name`) taken **after** installing: Guest Additions, Sysmon (running as a service, default channel `Microsoft-Windows-Sysmon/Operational`), Process Monitor (Procmon64.exe), Wireshark/tshark. There's no automated snapshot-creation helper — this is a manual, one-time setup step per the environment checklist referenced throughout `docs/implementation-audit.md`.
- Network mode: host-only or simulated by default (§1.4's safety boundary) — internet access is opt-in, not the default posture.

### 4.3 Guest agent — two choices
- **Default (`guest_backend = "vbox"`):** nothing to install. `SandboxController` drives the guest entirely through VirtualBox's own `guestcontrol`. This is the most-proven path.
- **HTTP backend (`guest_backend = "http"`, architecturally intended):** copy `adam/sandbox/guest/agent/` into the guest and run `install.ps1` as Administrator inside the guest — it's idempotent and self-verifying (checks PowerShell version, elevation, registers a scheduled task, opens the firewall/URL ACL, and runs a live `GET /health` check before reporting success). Then set `[http_guest].host` in `config/<ADAM_ENV>.toml` to the guest's real host-only-adapter IP (the committed default, `192.168.56.103`, is a placeholder from this project's own dev environment — it will not match yours). This backend's core capture path (health, Procmon, Sysmon) is now real-VM-validated as of this session's bug fixes; treat the diagnostics/network-manager endpoints and full CLI-driven runs through this backend as less-proven until you've exercised them yourself.

### 4.4 Running a session
```
python -m adam.cli.main run <path-to-sample> [--artifacts-dir artifacts] [-v]
```
No `pip install -e .` / console script exists yet — always invoke via `python -m`. `-v` turns on DEBUG logging, including every individual guest command ADAM issues (useful for a live demo — the audience sees exactly what's happening, not a black box). There are three testing-only override flags (`--sysmon-evtx-path`, `--procmon-csv-path`, `--network-ek-json-path`) that let you point a collector at an existing file instead of live guest capture — useful for rehearsing the demo without a full VM boot cycle if you've already captured one real run.

### 4.5 What happens, and what you get
`prepare()` restores the snapshot and boots → `arm()` copies the sample in → collectors start → `detonate()` runs the sample under a timeout → a short drain period → collectors stop, guest exports and the host fetches Procmon/Sysmon/network output → `teardown()` unconditionally restores the snapshot again, even on failure. Output: `artifacts/<session_id>/raw.jsonl` (one JSON line per captured `RawEvent`), a console summary line (`session <id>: COMPLETED (N raw events captured)`), and an exit code (0/1/2/130 per outcome). **What you will not get, today, from this command alone:** any `SemanticEvent`, `PolicyDecision`, or `MutationResult` — those only exist in the separate offline replay path (Part 6 explains how to show both together).

### 4.6 Seeing Policy/Deception run
```
python -m pytest tests/integration/test_replay_pipeline.py -v -s
```
The `-s` flag matters: the test prints a real summary table (intent → rule fired → primitive executed → plausibility score → revert verified) covering all 12 fixture events. This is currently the only way to see the Policy/Deception half of the system do anything, and it happens to already look like a demo table — see Part 6/7.

---

## Part 5 — Malware Testing Plan

**One correction to the premise first, because it matters for safety and for what "Stage 1" can honestly mean:** MalwareBazaar does not host "safe" or "malware-like" samples — everything on it is real, live, working malware, distributed zip-password-protected (`infected`) specifically to stop accidental execution and casual AV auto-detonation. There is no "Stage 1, low-risk MalwareBazaar sample." Stage 1 should use purpose-built simulation tools instead; MalwareBazaar samples start at Stage 2.

### Stage 1 — Safe, malware-*like* behaviour (no live malware at all)
Use **Atomic Red Team** (Red Canary, open-source, MIT-licensed, ~200+ self-contained "atomic" tests, each mapped to one MITRE ATT&CK technique, each running in under 5 minutes with its own cleanup command). Run a handful of atomics chosen to match ADAM's existing rule corpus:
- `T1082` (System Information Discovery) / `T1497` (Virtualization/Sandbox Evasion checks) → exercises `RECON_VIRTUALISATION` → `HIDE_VM_ARTIFACTS`.
- `T1012` (Query Registry) against domain-related keys → exercises `RECON_DOMAIN_CONTROLLER` → `SPAWN_FAKE_DC_ARTIFACTS` (this is also your one rule with a real predicate, `repeated_ldap_failure` — worth specifically exercising).
- `T1547.001` (Registry Run Keys) → exercises `PERSIST_RUN_KEY` → `PLANT_DECOY_RUN_KEY`.
- `T1135` (Network Share Discovery) → exercises `RECON_NETWORK_SHARES` → `MOUNT_FAKE_NETWORK_SHARE`.

This proves your Sysmon/ProcMon capture pipeline sees the right raw events, without any actual malicious payload in the guest. It does **not** exercise Policy/Deception live (Fusion still doesn't exist to turn these into `SemanticEvent`s) — its value here is purely validating that the *raw telemetry* side reacts correctly to the same technique categories your rule corpus already targets, which is useful evidence to show reviewers even without the live loop.

### Stage 2 — Common, well-documented malware families (MalwareBazaar, real risk, well-understood behaviour)
Pick samples via MalwareBazaar's browse-by-tag/family search (`bazaar.abuse.ch/browse/`), verified by SHA256 before use (the API/download always gives you the hash back — confirm it matches what you queried before unzipping). Good fits for your current 14-rule corpus:

- **AsyncRAT / XWorm / njRAT** (currently the most-uploaded families on MalwareBazaar) — commodity RATs. Expected: registry Run-key persistence (Procmon `RegSetValue` under `HKCU\...\Run`) → `PERSIST_RUN_KEY`; process/host discovery (`RECON_SYSTEM_UPTIME`, `RECON_INSTALLED_AV`) via WMI/registry queries → `SIMULATE_AV_PRESENCE`, `SPAWN_DECOY_PROCESSES`; a C2 beacon over HTTP(S) or a custom TCP protocol → `C2_BEACON` → `FABRICATE_C2_RESPONSE`. Exercises Sysmon Event ID 1 (process create), 3 (network connect), 13 (registry set), and your network collector's pcap/tshark path all at once.
- **Agent Tesla / Lumma / Vidar** (top infostealers) — browser-credential and wallet theft. Expected: file reads/writes under `%LOCALAPPDATA%\Google\Chrome\User Data\...\Login Data` → `CRED_BROWSER_STORE` → `INJECT_FAKE_BROWSER_CREDS`; crypto wallet file searches → `CRED_WALLET_SEARCH` → `PLANT_DECOY_WALLET`; SMTP/HTTP exfil → network telemetry, no current rule (`CRED_LSASS_ACCESS`/`CRED_CONFIG_FILE_HARVEST` are named in the taxonomy but have zero rules today — a real coverage gap worth fixing before this stage, see Part 7).
- **Remcos RAT** — sandbox-evasion-heavy. Expected: `EVADE_SANDBOX_DETECTED` (VM artifact checks, registry/WMI queries for `VBOX`/`VIRTUAL`) → currently maps to `LOG_ONLY` (your rule corpus deliberately doesn't spawn a primitive for this one — it's the one intent the architecture explicitly treats as detection-only) and `EVADE_SLEEP_SKIP` (`Sleep()`/`GetTickCount` loops) → `ACCELERATE_SYSTEM_CLOCK`.

For each: hash-verify on download, keep the password-protected zip as-is until the moment of detonation (don't leave an unzipped live binary sitting on a host filesystem), and detonate only inside the isolated guest with network mode `SIMULATED` unless you specifically need `INTERNET` for a real C2 callback (opt-in, logged, per §1.4).

### Stage 3 — Advanced malware (higher operational and legal caution)
- **Ransomware — LockBit 3.0 (builder-leaked variants are extensively documented) or a Cl0p/BlackCat sample.** Expected: mass file encryption (`IMPACT_MASS_FILE_ENCRYPT`), shadow-copy deletion via `vssadmin`/`wmic shadowcopy delete` (`IMPACT_SHADOW_COPY_DELETE`), ransom note drop (`IMPACT_RANSOM_NOTE_DROP`). **None of these three intents currently have a rule in `rules/default/` — this stage will produce rich raw telemetry and (if Fusion existed) rich semantic events, but zero policy decisions today, because the `impact.yaml` file named in the architecture's own folder hierarchy was never actually created.** Worth flagging to reviewers as a known, honest gap rather than silently avoiding ransomware in the demo.
- **PlugX / a documented loader chain** — for lateral-movement/`LATERAL_*` intents, same gap: no `lateral.yaml` exists either.

Given ADAM's safety boundary (§1.4: unconditional snapshot rollback, host-only/simulated network by default, no shared folders/clipboard, agent channel is one-way host→guest), Stage 3 samples are safe to detonate *inside the architecture as designed* — the risk is operational (a slow/failed rollback, or a misconfigured network mode accidentally bridging to a real network), not inherent to running the sample once. Treat Stage 3 as gated on Stage 1/2 both being clean, exactly as your own `docs/implementation-audit.md` already treats Phase 6's progression.

### Safe sourcing checklist
1. Query MalwareBazaar by hash/tag/family at `bazaar.abuse.ch/browse/` or via the `mb-api.abuse.ch/api/v1/` API (`get_file` + `sha256_hash`, `API-KEY` header).
2. Confirm the SHA256 you receive matches the hash you queried before doing anything else with the file.
3. The download is always a password-protected zip (password `infected` — an industry convention, not a secret) — this is intentional friction against accidental execution/AV auto-submission, not encryption for confidentiality. Extract only inside the isolated guest or an equally isolated analysis VM, never on your host.
4. Never disable your host AV to "let the download through" — quarantine-and-restore inside the guest snapshot is the correct workflow; your host should never see the unpacked binary at all if you can arrange the guest-side-only unzip.
5. Respect MalwareBazaar's daily download rate limit and fair-use terms; an API key (free) raises the limit over anonymous access.

---

## Part 6 — Reviewer Presentation (10–15 minutes, using only what's real)

Given Part 1–3's findings, the honest and actually-stronger framing is: **"here is a working capture pipeline, here is a working decision pipeline, and here is exactly the one connection between them that's still open."** Don't try to fake a live closed loop — a professor asking "show me a live semantic event triggering a live mutation" will immediately find the seam if you imply that exists.

**Demo 1 — Live VM capture (3–4 min).** Show `python -m adam.cli.main run <benign-or-Stage-1-sample> -v` running against the real VM. What's on screen: verbose logs showing snapshot restore → boot → guest-ready probe → detonation → capture start/stop, ending in `session ...: COMPLETED (N raw events captured)`. What they learn: the sandbox lifecycle is real, automated, and safe (unconditional rollback), and telemetry capture from a live Windows guest actually works — the hardest infrastructure problem in the whole project.

**Demo 2 — Raw telemetry, inspected (2 min).** `head -20 artifacts/<session_id>/raw.jsonl` or a quick `jq` filter by category. What they learn: `RawEvent`s are real, structured, schema-validated data (Sysmon registry/process/network events, ProcMon file/registry ops), not placeholder text.

**Demo 3 — Policy + Deception, live-executed (4–5 min, your strongest material).** Run `pytest tests/integration/test_replay_pipeline.py -v -s` and let the printed summary table render on screen (intent / rule fired / primitive executed / plausibility / revert verified, 12 rows). Narrate it as: real `SemanticEvent`s (stand-ins for what Fusion will eventually produce from Demo 2's raw events) → the real rule engine (show one YAML rule file open, e.g. `rules/default/recon.yaml`, to prove it's declarative and auditable) → real deception primitives actually executing (`apply_async`) and reverting (`revert_async`) against a channel. What they learn: the decision logic — the actual novel contribution — is implemented, tested, and behaves exactly as the architecture specifies, including the suppressed-decision and revert mechanics.

**Demo 4 — The gap, shown honestly (1–2 min).** Open `adam/sandbox/controller.py`'s `apply_mutation()` and show the `NotImplementedError` with its docstring pointing at the Deception Engine dependency. Say plainly: "Demo 1 produces the raw events; Demo 3 consumes semantic events; the component that converts one into the other — Fusion — and the adapter that connects Deception to this exact method, are the two pieces of work standing between what you just saw and the fully live closed loop." This preempts the obvious question rather than hoping nobody asks it.

**Demo 5 (optional, if time and a second sample) — Deception primitive detail (2 min).** Pick one primitive (e.g. `FakeDomainControllerDeception`) and show its `_build_changes()`/`_plausibility()` source — three concrete `Change` objects (registry set, DNS respond, SYSVOL dir create) and a real plausibility score with a documented weakness ("registry key mtime is post-boot — a timestamp-aware sample could detect this," directly echoing §2.4's own required self-disclosure). This demonstrates you understand the plausibility/detectability tradeoff the architecture explicitly cares about, not just that you wrote code.

What to have open/ready beforehand: a terminal in the repo root, the VM already snapshotted to `clean`, `ARCHITECTURE.md` open to §3.3 (the closed-loop diagram) to point at while narrating the gap, and `rules/default/recon.yaml` + one primitive file open in an editor tab.

---

## Part 7 — Quick Wins (ranked, before-the-review effort)

| # | Item | Impact | Effort | Why |
|---|---|---|---|---|
| 1 | **Promote `test_replay_pipeline.py`'s summary table into a standalone `scripts/demo_replay.py`** (or a real `adam replay` command) that prints it without needing `pytest -s` | High | Very Low | The exact table already exists and already looks like a demo artifact (Part 6, Demo 3) — this just removes "running pytest" from the optics, which reads more like a finished tool to non-engineers. |
| 2 | **Add a Graphviz/Mermaid process-tree or Sankey diagram from one real `raw.jsonl`** (parent PID → child PID from Sysmon Event ID 1) | High | Low | You already have real captured data (Demo 2); a visual process tree turns a JSONL dump into something a professor immediately reads at a glance. |
| 3 | **A tiny script that renders the replay summary table + a MITRE ATT&CK coverage bar (13/24 intents wired) as one static HTML page** | High | Low–Med | Gives you an actual "report," even a minimal one — directly addresses the fact that `adam/reporting/` doesn't exist, without needing to build the real thing. |
| 4 | **Wire 2–3 more rules for already-implemented-but-orphaned taxonomy intents** (`CRED_LSASS_ACCESS`, or add an `impact.yaml` with `IMPACT_SHADOW_COPY_DELETE` even without a matching primitive yet, verdict-only/`LOG_ONLY`) | Medium | Low | Directly closes a gap this audit flags (Part 5's Stage 3 ransomware note) and is genuinely fast — it's YAML, not code. |
| 5 | **A one-page MITRE ATT&CK coverage table** (which of your 14 rules map to which `attck.tactic`/`technique`, cross-referenced against §7.7) | Medium | Very Low | Pure documentation exercise using data you already have; professors respond well to ATT&CK framing. |
| 6 | **`adam/common/logging.py`** (structured JSON + coloured console per §13.1) | Medium | Low–Med | Currently every log line is ad hoc `logging.basicConfig` text; a real structured logger with `correlation_id` makes the verbose demo run (Demo 1) look materially more polished and traceable. |
| 7 | **A minimal `IOC` extraction script** (pull registry keys / file paths / network indicators straight out of one session's `raw.jsonl` into a short list) | Medium | Low | Cheap, and directly maps to `adam/reporting/ioc.py`'s intended job — shows reviewers you know what a real report needs even without building the full renderer. |
| 8 | **Fix the plausibility hardcoding** (at minimum, thread the real `applied_at` timestamp into `score_timestamp_consistency` instead of a hardcoded boolean) for 2–3 primitives | Low–Medium | Low | Directly closes the one place this audit found a documentation/code mismatch (Part 1); a reviewer who reads `plausibility.py` after reading your own reference doc will notice otherwise. |
| 9 | **A single Graphviz rendering of the dependency graph (§15.1) with your actual implemented/missing status colour-coded on top of it** | Medium | Very Low | Doubles as both a "we understand the architecture" artifact and an honest status chart — reuse this report's Part 2 table as the data source. |
| 10 | **README.md fix** — the current top-level `README.md` is actually Dev C's module-scoped README ("Standalone implementation of the Policy Engine + Adaptive Deception"), not a project-wide one | Low | Very Low | Cosmetic but a reviewer opening the repo cold will read this first; five minutes to write a real top-level summary is worth it. |

Sankey/registry-tree/dashboard-style visualizations were deliberately left off this list at high rank — they're higher-effort than the above for similar impact, and none of them currently have real backing data pipelines (no DB, no report generator) to draw from without first doing #2/#3.

---

## Part 8 — Final Verdict (as a reviewer would read this project)

### Biggest strengths
The infrastructure layer (your slice) is genuinely rigorous engineering, not a student prototype: a real state machine with disclosed invariants, two independent guest-communication backends with an actual interface boundary between them, real bugs found and fixed against a real VM (not hypothetical — the ArgumentList/pipeline-pollution/`$pid` bugs this session were real crashes with real root causes, fixed correctly). The Policy Engine is close to textbook-clean: a genuinely pure function, a sensible YAML-plus-escape-hatch DSL, and — notably — it persists suppressed decisions, which is a subtle, easy-to-skip requirement (§7.4) that was actually honored. The deception primitive catalogue is broad (11 primitives, matching the architecture's own catalogue almost 1:1) with real apply/revert symmetry.

### Biggest weaknesses
Two of four architectural pillars are simply absent, and one of them (Fusion) is the component that makes the *research claim* — as opposed to the infrastructure — real. Right now, nothing in the repository can currently demonstrate "malware searched for X, ADAM synthesized X, malware then behaved differently as a measurable result" against a live sample, because there's no live path from raw telemetry to a semantic event to a decision. The behavioural-yield metric (§2.3, the actual headline number the paper needs) has no implementation anywhere — not even a stub — because Reporting doesn't exist. Plausibility scoring, while architecturally present, is currently decorative in its inputs (hardcoded booleans), which undercuts §2.4's "we take detectability seriously" claim on close inspection.

### Likely reviewer questions
- "Show me this working against a real sample, live, with a real mutation happening in response to real behavior." → You cannot do this today; Part 6's Demo 4 is exactly the honest answer.
- "What's your behavioural yield number?" → None exists yet; be ready to say so plainly and point at what data would feed it (`raw.jsonl` + Policy/Deception's decision log) if Reporting existed.
- "How do you know the plausibility scores mean anything?" → Be ready to admit the hardcoded-input gap yourself rather than have it discovered; framing it as a known, disclosed, prioritized fix (which it now is, per this audit) reads far better than getting caught by the question.
- "Why isn't Fusion built yet, this late in the project?" → Answer honestly: it's a teammate's ownership slice under the architecture's own four-way split (§10.1), not something blocked by your work; your slice and Dev C's slice were explicitly designed (§10.4, the fixture/replay strategy) to develop independently of it, which is exactly what happened.
- "Is the guest agent actually installed and running, or is this the VirtualBox-native fallback?" → Know which backend you're demoing with and say so; don't let "http" vs "vbox" come up as a surprise.

### Weakest technical areas
Plausibility-score realism (hardcoded inputs); the complete absence of any persistence beyond a flat JSONL file (no session history, no comparison); the Deception↔Sandbox integration seam (two incompatible method signatures with no adapter, not just "unimplemented" but currently *unimplementable without new glue code*); rule-corpus coverage (13/24 taxonomy intents, and zero `IMPACT_*`/`LATERAL_*` rules despite those being exactly what ransomware/advanced-malware testing in Part 5's Stage 3 would exercise).

### Strongest technical achievements
The real-VM-validated HTTP guest agent, built from scratch in PowerShell 5.1 against a genuine C4 constraint (no .NET Core in the guest), with real bugs found and fixed through actual hardware testing this session — this is the part of the project least likely to be "just infrastructure" in a reviewer's eyes, because it required solving real, non-obvious platform compatibility problems (ArgumentList, pipeline pollution, reserved-variable collisions) that don't show up in a tutorial. The Policy Engine's purity and suppressed-decision persistence is the second strongest — it's a correct, careful reading of a subtle architectural requirement, not just a rules-if-else engine.

### What to emphasize
The engineering discipline evident in both slices that exist — real bugs, real fixes, real tests, honest disclosure of what's stubbed (both `docs/implementation-audit.md` and `docs/known_limitations.md` already model exactly the kind of self-aware reporting a reviewer respects; lean into that same tone live rather than overselling). The fact that the fixture/replay strategy (§4.2, ADR-004) worked exactly as designed — two developers built and fully tested a research-core component with zero VM access, which is precisely the parallelization bet the architecture made.

### What to avoid
Do not describe the project as having a "working closed loop" or "adaptive deception against live malware" in any general framing — say "capture pipeline" and "decision pipeline" as two named, connected-on-paper-not-in-code things. Do not lean on `docs/POLICY_DECEPTION_REFERENCE.md`'s "plausibility scores are computed, not hardcoded" line if asked to defend it in detail — you now know it's not quite true at the input level. Avoid volunteering ransomware/`IMPACT_*` behavior as a strength unless asked — there's no rule coverage for it yet, and it's better raised as a "next step" than as a claimed capability.

### Publishable/research level, or still a prototype?
**Still a prototype, honestly and by a meaningful margin** — not because the code quality is weak (it isn't), but because the paper's actual empirical claim (§2.3's behavioural yield, measured via A/B control/treatment sessions) cannot currently be computed by any code in the repository, and the mechanism that would make the claim *live* (Fusion) hasn't been started. What exists is a well-engineered, well-tested set of *components* for the eventual system, with the two hardest infrastructure problems (a working sandbox and a working decision engine) solved to a genuinely solid standard. That is legitimate, presentable progress — a reviewer should come away thinking "this team clearly knows what they're doing and is two teammates' worth of remaining work away from the real thing" — but presenting it as more than that risks a credibility hit the underlying work doesn't deserve.
