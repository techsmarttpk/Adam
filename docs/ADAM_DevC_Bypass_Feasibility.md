# ADAM — Can Dev C's Engines Run Today Without Dev B? (Session `sess_2026_08_05_a7f82ef0`)

Follow-up to `docs/ADAM_Full_Repository_Audit.md`. Read-only analysis — no code changed. Grounded in the actual artifacts at `artifacts/sess_2026_08_05_a7f82ef0/` (inspected directly, not assumed) and the actual `adam/policy/engine.py`, `adam/policy/context.py`, `adam/deception/engine.py` source.

**Short answer up front:** yes, Dev C's engines can run today — but not by feeding them `raw.jsonl` directly, and not, honestly, with *this specific session's* data, because this session didn't capture malware behavior. Read on for why, and what to do instead for tomorrow.

---

## Part 1 — Pipeline Analysis

### What Dev C's components actually accept

- **`PolicyEngine.evaluate(event, context)`** (`adam/policy/engine.py:38`) takes exactly one `adam.contracts.semantic_event.SemanticEvent` and one `SessionContextProtocol`-conforming object per call. `SemanticEvent` requires: `semantic_id`, `session_id`, `correlation_id`, `intent` (a string matching a rule's `when.intent`), `confidence` (0–1, gates against `global_confidence_gate`, default 0.60), `severity`, `window_start`/`window_end`, `actor` (`{pid, image, guid}`), `evidence` (list of strings), `detector`, `features` (a dict — this is what `feature_equals`/predicate conditions read), and optionally `attck`/`caused_by_mutation`. **It does not accept `RawEvent`, a list of raw events, or anything CSV/EVTX-shaped.** There is no overload, no coercion, nothing.
- **`SessionContext`** (`adam/policy/context.py:18`) just needs a `session_id` — everything else defaults (`BudgetTracker()`, empty decisions list). Trivial to construct.
- **`DeceptionEngine.execute_async(decision)`** (`adam/deception/engine.py:32`) takes exactly one `adam.contracts.policy_decision.PolicyDecision` (the direct output of `PolicyEngine.evaluate()`) and was constructed with a `channel` implementing the 4-argument `GuestMutationChannel` protocol (`apply_mutation(kind, target, operation, value) -> None`). It does not touch `RawEvent`, `SemanticEvent`, or any file format either.

### Is `raw.jsonl` alone sufficient?

**No — categorically, not a format issue you can work around, a genuine missing-component issue.** `raw.jsonl` is a stream of `RawEvent`s (source, category, process, `attributes: dict`). Nothing in the repository converts a `RawEvent` (or a batch of them) into a `SemanticEvent` — that conversion, with its normalize/correlate/interpret stages and confidence scoring, is Fusion's entire job (§5.4), and Fusion doesn't exist (confirmed again this pass: still only `adam/fusion/detectors/.gitkeep`, zero code). So `raw.jsonl` is necessary evidence but not sufficient input — Policy has no code path that reads it.

### Can `procmon.csv` be consumed directly?

**Not by the existing collector, and I found the actual reason empirically in this session's file, not just in theory.** `adam/collectors/parsers/pml.py`'s `parse_procmon_csv_row()` requires a **"Date & Time"** column (documented as a hard requirement since it's the only column carrying both date and time — ProcMon's *default* export column, "Time of Day", carries time only). I checked this session's actual file:

```
head -1 artifacts/sess_2026_08_05_a7f82ef0/procmon.csv
"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
```

This is the default column set, not the required one. That's why `raw.jsonl` has **zero `PROCMON`-sourced events** (verified: `grep -c '"source": "PROCMON"' raw.jsonl` → `0`) despite `procmon.csv` sitting right next to it with 198,491 real rows spanning a real 48-second capture window (20:04:30–20:05:18) — `ProcmonCollector` almost certainly rejected the header on first read and produced nothing, exactly as its own documented validation behavior predicts. This previously-theoretical gap (flagged in `docs/implementation-audit.md`'s Phase 7 section as a disclosed limitation) has now actually manifested in a real run. Fix is a one-line change to the guest's Procmon capture configuration (enable the "Date & Time" column in the saved Procmon configuration the agent launches with) — not proposed as a code change here per your instruction, just named as the root cause.

### Must `sysmon.evtx` be parsed first?

It already has been — automatically, as part of the session that produced this artifact folder. All 1,000 lines in `raw.jsonl` are `"source": "SYSMON"`, meaning `SysmonCollector` + `parse_sysmon_event_xml()` already ran and did their job. You don't need to touch `sysmon.evtx` again; `raw.jsonl` is its already-parsed output. (One real caveat below on what's actually *in* those 1,000 lines.)

### Can the current pipeline bypass Dev B "temporarily," using only existing code?

**Not using *this session's* raw telemetry, no — because zero lines of existing code perform any part of the RawEvent→SemanticEvent conversion, at any fidelity.** There is exactly one way to exercise Policy/Deception using 100% existing code today, and it's the same one from the prior audit: `tests/integration/test_replay_pipeline.py`'s fixture `SemanticEvent`s (`tests/fixtures/semantic_events/*.json`) → real `PolicyEngine` → real `DeceptionEngine`. That pipeline is real, already wired, already passing, and requires writing nothing new — but it uses hand-authored fixture data, not anything derived from `sess_2026_08_05_a7f82ef0`.

If you want *this session's* real telemetry to reach Policy/Deception, that requires new code — see Part 2. It cannot be done with zero new lines.

### What's actually in this session's data (important — checked directly, not assumed)

I inspected the actual content rather than assuming a malware run produced it, because the intended use of the artifacts changes the whole recommendation:

- **Time range of `raw.jsonl`: `2026-07-29T12:43` to `2026-08-05T14:35`** — a full week, not one session. This is the disclosed "Sysmon exports its entire operational log every time, relying on snapshot restore to keep it session-scoped" limitation (`agent.py`'s own docstring) actually biting: the guest's Sysmon log evidently isn't being reset by the snapshot, so every session's export starts with the same historical backlog. Combined with `SysmonCollector`'s 1,000-event internal buffer cap (`adam/collectors/sysmon.py:64`), the 1,000 lines you have are dominated by old backlog, not this run specifically.
- **Every process name in `raw.jsonl` is ordinary Windows/security-tooling background noise**: `CompatTelRunner.exe`, `svchost.exe`, `MsMpEng.exe`/`MpCmdRun.exe` (Defender), `OneDrive.exe`, `WerFault.exe`, `Procmon64.exe`, `VBoxService.exe`, `Sysmon64.exe`, `cleanmgr.exe`, `csc.exe`/`cvtres.exe` (a .NET runtime JIT-compile, itself unremarkable). **No sample process, no unusual binary name, appears anywhere in the 1,000 captured events.**
- **Zero registry writes to any `...\Run` key** anywhere in `raw.jsonl` (checked directly) — no persistence signal.
- **The 25 `NETWORK`-category Sysmon events are almost entirely `None`-destination (local/loopback) connections**, and the two with a real endpoint are PowerShell connecting to `[::1]:8765` — **that's ADAM's own HTTP guest agent port.** This session's "network activity" is the agent talking to itself, not a sample beaconing out.
- **`procmon.csv`'s real 48-second, 198k-row window** (the file the header bug is blocking) is *also* pure background noise by process name: `MsMpEng.exe`, `Procmon64.exe`, `etwdump.exe`, `MicrosoftEdgeUpdate.exe`, `tshark.exe`/`dumpcap.exe`, `svchost.exe`, `Sysmon64.exe`, `lsass.exe`, `notepad.exe`. No `CurrentVersion\Run` hits here either.

**Conclusion: this specific session captured infrastructure/diagnostic activity (very likely an agent install/health-check or a benign test run), not a malware detonation.** This matters directly for Parts 2 and 3 below — there is no malicious signal in this artifact set to build a demo around, regardless of what adapter you write.

### Cleanest temporary pipeline, using only existing code

```
tests/fixtures/semantic_events/*.json  (existing, hand-authored)
        │
        ▼
adam.policy.engine.PolicyEngine("rules/default").evaluate(event, SessionContext(session_id))
        │  (real rule matching, real budget/cooldown/confidence gating)
        ▼
adam.deception.engine.DeceptionEngine(channel).execute_async(decision)
        │  (real primitive apply_async, real Change construction, real plausibility scoring)
        ▼
MutationResult  +  channel's recorded (kind, target, operation, value) calls
```
This is exactly what `test_replay_pipeline.py` already does, end to end, today, with zero new code — see Part 3 for how to surface it as a demo output rather than a test-runner log.

---

## Part 2 — Minimal Integration (proposal only — nothing built)

If you want *real captured telemetry* (from a future, correctly-configured session) to reach Policy/Deception rather than only fixtures, the smallest honest addition is a **single, explicitly-temporary, pattern-matching bridge script** — not a Fusion reimplementation, not a statistical correlator, just a hardcoded lookup table from "a specific, recognizable RawEvent shape" to "one SemanticEvent." It should **not** live under `adam/fusion/` (that would preempt Dev B's actual ownership and design authority over that package — §10.1) and should **not** be imported by any production code path — it's a standalone script in the same spirit as your existing `tools/http_guest_diagnostic.py`, e.g. `tools/raw_event_bridge_TEMPORARY.py`, explicitly named and docstring-labeled as a stopgap to be deleted once Fusion lands.

```
input:  artifacts/<session_id>/raw.jsonl   (existing, already produced)
        │
        ▼
transformation (NEW — the only new code):
  for each RawEvent, check against a small, hardcoded pattern table, e.g.:
    category == REGISTRY and TargetObject matches r"\\Run\\"                → PERSIST_RUN_KEY
    category == REGISTRY and TargetObject contains "Domain"/"Netlogon"      → RECON_DOMAIN_CONTROLLER
    category == PROCESS  and image matches a known AV-checking pattern      → RECON_INSTALLED_AV
    category == NETWORK  and destination is non-loopback, non-RFC1918      → C2_BEACON
  on a match, construct ONE real adam.contracts.semantic_event.SemanticEvent:
    actor      = from the matching RawEvent's process field
    evidence   = [that RawEvent's event_id]           (real traceability, not fabricated)
    confidence = a fixed, disclosed constant per pattern (e.g. 0.65) — NOT a real
                 inference; label detector="ManualBridge@0.1-temporary" so nobody
                 mistakes this for Fusion's eventual, real confidence scoring
        │
        ▼
adam.policy.engine.PolicyEngine("rules/default").evaluate(event, SessionContext(...))
        │
        ▼
adam.deception.engine.DeceptionEngine(channel).execute_async(decision)
   channel = a small in-memory recorder (same shape as tests' existing FakeGuestChannel —
             reuse it, don't rewrite it)
        │
        ▼
output: MutationResult list + the recorder's logged (kind, target, operation, value) calls,
        printed as the same "intent / rule fired / primitive executed / plausibility /
        revert verified" table test_replay_pipeline.py already produces
```

**Honesty check on this specific session:** running this exact bridge against `sess_2026_08_05_a7f82ef0`'s `raw.jsonl` today would produce **zero matches** — there is no `Run`-key write, no domain-controller query, no non-loopback network destination in the captured data (see Part 1). This design is worth building for the *next* real malware run (especially once the Procmon column fix lands and Procmon's much richer 198k-event window becomes usable), but it would not manufacture a result out of this session's actual, benign content. Do not build it tonight expecting it to produce something for tomorrow — it won't, honestly, against this data.

This also directly answers your "do not duplicate Dev B" concern: a real Fusion engine does normalize/correlate/interpret across a sliding window with a registered-detector architecture and genuine confidence derivation (§5.4). This bridge does none of that — it's a flat lookup table with hardcoded confidence, explicitly disclosed as such, and designed to be deleted the day Fusion exists, not extended into a shadow Fusion.

---

## Part 3 — Demonstration (grounded in what this session's data actually supports)

Given the findings above, here's what's genuinely producible, split by whether it needs new code:

**From this session's real data, with existing code only (zero new code):**
- **Execution summary** — session ID, 1,000 raw events captured, breakdown by category (PROCESS 431, REGISTRY 406, FILE 134, NETWORK 25, SYSTEM 2, MODULE 2) and by source (100% SYSMON) — all already computed by `AnalysisSession.metrics`/directly countable from `raw.jsonl`.
- **Timeline** — `raw.jsonl` already carries `occurred_at` per event; sort and print. Real, available today, though be ready to explain the week-long span honestly (see below) rather than let it look like one 5-minute run.
- **Process activity view** — the distinct-image breakdown above is real and directly derivable.
- **Registry activity view** — real `TargetObject` values are already in the data; safe to show as "here's what ADAM's telemetry pipeline captures," not as "here's malware persistence" (there isn't any in this run).

**From `procmon.csv` directly (bypassing the broken collector, ad hoc, no code change to the pipeline — just reading the file):**
- A quick, honest "look, the richer 198k-event, correctly-time-scoped capture exists and is real — it's just in the wrong column format for the automated parser today" exhibit. Good supporting evidence for "the infrastructure works," bad as a source of "interesting" findings, since it's also all background noise in this run.

**Not producible from this session, with or without new code, because there's nothing malicious in it:**
- Policy matches / deception decisions grounded in *this session's real behavior* — there is no qualifying `SemanticEvent` to construct, real or bridged (Part 2).
- IOC summary of anything *suspicious* — an IOC list is easy to generate mechanically (unique file paths, registry keys, network endpoints touched), but for this session every entry is legitimate OS/security-tooling activity. You could show the mechanism works by presenting "0 suspicious IOCs in this run" as a valid negative result, but don't present it as if the sample was malicious.
- **MITRE ATT&CK technique mapping** — no code anywhere assigns `attck.tactic`/`technique` to a raw or semantic event automatically; this is a manual/human step today (Fusion's job eventually), not something you can run against this data.
- **Malware score** — no code anywhere computes anything like this. Do not present a number here; there is no formula backing it.
- **Persistence detection** — mechanically checkable (grep for `...\Run\` writes) and the honest answer for this session is **"none detected,"** which is a legitimate thing to show (proves the detection logic is real, even though the verdict is negative) — just don't let it read as "we checked and found nothing interesting" without the context that this wasn't a malware run.

**What I'd actually put in front of reviewers tomorrow, combining both sessions' worth of real material:**
1. **This session's execution summary + timeline + category breakdown** (2 min) — proves live capture, parsing, and structured `RawEvent` output work end-to-end against a real guest, with real numbers, not a mock.
2. **The Procmon column-format finding, stated plainly** (1 min) — "here's a second, richer, 198k-event real capture; here's the exact one-line reason it's not in the JSONL yet." This reads as competence (you found a real bug by inspecting real data), not as a weakness.
3. **The existing fixture replay pipeline** (`pytest tests/integration/test_replay_pipeline.py -v -s`, unchanged from the prior audit's Demo 3) — this remains your strongest, most reliable "Policy + Deception really executes" evidence, and it is completely unaffected by anything found in this session.
4. **The honest connective tissue** — say directly: "today's real capture (item 1) and today's real decision engine (item 3) haven't been run against each other yet, for two independent reasons: Fusion doesn't exist to do the conversion, and even a temporary bridge (which I've designed but not built) would find nothing to act on in this particular run, since it captured infrastructure activity, not a malware sample." This is a stronger position than pretending otherwise, and it directly sets up Part 5's recommendation.

---

## Part 4 — A Lightweight Dev D Frontend (1–2 days, against the current backend, unchanged)

Goal: visualize what already exists — `raw.jsonl`, the replay pipeline's `PolicyDecision`/`MutationResult` output — without inventing new backend capability. No FastAPI, no database, no live server required for a first cut; all of the above is static, file-based data today.

**Stack:** a single static HTML file (or a tiny Flask/FastAPI app if you want file-upload convenience) using Chart.js (timeline/category bars) + a plain HTML table (process/registry/IOC lists) + Graphviz.js or vis-network for the process tree. No build toolchain, no framework — matches §5.10's own "no SPA, no build toolchain" design principle, just pointed at flat files instead of a real `/api/v1` that doesn't exist yet. This is realistically buildable in 1–2 days precisely because it has zero new backend surface to write against.

**Pages:**
1. **Session Browser** — lists every folder under `artifacts/`, showing session ID, raw event count (`wc -l raw.jsonl`), and file inventory (which of raw.jsonl/procmon.csv/sysmon.evtx/network export are present) — directly answers "what runs do we have" without a database, just a directory listing.
2. **Session Detail — Execution Summary** — category/source breakdown (bar chart), time range, process count. All computable client-side from one `raw.jsonl` fetch.
3. **Session Detail — Timeline** — a horizontal scroll/zoom timeline of events by `occurred_at`, colour-coded by category. Real data, real value, and visually the single most "reviewer-friendly" chart you can build cheaply.
4. **Session Detail — Process Tree** — build parent/child edges from `process.pid`/`process.ppid` across the session's `PROCESS`-category events and render with vis-network or Graphviz — genuinely useful and something a professor will recognize immediately from real sandbox tools (Cuckoo/CAPE/Any.Run all have this view).
5. **Session Detail — Registry / File Activity Tables** — filterable tables straight from `raw.jsonl`'s `REGISTRY`/`FILE` category rows.
6. **Policy & Deception Viewer** — **this page reads the replay pipeline's output, not this session's raw data** (be explicit about that in the UI itself, e.g. a labelled "Reference Run" or "Simulated Decision Trace" panel) — render the same intent/rule/primitive/plausibility/revert table the pytest run already prints, as a proper table with colour-coded verdicts (`EXECUTE` green, `SUPPRESSED_*` amber). This is your best "the research core works" screen and it's just formatting already-existing print output.
7. **IOC Summary** — mechanically extracted unique file paths / registry keys / network endpoints from a session's `raw.jsonl`, with an honest empty state ("no indicators flagged") when a run — like this one — has nothing.

**Workflow:** point the page at a local `artifacts/` folder (file input or a tiny static file server — `python -m http.server` from the repo root is enough for a demo), pick a session from the browser page, drill into detail views. No auth, no persistence beyond the files already on disk — deliberately matching how little backend actually exists today rather than pretending otherwise.

**Presentation value:** this is the single highest-leverage Dev D deliverable for tomorrow's timeline specifically because it needs no new Python backend code at all — it's a pure consumer of files you already have (`raw.jsonl`) and output you can already produce (the replay table, redirected to a JSON file instead of stdout — a 10-line change to how the existing test prints its summary, not a new engine).

---

## Part 5 — Recommendation

**Can you already demonstrate a meaningful malware-analysis pipeline without waiting for Dev B? Yes — but as two separate, honestly-labelled halves, not one connected loop, and not using this specific session's data for the "malware" half.**

**What works today, unconditionally:**
- Real, automated, real-VM sandbox lifecycle + telemetry capture (Sysmon fully wired; Procmon capture is real but currently blocked from reaching `raw.jsonl` by a one-line configuration mismatch you now know the exact cause of).
- Real, fully-tested Policy Engine + Deception Engine, executing genuine rule matching, budget/cooldown/confidence gating, primitive application, and revert — proven via the existing replay pipeline against fixture data.

**What should be shown tomorrow:**
1. The live capture pipeline, using `sess_2026_08_05_a7f82ef0` (or a fresh run) as real, honest evidence — labelled accurately as infrastructure/telemetry evidence, not as "we analyzed malware."
2. The Procmon-format finding as a specific, credible piece of debugging, not hidden.
3. The replay pipeline's decision trace as your strongest "the research core works" evidence, clearly labelled as running against reference/fixture semantic events, not this session's data.
4. The gap between them stated plainly (no Fusion; even a temporary bridge would find nothing in this particular run) — this is more credible than implying a connection that doesn't exist, and it directly sets up "what's left."

**What should wait for Dev B (or, more precisely, doesn't need to wait — but shouldn't be faked in the meantime):**
- Any claim of a live, sample-driven `SemanticEvent` produced from real telemetry.
- Any MITRE ATT&CK mapping or malware score — no code produces either.
- Presenting the temporary bridge from Part 2 as if it were Fusion, or building it out further than a disclosed, deletable stopgap — that would misrepresent Dev B's ownership and the actual state of the research core.

**One concrete, low-risk thing worth doing before tomorrow if you have an hour:** fix the guest's Procmon capture configuration to include the "Date & Time" column (a Procmon GUI/config setting change on the guest image, not a code change) and run one more short session detonating something with actual, deliberate behavior (even a single Atomic Red Team test, per the prior audit's Part 5 recommendation) — that would give you a session where `raw.jsonl` actually contains something worth pointing a bridge script at, turning tomorrow's "here's the gap" story into "here's the gap, and here's what closing even a temporary version of it would show" for the next review instead.
