# Policy Engine + Adaptive Deception — Reference Document

**Owner:** Nived (Dev C)
**Modules:** `adam/policy/`, `adam/deception/`, `rules/`
**Branch:** `nived-dev`
**Status:** Feature-complete, 100% test coverage, ready for integration

This document is the single reference for what this module does, how to use
it, how to extend it, and what's still pending on the integration side.
If you're consuming `PolicyDecision` or `MutationResult` objects from this
module (Dilip, Pranav) or feeding it `SemanticEvent`s (Raghu), start here.

---

## 1. What this module does

Given a `SemanticEvent` (produced by the Fusion Engine), this module:

1. **Policy Engine** (`adam/policy/`) evaluates the event against a YAML rule
   corpus and returns zero or more `PolicyDecision`s — a decision to execute
   a deception, suppress (budget/cooldown/confidence), or log only.
2. **Deception Engine** (`adam/deception/`) takes an `EXECUTE` decision and
   applies the corresponding deception primitive against a guest mutation
   channel, returning a `MutationResult` with a plausibility score and full
   revert support.

Both engines are **pure functions** per ADR-004: identical `(event, context)`
input always produces identical output, and neither touches the network,
filesystem, or VM directly. This is what makes the whole thing testable
without a VM — see §5.

```
SemanticEvent → PolicyEngine.evaluate() → PolicyDecision → DeceptionEngine.execute_async() → MutationResult
```

---

## 2. Intent → Rule → Primitive catalogue (current state)

All 12 intent categories from the architecture spec (§7.8) are wired.
0 primitives missing.

| Intent | Rule ID | Primitive | Notes |
|---|---|---|---|
| `RECON_DOMAIN_CONTROLLER` | RULE-014, RULE-015 | `SPAWN_FAKE_DC_ARTIFACTS` | Two confidence tiers |
| `RECON_INSTALLED_AV` | RULE-016 | `SIMULATE_AV_PRESENCE` | |
| `RECON_VIRTUALISATION` | RULE-017 | `HIDE_VM_ARTIFACTS` | |
| `RECON_NETWORK_SHARES` | RULE-018 | `MOUNT_FAKE_NETWORK_SHARE` | |
| `RECON_USER_ARTIFACTS` | RULE-027 | `PLANT_DECOY_DOCUMENTS` | |
| `RECON_SYSTEM_UPTIME` | RULE-025 | `SPAWN_DECOY_PROCESSES` | |
| `RECON_DEBUGGER` | RULE-026 | `SPAWN_DECOY_PROCESSES` | Shares primitive with uptime |
| `CRED_BROWSER_STORE` | RULE-019 | `INJECT_FAKE_BROWSER_CREDS` | |
| `CRED_WALLET_SEARCH` | RULE-020 | `PLANT_DECOY_WALLET` | Split out from decoy documents |
| `PERSIST_RUN_KEY` | RULE-021 | `PLANT_DECOY_RUN_KEY` | |
| `EVADE_SANDBOX_DETECTED` | RULE-022 | *(none — `LOG_ONLY`)* | Deliberately no deception once evasion is detected |
| `EVADE_SLEEP_SKIP` | RULE-024 | `ACCELERATE_SYSTEM_CLOCK` | Special revert semantics — see §4 |
| `C2_BEACON` | RULE-023 | `FABRICATE_C2_RESPONSE` | |

Full rule definitions live under `rules/default/*.yaml`, split by tactic
family: `recon.yaml`, `credentials.yaml`, `persistence.yaml`, `evasion.yaml`,
`c2.yaml`. Every rule validates against `rules/schema/rule.schema.json`.

---

## 3. Data contracts (what other modules send/receive)

These currently live in `adam/contracts/` as **local stubs** matching the
shapes in the architecture doc §7.3–7.5. This is the one piece pending
integration — see §7.

**Input — `SemanticEvent`** (from Raghu's Fusion Engine):
```json
{
  "semantic_id": "sem_...",
  "session_id": "sess_...",
  "correlation_id": "corr_...",
  "intent": "RECON_DOMAIN_CONTROLLER",
  "confidence": 0.87,
  "severity": "MEDIUM",
  "window_start": "2026-07-21T14:32:11.401220Z",
  "window_end": "2026-07-21T14:32:13.902441Z",
  "actor": { "pid": 4812, "image": "C:\\Windows\\system32\\sample.exe", "guid": "{...}" },
  "evidence": ["raw_..."],
  "detector": "DomainControllerDetector",
  "features": { "distinct_registry_keys": 3 },
  "caused_by_mutation": null
}
```

**Output — `PolicyDecision`** (consumed by Deception Engine internally, and
by Dilip's dashboard/reports for the decision ledger):
```json
{
  "decision_id": "dec_...",
  "session_id": "sess_...",
  "correlation_id": "corr_...",
  "triggered_by": "sem_...",
  "rule_id": "RULE-014",
  "rule_version": "1.0.3",
  "action": "SPAWN_FAKE_DC_ARTIFACTS",
  "verdict": "EXECUTE",
  "priority": 80,
  "parameters": { "domain_name": "CORP.LOCAL" },
  "rationale": "Domain recon at confidence 0.87 (gate 0.75); budget 0/1 used"
}
```
`verdict` ∈ `EXECUTE` · `SUPPRESSED_BUDGET` · `SUPPRESSED_COOLDOWN` ·
`SUPPRESSED_CONFIDENCE` · `DRY_RUN` · `LOG_ONLY`.
**Suppressed decisions are real, persisted objects** — never `None`, never
dropped. Dilip's ledger should show these; a rule that fires often but
suppresses often is a meaningful finding, not noise to filter out.

**Output — `MutationResult`** (needs to reach Pranav's sandbox controller,
and reach back onto the bus per ADR-003 so Raghu's Fusion can attribute
subsequent behaviour):
```json
{
  "mutation_id": "mut_...",
  "session_id": "sess_...",
  "correlation_id": "corr_...",
  "decision_id": "dec_...",
  "primitive": "FakeDomainControllerDeception@1.0",
  "status": "APPLIED",
  "changes": [
    { "kind": "REGISTRY", "target": "HKLM\\...\\Domain", "operation": "SET", "value": "CORP.LOCAL" }
  ],
  "plausibility_score": 0.60,
  "revertible": true
}
```
`status` ∈ `APPLIED` · `PARTIAL` · `FAILED` · `REVERTED` · `SKIPPED`.

---

## 4. Design notes worth knowing before you integrate

- **Pure functions, explicit context.** `PolicyEngine.evaluate()` takes
  `SessionContext` as an explicit argument (budget consumed, cooldowns,
  prior decisions) rather than holding hidden state. Don't reuse one
  `SessionContext` instance across unrelated sessions.
- **Budgets and cooldowns are keyed per rule ID**, not global — firing one
  rule never consumes another rule's budget.
- **`dry_run=True` never touches the mutation channel at all** — verified
  across every primitive with a mocked channel spy. Use this for anyone
  who wants to see decisions without side effects (this is the CONTROL
  arm of the eventual A/B experiment).
- **Every primitive implements `revert_async()`**, and reverts happen in
  *reverse* order of the changes applied — this matters for primitives with
  interdependent changes (e.g. registry key referenced by a file).
- **`ACCELERATE_SYSTEM_CLOCK` is a special case:** it can't be "undone" by
  deleting discrete artifacts the way registry/file primitives can — its
  `revert_async` resynchronizes the clock back to host/NTP time instead.
  Worth flagging if anyone builds tooling that assumes all reverts look
  the same shape.
- **Plausibility scores are computed, not hardcoded** — via
  `adam/deception/plausibility.py`'s `score_timestamp_consistency` /
  `score_naming_consistency` / `combine`. Scores currently range 0.60–1.00
  across primitives depending on whether the primitive makes a
  post-boot-timestamped change.

---

## 5. Testing & how to verify it yourself

No VM needed to validate any of this — that's deliberate (ADR-004 / §17.2
of the architecture doc, replay-based testing).

```bash
pip install -r requirements.txt
python -m pytest tests/ -v --cov=adam.policy --cov=adam.deception --cov-report=term-missing
```

Current result: **51 tests passing, 100% coverage** on both `adam.policy`
and `adam.deception` (539/539 statements).

There's also an end-to-end replay smoke test —
`tests/integration/test_replay_pipeline.py` — that runs every fixture
`SemanticEvent` (all 12 intents) through the full
`PolicyEngine → DeceptionEngine` chain against a fake guest channel and
prints a summary table (rule fired, primitive executed, plausibility score,
revert verified). This is the fastest way to see the whole module work
without reading code:

```bash
python -m pytest tests/integration/test_replay_pipeline.py -s
```

---

## 6. How to extend this (for anyone touching `rules/` or adding a primitive)

Full instructions are in [`docs/rule_authoring.md`](./rule_authoring.md):
how to add a new YAML rule, when to use the DSL vs. a custom Python
predicate, and how to register a new deception primitive via
`@register_primitive`. Adding one of either is additive-only — you should
never need to touch `adam/policy/engine.py` or `adam/deception/engine.py`.

---

## 7. What's NOT done yet — read before integrating

Full detail in [`docs/known_limitations.md`](./known_limitations.md).
Summary:

1. **`adam/contracts/` is still a local stub**, not yet reconciled against
   the team's frozen shared package. Field shapes match the architecture
   doc's §7.2–7.6 schemas as closely as possible, but once the real
   `adam/contracts/` lands, imports need to be swapped over and the full
   suite re-run. This is the one real blocking dependency between this
   module and the rest of the pipeline.
2. **`revert_async()` has only been verified against a fake mutation
   channel (`FakeGuestChannel`)**, never against Pranav's real
   `ISandboxController`. The interface contract (`GuestMutationChannel`
   Protocol in `adam/deception/primitives/base.py`) is what Pranav's real
   controller needs to satisfy — flag early if there's any mismatch.
3. **No mutation has been published back onto the real event bus yet**
   (ADR-003) — that requires the bus wiring from Pranav/Raghu's side to
   exist first. `MutationResult` objects are correctly produced and
   revert-verified; they just haven't been round-tripped through a live
   bus into Fusion for attribution yet.

---

## 8. Quick FAQ for teammates

**"I'm Raghu — what shape does my `SemanticEvent` need to be in?"**
See §3. Match the intent strings exactly (case-sensitive) to the table in
§2 — anything outside that list currently produces no decision (not an
error, just an empty decision list).

**"I'm Pranav — what does my sandbox controller need to implement?"**
`GuestMutationChannel` Protocol in `adam/deception/primitives/base.py`.
Whatever `apply_mutation()` on your side does, it needs to accept the
`(kind, target, operation, value)` shape shown in §3's `changes` array.

**"I'm Dilip — what do I render on the dashboard/report?"**
`PolicyDecision` for the decision ledger (including suppressed ones —
don't filter them out), `MutationResult` for the mutation timeline,
including `plausibility_score` since the architecture spec requires
surfacing low-plausibility mutations rather than hiding them.
