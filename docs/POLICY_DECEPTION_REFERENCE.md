# Policy Engine & Adaptive Deception — Reference Document

**Modules:** `adam/policy/`, `adam/deception/`, `rules/`  
**Status:** Feature-complete, verified live pipeline & replay integration

This document is the core reference for the Policy Evaluation and Dynamic Deception subsystem within ADAM.

---

## 1. Subsystem Architecture & Workflow

Given a `SemanticEvent` (produced by the Event Fusion Engine), this subsystem performs:

1. **Policy Engine** (`adam/policy/`): Evaluates the incoming semantic event against declarative YAML rules (`rules/default/*.yaml`). It determines whether to emit an `EXECUTE` decision for deception, suppress the action (due to budget exhaustion, cooldown window, or low confidence threshold), or perform a `LOG_ONLY` audit action.
2. **Deception Engine** (`adam/deception/`): Receives `EXECUTE` decisions, resolves the corresponding deception primitive, and executes the mutation against the guest channel (`HTTPGuestChannel` / `GuestMutationChannel`). It records a `MutationResult` with plausibility scoring and full state-reversion support.

```text
SemanticEvent → PolicyEngine.evaluate() → PolicyDecision → DeceptionEngine.execute_async() → MutationResult
```

---

## 2. Intent → Rule → Deception Primitive Catalog

All 12 MITRE ATT&CK intent categories are fully mapped and wired:

| Intent Category | Rule ID | Deception Primitive | Action / Mutation Target |
|---|---|---|---|
| `RECON_DOMAIN_CONTROLLER` | RULE-014, RULE-015 | `SPAWN_FAKE_DC_ARTIFACTS` | Plants mock Domain Controller cache / SPN entries |
| `RECON_INSTALLED_AV` | RULE-016 | `SIMULATE_AV_PRESENCE` | Simulates decoy security services & processes |
| `RECON_VIRTUALISATION` | RULE-017 | `HIDE_VM_ARTIFACTS` | Masks hypervisor-identifying artifacts |
| `RECON_NETWORK_SHARES` | RULE-018 | `MOUNT_FAKE_NETWORK_SHARE` | Plants synthetic mapped network drives/shares |
| `RECON_USER_ARTIFACTS` | RULE-027 | `PLANT_DECOY_DOCUMENTS` | Plants lure files (e.g. `passwords.txt`, credentials) |
| `RECON_SYSTEM_UPTIME` | RULE-025 | `SPAWN_DECOY_PROCESSES` | Spawns plausible background decoy processes |
| `RECON_DEBUGGER` | RULE-026 | `SPAWN_DECOY_PROCESSES` | Spawns background debuggers / analysis decoys |
| `CRED_BROWSER_STORE` | RULE-019 | `INJECT_FAKE_BROWSER_CREDS` | Plants synthetic SQLite Chrome/Edge credential stores |
| `CRED_WALLET_SEARCH` | RULE-020 | `PLANT_DECOY_WALLET` | Plants decoy cryptocurrency wallet directories |
| `PERSIST_RUN_KEY` | RULE-021 | `PLANT_DECOY_RUN_KEY` | Plants registry Run / RunOnce persistence decoys |
| `EVADE_SANDBOX_DETECTED` | RULE-022 | *(none — `LOG_ONLY`)* | Deliberately skips active mutation once evasion is detected |
| `EVADE_SLEEP_SKIP` | RULE-024 | `ACCELERATE_SYSTEM_CLOCK` | Fast-forwards guest system clock to bypass sleep loops |
| `C2_BEACON` | RULE-023 | `FABRICATE_C2_RESPONSE` | Network-level synthetic response (see Known Limitations) |

---

## 3. Data Contracts & Envelopes

The subsystem communicates across the event bus (`adam/common/bus.py`) via typed Pydantic models:

- **`SemanticEvent`** (`adam/contracts/semantic_event.py`): Contains actor PID/image, intent category, confidence (0.0–1.0), severity, evidence traces, and MITRE ATT&CK tactic/technique IDs.
- **`PolicyDecision`** (`adam/contracts/policy_decision.py`): Contains `verdict` (`EXECUTE`, `SUPPRESSED_BUDGET`, `SUPPRESSED_COOLDOWN`, `SUPPRESSED_CONFIDENCE`, `LOG_ONLY`), targeted `action`, rule metadata, and suppression reason.
- **`MutationResult`** (`adam/contracts/mutation.py`): Contains mutation status (`APPLIED`, `FAILED`, `SKIPPED`, `REVERTED`), latency in milliseconds, plausibility score (0.0–1.0), list of applied environment changes, and error trace if failed.

---

## 4. Extension & Rule Authoring

To add new rules or primitives, refer to [`docs/rule_authoring.md`](./rule_authoring.md).
Adding rules to `rules/default/` or registering new primitives via `@register_primitive` is strictly additive and requires zero changes to the core engine.
