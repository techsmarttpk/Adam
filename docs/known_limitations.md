# Known Limitations & Technical Debt

This document tracks known limitations, pending integrations, and remaining architectural gaps for the Policy Engine (`adam/policy/`) and Adaptive Deception Engine (`adam/deception/`).

## 1. Environment & Integration Boundaries

- **Fake Guest Mutation Channel**: All `revert_async()` and `apply_async()` methods have been verified strictly against `FakeGuestChannel` protocol mocks (`AsyncMock`). Execution against a live VirtualBox VM or Pranav's `ISandboxController` module remains to be validated at the composition root (`adam/api/deps.py`).
- **Local Stub Contracts**: `adam/contracts/` (`enums.py`, `interfaces.py`, `mutation.py`, `policy_decision.py`, `semantic_event.py`) is currently a local stub enabling offline unit testing. It has not yet been reconciled or merged with the team's frozen shared package.

## 2. Deception Primitive Catalogue Delta

Currently, 7 primitive actions are registered and verified in `adam/deception/catalogue.py`:
1. `SPAWN_FAKE_DC_ARTIFACTS` (`FakeDomainControllerDeception`)
2. `PLANT_DECOY_RUN_KEY` (`PlantDecoyRunKey`)
3. `SIMULATE_AV_PRESENCE` (`SimulateAVPresence`)
4. `PLANT_DECOY_DOCUMENTS` (`PlantDecoyDocuments`)
5. `PLANT_DECOY_WALLET` (`PlantDecoyWallet`)
6. `MOUNT_FAKE_NETWORK_SHARE` (`MountFakeNetworkShare`)
7. `HIDE_VM_ARTIFACTS` (`HideVMArtifacts`)

### Missing Catalogue Primitives (per ARCHITECTURE.md §7.8)
The following primitives specified in the architecture document are not yet implemented in `adam/deception/primitives/`:
- **`PLANT_DECOY_DOCUMENTS` for `RECON_USER_ARTIFACTS`**: Specific user profile/document lures targeting general user artifact discovery (distinct from credential browser/wallet lures).
- **`INJECT_FAKE_BROWSER_CREDS`**: Direct injection of fake login records into browser SQLite login databases.
- **`FABRICATE_C2_RESPONSE`**: Intercepting network requests and returning fake C2 beacon responses.
- **`ACCELERATE_SYSTEM_CLOCK`**: Fast-forwarding system time to bypass sleep/delay anti-sandbox evasion.
- **`SPAWN_DECOY_PROCESSES`**: Dynamic process creation matching targeted process enumeration requests.

## 3. Test Coverage & Unreached Branches

Following Step 2, `adam.policy` achieved **100% line coverage**. The remaining uncovered lines in `adam.deception` consist of defensive exception branches:

- **`adam/deception/catalogue.py` (88%)**:
  - Line 22: `ValueError` when registering an `action_name` that is already registered.
  - Lines 32–33: `KeyError` when looking up an unregistered action name.
- **`adam/deception/plausibility.py` (90%)**:
  - Line 31: `if not scores: return 1.0` fallback branch when `combine()` is called with zero score arguments.
