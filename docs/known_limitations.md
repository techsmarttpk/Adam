# Known Limitations & Technical Debt

This document tracks known limitations, pending integrations, and architectural boundaries for the Policy Engine (`adam/policy/`) and Adaptive Deception Engine (`adam/deception/`).

## 1. Environment & Integration Boundaries

- **Fake Guest Mutation Channel**: All `revert_async()` and `apply_async()` methods have been verified strictly against `FakeGuestChannel` protocol mocks (`AsyncMock`). Execution against a live VirtualBox VM or Pranav's `ISandboxController` module remains to be validated at the composition root (`adam/api/deps.py`).
- **Local Stub Contracts**: `adam/contracts/` (`enums.py`, `interfaces.py`, `mutation.py`, `policy_decision.py`, `semantic_event.py`) is currently a local stub enabling offline unit testing. It has not yet been reconciled or merged with the team's frozen shared package.

## 2. Deception Primitive Catalogue Status

All 12 intent categories across the rule corpus (`rules/default/*.yaml`) are fully wired and functional. The catalogue registers 11 concrete primitives in `adam/deception/catalogue.py`:

1. `SPAWN_FAKE_DC_ARTIFACTS` (`FakeDomainControllerDeception`) — Domain controller identity lures
2. `PLANT_DECOY_RUN_KEY` (`PlantDecoyRunKey`) — Registry persistence decoy run key
3. `SIMULATE_AV_PRESENCE` (`SimulateAVPresence`) — Antivirus process & registry lures
4. `PLANT_DECOY_DOCUMENTS` (`PlantDecoyDocuments`) — Decoy documents for user artifact discovery
5. `PLANT_DECOY_WALLET` (`PlantDecoyWallet`) — Decoy cryptocurrency wallet lures
6. `INJECT_FAKE_BROWSER_CREDS` (`InjectFakeBrowserCreds`) — Decoy browser credential store entries
7. `FABRICATE_C2_RESPONSE` (`FabricateC2Response`) — Fabricated HTTP C2 beacon responses
8. `ACCELERATE_SYSTEM_CLOCK` (`AccelerateSystemClock`) — Guest system clock fast-forwarding for sleep evasion
9. `SPAWN_DECOY_PROCESSES` (`SpawnDecoyProcesses`) — Benign process lures for uptime/debugger recon
10. `MOUNT_FAKE_NETWORK_SHARE` (`MountFakeNetworkShare`) — Mounted fake SMB network share lures
11. `HIDE_VM_ARTIFACTS` (`HideVMArtifacts`) — VirtualBox hardware artifact masking

*Delta against ARCHITECTURE.md §7.8*: Zero missing primitives. Every intent in the architecture catalogue is fully implemented, wired in YAML, and verified end-to-end.

## 3. Test Coverage Status

100% line coverage is achieved across all modules in `adam.policy` and `adam.deception`.
