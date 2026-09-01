# ADAM Mutation Test Harness & Live Mutation Console

This document provides complete operator and developer documentation for the **ADAM Mutation Test Harness** and **Live Mutation Console**.

---

## 1. Overview & Research Objective

The Mutation Test Console provides a controlled dashboard-driven research harness for ADAM's closed adaptive deception loop. It allows operators to inject a standalone test executable (`adam_mutation_test.exe`), dispatch deterministic safe behavior triggers across different severity tiers, and observe the real-time event pipeline:

```text
Test Command
   ↓
RawEvent Telemetry (Sysmon / ProcMon / Network / Agent)
   ↓
Fusion Engine (SemanticEvent + Confidence + ATT&CK + Phase)
   ↓
Policy Engine (Rule Evaluation + Gating + Action Selection)
   ↓
Deception Engine (Dispatched to Guest Agent)
   ↓
Mutation Applied (Registry, File, Network, Process changes)
   ↓
MutationResult & Structured Environment Explanation
   ↓
Downstream Telemetry & Causal Attribution (caused_by_mutation)
```

---

## 2. Test Mode Isolation

To guarantee that research demonstrations never alter normal autonomous malware detonating sessions:
1. Test sessions are explicitly created with `mutation_test_mode = True` when injected via `/api/v1/mutation-tests/inject`.
2. Normal sandbox analysis sessions execute with `mutation_test_mode = False`.
3. The test harness does **NOT** bypass any confidence gates, policy rules, cooldowns, or causal attribution windows.

---

## 3. Building the Standalone Executable (`adam_mutation_test.exe`)

The test harness uses a standalone Windows binary compiled via `.NET Framework csc.exe`:

### Build Commands
```powershell
powershell -ExecutionPolicy Bypass -File tools/mutation_test/build.ps1
```
Output Binary:
```text
tools/mutation_test/dist/adam_mutation_test.exe
```

### Binary Metadata & Safety Banner
Running the binary directly:
```text
=================================================
 [ADAM-MUTATION-TEST] Diagnostic Harness
 Version: 1.0.0 | Harness: 1.0.0 | Manifest: 2026.1
 Notice: Safe deterministic telemetry triggers only.
=================================================
Usage: adam_mutation_test.exe --cmd <command_id>
```

---

## 4. Command Manifest & Severity Tiers

The test harness loads all available commands dynamically from `tools/mutation_test/manifest.json`.

| Severity | Command ID | Name | Expected Intent | Expected Policy Action | Action Type |
|---|---|---|---|---|---|
| **CRITICAL** | `crit_vm_check` | VM Artifact Check | `EVADE_VM_ARTIFACT_CHECK` | `SPOOF_HARDWARE_IDENTITY` | `MUTATE` |
| **CRITICAL** | `crit_process_hollowing` | Process Hollowing Probe | `INJECT_PROCESS_HOLLOWING` | `ACTIVATE_EPT_SHADOW_HOOK` | `MEASUREMENT` |
| **CRITICAL** | `crit_cloud_creds` | Cloud Credential Search | `CRED_CLOUD_CREDENTIAL_SEARCH` | `PLANT_DECOY_CLOUD_CREDENTIALS` | `MUTATE` |
| **CRITICAL** | `crit_c2_dga` | C2 DGA Probe | `C2_DGA_ACTIVITY` | `ACTIVATE_C2_SINKHOLE` | `MUTATE` |
| **CRITICAL** | `crit_shadow_copy_delete` | Shadow Copy Deletion | `IMPACT_SHADOW_COPY_DELETE` | `CREATE_DECOY_RECOVERY_TARGET` | `MUTATE` |
| **CRITICAL** | `crit_rdp_lateral` | Lateral RDP Connection | `LATERAL_RDP_CONNECTION` | `SYNTHESIZE_RDP_TARGETS` | `MUTATE` |
| **HIGH** | `high_recon_dc` | Domain Controller Discovery | `RECON_DOMAIN_CONTROLLER` | `SPAWN_FAKE_DC_ARTIFACTS` | `MUTATE` |
| **HIGH** | `high_browser_creds` | Browser Credential Search | `CRED_BROWSER_STORE` | `INJECT_FAKE_BROWSER_CREDS` | `MUTATE` |
| **HIGH** | `high_crypto_wallet` | Crypto Wallet Search | `CRED_WALLET_SEARCH` | `PLANT_DECOY_WALLET` | `MUTATE` |
| **HIGH** | `high_ssh_keys` | SSH Key Harvest | `COLLECT_SSH_KEYS` | `PLANT_DECOY_PRIVATE_KEYS` | `MUTATE` |
| **HIGH** | `high_admin_shares` | Admin Share Enumeration | `LATERAL_ADMIN_SHARE_ENUM` | `MOUNT_FAKE_NETWORK_SHARE` | `MUTATE` |
| **HIGH** | `high_c2_beacon` | C2 Polling Beacon | `C2_HTTP_POLLING` | `FABRICATE_C2_RESPONSE` | `MUTATE` |
| **MEDIUM** | `med_process_discovery` | Process Enumeration | `RECON_PROCESS_DISCOVERY` | `SPAWN_DECOY_PROCESSES` | `MUTATE` |
| **MEDIUM** | `med_user_discovery` | User Profile Discovery | `RECON_USER_DISCOVERY` | `SYNTHESIZE_USER_PROFILE` | `MUTATE` |
| **MEDIUM** | `med_installed_software` | Software Inventory | `RECON_INSTALLED_SOFTWARE` | `SYNTHESIZE_SOFTWARE_INVENTORY` | `MUTATE` |
| **LOW** | `low_system_info` | System Info Baseline | `RECON_OS_VERSION` | `NONE` | `OBSERVE` |
| **LOW** | `low_network_config` | Network Config | `RECON_NETWORK_CONFIG` | `NONE` | `OBSERVE` |
| **OBSERVE** | `obs_lsass_access` | LSASS Process Query | `CRED_LSASS_ACCESS` | `NONE` | `OBSERVE` |

---

## 5. API Endpoints

- `GET /api/v1/mutation-tests/commands`: Loads dynamic command manifest.
- `POST /api/v1/mutation-tests/inject`: Injects test binary into guest and initializes test mode.
- `POST /api/v1/mutation-tests/{session_id}/execute`: Triggers command stimulus.
- `POST /api/v1/mutation-tests/{session_id}/stop`: Stops test session and restores default state.
- `GET /api/v1/mutation-tests/{session_id}/results`: Returns validation verdict (`PASS`, `PARTIAL`, `FAILED`, `UNEXPECTED`).

---

## 6. Ground Truth Verification & Environment Snapshots

ADAM incorporates an independent verification layer to prove that mutations are not just declared, but physically manifest in the sandbox environment.

### 6.1 Environment Snapshot Model
`adam.deception.snapshot.EnvironmentSnapshot` captures:
- `domain_identity` (e.g. `WORKGROUP` -> `CORP.LOCAL`)
- `domain_controllers` (e.g. `['DC01.CORP.LOCAL']`)
- `network_shares` (e.g. `['\\\\DC01\\SYSVOL']`)
- `synthetic_files` (e.g. decoy Chrome Login Data, AWS credentials)
- `synthetic_registry_entries` (e.g. spoofed hardware BIOS)
- `active_measurement_hooks` (e.g. EPT shadow hooks)

### 6.2 Pipeline Integrity Proof Checklist
The dashboard and test harness verify 9 runtime invariant proofs:
1. `real_process_execution`: Process spawned with genuine PID in guest.
2. `real_guest_telemetry`: Sysmon / ETW telemetry emitted.
3. `real_fusion_detector`: Target detector matched and scored.
4. `real_semantic_event`: Valid SemanticEvent created on EventBus.
5. `real_policy_evaluation`: Policy rule evaluated with budget/cooldown checks.
6. `real_deception_primitive`: Mutation primitive selected.
7. `real_mutation_result`: MutationResult produced with structured explanation.
8. `real_environment_verification`: Physical guest inspection passes (`PASS`).
9. `real_causal_attribution`: Subsequent events carry `caused_by_mutation`.

---

## 7. Golden Mutation Suite & Verification Tests

The golden test suite (`tests/integration/test_golden_mutation_suite.py`) verifies:
1. **Discovery & Reconnaissance**: `high_recon_dc`, `med_process_discovery`, `low_system_info`.
2. **Credential Access**: `high_browser_creds`, `obs_lsass_access`.
3. **Defense Evasion**: `crit_vm_check`.
4. **Command and Control**: `crit_c2_dga`.
5. **Lateral Movement**: `high_admin_shares`.
6. **Process Injection**: `crit_process_hollowing`.
7. **Impact**: `crit_shadow_copy_delete`.
8. **Negative Tests**: Weak/benign stimuli do not trigger active mutations.
9. **Observe-Only Tests**: Critical uncontainable triggers (LSASS) correctly observe without mutating.
10. **Replay Correspondence**: Deterministic replay yields identical intent and confidence scores.

To run the full suite:
```bash
python -m pytest tests/integration/test_golden_mutation_suite.py
```
`EventBus`.

---

## 8. Live Mutation Inspector & Synthetic Environment Visualization

Clicking any `[MUTATION]` event in the live console displays the **Mutation Inspector**, exposing structured representations of what ADAM generated:

### Example: Domain Controller Discovery
- **Primitive**: `SPAWN_FAKE_DC_ARTIFACTS`
- **Domain**: `CORP.LOCAL`
- **Domain Controller**: `DC01.CORP.LOCAL` (`10.0.0.10`)
- **DNS Artifact**: `DC01.CORP.LOCAL -> 10.0.0.10`
- **Filesystem Artifact**: `C:\Windows\SYSVOL\sysvol\CORP.LOCAL\`
- **Registry Targets**: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain`

### Example: Browser Credential Vault Deception
- **Primitive**: `INJECT_FAKE_BROWSER_CREDS`
- **Browser Profile**: `Google Chrome (Default)`
- **Vault Database**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
- **Simulated Logins**: `admin@corp.local`, `executive_vpn`, `payroll_portal`

---

## 7. Interpreting Test Validation Verdicts

| Verdict | Condition | Meaning |
|---|---|---|
| **PASS** | `Observed Intent == Expected Intent` AND `Observed Decision == Expected Action` AND `Mutation Applied` | Perfect end-to-end closed-loop execution. |
| **PARTIAL** | `Observed Intent == Expected Intent`, but policy action differs or mutation was suppressed by budget/cooldown. | Intent detected, but action suppressed or altered. |
| **FAILED** | Expected intent was never detected. | Detector signature did not trigger on telemetry. |
| **UNEXPECTED** | Different semantic intent triggered before the expected intent. | Telemetry triggered secondary intent detector. |

---

## 8. Adding New Test Commands

To add a new command:
1. Add an entry into `tools/mutation_test/manifest.json` specifying `id`, `name`, `severity`, `category`, `expected_intent`, `expected_policy_action`, and `telemetry_pattern`.
2. Add the safe non-destructive trigger into `tools/mutation_test/Program.cs` under the switch statement.
3. Add the mock raw event generation pattern to `_generate_test_raw_events` in `adam/api/routers/mutation_tests.py`.
4. Rebuild via `tools/mutation_test/build.ps1`.
