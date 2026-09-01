# ADAM Mutation Catalogue

This document defines all Active Deception Mutations, Environment Synthesis Primitives, and Observation-Preserving Measurement Actions supported by the ADAM Orchestrator and Guest Agent.

## Mutation Execution Rules

1. **Reversible & Contained**: Every mutation produces a `MutationResult` with individual `MutationChange` entries, a `plausibility_score`, and is bounded by a `causal_window_ms`.
2. **Attributable**: Downstream `SemanticEvent`s occurring within the `causal_window_ms` receive `caused_by_mutation == mutation_id`.
3. **Category Disambiguation**:
   - **MUTATE**: Active environmental deception synthesized in flight to deceive the malware and force execution of dormant branches.
   - **OBSERVE**: No environment alteration; passive high-fidelity telemetry collection.
   - **MEASUREMENT**: Observation-preserving primitives designed to protect telemetry capture (e.g. EPT hooks, process tracking, snapshot preservation) rather than deceive the malware.

---

## 1. Active Deception Primitives (`MUTATE`)

### Filesystem & Artifact Deception
- `PLANT_DECOY_DOCUMENTS`: Injects simulated corporate documents (`.docx`, `.xlsx`, `.pdf`) with realistic metadata into user directories.
- `PLANT_DECOY_WALLET`: Injects Electrum/Bitcoin synthetic wallet structures.
- `INJECT_FAKE_BROWSER_CREDS`: Drops simulated SQLite browser login vaults into user profile paths.
- `PLANT_DECOY_PRIVATE_KEYS`: Generates synthetic OpenSSH RSA private keys in `~/.ssh/id_rsa`.
- `PLANT_DECOY_CREDENTIAL_ARTIFACTS`: Drops synthetic Windows Vault and Credential Manager files.
- `PLANT_DECOY_SESSION_DATA`: Drops synthetic session cookies and tokens.
- `PLANT_DECOY_PASSWORD_MANAGER`: Deploys KeePass `.kdbx` decoy databases.
- `PLANT_DECOY_CONFIG_FILES`: Plants decoy `unattend.xml` and `web.config` credential files.
- `PLANT_DECOY_SSH_CONFIG`: Generates decoy `~/.ssh/config` and `known_hosts` files.
- `PLANT_DECOY_RDP_ARTIFACTS`: Deploys decoy `.rdp` saved connection profiles.
- `PLANT_DECOY_EMAIL_DATA`: Generates decoy `.pst` and `.eml` mail archives.
- `PLANT_DECOY_API_TOKENS`: Plants decoy API keys and bearer tokens in config paths.
- `PLANT_DECOY_CLOUD_CREDENTIALS`: Deploys AWS (`~/.aws/credentials`) and Azure credential lures.
- `PLANT_STARTUP_DECOY`: Generates decoy startup shortcuts.
- `PLANT_DECOY_DLL_TARGET`: Plants vulnerable/target DLL binaries for sideloading.
- `PLANT_DECOY_LOGON_ARTIFACT`: Configures logon script triggers with benign decoys.
- `PLANT_DECOY_COM_ARTIFACT`: Deploys simulated COM object registry keys.
- `PLANT_DECOY_FINANCIAL_DATA`: Deploys synthetic payroll and accounting spreadsheets.
- `PLANT_DECOY_ARCHIVES`: Deploys passworded and unpassworded `.zip`/`.7z` archives.
- `SYNTHESIZE_DECOY_DATABASE`: Instantiates SQLite / local database lures.
- `PLANT_DECOY_SOURCE_REPOSITORY`: Generates mock git repositories with dummy source code.
- `PLANT_DECOY_CLOUD_CONFIG`: Deploys Terraform and Docker configurations.
- `CREATE_DECOY_RECOVERY_TARGET`: Deploys mock backup files and simulated volume shadow targets to satisfy ransomware deletion checks without losing system state.

### Registry & Environmental Identity Deception
- `SPAWN_FAKE_DC_ARTIFACTS`: Injects Domain Controller registry parameters (`Domain=CORP.LOCAL`), DNS host mappings, and SYSVOL file structures.
- `SIMULATE_AV_PRESENCE`: Injects Windows Defender / Antivirus active product status flags.
- `SPOOF_HARDWARE_IDENTITY`: Rewrites System and Video BIOS strings to physical hardware signatures (Dell / American Megatrends / NVIDIA).
- `HIDE_VM_ARTIFACTS`: Masks hypervisor-specific registry keys and drivers.
- `SPOOF_HOST_IDENTITY`: Alters hostname registry keys to match enterprise naming schemes.
- `SPOOF_DOMAIN_MEMBERSHIP`: Configures domain membership workstation registry values.
- `SYNTHESIZE_SOFTWARE_INVENTORY`: Populates Add/Remove Programs uninstall registry hives with standard enterprise software.
- `SPOOF_SECURITY_CONFIGURATION`: Emulates enterprise Group Policy and security configuration states.
- `SPOOF_FIREWALL_STATE`: Sets firewall state flags to indicate active filtering.
- `SIMULATE_AMSI_TARGET`: Configures AMSI provider registry hooks.
- `SIMULATE_SECURITY_CONFIGURATION`: Emulates active Defender real-time monitoring and exclusion flags.
- `SPOOF_PARENT_PROCESS`: Alters parent process telemetry cues for evasive malware.
- `SPOOF_DEBUGGER_STATE`: Emulates standard non-debugged environment state (`BeingDebugged=0`).
- `HIDE_ANALYSIS_ARTIFACTS`: Hides monitoring binaries from process lists.
- `TRIGGER_USER_SIMULATION`: Triggers realistic mouse movements, cursor positions, and keystroke dwelling.
- `NORMALIZE_TIMING`: Normalizes RDTSC / hardware timer ticks to counteract timing-based anti-sandbox checks.
- `SYNTHESIZE_USER_PROFILE`: Injects standard enterprise user documents and profile artifacts.
- `SYNTHESIZE_VPN_PROFILE`: Injects OpenVPN / Cisco AnyConnect client configs.

### Network & Infrastructure Deception
- `MOUNT_FAKE_NETWORK_SHARE`: Creates mock SMB share paths with confidential document lures.
- `SYNTHESIZE_NETWORK_TOPOLOGY`: Populates ARP tables, routing tables, and simulated LAN hosts.
- `SYNTHESIZE_RDP_TARGETS`: Emulates reachable RDP servers.
- `SYNTHESIZE_REMOTE_HOSTS`: Emulates reachable WinRM / SSH servers.
- `SYNTHESIZE_DOMAIN_TOPOLOGY`: Emulates enterprise Active Directory tree structures.
- `FABRICATE_C2_RESPONSE`: Synthesizes dynamic HTTP/S responses simulating active C2 tasking.
- `ACTIVATE_C2_SINKHOLE`: Redirects external network connections to local telemetry sinkholes.

### Process Deception
- `SPAWN_DECOY_PROCESSES`: Launches realistic benign background processes (e.g. `chrome.exe`, `excel.exe`).
- `SPAWN_DECOY_SERVICES`: Registers simulated background Windows services.

---

## 2. Observation-Preserving Mutations (`MEASUREMENT`)

- `ACTIVATE_EPT_MEMORY_CAPTURE`: Triggers EPT-level dirty-page tracking to dump newly unpacked memory regions.
- `ENABLE_PROCESS_TRACKING`: Attaches deep kernel telemetry to new process trees.
- `ENABLE_FILE_ACTIVITY_MONITOR`: Increases file system ETW / Minifilter telemetry granularity on active target folders.
- `PRESERVE_FORENSIC_ARTIFACT`: Backs up binary and dropped staging payloads before self-deletion or cleanup.
- `ENABLE_NETWORK_CAPTURE`: Initiates full-packet capture on active sockets.
- `EXTEND_CAPTURE_WINDOW`: Extends detonation timeout when active progressive activity is observed.
- `ENABLE_STAGE_TRACKING`: Attaches correlation IDs to multi-stage downstream loaders.
- `ACTIVATE_MEMORY_MONITOR`: Activates real-time tracking on RWX memory allocations.
- `ACTIVATE_EPT_SHADOW_HOOK`: Installs transparent shadow page hooks on sensitive API transition points.
- `ACTIVATE_FILE_SYSTEM_SNAPSHOT`: Creates an instant snapshot of disk sectors before mass encryption.
