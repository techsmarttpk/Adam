# ADAM System: Known Limitations & Operational Boundaries

This document lists the known architectural and operational limitations of the ADAM automated malware analysis and dynamic deception system identified and audited during the Phase 1–4 verification cycle.

---

### 1. `FABRICATE_C2_RESPONSE` & `NETWORK`-Kind Mutations Unimplemented
- **Description**: The guest-resident HTTP agent (`adam_agent.ps1` / `HTTPGuestChannel`) executes mutations in-guest (filesystem, registry, processes) and does not implement kernel-level or network-stack packet redirection/interception. Any policy decision emitting `NETWORK`-kind operations (e.g. `FABRICATE_C2_RESPONSE`) fails fast with an explicit descriptive error.
- **Evidence**:
  ```text
  2026-08-23 18:38:28,832 WARNING adam.pipeline.wiring: [DeceptionEngine] decision=dec_7d8f9c45421c action=FABRICATE_C2_RESPONSE mutation=mut_2f6063c04d74 FAILED: apply_mutation: NETWORK kind operations are not implemented in HTTPGuestChannel (kind='NETWORK', operation='RESPOND', target='http://c2.baddomain.org/beacon'). Host-side network interception is required.
  ```

---

### 2. `PLANT_DECOY_DOCUMENTS` Syntax / Timeout via `apply_mutation_batch`
- **Description**: `apply_mutation_batch` generates composite `cmd.exe /c` compound commands (`if not exist ... mkdir ... & (echo ...) > ...`). When formatted by `Common.psm1` (`Invoke-NativeProcess`), inner quotes are escaped as `\"`. Because `cmd.exe` treats `\` as a path character rather than a quote escape, `cmd.exe` consistently fails with `rc=1` (`The filename, directory name, or volume label syntax is incorrect`) or occasionally stalls waiting on `stdin` (`TIMEOUT: process did not exit within 30s`). Both failure signatures stem from the same underlying `cmd.exe` argument parsing incompatibility.
- **Evidence**:
  ```text
  2026-08-23 18:38:30,261 WARNING adam.pipeline.wiring: [DeceptionEngine] decision=dec_0110702851f9 action=PLANT_DECOY_DOCUMENTS mutation=mut_2f49d8e127f8 FAILED: apply_mutation_batch failed (rc=1): The filename, directory name, or volume label syntax is incorrect.
  ```

---

### 3. Procmon & Tshark Telemetry Unavailable in Current Golden Image
- **Description**: The current golden guest snapshot (`disk-resized-36gb-c-drive`) does not have `Procmon64.exe` or `tshark.exe` installed at their expected locations (`C:\Users\Admin\Downloads\ProcessMonitor\Procmon64.exe` and `C:\Program Files\Wireshark\tshark.exe`). Sysmon (`Microsoft-Windows-Sysmon/Operational`) is currently the sole working live telemetry source.
- **Evidence**:
  ```text
  2026-08-23 17:58:23,505 WARNING adam.sandbox.guest.http_channel: guest_http: tool unavailable -- procmon: not found in guest at configured path 'C:\Users\Admin\Downloads\ProcessMonitor\Procmon64.exe'
  2026-08-23 17:58:23,505 WARNING adam.sandbox.guest.http_channel: guest_http: tool unavailable -- tshark: not found in guest at configured path 'C:\Program Files\Wireshark\tshark.exe'
  ```

---

### 4. Synthetic Nature of `/simulate` API and Benchmark CLI
- **Description**: The `/simulate` REST API routes and the `adam benchmark` CLI remain synthetic offline test harnesses that exercise policy and detection engines against static event traces, without orchestrating real VirtualBox VMs or guest agent detonation. This behavior is intentional and deferred out of scope for this live VM pipeline cycle.
- **Evidence**:
  ```text
  adam/cli/benchmark.py and adam/api/routes/simulate.py utilize offline fixture feeds and mock guest channels by design, bypassing SandboxController.prepare() and live VM execution.
  ```

