# Implementation Plan: Continuous Stealth Telemetry Sandbox

We are transitioning the sandbox architecture to run in a continuous, triggerless, and network-stealthy mode. Malware analysis logs will stream out-of-band via QEMU VirtIO-Serial interfaces, bypassing guest network monitoring.

## Proposed Changes

### Configuration
* Add `use_virtio_serial` and `serial_pipe_name` settings to [default.toml](file:///c:/ADAM_Sandbox/Adam/config/default.toml) and [config.py](file:///c:/ADAM_Sandbox/Adam/adam/common/config.py).

### Guest Agent
* Modify [adam_agent.ps1](file:///c:/ADAM_Sandbox/Adam/adam/sandbox/guest/agent/adam_agent.ps1) to continuously write JSON logs to the serial character device `\\.\Global\adam_stealth_port` instead of pushing them via HTTP.

### Host named pipe receiver
* Create a background serial daemon `adam/orchestrator/serial_listener.py` to read logs from the host named pipe (`\\.\pipe\adam_telemetry`) and feed them into the event bus.

### Orchestrator & API Integration
* Modify [main.py](file:///c:/ADAM_Sandbox/Adam/adam/api/main.py) to spin up the Named Pipe listener and initialize the default persistent `sess_continuous_live` session upon server boot.

## Verification Plan

### Automated Tests
* Test serial parsing via mock pipe client.

### Manual Verification
* Boot guest QEMU VM manually with serial port bindings.
* Verify guest agent logs are read via serial pipe and stream directly to the local dashboard.
