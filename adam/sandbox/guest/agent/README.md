# `adam/sandbox/guest/agent/`

This directory holds two conceptually different things that happen to share a name:

## `agent.py` — host-side, GuestControl-based (the "compatibility backend")

A Python class (`GuestAgent`) that runs **on the host**, driving VirtualBox's `VBoxManage
guestcontrol` to shell commands into the guest. Wrapped by `VBoxGuestChannel`
(`adam/sandbox/guest/vbox_channel.py`) to satisfy the `GuestChannel` interface
(`adam/sandbox/guest/channel.py`). Selected by `guest_backend = "vbox"` (the default) in
`config/default.toml`. Fully operational, kept as-is — see its own module docstring for its
extensive diagnostics/bug-fix history.

## `adam_agent.ps1` + `modules/*.psm1` — guest-resident (the target architecture)

A PowerShell 5.1 HTTP service that runs **inside the guest VM**, exposing the REST API
documented in `docs/phase5-http-agent-api.md`. Talked to from the host via `HTTPGuestChannel`
(`adam/sandbox/guest/http_channel.py`), selected by `guest_backend = "http"`.

This is not Python/FastAPI — see `docs/phase5-migration-guide.md` for why: ARCHITECTURE.md's
own constraint C4 ("The guest agent is PowerShell 5.1 compatible. No .NET Core assumption") rules
out installing a Python runtime into the guest image, so this implementation uses PowerShell
5.1's built-in `System.Net.HttpListener` instead.

**Deployment is separate from the host application.** Nothing under `modules/` or
`adam_agent.ps1` is imported by any Python code — copy this directory into the guest (or run
`install.ps1`, which does this for you) and register it as a Scheduled Task so it starts
automatically. See `install.ps1`'s own docstring for the one-time setup steps, and re-capture the
VM's `clean` snapshot afterward so the setup survives every session's snapshot restore.

**Not executed against a real Windows guest as part of the change that added this file** — no
Windows/PowerShell runtime was available in the environment that wrote it. Reviewed carefully
against documented PowerShell 5.1 / .NET Framework APIs, but treat it as unverified until run on
a real VM.

| | `agent.py` | `adam_agent.ps1` / `modules/` |
|---|---|---|
| Runs on | Host | Guest |
| Language | Python | PowerShell 5.1 |
| Talks to guest via | VBoxManage guestcontrol (shell) | — (it *is* the guest process) |
| Talked to from host via | `VBoxGuestChannel` | `HTTPGuestChannel` |
| Backend selector | `guest_backend = "vbox"` | `guest_backend = "http"` |
