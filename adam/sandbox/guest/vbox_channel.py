"""
adam/sandbox/guest/vbox_channel.py

VBoxGuestChannel -- the "compatibility backend" GuestChannel implementation.
Wraps the existing, UNMODIFIED GuestAgent (adam/sandbox/guest/agent/agent.py,
VirtualBox GuestControl-based) behind the GuestChannel interface
(adam/sandbox/guest/channel.py) via plain composition/delegation.

This class is deliberately thin -- three one-line forwarding calls and
nothing else. It exists only so Runner can construct a GuestChannel without
depending on which concrete backend it is (see channel.py's own docstring
for why this matters), while GuestAgent itself stays completely untouched:
no method added, no signature changed, no behavior altered. Every
diagnostic, guarantee, and known issue documented in agent.py's own module
docstring (instrumentation, Bug #1-#4/Issue #1-#3 fixes, the filtered-token
"Known Issues" section) applies unchanged to sessions routed through this
wrapper.

Selected by default (`guest_backend = "vbox"` in config/default.toml) and
remains fully supported -- ARCHITECTURE.md's migration plan for this phase
is explicit that this backend is kept operational, not deprecated, until
HTTPGuestChannel (http_channel.py) reaches feature parity against a real
VM.
"""

from __future__ import annotations

from pathlib import Path

from adam.sandbox.guest.agent.agent import GuestAgent, TelemetryArtifacts, ToolAvailability


class VBoxGuestChannel:
    """GuestChannel backend delegating every call, unmodified, to a wrapped GuestAgent instance."""

    def __init__(self, guest_agent: GuestAgent) -> None:
        self._guest_agent = guest_agent

    async def verify_tools(self) -> ToolAvailability:
        return await self._guest_agent.verify_tools()

    async def start_captures(
        self,
        session_id: str,
        *,
        capture_procmon: bool = True,
        capture_network: bool = True,
    ) -> None:
        await self._guest_agent.start_captures(
            session_id, capture_procmon=capture_procmon, capture_network=capture_network
        )

    async def stop_export_and_fetch(
        self,
        session_id: str,
        host_artifact_dir: str | Path,
        *,
        export_sysmon: bool = True,
        export_procmon: bool = True,
        export_network: bool = True,
    ) -> TelemetryArtifacts:
        return await self._guest_agent.stop_export_and_fetch(
            session_id,
            host_artifact_dir,
            export_sysmon=export_sysmon,
            export_procmon=export_procmon,
            export_network=export_network,
        )
