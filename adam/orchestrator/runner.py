"""
adam/orchestrator/runner.py

Runner -- ARCHITECTURE.md Phase 8 ("Runner: CLI-facing entrypoint"). The
one place that wires SessionOrchestrator's real, production dependencies
together from Settings: a real VirtualBoxClient/SandboxController, a real
EventBus, and whichever concrete collectors the caller points at real,
host-accessible source files.

This module owns config loading (fail-fast: `get_settings()` -- or an
injected `Settings` -- validates via Pydantic before anything else
happens, per section 12.1/14.2's "refuse to start" category) and sample
hashing (building a real `SampleRef` from a file on disk). Everything else
is delegated to SessionOrchestrator, which owns the actual session logic
and is the thing exercised by adam/orchestrator/session.py's own offline
verification -- Runner itself is deliberately thin, since wiring real
components together is not independently interesting to unit-test the way
orchestration *logic* is (same reasoning
scripts/manual_test_sandbox_controller.py's `_new_controller()` helper is
thin and untested on its own, while SandboxController itself is heavily
tested).

Collector wiring, Phase 5 update. SysmonCollector/ProcmonCollector/
NetworkCollector each need a real, host-accessible source file path.
Before Phase 5, Runner had no way to produce one automatically and
accepted `sysmon_evtx_path`/`procmon_csv_path`/`network_ek_json_path` as
the only way to get a collector constructed at all -- running
`adam run <sample>` with none of these set was a "legitimate" session only
in the sense that it didn't crash; it always produced zero collectors and
an empty raw.jsonl.

Phase 5 (adam.sandbox.guest.agent.agent.GuestAgent) closes that gap:
Runner now always constructs a GuestAgent from `settings.guest_tools` and
passes it into SessionOrchestrator, which drives Procmon/tshark capture
and Sysmon/Procmon/tshark export automatically around detonate() -- see
adam/orchestrator/session.py's module docstring. The three keyword
arguments below remain, unchanged in meaning, but now serve their intended
purpose per this phase's own instruction: "existing CLI flags ... should
remain only as optional overrides for testing. Normal execution should
not require them." A source with an explicit override path here is passed
to SessionOrchestrator as a pre-built, constructor-injected collector
exactly as before Phase 5 (started before detonate, concurrently tailed);
GuestAgent is told (via SessionOrchestrator, by source_name) to skip
capturing/exporting that specific source, so the override is never
silently clobbered by a fresh capture.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from adam.collectors.base import BaseCollector
from adam.common.bus import EventBus
from adam.common.config import Settings, get_settings
from adam.contracts.session import AnalysisSession, SampleRef
from adam.orchestrator.session import SessionOrchestrator, build_collectors_from_telemetry, new_session_id
from adam.sandbox.controller import SandboxController
from adam.sandbox.guest.agent.agent import GuestAgent, TelemetryArtifacts
from adam.sandbox.guest.channel import GuestChannel
from adam.sandbox.guest.http_channel import HTTPGuestChannel
from adam.sandbox.guest.vbox_channel import VBoxGuestChannel
from adam.sandbox.vbox.client import VirtualBoxClient

logger = logging.getLogger(__name__)


def sample_ref_from_path(host_sample_path: str) -> SampleRef:
    """
    Builds a real SampleRef (genuine sha256/md5/size) from a file on disk.
    Same approach already proven in
    scripts/manual_test_sandbox_controller.py's `_sample_ref()` helper.
    """
    path = Path(host_sample_path)
    data = path.read_bytes()
    return SampleRef(
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        filename=path.name,
        size_bytes=len(data),
        file_type="PE32 executable",  # no real file-type sniffing yet -- disclosed placeholder
    )


class Runner:
    """
    CLI-facing entrypoint. See module docstring for scope. `settings`, if
    not provided, is loaded via `get_settings()` on first use of `run()` --
    not at Runner construction time, so a Runner can be constructed before
    deciding whether to supply an override (mainly for tests).
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings_override = settings

    def _resolve_settings(self) -> Settings:
        """
        Fail-fast config loading (ARCHITECTURE.md section 14.2's "refuse to
        start" category): Settings()/get_settings() raises
        pydantic.ValidationError immediately on invalid or missing
        configuration, before any VM operation is attempted. Not caught
        here -- letting it propagate, uncaught, IS the fail-fast behavior;
        catching and translating it into a clean CLI error message is
        adam/cli/run.py's job, not this method's.
        """
        return self._settings_override if self._settings_override is not None else get_settings()

    def _build_collectors(
        self,
        session_id: str,
        *,
        sysmon_evtx_path: str | None,
        procmon_csv_path: str | None,
        network_ek_json_path: str | None,
    ) -> list[BaseCollector]:
        """
        Builds collectors for whichever CLI-override paths were given.
        Delegates to adam.orchestrator.session.build_collectors_from_telemetry
        (the same function SessionOrchestrator calls for GuestAgent-exported
        paths) rather than duplicating the "only construct if not None"
        rule a second time -- see this module's docstring.
        """
        return build_collectors_from_telemetry(
            session_id,
            TelemetryArtifacts(
                sysmon_evtx_path=sysmon_evtx_path,
                procmon_csv_path=procmon_csv_path,
                network_ek_json_path=network_ek_json_path,
            ),
        )

    def _build_guest_channel(self, client: VirtualBoxClient, settings: Settings) -> GuestChannel:
        """
        Backend selection, driven entirely by `settings.guest_backend`
        (adam/common/config.py). This is the ONE place in the codebase
        that branches on which backend is active -- everywhere else
        (SessionOrchestrator, the collectors, the CLI) only ever sees a
        `GuestChannel`.

        "vbox" (default): wraps a freshly-constructed GuestAgent, sharing
        `client` with SandboxController exactly as before this Phase 5
        revision -- byte-for-byte the same object graph `run()` built
        previously, just behind the interface now.

        "http": constructs HTTPGuestChannel against
        `settings.http_guest`, talking to the guest-resident PowerShell
        agent instead of driving GuestControl. NOT YET VALIDATED against
        a real VM -- see docs/phase5-migration-guide.md.
        """
        if settings.guest_backend == "http":
            http_settings = settings.http_guest
            logger.info(
                "guest_backend=http -- using HTTPGuestChannel against %s", http_settings.base_url
            )
            return HTTPGuestChannel(
                http_settings.base_url,
                capture_dir=http_settings.capture_dir,
                procmon_path=http_settings.procmon_path,
                tshark_path=http_settings.tshark_path,
                sysmon_log=http_settings.sysmon_log,
                tshark_interface=http_settings.tshark_interface,
                request_timeout_s=http_settings.request_timeout_s,
                # Same setting SandboxController already uses for VM-level
                # wait_for_guest_ready() (see the `controller = ...`
                # construction below, in run()) -- reused here, not
                # duplicated as a second config field, so
                # HTTPGuestChannel.wait_until_ready()'s HTTP-level
                # readiness poll shares one timeout budget concept with
                # the VM-level one it always runs after.
                guest_ready_timeout_s=settings.sandbox.guest_ready_timeout_s,
            )

        logger.info("guest_backend=vbox -- using VBoxGuestChannel (compatibility backend)")
        guest_agent = GuestAgent(
            client,
            settings.sandbox.vm_name,
            guest_username=settings.sandbox.guest_username,
            guest_password=settings.sandbox.guest_password,
            settings=settings.guest_tools,
        )
        return VBoxGuestChannel(guest_agent)

    async def run(
        self,
        host_sample_path: str,
        *,
        sysmon_evtx_path: str | None = None,
        procmon_csv_path: str | None = None,
        network_ek_json_path: str | None = None,
        artifacts_dir: str | Path = "artifacts",
    ) -> AnalysisSession:
        """
        Loads (and thereby validates -- fail-fast) Settings, builds the
        real production SandboxController/EventBus/GuestAgent/collectors,
        and runs one full session via SessionOrchestrator.run_session().
        See module docstring for how CLI-override paths and GuestAgent's
        automatic capture now divide the three telemetry sources between
        them (Phase 5).
        """
        settings = self._resolve_settings()
        sample = sample_ref_from_path(host_sample_path)
        session_id = new_session_id()

        collectors = self._build_collectors(
            session_id,
            sysmon_evtx_path=sysmon_evtx_path,
            procmon_csv_path=procmon_csv_path,
            network_ek_json_path=network_ek_json_path,
        )
        logger.info(
            "session=%s starting with %d CLI-override collector(s): %s",
            session_id,
            len(collectors),
            [c.source_name for c in collectors],
        )

        client = VirtualBoxClient()
        controller = SandboxController(
            client,
            settings.sandbox.vm_name,
            snapshot_name=settings.sandbox.snapshot_name,
            guest_username=settings.sandbox.guest_username,
            guest_password=settings.sandbox.guest_password,
            boot_timeout=settings.sandbox.boot_timeout_s,
            guest_ready_timeout=settings.sandbox.guest_ready_timeout_s,
        )
        bus = EventBus()

        # Phase 5: always constructed, sharing the same VirtualBoxClient
        # instance controller uses (not a second, duplicate one) -- see
        # module docstring for how SessionOrchestrator skips capturing/
        # exporting any source already covered by a collector in
        # `collectors` above. Which concrete GuestChannel gets built is
        # the one decision this method makes on Settings.guest_backend's
        # behalf -- SessionOrchestrator itself never sees this setting,
        # only the resulting GuestChannel object (adam/sandbox/guest/
        # channel.py's whole reason for existing).
        guest_channel = self._build_guest_channel(client, settings)

        orchestrator = SessionOrchestrator(
            controller, bus, collectors, artifacts_dir=artifacts_dir, guest_agent=guest_channel
        )

        return await orchestrator.run_session(
            sample,
            settings,
            host_sample_path=host_sample_path,
            session_id=session_id,
        )
