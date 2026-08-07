"""
adam/orchestrator/session.py

SessionOrchestrator -- ARCHITECTURE.md section 6.1 (session lifecycle) and
section 8.4's bus subscription map ("Orchestrator | SessionLifecycle |
all"). Ties SandboxController, the collectors, and EventBus together into
one coordinated run: prepare -> arm -> detonate -> collect -> teardown,
producing a populated `artifacts/<session_id>/raw.jsonl` and a final
AnalysisSession. docs/dev-a-environment-and-roadmap.md Phase 8.

This module coordinates existing components; it does not reimplement any
of them. It calls SandboxController's already-tested methods, drains
already-tested BaseCollector subclasses via iter_events(), and publishes
onto an already-tested EventBus. Its own job is purely: ordering, the
collector-to-bus/persistence bridge the roadmap calls out explicitly (see
below), and guaranteed cleanup.

Step order matches the project's own stated Phase 8 execution model
exactly (config load/validate happens before this is ever called --
Settings() itself fails fast on construction per Milestone 4 -- so this
method starts from an already-validated `config: Settings`):

    3-5. controller.prepare()          (COLD -> RESTORING -> BOOTING -> READY,
                                         one call, per SandboxController's
                                         own design)
    6.   bus.start()
    7.   collector.start() for each collector, then spawn one pump task per
         collector (see _pump() below)
    8.   controller.arm(host_sample_path, guest_target_path)
    9.   controller.detonate(sample)
    10-11. (continuous, running in the background since step 7) each pump
         task drains its collector's iter_events(), writes every RawEvent to
         raw.jsonl FIRST, then publishes it onto the bus -- see _pump()'s
         docstring for why that order, not the reverse.
    12.  collector.stop() for each collector (lets each pump task's
         iter_events() drain the last buffered events and return)
    13.  bus.drain(timeout)
    14.  controller.teardown()
    15.  build and return AnalysisSession
    16.  guaranteed via one try/except/finally wrapping steps 3-14 -- see
         run_session()'s own docstring for the FAILED vs PARTIAL vs ABORTED
         distinction.

Collector-to-bus bridging (roadmap's own words, Phase 2 file list note):
"each collector's iter_events() yields RawEvents that get published onto
the bus by a thin wrapper in the orchestrator (Phase 8), not by the
collector itself calling bus.publish() directly, so collectors stay
unit-testable without a live bus." That thin wrapper is `_pump()` below.

Host-path gap, disclosed. The roadmap's own `SessionOrchestrator.run_session
(self, sample: SampleRef, config: Settings) -> AnalysisSession` signature
does not carry a host-side path to the sample file (`SampleRef` only has
sha256/md5/filename/size_bytes/file_type -- see adam/contracts/session.py),
but `SandboxController.arm()` needs a real host filesystem path to copy
from. This is the same category of gap already disclosed for `detonate()`
before Phase 2 existed (docs/implementation-audit.md, Phase 4 Deviations).
Resolved here with an explicit, required `host_sample_path` keyword-only
parameter on `run_session()` -- the CLI layer (adam/cli/run.py) has this
path directly from its own command-line argument, so this is a minimal,
necessary, disclosed deviation from the roadmap's literal two-argument
signature, not a guess at unspecified architecture.

Guest-telemetry-source gap -- RESOLVED (Phase 5). SysmonCollector/
ProcmonCollector/NetworkCollector each tail a HOST-side file path (an EVTX
file, a CSV export, a tshark -T ek export). Originally closed by
adam.sandbox.guest.agent.agent.GuestAgent (a host-orchestrated
VBoxManage-guestcontrol automation) via an optional `guest_agent`
constructor parameter that drives Procmon/tshark capture around detonate()
and exports Sysmon/Procmon/tshark telemetry to real host paths afterward,
from which this class builds and runs collectors automatically -- see
run_session()'s own step-by-step comments below for exactly where.

Phase 5 revision -- GuestChannel interface. The constructor parameter is
now typed `GuestChannel | None` (adam/sandbox/guest/channel.py), not
`GuestAgent | None` -- SessionOrchestrator calls only the three methods
that Protocol defines (verify_tools/start_captures/stop_export_and_fetch)
and does not know or care whether the concrete object passed in is
VBoxGuestChannel (wrapping the original, untouched GuestAgent) or
HTTPGuestChannel (talking to the guest-resident PowerShell HTTP agent) --
Runner (adam/orchestrator/runner.py) decides which one to construct, based
on `Settings.guest_backend`. The parameter name stays `guest_agent` for
backward compatibility with every existing caller/test that already
constructs a SessionOrchestrator with this keyword; only its accepted
type widened. SessionOrchestrator still does not duplicate the backend's
own work, and still reuses the exact same collector classes and _pump()
bridge as the pre-existing, constructor-injected `collectors` path,
unchanged. `guest_agent=None` (the default) preserves this class's
original behavior byte-for-byte, so every existing offline verification
scenario built against constructor-injected FakeCollectors continues to
exercise the same code path it always has.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from adam.collectors.base import BaseCollector
from adam.collectors.network import NetworkCollector
from adam.collectors.procmon import ProcmonCollector
from adam.collectors.sysmon import SysmonCollector
from adam.common.bus import EventBus
from adam.common.config import Settings
from adam.contracts.enums import Arm, NetworkMode, SessionStatus
from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.orchestrator.persistence import RawEventWriter
from adam.sandbox.controller import SandboxController
from adam.sandbox.guest.channel import GuestChannel, TelemetryArtifacts

logger = logging.getLogger(__name__)


def build_collectors_from_telemetry(session_id: str, artifacts: TelemetryArtifacts) -> list[BaseCollector]:
    """
    Step 10 of the Phase 5 guest-agent lifecycle: construct whichever
    concrete collectors have a real, exported host path to tail. Mirrors
    adam.orchestrator.runner.Runner._build_collectors()'s "only construct a
    collector if its path is not None" rule exactly -- that method now
    delegates here instead of duplicating the logic, so a CLI-override path
    and a GuestAgent-exported path are wired into a collector identically.
    Kept in this module (not runner.py) so SessionOrchestrator can call it
    directly once GuestAgent.stop_export_and_fetch() returns, mid-session,
    without runner.py needing visibility into a decision it isn't present
    for.
    """
    collectors: list[BaseCollector] = []
    if artifacts.sysmon_evtx_path is not None:
        collectors.append(SysmonCollector(artifacts.sysmon_evtx_path, session_id=session_id))
    if artifacts.procmon_csv_path is not None:
        collectors.append(ProcmonCollector(artifacts.procmon_csv_path, session_id=session_id))
    if artifacts.network_ek_json_path is not None:
        collectors.append(NetworkCollector(artifacts.network_ek_json_path, session_id=session_id))
    return collectors


def new_session_id() -> str:
    """
    Temporary session-ID generator, same disclosed-placeholder status as
    the `uuid.uuid4()`-based IDs in adam/collectors/parsers/evtx.py and
    pml.py: adam/common/ids.py (a real new_id(prefix) generator) does not
    exist yet (tracked in docs/remaining-work-plan.md). Formatted to match
    ARCHITECTURE.md section 7.1's own example style (`sess_YYYY_MM_DD_xxxx`)
    for readability in artifact directory names and logs.
    """
    now = datetime.now(timezone.utc)
    return f"sess_{now:%Y_%m_%d}_{uuid.uuid4().hex[:8]}"


class SessionOrchestrator:
    """
    Coordinates one SandboxController, one EventBus, and a fixed set of
    already-constructed collectors through a full session. See module
    docstring for the exact step order and the two disclosed gaps
    (host_sample_path, guest-side collector sourcing) this class does not
    attempt to solve.
    """

    def __init__(
        self,
        controller: SandboxController,
        bus: EventBus,
        collectors: Sequence[BaseCollector],
        *,
        artifacts_dir: str | Path = "artifacts",
        guest_target_path_template: str = "C:\\ADAM\\samples\\{filename}",
        bus_drain_timeout: float = 5.0,
        post_detonation_drain_seconds: float = 0.5,
        guest_agent: GuestChannel | None = None,
    ) -> None:
        self._controller = controller
        self._bus = bus
        self._collectors = list(collectors)
        self._artifacts_dir = Path(artifacts_dir)
        self._guest_target_path_template = guest_target_path_template
        self._bus_drain_timeout = bus_drain_timeout
        self._post_detonation_drain_seconds = post_detonation_drain_seconds
        # Phase 5 addition. None (the default) preserves this class's
        # pre-Phase-5 behavior exactly -- see module docstring's
        # "Guest-telemetry-source gap -- RESOLVED" note.
        self._guest_agent = guest_agent

    def _guest_target_path_for(self, sample: SampleRef) -> str:
        return self._guest_target_path_template.format(filename=sample.filename)

    async def _publish_lifecycle(self, session_id: str, status: SessionStatus, detail: str) -> None:
        lifecycle = SessionLifecycle(
            session_id=session_id, status=status, detail=detail, occurred_at=datetime.now(timezone.utc)
        )
        envelope: Envelope[SessionLifecycle] = Envelope(
            message_id=f"msg_{uuid.uuid4().hex}",
            message_type="SessionLifecycle",
            session_id=session_id,
            correlation_id=session_id,
            emitted_at=datetime.now(timezone.utc),
            emitter="orchestrator.session",
            payload=lifecycle,
        )
        try:
            await self._bus.publish(envelope)
        except Exception:
            logger.exception("failed to publish SessionLifecycle(%s) for session=%s", status.value, session_id)

    async def _pump(self, collector: BaseCollector, session_id: str, writer: RawEventWriter) -> None:
        """
        The "thin wrapper" the roadmap's Phase 2 notes describe: drains one
        collector's iter_events() for the lifetime of the session.

        Writes to raw.jsonl BEFORE publishing to the bus, deliberately: per
        ADR-005 and persistence.py's own module docstring, raw.jsonl is the
        authoritative record and must not be affected by the bus's lossy
        drop-under-backpressure delivery (section 8.2/8.3) -- if publishing
        raced ahead of persisting, a dropped bus message would have no
        bearing on durability, but the reverse ordering keeps that
        guarantee true by construction rather than by coincidence.

        correlation_id policy: since Fusion (which would normally assign a
        shared correlation_id across a cluster of related raw events) does
        not exist yet, each RawEvent's own event_id is used as its
        correlation_id -- every event starts as its own correlation chain,
        joinable later. Disclosed placeholder, not a claim this is Fusion's
        real correlation logic.
        """
        async for event in collector.iter_events():
            try:
                await writer.write(event)
            except Exception:
                logger.exception(
                    "session=%s collector=%s failed to persist RawEvent -- event lost",
                    session_id,
                    collector.source_name,
                )
                continue

            envelope: Envelope[RawEvent] = Envelope(
                message_id=f"msg_{uuid.uuid4().hex}",
                message_type="RawEvent",
                session_id=session_id,
                correlation_id=event.event_id,
                emitted_at=datetime.now(timezone.utc),
                emitter=f"collector.{collector.source_name}",
                payload=event,
            )
            try:
                await self._bus.publish(envelope)
            except Exception:
                logger.exception(
                    "session=%s collector=%s failed to publish RawEvent onto bus (already durable in raw.jsonl)",
                    session_id,
                    collector.source_name,
                )

    async def run_session(
        self,
        sample: SampleRef,
        config: Settings,
        *,
        host_sample_path: str,
        session_id: str | None = None,
        experiment_id: str = "adhoc",
        arm: Arm = Arm.CONTROL,
        sample_timeout_seconds: int = 300,
    ) -> AnalysisSession:
        """
        Runs one full session. See module docstring for step order.

        `session_id`: normally left as None, in which case a fresh ID is
        generated internally (new_session_id()). Accepted as an explicit
        override because the injected `collectors` were already
        constructed with a `session_id` baked into their own constructor
        (SysmonCollector/ProcmonCollector/NetworkCollector all tag every
        RawEvent they produce with the session_id they were built with) --
        a caller building collectors ahead of time (see runner.py) must
        generate the ID first via new_session_id(), pass it to both the
        collectors' constructors and here, so every RawEvent's
        `session_id` field and this session's own `session_id` agree. If
        left None, the auto-generated ID obviously won't match whatever
        (if anything) was baked into already-constructed collectors --
        the caller's responsibility to keep these consistent when
        pre-building collectors, same as any other dependency-injected
        component.

        Status/error semantics on the returned AnalysisSession:
          - COMPLETED: every step succeeded.
          - FAILED: something failed before collectors were ever started
            (prepare() itself, or bus.start()) -- no telemetry could
            possibly have been captured, so there is nothing "partial"
            about the result.
          - PARTIAL: something failed after collectors were started
            (arm(), detonate(), or anything else mid-session) --
            ARCHITECTURE.md section 14.4: "A session that errored still
            produces a report -- marked PARTIAL. Partial results are still
            evidence." Whatever raw.jsonl accumulated before the failure
            is retained.
          - ABORTED: the session was cancelled (Ctrl-C / task
            cancellation). Deliberately NOT re-raised as CancelledError --
            see the try/except below for why this method's contract is to
            always return a well-formed AnalysisSession, including on
            cancellation, matching this project's requirement that a
            session "exit cleanly even if failures occur."

        teardown() is called unconditionally in the finally block and never
        raises (SandboxController's own guarantee, section 14.4) -- the VM
        is restored to `clean` regardless of what happened above it.

        Phase 5 (guest_agent, constructor parameter): when supplied, this
        method additionally starts Procmon/tshark captures after arm() and,
        after detonate() completes, stops those captures, exports Sysmon/
        Procmon/tshark telemetry, copies it to the host, and automatically
        builds+starts the matching collectors -- see the inline comments
        around arm()/detonate() below for exactly where. A source already
        covered by a constructor-injected collector (the pre-Phase-5 CLI-
        override path) is never re-captured. `collectors_started` (and
        therefore the PARTIAL-vs-FAILED distinction above) is set True by
        either path, whichever starts a collector first.
        """
        if session_id is None:
            session_id = new_session_id()
        started_at = datetime.now(timezone.utc)
        guest_target_path = self._guest_target_path_for(sample)

        session_config = SessionConfig(
            deception_enabled=False,  # Deception Engine (section 5.6, Dev C) does not exist yet
            policy_ruleset="none",  # Policy Engine (section 5.5, Dev C) does not exist yet
            vm_profile=config.sandbox.vm_name,  # VMProfile/profiles.py does not exist yet -- vm_name stands in, disclosed
            timeout_seconds=sample_timeout_seconds,
            network_mode=NetworkMode.HOST_ONLY,  # not yet a real SandboxSettings field -- safest disclosed default
        )

        artifact_path = self._artifacts_dir / session_id / "raw.jsonl"
        writer = RawEventWriter(artifact_path)

        status = SessionStatus.PENDING
        error: str | None = None
        collectors_started = False
        pump_tasks: list[asyncio.Task[None]] = []
        # Phase 5: collectors GuestAgent builds AFTER detonate() (once
        # telemetry has actually been exported to real host paths), kept
        # separate from self._collectors/pump_tasks above -- which remain
        # exactly the pre-Phase-5 constructor-injected, started-before-
        # detonate path -- and merged with them only in the finally block's
        # stop/await loops below, so neither path's own logic changes.
        guest_collectors: list[BaseCollector] = []
        guest_pump_tasks: list[asyncio.Task[None]] = []

        await writer.open()
        await self._publish_lifecycle(session_id, status, "session created")

        try:
            status = SessionStatus.PREPARING
            await self._publish_lifecycle(session_id, status, "restoring snapshot and booting guest")
            await self._controller.prepare()

            await self._bus.start()

            for collector in self._collectors:
                await collector.start()
                # Set True as soon as the FIRST collector starts, not only
                # after the whole loop succeeds: if a later collector's
                # start() raises, the ones that already started may have
                # captured something real, so the failure must still be
                # classified PARTIAL, not FAILED. stop() in the finally
                # block below is safe to call on every collector regardless
                # (BaseCollector.stop() is a no-op if the collector's task
                # was never created).
                collectors_started = True
                # Pump task spawned immediately after each collector starts,
                # not batched after the whole loop: if a LATER collector's
                # start() raises, this one's already-buffered events must
                # still get drained and persisted, not silently lost.
                pump_tasks.append(
                    asyncio.create_task(
                        self._pump(collector, session_id, writer),
                        name=f"adam.orchestrator.pump.{collector.source_name}",
                    )
                )

            await self._controller.arm(host_sample_path, guest_target_path)

            # Diagnostics addition: verify_tools() is a pre-existing public
            # GuestAgent method that was previously never actually called
            # by this class -- its up-front tool-availability and guest-
            # workspace-directory diagnostics therefore never ran on a real
            # session. Calling it here (no interface change, no new
            # method -- just a call-site addition) is what makes those
            # diagnostics actually appear in a real run's logs. Guarded the
            # same defense-in-depth way as every other guest_agent call in
            # this method, even though GuestAgent's own methods are
            # documented to never raise.
            if self._guest_agent is not None:
                try:
                    await self._guest_agent.verify_tools()
                except Exception:
                    logger.exception(
                        "session=%s guest_agent.verify_tools raised unexpectedly -- continuing anyway",
                        session_id,
                    )

            # Phase 5, steps 2-3: start Procmon/tshark captures inside the
            # guest, detached, before the sample runs. Sources already
            # covered by a constructor-injected collector (a CLI override
            # path -- see adam/orchestrator/runner.py) are skipped so
            # GuestAgent never captures something that would just be
            # discarded in favor of the override.
            if self._guest_agent is not None:
                overridden_sources = {c.source_name for c in self._collectors}
                try:
                    await self._guest_agent.start_captures(
                        session_id,
                        capture_procmon="procmon" not in overridden_sources,
                        capture_network="network" not in overridden_sources,
                    )
                except Exception:
                    # GuestAgent's own methods are documented to never raise
                    # (partial-telemetry guarantee) -- guarded anyway, same
                    # defense-in-depth convention as teardown()/
                    # _publish_lifecycle() elsewhere in this method.
                    logger.exception(
                        "session=%s guest_agent.start_captures raised unexpectedly -- "
                        "continuing detonation without guest-driven captures",
                        session_id,
                    )

            status = SessionStatus.RUNNING
            await self._publish_lifecycle(session_id, status, "detonating sample")
            await self._controller.detonate(sample)

            # Give constructor-injected collectors a short grace period to
            # pick up trailing telemetry (e.g. process-exit events) before
            # stop() cuts them off in the finally block below. Not used by
            # guest-driven collectors below -- those don't exist yet at
            # this point, and get their own, separate grace sleep once
            # they're started.
            await asyncio.sleep(self._post_detonation_drain_seconds)

            # Phase 5, steps 6-10: stop captures, export telemetry in-guest,
            # copy it to the host artifact directory, and automatically
            # build+start the matching collectors -- no CLI arguments
            # required (this phase's own stated goal). Sources already
            # covered by a CLI override are skipped, same reasoning as
            # start_captures() above.
            if self._guest_agent is not None:
                overridden_sources = {c.source_name for c in self._collectors}
                try:
                    artifacts = await self._guest_agent.stop_export_and_fetch(
                        session_id,
                        self._artifacts_dir / session_id,
                        export_sysmon="sysmon" not in overridden_sources,
                        export_procmon="procmon" not in overridden_sources,
                        export_network="network" not in overridden_sources,
                    )
                except Exception:
                    logger.exception(
                        "session=%s guest_agent.stop_export_and_fetch raised unexpectedly -- "
                        "no guest-driven telemetry available this session",
                        session_id,
                    )
                    artifacts = TelemetryArtifacts()

                guest_collectors = build_collectors_from_telemetry(session_id, artifacts)
                for collector in guest_collectors:
                    await collector.start()
                    collectors_started = True  # same reasoning as the constructor-injected loop above
                    guest_pump_tasks.append(
                        asyncio.create_task(
                            self._pump(collector, session_id, writer),
                            name=f"adam.orchestrator.pump.{collector.source_name}",
                        )
                    )

                if guest_collectors:
                    # The exported files are already complete and static by
                    # this point -- this sleep only needs to cover one poll
                    # cycle (each collector's default poll_interval is
                    # 0.1s) so the first (and only) poll ingests everything,
                    # not a live-tailing grace period the way the sleep
                    # above is for the constructor-injected path.
                    await asyncio.sleep(self._post_detonation_drain_seconds)

            status = SessionStatus.COMPLETED

        except asyncio.CancelledError:
            status = SessionStatus.ABORTED
            error = "session cancelled (Ctrl-C / task cancellation)"
            logger.warning("session=%s cancelled", session_id)
        except Exception as exc:
            status = SessionStatus.PARTIAL if collectors_started else SessionStatus.FAILED
            error = f"{type(exc).__name__}: {exc}"
            logger.exception("session=%s failed during %s", session_id, status.value)
        finally:
            # self._collectors (constructor-injected, started before
            # detonate) and guest_collectors (Phase 5, started after
            # detonate/export/fetch -- empty if guest_agent is None or
            # produced no telemetry) are stopped and drained together here;
            # neither path's own start-up logic above needed to change.
            for collector in (*self._collectors, *guest_collectors):
                try:
                    await collector.stop()
                except Exception:
                    logger.exception("session=%s collector=%s failed to stop", session_id, collector.source_name)

            for task in (*pump_tasks, *guest_pump_tasks):
                try:
                    await task
                except Exception:
                    logger.exception("session=%s a pump task raised unexpectedly", session_id)

            # Published here, before drain() -- not after it, further down
            # this function -- specifically so a live subscriber still has
            # a running consumer task to actually receive it. drain()
            # cancels every consumer task once queues empty, so anything
            # published after that point would sit forever undelivered.
            await self._publish_lifecycle(session_id, status, error or "session finished")

            try:
                await self._bus.drain(timeout=self._bus_drain_timeout)
            except Exception:
                logger.exception("session=%s bus drain failed", session_id)

            # SandboxController.teardown() is documented to never raise
            # (ARCHITECTURE.md section 14.4) -- guarded anyway, defense in
            # depth, consistent with every other cleanup step above.
            try:
                await self._controller.teardown()
            except Exception:
                logger.exception("session=%s controller teardown raised unexpectedly", session_id)

            await writer.close()

        ended_at = datetime.now(timezone.utc)

        return AnalysisSession(
            session_id=session_id,
            experiment_id=experiment_id,
            arm=arm,
            sample=sample,
            config=session_config,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            metrics=SessionMetrics(raw_events=writer.count),
            error=error,
        )
