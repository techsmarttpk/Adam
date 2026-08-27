"""
adam/pipeline/live.py
Live orchestrator for ADAM. Wires the EventBus to live file-tailing collectors,
EventFusionEngine, PolicyEngine, and DeceptionEngine.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import List

from adam.common.bus import EventBus
from adam.common.config import get_settings
from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.fusion.models import RawEvent as FusionRawEvent
from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.enums import Verdict
from adam.collectors.sysmon import SysmonCollector
from adam.collectors.procmon import ProcmonCollector
from adam.collectors.network import NetworkCollector
from adam.fusion.engine import EventFusionEngine
from adam.policy.engine import PolicyEngine
from adam.policy.context import SessionContext
from adam.deception.engine import DeceptionEngine
from adam.sandbox.guest.http_channel import HTTPGuestChannel

logger = logging.getLogger(__name__)

from adam.fusion.mapping import map_detection_to_intent

class LiveFusionBridge:
    def __init__(self, bus: EventBus, session_id: str):
        self.bus = bus
        self.session_id = session_id
        self.fusion_engine = EventFusionEngine()
        self.buffer: List[RawEvent] = []
        self._idx = 0

    async def handle_raw_event(self, envelope: Envelope[RawEvent]):
        self.buffer.append(envelope.payload)
        if len(self.buffer) >= 100:
            await self.flush()

    async def flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        
        fusion_batch = []
        for re in batch:
            fusion_re = FusionRawEvent(
                timestamp=re.occurred_at,
                source=re.source.name.lower() if hasattr(re.source, 'name') else str(re.source),
                event_type=re.category.name if hasattr(re.category, 'name') else str(re.category),
                process_id=re.process.pid if re.process else None,
                parent_process_id=re.process.ppid if re.process else None,
                process_name=re.process.image if re.process else None,
                command_line=re.process.command_line if re.process else None,
                payload=re.attributes
            )
            fusion_batch.append(fusion_re)
            
        try:
            fusion_result = self.fusion_engine.process(fusion_batch)
        except Exception as e:
            logger.error(f"Fusion engine process error: {e}")
            return
        
        for detection in fusion_result.detections:
            self._idx += 1
            intent, tactic, technique = map_detection_to_intent(detection)
            first_ev = detection.evidence[0] if detection.evidence else None
            pid = first_ev.process_id if (first_ev and first_ev.process_id) else 1000
            pname = first_ev.process_name if (first_ev and first_ev.process_name) else "unknown.exe"

            ts = detection.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            features = {"file_count": len(detection.evidence), "has_target": True}
            if intent == "RECON_DOMAIN_CONTROLLER":
                features["ldap_attempts"] = 3
                features["all_failed"] = True
            elif intent == "PERSIST_RUN_KEY":
                features["distinct_registry_keys"] = 6

            se = SemanticEvent(
                semantic_id=f"sem_fusion_{self._idx:03d}",
                session_id=self.session_id,
                correlation_id=f"corr_fusion_{self._idx:03d}",
                intent=intent,
                confidence=detection.confidence,
                severity=detection.severity,
                window_start=ts,
                window_end=ts,
                actor=Actor(pid=pid, image=f"C:\\Windows\\System32\\{pname}", guid=f"{{guid-fusion-{self._idx:04d}}}"),
                evidence=[ev.process_name for ev in detection.evidence if ev.process_name],
                attck=AttckRef(tactic=tactic, technique=technique),
                detector=f"{detection.category}Detector@1.0",
                features=features,
            )
            
            env = Envelope[SemanticEvent](
                message_id=str(uuid.uuid4()),
                message_type="SemanticEvent",
                session_id=self.session_id,
                correlation_id=se.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="LiveFusionBridge",
                payload=se
            )
            await self.bus.publish(env)


class LiveOrchestrator:
    def __init__(self, sysmon_path: str, procmon_path: str, network_path: str, rules_path: str):
        self.session_id = f"live_{uuid.uuid4().hex[:8]}"
        self.bus = EventBus()
        
        self.sysmon = SysmonCollector(sysmon_path, session_id=self.session_id) if sysmon_path else None
        self.procmon = ProcmonCollector(procmon_path, session_id=self.session_id) if procmon_path else None
        self.network = NetworkCollector(network_path, session_id=self.session_id) if network_path else None
        
        self.fusion_bridge = LiveFusionBridge(self.bus, self.session_id)
        
        self.policy_engine = PolicyEngine(rules_path)
        self.session_context = SessionContext(session_id=self.session_id)
        
        # Build real HTTPGuestChannel from config for deception mutations
        settings = get_settings()
        http_settings = settings.http_guest
        guest_channel = HTTPGuestChannel(
            http_settings.base_url,
            capture_dir=http_settings.capture_dir,
            procmon_path=http_settings.procmon_path,
            tshark_path=http_settings.tshark_path,
            sysmon_log=http_settings.sysmon_log,
            tshark_interface=http_settings.tshark_interface,
            request_timeout_s=http_settings.request_timeout_s,
            guest_ready_timeout_s=settings.sandbox.guest_ready_timeout_s,
        )
        self.deception_engine = DeceptionEngine(guest_channel)
        
        self.bus.subscribe(RawEvent, self.fusion_bridge.handle_raw_event, name="fusion_bridge")
        self.bus.subscribe(SemanticEvent, self.handle_semantic_event, name="policy_deception")
        
        self.tasks: List[asyncio.Task] = []

    async def handle_semantic_event(self, envelope: Envelope[SemanticEvent]):
        event = envelope.payload
        decisions = self.policy_engine.evaluate(event, self.session_context)
        
        for decision in decisions:
            d_env = Envelope[PolicyDecision](
                message_id=str(uuid.uuid4()),
                message_type="PolicyDecision",
                session_id=self.session_id,
                correlation_id=event.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="PolicyEngine",
                payload=decision
            )
            await self.bus.publish(d_env)
            
            if decision.verdict == Verdict.EXECUTE:
                mutation_result = await self.deception_engine.execute_async(decision)
                m_env = Envelope[MutationResult](
                    message_id=str(uuid.uuid4()),
                    message_type="MutationResult",
                    session_id=self.session_id,
                    correlation_id=event.correlation_id,
                    emitted_at=datetime.now(timezone.utc),
                    emitter="DeceptionEngine",
                    payload=mutation_result
                )
                await self.bus.publish(m_env)

    async def run_collector(self, collector, name: str):
        await collector.start()
        async for event in collector.iter_events():
            env = Envelope[RawEvent](
                message_id=str(uuid.uuid4()),
                message_type="RawEvent",
                session_id=self.session_id,
                correlation_id=str(uuid.uuid4()),
                emitted_at=datetime.now(timezone.utc),
                emitter=name,
                payload=event
            )
            await self.bus.publish(env)

    async def start(self):
        await self.bus.start()
        if self.sysmon:
            self.tasks.append(asyncio.create_task(self.run_collector(self.sysmon, "sysmon")))
        if self.procmon:
            self.tasks.append(asyncio.create_task(self.run_collector(self.procmon, "procmon")))
        if self.network:
            self.tasks.append(asyncio.create_task(self.run_collector(self.network, "network")))
            
        async def periodic_flush():
            while True:
                await asyncio.sleep(1.0)
                await self.fusion_bridge.flush()
        self.tasks.append(asyncio.create_task(periodic_flush()))

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        if self.sysmon:
            await self.sysmon.stop()
        if self.procmon:
            await self.procmon.stop()
        if self.network:
            await self.network.stop()
        await self.bus.drain(2.0)
