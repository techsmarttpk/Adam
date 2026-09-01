import asyncio
import logging
import time
from typing import Optional, List, Dict, Any
from adam.contracts.session import AnalysisSession, SessionMetrics
from adam.contracts.enums import SessionStatus
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.common.bus import EventBus
from adam.common.timeutil import now_utc
from adam.sandbox.controller import SandboxController
from adam.fusion.engine import FusionEngine
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine
from adam.db.repositories.sessions import SessionRepository
from adam.db.repositories.events import EventRepository
from adam.db.repositories.decisions import DecisionRepository
from adam.db.repositories.mutations import MutationRepository

# Autonomous AMTD & VMI / DRL Framework Subsystems
from adam.sandbox.vmi.ept_controller import EPTController
from adam.sandbox.vmi.syscall_virtualizer import SyscallVirtualizer
from adam.sandbox.vmi.kernel_polymorphism import KernelPolymorphismEngine, MitigationState
from adam.sandbox.vmi.dkom_tracker import DKOMTracker
from adam.sandbox.vmi.differential_memory import DifferentialMemoryAnalyzer
from adam.policy.drl.encoder import AttentionEventEncoder
from adam.policy.drl.dual_stream import DualStreamPolicy, PolicyAction
from adam.policy.drl.gym_env import ActionType
from adam.deception.synthetic.user_simulator import UserSimulator
from adam.deception.synthetic.decoys import SyntheticDecoyEngine
from adam.deception.c2.sinkhole import C2Sinkhole
from adam.reporting.intelligence import ThreatIntelligenceSynthesizer

# Research-Grade Engines: Causal Provenance, Environment State, Deception Memory, Chains & Backfire
from adam.core.provenance.tracker import CausalProvenanceEngine
from adam.core.environment.state_model import EnvironmentStateModel, CrossSourceConsistencyChecker
from adam.policy.memory.store import DeceptionMemoryStore
from adam.policy.backfire import DeceptionBackfireDetector
from adam.policy.chains.planner import DeceptionChainPlanner
from adam.policy.adaptive_budget import AdaptiveBudgetManager
from adam.policy.counterfactual import CounterfactualEvaluator

logger = logging.getLogger("adam.orchestrator.session")


class SessionRunner:
    """Autonomous AMTD Analysis Session Runner.

    Orchestrates real-time kernel mutation, attention-based event encoding,
    dual-stream reinforcement learning, dead man's switch jumpstarts, causal provenance,
    deception memory, backfire detection, and automated YARA / STIX 2.1 threat intelligence synthesis.
    """

    def __init__(
        self,
        session: AnalysisSession,
        bus: EventBus,
        sandbox: SandboxController,
        fusion: FusionEngine,
        policy: PolicyEngine,
        deception: DeceptionEngine,
        session_repo: SessionRepository,
        event_repo: EventRepository,
        decision_repo: DecisionRepository,
        mutation_repo: MutationRepository,
        idle_timeout_seconds: float = 8.0,
    ) -> None:
        self.session = session
        self.bus = bus
        self.sandbox = sandbox
        self.fusion = fusion
        self.policy = policy
        self.deception = deception
        self.session_repo = session_repo
        self.event_repo = event_repo
        self.decision_repo = decision_repo
        self.mutation_repo = mutation_repo
        self.idle_timeout_seconds = idle_timeout_seconds

        self.raw_count = 0
        self.sem_count = 0
        self.dec_count = 0
        self.mut_count = 0
        self.post_mut_count = 0
        self.active_mutation_id: Optional[str] = None
        self._subs = []

        # Autonomous Subsystems
        self.ept_controller = EPTController(vm_id=session.session_id)
        self.syscall_virtualizer = SyscallVirtualizer()
        self.kernel_poly = KernelPolymorphismEngine()
        self.dkom_tracker = DKOMTracker()
        self.memory_analyzer = DifferentialMemoryAnalyzer()
        self.attention_encoder = AttentionEventEncoder()
        self.drl_policy = DualStreamPolicy()
        self.user_simulator = UserSimulator()
        self.decoy_engine = SyntheticDecoyEngine(session_id=session.session_id)
        self.c2_sinkhole = C2Sinkhole()
        self.intel_synthesizer = ThreatIntelligenceSynthesizer(session_id=session.session_id)

        # Research Layer Engines
        self.provenance_engine = CausalProvenanceEngine(default_window_ms=30000)
        self.env_state = EnvironmentStateModel()
        self.deception_memory = DeceptionMemoryStore()
        self.backfire_detector = DeceptionBackfireDetector()
        self.chain_planner = DeceptionChainPlanner()
        self.adaptive_budget = AdaptiveBudgetManager(global_max_mutations=15)
        self.counterfactual_evaluator = CounterfactualEvaluator()

        self.last_event_time = time.time()
        self.event_history: List[Dict[str, Any]] = []
        self.intents_history: List[str] = []
        self.accessed_categories: List[str] = []
        self.forced_mutations_triggered = 0

    async def run(self, sample_path: str) -> None:
        logger.info(f"Starting AMTD autonomous execution session {self.session.session_id} under experiment {self.session.experiment_id}")
        self.session.status = SessionStatus.RUNNING
        self.session_repo.save(self.session)
        self.sandbox.set_session_id(self.session.session_id)

        # Seed initial intelligence
        self.intel_synthesizer.record_artifact(
            "PAYLOAD_HASH", self.session.sample.sha256, confidence=1.0, description="Detonated sample SHA256"
        )

        self._subs.append(self.bus.subscribe(RawEvent, self._handle_raw_event, name="raw-to-fusion"))
        self._subs.append(self.bus.subscribe(SemanticEvent, self._handle_semantic_event, name="sem-to-policy"))
        self._subs.append(self.bus.subscribe(PolicyDecision, self._handle_decision, name="dec-to-deception"))
        self._subs.append(self.bus.subscribe(MutationResult, self._handle_mutation, name="mutation-tracker"))

        try:
            await self.sandbox.prepare()
            await self.sandbox.detonate(sample_path)

            timeout = self.session.config.timeout_seconds
            logger.info(f"Detonation active, running AMTD session loop with max window {timeout}s...")

            # Run adaptive execution loop with Dead Man's Switch / Idle Timeout checks
            start_time = time.time()
            while (time.time() - start_time) < timeout:
                await asyncio.sleep(1.0)
                time_since_last_event = time.time() - self.last_event_time

                # Fail-Safe Dead Man's Switch: If malware is dormant, force state mutation
                if time_since_last_event > self.idle_timeout_seconds:
                    logger.warning(
                        f"Dormancy detected ({time_since_last_event:.1f}s without events). "
                        "Triggering emergency Forced State Mutation to jumpstart sample."
                    )
                    await self._trigger_forced_state_mutation()

            self.session.status = SessionStatus.COMPLETED

        except Exception as e:
            logger.error(f"Detonation run error: {e}", exc_info=True)
            self.session.status = SessionStatus.FAILED
            self.session.error = str(e)

        finally:
            logger.info("Executing teardown and synthesizing threat intelligence...")
            for sub in self._subs:
                sub.task.cancel()
            self._subs.clear()

            await self.sandbox.collect_artifacts()
            await self.sandbox.teardown()

            # Record final memory outcome
            fingerprint = self.deception_memory.compute_behavioral_fingerprint(
                intents_sequence=self.intents_history,
                accessed_categories=self.accessed_categories,
                network_destinations_count=len(self.c2_sinkhole.dga_domains_resolved),
            )
            for mut_id, events in self.provenance_engine.mutation_attributed_events.items():
                self.deception_memory.record_outcome(
                    fingerprint_hash=fingerprint,
                    intent=self.intents_history[-1] if self.intents_history else "UNKNOWN",
                    mutation_action=mut_id,
                    yield_score=float(len(events) * 20.0),
                    new_semantic_events=len(events),
                    new_iocs=len(self.intel_synthesizer.artifacts),
                    deception_detected=self.backfire_detector.has_backfired_on_mutation(mut_id),
                )

            # Synthesize final YARA rules & STIX 2.1 bundle
            yara_rule = self.intel_synthesizer.generate_yara_rule(f"Sample_{self.session.sample.filename}")
            stix_bundle = self.intel_synthesizer.export_stix21_bundle()
            logger.info(f"Synthesized {len(stix_bundle.get('objects', []))} STIX 2.1 indicators and dynamic YARA signature.")

            self.session.ended_at = now_utc()
            self.session.metrics = SessionMetrics(
                raw_events=self.raw_count,
                semantic_events=self.sem_count,
                decisions_total=self.dec_count,
                decisions_executed=self.mut_count,
                mutations_applied=self.mut_count,
                semantic_events_post_mutation=self.post_mut_count
            )
            self.session_repo.update_status(
                self.session.session_id,
                self.session.status,
                self.session.ended_at,
                self.session.error
            )
            self.session_repo.update_metrics(self.session.session_id, self.session.metrics)
            logger.info(f"Session {self.session.session_id} runner terminated successfully.")

    async def _trigger_forced_state_mutation(self) -> None:
        """Applies tactical anti-dormancy state mutations to force execution progress."""
        self.forced_mutations_triggered += 1
        self.last_event_time = time.time()  # Reset idle timer

        # 1. Randomize syscalls
        self.syscall_virtualizer.randomize_syscall_indices()

        # 2. Dynamic mitigation toggle
        mit_state = MitigationState.ENABLED if (self.forced_mutations_triggered % 2 == 1) else MitigationState.DISABLED
        self.kernel_poly.toggle_mitigation_atomically("CVE-2017-5715", mit_state, tx_id=f"tx_dormancy_{self.forced_mutations_triggered}")

        # 3. Simulate human activity (Bézier mouse movements)
        self.user_simulator.generate_random_user_session(duration_seconds=2)

    async def _handle_raw_event(self, event: RawEvent) -> None:
        self.raw_count += 1
        self.last_event_time = time.time()
        self.event_repo.save_raw_event(event)
        self.accessed_categories.append(event.category.value)

        # Causal provenance check
        self.provenance_engine.evaluate_raw_event_causality(event)

        # Deception backfire check
        self.backfire_detector.inspect_raw_event(event)

        # Ingest into attention encoder buffer
        pid_val = event.process.pid if event.process else 0
        target_val = str(event.attributes.get("target_object") or event.attributes.get("target_path") or event.attributes.get("target") or "")
        self.event_history.append({
            "type": str(event.category.value if hasattr(event.category, "value") else event.category),
            "pid": pid_val,
            "target": target_val,
            "severity": 0.5,
            "timestamp_ns": int(time.time() * 1e9),
        })

        await self.fusion.ingest(event)

    async def _handle_semantic_event(self, event: SemanticEvent) -> None:
        self.sem_count += 1
        self.last_event_time = time.time()
        self.intents_history.append(event.intent)

        # Provenance attribution
        attributed_mut = self.provenance_engine.attribute_semantic_event(event, self.active_mutation_id)
        if attributed_mut:
            event.caused_by_mutation = attributed_mut
            self.post_mut_count += 1

        self.event_repo.save_semantic_event(event)
        self.backfire_detector.inspect_semantic_event(event)

        # Check tripwires
        target = str(event.features.get("target_path") or event.features.get("target_object") or "")
        if target:
            file_alert = self.decoy_engine.record_file_access(target)
            if file_alert:
                self.intel_synthesizer.record_artifact("CANARY_FILE_TOUCHED", target, confidence=0.95)

        # Check deception chains
        chain_action = self.chain_planner.get_next_chain_action(event.intent)
        if chain_action:
            chain_name, next_act = chain_action
            logger.info(f"Deception chain '{chain_name}' activated next step: {next_act}")

        # Autonomous DRL evaluation
        state_vec = self.attention_encoder.compute_attention_embedding(self.event_history[-10:])
        policy_action = self.drl_policy.select_action(
            state_embedding=state_vec,
            execution_phase="EXECUTION",
            is_evasion_detected=False,
            is_sample_dormant=False,
        )

        if policy_action.action_type == ActionType.RANDOMIZE_SYSCALLS:
            self.syscall_virtualizer.randomize_syscall_indices()
        elif policy_action.action_type == ActionType.SHUFFLE_KERNEL_MEMORY:
            self.kernel_poly.shuffle_kernel_memory_layout(entropy_seed=int(time.time()))
        elif policy_action.action_type == ActionType.ENABLE_C2_SINKHOLE:
            sink_ip = self.c2_sinkhole.resolve_dns_query("malicious-c2-callback.net")
            self.intel_synthesizer.record_artifact("C2_SINKHOLE_ACTIVE", sink_ip, confidence=0.9)

        await self.policy.evaluate(event)

    async def _handle_decision(self, decision: PolicyDecision) -> None:
        self.dec_count += 1
        self.decision_repo.save(decision)

        # Adaptive budget check
        can_exec, reason = self.adaptive_budget.can_execute(decision.action)
        if not can_exec:
            logger.warning(f"Decision {decision.action} suppressed by AdaptiveBudget: {reason}")
            return

        self.adaptive_budget.record_execution(decision.action)
        await self.deception.execute(decision)

    async def _handle_mutation(self, mutation: MutationResult) -> None:
        self.mut_count += 1
        self.mutation_repo.save(mutation)
        self.active_mutation_id = mutation.mutation_id
        self.fusion.set_active_mutation(mutation.mutation_id)

        # Register in provenance, environment state, and backfire detector
        self.provenance_engine.register_mutation(mutation)
        self.env_state.update_from_mutation(mutation.primitive, {})
        self.backfire_detector.set_active_mutation(mutation.mutation_id, mutation.applied_at)

        async def clear_causal_window_later():
            await asyncio.sleep(30.0)
            if self.active_mutation_id == mutation.mutation_id:
                self.active_mutation_id = None
                self.fusion.set_active_mutation(None)
                self.backfire_detector.set_active_mutation(None)
        asyncio.create_task(clear_causal_window_later())
