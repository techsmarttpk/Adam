import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from adam.contracts.interfaces import IPolicyEngine
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.enums import PolicyVerdict
from adam.common.config import PolicySettings
from adam.common.bus import EventBus
from adam.policy.loader import RuleLoader, PolicyRule
from adam.common.timeutil import now_utc

logger = logging.getLogger("adam.policy.engine")

class SessionPolicyContext:
    """Tracks budgets and cooldowns for a single analysis session."""
    def __init__(self) -> None:
        self.rule_execution_counts: Dict[str, int] = {}
        self.rule_last_executed: Dict[str, datetime] = {}
        self.total_mutations = 0

class PolicyEngine(IPolicyEngine):
    def __init__(self, settings: PolicySettings, bus: EventBus) -> None:
        self.settings = settings
        self.bus = bus
        self.rules = RuleLoader.load_rules(settings.ruleset_path)
        self.contexts: Dict[str, SessionPolicyContext] = {}

    def get_or_create_context(self, session_id: str) -> SessionPolicyContext:
        if session_id not in self.contexts:
            self.contexts[session_id] = SessionPolicyContext()
        return self.contexts[session_id]

    async def evaluate(self, event: SemanticEvent, context: Any = None) -> List[PolicyDecision]:
        session_id = event.session_id
        ctx = self.get_or_create_context(session_id)
        decisions = []
        
        matching_rules = [r for r in self.rules if r.intent == event.intent]
        
        for rule in matching_rules:
            start_eval = datetime.now()
            verdict = PolicyVerdict.EXECUTE
            rationale = rule.rationale or "Matches rule trigger conditions."
            
            # 1. OBSERVE action check
            if rule.action == "NONE" or rule.action_category == "OBSERVE" or rule.default_verdict == "OBSERVE":
                verdict = PolicyVerdict.DRY_RUN
                rationale = f"Telemetry observation rule (no active mutation): {rationale}"

            # 2. Confidence gates
            elif event.confidence < rule.confidence_gte:
                verdict = PolicyVerdict.SUPPRESSED_CONFIDENCE
                rationale = f"Event confidence ({event.confidence}) below rule threshold ({rule.confidence_gte})."
            
            elif event.confidence < self.settings.global_confidence_gate:
                verdict = PolicyVerdict.SUPPRESSED_CONFIDENCE
                rationale = f"Event confidence ({event.confidence}) below global confidence gate ({self.settings.global_confidence_gate})."
                
            # 3. Session / Rule Budgets
            elif session_id != "sess_continuous_live" and ctx.rule_execution_counts.get(rule.rule_id, 0) >= rule.max_per_session:
                verdict = PolicyVerdict.SUPPRESSED_BUDGET
                rationale = f"Rule has reached its max execution budget ({rule.max_per_session}) for this session."
                
            elif session_id != "sess_continuous_live" and ctx.total_mutations >= self.settings.max_mutations_per_session:
                verdict = PolicyVerdict.SUPPRESSED_BUDGET
                rationale = f"Session has reached the global mutation budget ({self.settings.max_mutations_per_session})."
                
            # 4. Cooldown
            elif rule.rule_id in ctx.rule_last_executed:
                last_time = ctx.rule_last_executed[rule.rule_id]
                time_since = (now_utc() - last_time).total_seconds()
                if time_since < rule.cooldown_seconds:
                    verdict = PolicyVerdict.SUPPRESSED_COOLDOWN
                    rationale = f"Rule cooldown active. Time since last execution: {time_since:.1f}s / {rule.cooldown_seconds}s."

            # 5. Global dry run
            if verdict == PolicyVerdict.EXECUTE and self.settings.dry_run:
                verdict = PolicyVerdict.DRY_RUN
                rationale = "Dry run mode enabled in settings."

            if verdict == PolicyVerdict.EXECUTE:
                ctx.rule_execution_counts[rule.rule_id] = ctx.rule_execution_counts.get(rule.rule_id, 0) + 1
                ctx.rule_last_executed[rule.rule_id] = now_utc()
                ctx.total_mutations += 1
                
            eval_ms = (datetime.now() - start_eval).total_seconds() * 1000.0
            
            decision = PolicyDecision(
                decision_id=f"dec_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                correlation_id=event.correlation_id,
                triggered_by=event.semantic_id,
                rule_id=rule.rule_id,
                rule_version="1.0",
                action=rule.action,
                verdict=verdict,
                priority=rule.priority,
                parameters={
                    "action_category": rule.action_category,
                    "severity": rule.severity,
                    "default_verdict": rule.default_verdict
                },
                rationale=rationale,
                decided_at=now_utc(),
                evaluation_ms=eval_ms
            )
            
            decisions.append(decision)
            await self.bus.publish(decision)
            
        return decisions
