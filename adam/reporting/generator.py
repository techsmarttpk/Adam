from typing import Any
from adam.contracts.interfaces import IReportGenerator
from adam.db.interfaces import ISessionRepository, IEventRepository, IDecisionRepository, IMutationRepository
from adam.reporting.renderers import JSONRenderer, MarkdownRenderer, HTMLRenderer

class ReportGenerator(IReportGenerator):
    def __init__(
        self,
        session_repo: ISessionRepository,
        event_repo: IEventRepository,
        decision_repo: IDecisionRepository,
        mutation_repo: IMutationRepository,
        plausibility_warn_below: float = 0.5
    ):
        self.session_repo = session_repo
        self.event_repo = event_repo
        self.decision_repo = decision_repo
        self.mutation_repo = mutation_repo
        self.plausibility_warn_below = plausibility_warn_below
        
        self.renderers = {
            "json": JSONRenderer(),
            "md": MarkdownRenderer(),
            "html": HTMLRenderer(),
        }

    async def generate(self, session_id: str, format: str = "json") -> str:
        session = await self.session_repo.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        events = await self.event_repo.get_semantic_by_session(session_id)
        mutations = await self.mutation_repo.get_by_session(session_id)

        # Timeline
        timeline = []
        for e in events:
            timeline.append({
                "type": "SemanticEvent",
                "time": e.window_start,
                "intent": e.intent,
                "confidence": e.confidence
            })
        for m in mutations:
            timeline.append({
                "type": "MutationResult",
                "time": m.applied_at,
                "primitive": m.primitive,
                "status": m.status.value if hasattr(m.status, "value") else str(m.status)
            })
        timeline.sort(key=lambda x: x["time"])

        # ATT&CK Coverage
        attck_coverage = []
        for e in events:
            if e.attck:
                cov = f"{e.attck.tactic}/{e.attck.technique}"
                if cov not in attck_coverage:
                    attck_coverage.append(cov)

        # IOC extraction
        iocs = []
        for m in mutations:
            for c in m.changes:
                iocs.append({"source": "mutation", "target": c.target, "operation": c.operation})
        for e in events:
            if "target_object" in e.features:
                iocs.append({"source": "semantic_event", "target": e.features["target_object"]})
            if "network_endpoint" in e.features:
                iocs.append({"source": "semantic_event", "target": e.features["network_endpoint"], "operation": "network"})

        # Detection risk
        high_risk_mutations = [
            m.model_dump() for m in mutations if m.plausibility_score < self.plausibility_warn_below
        ]

        data = {
            "session_id": session_id,
            "experiment_id": session.experiment_id,
            "arm": session.arm.value if hasattr(session.arm, "value") else str(session.arm),
            "timeline": timeline,
            "attck_coverage": attck_coverage,
            "iocs": iocs,
            "detection_risk": high_risk_mutations,
        }

        if format not in self.renderers:
            raise ValueError(f"Unsupported format {format}")
            
        return self.renderers[format].render(data)

    async def generate_comparison(self, experiment_id: str) -> str:
        all_sessions = await self.session_repo.list_all()
        exp_sessions = [s for s in all_sessions if s.experiment_id == experiment_id]
        
        control_session = next((s for s in exp_sessions if s.arm.value == "CONTROL" or str(s.arm) == "CONTROL"), None)
        treatment_session = next((s for s in exp_sessions if s.arm.value == "TREATMENT" or str(s.arm) == "TREATMENT"), None)

        if not control_session or not treatment_session:
            raise ValueError(f"Experiment {experiment_id} missing CONTROL or TREATMENT session")

        t_events = await self.event_repo.get_semantic_by_session(treatment_session.session_id)
        c_events = await self.event_repo.get_semantic_by_session(control_session.session_id)

        t_post_mutation = [e for e in t_events if e.caused_by_mutation is not None]
        c_post_mutation = [e for e in c_events if e.caused_by_mutation is not None]

        delta_semantic_events = len(t_post_mutation) - len(c_post_mutation)

        def extract_distinct(events):
            intents = set(e.intent for e in events)
            networks = set(e.features.get("network_endpoint") for e in events if "network_endpoint" in e.features)
            return intents, networks

        t_intents, t_networks = extract_distinct(t_post_mutation)
        c_intents, c_networks = extract_distinct(c_post_mutation)

        data = {
            "experiment_id": experiment_id,
            "control_session": control_session.session_id,
            "treatment_session": treatment_session.session_id,
            "delta_semantic_events": delta_semantic_events,
            "distinct_intents_yield": list(t_intents - c_intents),
            "distinct_networks_yield": list(t_networks - c_networks)
        }

        return self.renderers["json"].render(data)
