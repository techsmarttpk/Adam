import os
import json
import logging
from typing import Dict, Any
from adam.db.repositories.sessions import SessionRepository
from adam.db.repositories.events import EventRepository
from adam.db.repositories.decisions import DecisionRepository
from adam.db.repositories.mutations import MutationRepository
from adam.common.timeutil import to_iso

logger = logging.getLogger("adam.reporting.generator")

class ReportGenerator:
    def __init__(
        self,
        session_repo: SessionRepository,
        event_repo: EventRepository,
        decision_repo: DecisionRepository,
        mutation_repo: MutationRepository
    ) -> None:
        self.session_repo = session_repo
        self.event_repo = event_repo
        self.decision_repo = decision_repo
        self.mutation_repo = mutation_repo

    async def generate_session_report(self, session_id: str) -> Dict[str, Any]:
        """Generates a complete structured report and PDF for a single analysis session."""
        session = await self.session_repo.get(session_id)
        if not session:
            return {"error": f"Session {session_id} not found"}

        events = await self.event_repo.get_semantic_events(session_id)
        decisions = await self.decision_repo.get_decisions(session_id)
        mutations = await self.mutation_repo.get_mutations(session_id)
        raw_events = await self.event_repo.get_raw_events(session_id)

        from adam.reporting.model import ReportDataAggregator
        from adam.reporting.pdf_generator import MalwareReportPDFGenerator

        report_model = ReportDataAggregator.build(
            session=session,
            raw_events=raw_events,
            semantic_events=events,
            decisions=decisions,
            mutations=mutations
        )

        session_dir = os.path.join("artifacts", session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        # Save JSON
        report_path = os.path.join(session_dir, "report.json")
        with open(report_path, "w") as f:
            json.dump({
                "session_id": session_id,
                "risk_score": report_model.risk_score.score,
                "risk_level": report_model.risk_score.level,
                "kpis": report_model.kpis.__dict__,
                "severity_distribution": report_model.severity_distribution.__dict__,
                "top_intents": report_model.top_intents,
                "key_findings": report_model.key_findings
            }, f, indent=2)

        # Save PDF
        try:
            pdf_bytes = MalwareReportPDFGenerator.generate_pdf(report_model)
            pdf_path = os.path.join(session_dir, "threat_report.pdf")
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            logger.info(f"Saved session report PDF to {pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate session PDF: {e}")

        logger.info(f"Saved session report JSON to {report_path}")
        return {"session_id": session_id, "status": "generated", "report_path": report_path}

    async def generate_comparison_report(self, experiment_id: str) -> str:
        """Compares CONTROL vs TREATMENT sessions for the same experiment to calculate behavioral yield."""
        conn = await self.session_repo.db_conn.connect()
        async with conn.execute(
            """
            SELECT session_id, arm, status FROM sessions
            WHERE experiment_id = ?
            """,
            (experiment_id,)
        ) as cursor:
            rows = await cursor.fetchall()

        control_session_id = None
        treatment_session_id = None
        
        for row in rows:
            if row[1] == "CONTROL":
                control_session_id = row[0]
            elif row[1] == "TREATMENT":
                treatment_session_id = row[0]

        if not control_session_id or not treatment_session_id:
            return f"# Comparison Report: {experiment_id}\n\nError: Both CONTROL and TREATMENT arms must be completed to generate yield diffs."

        control_session = await self.session_repo.get(control_session_id)
        treatment_session = await self.session_repo.get(treatment_session_id)

        if not control_session or not treatment_session:
            return f"# Comparison Report: {experiment_id}\n\nError: Session metadata not found."

        control_events = await self.event_repo.get_semantic_events(control_session_id)
        treatment_events = await self.event_repo.get_semantic_events(treatment_session_id)

        yield_count = treatment_session.metrics.semantic_events_post_mutation
        behavioral_delta = len(treatment_events) - len(control_events)

        markdown = f"""# ADAM Behavioral Yield Comparison Report
## Experiment ID: {experiment_id}

### Execution Overview
| Arm | Session ID | Status | Raw Events | Semantic Events | Mutations Applied |
|---|---|---|---|---|---|
| **CONTROL (Dry Run)** | [{control_session_id}](file:///c:/ADAM_Sandbox/Adam/artifacts/{control_session_id}/report.json) | {control_session.status.value} | {control_session.metrics.raw_events} | {control_session.metrics.semantic_events} | 0 |
| **TREATMENT (Active)** | [{treatment_session_id}](file:///c:/ADAM_Sandbox/Adam/artifacts/{treatment_session_id}/report.json) | {treatment_session.status.value} | {treatment_session.metrics.raw_events} | {treatment_session.metrics.semantic_events} | {treatment_session.metrics.mutations_applied} |

### Research Yield Summary
* **Behavioral Yield (Post-Mutation Events)**: **{yield_count}**
* **Net Semantic Delta (Treatment vs Control)**: **+{behavioral_delta}**

### Treatment Semantic Timeline
"""
        for e in treatment_events:
            mutation_indicator = f" [Attributed to {e.caused_by_mutation}]" if e.caused_by_mutation else ""
            markdown += f"- **{e.window_start.strftime('%H:%M:%S.%f')[:-3]}**: `{e.intent}` (Confidence: {e.confidence:.2f}) - Severity: *{e.severity}*{mutation_indicator}\n"

        exp_dir = os.path.join("artifacts", f"experiment_{experiment_id}")
        os.makedirs(exp_dir, exist_ok=True)
        md_path = os.path.join(exp_dir, "yield_report.md")
        with open(md_path, "w") as f:
            f.write(markdown)
            
        logger.info(f"Saved comparison report MD to {md_path}")
        return markdown
