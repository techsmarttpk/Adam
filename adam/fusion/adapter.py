"""
adam/fusion/adapter.py

Integration adapter between the frozen `adam.contracts` boundary
(`RawEvent`/`SemanticEvent`, ARCHITECTURE.md sections 7.2/7.3) and Dev B's
Event Fusion Engine internals (`adam.fusion.models`/`engine.py`), which were
built against their own internal dataclasses rather than the frozen
contracts models (see docs/ADAM_Full_Repository_Audit.md and
docs/ADAM_DevC_Bypass_Feasibility.md for how this was found).

This module does NOT modify anything under `adam/fusion/` — the engine,
normalizer, correlator, window, process tree, and all ten detectors remain
entirely Dev B's code, untouched. It only translates at the two edges of
the package, generalizing the one-off, file-based idea already present in
`adam.fusion.jsonl_converter` into an in-memory bridge that can run inside
a live session (`adam.orchestrator.pipeline`), not only against a saved
`raw.jsonl`.

Disclosed mapping decisions
----------------------------
- Dev B's `SemanticEvent` has no `intent` field (the section 7.7 taxonomy
  string Policy's YAML rules key off via `when.intent`) — it has `category`
  (an ATT&CK-tactic-level string, e.g. "Reconnaissance") and `technique_id`
  (an ATT&CK technique ID, e.g. "T1082"). `CATEGORY_TO_INTENT` below is a
  coarse, static, one-per-category lookup, chosen to line up with an
  existing `rules/default/` rule wherever a reasonable one exists, and with
  a taxonomy-consistent new name otherwise (harmless when no rule matches —
  `PolicyEngine.evaluate()` simply produces zero decisions for that event).
  This is explicitly NOT the fine-grained, per-event intent inference
  Fusion will eventually own — it is the smallest adapter that lets
  already-real detector output reach the already-real Policy Engine today.
- Dev B's `SemanticEvent.actor` has no `guid` (Sysmon's process GUID) —
  synthesized deterministically from pid + timestamp and clearly tagged
  `synthetic-` so nothing downstream mistakes it for a real Sysmon GUID.
- Dev B's `SemanticEvent.evidence` is a list of *their* `RawEvent` objects,
  not contract `RawEvent` IDs. `raw_event_to_fusion()` stashes the
  originating `adam.contracts.raw_event.RawEvent.event_id` into
  `payload["_adam_event_id"]` on the way in specifically so
  `fusion_semantic_to_contract()` can recover real evidence IDs on the way
  out — preserving section 7.1's correlation_id/evidence traceability chain
  instead of fabricating placeholder IDs.
"""

from __future__ import annotations

import uuid
from datetime import timezone

from adam.contracts.raw_event import RawEvent as ContractRawEvent
from adam.contracts.semantic_event import Actor, AttckRef
from adam.contracts.semantic_event import SemanticEvent as ContractSemanticEvent
from adam.fusion.models import RawEvent as FusionRawEvent
from adam.fusion.models import SemanticEvent as FusionSemanticEvent

__all__ = [
    "CATEGORY_TO_INTENT",
    "raw_event_to_fusion",
    "fusion_semantic_to_contract",
]

# Coarse category -> ARCHITECTURE.md section 7.7 taxonomy intent mapping.
# See module docstring. Entries marked "no rule yet" resolve to an intent
# string not currently present in any rules/default/*.yaml file -- these
# SemanticEvents still flow through PolicyEngine.evaluate() correctly, they
# simply match zero rules and produce zero decisions, which is the correct,
# safe behavior for an intent nobody has authored a rule for yet.
CATEGORY_TO_INTENT: dict[str, str] = {
    "Reconnaissance": "RECON_SYSTEM_UPTIME",
    "Persistence": "PERSIST_RUN_KEY",
    "Credential Access": "CRED_BROWSER_STORE",
    "Defense Evasion": "EVADE_SANDBOX_DETECTED",
    "Privilege Escalation": "PRIVESC_TOKEN_MANIPULATION",  # no rule yet
    "Lateral Movement": "LATERAL_SMB_ENUM",  # no rule yet
    "Collection": "COLLECTION_STAGED_DATA",  # not in section 7.7 either -- Dev B addition, no rule yet
    "Command and Control": "C2_BEACON",
    "Exfiltration": "EXFIL_DATA_TRANSFER",  # not in section 7.7 either -- Dev B addition, no rule yet
    "Impact": "IMPACT_MASS_FILE_ENCRYPT",  # no rule yet
}

_EVIDENCE_ID_KEY = "_adam_event_id"


def raw_event_to_fusion(event: ContractRawEvent) -> FusionRawEvent:
    """
    One `adam.contracts.raw_event.RawEvent` -> one `adam.fusion.models.RawEvent`.

    Carries every `attributes` key through into `payload` (richer detector
    input than `adam.fusion.jsonl_converter`'s file-based path, which only
    preserved `command_line`) and stashes the real `event_id` so evidence
    can be traced back to it later.
    """
    process = event.process
    payload: dict[str, object] = dict(event.attributes)
    payload[_EVIDENCE_ID_KEY] = event.event_id
    if process is not None:
        payload.setdefault("command_line", process.command_line)

    return FusionRawEvent(
        timestamp=event.occurred_at,
        source=event.source.value,
        event_type=event.category.value,
        process_id=process.pid if process is not None else None,
        parent_process_id=process.ppid if process is not None else None,
        process_name=process.image if process is not None else None,
        command_line=process.command_line if process is not None else None,
        payload=payload,
    )


def fusion_semantic_to_contract(
    sem: FusionSemanticEvent,
    *,
    session_id: str,
    detector_name: str = "fusion",
) -> ContractSemanticEvent:
    """
    One Dev B `adam.fusion.models.SemanticEvent` (a detector's raw output)
    -> one real, frozen `adam.contracts.semantic_event.SemanticEvent` ready
    to hand to `adam.policy.engine.PolicyEngine.evaluate()`.
    """
    evidence_ids = [
        raw_id
        for raw_evt in sem.evidence
        if (raw_id := raw_evt.payload.get(_EVIDENCE_ID_KEY))
    ]

    first = sem.evidence[0] if sem.evidence else None
    pid = first.process_id if first is not None and first.process_id is not None else 0
    image = first.process_name if first is not None and first.process_name else "unknown"

    window = sem.timestamp if sem.timestamp.tzinfo is not None else sem.timestamp.replace(tzinfo=timezone.utc)

    return ContractSemanticEvent(
        semantic_id=f"sem_{uuid.uuid4().hex[:12]}",
        session_id=session_id,
        correlation_id=str(evidence_ids[0]) if evidence_ids else f"corr_{uuid.uuid4().hex[:12]}",
        intent=CATEGORY_TO_INTENT.get(sem.category, sem.category.upper().replace(" ", "_")),
        confidence=sem.confidence,
        severity=sem.severity,
        window_start=window,
        window_end=window,
        actor=Actor(pid=pid, image=image, guid=f"synthetic-{pid}-{int(window.timestamp())}"),
        evidence=[str(e) for e in evidence_ids],
        attck=AttckRef(tactic=sem.category, technique=sem.technique_id),
        detector=f"{detector_name}@fusion-integration-0.1",
        features={
            "description": sem.description,
            "technique_id": sem.technique_id,
            "raw_category": sem.category,
        },
    )
