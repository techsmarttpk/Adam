import logging
from typing import Optional
from adam.contracts.interfaces import IDeceptionEngine, ISandboxController
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.enums import PolicyVerdict
from adam.common.bus import EventBus

logger = logging.getLogger("adam.deception.engine")

class DeceptionEngine(IDeceptionEngine):
    def __init__(self, sandbox_controller: ISandboxController, bus: EventBus) -> None:
        self.sandbox_controller = sandbox_controller
        self.bus = bus

    async def execute(self, decision: PolicyDecision) -> Optional[MutationResult]:
        if decision.verdict != PolicyVerdict.EXECUTE:
            logger.info(f"Deception action {decision.action} skipped due to decision verdict: {decision.verdict.value}")
            return None
            
        logger.info(f"DeceptionEngine dispatching mutation command to guest: {decision.action}")
        try:
            result = await self.sandbox_controller.apply_mutation(decision)
            await self.bus.publish(result)
            return result
        except Exception as e:
            logger.error(f"Error during deception mutation dispatch: {e}", exc_info=True)
            return None
