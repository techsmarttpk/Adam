import logging
from enum import Enum
from adam.common.errors import SandboxStateError

logger = logging.getLogger("adam.sandbox.state")

class SandboxState(str, Enum):
    COLD = "COLD"
    RESTORING = "RESTORING"
    BOOTING = "BOOTING"
    READY = "READY"
    ARMED = "ARMED"
    RUNNING = "RUNNING"
    TEARDOWN = "TEARDOWN"
    FAILED = "FAILED"

class SandboxFSM:
    def __init__(self) -> None:
        self._state = SandboxState.COLD
        
    @property
    def state(self) -> SandboxState:
        return self._state

    def transition_to(self, new_state: SandboxState) -> None:
        valid_transitions = {
            SandboxState.COLD: [SandboxState.RESTORING],
            SandboxState.RESTORING: [SandboxState.BOOTING, SandboxState.FAILED],
            SandboxState.BOOTING: [SandboxState.READY, SandboxState.FAILED],
            SandboxState.READY: [SandboxState.ARMED, SandboxState.TEARDOWN, SandboxState.FAILED],
            SandboxState.ARMED: [SandboxState.RUNNING, SandboxState.TEARDOWN, SandboxState.FAILED],
            SandboxState.RUNNING: [SandboxState.TEARDOWN, SandboxState.FAILED],
            SandboxState.TEARDOWN: [SandboxState.COLD, SandboxState.FAILED],
            SandboxState.FAILED: [SandboxState.COLD],
        }
        
        current = self._state
        if current == new_state:
            return

        if new_state in valid_transitions.get(current, []):
            logger.info(f"Sandbox state transition: {current.value} -> {new_state.value}")
            self._state = new_state
        else:
            if new_state in [SandboxState.FAILED, SandboxState.TEARDOWN]:
                logger.warning(f"Forced sandbox state transition: {current.value} -> {new_state.value}")
                self._state = new_state
                return
            raise SandboxStateError(f"Invalid sandbox state transition: {current.value} -> {new_state.value}")
