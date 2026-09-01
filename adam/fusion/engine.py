import logging
from typing import List, Callable, Optional
from adam.contracts.interfaces import IFusionEngine
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.common.config import FusionSettings
from adam.common.bus import EventBus
from adam.fusion.normalise import EventNormaliser
from adam.fusion.correlate import EventCorrelator
from adam.fusion import detectors

from adam.fusion.registry import DETECTOR_REGISTRY

logger = logging.getLogger("adam.fusion.engine")

class FusionEngine(IFusionEngine):
    def __init__(self, settings: FusionSettings, bus: EventBus) -> None:
        self.settings = settings
        self.bus = bus
        self.correlator = EventCorrelator(window_seconds=settings.window_seconds)
        self._current_mutation_id: Optional[str] = None

    def set_active_mutation(self, mutation_id: Optional[str]) -> None:
        self._current_mutation_id = mutation_id

    async def ingest(self, event: RawEvent) -> List[SemanticEvent]:
        norm_event = EventNormaliser.normalise(event)
        self.correlator.add_event(norm_event)
        
        semantic_events = []
        for detector_func in DETECTOR_REGISTRY:
            try:
                results = detector_func(self.correlator, norm_event)
                for se in results:
                    if self._current_mutation_id:
                        se.caused_by_mutation = self._current_mutation_id
                    semantic_events.append(se)
            except Exception as e:
                logger.error(f"Detector error in {detector_func.__name__}: {e}", exc_info=True)

        for se in semantic_events:
            await self.bus.publish(se)
            
        return semantic_events
