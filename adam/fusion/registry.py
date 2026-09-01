from typing import List, Callable
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.raw_event import RawEvent
from adam.fusion.correlate import EventCorrelator

DETECTOR_REGISTRY: List[Callable[[EventCorrelator, RawEvent], List[SemanticEvent]]] = []

def register_detector(func: Callable[[EventCorrelator, RawEvent], List[SemanticEvent]]):
    DETECTOR_REGISTRY.append(func)
    return func
