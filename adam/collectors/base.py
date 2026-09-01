import asyncio
from typing import AsyncIterator
from adam.contracts.interfaces import ICollector
from adam.contracts.raw_event import RawEvent
from adam.common.bus import EventBus

class BaseCollector(ICollector):
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._running = False

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def iter_events(self) -> AsyncIterator[RawEvent]:
        if False:
            yield  # Make it an async generator
        raise NotImplementedError
