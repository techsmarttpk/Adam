"""
adam/common/bus.py

EventBus -- ARCHITECTURE.md section 8. An in-process asyncio publish/
subscribe broker: the one non-database, non-HTTP way modules are allowed to
talk to each other (section 11.1). Every message passed through here is an
Envelope (adam/contracts/envelope.py, section 7.1); subscribers register
against the payload type they care about (RawEvent, SemanticEvent, ...) and
receive the whole Envelope, so correlation_id/session_id/emitted_at travel
with the payload rather than being stripped at the door.

ARCHITECTURE.md section 8.1 presents `EventBus` as a `Protocol` -- purely
for documentation purposes, the same way section 5.2 presents
`ISandboxController` as a Protocol that `SandboxController` implements
under a different name. Here, unusually, the roadmap's own Phase 1 spec
(docs/dev-a-environment-and-roadmap.md) names the concrete deliverable
class `EventBus` too, so this file defines exactly one class of that name
matching section 8.1's four-method surface, rather than an abstract
Protocol plus a separately-named implementation.

Guarantees implemented (section 8.2):
  - Per-publisher FIFO ordering: publish() enqueues into each matching
    subscriber's queue with a single non-blocking put_nowait() and no real
    `await` suspension point in between, so a coroutine's own sequential
    publish() calls always complete one at a time, in order -- and, as a
    side effect of having no internal suspension point, two concurrent
    publishers' publish() calls cannot interleave with each other either
    (each runs to completion in one uninterrupted step under asyncio's
    cooperative scheduling). Stronger than the section 8.2 requirement,
    not a violation of it.
  - At-most-once delivery: a message is either delivered once to a given
    subscriber's handler or dropped (see QueueOverflow below) -- never
    delivered twice, never redelivered after a handler exception.
  - Handler isolation: each subscriber has its own consumer task and its
    own try/except around the handler call. An exception in one handler is
    logged and does not affect any other subscriber or the publisher.
  - Bounded memory: every subscriber queue has a fixed maxsize (queue_size,
    default 1000) set at subscribe() time.

Not guaranteed (section 8.2), by design:
  - Cross-publisher global ordering. Use `occurred_at`/`emitted_at` for
    causal ordering across publishers.
  - Durability. That's `raw.jsonl`'s job (ADR-005), not this bus's.
  - Delivery under backpressure. A full subscriber queue drops the new
    message rather than blocking the publisher (section 8.3: blocking a
    collector because a slow subscriber is backed up would corrupt the
    timing fidelity of the whole experiment and could let malware outrun
    the analysis). Drops are counted per subscriber and logged at WARNING
    -- see Subscription.dropped and the QueueOverflow note below.

QueueOverflow
--------------
Section 8.2 refers to a "counted, logged QueueOverflow" rather than a
raised exception -- consistent with "drop rather than block" (section 8.3):
raising would still require the publisher to handle it, which is exactly
the coupling this design avoids. QueueOverflow here is therefore a logged
WARNING plus an incrementing `Subscription.dropped` counter, not an
exception class. `adam/common/errors.py` does not exist yet (Phase 1
remaining item, tracked in docs/remaining-work-plan.md); if a future
AdamError-hierarchy need for a structured overflow record emerges, it
belongs there, not here.

Logging: `adam/common/logging.py` does not exist yet either (same tracked
gap), so this module uses the stdlib `logging` module directly via
`logging.getLogger(__name__)`. Switch to `get_logger("common.bus")` once
that lands -- no behavioural change expected, same as this project's other
pre-logging.py modules (e.g. adam/sandbox/controller.py).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

from adam.contracts.envelope import Envelope

logger = logging.getLogger(__name__)

T = TypeVar("T")

Handler = Callable[[Envelope[T]], Awaitable[None]]
"""A subscriber's callback: receives the full Envelope wrapping its payload."""


@dataclass
class Subscription:
    """
    Handle returned by EventBus.subscribe(). Identifies one subscriber and
    exposes its live delivered/dropped counters (section 8.3: drops are
    "counted per subscriber and surfaced in session metrics"). Call
    .unsubscribe() to stop receiving messages and cancel the subscriber's
    consumer task.
    """

    name: str
    message_type: type[Any]
    queue_size: int
    delivered: int = field(default=0, compare=False)
    dropped: int = field(default=0, compare=False)
    _bus: EventBus | None = field(default=None, repr=False, compare=False)

    def unsubscribe(self) -> None:
        if self._bus is not None:
            self._bus._unsubscribe(self)
            self._bus = None


@dataclass
class _Subscriber:
    """Internal bookkeeping paired 1:1 with a Subscription. Not public API."""

    subscription: Subscription
    handler: Handler[Any]
    queue: asyncio.Queue[Envelope[Any]]
    task: asyncio.Task[None] | None = None


class EventBus:
    """
    In-process asyncio pub/sub broker. See module docstring for the full
    guarantee set. Matches ARCHITECTURE.md section 8.1's four-method
    surface (`subscribe`, `publish`, `start`, `drain`) and
    docs/dev-a-environment-and-roadmap.md's Phase 1 "Public interfaces"
    listing exactly:

        EventBus.subscribe(message_type, handler, *, name, queue_size=1000) -> Subscription
        EventBus.publish(message) -> None                       # async
        EventBus.start() -> None                                 # async
        EventBus.drain(timeout) -> None                           # async
    """

    def __init__(self) -> None:
        self._subscribers: dict[type[Any], list[_Subscriber]] = {}
        self._started = False

    def subscribe(
        self,
        message_type: type[T],
        handler: Handler[T],
        *,
        name: str,
        queue_size: int = 1000,
    ) -> Subscription:
        """
        Registers `handler` to receive every published Envelope whose
        payload is an instance of `message_type` (subclasses included).
        Safe to call before or after start(): if the bus is already
        running, the new subscriber's consumer task is started immediately;
        otherwise it starts when start() is called.
        """
        subscription = Subscription(
            name=name, message_type=message_type, queue_size=queue_size, _bus=self
        )
        queue: asyncio.Queue[Envelope[Any]] = asyncio.Queue(maxsize=queue_size)
        subscriber = _Subscriber(subscription=subscription, handler=handler, queue=queue)
        self._subscribers.setdefault(message_type, []).append(subscriber)

        if self._started:
            subscriber.task = asyncio.create_task(self._consume(subscriber), name=f"adam.bus.{name}")

        return subscription

    async def publish(self, message: Envelope[Any]) -> None:
        """
        Fans `message` out to every subscriber registered for
        type(message.payload) or one of its superclasses. Non-blocking per
        subscriber: a full queue drops this message for that subscriber
        (counted + logged as QueueOverflow), never blocks the publisher and
        never affects delivery to any other subscriber. See section 8.3.
        """
        payload_type = type(message.payload)
        for registered_type, subscribers in self._subscribers.items():
            if not isinstance(message.payload, registered_type):
                continue
            for subscriber in subscribers:
                try:
                    subscriber.queue.put_nowait(message)
                    subscriber.subscription.delivered += 1
                except asyncio.QueueFull:
                    subscriber.subscription.dropped += 1
                    logger.warning(
                        "QueueOverflow: dropped message_type=%s for subscriber=%r "
                        "(queue_size=%d, total_dropped=%d)",
                        payload_type.__name__,
                        subscriber.subscription.name,
                        subscriber.subscription.queue_size,
                        subscriber.subscription.dropped,
                    )

    async def start(self) -> None:
        """
        Starts one consumer task per currently-registered subscriber.
        Idempotent: calling start() twice does not create duplicate
        consumer tasks for subscribers that already have one.
        """
        self._started = True
        for subscribers in self._subscribers.values():
            for subscriber in subscribers:
                if subscriber.task is None:
                    subscriber.task = asyncio.create_task(
                        self._consume(subscriber), name=f"adam.bus.{subscriber.subscription.name}"
                    )

    async def drain(self, timeout: float) -> None:
        """
        Waits up to `timeout` seconds total for every subscriber queue to
        be fully processed, then cancels all consumer tasks and marks the
        bus stopped. Best-effort: a timeout is logged, not raised -- mirrors
        this project's established teardown()-style "never raise from
        shutdown" convention (ARCHITECTURE.md section 14.4).
        """
        all_subscribers = [s for subs in self._subscribers.values() for s in subs]
        joins = [subscriber.queue.join() for subscriber in all_subscribers]
        if joins:
            try:
                await asyncio.wait_for(asyncio.gather(*joins), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning(
                    "EventBus.drain() timed out after %.1fs with messages still queued", timeout
                )

        for subscriber in all_subscribers:
            if subscriber.task is not None:
                subscriber.task.cancel()
        for subscriber in all_subscribers:
            if subscriber.task is not None:
                try:
                    await subscriber.task
                except asyncio.CancelledError:
                    pass
                subscriber.task = None

        self._started = False

    def _unsubscribe(self, subscription: Subscription) -> None:
        subscribers = self._subscribers.get(subscription.message_type, [])
        for subscriber in list(subscribers):
            if subscriber.subscription is subscription:
                subscribers.remove(subscriber)
                if subscriber.task is not None:
                    subscriber.task.cancel()
                break

    async def _consume(self, subscriber: _Subscriber) -> None:
        """
        One subscriber's dedicated consumer loop. Handler isolation
        (section 8.2): an exception raised by the handler is caught, logged,
        and the loop continues -- it never propagates to the publisher or
        to any other subscriber's consumer task.
        """
        while True:
            envelope = await subscriber.queue.get()
            try:
                await subscriber.handler(envelope)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "handler error in subscriber=%r for message_type=%s -- "
                    "isolated, other subscribers unaffected",
                    subscriber.subscription.name,
                    subscriber.subscription.message_type.__name__,
                )
            finally:
                subscriber.queue.task_done()
