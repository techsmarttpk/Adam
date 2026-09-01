import asyncio
import inspect
import logging
from typing import TypeVar, Callable, Any, Type, Optional, Coroutine
from dataclasses import dataclass

T = TypeVar("T")
Handler = Callable[[T], Any]

logger = logging.getLogger("adam.common.bus")

@dataclass
class Subscription:
    name: str
    message_type: Type[Any]
    queue: asyncio.Queue
    handler: Handler[Any]
    task: asyncio.Task
    dropped_count: int = 0

class EventBus:
    def __init__(self, default_queue_size: int = 1000, overflow_policy: str = "DROP_OLDEST") -> None:
        self.default_queue_size = default_queue_size
        self.overflow_policy = overflow_policy
        self._subscriptions: list[Subscription] = []
        self._is_started = False
        self._tasks: list[asyncio.Task] = []

    def subscribe(self, message_type: Type[T], handler: Handler[T],
                  *, name: str, queue_size: Optional[int] = None) -> Subscription:
        q_size = queue_size if queue_size is not None else self.default_queue_size
        queue: asyncio.Queue = asyncio.Queue(maxsize=q_size)
        
        async def subscription_worker():
            while True:
                try:
                    message = await queue.get()
                    try:
                        if inspect.iscoroutinefunction(handler):
                            await handler(message)
                        else:
                            handler(message)
                    except Exception as e:
                        logger.error(
                            f"Error in subscription handler '{name}' for message type {message_type.__name__}: {e}",
                            exc_info=True
                        )
                    finally:
                        try:
                            queue.task_done()
                        except Exception:
                            pass
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in worker task '{name}': {e}", exc_info=True)

        task = asyncio.create_task(subscription_worker(), name=f"bus-sub-{name}")
        sub = Subscription(name=name, message_type=message_type, queue=queue, handler=handler, task=task)
        self._subscriptions.append(sub)
        self._tasks.append(task)
        return sub

    async def publish(self, message: Any) -> None:
        msg_type = type(message)
        for sub in self._subscriptions:
            if issubclass(msg_type, sub.message_type):
                try:
                    sub.queue.put_nowait(message)
                except asyncio.QueueFull:
                    sub.dropped_count += 1
                    if self.overflow_policy == "DROP_OLDEST":
                        try:
                            sub.queue.get_nowait()
                            sub.queue.task_done()
                            sub.queue.put_nowait(message)
                            logger.warning(
                                f"Subscription queue overflow for subscriber '{sub.name}'. Dropped oldest message."
                            )
                            continue
                        except asyncio.QueueEmpty:
                            pass
                    logger.warning(
                        f"Subscription queue overflow for subscriber '{sub.name}'. Dropping message of type {msg_type.__name__}."
                    )

    async def start(self) -> None:
        self._is_started = True
        logger.info("Event bus started.")

    async def drain(self, timeout: float = 5.0) -> None:
        async def wait_for_queues():
            for sub in list(self._subscriptions):
                if not sub.queue.empty():
                    try:
                        await sub.queue.join()
                    except Exception:
                        pass
                
        try:
            await asyncio.wait_for(wait_for_queues(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("Event bus drain timed out.")
        except Exception:
            pass

    async def stop(self) -> None:
        self._is_started = False
        for sub in list(self._subscriptions):
            sub.task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._subscriptions.clear()
