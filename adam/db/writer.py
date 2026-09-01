import asyncio
import logging
from typing import Tuple, List, Optional
from adam.common.config import DbSettings
from adam.db.connection import DbConnection

logger = logging.getLogger("adam.db.writer")

class DbWriter:
    def __init__(self, db_conn: DbConnection, settings: DbSettings) -> None:
        self.db_conn = db_conn
        self.batch_size = settings.batch_size
        self.batch_interval = settings.batch_interval_ms / 1000.0
        self.queue: asyncio.Queue[Tuple[str, tuple]] = asyncio.Queue(maxsize=10000)
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    def enqueue(self, sql: str, params: tuple = ()) -> None:
        try:
            self.queue.put_nowait((sql, params))
        except asyncio.QueueFull:
            logger.warning("DB writer queue full! Dropping database write operation.")

    async def start(self) -> None:
        self._running = True
        try:
            self.queue.get_nowait()
        except (asyncio.QueueEmpty, RuntimeError):
            pass
        # Recreate queue for the current running loop if needed
        self.queue = asyncio.Queue(maxsize=10000)
        self._worker_task = asyncio.create_task(self._worker_loop(), name="db-writer-worker")
        logger.info("Database writer worker task started.")

    async def stop(self) -> None:
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        await self._drain_remaining()
        logger.info("Database writer worker task stopped.")

    async def _worker_loop(self) -> None:
        while self._running:
            try:
                sql, params = await self.queue.get()
                batch = [(sql, params)]
                self.queue.task_done()

                start_time = asyncio.get_event_loop().time()
                while len(batch) < self.batch_size:
                    timeout = self.batch_interval - (asyncio.get_event_loop().time() - start_time)
                    if timeout <= 0:
                        break
                    try:
                        sql, params = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                        batch.append((sql, params))
                        self.queue.task_done()
                    except asyncio.TimeoutError:
                        break

                await self._write_batch(batch)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in DB writer loop: {e}", exc_info=True)
                await asyncio.sleep(1.0)

    async def _write_batch(self, batch: List[Tuple[str, tuple]]) -> None:
        conn = await self.db_conn.connect()
        for attempt in range(10):
            try:
                for sql, params in batch:
                    await conn.execute(sql, params)
                await conn.commit()
                return
            except Exception as e:
                logger.warning(f"Database batch write attempt {attempt + 1} failed ({e}), retrying...")
                try:
                    await conn.rollback()
                except Exception:
                    pass
                await asyncio.sleep(0.02 * (attempt + 1))
        logger.error(f"Failed to commit database batch of size {len(batch)} after retries.")

    async def _drain_remaining(self) -> None:
        batch = []
        while not self.queue.empty():
            try:
                sql, params = self.queue.get_nowait()
                batch.append((sql, params))
                self.queue.task_done()
            except Exception:
                break
        if batch:
            logger.info(f"Draining remaining {len(batch)} database writes...")
            await self._write_batch(batch)
