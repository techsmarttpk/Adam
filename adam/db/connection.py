import os
import asyncio
import aiosqlite
import logging
from typing import Optional
from adam.common.config import DbSettings

logger = logging.getLogger("adam.db.connection")

class DbConnection:
    def __init__(self, settings: DbSettings) -> None:
        self.db_path = settings.path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> aiosqlite.Connection:
        if self._conn is not None:
            try:
                # Test connection responsiveness
                await self._conn.execute("SELECT 1;")
                return self._conn
            except Exception:
                try:
                    await self._conn.close()
                except Exception:
                    pass
                self._conn = None

        dir_name = os.path.dirname(self.db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        logger.info(f"Connecting to SQLite database at {self.db_path}")
        self._conn = await aiosqlite.connect(self.db_path, timeout=60.0)
        
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA synchronous=OFF;")
        await self._conn.execute("PRAGMA busy_timeout=60000;")
        await self._conn.commit()

        await self._init_schema()
        return self._conn

    async def _init_schema(self) -> None:
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        if not os.path.exists(schema_path):
            logger.warning(f"Schema file not found at {schema_path}, skipping schema initialization.")
            return

        with open(schema_path, "r") as f:
            schema_sql = f.read()

        logger.info("Initializing SQLite database schema...")
        assert self._conn is not None
        await self._conn.executescript(schema_sql)
        await self._conn.commit()

    async def disconnect(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
            logger.info("Disconnected from SQLite database.")
