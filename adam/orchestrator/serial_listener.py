import asyncio
import ctypes
import json
import logging
from typing import Any, Optional
from adam.contracts.raw_event import RawEvent
from adam.common.bus import EventBus

logger = logging.getLogger("uvicorn.error")

INVALID_HANDLE_VALUE = -1
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

class WindowsNamedPipeServer:
    def __init__(self, pipe_name: str, bus: EventBus) -> None:
        self.pipe_name = pipe_name
        self.bus = bus
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._h_pipe: Optional[int] = None
        self._socket_writer = None
        self._sub = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        from adam.contracts.policy_decision import PolicyDecision
        self._sub = self.bus.subscribe(PolicyDecision, self._handle_policy_decision, name="pipe-outbound-decisions")
        logger.info(f"Stealth Serial stream listener initialized for target: {self.pipe_name}")

    async def stop(self) -> None:
        self._running = False
        if self._sub:
            self._sub.task.cancel()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Stealth Serial stream listener stopped.")

    async def _handle_policy_decision(self, decision: PolicyDecision) -> None:
        from adam.api.routers.mutation_tests import _ACTIVE_TEST_SESSIONS
        if decision.session_id != "sess_continuous_live" and decision.session_id not in _ACTIVE_TEST_SESSIONS:
            return
        
        try:
            payload_str = decision.model_dump_json() + "\n"
            payload_bytes = payload_str.encode("utf-8")
            
            if self._socket_writer:
                self._socket_writer.write(payload_bytes)
                await self._socket_writer.drain()
                logger.info(f"Stealth Serial socket wrote policy decision: {decision.action}")
                return

            h_pipe = self._h_pipe
            if h_pipe and h_pipe != INVALID_HANDLE_VALUE:
                logger.info(f"Stealth Pipe writing policy decision: {decision.action}")
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._write_file,
                    h_pipe,
                    payload_bytes
                )
        except Exception as e:
            logger.error(f"Failed to write policy decision to guest serial: {e}", exc_info=True)

    async def _run_loop(self) -> None:
        pipe_name = self.pipe_name
        
        while self._running:
            # First check if TCP socket serial connection (port 8444 or host:port) is configured or available
            is_socket = ":" in pipe_name or pipe_name.isdigit() or pipe_name.startswith("tcp://")
            
            if is_socket or not pipe_name.startswith("\\\\"):
                # Try TCP socket connection
                host = "127.0.0.1"
                port = 8444
                if ":" in pipe_name:
                    parts = pipe_name.replace("tcp://", "").split(":")
                    host = parts[0]
                    port = int(parts[1])
                elif pipe_name.isdigit():
                    port = int(pipe_name)
                    
                try:
                    reader, writer = await asyncio.open_connection(host, port)
                    self._socket_writer = writer
                    logger.info(f"Successfully connected to QEMU VirtIO serial socket ({host}:{port}). Ingesting live telemetry stream...")
                    
                    while self._running and not reader.at_eof():
                        line = await reader.readline()
                        if not line:
                            break
                        line_str = line.strip()
                        if line_str:
                            await self._process_line(line_str)
                            
                except Exception as e:
                    # Retry socket connection
                    pass
                finally:
                    self._socket_writer = None
                await asyncio.sleep(1)

            # Attempt to connect to the duplex pipe created by QEMU
            h_pipe = ctypes.windll.kernel32.CreateFileW(
                pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )

            if h_pipe == INVALID_HANDLE_VALUE:
                # Pipe doesn't exist yet (QEMU is not running)
                await asyncio.sleep(1)
                continue

            self._h_pipe = h_pipe
            logger.info("Successfully connected to QEMU duplex named pipe. Ingesting stream...")
            
            try:
                await self._read_stream(h_pipe)
            except Exception as e:
                logger.error(f"Error reading from serial pipe: {e}")
            
            self._h_pipe = None
            ctypes.windll.kernel32.CloseHandle(h_pipe)
            logger.info("Disconnected from named pipe. Cleaning handle and retrying connection...")
            await asyncio.sleep(1)

    async def _read_stream(self, h_pipe: int) -> None:
        buffer_size = 4096
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_read = ctypes.c_ulong(0)
        bytes_avail = ctypes.c_ulong(0)
        data_acc = b""
        
        while self._running:
            # Non-blocking peek to check connection health and available data
            success = ctypes.windll.kernel32.PeekNamedPipe(
                h_pipe, None, 0, None, ctypes.byref(bytes_avail), None
            )
            
            if not success:
                logger.info("QEMU client pipe broken or closed.")
                break
                
            if bytes_avail.value == 0:
                # No data yet, yield control to prevent CPU spin and allow other tasks to run
                await asyncio.sleep(0.1)
                continue
                
            # Data is available, we can read safely without blocking the thread pool
            read_success = await asyncio.get_event_loop().run_in_executor(
                None,
                self._read_file,
                h_pipe,
                buffer,
                buffer_size,
                ctypes.byref(bytes_read)
            )
            
            if not read_success or bytes_read.value == 0:
                logger.info("Read operation returned 0 bytes or failed.")
                break
                
            data_acc += buffer.raw[:bytes_read.value]
            
            while b"\n" in data_acc:
                line, rest = data_acc.split(b"\n", 1)
                data_acc = rest
                if line.strip():
                    await self._process_line(line.strip())

    async def _process_line(self, line_bytes: bytes) -> None:
        text = line_bytes.decode("utf-8", errors="ignore").strip()
        if not text:
            return
            
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(text):
            # Skip any whitespace or delimiters
            while idx < len(text) and text[idx] in " \r\n\t,;":
                idx += 1
            if idx >= len(text):
                break
                
            try:
                payload, end_idx = decoder.raw_decode(text[idx:])
                idx += end_idx
                
                if isinstance(payload, dict):
                    if "mutation_id" in payload:
                        from adam.contracts.mutation import MutationResult
                        mutation = MutationResult.model_validate(payload)
                        await self.bus.publish(mutation)
                    else:
                        if "event_id" not in payload:
                            import uuid
                            payload["event_id"] = f"raw_{uuid.uuid4().hex[:16]}"
                        if "session_id" not in payload:
                            payload["session_id"] = "sess_continuous_live"
                        if "observed_at" not in payload:
                            from adam.common.timeutil import to_iso, now_utc
                            payload["observed_at"] = to_iso(now_utc())
                        event = RawEvent.model_validate(payload)
                        await self.bus.publish(event)
            except Exception as e:
                # If a corrupted fragment is encountered, advance to next possible JSON object
                next_brace = text.find("{", idx + 1)
                if next_brace != -1:
                    idx = next_brace
                else:
                    break

    def _read_file(self, h_pipe: int, buffer: Any, buffer_size: int, p_bytes_read: Any) -> bool:
        return ctypes.windll.kernel32.ReadFile(
            h_pipe, buffer, buffer_size, p_bytes_read, None
        )

    def _write_file(self, h_pipe: int, data: bytes) -> bool:
        bytes_written = ctypes.c_ulong(0)
        return ctypes.windll.kernel32.WriteFile(
            h_pipe, data, len(data), ctypes.byref(bytes_written), None
        )
