import asyncio
import logging
import os
from typing import Optional
from adam.common.errors import VMOperationError
from adam.common.config import SandboxSettings

logger = logging.getLogger("adam.sandbox.qemu.client")

class QemuClient:
    def __init__(self, settings: SandboxSettings) -> None:
        self.settings = settings
        self.qemu_process: Optional[asyncio.subprocess.Process] = None
        self.overlay_path = os.path.join("artifacts", "qemu_active_overlay.qcow2")

    async def start(self) -> None:
        """Starts the QEMU virtual machine in the background using active overlay."""
        if not os.path.exists(self.overlay_path):
            raise VMOperationError(f"Active overlay file not found at {self.overlay_path}. Call prepare() first.")

        accel_flags = ["-accel", "whpx", "-accel", "tcg"] if os.name == "nt" else ["-enable-kvm"]
        netdev = "user,id=net0,restrict=on"
        if self.settings.network_mode == "INTERNET":
            netdev = "user,id=net0"
        netdev = f"{netdev},hostfwd=tcp:127.0.0.1:{self.settings.hostfwd_port_host}-:{self.settings.hostfwd_port_guest}"
        
        cmd = [
            self.settings.qemu_system_path,
            "-m", str(self.settings.memory_mb),
            "-smp", str(self.settings.cpu_count),
            *accel_flags,
            "-drive", f"file={self.overlay_path},format=qcow2",
            "-netdev", netdev,
            "-device", "e1000,netdev=net0"
        ]
        
        if os.name != "nt":
            cmd.append("-nographic")

        logger.info(f"Launching QEMU process: {' '.join(cmd)}")
        try:
            self.qemu_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            logger.info(f"QEMU process started with PID {self.qemu_process.pid}")
        except Exception as e:
            raise VMOperationError(f"Failed to start QEMU process: {e}")

    async def stop(self) -> None:
        """Stops the QEMU process by sending a terminate signal or killing it."""
        if not self.qemu_process:
            return
            
        logger.info("Stopping QEMU process...")
        try:
            self.qemu_process.terminate()
            try:
                await asyncio.wait_for(self.qemu_process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("QEMU did not terminate gracefully, killing process...")
                self.qemu_process.kill()
                await self.qemu_process.wait()
        except Exception as e:
            logger.error(f"Error terminating QEMU process: {e}")
        finally:
            self.qemu_process = None
            logger.info("QEMU process stopped.")

    @property
    def is_running(self) -> bool:
        return self.qemu_process is not None and self.qemu_process.returncode is None
