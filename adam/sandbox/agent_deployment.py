import os
import hashlib
import asyncio
import logging
from typing import Dict, Any, Optional
import httpx

from adam.common.config import SandboxSettings
from adam.common.timeutil import now_utc, to_iso

logger = logging.getLogger("adam.sandbox.agent_deployment")

HOST_AGENT_PATH = os.path.join(os.path.dirname(__file__), "guest", "agent", "adam_agent.ps1")

class AgentDeploymentManager:
    """
    Automatic Guest Agent Deployment & Synchronization Manager.
    Computes SHA-256 hashes of host canonical adam_agent.ps1, queries the guest VM,
    and atomically deploys updates with zero manual copying or VM reboots.
    """
    def __init__(self, settings: SandboxSettings) -> None:
        self.settings = settings
        self.source_path = os.path.abspath(HOST_AGENT_PATH)
        self.agent_base_url = f"http://127.0.0.1:{settings.hostfwd_port_host}"
        self._last_deployed_hash: Optional[str] = None
        self._deployment_lock = asyncio.Lock()
        self._deployment_log: list[Dict[str, Any]] = []

    def calculate_host_hash(self) -> str:
        """Computes SHA-256 of the host-side canonical adam_agent.ps1."""
        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Host agent script not found at {self.source_path}")
        with open(self.source_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def get_host_version(self) -> str:
        """Extracts version string from host-side adam_agent.ps1 header."""
        if not os.path.exists(self.source_path):
            return "unknown"
        try:
            with open(self.source_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "$agentVersion" in line and "=" in line:
                        parts = line.split("=", 1)
                        return parts[1].strip().strip('"').strip("'").strip()
        except Exception:
            pass
        return "1.0.0"

    async def query_guest_status(self) -> Dict[str, Any]:
        """Queries the running guest agent for heartbeat, version, and running script hash."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self.agent_base_url}/heartbeat")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "reachable": True,
                        "status": data.get("status", "alive"),
                        "guest_version": data.get("agent_version", "1.0.0"),
                        "guest_sha256": data.get("agent_sha256", ""),
                        "guest_pid": data.get("pid"),
                        "guest_instance_count": data.get("instance_count", 1)
                    }
        except Exception as e:
            return {
                "reachable": False,
                "status": "unreachable",
                "error": str(e),
                "guest_version": "unknown",
                "guest_sha256": ""
            }
        return {"reachable": False, "status": "unreachable", "guest_version": "unknown", "guest_sha256": ""}

    async def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status comparison between host and guest agent."""
        host_hash = self.calculate_host_hash()
        host_version = self.get_host_version()
        guest_info = await self.query_guest_status()

        guest_hash = guest_info.get("guest_sha256", "")
        reachable = guest_info.get("reachable", False)

        if not reachable:
            sync_status = "GUEST_UNREACHABLE"
        elif host_hash == guest_hash:
            sync_status = "CURRENT"
        else:
            sync_status = "UPDATE_AVAILABLE"

        return {
            "sync_status": sync_status,
            "host": {
                "version": host_version,
                "sha256": host_hash,
                "path": self.source_path,
                "size_bytes": os.path.getsize(self.source_path) if os.path.exists(self.source_path) else 0
            },
            "guest": {
                "reachable": reachable,
                "version": guest_info.get("guest_version", "unknown"),
                "sha256": guest_hash,
                "status": guest_info.get("status", "unknown"),
                "pid": guest_info.get("guest_pid"),
                "instance_count": guest_info.get("guest_instance_count", 0)
            },
            "history": self._deployment_log[-10:]
        }

    async def ensure_agent_current(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Idempotently checks if the guest agent is running the latest host version.
        If hash mismatch is detected, triggers auto-deployment and atomic restart.
        """
        async with self._deployment_lock:
            status = await self.get_status()
            if status["sync_status"] == "CURRENT":
                logger.debug("Guest agent is already up-to-date (SHA-256 match).")
                return {"status": "SKIPPED", "message": "Agent is already current", "details": status}
            
            if not status["guest"]["reachable"]:
                logger.warning("Cannot auto-deploy agent: Guest is unreachable.")
                return {"status": "FAILED", "message": "Guest is unreachable", "details": status}

            logger.info(f"Agent update detected (Host: {status['host']['sha256'][:10]} != Guest: {status['guest']['sha256'][:10]}). Auto-deploying...")
            return await self._execute_deployment(session_id=session_id, host_hash=status["host"]["sha256"], old_hash=status["guest"]["sha256"])

    async def deploy_agent(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Manually or programmatically force deployment of host agent to guest."""
        async with self._deployment_lock:
            status = await self.get_status()
            return await self._execute_deployment(
                session_id=session_id,
                host_hash=status["host"]["sha256"],
                old_hash=status["guest"]["sha256"]
            )

    async def _execute_deployment(self, session_id: Optional[str], host_hash: str, old_hash: str) -> Dict[str, Any]:
        """Executes the host->guest transfer, atomic verification, and single-instance reload."""
        start_time = now_utc()
        log_entry = {
            "timestamp": to_iso(start_time),
            "session_id": session_id or "sess_continuous_live",
            "old_hash": old_hash,
            "new_hash": host_hash,
            "status": "STARTING",
            "error": None
        }
        self._deployment_log.append(log_entry)

        try:
            with open(self.source_path, "rb") as f:
                agent_bytes = f.read()

            # 1. Transfer to guest via atomic deployment endpoint (/agent/update)
            logger.info("Transferring updated adam_agent.ps1 to guest...")
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.agent_base_url}/agent/update",
                    content=agent_bytes,
                    headers={
                        "X-Agent-Sha256": host_hash,
                        "X-Agent-Version": self.get_host_version()
                    }
                )
                if resp.status_code != 200:
                    raise RuntimeError(f"Guest agent transfer rejected: {resp.text}")

                deploy_resp = resp.json()
                if deploy_resp.get("status") != "staged":
                    raise RuntimeError(f"Unexpected deployment response: {deploy_resp}")

            # 2. Trigger atomic restart in guest
            logger.info("Triggering guest agent atomic restart...")
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp_restart = await client.post(
                    f"{self.agent_base_url}/agent/restart",
                    json={"expected_sha256": host_hash}
                )
                if resp_restart.status_code != 200:
                    raise RuntimeError(f"Agent restart request failed: {resp_restart.text}")

            # 3. Wait for new agent to initialize and verify heartbeat handshake
            logger.info("Verifying new agent heartbeat and SHA-256 handshake...")
            verified = False
            for attempt in range(15):
                await asyncio.sleep(1.0)
                guest_info = await self.query_guest_status()
                if guest_info.get("reachable") and guest_info.get("guest_sha256") == host_hash:
                    verified = True
                    break

            if not verified:
                raise RuntimeError(f"Verification timed out: New agent failed to report matching hash ({host_hash}).")

            self._last_deployed_hash = host_hash
            elapsed = (now_utc() - start_time).total_seconds()
            log_entry["status"] = "SUCCESS"
            log_entry["duration_s"] = round(elapsed, 2)
            logger.info(f"Agent update successfully applied and verified in {elapsed:.2f}s (SHA: {host_hash[:12]}).")

            return {
                "status": "SUCCESS",
                "message": "Guest agent successfully updated and verified.",
                "duration_seconds": elapsed,
                "host_sha256": host_hash,
                "guest_sha256": host_hash
            }

        except Exception as e:
            elapsed = (now_utc() - start_time).total_seconds()
            log_entry["status"] = "FAILED"
            log_entry["error"] = str(e)
            log_entry["duration_s"] = round(elapsed, 2)
            logger.error(f"Agent deployment failed: {e}", exc_info=True)
            return {
                "status": "FAILED",
                "error": str(e),
                "duration_seconds": elapsed
            }
