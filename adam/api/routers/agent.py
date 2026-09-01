from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, Optional
from pydantic import BaseModel
import adam.api.deps as deps

router = APIRouter(prefix="/api/v1/agent", tags=["Guest Agent Manager"])

class DeployRequest(BaseModel):
    session_id: Optional[str] = "sess_continuous_live"
    force: Optional[bool] = False

@router.get("/status")
async def get_agent_status() -> Dict[str, Any]:
    """Returns real-time synchronization status and SHA-256 hash comparison between host and guest agent."""
    manager = deps.agent_deployment_manager
    return await manager.get_status()

@router.post("/deploy")
async def deploy_agent(req: Optional[DeployRequest] = None) -> Dict[str, Any]:
    """Triggers automatic synchronization, atomic upload, verification, and reload of adam_agent.ps1 in the guest VM."""
    manager = deps.agent_deployment_manager
    session_id = req.session_id if req else "sess_continuous_live"
    res = await manager.deploy_agent(session_id=session_id)
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=500, detail=res.get("error", "Deployment failed"))
    return res

@router.post("/restart")
async def restart_agent(req: Optional[DeployRequest] = None) -> Dict[str, Any]:
    """Forces restart of the single guest agent process without modifying the script."""
    manager = deps.agent_deployment_manager
    session_id = req.session_id if req else "sess_continuous_live"
    res = await manager.deploy_agent(session_id=session_id)
    return res
