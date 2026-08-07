"""
adam/contracts/session.py

AnalysisSession -- ARCHITECTURE.md section 7.6. The top-level record for one
detonation: which sample, which experimental arm, what config it ran under,
and the aggregate metrics used for the paper's behavioural-yield comparison
(section 2.3).

`SampleRef` is also defined here rather than in a separate file: Phase 2's
file list (docs/dev-a-environment-and-roadmap.md) does not include a
dedicated sample.py, and section 7.6's `sample` object has no other home.
It is also the type `ISandboxController.detonate()` accepts (section
5.2/7.6 cross-reference) -- see interfaces.py.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from adam.contracts.enums import Arm, NetworkMode, SessionStatus


class SessionLifecycle(BaseModel):
    """
    Published onto the bus at each major session transition (section 8.4).
    Moved from adam/orchestrator/session.py to here for better dependency management.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    status: SessionStatus
    detail: str
    occurred_at: datetime

class SampleRef(BaseModel):
    """
    AnalysisSession.sample -- ARCHITECTURE.md section 7.6 example. Also the
    parameter type of `ISandboxController.detonate()` (interfaces.py),
    matching docs/dev-a-environment-and-roadmap.md's
    `async def detonate(self, sample: SampleRef) -> None`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sha256: str = Field(min_length=64, max_length=64)
    md5: str = Field(min_length=32, max_length=32)
    filename: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    file_type: str = Field(min_length=1)

    @field_validator("sha256")
    @classmethod
    def _sha256_is_hex(cls, value: str) -> str:
        return _require_hex(value, "sha256")

    @field_validator("md5")
    @classmethod
    def _md5_is_hex(cls, value: str) -> str:
        return _require_hex(value, "md5")


def _require_hex(value: str, field_name: str) -> str:
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a hex digest, got {value!r}") from exc
    return value.lower()


class SessionConfig(BaseModel):
    """AnalysisSession.config -- ARCHITECTURE.md section 7.6 example."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    deception_enabled: bool
    policy_ruleset: str = Field(min_length=1)
    vm_profile: str = Field(min_length=1)
    timeout_seconds: int = Field(gt=0)
    network_mode: NetworkMode


class SessionMetrics(BaseModel):
    """
    AnalysisSession.metrics -- ARCHITECTURE.md section 7.6 example. All
    counters default to 0 so a session can be constructed as soon as it
    starts (before any events exist) and updated in place as it progresses.
    """

    model_config = ConfigDict(extra="forbid")

    raw_events: int = Field(default=0, ge=0)
    semantic_events: int = Field(default=0, ge=0)
    decisions_total: int = Field(default=0, ge=0)
    decisions_executed: int = Field(default=0, ge=0)
    mutations_applied: int = Field(default=0, ge=0)
    semantic_events_post_mutation: int = Field(default=0, ge=0)


class AnalysisSession(BaseModel):
    """See module docstring. Matches the JSON shape in section 7.6 exactly."""

    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1)
    experiment_id: str = Field(min_length=1)
    arm: Arm
    sample: SampleRef
    config: SessionConfig
    status: SessionStatus
    started_at: datetime
    ended_at: datetime | None = None
    metrics: SessionMetrics = Field(default_factory=SessionMetrics)
    error: str | None = None

    @field_validator("started_at", "ended_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "started_at/ended_at must be timezone-aware (UTC), "
                "per ARCHITECTURE.md section 5.1"
            )
        return value
