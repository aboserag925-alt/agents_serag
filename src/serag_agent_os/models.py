from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TaskStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass(frozen=True)
class AgentSpec:
    id: str
    name_ar: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class TaskRequest:
    title: str
    description: str
    capability: str
    risk: str = "low"
    action: str = "internal_analysis"
    requested_by: str = "owner"
    idempotency_key: str | None = None


@dataclass
class Task:
    id: str
    title: str
    description: str
    capability: str
    risk: str
    action: str
    requested_by: str
    assigned_agent: str
    status: TaskStatus
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    approval_id: str | None = None
    result: Any = None
    error: str | None = None

    @classmethod
    def from_request(cls, request: TaskRequest, agent_id: str, status: TaskStatus):
        return cls(
            id=str(uuid4()), title=request.title, description=request.description,
            capability=request.capability, risk=request.risk, action=request.action,
            requested_by=request.requested_by, assigned_agent=agent_id, status=status,
        )
