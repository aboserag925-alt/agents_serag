from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

from .approvals import ApprovalManager
from .audit import AuditLog
from .models import Task, TaskRequest, TaskStatus
from .registry import AgentRegistry


Handler = Callable[[Task], Any]
ALLOWED_ACTIONS = {
    "internal_analysis", "external_write", "publish",
    "financial_transaction", "moodle_write", "send_message", "delete_data",
}


class SeragOrchestrator:
    def __init__(self, registry: AgentRegistry, handlers: dict[str, Handler] | None = None):
        self.registry = registry
        self.handlers = handlers or {}
        self.approvals = ApprovalManager()
        self.audit = AuditLog()
        self.tasks: dict[str, Task] = {}
        self._idempotency: dict[str, str] = {}

    @classmethod
    def default(cls):
        config = Path(__file__).resolve().parents[2] / "config" / "agents.json"
        return cls(AgentRegistry.from_file(config))

    def register_handler(self, capability: str, handler: Handler) -> None:
        self.registry.for_capability(capability)
        self.handlers[capability] = handler

    def submit(self, request: TaskRequest) -> Task:
        if not request.title.strip() or not request.description.strip():
            raise ValueError("Task title and description are required")
        if request.risk not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid risk level")
        if request.action not in ALLOWED_ACTIONS:
            raise ValueError("Invalid or unrecognized action")
        if request.idempotency_key and request.idempotency_key in self._idempotency:
            existing = self.tasks[self._idempotency[request.idempotency_key]]
            same_request = (
                existing.title == request.title
                and existing.description == request.description
                and existing.capability == request.capability
                and existing.risk == request.risk
                and existing.action == request.action
                and existing.requested_by == request.requested_by
            )
            if not same_request:
                raise ValueError("Idempotency key was already used for a different request")
            return existing
        agent = self.registry.for_capability(request.capability)
        task = Task.from_request(request, agent.id, TaskStatus.QUEUED)
        if self.approvals.required(request.risk, request.action):
            task.status = TaskStatus.AWAITING_APPROVAL
            task.approval_id = self.approvals.request(task.id)
        self.tasks[task.id] = task
        if request.idempotency_key:
            self._idempotency[request.idempotency_key] = task.id
        self.audit.append("task_submitted", task.id, {"agent": agent.id, "status": task.status.value})
        return task

    def approve(self, task_id: str, approval_id: str) -> Task:
        task = self.tasks[task_id]
        if task.status != TaskStatus.AWAITING_APPROVAL or not self.approvals.approve(approval_id, task_id):
            raise PermissionError("Approval is invalid, expired, or belongs to another task")
        task.status = TaskStatus.QUEUED
        task.approval_id = None
        task.updated_at = datetime.now(timezone.utc).isoformat()
        self.audit.append("task_approved", task.id)
        return task

    def reject(self, task_id: str, approval_id: str) -> Task:
        task = self.tasks[task_id]
        if task.status != TaskStatus.AWAITING_APPROVAL or not self.approvals.reject(approval_id, task_id):
            raise PermissionError("Approval is invalid, expired, or belongs to another task")
        task.status = TaskStatus.REJECTED
        task.approval_id = None
        task.updated_at = datetime.now(timezone.utc).isoformat()
        self.audit.append("task_rejected", task.id)
        return task

    def run(self, task_id: str) -> Task:
        task = self.tasks[task_id]
        if task.status != TaskStatus.QUEUED:
            raise PermissionError("Only queued and approved tasks can run")
        handler = self.handlers.get(task.capability)
        if handler is None:
            raise RuntimeError(f"No execution handler registered for {task.capability}")
        task.status = TaskStatus.RUNNING
        task.updated_at = datetime.now(timezone.utc).isoformat()
        self.audit.append("task_started", task.id, {"agent": task.assigned_agent})
        try:
            task.result = handler(task)
            task.status = TaskStatus.COMPLETED
            self.audit.append("task_completed", task.id)
        except Exception as exc:
            task.error = f"{type(exc).__name__}: {exc}"
            task.status = TaskStatus.FAILED
            self.audit.append("task_failed", task.id, {"error_type": type(exc).__name__})
        finally:
            task.updated_at = datetime.now(timezone.utc).isoformat()
        return task

    def status(self, task_id: str) -> dict:
        task = self.tasks[task_id]
        return {
            "id": task.id, "title": task.title, "agent": task.assigned_agent,
            "status": task.status.value, "approval_required": task.approval_id is not None,
            "result": task.result, "error": task.error,
        }
