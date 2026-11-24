import pytest

from serag_agent_os import SeragOrchestrator, TaskRequest, TaskStatus
from serag_agent_os.registry import AgentRegistry
from serag_agent_os.models import AgentSpec


def make_os():
    registry = AgentRegistry([
        AgentSpec("admin", "إداري", ("report",)),
        AgentSpec("finance", "مالي", ("budget",)),
    ])
    return SeragOrchestrator(registry)


def test_protected_task_waits_for_approval():
    os = make_os()
    task = os.submit(TaskRequest("دفع", "فاتورة", "budget", risk="high"))
    assert task.status == TaskStatus.AWAITING_APPROVAL
    with pytest.raises(PermissionError):
        os.run(task.id)


def test_approved_task_runs_registered_handler():
    os = make_os()
    os.register_handler("report", lambda task: {"ok": True})
    task = os.submit(TaskRequest("تقرير", "ملخص", "report"))
    assert os.run(task.id).status == TaskStatus.COMPLETED


def test_external_write_requires_approval_even_when_low_risk():
    os = make_os()
    task = os.submit(TaskRequest("نشر", "منشور", "report", action="publish"))
    assert task.status == TaskStatus.AWAITING_APPROVAL


def test_wrong_approval_cannot_unlock_task():
    os = make_os()
    task = os.submit(TaskRequest("دفع", "فاتورة", "budget", risk="critical"))
    with pytest.raises(PermissionError):
        os.approve(task.id, "not-the-token")


def test_idempotency_key_prevents_duplicate_tasks():
    os = make_os()
    request = TaskRequest("تقرير", "ملخص", "report", idempotency_key="same-request")
    first = os.submit(request)
    second = os.submit(request)
    assert first.id == second.id
    assert len(os.tasks) == 1


def test_unknown_capability_is_rejected():
    os = make_os()
    with pytest.raises(ValueError):
        os.submit(TaskRequest("مهمة", "وصف", "not-registered"))


def test_audit_chain_verifies():
    os = make_os()
    os.submit(TaskRequest("تقرير", "ملخص", "report"))
    assert os.audit.verify()
