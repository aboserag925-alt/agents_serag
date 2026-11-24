from uuid import uuid4


class ApprovalManager:
    PROTECTED_ACTIONS = {
        "external_write", "publish", "financial_transaction",
        "moodle_write", "send_message", "delete_data",
    }
    PROTECTED_RISKS = {"high", "critical"}

    def __init__(self):
        self._pending: dict[str, str] = {}

    def required(self, risk: str, action: str) -> bool:
        return risk in self.PROTECTED_RISKS or action in self.PROTECTED_ACTIONS

    def request(self, task_id: str) -> str:
        approval_id = str(uuid4())
        self._pending[approval_id] = task_id
        return approval_id

    def approve(self, approval_id: str, task_id: str) -> bool:
        return self._pending.pop(approval_id, None) == task_id

    def reject(self, approval_id: str, task_id: str) -> bool:
        return self._pending.pop(approval_id, None) == task_id
