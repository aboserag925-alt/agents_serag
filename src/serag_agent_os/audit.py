import hashlib
import json
from datetime import datetime, timezone


class AuditLog:
    def __init__(self):
        self._events: list[dict] = []

    def append(self, event: str, task_id: str, details: dict | None = None) -> dict:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "task_id": task_id,
            "details": details or {},
            "previous_hash": self._events[-1]["hash"] if self._events else "GENESIS",
        }
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        record = {**payload, "hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}
        self._events.append(record)
        return dict(record)

    def verify(self) -> bool:
        previous = "GENESIS"
        for record in self._events:
            payload = {k: v for k, v in record.items() if k != "hash"}
            canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if record["previous_hash"] != previous or record["hash"] != expected:
                return False
            previous = record["hash"]
        return True

    def events(self) -> tuple[dict, ...]:
        return tuple(dict(event) for event in self._events)
