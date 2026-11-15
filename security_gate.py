import hmac
import os
import re
import threading
import time
from typing import Optional, Dict, Any, Tuple, List

import task_store

# No embedded/default credentials. Configure HUB_AUTH_TOKEN through the
# deployment secret manager before enabling protected operations.
AUTH_TOKEN = os.getenv("HUB_AUTH_TOKEN", "")

SENSITIVE_ACTION_TYPES = {
    "FILE_DELETE": "حذف ملفات أو بيانات من المشروع",
    "SECRETS_UPDATE": "تعديل أو قراءة مفاتيح وأسرار النظام",
    "GIT_PUSH_PROD": "النشر المباشر إلى الإنتاج السحابي",
    "GIT_MERGE_MAIN": "الدمج المباشر إلى الفرع الرئيسي main",
    "EXTERNAL_TRANSACTION": "عمليات مدفوعة أو طلبات لخدمات خارجية بمقابل مالي",
    "BUDGET_EXCEEDED": "تجاوز الميزانية أو سقف استهلاك الرموز المحدد",
    "PROD_CONFIG_CHANGE": "تغيير إعدادات الخدمات السحابية الإنتاجية",
}

SECRET_PATTERNS = [
    (re.compile(r"(api[_-]?key|token|secret|password|passwd|auth[_-]?key)(\\s*[:=]\\s*)(['\\\"][^'\\\"]+['\\\"]|[^\\s,;]+)", re.IGNORECASE), r"\\1\\2***REDACTED_SECRET***"),
    (re.compile(r"(AIza[0-9A-Za-z\\-_]{35})"), "***REDACTED_GOOGLE_KEY***"),
    (re.compile(r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"), "***REDACTED_GITHUB_TOKEN***"),
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})"), "***REDACTED_OPENAI_KEY***"),
    (re.compile(r"(Bearer\\s+)[A-Za-z0-9_\\-\\.]{15,}", re.IGNORECASE), r"\\1***REDACTED_BEARER***"),
    (re.compile(r"(postgres(ql)?://[^:]+:)([^@]+)(@)", re.IGNORECASE), r"\\1***REDACTED_DB_PWD***\\4"),
]


def mask_secrets(text: str) -> str:
    """Mask common credentials before writing text to logs or UI."""
    if not isinstance(text, str):
        return str(text)
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def mask_dict_secrets(data: Any) -> Any:
    """Recursively mask secret-like dictionary keys and string values."""
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            if any(part in str(key).lower() for part in ("key", "secret", "token", "password", "credential")):
                cleaned[key] = "***REDACTED_SECRET***"
            else:
                cleaned[key] = mask_dict_secrets(value)
        return cleaned
    if isinstance(data, list):
        return [mask_dict_secrets(item) for item in data]
    if isinstance(data, str):
        return mask_secrets(data)
    return data


def is_sensitive_action(action_type: str, details: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, str]:
    """Return whether an action requires explicit human approval."""
    details = details or {}
    action_type = action_type.upper()

    if action_type in SENSITIVE_ACTION_TYPES:
        risk = "HIGH" if action_type in (
            "FILE_DELETE", "SECRETS_UPDATE", "GIT_PUSH_PROD", "EXTERNAL_TRANSACTION"
        ) else "MEDIUM"
        return True, risk, SENSITIVE_ACTION_TYPES[action_type]

    command = details.get("command", "") or details.get("prompt", "")
    if isinstance(command, str):
        if re.search(r"\\b(rm\\s+-rf|dd\\s+if=|mkfs|chmod\\s+-R\\s+777|git\\s+push.*main)\\b", command, re.IGNORECASE):
            return True, "CRITICAL", "أمر تنفيذي عالي الخطورة يتضمن حذفاً واسعاً أو تعديل صلاحيات جذرية"
        if re.search(r"\\b(drop\\s+table|delete\\s+from|truncate)\\b", command, re.IGNORECASE):
            return True, "HIGH", "عملية حذف أو تفريغ لقاعدة البيانات"

    return False, "LOW", "عملية روتينية مسموح بها"


def check_permission_and_gate(
    task_id: str,
    action_type: str,
    actor: str,
    details: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str]]:
    """Create a persisted approval request for sensitive operations."""
    sensitive, risk_level, reason = is_sensitive_action(action_type, details)
    if sensitive:
        approval_id = task_store.create_pending_approval(
            task_id=task_id,
            action_type=action_type,
            description=reason,
            risk_level=risk_level,
            requested_by=actor,
            payload=details,
        )
        task_store.update_task(
            task_id,
            status="BLOCKED",
            error_message=f"تتطلب المهمة موافقة حساسة: {reason} (معرّف الموافقة: {approval_id})",
        )
        return False, approval_id

    task_store.log_audit(f"AUTO_ALLOWED_{action_type}", actor, target=task_id, details=details)
    return True, None


_rate_limit_records: Dict[str, List[float]] = {}
_rate_lock = threading.Lock()


def is_rate_limited(client_ip: str, max_calls: int = 120, period_sec: float = 60.0) -> bool:
    now = time.time()
    with _rate_lock:
        records = [stamp for stamp in _rate_limit_records.get(client_ip, []) if now - stamp < period_sec]
        if len(records) >= max_calls:
            _rate_limit_records[client_ip] = records
            return True
        records.append(now)
        _rate_limit_records[client_ip] = records
        return False


def verify_token(token: Optional[str]) -> bool:
    """
    Fail closed: missing server credential, missing request credential,
    and development bypass strings are all rejected.
    The caller must pass the Authorization header value.
    """
    configured_token = AUTH_TOKEN
    if not configured_token or not token:
        return False

    supplied = token.strip()
    if supplied[:7].lower() == "bearer ":
        supplied = supplied[7:].strip()

    if not supplied:
        return False
    return hmac.compare_digest(supplied, configured_token)
