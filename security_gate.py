import os
import re
import hmac
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
import task_store

BASE_DIR = Path(__file__).resolve().parent

# Authentication fails closed: no built-in token and no development bypass.
AUTH_TOKEN = os.getenv("HUB_AUTH_TOKEN")

# Sensitive Actions requiring explicit approval
SENSITIVE_ACTION_TYPES = {
    "FILE_DELETE": "حذف ملفات أو بيانات من المشروع",
    "SECRETS_UPDATE": "تعديل أو قراءة مفاتيح وأسرار النظام",
    "GIT_PUSH_PROD": "النشر المباشر إلى الإنتاج السحابي",
    "GIT_MERGE_MAIN": "الدمج المباشر إلى الفرع الرئيسي main",
    "EXTERNAL_TRANSACTION": "عمليات مدفوعة أو طلبات لخدمات خارجية بمقابل مالي",
    "BUDGET_EXCEEDED": "تجاوز الميزانية أو سقف استهلاك الرموز المحدد",
    "PROD_CONFIG_CHANGE": "تغيير إعدادات الخدمات السحابية الإنتاجية"
}

# Regex patterns for detecting and redacting sensitive data
SECRET_PATTERNS = [
    (re.compile(r"(api[_-]?key|token|secret|password|passwd|auth[_-]?key)(\s*[:=]\s*)(['\"][^'\"]+['\"]|[^\s,;]+)", re.IGNORECASE), r"\1\2***REDACTED_SECRET***"),
    (re.compile(r"(AIza[0-9A-Za-z\-_]{35})"), "***REDACTED_GOOGLE_KEY***"),
    (re.compile(r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"), "***REDACTED_GITHUB_TOKEN***"),
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})"), "***REDACTED_OPENAI_KEY***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE), r"\1***REDACTED_BEARER***"),
    (re.compile(r"(postgres(ql)?:\/\/[^:]+:)([^@]+)(@)", re.IGNORECASE), r"\1***REDACTED_DB_PWD***\4"),
]

def mask_secrets(text: str) -> str:
    """Masks secrets and tokens from text or log outputs."""
    if not isinstance(text, str):
        return str(text)
    sanitized = text
    for pattern, repl in SECRET_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized

def mask_dict_secrets(data: Any) -> Any:
    """Recursively masks sensitive keys and values in dictionaries or lists."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if any(s in k.lower() for s in ["key", "secret", "token", "password", "credential"]):
                cleaned[k] = "***REDACTED_SECRET***"
            else:
                cleaned[k] = mask_dict_secrets(v)
        return cleaned
    elif isinstance(data, list):
        return [mask_dict_secrets(item) for item in data]
    elif isinstance(data, str):
        return mask_secrets(data)
    return data

def is_sensitive_action(action_type: str, details: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, str]:
    """
    Checks if an action requires explicit user approval.
    Returns (is_sensitive, risk_level, reason)
    """
    details = details or {}
    action_type = action_type.upper()

    if action_type in SENSITIVE_ACTION_TYPES:
        risk_level = "HIGH" if action_type in ("FILE_DELETE", "SECRETS_UPDATE", "GIT_PUSH_PROD", "EXTERNAL_TRANSACTION") else "MEDIUM"
        return True, risk_level, SENSITIVE_ACTION_TYPES[action_type]

    # Inspect command line or prompt for dangerous patterns
    cmd = details.get("command", "") or details.get("prompt", "")
    if isinstance(cmd, str):
        if re.search(r"\b(rm\s+-rf|dd\s+if=|mkfs|chmod\s+-R\s+777|git\s+push.*main)\b", cmd, re.IGNORECASE):
            return True, "CRITICAL", "أمر تنفيذي عالي الخطورة يتضمن حذفاً واسعاً أو تعديل صلاحيات جذرية"
        if re.search(r"\b(drop\s+table|delete\s+from|truncate)\b", cmd, re.IGNORECASE):
            return True, "HIGH", "عملية حذف أو تفريغ لقاعدة البيانات"

    return False, "LOW", "عملية روتينية مسموح بها"

def check_permission_and_gate(task_id: str, action_type: str, actor: str, details: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
    """
    Gates an action: If sensitive, registers a pending approval and returns (False, approval_id).
    If routine, logs and returns (True, None).
    """
    is_sensitive, risk_level, reason = is_sensitive_action(action_type, details)
    if is_sensitive:
        approval_id = task_store.create_pending_approval(
            task_id=task_id,
            action_type=action_type,
            description=reason,
            risk_level=risk_level,
            requested_by=actor,
            payload=details
        )
        task_store.update_task(task_id, status="BLOCKED", error_message=f"تتطلب المهمة موافقة حساسة: {reason} (معرّف الموافقة: {approval_id})")
        return False, approval_id

    # Routine allowed
    task_store.log_audit(f"AUTO_ALLOWED_{action_type}", actor, target=task_id, details=details)
    return True, None

# Simple Rate Limiter
_rate_limit_records: Dict[str, List[float]] = {}
_rate_lock = threading.Lock()

def is_rate_limited(client_ip: str, max_calls: int = 120, period_sec: float = 60.0) -> bool:
    now = time.time()
    with _rate_lock:
        records = _rate_limit_records.setdefault(client_ip, [])
        _rate_limit_records[client_ip] = [t for t in records if now - t < period_sec]
        if len(_rate_limit_records[client_ip]) >= max_calls:
            return True
        _rate_limit_records[client_ip].append(now)
        return False

def verify_token(token: Optional[str]) -> bool:
    """Validate a configured bearer token; reject missing configuration and all bypasses."""
    expected = AUTH_TOKEN or os.getenv("HUB_AUTH_TOKEN")
    if not isinstance(expected, str) or not expected.strip():
        return False
    if not isinstance(token, str) or not token.strip():
        return False
    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()
    if not clean_token:
        return False
    return hmac.compare_digest(clean_token, expected.strip())
