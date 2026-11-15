import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

logger = logging.getLogger("agents-hub.secrets")

# In-memory runtime secrets vault (never exposed to frontend/browser)
_RUNTIME_VAULT: Dict[str, str] = {}
_VAULT_LOADED = False

def load_local_env_file():
    """Safely reads .env if present in the project directory."""
    if not ENV_FILE.exists():
        return
    try:
        content = ENV_FILE.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception as e:
        logger.warning(f"Notice reading local .env: {e}")

def init_secrets() -> Dict[str, Any]:
    global _VAULT_LOADED
    load_local_env_file()

    env_name = os.getenv("APP_ENV", "development").lower()
    client_id = os.getenv("INFISICAL_CLIENT_ID")
    client_secret = os.getenv("INFISICAL_CLIENT_SECRET")
    project_id = os.getenv("INFISICAL_PROJECT_ID")

    infisical_configured = bool(client_id and client_secret and project_id)
    connected = False
    status_message = "بيئة محلية — يتم تحميل المتغيرات من نظام التشغيل."

    if infisical_configured:
        # In cloud staging/production with Infisical Machine Identity
        try:
            import urllib.request
            auth_url = os.getenv("INFISICAL_SITE_URL", "https://app.infisical.com") + "/api/v1/auth/universal-auth/login"
            payload = json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode("utf-8")
            req = urllib.request.Request(auth_url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    connected = True
                    status_message = f"متصل رسمياً بـ Infisical (البيئة: {env_name})"
        except Exception as e:
            status_message = f"تعذر الاتصال بـ Infisical Machine Identity: {str(e)[:100]}"
            connected = False
    else:
        if env_name in ("staging", "production"):
            status_message = "Infisical غير مهيأ بعد — يتطلب إعداد Machine Identity في السيرفر السحابي."
        else:
            status_message = "بيئة تطوير محلية (Development) — جاهز للتكامل مع Infisical."

    # Cache standard non-secret / secret keys available in environment
    known_keys = [
        "PORT", "HOST", "APP_ENV", "HUB_AUTH_TOKEN", "ALLOWED_ORIGINS",
        "GEMINI_API_KEY", "DATABASE_URL", "INFISICAL_PROJECT_ID"
    ]
    for k in known_keys:
        val = os.getenv(k)
        if val:
            _RUNTIME_VAULT[k] = val

    _VAULT_LOADED = True
    return {
        "connected": connected,
        "environment": env_name,
        "infisical_configured": infisical_configured,
        "status_message": status_message
    }

def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    if not _VAULT_LOADED:
        init_secrets()
    return _RUNTIME_VAULT.get(key, os.getenv(key, default))

def get_secrets_status() -> Dict[str, Any]:
    env_name = os.getenv("APP_ENV", "development").lower()
    client_id = bool(os.getenv("INFISICAL_CLIENT_ID"))
    client_secret = bool(os.getenv("INFISICAL_CLIENT_SECRET"))
    project_id = bool(os.getenv("INFISICAL_PROJECT_ID"))
    
    # List of variable names that have been loaded (VALUES ARE NEVER RETURNED!)
    loaded_var_names = [k for k, v in _RUNTIME_VAULT.items() if v]

    return {
        "environment": env_name,
        "infisical_configured": bool(client_id and client_secret and project_id),
        "infisical_client_id_present": client_id,
        "infisical_client_secret_present": client_secret,
        "infisical_project_id_present": project_id,
        "loaded_keys_count": len(loaded_var_names),
        "loaded_keys_names": loaded_var_names,
        "vault_active": True
    }

# Auto-initialize
init_secrets()
