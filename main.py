import os
import sys
import json
import time
import signal
import socket
import re
import shutil
import shlex
import subprocess
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, WebSocket, WebSocketDisconnect, Header
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import task_store
import security_gate
import secrets_manager
import maestro_engine

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
AGENTS_FILE = BASE_DIR / "agents.json"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# CORS Allowed Origins
# Cross-origin access is opt-in. Never combine wildcard origins with credentials.
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
origins = [
    origin.strip()
    for origin in allowed_origins_env.split(",")
    if origin.strip() and origin.strip() != "*"
]

# Lifespan for 24/7 Resilience & Startup Reconciliation
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Startup Recovery: Reconcile orphan tasks after any unexpected restart
    reconciliation = task_store.reconcile_orphan_tasks()
    print(f"[24/7 BOOT RECOVERY] Tasks Reconciled: {reconciliation}")
    maestro_engine.MaestroOrchestrator.register_agent_states()
    task_store.log_audit("SERVER_STARTUP", "System", details={"reconciliation": reconciliation})
    yield
    # 2. Graceful Shutdown
    print("[SERVER SHUTDOWN] Cleaning up resources gracefully...")
    task_store.log_audit("SERVER_SHUTDOWN", "System")

app = FastAPI(
    title="Autonomous Agents Hub 24/7",
    description="منصة الوكلاء الذكية المستقلة الموحدة — مدارة بواسطة Maestro على مدار الساعة",
    version="2.0.0",
    lifespan=lifespan
)

@app.middleware("http")
async def protect_api_routes(request: Request, call_next):
    """Require the configured bearer token for every HTTP API endpoint."""
    if request.url.path.startswith("/api/"):
        if not security_gate.verify_token(request.headers.get("authorization")):
            return JSONResponse(
                status_code=401,
                content={"detail": "غير مصرح: يلزم رمز HUB_AUTH_TOKEN صالح"}
            )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

managed_processes: Dict[str, Dict[str, Any]] = {}

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        # Accept first, but do not expose this socket to broadcasts before auth.
        await websocket.accept()

    def register_authenticated(self, websocket: WebSocket):
        if websocket not in self.active_connections:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Hook Maestro broadcast events into WebSocket manager
def handle_maestro_event(event: Dict[str, Any]):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast(event))
    except Exception:
        pass

maestro_engine.subscribe_events(handle_maestro_event)

def clean_ansi(text: str) -> str:
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_regex.sub('', text)

def load_agents() -> List[Dict[str, Any]]:
    if not AGENTS_FILE.exists():
        return []
    try:
        with open(AGENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading agents.json: {e}", file=sys.stderr)
        return []

def is_port_listening(port: Optional[int]) -> bool:
    if not port:
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            return s.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False

def find_running_pid(pattern: Optional[str], agent_id: str) -> Optional[int]:
    # 1. Check in-memory managed process
    if agent_id in managed_processes:
        info = managed_processes[agent_id]
        pid = info.get("pid")
        if pid and os.path.exists(f"/proc/{pid}"):
            return pid
        else:
            managed_processes.pop(agent_id, None)

    # 2. Check saved pidfile
    pidfile = LOGS_DIR / f"{agent_id}.pid"
    if pidfile.exists():
        try:
            saved_pid = int(pidfile.read_text().strip())
            if os.path.exists(f"/proc/{saved_pid}"):
                return saved_pid
            else:
                pidfile.unlink(missing_ok=True)
        except Exception:
            pidfile.unlink(missing_ok=True)

    # 3. Check /proc by pattern
    if not pattern:
        return None
    try:
        pat = re.compile(pattern, re.IGNORECASE)
        my_pid = os.getpid()
        for p in os.listdir("/proc"):
            if not p.isdigit() or int(p) == my_pid:
                continue
            cmd_file = Path(f"/proc/{p}/cmdline")
            if not cmd_file.exists():
                continue
            try:
                cmd = cmd_file.read_bytes().decode("latin1", "replace").replace("\x00", " ").strip()
                if pat.search(cmd):
                    return int(p)
            except Exception:
                continue
    except Exception as e:
        print(f"Error scanning /proc: {e}", file=sys.stderr)

    return None

def get_last_log_snippet(agent_id: str, max_chars: int = 150) -> str:
    logfile = LOGS_DIR / f"{agent_id}.log"
    if not logfile.exists():
        return "لا توجد سجلات بعد."
    try:
        content = logfile.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return "السجل فارغ."
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if lines:
            last = lines[-1]
            return security_gate.mask_secrets(clean_ansi(last[:max_chars]))
        return "لا توجد أسطر مسجلة."
    except Exception:
        return "تعذر قراءة السجل."

def get_system_metrics() -> Dict[str, Any]:
    mem_total = 0
    mem_available = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) // 1024
    except Exception:
        pass
    mem_used = mem_total - mem_available if mem_total else 0
    mem_percent = round((mem_used / mem_total * 100), 1) if mem_total else 0

    uptime_sec = 0
    try:
        with open("/proc/uptime", "r") as f:
            uptime_sec = int(float(f.readline().split()[0]))
    except Exception:
        pass
    uptime_hours = round(uptime_sec / 3600, 1)

    proc_count = 0
    try:
        proc_count = len([p for p in os.listdir("/proc") if p.isdigit()])
    except Exception:
        pass

    # Disk usage
    disk_total_mb = 0
    disk_used_mb = 0
    disk_percent = 0.0
    try:
        tot, used, free = shutil.disk_usage(str(BASE_DIR))
        disk_total_mb = tot // (1024 * 1024)
        disk_used_mb = used // (1024 * 1024)
        disk_percent = round((used / tot * 100), 1) if tot else 0.0
    except Exception:
        pass

    return {
        "mem_total_mb": mem_total,
        "mem_used_mb": mem_used,
        "mem_available_mb": mem_available,
        "mem_percent": mem_percent,
        "uptime_hours": uptime_hours,
        "proc_count": proc_count,
        "disk_total_mb": disk_total_mb,
        "disk_used_mb": disk_used_mb,
        "disk_percent": disk_percent,
        "python_version": sys.version.split()[0],
    }

# ==============================================================================
# 24/7 Health & Readiness Probes
# ==============================================================================

@app.get("/health")
def liveness_probe():
    return {
        "status": "healthy",
        "service": "agents-hub",
        "timestamp": time.time(),
        "uptime": get_system_metrics()["uptime_hours"]
    }

@app.get("/ready")
def readiness_probe():
    try:
        # Check SQLite DB connectivity
        task_store.get_connection().execute("SELECT 1;").fetchone()
        db_ready = True
    except Exception:
        db_ready = False

    secrets_status = secrets_manager.get_secrets_status()

    is_ready = db_ready
    return {
        "ready": is_ready,
        "database": "connected" if db_ready else "error",
        "secrets_vault": secrets_status["vault_active"],
        "infisical_configured": secrets_status["infisical_configured"]
    }

# ==============================================================================
# WebSocket Real-Time Events Stream
# ==============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Authenticate before sending system state or approval counts.
        auth_message = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        if not auth_message.startswith("auth:") or not security_gate.verify_token(auth_message[5:]):
            await websocket.close(code=4401, reason="Authentication required")
            return

        # Register only after successful authentication so broadcasts cannot leak.
        ws_manager.register_authenticated(websocket)

        # Send initial sync payload only after successful authentication.
        await websocket.send_json({
            "event_type": "INITIAL_SYNC",
            "data": {
                "system": get_system_metrics(),
                "agent_states": task_store.get_all_agent_states(),
                "pending_approvals_count": len(task_store.list_pending_approvals("PENDING"))
            },
            "timestamp": time.time()
        })
        while True:
            # Keep-alive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, asyncio.TimeoutError):
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# ==============================================================================
# Maestro Tasks & Approvals API
# ==============================================================================

class TaskSubmitRequest(BaseModel):
    description: str
    category: str = "general"
    priority: int = 10
    input_data: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None

class ApprovalResolveRequest(BaseModel):
    decision: str  # APPROVED or REJECTED
    reviewer: str = "Admin"
    reason: Optional[str] = None

@app.post("/api/tasks")
async def api_submit_task(req: TaskSubmitRequest, authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")
    
    desc = req.description.strip()
    if not desc:
        raise HTTPException(status_code=400, detail="يجب تحديد وصف للمهمة")
    
    try:
        task = await maestro_engine.MaestroOrchestrator.submit_task(
            description=desc,
            category=req.category,
            priority=req.priority,
            input_data=req.input_data,
            idempotency_key=req.idempotency_key
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "task": task}

@app.get("/api/tasks")
def api_list_tasks(status: Optional[str] = None, agent: Optional[str] = None, limit: int = 50, offset: int = 0):
    tasks = task_store.list_tasks(status=status, assigned_agent=agent, limit=limit, offset=offset)
    return {"ok": True, "count": len(tasks), "tasks": tasks}

@app.get("/api/tasks/{task_id}")
def api_get_task_detail(task_id: str):
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="المهمة غير موجودة")
    events = task_store.get_task_events(task_id)
    task["events"] = events
    return {"ok": True, "task": task}

@app.get("/api/approvals")
def api_list_approvals(status: str = "PENDING"):
    approvals = task_store.list_pending_approvals(status=status)
    return {"ok": True, "approvals": approvals}

@app.post("/api/approvals/{approval_id}/resolve")
async def api_resolve_approval(approval_id: str, req: ApprovalResolveRequest, authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")

    decision = req.decision.upper()
    if decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="القرار يجب أن يكون APPROVED أو REJECTED")

    success = task_store.resolve_approval(approval_id, decision, req.reviewer, req.reason)
    if not success:
        raise HTTPException(status_code=404, detail="طلب الموافقة غير موجود أو تمت معالجته بالفعل")

    # Find associated task and notify Maestro
    approvals = task_store.list_pending_approvals(decision)
    target_appr = next((a for a in approvals if a["approval_id"] == approval_id), None)
    if target_appr:
        await maestro_engine.MaestroOrchestrator.resume_blocked_task(target_appr["task_id"], approval_id, decision)

    return {"ok": True, "message": f"تم تسجيل القرار ({decision}) بنجاح"}

@app.get("/api/audit")
def api_get_audit_logs(limit: int = 100):
    logs = task_store.list_audit_logs(limit=limit)
    return {"ok": True, "logs": logs}

@app.get("/api/secrets/status")
def api_secrets_status():
    status = secrets_manager.get_secrets_status()
    return {"ok": True, "secrets_status": status}

@app.post("/api/system/emergency-stop")
def api_emergency_stop(authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")

    # 1. Stop all tasks in DB
    result = task_store.emergency_stop_all()

    # 2. Terminate all active managed subprocesses
    killed_processes = 0
    for agent_id, info in list(managed_processes.items()):
        pid = info.get("pid")
        if pid:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
            killed_processes += 1
    managed_processes.clear()

    # Broadcast emergency stop
    maestro_engine.broadcast_event("EMERGENCY_STOP_TRIGGERED", {"halted_tasks": result["halted_tasks"]})

    return {
        "ok": True,
        "message": "تم تفعيل الإيقاف الطارئ (Emergency Stop) لكافة الوكلاء والمهام فوراً.",
        "halted_tasks": result["halted_tasks"],
        "killed_processes": killed_processes
    }

# ==============================================================================
# Existing APIs (Fully Preserved for Backward Compatibility)
# ==============================================================================

class PromptRequest(BaseModel):
    prompt: str

@app.get("/api/system/stats")
def api_system_stats():
    agents = load_agents()
    running_count = 0
    for ag in agents:
        pid = find_running_pid(ag.get("pattern"), ag["id"])
        port_open = is_port_listening(ag.get("port"))
        if pid or port_open:
            running_count += 1

    metrics = get_system_metrics()
    metrics["total_agents"] = len(agents)
    metrics["running_agents"] = running_count
    metrics["six_agents_active"] = len(task_store.get_all_agent_states())
    return metrics

@app.get("/api/agents")
def api_get_agents():
    agents = load_agents()
    enriched = []
    for ag in agents:
        agent_id = ag["id"]
        pid = find_running_pid(ag.get("pattern"), agent_id)
        port = ag.get("port")
        port_open = is_port_listening(port)
        is_running = bool(pid or port_open)
        snippet = get_last_log_snippet(agent_id)

        item = dict(ag)
        item["status"] = "running" if is_running else "stopped"
        item["pid"] = pid
        item["port_open"] = port_open
        item["last_log"] = snippet
        enriched.append(item)
    return enriched

@app.post("/api/agents/{agent_id}/start")
def api_start_agent(agent_id: str, authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")

    agents = {ag["id"]: ag for ag in load_agents()}
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="الوكيل غير موجود")

    ag = agents[agent_id]
    existing_pid = find_running_pid(ag.get("pattern"), agent_id)
    if existing_pid:
        return {"ok": True, "message": f"الوكيل يعمل بالفعل بمعرّف العملية (PID: {existing_pid})", "pid": existing_pid}

    cmd = ag.get("start_cmd")
    cwd = ag.get("cwd", str(Path.home()))
    if not cmd:
        raise HTTPException(status_code=400, detail="أمر التشغيل غير محدد لهذا الوكيل")

    logfile_path = LOGS_DIR / f"{agent_id}.log"
    pidfile_path = LOGS_DIR / f"{agent_id}.pid"

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(logfile_path, "a", encoding="utf-8") as log_f:
        log_f.write(f"\n--- [بدء التشغيل] {timestamp} | الأمر: {cmd} ---\n")
        log_f.flush()

        try:
            argv = shlex.split(cmd)
            if not argv:
                raise HTTPException(status_code=400, detail="أمر التشغيل غير صالح لهذا الوكيل")

            proc = subprocess.Popen(
                argv,
                shell=False,
                cwd=cwd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
                env=os.environ.copy()
            )
            pid = proc.pid
            managed_processes[agent_id] = {
                "pid": pid,
                "process": proc,
                "started_at": timestamp
            }
            pidfile_path.write_text(str(pid))
            task_store.log_audit("AGENT_START", "User", target=agent_id, details={"pid": pid, "cmd": cmd})
            return {"ok": True, "message": f"تم تشغيل الوكيل بنجاح (PID: {pid})", "pid": pid}
        except Exception as e:
            log_f.write(f"\n[خطأ أثناء التشغيل]: {str(e)}\n")
            raise HTTPException(status_code=500, detail=f"فشل تشغيل الوكيل: {str(e)}")

@app.post("/api/agents/{agent_id}/stop")
def api_stop_agent(agent_id: str, authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")

    agents = {ag["id"]: ag for ag in load_agents()}
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="الوكيل غير موجود")

    ag = agents[agent_id]
    pid = find_running_pid(ag.get("pattern"), agent_id)
    if not pid:
        (LOGS_DIR / f"{agent_id}.pid").unlink(missing_ok=True)
        return {"ok": True, "message": "الوكيل متوقف بالفعل."}

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    logfile_path = LOGS_DIR / f"{agent_id}.log"
    try:
        with open(logfile_path, "a", encoding="utf-8") as log_f:
            log_f.write(f"\n--- [إيقاف التشغيل] {timestamp} | إنهاء العملية (PID: {pid}) ---\n")

        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            os.kill(pid, signal.SIGTERM)

        for _ in range(10):
            time.sleep(0.1)
            if not os.path.exists(f"/proc/{pid}"):
                break
        else:
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

        managed_processes.pop(agent_id, None)
        (LOGS_DIR / f"{agent_id}.pid").unlink(missing_ok=True)
        task_store.log_audit("AGENT_STOP", "User", target=agent_id, details={"pid": pid})
        return {"ok": True, "message": f"تم إيقاف الوكيل بنجاح (PID: {pid})"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"حدث خطأ أثناء إيقاف العملية: {str(e)}")

@app.get("/api/agents/{agent_id}/logs")
def api_get_logs(agent_id: str, lines: int = 150):
    logfile = LOGS_DIR / f"{agent_id}.log"
    if not logfile.exists():
        return {
            "ok": True,
            "agent_id": agent_id,
            "content": f"لا توجد سجلات تشغيل حتى الآن للوكيل ({agent_id}). يمكنك النقر على 'تشغيل' لبدء تشغيله وتسجيل مخرجاته.",
            "total_lines": 0
        }
    try:
        text = logfile.read_text(encoding="utf-8", errors="replace")
        all_lines = text.splitlines()
        slice_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        cleaned = security_gate.mask_secrets(clean_ansi("\n".join(slice_lines)))
        return {
            "ok": True,
            "agent_id": agent_id,
            "content": cleaned if cleaned.strip() else "السجل فارغ حالياً.",
            "total_lines": len(all_lines)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"تعذر قراءة السجل: {str(e)}")

@app.delete("/api/agents/{agent_id}/logs")
def api_clear_logs(agent_id: str, authorization: Optional[str] = Header(None)):
    if not security_gate.verify_token(authorization):
        raise HTTPException(status_code=401, detail="غير مصرح: مفتاح المصادقة غير صالح")

    logfile = LOGS_DIR / f"{agent_id}.log"
    try:
        logfile.write_text(f"--- تم تفريغ السجل في {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n", encoding="utf-8")
        task_store.log_audit("CLEAR_LOGS", "User", target=agent_id)
        return {"ok": True, "message": "تم مسح السجل بنجاح"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"فشل مسح السجل: {str(e)}")

@app.post("/api/agents/{agent_id}/prompt")
async def api_send_prompt(agent_id: str, req: PromptRequest):
    prompt = req.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="الرجاء كتابة نص الطلب أو الأمر")

    agents = {ag["id"]: ag for ag in load_agents()}
    if agent_id not in agents:
        raise HTTPException(status_code=404, detail="الوكيل غير موجود")

    ag = agents[agent_id]
    start_time = time.time()

    # Specialized handlers
    if agent_id == "skillspector":
        risks = []
        dangerous_patterns = [
            (r"\b(eval|exec|compile|os\.system|subprocess\.|__import__|open\s*\()\b", "استدعاء دوال تشغيل أوامر نظام مباشرة أو تفسير أكواد ديناميكية"),
            (r"(api[_-]?key|secret|token|password|bearer|auth|credentials)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{8,}['\"]", "احتمال تسريب بيانات حساسة أو مفاتيح سرية صريحة"),
            (r"\b(rm\s+-rf|chmod\s+777|curl\s+.*\s*\|\s*bash|wget\s+.*\s*\|\s*sh)\b", "أوامر شل عالية الخطورة قد تتسبب في تعديل أو حذف ملفات النظام"),
            (r"(ignore\s+all\s+previous\s+instructions|system\s+prompt|jailbreak|bypass)", "محاولة حقن تعليمات برمجية (Prompt Injection) ضد النماذج"),
        ]
        for pat, desc in dangerous_patterns:
            matches = re.findall(pat, prompt, re.IGNORECASE)
            if matches:
                risks.append({"pattern": desc, "count": len(matches)})

        risk_level = "عالي ⚠️" if any("أوامر شل" in r["pattern"] or "حقن" in r["pattern"] for r in risks) else ("متوسط 🟡" if risks else "منخفض / آمن 🟢")
        report_lines = [
            f"### 🛡️ تقرير الفحص الأمني من SkillSpector",
            f"**الهدف المفحوص:** تحليل النص والتعليمات البرمجية المدخلة",
            f"**مستوى الخطورة الإجمالي:** `{risk_level}`",
            f"**عدد المخاطر المكتشفة:** {len(risks)}",
            "",
            "#### 📊 التفاصيل والنتائج:"
        ]
        if risks:
            for r in risks:
                report_lines.append(f"- 🔴 **تنبيه أمني:** {r['pattern']} (تكرار: {r['count']})")
            report_lines.append("\n**التوصية:** تجنب تشغيل الأكواد الحاوية على هذه الأنماط دون عزل أمني صارم (Sandboxing).")
        else:
            report_lines.append("- ✅ لم يتم رصد أي أنماط استغلال معروفة أو تسريب مفاتيح أو حقن تعليمات في هذا النص.")
            report_lines.append("- ✅ فحص التوافق وسلامة المهارات (Skill Integrity): مطابق لمعايير الأمان.")

        elapsed = round(time.time() - start_time, 2)
        return {
            "ok": True,
            "agent_id": agent_id,
            "agent_name": ag["name_ar"],
            "response": "\n".join(report_lines),
            "execution_time_seconds": elapsed,
            "status": "success"
        }

    elif agent_id == "hares-maestro":
        # Dispatch to the real Maestro Orchestrator pipeline!
        try:
            task = await maestro_engine.MaestroOrchestrator.submit_task(
                description=prompt,
                category="governance",
                priority=5
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        elapsed = round(time.time() - start_time, 2)
        return {
            "ok": True,
            "agent_id": agent_id,
            "agent_name": ag["name_ar"],
            "task_id": task["task_id"],
            "response": f"### 🛡️ حارس مايسترو — تم استلام الطلب وتوجيهه إلى محرك المنصة المستقل\n\n- **معرّف المهمة:** `{task['task_id']}`\n- **الحالة:** `جارِ التنفيذ والتوزيع على الوكلاء المتخصصين`\n- **المرحلة:** استلام وتحليل الهدف بواسطة Product Agent والتحقق الأمني.",
            "execution_time_seconds": elapsed,
            "status": "success"
        }

    elif agent_id == "aboserag":
        if is_port_listening(3000):
            try:
                import urllib.request
                req_data = json.dumps({"message": prompt}).encode("utf-8")
                http_req = urllib.request.Request(
                    "http://127.0.0.1:3000/api/chat",
                    data=req_data,
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(http_req, timeout=15) as resp:
                    resp_data = resp.read().decode("utf-8")
                    return {
                        "ok": True,
                        "agent_id": agent_id,
                        "agent_name": ag["name_ar"],
                        "response": f"**رد أبو سراج (عبر الخادم النشط):**\n\n{resp_data}",
                        "execution_time_seconds": round(time.time() - start_time, 2),
                        "status": "success"
                    }
            except Exception:
                pass
        return {
            "ok": True,
            "agent_id": agent_id,
            "agent_name": ag["name_ar"],
            "response": f"### 🤖 رسالة من أبو سراج\n\nأهلاً بك! لقد استلمت طلبك:\n> {prompt}\n\n💡 خادم أبو سراج في المسار `~/aboserag-agent` جاهز. يمكنك تشغيل الخادم بالنقر على زر **تشغيل** أعلاه لفتح واجهة الويب PWA وتفعيل أدوات قراءة الملفات وتنفيذ الأوامر وتكامل Gmail.",
            "execution_time_seconds": round(time.time() - start_time, 2),
            "status": "info"
        }

    elif agent_id == "crush":
        try:
            cmd = ["crush", "run", prompt]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            output = security_gate.mask_secrets(clean_ansi(stdout.decode("utf-8", "replace").strip()))
            err = security_gate.mask_secrets(clean_ansi(stderr.decode("utf-8", "replace").strip()))
            res = output or err or "تم تنفيذ الأمر بواسطة Charm Crush دون مخرجات."
            return {
                "ok": True,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": res,
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "success"
            }
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": "⚠️ استغرق وكيل Crush وقتاً طويلاً للإجابة (تجاوز مهلة 30 ثانية).",
                "execution_time_seconds": 30.0,
                "status": "timeout"
            }
        except Exception as e:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": f"⚠️ تعذر تشغيل أمر Crush: {str(e)}",
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "error"
            }

    elif agent_id == "opencode":
        try:
            cmd = ["opencode", "run", prompt]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=35.0)
            output = security_gate.mask_secrets(clean_ansi(stdout.decode("utf-8", "replace").strip()))
            err = security_gate.mask_secrets(clean_ansi(stderr.decode("utf-8", "replace").strip()))
            res = output or err or "تم تنفيذ الأمر بواسطة OpenCode."
            return {
                "ok": True,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": res,
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "success"
            }
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": "⚠️ استغرق OpenCode وقتاً طويلاً.",
                "execution_time_seconds": 35.0,
                "status": "timeout"
            }
        except Exception as e:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": f"⚠️ خطأ أثناء استدعاء OpenCode: {str(e)}",
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "error"
            }

    elif agent_id == "codex":
        try:
            cmd = ["codex", "exec", prompt]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            output = security_gate.mask_secrets(clean_ansi(stdout.decode("utf-8", "replace").strip()))
            err = security_gate.mask_secrets(clean_ansi(stderr.decode("utf-8", "replace").strip()))
            res = output or err or "تم تنفيذ المهمة بواسطة Codex."
            return {
                "ok": True,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": res,
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "success"
            }
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": "⚠️ استغرق Codex وقتاً أطول من المعتاد.",
                "execution_time_seconds": 30.0,
                "status": "timeout"
            }
        except Exception as e:
            return {
                "ok": False,
                "agent_id": agent_id,
                "agent_name": ag["name_ar"],
                "response": f"⚠️ تعذر استدعاء Codex: {str(e)}",
                "execution_time_seconds": round(time.time() - start_time, 2),
                "status": "error"
            }

    else:
        elapsed = round(time.time() - start_time, 2)
        is_running = bool(find_running_pid(ag.get("pattern"), agent_id) or is_port_listening(ag.get("port")))
        status_text = "🟢 قيد التشغيل حالياً" if is_running else "🔴 متوقف حالياً"
        res = [
            f"### 💬 رد الوكيل: {ag['name_ar']}",
            f"**الحالة التشغيلية:** {status_text}",
            f"**المسار:** `{ag.get('cwd', '~')}`",
            "",
            f"تم استلام طلبك: **\"{prompt}\"**",
            "",
            "ℹ️ هذا الوكيل يتطلب بيئته الخاصة أو تشغيل خادمه للتعامل التفاعلي الكامل. يمكنك النقر على زر **تشغيل** أعلى البطاقة لتشغيله في الخلفية ثم الاطلاع على سجلاته الحية."
        ]
        return {
            "ok": True,
            "agent_id": agent_id,
            "agent_name": ag["name_ar"],
            "response": "\n".join(res),
            "execution_time_seconds": elapsed,
            "status": "info"
        }

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_file = BASE_DIR / "static" / "index.html"
    if html_file.exists():
        return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Agents Hub is starting...</h1>")

@app.get("/manifest.json")
def serve_manifest():
    manifest_file = BASE_DIR / "static" / "manifest.json"
    if manifest_file.exists():
        return FileResponse(manifest_file, media_type="application/manifest+json")
    raise HTTPException(status_code=404, detail="Manifest not found")

@app.get("/sw.js")
def serve_sw():
    sw_file = BASE_DIR / "static" / "sw.js"
    if sw_file.exists():
        return FileResponse(sw_file, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="Service worker not found")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
