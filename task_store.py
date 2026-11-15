import os
import json
import time
import uuid
import sqlite3
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "agents_hub.db"

_db_lock = threading.RLock()

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db():
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Tasks Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE NOT NULL,
                parent_task_id TEXT,
                description TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                assigned_agent TEXT NOT NULL,
                priority INTEGER DEFAULT 10,
                status TEXT NOT NULL,
                idempotency_key TEXT UNIQUE,
                input_data TEXT DEFAULT '{}',
                result TEXT DEFAULT '{}',
                error_message TEXT,
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                steps_count INTEGER DEFAULT 0,
                max_steps INTEGER DEFAULT 20,
                tokens_used INTEGER DEFAULT 0,
                cost_estimate REAL DEFAULT 0.0,
                budget_limit REAL DEFAULT 1.0,
                timeout_seconds INTEGER DEFAULT 120,
                locked_by TEXT,
                locked_at REAL,
                lock_expires_at REAL,
                started_at REAL,
                completed_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(assigned_agent);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_idempotency ON tasks(idempotency_key);")

            # 2. Task Events / History
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                agent TEXT,
                details TEXT DEFAULT '{}',
                timestamp REAL NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_task_id ON task_events(task_id);")

            # 3. Resource & File Locks (concurrency control)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS resource_locks (
                resource_id TEXT PRIMARY KEY,
                locked_by_task_id TEXT NOT NULL,
                locked_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );
            """)

            # 4. Audit Log (Sensitive events & actions)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT,
                details TEXT DEFAULT '{}',
                ip_address TEXT,
                created_at REAL NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);")

            # 5. Agent State & Health Registry
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_states (
                agent_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                version TEXT DEFAULT '1.0.0',
                current_task_id TEXT,
                last_active_at REAL,
                total_tasks_completed INTEGER DEFAULT 0,
                total_tasks_failed INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}'
            );
            """)

            # 6. Approvals Queue (Sensitive Approval Mode)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_approvals (
                approval_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                description TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                status TEXT DEFAULT 'PENDING',
                requested_by TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at REAL,
                rejection_reason TEXT,
                created_at REAL NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON pending_approvals(status);")

            conn.commit()

# --- Task CRUD & Lifecycle ---

def create_task(
    description: str,
    assigned_agent: str,
    input_data: Optional[Dict[str, Any]] = None,
    category: str = "general",
    priority: int = 10,
    parent_task_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    max_retries: int = 3,
    max_steps: int = 20,
    timeout_seconds: int = 120,
    budget_limit: float = 1.0
) -> Dict[str, Any]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Idempotency check
            if idempotency_key:
                cursor.execute("SELECT * FROM tasks WHERE idempotency_key = ?", (idempotency_key,))
                row = cursor.fetchone()
                if row:
                    task_dict = dict(row)
                    task_dict["input_data"] = json.loads(task_dict["input_data"])
                    task_dict["result"] = json.loads(task_dict["result"])
                    return task_dict

            task_id = f"task_{uuid.uuid4().hex[:12]}"
            now = time.time()
            input_json = json.dumps(input_data or {}, ensure_ascii=False)

            cursor.execute("""
            INSERT INTO tasks (
                task_id, parent_task_id, description, category, assigned_agent,
                priority, status, idempotency_key, input_data, max_retries,
                max_steps, timeout_seconds, budget_limit, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'RECEIVE', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id, parent_task_id, description, category, assigned_agent,
                priority, idempotency_key, input_json, max_retries,
                max_steps, timeout_seconds, budget_limit, now, now
            ))
            conn.commit()

    log_task_event(task_id, "RECEIVE", assigned_agent, {"description": description})
    return get_task(task_id)

def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["input_data"] = json.loads(data["input_data"] or "{}")
            data["result"] = json.loads(data["result"] or "{}")
            return data

def list_tasks(
    status: Optional[str] = None,
    assigned_agent: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM tasks WHERE 1=1"
            params = []
            if status:
                query += " AND status = ?"
                params.append(status)
            if assigned_agent:
                query += " AND assigned_agent = ?"
                params.append(assigned_agent)
            
            query += " ORDER BY priority ASC, created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["input_data"] = json.loads(item["input_data"] or "{}")
                item["result"] = json.loads(item["result"] or "{}")
                results.append(item)
            return results

def update_task(
    task_id: str,
    status: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
    retry_count: Optional[int] = None,
    steps_increment: int = 0,
    tokens_used: Optional[int] = None,
    cost_estimate: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            
            updates = ["updated_at = ?"]
            params = [now]

            if status:
                updates.append("status = ?")
                params.append(status)
                if status in ("EXECUTE", "EXECUTING"):
                    updates.append("started_at = COALESCE(started_at, ?)")
                    params.append(now)
                elif status in ("COMPLETE", "COMPLETED", "FAILED", "CANCELLED"):
                    updates.append("completed_at = ?")
                    params.append(now)

            if result is not None:
                updates.append("result = ?")
                params.append(json.dumps(result, ensure_ascii=False))

            if error_message is not None:
                updates.append("error_message = ?")
                params.append(error_message)

            if retry_count is not None:
                updates.append("retry_count = ?")
                params.append(retry_count)

            if steps_increment > 0:
                updates.append("steps_count = steps_count + ?")
                params.append(steps_increment)

            if tokens_used is not None:
                updates.append("tokens_used = tokens_used + ?")
                params.append(tokens_used)

            if cost_estimate is not None:
                updates.append("cost_estimate = cost_estimate + ?")
                params.append(cost_estimate)

            params.append(task_id)
            query = f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?"
            cursor.execute(query, params)
            conn.commit()

    if status:
        log_task_event(task_id, status, None, {"error": error_message} if error_message else {})
    return get_task(task_id)

def log_task_event(task_id: str, event_type: str, agent: Optional[str], details: Optional[Dict[str, Any]] = None):
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO task_events (task_id, event_type, agent, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """, (
                task_id,
                event_type,
                agent,
                json.dumps(details or {}, ensure_ascii=False),
                time.time()
            ))
            conn.commit()

def get_task_events(task_id: str) -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM task_events WHERE task_id = ? ORDER BY timestamp ASC", (task_id,))
            rows = cursor.fetchall()
            events = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details"] or "{}")
                events.append(item)
            return events

# --- Resource Concurrency Locking ---

def acquire_resource_lock(resource_id: str, task_id: str, ttl_seconds: float = 60.0) -> bool:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            # Clean expired lock first
            cursor.execute("DELETE FROM resource_locks WHERE resource_id = ? AND expires_at < ?", (resource_id, now))
            try:
                cursor.execute("""
                INSERT INTO resource_locks (resource_id, locked_by_task_id, locked_at, expires_at)
                VALUES (?, ?, ?, ?)
                """, (resource_id, task_id, now, now + ttl_seconds))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

def release_resource_lock(resource_id: str, task_id: str) -> bool:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM resource_locks WHERE resource_id = ? AND locked_by_task_id = ?", (resource_id, task_id))
            conn.commit()
            return cursor.rowcount > 0

# --- Audit Logs ---

def log_audit(action: str, actor: str, target: Optional[str] = None, details: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None):
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO audit_logs (action, actor, target, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                action,
                actor,
                target,
                json.dumps(details or {}, ensure_ascii=False),
                ip_address,
                time.time()
            ))
            conn.commit()

def list_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            logs = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details"] or "{}")
                logs.append(item)
            return logs

# --- Agent States ---

def upsert_agent_state(
    agent_id: str,
    role: str,
    status: str,
    current_task_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            meta_json = json.dumps(metadata or {}, ensure_ascii=False)
            cursor.execute("""
            INSERT INTO agent_states (agent_id, role, status, current_task_id, last_active_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                role = excluded.role,
                status = excluded.status,
                current_task_id = excluded.current_task_id,
                last_active_at = excluded.last_active_at,
                metadata = excluded.metadata
            """, (agent_id, role, status, current_task_id, now, meta_json))
            conn.commit()

def get_all_agent_states() -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agent_states ORDER BY agent_id ASC")
            rows = cursor.fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["metadata"] = json.loads(item["metadata"] or "{}")
                result.append(item)
            return result

# --- Pending Approvals (Sensitive Approval Mode) ---

def create_pending_approval(
    task_id: str,
    action_type: str,
    description: str,
    risk_level: str,
    requested_by: str,
    payload: Optional[Dict[str, Any]] = None
) -> str:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            approval_id = f"appr_{uuid.uuid4().hex[:10]}"
            now = time.time()
            cursor.execute("""
            INSERT INTO pending_approvals (
                approval_id, task_id, action_type, description,
                risk_level, payload, status, requested_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """, (
                approval_id, task_id, action_type, description,
                risk_level, json.dumps(payload or {}, ensure_ascii=False),
                requested_by, now
            ))
            conn.commit()
            log_audit("APPROVAL_REQUESTED", requested_by, target=task_id, details={
                "approval_id": approval_id,
                "action_type": action_type,
                "risk_level": risk_level,
                "description": description
            })
            return approval_id

def resolve_approval(approval_id: str, decision: str, reviewer: str, reason: Optional[str] = None) -> bool:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            cursor.execute("""
            UPDATE pending_approvals
            SET status = ?, reviewed_by = ?, reviewed_at = ?, rejection_reason = ?
            WHERE approval_id = ? AND status = 'PENDING'
            """, (decision.upper(), reviewer, now, reason, approval_id))
            conn.commit()
            success = cursor.rowcount > 0
            if success:
                log_audit(f"APPROVAL_{decision.upper()}", reviewer, target=approval_id, details={"reason": reason})
            return success

def list_pending_approvals(status: str = "PENDING") -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pending_approvals WHERE status = ? ORDER BY created_at DESC", (status,))
            rows = cursor.fetchall()
            approvals = []
            for r in rows:
                item = dict(r)
                item["payload"] = json.loads(item["payload"] or "{}")
                approvals.append(item)
            return approvals

# --- 24/7 Reconciliation on Boot ---

def reconcile_orphan_tasks() -> Dict[str, Any]:
    """
    Called upon server startup to recover interrupted or orphaned tasks.
    Any task that was in DISPATCH, EXECUTE, or EXECUTING is safely transitioned to BLOCKED
    or RECOVERED so that it does not stay in an invalid state.
    """
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT task_id, status, retry_count, max_retries
            FROM tasks
            WHERE status IN ('DISPATCH', 'EXECUTE', 'EXECUTING', 'ANALYZE', 'PLAN', 'VERIFY')
            """)
            orphaned = cursor.fetchall()
            recovered_count = 0
            blocked_count = 0

            for row in orphaned:
                tid = row["task_id"]
                retries = row["retry_count"]
                max_ret = row["max_retries"]
                if retries < max_ret:
                    # Can retry
                    update_task(
                        tid,
                        status="RECEIVE",
                        retry_count=retries + 1,
                        error_message="Recovered on startup after unexpected server restart"
                    )
                    log_task_event(tid, "RECOVERED_ON_BOOT", "Maestro", {"attempt": retries + 1})
                    recovered_count += 1
                else:
                    update_task(
                        tid,
                        status="BLOCKED",
                        error_message="Task interrupted on crash and exceeded max retries"
                    )
                    log_task_event(tid, "BLOCKED_ON_BOOT", "Maestro", {"reason": "Max retries exceeded on boot"})
                    blocked_count += 1

            # Release all stale resource locks
            cursor.execute("DELETE FROM resource_locks")
            conn.commit()

            return {
                "total_orphans": len(orphaned),
                "requeued_tasks": recovered_count,
                "blocked_tasks": blocked_count
            }

def emergency_stop_all() -> Dict[str, Any]:
    with _db_lock:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            cursor.execute("""
            UPDATE tasks
            SET status = 'BLOCKED',
                error_message = 'EMERGENCY_STOP: All operations halted by user request',
                completed_at = ?,
                updated_at = ?
            WHERE status IN ('RECEIVE', 'ANALYZE', 'PLAN', 'DISPATCH', 'EXECUTE', 'EXECUTING', 'VERIFY')
            """, (now, now))
            halted_tasks = cursor.rowcount

            cursor.execute("UPDATE agent_states SET status = 'stopped', current_task_id = NULL")
            cursor.execute("DELETE FROM resource_locks")
            conn.commit()

            log_audit("EMERGENCY_STOP", "Admin", details={"halted_tasks": halted_tasks})
            return {"ok": True, "halted_tasks": halted_tasks}

# Auto-initialize database on import
init_db()
