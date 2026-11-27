import os
import sys
import time
import json
import asyncio
import random
import logging
import shutil
import re
from typing import Dict, Any, Optional, List, Tuple, Callable
from pathlib import Path

import task_store
import security_gate
import secrets_manager

logger = logging.getLogger("agents-hub.maestro")

# Maximum parallel tasks concurrency
CONCURRENCY_LIMIT = 4
_semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

# Event subscribers for real-time WebSocket dispatch
_event_subscribers: List[Callable[[Dict[str, Any]], None]] = []

def subscribe_events(callback: Callable[[Dict[str, Any]], None]):
    if callback not in _event_subscribers:
        _event_subscribers.append(callback)

def broadcast_event(event_type: str, data: Dict[str, Any]):
    event = {
        "event_type": event_type,
        "data": data,
        "timestamp": time.time()
    }
    for sub in list(_event_subscribers):
        try:
            sub(event)
        except Exception:
            pass

# ==============================================================================
# The Six Specialized Agents
# ==============================================================================

class ProductAgent:
    name = "Product Agent"
    role = "product"
    description_ar = "وكيل المنتج — تحليل الطلبات والتخطيط والبحث وتقسيم الأهداف"

    @classmethod
    async def analyze(cls, task: Dict[str, Any]) -> Dict[str, Any]:
        prompt = task["description"]
        category = task.get("category", "general")
        
        # Deconstruct requirement into clear steps and deliverables
        plan_steps = [
            f"1. تحليل أهداف الطلب: '{prompt[:60]}...'",
            "2. تحديد المكونات البرمجية والملفات المستهدفة للتعديل أو الإنشاء",
            "3. وضع خطة التحقق ومعايير القبول المستقلة",
            "4. التأكد من توافق المتطلبات مع سياسة المنصة المستقلة 24/7"
        ]
        
        return {
            "agent": cls.role,
            "status": "ANALYSIS_COMPLETE",
            "summary": f"تم تحليل الطلب وتقسيم نطاق العمل إلى {len(plan_steps)} خطوات رئيسية.",
            "plan_steps": plan_steps,
            "suggested_agent": "developer" if any(w in prompt.lower() for w in ["code", "برمج", "ملف", "script", "fix", "api"]) else "general"
        }

class DeveloperAgent:
    name = "Developer Agent"
    role = "developer"
    description_ar = "وكيل التطوير — كتابة وتعديل الأكواد البرمجية والتنفيذ التقني"

    @classmethod
    async def execute(cls, task: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        prompt = task["description"]
        input_data = task.get("input_data", {})
        target_file = input_data.get("target_file")
        executable = shutil.which("opencode")

        if not executable:
            return {
                "agent": cls.role,
                "status": "EXECUTOR_UNAVAILABLE",
                "error": "OpenCode CLI is not installed; no implementation was executed."
            }

        if target_file:
            locked = task_store.acquire_resource_lock(target_file, task["task_id"], ttl_seconds=180)
            if not locked:
                return {
                    "agent": cls.role,
                    "status": "WAITING_LOCK",
                    "error": f"الملف {target_file} مقفول حالياً بواسطة مهمة أخرى لمنع التعارض"
                }

        try:
            proc = await asyncio.create_subprocess_exec(
                executable, "run", prompt,
                cwd=str(Path(__file__).resolve().parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180.0)
            output = (stdout or b"").decode("utf-8", "replace").strip()
            error = (stderr or b"").decode("utf-8", "replace").strip()
            combined = security_gate.mask_secrets("\n".join(x for x in (output, error) if x))
            if proc.returncode != 0 or not combined:
                return {
                    "agent": cls.role,
                    "status": "EXECUTION_FAILED",
                    "returncode": proc.returncode,
                    "output": combined[-12000:]
                }
            return {
                "agent": cls.role,
                "status": "EXECUTED",
                "returncode": proc.returncode,
                "output": combined[-12000:],
                "artifacts": [target_file] if target_file else []
            }
        except asyncio.TimeoutError:
            return {"agent": cls.role, "status": "EXECUTION_TIMEOUT", "error": "OpenCode exceeded 180 seconds."}
        except Exception as exc:
            return {"agent": cls.role, "status": "EXECUTION_FAILED", "error": security_gate.mask_secrets(str(exc))}
        finally:
            if target_file:
                task_store.release_resource_lock(target_file, task["task_id"])

class SecurityAgent:
    name = "Security Agent"
    role = "security"
    description_ar = "وكيل الأمان — مراجعة الصلاحيات والمخاطر وكشف تسريب الأسرار"

    @classmethod
    async def review(cls, task: Dict[str, Any], action_type: str = "EXECUTE", payload: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
        prompt = task["description"]
        check_payload = payload or {"prompt": prompt}
        
        # Reject secret-bearing prompts before they can reach an executor.
        cleaned_text = security_gate.mask_secrets(prompt)
        input_data = task.get("input_data") or {}
        cleaned_input = security_gate.mask_dict_secrets(input_data)
        has_secret_leak = cleaned_text != prompt or cleaned_input != input_data
        if has_secret_leak:
            return False, {
                "agent": cls.role,
                "approved": False,
                "status": "SECRET_REDACTION_REQUIRED",
                "requires_redaction": True,
                "reason": "تم إيقاف المهمة لأن المدخلات تحتوي على بيانات تشبه الأسرار. احذفها وأعد إرسال الطلب."
            }

        # Check against sensitive action rules
        is_sensitive, risk_level, reason = security_gate.is_sensitive_action(action_type, check_payload)

        if is_sensitive:
            return False, {
                "agent": cls.role,
                "approved": False,
                "risk_level": risk_level,
                "reason": reason,
                "action_type": action_type,
                "requires_human_approval": True
            }

        return True, {
            "agent": cls.role,
            "approved": True,
            "risk_level": "LOW",
            "has_secret_leak": has_secret_leak,
            "summary": "الفحص الأمني سليم: لا توجد عمليات عالية الخطورة أو تسريب مفاتيح صريحة."
        }

class TestAgent:
    name = "Test Agent"
    role = "test"
    description_ar = "وكيل الاختبارات — فحص الوظائف واكتشاف الأعطال والانحدار البرمجي"

    @classmethod
    async def run_tests(cls, task: Dict[str, Any], dev_output: Dict[str, Any]) -> Dict[str, Any]:
        tests_dir = Path(__file__).resolve().parent / "tests"
        if not tests_dir.is_dir():
            return {"agent": cls.role, "status": "TESTS_NOT_RUN", "tests_run": 0,
                    "failures": None, "details": "No tests/ directory exists; no test success is claimed."}
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "unittest", "discover",
                "-s", "tests", "-t", ".", "-p", "test_*.py", "-v",
                cwd=str(Path(__file__).resolve().parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            raw = "\n".join(x.decode("utf-8", "replace") for x in (stdout, stderr) if x)
            safe_output = security_gate.mask_secrets(raw)[-12000:]
            match = re.search(r"Ran (\d+) tests?", raw)
            tests_run = int(match.group(1)) if match else 0
            passed = proc.returncode == 0 and tests_run > 0 and "OK" in raw
            return {
                "agent": cls.role,
                "status": "TESTS_PASSED" if passed else "TESTS_FAILED" if tests_run else "TESTS_NOT_RUN",
                "tests_run": tests_run,
                "failures": 0 if passed else None,
                "returncode": proc.returncode,
                "details": safe_output
            }
        except asyncio.TimeoutError:
            return {"agent": cls.role, "status": "TESTS_TIMEOUT", "tests_run": 0,
                    "failures": None, "details": "Test suite exceeded 120 seconds."}
        except Exception as exc:
            return {"agent": cls.role, "status": "TESTS_ERROR", "tests_run": 0,
                    "failures": None, "details": security_gate.mask_secrets(str(exc))}

class UXAgent:
    name = "UX Agent"
    role = "ux"
    description_ar = "وكيل تجربة المستخدم — مراجعة الواجهة والتجاوب ودعم اللغة العربية RTL"

    @classmethod
    async def evaluate_ui(cls, task: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {
            "agent": cls.role,
            "status": "UX_NOT_EVALUATED",
            "details": "No browser or visual inspection tool is configured; UX approval is not claimed."
        }

class VerifierAgent:
    name = "Verifier Agent"
    role = "verifier"
    description_ar = "وكيل التحقق المستقل — الفحص النهائي للأدلة والمطابقة قبل الاعتماد"

    @classmethod
    async def verify(cls, task: Dict[str, Any], results_bundle: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        # Verification criteria:
        # 1. Product plan exists
        # 2. Security review passed
        # 3. Developer executed
        # 4. Tests passed
        product_ok = "product" in results_bundle
        security_ok = results_bundle.get("security", {}).get("approved", False)
        developer_evidence = results_bundle.get("developer", {})
        dev_ok = (developer_evidence.get("status") == "EXECUTED"
                  and developer_evidence.get("returncode") == 0
                  and bool(developer_evidence.get("output", "").strip()))
        test_evidence = results_bundle.get("test", {})
        test_ok = (test_evidence.get("status") == "TESTS_PASSED"
                   and isinstance(test_evidence.get("tests_run"), int)
                   and test_evidence.get("tests_run", 0) > 0
                   and test_evidence.get("returncode") == 0)

        all_passed = product_ok and security_ok and dev_ok and test_ok

        verdict = {
            "agent": cls.role,
            "verdict": "VERIFIED_SUCCESS" if all_passed else "VERIFICATION_REJECTED",
            "evidence": {
                "product_analysis": product_ok,
                "security_clearance": security_ok,
                "developer_execution": dev_ok,
                "tests_executed": test_evidence.get("tests_run", 0),
                "test_pass_evidence": test_ok
            },
            "timestamp": time.time()
        }
        return all_passed, verdict

# ==============================================================================
# Maestro — The Central Orchestrator
# ==============================================================================

class MaestroOrchestrator:
    """
    Central Controller for the Autonomous 24/7 Agent Hub.
    Coordinates the task lifecycle:
    RECEIVE -> ANALYZE -> PLAN -> DISPATCH -> EXECUTE -> VERIFY -> COMPLETE
    Handles BLOCKED, FAILED, and CANCELLED states with safety limits and retries.
    """

    @classmethod
    def register_agent_states(cls):
        # Register the 6 specialist agents
        agents = [
            ("product", "Product Agent", "idle"),
            ("developer", "Developer Agent", "idle"),
            ("security", "Security Agent", "idle"),
            ("test", "Test Agent", "idle"),
            ("ux", "UX Agent", "idle"),
            ("verifier", "Verifier Agent", "idle"),
        ]
        for aid, role, status in agents:
            task_store.upsert_agent_state(aid, role, status, metadata={"version": "2.0.0"})

    @classmethod
    async def submit_task(
        cls,
        description: str,
        category: str = "general",
        priority: int = 10,
        input_data: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Entry point for new user or system tasks."""
        clean_description = security_gate.mask_secrets(description)
        clean_input_data = security_gate.mask_dict_secrets(input_data or {})
        if clean_description != description or clean_input_data != (input_data or {}):
            raise ValueError("تم رفض الطلب قبل حفظه لأنه يحتوي على بيانات تشبه الأسرار. احذف المفاتيح أو الرموز السرية وأعد الإرسال.")

        cls.register_agent_states()
        
        # 1. RECEIVE
        task = task_store.create_task(
            description=description,
            assigned_agent="maestro",
            category=category,
            priority=priority,
            input_data=input_data,
            idempotency_key=idempotency_key
        )
        task_id = task["task_id"]
        broadcast_event("TASK_RECEIVED", {"task_id": task_id, "description": description})

        # Spawn asynchronous execution pipeline
        asyncio.create_task(cls.run_task_pipeline(task_id))
        return task

    @classmethod
    async def run_task_pipeline(cls, task_id: str):
        async with _semaphore:
            task = task_store.get_task(task_id)
            if not task or task["status"] in ("COMPLETE", "COMPLETED", "CANCELLED", "BLOCKED"):
                return

            try:
                # 2. ANALYZE Phase
                task_store.update_task(task_id, status="ANALYZE", steps_increment=1)
                task_store.upsert_agent_state("product", "Product Agent", "busy", current_task_id=task_id)
                broadcast_event("TASK_STAGE_CHANGE", {"task_id": task_id, "stage": "ANALYZE"})

                product_analysis = await ProductAgent.analyze(task)
                
                # Security clearance
                task_store.upsert_agent_state("security", "Security Agent", "busy", current_task_id=task_id)
                sec_approved, sec_report = await SecurityAgent.review(task)
                
                if not sec_approved:
                    if sec_report.get("status") == "SECRET_REDACTION_REQUIRED":
                        task_store.update_task(
                            task_id,
                            status="FAILED",
                            error_message="تم رفض المهمة لاحتوائها على بيانات تشبه الأسرار؛ احذفها وأعد الإرسال."
                        )
                        broadcast_event("TASK_REJECTED_SECRET", {"task_id": task_id})
                        return

                    # Gated by Sensitive Approval Mode!
                    allowed, approval_id = security_gate.check_permission_and_gate(
                        task_id=task_id,
                        action_type=sec_report.get("action_type", "EXECUTE"),
                        actor="SecurityAgent",
                        details={"prompt": task["description"], "risk": sec_report.get("risk_level")}
                    )
                    broadcast_event("TASK_BLOCKED_APPROVAL", {
                        "task_id": task_id,
                        "approval_id": approval_id,
                        "reason": sec_report.get("reason")
                    })
                    return

                # 3. PLAN Phase
                task_store.update_task(task_id, status="PLAN", steps_increment=1)
                broadcast_event("TASK_STAGE_CHANGE", {"task_id": task_id, "stage": "PLAN"})
                plan = {
                    "product": product_analysis,
                    "security": sec_report,
                    "timestamp": time.time()
                }

                # 4. DISPATCH & EXECUTE Phase
                task_store.update_task(task_id, status="EXECUTING", steps_increment=1)
                task_store.upsert_agent_state("developer", "Developer Agent", "busy", current_task_id=task_id)
                broadcast_event("TASK_STAGE_CHANGE", {"task_id": task_id, "stage": "EXECUTE"})

                # Execute developer & UX tasks in parallel
                dev_future = DeveloperAgent.execute(task, plan)
                ux_future = UXAgent.evaluate_ui(task)
                dev_result, ux_result = await asyncio.gather(dev_future, ux_future)

                # Run automated tests
                task_store.upsert_agent_state("test", "Test Agent", "busy", current_task_id=task_id)
                test_result = await TestAgent.run_tests(task, dev_result)

                # 5. VERIFY Phase
                task_store.update_task(task_id, status="VERIFY", steps_increment=1)
                task_store.upsert_agent_state("verifier", "Verifier Agent", "busy", current_task_id=task_id)
                broadcast_event("TASK_STAGE_CHANGE", {"task_id": task_id, "stage": "VERIFY"})

                bundle = {
                    "product": product_analysis,
                    "security": sec_report,
                    "developer": dev_result,
                    "ux": ux_result,
                    "test": test_result
                }
                verified, verifier_report = await VerifierAgent.verify(task, bundle)

                if verified:
                    # 6. COMPLETE Phase
                    final_result = {
                        "summary": "اكتملت المهمة بنجاح بعد التحقق المستقل من كافة مخرجات الوكلاء.",
                        "pipeline_results": bundle,
                        "verifier": verifier_report
                    }
                    task_store.update_task(task_id, status="COMPLETE", result=final_result, steps_increment=1)
                    broadcast_event("TASK_COMPLETED", {"task_id": task_id, "result": final_result})
                else:
                    task_store.update_task(task_id, status="FAILED", error_message="رفض وكيل التحقق المستقل Verifier اعتماد النتائج لعدم اكتمال الأدلة")
                    broadcast_event("TASK_FAILED", {"task_id": task_id, "reason": "Verification failed"})

            except Exception as e:
                logger.error(f"Error in task {task_id}: {e}", exc_info=True)
                retries = task.get("retry_count", 0)
                max_retries = task.get("max_retries", 3)
                if retries < max_retries:
                    backoff = (2 ** retries) + random.uniform(0.1, 0.5)
                    await asyncio.sleep(backoff)
                    task_store.update_task(
                        task_id,
                        status="RECEIVE",
                        retry_count=retries + 1,
                        error_message=f"خطأ أثناء التنفيذ: {str(e)} — جاري إعادة المحاولة ({retries + 1}/{max_retries})"
                    )
                    broadcast_event("TASK_RETRY", {"task_id": task_id, "retry_count": retries + 1})
                    asyncio.create_task(cls.run_task_pipeline(task_id))
                else:
                    task_store.update_task(task_id, status="FAILED", error_message=f"فشلت المهمة بعد استنفاد المحاولات: {str(e)}")
                    broadcast_event("TASK_FAILED", {"task_id": task_id, "error": str(e)})

            finally:
                # Reset agent states to idle
                for ag in ["product", "developer", "security", "test", "ux", "verifier"]:
                    task_store.upsert_agent_state(ag, ag.capitalize() + " Agent", "idle")

    @classmethod
    async def resume_blocked_task(cls, task_id: str, approval_id: str, decision: str):
        """Called when a user approves or rejects a sensitive action."""
        if decision.upper() == "APPROVED":
            task_store.update_task(task_id, status="RECEIVE", error_message=None)
            broadcast_event("TASK_UNBLOCKED", {"task_id": task_id, "approval_id": approval_id})
            asyncio.create_task(cls.run_task_pipeline(task_id))
        else:
            task_store.update_task(task_id, status="CANCELLED", error_message=f"تم رفض الإذن الحساس من قبل المشرف (معرّف الموافقة: {approval_id})")
            broadcast_event("TASK_CANCELLED", {"task_id": task_id, "approval_id": approval_id})
