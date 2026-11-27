import asyncio
import unittest

from maestro_engine import MaestroOrchestrator, SecurityAgent, VerifierAgent
from unittest.mock import patch


class VerifierEvidenceTests(unittest.TestCase):
    def test_rejects_simulated_implementation_and_unverified_test_claim(self):
        bundle = {
            "product": {"status": "ANALYSIS_COMPLETE"},
            "security": {"approved": True},
            "developer": {"status": "IMPLEMENTED"},
            "test": {"status": "TESTS_PASSED", "tests_run": 3, "returncode": 0},
        }
        verified, report = asyncio.run(VerifierAgent.verify({}, bundle))
        self.assertFalse(verified)
        self.assertFalse(report["evidence"]["developer_execution"])

    def test_accepts_only_real_execution_and_nonzero_test_count(self):
        bundle = {
            "product": {"status": "ANALYSIS_COMPLETE"},
            "security": {"approved": True},
            "developer": {"status": "EXECUTED", "returncode": 0, "output": "completed"},
            "test": {"status": "TESTS_PASSED", "tests_run": 1, "returncode": 0},
        }
        verified, report = asyncio.run(VerifierAgent.verify({}, bundle))
        self.assertTrue(verified)
        self.assertTrue(report["evidence"]["test_pass_evidence"])

    def test_rejects_zero_test_count(self):
        bundle = {
            "product": {"status": "ANALYSIS_COMPLETE"},
            "security": {"approved": True},
            "developer": {"status": "EXECUTED", "returncode": 0},
            "test": {"status": "TESTS_PASSED", "tests_run": 0, "returncode": 0},
        }
        verified, _ = asyncio.run(VerifierAgent.verify({}, bundle))
        self.assertFalse(verified)


if __name__ == "__main__":
    unittest.main()


class SecretHandlingTests(unittest.TestCase):
    def test_security_agent_rejects_secret_in_prompt(self):
        task = {
            "description": 'Please use api_key="test_secret_value_1234567890"',
            "input_data": {},
        }
        approved, report = asyncio.run(SecurityAgent.review(task))
        self.assertFalse(approved)
        self.assertEqual(report["status"], "SECRET_REDACTION_REQUIRED")
        self.assertTrue(report["requires_redaction"])

    def test_security_agent_rejects_secret_in_input_data(self):
        task = {
            "description": "Run the requested task",
            "input_data": {"api_key": "test-secret-value"},
        }
        approved, report = asyncio.run(SecurityAgent.review(task))
        self.assertFalse(approved)
        self.assertEqual(report["status"], "SECRET_REDACTION_REQUIRED")

    def test_submit_task_rejects_secret_before_database_write(self):
        with patch.object(MaestroOrchestrator, "register_agent_states") as register:
            with patch("maestro_engine.task_store.create_task") as create_task:
                with self.assertRaisesRegex(ValueError, "بيانات تشبه الأسرار"):
                    asyncio.run(MaestroOrchestrator.submit_task(
                        description='api_key="test_secret_value_1234567890"'
                    ))
                register.assert_not_called()
                create_task.assert_not_called()
