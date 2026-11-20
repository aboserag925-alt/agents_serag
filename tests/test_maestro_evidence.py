import asyncio
import unittest

from maestro_engine import VerifierAgent


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
