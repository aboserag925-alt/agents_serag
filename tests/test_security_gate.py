import os
import unittest
from unittest.mock import patch

import security_gate


class VerifyTokenTests(unittest.TestCase):
    def test_rejects_missing_server_token(self):
        with patch.object(security_gate, "AUTH_TOKEN", ""):
            self.assertFalse(security_gate.verify_token("Bearer anything"))

    def test_reads_token_loaded_after_module_import(self):
        with patch.object(security_gate, "AUTH_TOKEN", ""), patch.dict(
            os.environ, {"HUB_AUTH_TOKEN": "loaded-from-env-file"}
        ):
            self.assertTrue(security_gate.verify_token("Bearer loaded-from-env-file"))

    def test_rejects_missing_request_token(self):
        with patch.object(security_gate, "AUTH_TOKEN", "configured-secret"):
            self.assertFalse(security_gate.verify_token(None))
            self.assertFalse(security_gate.verify_token(""))

    def test_accepts_exact_bearer_token(self):
        with patch.object(security_gate, "AUTH_TOKEN", "configured-secret"):
            self.assertTrue(security_gate.verify_token("Bearer configured-secret"))
            self.assertTrue(security_gate.verify_token("bearer configured-secret"))

    def test_rejects_wrong_and_development_bypass_tokens(self):
        with patch.object(security_gate, "AUTH_TOKEN", "configured-secret"):
            self.assertFalse(security_gate.verify_token("wrong"))
            self.assertFalse(security_gate.verify_token("dev-bypass"))

    def test_rejects_whitespace_only_request_token(self):
        with patch.object(security_gate, "AUTH_TOKEN", "configured-secret"):
            self.assertFalse(security_gate.verify_token("Bearer   "))


if __name__ == "__main__":
    unittest.main()
