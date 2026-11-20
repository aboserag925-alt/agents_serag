import os
import unittest
from unittest.mock import patch

import security_gate


class VerifyTokenTests(unittest.TestCase):
    def setUp(self):
        self.auth_patch = patch.object(security_gate, "AUTH_TOKEN", None)
        self.auth_patch.start()
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.auth_patch.stop()

    def test_missing_server_secret_fails_closed(self):
        self.assertFalse(security_gate.verify_token("anything"))

    def test_missing_request_token_is_rejected(self):
        with patch.dict(os.environ, {"HUB_AUTH_TOKEN": "test-secret"}):
            self.assertFalse(security_gate.verify_token(None))
            self.assertFalse(security_gate.verify_token(""))

    def test_wrong_token_is_rejected(self):
        with patch.dict(os.environ, {"HUB_AUTH_TOKEN": "test-secret"}):
            self.assertFalse(security_gate.verify_token("wrong"))

    def test_legacy_development_bypass_is_rejected(self):
        with patch.dict(os.environ, {"HUB_AUTH_TOKEN": "test-secret"}):
            self.assertFalse(security_gate.verify_token("dev-bypass"))

    def test_exact_token_is_accepted(self):
        with patch.dict(os.environ, {"HUB_AUTH_TOKEN": "test-secret"}):
            self.assertTrue(security_gate.verify_token("test-secret"))

    def test_bearer_token_is_accepted(self):
        with patch.dict(os.environ, {"HUB_AUTH_TOKEN": "test-secret"}):
            self.assertTrue(security_gate.verify_token("Bearer test-secret"))


if __name__ == "__main__":
    unittest.main()
