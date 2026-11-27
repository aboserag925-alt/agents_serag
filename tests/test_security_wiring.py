import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SecurityWiringTests(unittest.TestCase):
    def test_websocket_is_registered_only_after_authentication(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        manager = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ConnectionManager"
        )
        connect = next(node for node in manager.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "connect")
        register = next(node for node in manager.body if isinstance(node, ast.FunctionDef) and node.name == "register_authenticated")

        self.assertFalse(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            for node in ast.walk(connect)
        ))
        self.assertTrue(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            for node in ast.walk(register)
        ))

        endpoint = next(
            node for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "websocket_endpoint"
        )
        calls = [
            node for node in ast.walk(endpoint)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"verify_token", "register_authenticated"}
        ]
        call_names = [node.func.attr for node in sorted(calls, key=lambda n: n.lineno)]
        self.assertLess(call_names.index("verify_token"), call_names.index("register_authenticated"))

    def test_cors_does_not_default_to_wildcard(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn('os.getenv("ALLOWED_ORIGINS", "")', source)
        self.assertIn('origin.strip() != "*"', source)


if __name__ == "__main__":
    unittest.main()


class AgentProcessLaunchTests(unittest.TestCase):
    def test_agent_commands_are_started_without_a_shell(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        endpoint = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "api_start_agent"
        )
        calls = [
            node for node in ast.walk(endpoint)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Popen"
        ]
        self.assertEqual(len(calls), 1)
        kwargs = {item.arg: item.value for item in calls[0].keywords}
        self.assertIsInstance(kwargs.get("shell"), ast.Constant)
        self.assertIs(kwargs["shell"].value, False)
        self.assertIsInstance(calls[0].args[0], ast.Name)
        self.assertEqual(calls[0].args[0].id, "argv")
        self.assertTrue(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "split"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shlex"
            for node in ast.walk(endpoint)
        ))
