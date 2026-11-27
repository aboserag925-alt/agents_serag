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


class StartupRecoveryWiringTests(unittest.TestCase):
    def test_startup_schedules_recovered_receive_tasks(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        lifespan = next(
            node for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "lifespan"
        )
        calls = [
            node for node in ast.walk(lifespan)
            if isinstance(node, ast.Call)
        ]
        list_tasks_calls = [
            node for node in calls
            if isinstance(node.func, ast.Attribute)
            and node.func.attr == "list_tasks"
        ]
        self.assertTrue(list_tasks_calls)
        self.assertTrue(any(
            keyword.arg == "status"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "RECEIVE"
            for call in list_tasks_calls for keyword in call.keywords
        ))
        self.assertTrue(any(
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "create_task"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "asyncio"
            for node in calls
        ))


class ApiRateLimitWiringTests(unittest.TestCase):
    def test_http_api_middleware_applies_rate_limiter(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        middleware = next(
            node for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "protect_api_routes"
        )
        self.assertTrue(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "is_rate_limited"
            for node in ast.walk(middleware)
        ))
