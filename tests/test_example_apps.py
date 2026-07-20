from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any

from intel.integration import DECISION_SCHEMA

try:
    import fastapi
    from httpx import ASGITransport, AsyncClient
except ImportError:
    fastapi = None  # type: ignore[assignment]
    ASGITransport = None  # type: ignore[assignment,misc]
    AsyncClient = None  # type: ignore[assignment,misc]

ROOT = Path(__file__).resolve().parents[1]
FASTAPI_EXAMPLE = ROOT / "integrations/examples/python/fastapi_app.py"
PYTHON_EXAMPLES = str(FASTAPI_EXAMPLE.parent)


class FakeGatewayClient:
    def __init__(self, policy_exit_code: int) -> None:
        self.policy_exit_code = policy_exit_code
        self.events: list[dict[str, Any]] = []

    def score(self, event: dict[str, Any]) -> dict[str, Any]:
        self.events.append(event)
        score = 0 if self.policy_exit_code == 0 else 78
        return {
            "ok": True,
            "schema": DECISION_SCHEMA,
            "request_id": "example-app-request",
            "recorded": True,
            "policy_exit_code": self.policy_exit_code,
            "decision": {
                "event_id": str(event.get("event_id") or "example-app-event"),
                "score": score,
                "suggested_action": (
                    "allow/log" if score == 0 else "quarantine/block tool action"
                ),
                "matched_attack_ids": [],
                "matched_rules": [],
                "reasons": [],
                "mitigations_applied": [],
                "trust_level": "untrusted_data",
                "redacted_excerpt": "Bounded example summary.",
                "deny_tool_call": False,
                "correlation_scope": None,
                "correlation_window_seconds": 0,
                "correlated_event_count": 0,
            },
        }


def load_fastapi_example() -> ModuleType:
    if PYTHON_EXAMPLES not in sys.path:
        sys.path.insert(0, PYTHON_EXAMPLES)
    spec = importlib.util.spec_from_file_location(
        "vexyl_fastapi_example", FASTAPI_EXAMPLE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the FastAPI example")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(
    fastapi is None or AsyncClient is None,
    "FastAPI example dependencies are not installed",
)
class FastAPIExampleCompatibilityTests(unittest.TestCase):
    def test_allow_route_does_not_read_or_forward_request_body(self) -> None:
        asyncio.run(self._assert_allow_route())

    async def _assert_allow_route(self) -> None:
        module = load_fastapi_example()
        gateway = FakeGatewayClient(0)
        app = module.create_app(
            client=gateway,
            identifier_key="fastapi-example-test-key-material",
        )
        transport = ASGITransport(app=app)  # type: ignore[misc,operator]
        async with AsyncClient(  # type: ignore[misc,operator]
            transport=transport,
            base_url="http://example.test",
        ) as client:
            response = await client.post(
                "/demo/rag/allow",
                content="token=body-value-must-not-be-read",
                headers={"content-type": "text/plain"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["context_admitted"])
        event = json.dumps(gateway.events[0], sort_keys=True)
        self.assertNotIn("body-value-must-not-be-read", event)
        self.assertNotIn("fastapi-demo-document-allow", event)
        self.assertNotIn("fastapi-demo-session-allow", event)

    def test_denied_route_returns_bounded_policy_response(self) -> None:
        asyncio.run(self._assert_denied_route())

    async def _assert_denied_route(self) -> None:
        module = load_fastapi_example()
        app = module.create_app(
            client=FakeGatewayClient(4),
            identifier_key="fastapi-example-test-key-material",
        )
        transport = ASGITransport(app=app)  # type: ignore[misc,operator]
        async with AsyncClient(  # type: ignore[misc,operator]
            transport=transport,
            base_url="http://example.test",
        ) as client:
            response = await client.post("/demo/rag/block")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["policy_exit_code"], 4)
        self.assertNotIn("matched_rules", response.json())
        self.assertEqual(response.headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main(verbosity=2)
