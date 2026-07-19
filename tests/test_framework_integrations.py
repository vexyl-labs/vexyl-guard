from __future__ import annotations

import json
import unittest
from typing import Any

from intel.client import GatewayClientError
from intel.middleware import (
    MCPToolGuard,
    ModelGatewayGuard,
    VexylASGIMiddleware,
    VexylPolicyDenied,
    VexylPolicyUnavailable,
    VexylRequestGuard,
    guard_from_asgi_scope,
)


class FakeGatewayClient:
    def __init__(
        self, response: dict[str, Any] | None = None, error: Exception | None = None
    ) -> None:
        self.response = response or allowed_response()
        self.error = error
        self.events: list[dict[str, Any]] = []

    def score(self, event: dict[str, Any]) -> dict[str, Any]:
        self.events.append(event)
        if self.error:
            raise self.error
        return self.response


def allowed_response() -> dict[str, Any]:
    return {
        "ok": True,
        "request_id": "safe-request-id",
        "policy_exit_code": 0,
        "decision": {"score": 0, "suggested_action": "allow/log"},
    }


def denied_response(policy_exit_code: int = 4) -> dict[str, Any]:
    return {
        "ok": True,
        "request_id": "safe-request-id",
        "policy_exit_code": policy_exit_code,
        "decision": {
            "score": 78 if policy_exit_code == 4 else 58,
            "suggested_action": (
                "quarantine/block tool action"
                if policy_exit_code == 4
                else "require human approval or policy verifier"
            ),
        },
    }


class FrameworkIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_guard_allows_only_policy_code_zero(self) -> None:
        guard = VexylRequestGuard(FakeGatewayClient())  # type: ignore[arg-type]
        response = await guard.require_allowed(
            {"input_channel": "chat", "data_origin": "user"}
        )
        self.assertEqual(response["policy_exit_code"], 0)

        denied = VexylRequestGuard(  # type: ignore[arg-type]
            FakeGatewayClient(denied_response())
        )
        with self.assertRaises(VexylPolicyDenied) as raised:
            await denied.require_allowed(
                {"input_channel": "tool", "data_origin": "internal_db"}
            )
        self.assertEqual(raised.exception.status_code, 403)

    async def test_request_guard_fails_closed_on_gateway_error(self) -> None:
        guard = VexylRequestGuard(  # type: ignore[arg-type]
            FakeGatewayClient(error=GatewayClientError("local test failure"))
        )
        with self.assertRaises(VexylPolicyUnavailable):
            await guard.require_allowed(
                {"input_channel": "chat", "data_origin": "user"}
            )

    async def test_request_guard_fails_closed_on_malformed_policy_code(self) -> None:
        response = allowed_response()
        response["policy_exit_code"] = []
        guard = VexylRequestGuard(  # type: ignore[arg-type]
            FakeGatewayClient(response=response)
        )
        with self.assertRaises(VexylPolicyUnavailable):
            await guard.require_allowed(
                {"input_channel": "chat", "data_origin": "user"}
            )

    async def test_asgi_middleware_does_not_read_the_request_body(self) -> None:
        client = FakeGatewayClient()
        sent: list[dict[str, Any]] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            guard = guard_from_asgi_scope(scope)
            await guard.require_allowed(
                {"input_channel": "chat", "data_origin": "user"}
            )
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def receive() -> dict[str, Any]:
            raise AssertionError("middleware must not consume the request body")

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        middleware = VexylASGIMiddleware(app, client=client)  # type: ignore[arg-type]
        await middleware({"type": "http", "state": {}}, receive, send)
        self.assertEqual(sent[0]["status"], 204)
        self.assertEqual(len(client.events), 1)

    async def test_asgi_middleware_returns_bounded_policy_errors(self) -> None:
        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            await guard_from_asgi_scope(scope).require_allowed(
                {"input_channel": "tool", "data_origin": "internal_db"}
            )

        async def receive() -> dict[str, Any]:
            raise AssertionError("middleware must not consume the request body")

        for policy_code, expected_status in ((3, 409), (4, 403)):
            sent: list[dict[str, Any]] = []

            async def send(message: dict[str, Any]) -> None:
                sent.append(message)

            middleware = VexylASGIMiddleware(  # type: ignore[arg-type]
                app,
                client=FakeGatewayClient(denied_response(policy_code)),
            )
            await middleware({"type": "http", "state": {}}, receive, send)
            self.assertEqual(sent[0]["status"], expected_status)
            payload = json.loads(sent[1]["body"])
            self.assertEqual(payload["policy_exit_code"], policy_code)
            self.assertNotIn("matched_rules", payload)

    async def test_mcp_guard_builds_exact_static_authorization(self) -> None:
        client = FakeGatewayClient()
        request_guard = VexylRequestGuard(client)  # type: ignore[arg-type]
        guard = MCPToolGuard(
            request_guard,
            server_name="docs",
            tool_name="search",
            tool_action="search approved documentation",
            permissions=["read"],
            user_allowed_actions=["search approved documentation"],
            policy_allowed_actions=["search approved documentation"],
            verified_mitigations=[
                "tool_allowlist",
                "scoped_read_only_credentials",
            ],
        )
        await guard.authorize("Search approved internal documentation.")
        event = client.events[0]
        self.assertEqual(event["tool_name"], "mcp:docs:search")
        self.assertEqual(event["context"]["allowed_tools"], ["mcp:docs:search"])
        self.assertEqual(
            event["context"]["user_scope"]["allowed_actions"],
            ["search approved documentation"],
        )

    async def test_model_gateway_guard_applies_expected_identity(self) -> None:
        client = FakeGatewayClient()
        request_guard = VexylRequestGuard(client)  # type: ignore[arg-type]
        guard = ModelGatewayGuard(
            request_guard,
            expected_model_provider="approved-provider",
            expected_model_name="approved-model",
        )
        await guard.authorize(
            "Invoke the approved summarization model.",
            model_provider="approved-provider",
            model_name="approved-model",
            token_count_estimate=1200,
        )
        event = client.events[0]
        self.assertEqual(event["model_provider"], "approved-provider")
        self.assertEqual(event["context"]["expected_model_name"], "approved-model")


if __name__ == "__main__":
    unittest.main(verbosity=2)
