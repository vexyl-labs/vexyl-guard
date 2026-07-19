from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from .client import GatewayClientError, VexylGatewayClient
from .integration import (
    GatewayEventError,
    mcp_tool_call_event,
    model_api_event,
)

ASGIApp = Callable[
    [
        MutableMapping[str, Any],
        Callable[[], Awaitable[dict[str, Any]]],
        Callable[[dict[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]


class VexylPolicyError(RuntimeError):
    status_code = 500
    error_code = "vexyl_policy_error"

    def public_payload(self) -> dict[str, Any]:
        return {"error": self.error_code}


class VexylPolicyUnavailable(VexylPolicyError):
    status_code = 503
    error_code = "vexyl_policy_unavailable"

    def __init__(self) -> None:
        super().__init__("local Vexyl Guard policy decision is unavailable")


class VexylPolicyDenied(VexylPolicyError):
    error_code = "vexyl_policy_denied"

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.policy_exit_code = int(response.get("policy_exit_code") or 4)
        self.status_code = 409 if self.policy_exit_code == 3 else 403
        decision = response.get("decision")
        self.decision = decision if isinstance(decision, dict) else {}
        super().__init__(str(self.decision.get("suggested_action") or "policy denied"))

    def public_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.error_code,
            "policy_exit_code": self.policy_exit_code,
            "suggested_action": self.decision.get("suggested_action")
            or "block and review",
        }
        request_id = self.response.get("request_id")
        if isinstance(request_id, str) and request_id:
            payload["request_id"] = request_id
        return payload


class VexylRequestGuard:
    """Request-scoped access to the local gateway without inspecting request bodies."""

    def __init__(self, client: VexylGatewayClient) -> None:
        self.client = client

    async def score(self, event: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await asyncio.to_thread(self.client.score, event)
        except (GatewayClientError, GatewayEventError) as exc:
            raise VexylPolicyUnavailable from exc
        policy_code = response.get("policy_exit_code")
        if (
            not isinstance(policy_code, int)
            or isinstance(policy_code, bool)
            or policy_code not in {0, 3, 4}
        ):
            raise VexylPolicyUnavailable
        return response

    async def require_allowed(self, event: dict[str, Any]) -> dict[str, Any]:
        response = await self.score(event)
        if response["policy_exit_code"] != 0:
            raise VexylPolicyDenied(response)
        return response


class VexylASGIMiddleware:
    """Inject a VexylRequestGuard into ASGI HTTP request state."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        client: VexylGatewayClient | None = None,
        state_key: str = "vexyl_guard",
    ) -> None:
        if not state_key or not state_key.isidentifier():
            raise ValueError("state_key must be a valid identifier")
        self.app = app
        self.client = client or VexylGatewayClient()
        self.state_key = state_key

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        state = scope.get("state")
        if not isinstance(state, MutableMapping):
            state = {}
            scope["state"] = state
        state[self.state_key] = VexylRequestGuard(self.client)

        response_started = False

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except VexylPolicyError as exc:
            if response_started:
                raise
            await _send_policy_error(send, exc)


def guard_from_asgi_scope(
    scope: MutableMapping[str, Any], *, state_key: str = "vexyl_guard"
) -> VexylRequestGuard:
    state = scope.get("state")
    guard = state.get(state_key) if isinstance(state, MutableMapping) else None
    if not isinstance(guard, VexylRequestGuard):
        raise VexylPolicyUnavailable
    return guard


class MCPToolGuard:
    """Apply trusted static MCP tool policy before invoking a tool handler."""

    def __init__(
        self,
        request_guard: VexylRequestGuard,
        *,
        server_name: str,
        tool_name: str,
        tool_action: str,
        permissions: Iterable[str] = (),
        user_allowed_actions: Iterable[str] = (),
        policy_allowed_actions: Iterable[str] = (),
        verified_mitigations: Iterable[str] = (),
    ) -> None:
        self.request_guard = request_guard
        self.server_name = server_name
        self.tool_name = tool_name
        self.tool_action = tool_action
        self.permissions = tuple(permissions)
        self.allowed_tool = f"mcp:{server_name}:{tool_name}"
        self.user_allowed_actions = tuple(user_allowed_actions)
        self.policy_allowed_actions = tuple(policy_allowed_actions)
        self.verified_mitigations = tuple(verified_mitigations)

    async def authorize(
        self,
        security_summary: str,
        *,
        user_id_hash: str | None = None,
        session_id_hash: str | None = None,
        data_origin: str = "internal_db",
        data_classification: str = "unknown",
        network_destination: str | None = None,
        human_approval: bool = False,
        irreversible: bool = False,
    ) -> dict[str, Any]:
        event = mcp_tool_call_event(
            security_summary,
            server_name=self.server_name,
            tool_name=self.tool_name,
            tool_action=self.tool_action,
            permissions=self.permissions,
            allowed_tools=[self.allowed_tool],
            user_allowed_actions=self.user_allowed_actions,
            policy_allowed_actions=self.policy_allowed_actions,
            verified_mitigations=self.verified_mitigations,
            user_id_hash=user_id_hash,
            session_id_hash=session_id_hash,
            data_origin=data_origin,
            data_classification=data_classification,
            network_destination=network_destination,
            human_approval=human_approval,
            irreversible=irreversible,
        )
        return await self.request_guard.require_allowed(event)


class ModelGatewayGuard:
    """Apply model identity and budget policy before a provider invocation."""

    def __init__(
        self,
        request_guard: VexylRequestGuard,
        *,
        expected_model_provider: str,
        expected_model_name: str,
        runtime_token_budget: int = 250_000,
        runtime_cost_budget: float = 25.0,
    ) -> None:
        self.request_guard = request_guard
        self.expected_model_provider = expected_model_provider
        self.expected_model_name = expected_model_name
        self.runtime_token_budget = runtime_token_budget
        self.runtime_cost_budget = runtime_cost_budget

    async def authorize(
        self,
        security_summary: str,
        *,
        model_provider: str,
        model_name: str,
        user_id_hash: str | None = None,
        session_id_hash: str | None = None,
        token_count_estimate: int = 0,
        cost_estimate: float = 0.0,
    ) -> dict[str, Any]:
        event = model_api_event(
            security_summary,
            model_provider=model_provider,
            model_name=model_name,
            expected_model_provider=self.expected_model_provider,
            expected_model_name=self.expected_model_name,
            user_id_hash=user_id_hash,
            session_id_hash=session_id_hash,
            token_count_estimate=token_count_estimate,
            cost_estimate=cost_estimate,
            runtime_token_budget=self.runtime_token_budget,
            runtime_cost_budget=self.runtime_cost_budget,
        )
        return await self.request_guard.require_allowed(event)


async def _send_policy_error(
    send: Callable[[dict[str, Any]], Awaitable[None]], error: VexylPolicyError
) -> None:
    body = json.dumps(error.public_payload(), separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": error.status_code,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
