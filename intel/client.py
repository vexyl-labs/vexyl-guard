from __future__ import annotations

import http.client
import json
import os
import socket
from pathlib import Path
from typing import Any

from .integration import (
    ALLOWED_EVENT_FIELDS,
    DECISION_SCHEMA,
    EVENT_SCHEMA,
    validate_gateway_event,
)

DEFAULT_SOCKET_PATH = "/run/vexyl/ai-gateway.sock"
DEFAULT_TOKEN_FILE = "/etc/vexyl/ai-gateway.token"
MAX_RESPONSE_BYTES = 262_144

_ALLOWED_RESPONSE_FIELDS = {
    "ok",
    "schema",
    "request_id",
    "recorded",
    "policy_exit_code",
    "decision",
}
_ALLOWED_DECISION_FIELDS = {
    "event_id",
    "score",
    "suggested_action",
    "matched_attack_ids",
    "matched_rules",
    "reasons",
    "mitigations_applied",
    "trust_level",
    "redacted_excerpt",
    "deny_tool_call",
    "correlation_scope",
    "correlation_window_seconds",
    "correlated_event_count",
}
_ALLOWED_TRUST_LEVELS = {
    "untrusted_data",
    "trusted_control",
    "user_instruction",
    "internal_data",
    "persistent_context",
    "unknown",
}


class GatewayClientError(RuntimeError):
    """Raised when the local gateway cannot return a valid decision."""


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class VexylGatewayClient:
    def __init__(
        self,
        *,
        socket_path: str | None = None,
        token: str | None = None,
        token_file: str | None = None,
        timeout: float = 2.0,
    ) -> None:
        self.socket_path = socket_path or os.environ.get(
            "VEXYL_AI_GATEWAY_SOCKET", DEFAULT_SOCKET_PATH
        )
        self.token = token or _read_token(
            token_file
            or os.environ.get("VEXYL_AI_GATEWAY_TOKEN_FILE", DEFAULT_TOKEN_FILE)
        )
        self.timeout = timeout

    def score(self, event: dict[str, Any]) -> dict[str, Any]:
        runtime_event = validate_gateway_event(event)
        normalized_event = {
            key: value
            for key, value in runtime_event.to_dict().items()
            if key in ALLOWED_EVENT_FIELDS and value is not None
        }
        payload = {
            "schema": EVENT_SCHEMA,
            "event": normalized_event,
        }
        response = self._request("POST", "/v1/decisions", payload)
        return validate_gateway_response(
            response, expected_event_id=runtime_event.event_id
        )

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health")

    def runtime_status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/runtime-status")

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Connection": "close",
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))

        connection = _UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            connection.request(method, path, body=body, headers=headers)
            http_response = connection.getresponse()
            response_body = http_response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise GatewayClientError("local Vexyl gateway request failed") from exc
        finally:
            connection.close()

        if len(response_body) > MAX_RESPONSE_BYTES:
            raise GatewayClientError("gateway response exceeded the local limit")
        if http_response.headers.get_content_type() != "application/json":
            raise GatewayClientError("gateway returned an unsupported content type")
        try:
            response = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayClientError(
                "gateway returned an invalid JSON response"
            ) from exc
        if not isinstance(response, dict):
            raise GatewayClientError("gateway returned an invalid response object")
        if http_response.status != 200 or response.get("ok") is not True:
            error = response.get("error")
            code = error.get("code") if isinstance(error, dict) else "gateway_error"
            raise GatewayClientError(f"gateway rejected the request: {code}")
        return response


def validate_gateway_response(
    response: dict[str, Any], *, expected_event_id: str | None = None
) -> dict[str, Any]:
    """Reject malformed or contradictory decisions before an application can allow."""

    if not isinstance(response, dict):
        raise GatewayClientError("gateway returned an invalid response object")
    unknown_response_fields = sorted(set(response) - _ALLOWED_RESPONSE_FIELDS)
    if unknown_response_fields:
        raise GatewayClientError(
            f"gateway returned an unsupported response field: "
            f"{unknown_response_fields[0]}"
        )
    if response.get("ok") is not True:
        raise GatewayClientError("gateway response was not successful")
    if response.get("schema") != DECISION_SCHEMA:
        raise GatewayClientError("gateway returned an unsupported decision schema")
    if response.get("recorded") is not True:
        raise GatewayClientError("gateway decision was not recorded")
    _required_string(response, "request_id", maximum_length=128)

    policy_exit_code = _required_integer(
        response, "policy_exit_code", minimum=0, maximum=4
    )
    if policy_exit_code not in {0, 3, 4}:
        raise GatewayClientError("gateway returned an unsupported policy exit code")

    decision = response.get("decision")
    if not isinstance(decision, dict):
        raise GatewayClientError("gateway response did not include a decision")
    unknown_decision_fields = sorted(set(decision) - _ALLOWED_DECISION_FIELDS)
    if unknown_decision_fields:
        raise GatewayClientError(
            f"gateway returned an unsupported decision field: "
            f"{unknown_decision_fields[0]}"
        )

    event_id = _required_string(decision, "event_id", maximum_length=128)
    if expected_event_id is not None and event_id != expected_event_id:
        raise GatewayClientError("gateway decision event id did not match the request")
    score = _required_integer(decision, "score", minimum=0, maximum=100)
    suggested_action = _required_string(decision, "suggested_action", maximum_length=80)
    expected_action = _suggested_action_for_score(score)
    if suggested_action != expected_action:
        raise GatewayClientError("gateway decision action contradicted its score")

    _required_string_list(
        decision, "matched_attack_ids", maximum_items=64, maximum_length=128
    )
    _required_string_list(
        decision, "matched_rules", maximum_items=128, maximum_length=256
    )
    _required_string_list(decision, "reasons", maximum_items=64, maximum_length=512)
    _required_string_list(
        decision, "mitigations_applied", maximum_items=32, maximum_length=128
    )

    trust_level = _required_string(decision, "trust_level", maximum_length=32)
    if trust_level not in _ALLOWED_TRUST_LEVELS:
        raise GatewayClientError("gateway returned an unsupported trust level")
    if "redacted_excerpt" not in decision:
        raise GatewayClientError("gateway response did not include redacted_excerpt")
    redacted_excerpt = decision["redacted_excerpt"]
    if redacted_excerpt is not None and (
        not isinstance(redacted_excerpt, str) or len(redacted_excerpt) > 500
    ):
        raise GatewayClientError("gateway returned an invalid redacted excerpt")
    deny_tool_call = decision.get("deny_tool_call")
    if not isinstance(deny_tool_call, bool):
        raise GatewayClientError("gateway returned an invalid tool decision")

    if "correlation_scope" not in decision:
        raise GatewayClientError("gateway response did not include correlation_scope")
    correlation_scope = decision["correlation_scope"]
    if correlation_scope is not None and correlation_scope not in {"session", "user"}:
        raise GatewayClientError("gateway returned an invalid correlation scope")
    _required_integer(
        decision,
        "correlation_window_seconds",
        minimum=0,
        maximum=86_400,
    )
    _required_integer(decision, "correlated_event_count", minimum=0, maximum=2_000)

    expected_exit_code = _policy_exit_code(score, deny_tool_call)
    if policy_exit_code != expected_exit_code:
        raise GatewayClientError("gateway policy exit code contradicted its decision")
    return response


def _suggested_action_for_score(score: int) -> str:
    if score <= 24:
        return "allow/log"
    if score <= 49:
        return "warn/log"
    if score <= 69:
        return "require human approval or policy verifier"
    if score <= 84:
        return "quarantine/block tool action"
    return "block and open incident"


def _policy_exit_code(score: int, deny_tool_call: bool) -> int:
    if deny_tool_call or score >= 70:
        return 4
    if score >= 50:
        return 3
    return 0


def _required_string(data: dict[str, Any], key: str, *, maximum_length: int) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum_length:
        raise GatewayClientError(f"gateway returned an invalid {key}")
    return value


def _required_integer(
    data: dict[str, Any], key: str, *, minimum: int, maximum: int
) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise GatewayClientError(f"gateway returned an invalid {key}")
    if not minimum <= value <= maximum:
        raise GatewayClientError(f"gateway returned an out-of-range {key}")
    return value


def _required_string_list(
    data: dict[str, Any],
    key: str,
    *,
    maximum_items: int,
    maximum_length: int,
) -> None:
    value = data.get(key)
    if not isinstance(value, list) or len(value) > maximum_items:
        raise GatewayClientError(f"gateway returned an invalid {key}")
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > maximum_length:
            raise GatewayClientError(f"gateway returned an invalid {key} item")


def _read_token(path: str) -> str:
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise GatewayClientError("unable to read the local gateway token") from exc
    if not 32 <= len(token) <= 256 or any(character.isspace() for character in token):
        raise GatewayClientError("local gateway token is invalid")
    return token
