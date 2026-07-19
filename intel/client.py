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
        if response.get("schema") != DECISION_SCHEMA:
            raise GatewayClientError("gateway returned an unsupported decision schema")
        if not isinstance(response.get("decision"), dict):
            raise GatewayClientError("gateway response did not include a decision")
        return response

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
            response_body = http_response.read(262_145)
        except (OSError, http.client.HTTPException) as exc:
            raise GatewayClientError("local Vexyl gateway request failed") from exc
        finally:
            connection.close()

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


def _read_token(path: str) -> str:
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise GatewayClientError("unable to read the local gateway token") from exc
    if not 32 <= len(token) <= 256 or any(character.isspace() for character in token):
        raise GatewayClientError("local gateway token is invalid")
    return token
