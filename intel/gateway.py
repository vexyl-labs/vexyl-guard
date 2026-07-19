from __future__ import annotations

import errno
import grp
import hmac
import json
import os
import secrets
import signal
import socket
import socketserver
import stat
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from uuid import uuid4

from .database import runtime_history_status, seed_db
from .integration import DECISION_SCHEMA, EVENT_SCHEMA, GatewayEventError
from .integration import validate_gateway_event
from .scoring import score_and_record_ai_event

DEFAULT_DB_PATH = "/var/lib/vexyl/ai_threats.sqlite"
DEFAULT_SOCKET_PATH = "/run/vexyl/ai-gateway.sock"
DEFAULT_TOKEN_FILE = "/etc/vexyl/ai-gateway.token"
DEFAULT_MAX_BODY_BYTES = 65_536
MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 256


class GatewayConfigurationError(RuntimeError):
    """Raised when the local gateway cannot start securely."""


class _GatewayShutdown(Exception):
    pass


@dataclass(frozen=True)
class GatewayConfiguration:
    db_path: str
    socket_path: str
    token: str
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    socket_mode: int = 0o660
    socket_group: str | None = None


class VexylGatewayServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    request_queue_size = 64
    request_timeout_seconds = 5.0

    def __init__(self, configuration: GatewayConfiguration) -> None:
        self.configuration = configuration
        self._socket_inode: int | None = None
        _prepare_socket_path(configuration.socket_path)
        super().__init__(configuration.socket_path, VexylGatewayRequestHandler)
        try:
            os.chmod(configuration.socket_path, configuration.socket_mode)
            if configuration.socket_group:
                group_id = grp.getgrnam(configuration.socket_group).gr_gid
                os.chown(configuration.socket_path, -1, group_id)
            self._socket_inode = os.stat(configuration.socket_path).st_ino
        except Exception:
            super().server_close()
            _unlink_owned_socket(configuration.socket_path)
            raise

    def server_close(self) -> None:
        super().server_close()
        path = self.configuration.socket_path
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(path_stat.st_mode) and path_stat.st_ino == self._socket_inode:
            os.unlink(path)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address


class VexylGatewayRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "VexylLocalGateway"
    sys_version = ""

    def do_GET(self) -> None:
        if not self._authorize():
            return
        if self.path == "/v1/health":
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "vexyl-ai-gateway",
                    "event_schema": EVENT_SCHEMA,
                    "decision_schema": DECISION_SCHEMA,
                },
            )
            return
        if self.path == "/v1/runtime-status":
            status = runtime_history_status(self._configuration.db_path)
            self._send_json(200, {"ok": True, "runtime_history": status})
            return
        self._error(404, "not_found", "endpoint not found")

    def do_POST(self) -> None:
        if not self._authorize():
            return
        if self.path != "/v1/decisions":
            self._error(404, "not_found", "endpoint not found")
            return
        if self.headers.get("Transfer-Encoding"):
            self._error(
                400, "unsupported_transfer_encoding", "content length is required"
            )
            return
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            self._error(415, "unsupported_media_type", "application/json is required")
            return

        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            content_length = -1
        if content_length < 1:
            self._error(
                400, "invalid_content_length", "a JSON request body is required"
            )
            return
        if content_length > self._configuration.max_body_bytes:
            self._error(
                413, "request_too_large", "request body exceeds the local limit"
            )
            return

        try:
            body = self.rfile.read(content_length)
            envelope = json.loads(body.decode("utf-8"))
            event = self._validate_envelope(envelope)
            decision = score_and_record_ai_event(
                event, db_path=self._configuration.db_path
            )
        except TimeoutError:
            self._error(408, "request_timeout", "request body timed out")
            return
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "invalid_json", "request body must be valid JSON")
            return
        except GatewayEventError as exc:
            self._error(400, "invalid_event", str(exc))
            return
        except Exception as exc:
            print(
                f"Vexyl AI gateway request failed: {type(exc).__name__}",
                file=sys.stderr,
            )
            self._error(500, "scoring_failed", "local scoring could not complete")
            return

        policy_exit_code = decision_policy_exit_code(decision.to_dict())
        self._send_json(
            200,
            {
                "ok": True,
                "schema": DECISION_SCHEMA,
                "request_id": str(uuid4()),
                "recorded": True,
                "policy_exit_code": policy_exit_code,
                "decision": decision.to_dict(),
            },
        )

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_HEAD(self) -> None:
        if self._authorize():
            self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        if self._authorize():
            self._method_not_allowed()

    def do_TRACE(self) -> None:
        if self._authorize():
            self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def _configuration(self) -> GatewayConfiguration:
        return self.server.configuration  # type: ignore[attr-defined,no-any-return]

    def _authorize(self) -> bool:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, provided = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not hmac.compare_digest(provided, self._configuration.token)
        ):
            self._error(
                401, "unauthorized", "valid local bearer authentication is required"
            )
            return False
        return True

    def _validate_envelope(self, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            raise GatewayEventError("request envelope must be a JSON object")
        unknown = sorted(set(envelope) - {"schema", "event"})
        if unknown:
            raise GatewayEventError(f"unsupported envelope field: {unknown[0]}")
        if envelope.get("schema") != EVENT_SCHEMA:
            raise GatewayEventError("unsupported event schema")
        event = envelope.get("event")
        if not isinstance(event, dict):
            raise GatewayEventError("event must be a JSON object")
        return validate_gateway_event(event).to_dict()

    def _method_not_allowed(self) -> None:
        self._error(405, "method_not_allowed", "HTTP method is not supported")

    def _error(self, status: int, code: str, message: str) -> None:
        self._send_json(
            status,
            {"ok": False, "error": {"code": code, "message": message}},
        )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def create_gateway_server(
    *,
    db_path: str = DEFAULT_DB_PATH,
    socket_path: str = DEFAULT_SOCKET_PATH,
    token: str,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    socket_mode: int = 0o660,
    socket_group: str | None = None,
) -> VexylGatewayServer:
    _validate_token(token)
    if not 4096 <= max_body_bytes <= 1_048_576:
        raise GatewayConfigurationError(
            "gateway body limit must be between 4096 and 1048576 bytes"
        )
    if socket_mode & 0o007:
        raise GatewayConfigurationError("gateway socket cannot grant access to others")
    Path(socket_path).parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    seed_db(db_path)
    return VexylGatewayServer(
        GatewayConfiguration(
            db_path=db_path,
            socket_path=socket_path,
            token=token,
            max_body_bytes=max_body_bytes,
            socket_mode=socket_mode,
            socket_group=socket_group,
        )
    )


def serve_gateway(**kwargs: Any) -> None:
    server = create_gateway_server(**kwargs)
    print(f"Vexyl AI gateway listening on {server.configuration.socket_path}")
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_shutdown(signum: int, frame: Any) -> None:
        raise _GatewayShutdown

    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        server.serve_forever(poll_interval=0.25)
    except (_GatewayShutdown, KeyboardInterrupt):
        pass
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        server.server_close()


def create_gateway_token_file(
    path: str,
    *,
    force: bool = False,
    group: str | None = None,
) -> Path:
    token_path = Path(path)
    token_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(token_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise GatewayConfigurationError("gateway token path must be a regular file")
        os.fchmod(descriptor, 0o600)
        token = secrets.token_urlsafe(48)
        os.write(descriptor, f"{token}\n".encode("ascii"))
        os.fsync(descriptor)
        if group:
            os.fchown(descriptor, -1, grp.getgrnam(group).gr_gid)
            os.fchmod(descriptor, 0o640)
    finally:
        os.close(descriptor)
    return token_path


def read_gateway_token(path: str) -> str:
    try:
        path_stat = os.lstat(path)
    except OSError as exc:
        raise GatewayConfigurationError(
            "unable to read the gateway token file"
        ) from exc
    if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
        raise GatewayConfigurationError("gateway token path must be a regular file")
    if path_stat.st_mode & (stat.S_IWGRP | stat.S_IRWXO):
        raise GatewayConfigurationError(
            "gateway token file must not be group-writable or accessible by others"
        )
    try:
        token = Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise GatewayConfigurationError(
            "unable to read the gateway token file"
        ) from exc
    _validate_token(token)
    return token


def decision_policy_exit_code(decision: dict[str, Any]) -> int:
    score = int(decision.get("score") or 0)
    if decision.get("deny_tool_call") is True or score >= 70:
        return 4
    if score >= 50:
        return 3
    return 0


def parse_socket_mode(value: str) -> int:
    try:
        parsed = int(value, 8)
    except ValueError as exc:
        raise GatewayConfigurationError("socket mode must be an octal value") from exc
    if not 0 <= parsed <= 0o777:
        raise GatewayConfigurationError("socket mode is outside the accepted range")
    return parsed


def _validate_token(token: str) -> None:
    if not MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH:
        raise GatewayConfigurationError("gateway token length is invalid")
    if any(character.isspace() for character in token):
        raise GatewayConfigurationError("gateway token cannot contain whitespace")


def _prepare_socket_path(path: str) -> None:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(path_stat.st_mode):
        raise GatewayConfigurationError(
            "gateway socket path already exists and is not a socket"
        )

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        probe.connect(path)
    except OSError as exc:
        if exc.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise GatewayConfigurationError(
                "gateway socket path is not available"
            ) from exc
    else:
        raise GatewayConfigurationError("another gateway is already listening")
    finally:
        probe.close()

    if path_stat.st_uid != os.geteuid():
        raise GatewayConfigurationError("stale gateway socket is owned by another user")
    os.unlink(path)


def _unlink_owned_socket(path: str) -> None:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(path_stat.st_mode) and path_stat.st_uid == os.geteuid():
        os.unlink(path)
