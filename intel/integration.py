from __future__ import annotations

import hashlib
import hmac
import math
from datetime import datetime
from typing import Any, Iterable

from .models import RuntimeAIEvent

EVENT_SCHEMA = "vexyl.ai_event.v1"
DECISION_SCHEMA = "vexyl.risk_decision.v1"

ALLOWED_EVENT_FIELDS = {
    "event_id",
    "timestamp_utc",
    "user_id_hash",
    "session_id_hash",
    "model_provider",
    "model_name",
    "input_channel",
    "data_origin",
    "text_excerpt_redacted",
    "retrieved_doc_ids",
    "tool_name",
    "tool_action",
    "tool_permissions",
    "data_classification",
    "planned_actions",
    "network_destination",
    "cost_estimate",
    "token_count_estimate",
    "verified_mitigations",
    "context",
}

ALLOWED_CONTEXT_FIELDS = {
    "allowed_tools",
    "user_scope",
    "tool_policy",
    "human_approval",
    "human_approval_completed",
    "runtime_token_budget",
    "runtime_cost_budget",
    "expected_model_provider",
    "expected_model_name",
    "uses_delegated_identity",
    "delegated_identity_verified",
    "identity_scope_verified",
    "inter_agent_message",
    "sender_identity_verified",
    "message_integrity_verified",
    "delegation_depth",
    "fanout_count",
    "retry_count",
    "max_delegation_depth",
    "max_fanout_count",
    "max_retry_count",
    "approval_rationale_source",
    "independent_verification_completed",
    "oversight_disabled",
    "audit_disabled",
    "policy_self_modified",
    "undeclared_action",
    "irreversible",
    "cross_tenant",
}

BOOLEAN_CONTEXT_FIELDS = {
    "human_approval",
    "human_approval_completed",
    "uses_delegated_identity",
    "delegated_identity_verified",
    "identity_scope_verified",
    "inter_agent_message",
    "sender_identity_verified",
    "message_integrity_verified",
    "independent_verification_completed",
    "oversight_disabled",
    "audit_disabled",
    "policy_self_modified",
    "undeclared_action",
    "irreversible",
    "cross_tenant",
}

INTEGER_CONTEXT_FIELDS = {
    "runtime_token_budget",
    "delegation_depth",
    "fanout_count",
    "retry_count",
    "max_delegation_depth",
    "max_fanout_count",
    "max_retry_count",
}

STRING_CONTEXT_FIELDS = {
    "expected_model_provider",
    "expected_model_name",
    "approval_rationale_source",
}

ALLOWED_INPUT_CHANNELS = {
    "api",
    "agent_plan",
    "chat",
    "email",
    "file",
    "memory",
    "model",
    "other",
    "rag",
    "supply_chain",
    "tool",
    "web",
}

ALLOWED_DATA_ORIGINS = {
    "developer",
    "internal_db",
    "memory",
    "model_output",
    "retrieved_external",
    "supply_chain",
    "system",
    "tool_output",
    "unknown",
    "user",
}

ALLOWED_DATA_CLASSIFICATIONS = {
    "public",
    "internal",
    "confidential",
    "secret",
    "regulated",
    "unknown",
}


class GatewayEventError(ValueError):
    """Raised when an integration submits an unsafe or malformed event."""


def hash_identifier(identifier: str, key: str | bytes) -> str:
    """Create a stable opaque identifier without exposing the source value."""

    if not isinstance(identifier, str) or not identifier:
        raise GatewayEventError("identifier must be a non-empty string")
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    if len(key_bytes) < 16:
        raise GatewayEventError("identifier hashing key must be at least 16 bytes")
    return hmac.new(key_bytes, identifier.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_gateway_event(data: dict[str, Any]) -> RuntimeAIEvent:
    """Validate the narrow, redacted event contract accepted by the gateway."""

    if not isinstance(data, dict):
        raise GatewayEventError("event must be a JSON object")

    unknown = sorted(set(data) - ALLOWED_EVENT_FIELDS)
    if unknown:
        raise GatewayEventError(f"unsupported event field: {unknown[0]}")

    _optional_string(data, "event_id", 128)
    _validate_timestamp(data.get("timestamp_utc"))
    _optional_string(data, "user_id_hash", 256)
    _optional_string(data, "session_id_hash", 256)
    _optional_string(data, "model_provider", 128)
    _optional_string(data, "model_name", 128)
    _enum_value(data, "input_channel", ALLOWED_INPUT_CHANNELS)
    _enum_value(data, "data_origin", ALLOWED_DATA_ORIGINS)
    _optional_string(data, "text_excerpt_redacted", 2048)
    _string_list(data, "retrieved_doc_ids", maximum_items=64, maximum_length=256)
    _optional_string(data, "tool_name", 256)
    _optional_string(data, "tool_action", 512)
    _string_list(data, "tool_permissions", maximum_items=32, maximum_length=128)
    _enum_value(data, "data_classification", ALLOWED_DATA_CLASSIFICATIONS)
    _string_list(data, "planned_actions", maximum_items=64, maximum_length=512)
    _optional_string(data, "network_destination", 512)
    _number_value(data, "cost_estimate", minimum=0, maximum=1_000_000)
    _integer_value(data, "token_count_estimate", minimum=0, maximum=2_000_000_000)
    _string_list(data, "verified_mitigations", maximum_items=32, maximum_length=128)
    _validate_context(data.get("context"))
    return RuntimeAIEvent.from_dict(data)


def prompt_event(
    security_summary: str,
    *,
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    data_classification: str = "unknown",
) -> dict[str, Any]:
    return _event(
        input_channel="chat",
        data_origin="user",
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        data_classification=data_classification,
    )


def rag_content_event(
    security_summary: str,
    *,
    document_ids: Iterable[str] = (),
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    data_classification: str = "unknown",
) -> dict[str, Any]:
    return _event(
        input_channel="rag",
        data_origin="retrieved_external",
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        data_classification=data_classification,
        retrieved_doc_ids=list(document_ids),
    )


def memory_write_event(
    security_summary: str,
    *,
    data_origin: str,
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    data_classification: str = "unknown",
) -> dict[str, Any]:
    return _event(
        input_channel="memory",
        data_origin=data_origin,
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        data_classification=data_classification,
        planned_actions=["write persistent memory"],
    )


def agent_plan_event(
    security_summary: str,
    *,
    planned_actions: Iterable[str],
    allowed_tools: Iterable[str] = (),
    user_allowed_actions: Iterable[str] = (),
    policy_allowed_actions: Iterable[str] = (),
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    human_approval: bool = False,
) -> dict[str, Any]:
    return _event(
        input_channel="agent_plan",
        data_origin="internal_db",
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        planned_actions=list(planned_actions),
        context=_authorization_context(
            allowed_tools,
            user_allowed_actions,
            policy_allowed_actions,
            human_approval,
        ),
    )


def tool_call_event(
    security_summary: str,
    *,
    tool_name: str,
    tool_action: str,
    permissions: Iterable[str] = (),
    allowed_tools: Iterable[str] = (),
    user_allowed_actions: Iterable[str] = (),
    policy_allowed_actions: Iterable[str] = (),
    verified_mitigations: Iterable[str] = (),
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    data_origin: str = "internal_db",
    data_classification: str = "unknown",
    network_destination: str | None = None,
    human_approval: bool = False,
    irreversible: bool = False,
) -> dict[str, Any]:
    return _event(
        input_channel="tool",
        data_origin=data_origin,
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        tool_name=tool_name,
        tool_action=tool_action,
        tool_permissions=list(permissions),
        data_classification=data_classification,
        network_destination=network_destination,
        verified_mitigations=list(verified_mitigations),
        context={
            **_authorization_context(
                allowed_tools,
                user_allowed_actions,
                policy_allowed_actions,
                human_approval,
            ),
            "irreversible": irreversible,
        },
    )


def mcp_tool_call_event(
    security_summary: str,
    *,
    server_name: str,
    tool_name: str,
    tool_action: str,
    **kwargs: Any,
) -> dict[str, Any]:
    return tool_call_event(
        security_summary,
        tool_name=f"mcp:{server_name}:{tool_name}",
        tool_action=tool_action,
        **kwargs,
    )


def model_api_event(
    security_summary: str,
    *,
    model_provider: str,
    model_name: str,
    expected_model_provider: str,
    expected_model_name: str,
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    token_count_estimate: int = 0,
    cost_estimate: float = 0.0,
    runtime_token_budget: int = 250_000,
    runtime_cost_budget: float = 25.0,
) -> dict[str, Any]:
    return _event(
        input_channel="model",
        data_origin="internal_db",
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        model_provider=model_provider,
        model_name=model_name,
        token_count_estimate=token_count_estimate,
        cost_estimate=cost_estimate,
        context={
            "expected_model_provider": expected_model_provider,
            "expected_model_name": expected_model_name,
            "runtime_token_budget": runtime_token_budget,
            "runtime_cost_budget": runtime_cost_budget,
        },
    )


def supply_chain_event(
    security_summary: str,
    *,
    user_id_hash: str | None = None,
    session_id_hash: str | None = None,
    human_approval: bool = False,
) -> dict[str, Any]:
    return _event(
        input_channel="supply_chain",
        data_origin="supply_chain",
        security_summary=security_summary,
        user_id_hash=user_id_hash,
        session_id_hash=session_id_hash,
        planned_actions=["change AI supply-chain component"],
        context={"human_approval": human_approval},
    )


def _event(
    *,
    input_channel: str,
    data_origin: str,
    security_summary: str,
    user_id_hash: str | None,
    session_id_hash: str | None,
    **values: Any,
) -> dict[str, Any]:
    event = {
        "input_channel": input_channel,
        "data_origin": data_origin,
        "text_excerpt_redacted": security_summary,
        **values,
    }
    if user_id_hash:
        event["user_id_hash"] = user_id_hash
    if session_id_hash:
        event["session_id_hash"] = session_id_hash
    validate_gateway_event(event)
    return event


def _authorization_context(
    allowed_tools: Iterable[str],
    user_allowed_actions: Iterable[str],
    policy_allowed_actions: Iterable[str],
    human_approval: bool,
) -> dict[str, Any]:
    return {
        "allowed_tools": list(allowed_tools),
        "user_scope": {"allowed_actions": list(user_allowed_actions)},
        "tool_policy": {"allowed_actions": list(policy_allowed_actions)},
        "human_approval": human_approval,
    }


def _optional_string(data: dict[str, Any], key: str, maximum_length: int) -> None:
    value = data.get(key)
    if value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise GatewayEventError(f"{key} must be a non-empty string")
    if len(value) > maximum_length:
        raise GatewayEventError(f"{key} exceeds {maximum_length} characters")


def _enum_value(data: dict[str, Any], key: str, allowed: set[str]) -> None:
    value = data.get(key)
    if value is None:
        return
    if not isinstance(value, str) or value not in allowed:
        raise GatewayEventError(f"{key} contains an unsupported value")


def _string_list(
    data: dict[str, Any], key: str, *, maximum_items: int, maximum_length: int
) -> None:
    value = data.get(key)
    if value is None:
        return
    if not isinstance(value, list) or len(value) > maximum_items:
        raise GatewayEventError(f"{key} must be a bounded JSON string array")
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > maximum_length:
            raise GatewayEventError(f"{key} contains an invalid item")


def _number_value(
    data: dict[str, Any], key: str, *, minimum: float, maximum: float
) -> None:
    value = data.get(key)
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatewayEventError(f"{key} must be numeric")
    if not math.isfinite(float(value)) or not minimum <= value <= maximum:
        raise GatewayEventError(f"{key} is outside the accepted range")


def _integer_value(
    data: dict[str, Any], key: str, *, minimum: int, maximum: int
) -> None:
    value = data.get(key)
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise GatewayEventError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise GatewayEventError(f"{key} is outside the accepted range")


def _validate_timestamp(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str) or len(value) > 40:
        raise GatewayEventError("timestamp_utc must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GatewayEventError("timestamp_utc must be an ISO-8601 string") from exc
    if parsed.tzinfo is None:
        raise GatewayEventError("timestamp_utc must include a timezone")


def _validate_context(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise GatewayEventError("context must be a JSON object")
    unknown = sorted(set(value) - ALLOWED_CONTEXT_FIELDS)
    if unknown:
        raise GatewayEventError(f"unsupported context field: {unknown[0]}")

    _string_list(value, "allowed_tools", maximum_items=64, maximum_length=256)
    for key in ("user_scope", "tool_policy"):
        scope = value.get(key)
        if scope is None:
            continue
        if not isinstance(scope, dict) or set(scope) - {"allowed_actions"}:
            raise GatewayEventError(f"{key} must contain only allowed_actions")
        _string_list(scope, "allowed_actions", maximum_items=64, maximum_length=512)

    for key in BOOLEAN_CONTEXT_FIELDS:
        if key in value and not isinstance(value[key], bool):
            raise GatewayEventError(f"{key} must be a boolean")
    for key in INTEGER_CONTEXT_FIELDS:
        _integer_value(value, key, minimum=0, maximum=2_000_000_000)
    _number_value(value, "runtime_cost_budget", minimum=0, maximum=1_000_000)
    for key in STRING_CONTEXT_FIELDS:
        _optional_string(value, key, 256)
