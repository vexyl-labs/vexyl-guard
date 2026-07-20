from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from intel.integration import hash_identifier
from intel.middleware import MCPToolGuard, VexylRequestGuard

DOCS_SERVER_NAME = "docs"
DOCS_TOOL_NAME = "search"
DOCS_TOOL_ACTION = "search approved documentation"


def create_docs_search_guard(request_guard: VexylRequestGuard) -> MCPToolGuard:
    """Create an MCP guard from static application-owned authorization policy."""

    return MCPToolGuard(
        request_guard,
        server_name=DOCS_SERVER_NAME,
        tool_name=DOCS_TOOL_NAME,
        tool_action=DOCS_TOOL_ACTION,
        permissions=["read"],
        user_allowed_actions=[DOCS_TOOL_ACTION],
        policy_allowed_actions=[DOCS_TOOL_ACTION],
        verified_mitigations=[
            "tool_allowlist",
            "scoped_read_only_credentials",
        ],
    )


async def execute_docs_search(
    request_guard: VexylRequestGuard,
    *,
    query: str,
    session_reference: str,
    identifier_key: str | bytes,
    execute: Callable[[str], Awaitable[Any]],
) -> Any:
    """Authorize a fixed read-only MCP action before invoking its handler."""

    validated_query = _validated_query(query)
    session_hash = hash_identifier(
        _bounded_reference(session_reference), identifier_key
    )
    await create_docs_search_guard(request_guard).authorize(
        "Search the approved documentation corpus with a validated query.",
        session_id_hash=session_hash,
        data_origin="internal_db",
        data_classification="internal",
    )
    return await execute(validated_query)


def _validated_query(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("query must be a string")
    if any(ord(character) < 32 for character in value):
        raise ValueError("query contains control characters")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 200:
        raise ValueError("query must be between 1 and 200 characters")
    return normalized


def _bounded_reference(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("session_reference must be a string")
    if not value.strip() or len(value) > 512:
        raise ValueError("session_reference must be a bounded non-empty string")
    return value
