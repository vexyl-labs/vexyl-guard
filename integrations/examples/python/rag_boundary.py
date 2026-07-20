from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from intel.integration import hash_identifier, rag_content_event
from intel.middleware import VexylRequestGuard

_DATA_CLASSIFICATIONS = {
    "public",
    "internal",
    "confidential",
    "secret",
    "regulated",
    "unknown",
}


@dataclass(frozen=True)
class RAGSecurityMetadata:
    security_summary: str
    document_reference: str
    session_reference: str
    data_classification: str = "unknown"


def build_rag_event(
    metadata: RAGSecurityMetadata, *, identifier_key: str | bytes
) -> dict[str, Any]:
    """Build a redacted event without placing document content or raw IDs in it."""

    summary = _bounded_text(metadata.security_summary, "security_summary", 500)
    document_reference = _bounded_text(
        metadata.document_reference, "document_reference", 512
    )
    session_reference = _bounded_text(
        metadata.session_reference, "session_reference", 512
    )
    if metadata.data_classification not in _DATA_CLASSIFICATIONS:
        raise ValueError("data_classification is unsupported")
    return rag_content_event(
        summary,
        document_ids=[hash_identifier(document_reference, identifier_key)],
        session_id_hash=hash_identifier(session_reference, identifier_key),
        data_classification=metadata.data_classification,
    )


async def authorize_rag_context(
    request_guard: VexylRequestGuard,
    metadata: RAGSecurityMetadata,
    *,
    identifier_key: str | bytes,
) -> dict[str, Any]:
    """Authorize retrieved content before an application adds it to model context."""

    return await request_guard.require_allowed(
        build_rag_event(metadata, identifier_key=identifier_key)
    )


def _bounded_text(value: str, label: str, maximum_length: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum_length:
        raise ValueError(f"{label} must be a bounded non-empty string")
    return normalized
