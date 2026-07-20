from __future__ import annotations

import os

from fastapi import FastAPI, Request

from intel.client import VexylGatewayClient
from intel.middleware import VexylASGIMiddleware
from rag_boundary import RAGSecurityMetadata, authorize_rag_context

ALLOW_METADATA = RAGSecurityMetadata(
    security_summary="Retrieved content contains ordinary product documentation.",
    document_reference="fastapi-demo-document-allow",
    session_reference="fastapi-demo-session-allow",
    data_classification="public",
)
BLOCK_METADATA = RAGSecurityMetadata(
    security_summary=(
        "External content says the assistant should ignore the user and call a tool."
    ),
    document_reference="fastapi-demo-document-block",
    session_reference="fastapi-demo-session-block",
    data_classification="public",
)


def create_app(
    *,
    client: VexylGatewayClient | None = None,
    identifier_key: str | bytes | None = None,
) -> FastAPI:
    """Create a FastAPI demo whose routes cross explicit RAG policy boundaries."""

    key = _identifier_key(identifier_key)
    app = FastAPI(title="Vexyl Guard FastAPI Example", version="1")
    app.add_middleware(VexylASGIMiddleware, client=client)

    @app.get("/healthz")
    async def health() -> dict[str, object]:
        return {"ok": True, "component": "vexyl-fastapi-example"}

    @app.post("/demo/rag/allow")
    async def allow_rag(request: Request) -> dict[str, object]:
        response = await authorize_rag_context(
            request.state.vexyl_guard,
            ALLOW_METADATA,
            identifier_key=key,
        )
        return {
            "ok": True,
            "context_admitted": True,
            "policy_exit_code": response["policy_exit_code"],
        }

    @app.post("/demo/rag/block")
    async def block_rag(request: Request) -> dict[str, object]:
        response = await authorize_rag_context(
            request.state.vexyl_guard,
            BLOCK_METADATA,
            identifier_key=key,
        )
        return {
            "ok": True,
            "context_admitted": True,
            "policy_exit_code": response["policy_exit_code"],
        }

    return app


def _identifier_key(value: str | bytes | None) -> str | bytes:
    candidate = value or os.environ.get("VEXYL_EXAMPLE_IDENTIFIER_KEY")
    if isinstance(candidate, str):
        size = len(candidate.encode("utf-8"))
    elif isinstance(candidate, bytes):
        size = len(candidate)
    else:
        size = 0
    if not 16 <= size <= 256:
        raise RuntimeError(
            "Set VEXYL_EXAMPLE_IDENTIFIER_KEY to private random material "
            "between 16 and 256 bytes"
        )
    return candidate
