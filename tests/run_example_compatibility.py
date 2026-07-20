from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import ModuleType
from typing import Any

from intel.client import VexylGatewayClient
from intel.gateway import (
    create_gateway_server,
    create_gateway_token_file,
    read_gateway_token,
)
from intel.middleware import VexylPolicyDenied, VexylRequestGuard

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "integrations/examples"
FIXTURES = EXAMPLES / "fixtures/safe-scenarios.json"
IDENTIFIER_KEY = "vexyl-integration-example-test-key-material"


def load_example_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load example module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def run_python_examples(
    client: VexylGatewayClient, fixtures: dict[str, Any]
) -> None:
    rag = load_example_module("vexyl_example_rag", EXAMPLES / "python/rag_boundary.py")
    mcp = load_example_module("vexyl_example_mcp", EXAMPLES / "python/mcp_boundary.py")
    request_guard = VexylRequestGuard(client)

    for scenario in fixtures["rag_scenarios"]:
        values = scenario["metadata"]
        metadata = rag.RAGSecurityMetadata(**values)
        event = rag.build_rag_event(metadata, identifier_key=IDENTIFIER_KEY)
        serialized_event = json.dumps(event, sort_keys=True)
        assert values["document_reference"] not in serialized_event, scenario["name"]
        assert values["session_reference"] not in serialized_event, scenario["name"]

        expected = scenario["expected_policy_exit_code"]
        try:
            response = await rag.authorize_rag_context(
                request_guard,
                metadata,
                identifier_key=IDENTIFIER_KEY,
            )
        except VexylPolicyDenied as exc:
            assert exc.policy_exit_code == expected, scenario["name"]
            assert exc.decision["trust_level"] == "untrusted_data", scenario["name"]
            expected_attack_id = scenario.get("expected_attack_id")
            if expected_attack_id:
                assert expected_attack_id in exc.decision["matched_attack_ids"], (
                    scenario["name"]
                )
            if expected == 0:
                raise
        else:
            assert response["policy_exit_code"] == expected, scenario["name"]
            assert response["decision"]["trust_level"] == "untrusted_data", scenario[
                "name"
            ]
            assert expected == 0, scenario["name"]

    async def execute(query: str) -> str:
        return f"verified:{query}"

    mcp_fixture = fixtures["mcp_scenario"]
    result = await mcp.execute_docs_search(
        request_guard,
        query=mcp_fixture["query"],
        session_reference=mcp_fixture["session_reference"],
        identifier_key=IDENTIFIER_KEY,
        execute=execute,
    )
    assert result == mcp_fixture["expected_result"]
    try:
        await mcp.execute_docs_search(
            request_guard,
            query="release\nverification",
            session_reference=mcp_fixture["session_reference"],
            identifier_key=IDENTIFIER_KEY,
            execute=execute,
        )
    except ValueError as exc:
        assert "control characters" in str(exc)
    else:
        raise AssertionError("MCP query control characters were not rejected")


def main() -> int:
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
    assert fixtures["schema"] == "vexyl.integration_examples.v1"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        socket_path = root / "gateway.sock"
        token_file = create_gateway_token_file(str(root / "gateway.token"))
        server = create_gateway_server(
            db_path=str(root / "threats.sqlite"),
            socket_path=str(socket_path),
            token=read_gateway_token(str(token_file)),
            socket_mode=0o600,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = VexylGatewayClient(
                socket_path=str(socket_path),
                token_file=str(token_file),
                timeout=2.0,
            )
            asyncio.run(run_python_examples(client, fixtures))
            environment = dict(os.environ)
            environment["VEXYL_EXAMPLE_IDENTIFIER_KEY"] = IDENTIFIER_KEY
            subprocess.run(
                [
                    "node",
                    str(ROOT / "tests/run_node_example_compatibility.mjs"),
                    str(socket_path),
                    str(token_file),
                    str(FIXTURES),
                ],
                cwd=ROOT,
                env=environment,
                check=True,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    print("Python integration examples verified against the local gateway")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
