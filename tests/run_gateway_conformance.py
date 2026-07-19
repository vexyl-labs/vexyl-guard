from __future__ import annotations

import json
import subprocess
import tempfile
import threading
from pathlib import Path

from intel.client import VexylGatewayClient
from intel.gateway import (
    create_gateway_server,
    create_gateway_token_file,
    read_gateway_token,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/integration/gateway-conformance.json"


def main() -> int:
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
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
            for fixture in fixtures:
                response = client.score(fixture["event"])
                assert (
                    response["policy_exit_code"] == fixture["expected_policy_exit_code"]
                ), fixture["name"]
                expected_attack_id = fixture.get("expected_attack_id")
                if expected_attack_id:
                    assert (
                        expected_attack_id in response["decision"]["matched_attack_ids"]
                    ), fixture["name"]

            subprocess.run(
                [
                    "node",
                    str(ROOT / "tests/run_node_gateway_conformance.mjs"),
                    str(socket_path),
                    str(token_file),
                    str(FIXTURES),
                ],
                cwd=ROOT,
                check=True,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    print(f"Python conformance verified {len(fixtures)} gateway decisions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
