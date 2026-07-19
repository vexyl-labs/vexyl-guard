import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { VexylGatewayClient } from "../integrations/node/vexyl-guard-client.mjs";

const [socketPath, tokenFile, fixturePath] = process.argv.slice(2);
if (!socketPath || !tokenFile || !fixturePath) {
  throw new Error("Usage: node run_node_gateway_conformance.mjs SOCKET TOKEN_FILE FIXTURES");
}

const fixtures = JSON.parse(await readFile(fixturePath, "utf8"));
const client = new VexylGatewayClient({ socketPath, tokenFile, timeoutMs: 2000 });

for (const fixture of fixtures) {
  const response = await client.score(fixture.event);
  assert.equal(
    response.policy_exit_code,
    fixture.expected_policy_exit_code,
    fixture.name,
  );
  if (fixture.expected_attack_id) {
    assert.ok(
      response.decision.matched_attack_ids.includes(fixture.expected_attack_id),
      fixture.name,
    );
  }
}

console.log(`Node.js conformance verified ${fixtures.length} gateway decisions`);
