import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { VexylGatewayClient } from "../integrations/node/vexyl-guard-client.mjs";
import {
  VexylPolicyDenied,
  VexylRequestGuard,
} from "../integrations/node/vexyl-guard-middleware.mjs";
import {
  authorizeRagContext,
  buildRagEvent,
} from "../integrations/examples/node/rag-boundary.mjs";
import { executeDocsSearch } from "../integrations/examples/node/mcp-boundary.mjs";

const [socketPath, tokenFile, fixturePath] = process.argv.slice(2);
const identifierKey = process.env.VEXYL_EXAMPLE_IDENTIFIER_KEY;
if (!socketPath || !tokenFile || !fixturePath || !identifierKey) {
  throw new Error(
    "Usage: VEXYL_EXAMPLE_IDENTIFIER_KEY=... node run_node_example_compatibility.mjs SOCKET TOKEN FIXTURES",
  );
}

const fixtures = JSON.parse(await readFile(fixturePath, "utf8"));
assert.equal(fixtures.schema, "vexyl.integration_examples.v1");
const client = new VexylGatewayClient({ socketPath, tokenFile, timeoutMs: 2000 });
const requestGuard = new VexylRequestGuard(client);

for (const scenario of fixtures.rag_scenarios) {
  const source = scenario.metadata;
  const metadata = {
    securitySummary: source.security_summary,
    documentReference: source.document_reference,
    sessionReference: source.session_reference,
    dataClassification: source.data_classification,
  };
  const serializedEvent = JSON.stringify(buildRagEvent(metadata, { identifierKey }));
  assert.ok(!serializedEvent.includes(source.document_reference), scenario.name);
  assert.ok(!serializedEvent.includes(source.session_reference), scenario.name);

  try {
    const response = await authorizeRagContext(requestGuard, metadata, {
      identifierKey,
    });
    assert.equal(response.policy_exit_code, scenario.expected_policy_exit_code);
    assert.equal(response.decision.trust_level, "untrusted_data", scenario.name);
    assert.equal(scenario.expected_policy_exit_code, 0, scenario.name);
  } catch (error) {
    if (!(error instanceof VexylPolicyDenied)) throw error;
    assert.equal(error.policyExitCode, scenario.expected_policy_exit_code);
    assert.equal(error.decision.trust_level, "untrusted_data", scenario.name);
    if (scenario.expected_attack_id) {
      assert.ok(
        error.decision.matched_attack_ids.includes(scenario.expected_attack_id),
        scenario.name,
      );
    }
    assert.notEqual(scenario.expected_policy_exit_code, 0, scenario.name);
  }
}

const mcpFixture = fixtures.mcp_scenario;
const result = await executeDocsSearch(requestGuard, {
  query: mcpFixture.query,
  sessionReference: mcpFixture.session_reference,
  identifierKey,
  execute: async (query) => `verified:${query}`,
});
assert.equal(result, mcpFixture.expected_result);
await assert.rejects(
  executeDocsSearch(requestGuard, {
    query: "release\nverification",
    sessionReference: mcpFixture.session_reference,
    identifierKey,
    execute: async (query) => `verified:${query}`,
  }),
  /control characters/,
);

console.log("Node.js integration examples verified against the local gateway");
