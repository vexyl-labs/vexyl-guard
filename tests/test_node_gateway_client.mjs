import assert from "node:assert/strict";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  DECISION_SCHEMA,
  EVENT_SCHEMA,
  VexylGatewayError,
  VexylGatewayClient,
  hashIdentifier,
  mcpToolCallEvent,
  ragContentEvent,
  validateGatewayResponse,
} from "../integrations/node/vexyl-guard-client.mjs";

const directory = await mkdtemp(path.join(tmpdir(), "vexyl-node-client-"));
const socketPath = path.join(directory, "gateway.sock");
const token = "node-client-test-token-material-0123456789abcdef";
let receivedEnvelope;

function validResponse(eventId) {
  return {
    ok: true,
    schema: DECISION_SCHEMA,
    request_id: "node-client-request-id",
    recorded: true,
    policy_exit_code: 4,
    decision: {
      event_id: eventId,
      score: 78,
      suggested_action: "quarantine/block tool action",
      matched_attack_ids: ["AI-PI-002"],
      matched_rules: ["rule:AI-PI-002:external_instruction_takeover"],
      reasons: ["External content remained untrusted."],
      mitigations_applied: [],
      trust_level: "untrusted_data",
      redacted_excerpt: "External content contains instruction-like text.",
      deny_tool_call: false,
      correlation_scope: null,
      correlation_window_seconds: 0,
      correlated_event_count: 0,
    },
  };
}

const server = http.createServer((request, response) => {
  assert.equal(request.method, "POST");
  assert.equal(request.url, "/v1/decisions");
  assert.equal(request.headers.authorization, `Bearer ${token}`);
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    receivedEnvelope = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const body = JSON.stringify(validResponse(receivedEnvelope.event.event_id));
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
    });
    response.end(body);
  });
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(socketPath, resolve);
});

try {
  const firstHash = hashIdentifier("local-session", "node-client-test-key-material");
  const secondHash = hashIdentifier("local-session", "node-client-test-key-material");
  const tenantHash = hashIdentifier("local-tenant", "node-client-test-key-material");
  assert.equal(firstHash, secondHash);
  assert.equal(firstHash.length, 64);

  const client = new VexylGatewayClient({ socketPath, token, timeoutMs: 1000 });
  const event = ragContentEvent("External content contains instruction-like text.", {
    documentIds: ["opaque-document-hash"],
    tenantIdHash: tenantHash,
    sessionIdHash: firstHash,
  });
  const decision = await client.score(event);
  assert.equal(decision.policy_exit_code, 4);
  assert.equal(receivedEnvelope.schema, EVENT_SCHEMA);
  assert.equal(typeof receivedEnvelope.event.event_id, "string");
  const { event_id: receivedEventId, ...receivedEvent } = receivedEnvelope.event;
  assert.ok(receivedEventId.length > 0);
  assert.deepEqual(receivedEvent, event);
  assert.equal(receivedEvent.tenant_id_hash, tenantHash);
  assert.throws(
    () =>
      ragContentEvent("Bounded summary.", {
        tenantIdHash: "raw-tenant-name",
      }),
    VexylGatewayError,
  );

  const contractResponse = validResponse("expected-event-id");
  assert.equal(
    validateGatewayResponse(contractResponse, {
      expectedEventId: "expected-event-id",
    }),
    contractResponse,
  );
  assert.throws(
    () => validateGatewayResponse({ ...contractResponse, policy_exit_code: 0 }),
    VexylGatewayError,
  );
  assert.throws(
    () =>
      validateGatewayResponse({
        ...contractResponse,
        decision: { ...contractResponse.decision, suggested_action: "allow/log" },
      }),
    VexylGatewayError,
  );
  assert.throws(
    () =>
      validateGatewayResponse(contractResponse, {
        expectedEventId: "wrong-event-id",
      }),
    VexylGatewayError,
  );
  assert.throws(
    () => validateGatewayResponse({ ...contractResponse, recorded: false }),
    VexylGatewayError,
  );
  assert.throws(
    () =>
      validateGatewayResponse({
        ...contractResponse,
        decision: {
          ...contractResponse.decision,
          raw_prompt: "must never be returned",
        },
      }),
    VexylGatewayError,
  );

  const mcpEvent = mcpToolCallEvent("Read approved documentation.", {
    serverName: "docs",
    toolName: "search",
    toolAction: "search approved documentation",
    allowedTools: ["mcp:docs:search"],
    userAllowedActions: ["search approved documentation"],
    policyAllowedActions: ["search approved documentation"],
  });
  assert.equal(mcpEvent.tool_name, "mcp:docs:search");

  await assert.rejects(client.score({ prompt: "raw prompt is not accepted" }));
  await assert.rejects(
    client.score({
      input_channel: "tool",
      data_origin: "internal_db",
      context: { arguments: { secret: "not accepted" } },
    }),
    VexylGatewayError,
  );
  await assert.rejects(
    client.score({ input_channel: "unsupported", data_origin: "user" }),
    VexylGatewayError,
  );
  console.log("Node.js gateway client contract verified");
} finally {
  await new Promise((resolve) => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
