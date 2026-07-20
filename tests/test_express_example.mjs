import assert from "node:assert/strict";
import { once } from "node:events";

import { DECISION_SCHEMA } from "../integrations/node/vexyl-guard-client.mjs";
import { createApp } from "../integrations/examples/node/express-app.mjs";

class FakeGatewayClient {
  constructor(policyExitCode) {
    this.policyExitCode = policyExitCode;
    this.events = [];
  }

  async score(event) {
    this.events.push(event);
    const score = this.policyExitCode === 0 ? 0 : 78;
    return {
      ok: true,
      schema: DECISION_SCHEMA,
      request_id: "express-example-request",
      recorded: true,
      policy_exit_code: this.policyExitCode,
      decision: {
        event_id: event.event_id ?? "express-example-event",
        score,
        suggested_action:
          score === 0 ? "allow/log" : "quarantine/block tool action",
        matched_attack_ids: [],
        matched_rules: [],
        reasons: [],
        mitigations_applied: [],
        trust_level: "untrusted_data",
        redacted_excerpt: "Bounded example summary.",
        deny_tool_call: false,
        correlation_scope: null,
        correlation_window_seconds: 0,
        correlated_event_count: 0,
      },
    };
  }
}

async function withServer(app, callback) {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

const allowedGateway = new FakeGatewayClient(0);
await withServer(
  createApp({
    client: allowedGateway,
    identifierKey: "express-example-test-key-material",
  }),
  async (baseUrl) => {
    const response = await fetch(`${baseUrl}/demo/rag/allow`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "token=body-value-must-not-be-read",
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-powered-by"), null);
    assert.equal((await response.json()).context_admitted, true);
  },
);
const serializedEvent = JSON.stringify(allowedGateway.events[0]);
assert.ok(!serializedEvent.includes("body-value-must-not-be-read"));
assert.ok(!serializedEvent.includes("express-demo-document-allow"));
assert.ok(!serializedEvent.includes("express-demo-session-allow"));

await withServer(
  createApp({
    client: new FakeGatewayClient(4),
    identifierKey: "express-example-test-key-material",
  }),
  async (baseUrl) => {
    const response = await fetch(`${baseUrl}/demo/rag/block`, { method: "POST" });
    const payload = await response.json();
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(payload.policy_exit_code, 4);
    assert.equal(payload.matched_rules, undefined);
  },
);

console.log("Express example HTTP contract verified");
