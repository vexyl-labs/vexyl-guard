import assert from "node:assert/strict";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  DECISION_SCHEMA,
  EVENT_SCHEMA,
  VexylGatewayClient,
  hashIdentifier,
  mcpToolCallEvent,
  ragContentEvent,
} from "../integrations/node/vexyl-guard-client.mjs";

const directory = await mkdtemp(path.join(tmpdir(), "vexyl-node-client-"));
const socketPath = path.join(directory, "gateway.sock");
const token = "node-client-test-token-material-0123456789abcdef";
let receivedEnvelope;

const server = http.createServer((request, response) => {
  assert.equal(request.method, "POST");
  assert.equal(request.url, "/v1/decisions");
  assert.equal(request.headers.authorization, `Bearer ${token}`);
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    receivedEnvelope = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const body = JSON.stringify({
      ok: true,
      schema: DECISION_SCHEMA,
      recorded: true,
      policy_exit_code: 4,
      decision: {
        score: 78,
        suggested_action: "quarantine/block tool action",
      },
    });
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
  assert.equal(firstHash, secondHash);
  assert.equal(firstHash.length, 64);

  const client = new VexylGatewayClient({ socketPath, token, timeoutMs: 1000 });
  const event = ragContentEvent("External content contains instruction-like text.", {
    documentIds: ["opaque-document-hash"],
    sessionIdHash: firstHash,
  });
  const decision = await client.score(event);
  assert.equal(decision.policy_exit_code, 4);
  assert.equal(receivedEnvelope.schema, EVENT_SCHEMA);
  assert.deepEqual(receivedEnvelope.event, event);

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
  console.log("Node.js gateway client contract verified");
} finally {
  await new Promise((resolve) => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
