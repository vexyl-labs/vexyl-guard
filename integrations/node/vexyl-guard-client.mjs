import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";

export const EVENT_SCHEMA = "vexyl.ai_event.v1";
export const DECISION_SCHEMA = "vexyl.risk_decision.v1";

const DEFAULT_SOCKET_PATH = "/run/vexyl/ai-gateway.sock";
const DEFAULT_TOKEN_FILE = "/etc/vexyl/ai-gateway.token";
const ALLOWED_EVENT_FIELDS = new Set([
  "event_id",
  "timestamp_utc",
  "user_id_hash",
  "session_id_hash",
  "model_provider",
  "model_name",
  "input_channel",
  "data_origin",
  "text_excerpt_redacted",
  "retrieved_doc_ids",
  "tool_name",
  "tool_action",
  "tool_permissions",
  "data_classification",
  "planned_actions",
  "network_destination",
  "cost_estimate",
  "token_count_estimate",
  "verified_mitigations",
  "context",
]);

export class VexylGatewayError extends Error {}

export class VexylGatewayClient {
  constructor({
    socketPath = process.env.VEXYL_AI_GATEWAY_SOCKET ?? DEFAULT_SOCKET_PATH,
    token,
    tokenFile = process.env.VEXYL_AI_GATEWAY_TOKEN_FILE ?? DEFAULT_TOKEN_FILE,
    timeoutMs = 2000,
  } = {}) {
    this.socketPath = socketPath;
    this.token = token ?? readToken(tokenFile);
    this.timeoutMs = timeoutMs;
  }

  async score(event) {
    validateEvent(event);
    const response = await this.#request("POST", "/v1/decisions", {
      schema: EVENT_SCHEMA,
      event,
    });
    if (response.schema !== DECISION_SCHEMA || !response.decision) {
      throw new VexylGatewayError("Gateway returned an unsupported decision");
    }
    return response;
  }

  health() {
    return this.#request("GET", "/v1/health");
  }

  runtimeStatus() {
    return this.#request("GET", "/v1/runtime-status");
  }

  #request(method, path, payload) {
    const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    const headers = {
      Accept: "application/json",
      Authorization: `Bearer ${this.token}`,
      Connection: "close",
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(body.length);
    }

    return new Promise((resolve, reject) => {
      const request = http.request(
        {
          socketPath: this.socketPath,
          path,
          method,
          headers,
          timeout: this.timeoutMs,
        },
        (response) => {
          const chunks = [];
          let received = 0;
          response.on("data", (chunk) => {
            received += chunk.length;
            if (received > 262144) {
              response.destroy(new VexylGatewayError("Gateway response exceeded the limit"));
              return;
            }
            chunks.push(chunk);
          });
          response.on("error", reject);
          response.on("end", () => {
            let parsed;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch (error) {
              reject(new VexylGatewayError("Gateway returned invalid JSON", { cause: error }));
              return;
            }
            if (response.statusCode !== 200 || parsed.ok !== true) {
              const code = parsed?.error?.code ?? "gateway_error";
              reject(new VexylGatewayError(`Gateway rejected the request: ${code}`));
              return;
            }
            resolve(parsed);
          });
        },
      );
      request.on("timeout", () => request.destroy(new Error("Gateway request timed out")));
      request.on("error", (error) => {
        reject(new VexylGatewayError("Local Vexyl gateway request failed", { cause: error }));
      });
      if (body !== undefined) request.write(body);
      request.end();
    });
  }
}

export function hashIdentifier(identifier, key) {
  if (typeof identifier !== "string" || identifier.length === 0) {
    throw new VexylGatewayError("Identifier must be a non-empty string");
  }
  const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key ?? "", "utf8");
  if (keyBuffer.length < 16) {
    throw new VexylGatewayError("Identifier hashing key must be at least 16 bytes");
  }
  return createHmac("sha256", keyBuffer).update(identifier, "utf8").digest("hex");
}

export function ragContentEvent(
  securitySummary,
  { documentIds = [], userIdHash, sessionIdHash, dataClassification = "unknown" } = {},
) {
  return event({
    input_channel: "rag",
    data_origin: "retrieved_external",
    text_excerpt_redacted: securitySummary,
    retrieved_doc_ids: documentIds,
    user_id_hash: userIdHash,
    session_id_hash: sessionIdHash,
    data_classification: dataClassification,
  });
}

export function agentPlanEvent(
  securitySummary,
  {
    plannedActions,
    allowedTools = [],
    userAllowedActions = [],
    policyAllowedActions = [],
    userIdHash,
    sessionIdHash,
    humanApproval = false,
  },
) {
  return event({
    input_channel: "agent_plan",
    data_origin: "internal_db",
    text_excerpt_redacted: securitySummary,
    planned_actions: plannedActions,
    user_id_hash: userIdHash,
    session_id_hash: sessionIdHash,
    context: authorizationContext(
      allowedTools,
      userAllowedActions,
      policyAllowedActions,
      humanApproval,
    ),
  });
}

export function toolCallEvent(
  securitySummary,
  {
    toolName,
    toolAction,
    permissions = [],
    allowedTools = [],
    userAllowedActions = [],
    policyAllowedActions = [],
    verifiedMitigations = [],
    userIdHash,
    sessionIdHash,
    dataOrigin = "internal_db",
    dataClassification = "unknown",
    networkDestination,
    humanApproval = false,
    irreversible = false,
  },
) {
  return event({
    input_channel: "tool",
    data_origin: dataOrigin,
    text_excerpt_redacted: securitySummary,
    tool_name: toolName,
    tool_action: toolAction,
    tool_permissions: permissions,
    user_id_hash: userIdHash,
    session_id_hash: sessionIdHash,
    data_classification: dataClassification,
    network_destination: networkDestination,
    verified_mitigations: verifiedMitigations,
    context: {
      ...authorizationContext(
        allowedTools,
        userAllowedActions,
        policyAllowedActions,
        humanApproval,
      ),
      irreversible,
    },
  });
}

export function mcpToolCallEvent(
  securitySummary,
  { serverName, toolName, ...options },
) {
  return toolCallEvent(securitySummary, {
    ...options,
    toolName: `mcp:${serverName}:${toolName}`,
  });
}

export function modelApiEvent(
  securitySummary,
  {
    modelProvider,
    modelName,
    expectedModelProvider,
    expectedModelName,
    userIdHash,
    sessionIdHash,
    tokenCountEstimate = 0,
    costEstimate = 0,
    runtimeTokenBudget = 250000,
    runtimeCostBudget = 25,
  },
) {
  return event({
    input_channel: "model",
    data_origin: "internal_db",
    text_excerpt_redacted: securitySummary,
    model_provider: modelProvider,
    model_name: modelName,
    user_id_hash: userIdHash,
    session_id_hash: sessionIdHash,
    token_count_estimate: tokenCountEstimate,
    cost_estimate: costEstimate,
    context: {
      expected_model_provider: expectedModelProvider,
      expected_model_name: expectedModelName,
      runtime_token_budget: runtimeTokenBudget,
      runtime_cost_budget: runtimeCostBudget,
    },
  });
}

function event(values) {
  const result = Object.fromEntries(
    Object.entries(values).filter(([, value]) => value !== undefined && value !== null),
  );
  validateEvent(result);
  return result;
}

function authorizationContext(
  allowedTools,
  userAllowedActions,
  policyAllowedActions,
  humanApproval,
) {
  return {
    allowed_tools: allowedTools,
    user_scope: { allowed_actions: userAllowedActions },
    tool_policy: { allowed_actions: policyAllowedActions },
    human_approval: humanApproval,
  };
}

function validateEvent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new VexylGatewayError("Event must be an object");
  }
  for (const key of Object.keys(value)) {
    if (!ALLOWED_EVENT_FIELDS.has(key)) {
      throw new VexylGatewayError(`Unsupported event field: ${key}`);
    }
  }
  if (
    typeof value.text_excerpt_redacted === "string" &&
    value.text_excerpt_redacted.length > 2048
  ) {
    throw new VexylGatewayError("Redacted security summary exceeds 2048 characters");
  }
}

function readToken(path) {
  let token;
  try {
    token = readFileSync(path, "utf8").trim();
  } catch (error) {
    throw new VexylGatewayError("Unable to read the local gateway token", { cause: error });
  }
  if (token.length < 32 || token.length > 256 || /\s/.test(token)) {
    throw new VexylGatewayError("Local gateway token is invalid");
  }
  return token;
}
