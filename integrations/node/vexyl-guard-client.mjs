import { createHmac, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";

export const EVENT_SCHEMA = "vexyl.ai_event.v1";
export const DECISION_SCHEMA = "vexyl.risk_decision.v1";

const DEFAULT_SOCKET_PATH = "/run/vexyl/ai-gateway.sock";
const DEFAULT_TOKEN_FILE = "/etc/vexyl/ai-gateway.token";
const MAX_RESPONSE_BYTES = 262144;
const ALLOWED_EVENT_FIELDS = new Set([
  "event_id",
  "timestamp_utc",
  "tenant_id_hash",
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
const ALLOWED_CONTEXT_FIELDS = new Set([
  "allowed_tools",
  "user_scope",
  "tool_policy",
  "human_approval",
  "human_approval_completed",
  "runtime_token_budget",
  "runtime_cost_budget",
  "expected_model_provider",
  "expected_model_name",
  "uses_delegated_identity",
  "delegated_identity_verified",
  "identity_scope_verified",
  "inter_agent_message",
  "sender_identity_verified",
  "message_integrity_verified",
  "delegation_depth",
  "fanout_count",
  "retry_count",
  "max_delegation_depth",
  "max_fanout_count",
  "max_retry_count",
  "approval_rationale_source",
  "independent_verification_completed",
  "oversight_disabled",
  "audit_disabled",
  "policy_self_modified",
  "undeclared_action",
  "irreversible",
  "cross_tenant",
]);
const BOOLEAN_CONTEXT_FIELDS = new Set([
  "human_approval",
  "human_approval_completed",
  "uses_delegated_identity",
  "delegated_identity_verified",
  "identity_scope_verified",
  "inter_agent_message",
  "sender_identity_verified",
  "message_integrity_verified",
  "independent_verification_completed",
  "oversight_disabled",
  "audit_disabled",
  "policy_self_modified",
  "undeclared_action",
  "irreversible",
  "cross_tenant",
]);
const INTEGER_CONTEXT_FIELDS = new Set([
  "runtime_token_budget",
  "delegation_depth",
  "fanout_count",
  "retry_count",
  "max_delegation_depth",
  "max_fanout_count",
  "max_retry_count",
]);
const STRING_CONTEXT_FIELDS = new Set([
  "expected_model_provider",
  "expected_model_name",
  "approval_rationale_source",
]);
const ALLOWED_INPUT_CHANNELS = new Set([
  "api",
  "agent_plan",
  "chat",
  "email",
  "file",
  "memory",
  "model",
  "other",
  "rag",
  "supply_chain",
  "tool",
  "web",
]);
const ALLOWED_DATA_ORIGINS = new Set([
  "developer",
  "internal_db",
  "memory",
  "model_output",
  "retrieved_external",
  "supply_chain",
  "system",
  "tool_output",
  "unknown",
  "user",
]);
const ALLOWED_DATA_CLASSIFICATIONS = new Set([
  "public",
  "internal",
  "confidential",
  "secret",
  "regulated",
  "unknown",
]);
const ALLOWED_RESPONSE_FIELDS = new Set([
  "ok",
  "schema",
  "request_id",
  "recorded",
  "policy_exit_code",
  "decision",
]);
const ALLOWED_DECISION_FIELDS = new Set([
  "event_id",
  "score",
  "suggested_action",
  "matched_attack_ids",
  "matched_rules",
  "reasons",
  "mitigations_applied",
  "trust_level",
  "redacted_excerpt",
  "deny_tool_call",
  "correlation_scope",
  "correlation_window_seconds",
  "correlated_event_count",
]);
const ALLOWED_TRUST_LEVELS = new Set([
  "untrusted_data",
  "trusted_control",
  "user_instruction",
  "internal_data",
  "persistent_context",
  "unknown",
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
    const normalizedEvent = {
      ...event,
      event_id: event.event_id ?? randomUUID(),
    };
    validateEvent(normalizedEvent);
    const response = await this.#request("POST", "/v1/decisions", {
      schema: EVENT_SCHEMA,
      event: normalizedEvent,
    });
    return validateGatewayResponse(response, {
      expectedEventId: normalizedEvent.event_id,
    });
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
            if (received > MAX_RESPONSE_BYTES) {
              response.destroy(new VexylGatewayError("Gateway response exceeded the limit"));
              return;
            }
            chunks.push(chunk);
          });
          response.on("error", reject);
          response.on("end", () => {
            const contentType = String(response.headers["content-type"] ?? "")
              .split(";", 1)[0]
              .trim()
              .toLowerCase();
            if (contentType !== "application/json") {
              reject(new VexylGatewayError("Gateway returned an unsupported content type"));
              return;
            }
            let parsed;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch (error) {
              reject(new VexylGatewayError("Gateway returned invalid JSON", { cause: error }));
              return;
            }
            if (!isRecord(parsed)) {
              reject(new VexylGatewayError("Gateway returned an invalid response object"));
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
  {
    documentIds = [],
    tenantIdHash,
    userIdHash,
    sessionIdHash,
    dataClassification = "unknown",
  } = {},
) {
  return event({
    input_channel: "rag",
    data_origin: "retrieved_external",
    text_excerpt_redacted: securitySummary,
    retrieved_doc_ids: documentIds,
    tenant_id_hash: tenantIdHash,
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
    tenantIdHash,
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
    tenant_id_hash: tenantIdHash,
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
    tenantIdHash,
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
    tenant_id_hash: tenantIdHash,
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
    tenantIdHash,
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
    tenant_id_hash: tenantIdHash,
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
  if (!isRecord(value)) {
    throw new VexylGatewayError("Event must be an object");
  }
  for (const key of Object.keys(value)) {
    if (!ALLOWED_EVENT_FIELDS.has(key)) {
      throw new VexylGatewayError(`Unsupported event field: ${key}`);
    }
  }
  optionalString(value, "event_id", 128);
  validateTimestamp(value.timestamp_utc);
  opaqueHash(value, "tenant_id_hash");
  optionalString(value, "user_id_hash", 256);
  optionalString(value, "session_id_hash", 256);
  optionalString(value, "model_provider", 128);
  optionalString(value, "model_name", 128);
  enumValue(value, "input_channel", ALLOWED_INPUT_CHANNELS);
  enumValue(value, "data_origin", ALLOWED_DATA_ORIGINS);
  optionalString(value, "text_excerpt_redacted", 2048);
  stringList(value, "retrieved_doc_ids", 64, 256);
  optionalString(value, "tool_name", 256);
  optionalString(value, "tool_action", 512);
  stringList(value, "tool_permissions", 32, 128);
  enumValue(value, "data_classification", ALLOWED_DATA_CLASSIFICATIONS);
  stringList(value, "planned_actions", 64, 512);
  optionalString(value, "network_destination", 512);
  numberValue(value, "cost_estimate", 0, 1000000);
  integerValue(value, "token_count_estimate", 0, 2000000000);
  stringList(value, "verified_mitigations", 32, 128);
  validateContext(value.context);
}

function opaqueHash(value, field) {
  const candidate = value[field];
  if (candidate === undefined || candidate === null) return;
  if (typeof candidate !== "string" || !/^[0-9a-f]{64}$/.test(candidate)) {
    throw new VexylGatewayError(
      `${field} must be a lowercase 64-character HMAC-SHA256 value`,
    );
  }
}

export function validateGatewayResponse(response, { expectedEventId } = {}) {
  if (!isRecord(response)) {
    throw new VexylGatewayError("Gateway returned an invalid response object");
  }
  rejectUnknownFields(response, ALLOWED_RESPONSE_FIELDS, "response");
  if (response.ok !== true) {
    throw new VexylGatewayError("Gateway response was not successful");
  }
  if (response.schema !== DECISION_SCHEMA) {
    throw new VexylGatewayError("Gateway returned an unsupported decision schema");
  }
  if (response.recorded !== true) {
    throw new VexylGatewayError("Gateway decision was not recorded");
  }
  requiredString(response, "request_id", 128);
  const policyExitCode = requiredInteger(response, "policy_exit_code", 0, 4);
  if (![0, 3, 4].includes(policyExitCode)) {
    throw new VexylGatewayError("Gateway returned an unsupported policy exit code");
  }

  const decision = response.decision;
  if (!isRecord(decision)) {
    throw new VexylGatewayError("Gateway response did not include a decision");
  }
  rejectUnknownFields(decision, ALLOWED_DECISION_FIELDS, "decision");
  const eventId = requiredString(decision, "event_id", 128);
  if (expectedEventId !== undefined && eventId !== expectedEventId) {
    throw new VexylGatewayError("Gateway decision event id did not match the request");
  }
  const score = requiredInteger(decision, "score", 0, 100);
  const suggestedAction = requiredString(decision, "suggested_action", 80);
  if (suggestedAction !== suggestedActionForScore(score)) {
    throw new VexylGatewayError("Gateway decision action contradicted its score");
  }

  requiredStringList(decision, "matched_attack_ids", 64, 128);
  requiredStringList(decision, "matched_rules", 128, 256);
  requiredStringList(decision, "reasons", 64, 512);
  requiredStringList(decision, "mitigations_applied", 32, 128);
  const trustLevel = requiredString(decision, "trust_level", 32);
  if (!ALLOWED_TRUST_LEVELS.has(trustLevel)) {
    throw new VexylGatewayError("Gateway returned an unsupported trust level");
  }
  if (
    decision.redacted_excerpt !== null &&
    (typeof decision.redacted_excerpt !== "string" ||
      decision.redacted_excerpt.length > 500)
  ) {
    throw new VexylGatewayError("Gateway returned an invalid redacted excerpt");
  }
  if (typeof decision.deny_tool_call !== "boolean") {
    throw new VexylGatewayError("Gateway returned an invalid tool decision");
  }
  if (
    decision.correlation_scope !== null &&
    !["session", "user"].includes(decision.correlation_scope)
  ) {
    throw new VexylGatewayError("Gateway returned an invalid correlation scope");
  }
  requiredInteger(decision, "correlation_window_seconds", 0, 86400);
  requiredInteger(decision, "correlated_event_count", 0, 2000);

  if (policyExitCode !== policyExitCodeForDecision(score, decision.deny_tool_call)) {
    throw new VexylGatewayError("Gateway policy exit code contradicted its decision");
  }
  return response;
}

function validateContext(value) {
  if (value === undefined || value === null) return;
  if (!isRecord(value)) {
    throw new VexylGatewayError("context must be an object");
  }
  rejectUnknownFields(value, ALLOWED_CONTEXT_FIELDS, "context");
  stringList(value, "allowed_tools", 64, 256);
  for (const key of ["user_scope", "tool_policy"]) {
    const scope = value[key];
    if (scope === undefined || scope === null) continue;
    if (!isRecord(scope)) {
      throw new VexylGatewayError(`${key} must contain only allowed_actions`);
    }
    rejectUnknownFields(scope, new Set(["allowed_actions"]), key);
    stringList(scope, "allowed_actions", 64, 512);
  }
  for (const key of BOOLEAN_CONTEXT_FIELDS) {
    if (key in value && typeof value[key] !== "boolean") {
      throw new VexylGatewayError(`${key} must be a boolean`);
    }
  }
  for (const key of INTEGER_CONTEXT_FIELDS) {
    integerValue(value, key, 0, 2000000000);
  }
  numberValue(value, "runtime_cost_budget", 0, 1000000);
  for (const key of STRING_CONTEXT_FIELDS) {
    optionalString(value, key, 256);
  }
}

function optionalString(data, key, maximumLength) {
  const value = data[key];
  if (value === undefined || value === null) return;
  if (typeof value !== "string" || value.trim() === "" || value.length > maximumLength) {
    throw new VexylGatewayError(`${key} must be a bounded non-empty string`);
  }
}

function enumValue(data, key, allowed) {
  const value = data[key];
  if (value === undefined || value === null) return;
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new VexylGatewayError(`${key} contains an unsupported value`);
  }
}

function stringList(data, key, maximumItems, maximumLength) {
  const value = data[key];
  if (value === undefined || value === null) return;
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new VexylGatewayError(`${key} must be a bounded string array`);
  }
  for (const item of value) {
    if (typeof item !== "string" || item.trim() === "" || item.length > maximumLength) {
      throw new VexylGatewayError(`${key} contains an invalid item`);
    }
  }
}

function numberValue(data, key, minimum, maximum) {
  const value = data[key];
  if (value === undefined || value === null) return;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new VexylGatewayError(`${key} must be numeric`);
  }
  if (value < minimum || value > maximum) {
    throw new VexylGatewayError(`${key} is outside the accepted range`);
  }
}

function integerValue(data, key, minimum, maximum) {
  const value = data[key];
  if (value === undefined || value === null) return;
  if (!Number.isInteger(value)) {
    throw new VexylGatewayError(`${key} must be an integer`);
  }
  if (value < minimum || value > maximum) {
    throw new VexylGatewayError(`${key} is outside the accepted range`);
  }
}

function validateTimestamp(value) {
  if (value === undefined || value === null) return;
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !/(?:Z|[+-]\d{2}:\d{2})$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new VexylGatewayError("timestamp_utc must be an ISO-8601 string with timezone");
  }
}

function rejectUnknownFields(value, allowed, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) {
    throw new VexylGatewayError(`Unsupported ${label} field: ${unknown[0]}`);
  }
}

function requiredString(data, key, maximumLength) {
  const value = data[key];
  if (typeof value !== "string" || value.trim() === "" || value.length > maximumLength) {
    throw new VexylGatewayError(`Gateway returned an invalid ${key}`);
  }
  return value;
}

function requiredInteger(data, key, minimum, maximum) {
  const value = data[key];
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new VexylGatewayError(`Gateway returned an invalid ${key}`);
  }
  return value;
}

function requiredStringList(data, key, maximumItems, maximumLength) {
  const value = data[key];
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new VexylGatewayError(`Gateway returned an invalid ${key}`);
  }
  for (const item of value) {
    if (typeof item !== "string" || item.trim() === "" || item.length > maximumLength) {
      throw new VexylGatewayError(`Gateway returned an invalid ${key} item`);
    }
  }
}

function suggestedActionForScore(score) {
  if (score <= 24) return "allow/log";
  if (score <= 49) return "warn/log";
  if (score <= 69) return "require human approval or policy verifier";
  if (score <= 84) return "quarantine/block tool action";
  return "block and open incident";
}

function policyExitCodeForDecision(score, denyToolCall) {
  if (denyToolCall || score >= 70) return 4;
  if (score >= 50) return 3;
  return 0;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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
