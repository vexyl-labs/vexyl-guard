import { hashIdentifier } from "../../node/vexyl-guard-client.mjs";
import { MCPToolGuard } from "../../node/vexyl-guard-middleware.mjs";

export const DOCS_SERVER_NAME = "docs";
export const DOCS_TOOL_NAME = "search";
export const DOCS_TOOL_ACTION = "search approved documentation";

export function createDocsSearchGuard(requestGuard) {
  return new MCPToolGuard(requestGuard, {
    serverName: DOCS_SERVER_NAME,
    toolName: DOCS_TOOL_NAME,
    toolAction: DOCS_TOOL_ACTION,
    permissions: ["read"],
    userAllowedActions: [DOCS_TOOL_ACTION],
    policyAllowedActions: [DOCS_TOOL_ACTION],
    verifiedMitigations: ["tool_allowlist", "scoped_read_only_credentials"],
  });
}

export async function executeDocsSearch(
  requestGuard,
  { query, sessionReference, identifierKey, execute },
) {
  const validatedQuery = validateQuery(query);
  const sessionHash = hashIdentifier(
    boundedReference(sessionReference),
    identifierKey,
  );
  await createDocsSearchGuard(requestGuard).authorize(
    "Search the approved documentation corpus with a validated query.",
    {
      sessionIdHash: sessionHash,
      dataOrigin: "internal_db",
      dataClassification: "internal",
    },
  );
  if (typeof execute !== "function") throw new TypeError("execute must be a function");
  return await execute(validatedQuery);
}

function validateQuery(value) {
  if (typeof value !== "string") throw new TypeError("query must be a string");
  if (/[\u0000-\u001f]/.test(value)) {
    throw new TypeError("query must not contain control characters");
  }
  const normalized = value.trim().split(/\s+/).join(" ");
  if (!normalized || normalized.length > 200) {
    throw new TypeError("query must be a bounded non-empty string");
  }
  return normalized;
}

function boundedReference(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 512) {
    throw new TypeError("sessionReference must be a bounded non-empty string");
  }
  return value;
}
