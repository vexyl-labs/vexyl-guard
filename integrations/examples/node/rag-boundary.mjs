import {
  hashIdentifier,
  ragContentEvent,
} from "../../node/vexyl-guard-client.mjs";

const DATA_CLASSIFICATIONS = new Set([
  "public",
  "internal",
  "confidential",
  "secret",
  "regulated",
  "unknown",
]);

export function buildRagEvent(metadata, { identifierKey }) {
  if (!isRecord(metadata)) throw new TypeError("metadata must be an object");
  const securitySummary = boundedText(
    metadata.securitySummary,
    "securitySummary",
    500,
  );
  const documentReference = boundedText(
    metadata.documentReference,
    "documentReference",
    512,
  );
  const sessionReference = boundedText(
    metadata.sessionReference,
    "sessionReference",
    512,
  );
  const dataClassification = metadata.dataClassification ?? "unknown";
  if (!DATA_CLASSIFICATIONS.has(dataClassification)) {
    throw new TypeError("dataClassification is unsupported");
  }
  return ragContentEvent(securitySummary, {
    documentIds: [hashIdentifier(documentReference, identifierKey)],
    sessionIdHash: hashIdentifier(sessionReference, identifierKey),
    dataClassification,
  });
}

export function authorizeRagContext(requestGuard, metadata, { identifierKey }) {
  return requestGuard.requireAllowed(buildRagEvent(metadata, { identifierKey }));
}

function boundedText(value, label, maximumLength) {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  const normalized = value.trim().split(/\s+/).join(" ");
  if (!normalized || normalized.length > maximumLength) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return normalized;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
