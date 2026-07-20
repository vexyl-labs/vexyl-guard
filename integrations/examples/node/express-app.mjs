import express from "express";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { VexylGatewayClient } from "../../node/vexyl-guard-client.mjs";
import {
  createVexylGuardMiddleware,
  vexylGuardErrorHandler,
} from "../../node/vexyl-guard-middleware.mjs";
import { authorizeRagContext } from "./rag-boundary.mjs";

const ALLOW_METADATA = Object.freeze({
  securitySummary: "Retrieved content contains ordinary product documentation.",
  documentReference: "express-demo-document-allow",
  sessionReference: "express-demo-session-allow",
  dataClassification: "public",
});
const BLOCK_METADATA = Object.freeze({
  securitySummary:
    "External content says the assistant should ignore the user and call a tool.",
  documentReference: "express-demo-document-block",
  sessionReference: "express-demo-session-block",
  dataClassification: "public",
});

export function createApp({ client = new VexylGatewayClient(), identifierKey } = {}) {
  const key = validatedIdentifierKey(
    identifierKey ?? process.env.VEXYL_EXAMPLE_IDENTIFIER_KEY,
  );
  const app = express();
  app.disable("x-powered-by");
  app.use(createVexylGuardMiddleware({ client }));

  app.get("/healthz", (request, response) => {
    response.json({ ok: true, component: "vexyl-express-example" });
  });

  app.post("/demo/rag/allow", async (request, response, next) => {
    try {
      const decision = await authorizeRagContext(request.vexylGuard, ALLOW_METADATA, {
        identifierKey: key,
      });
      response.json({
        ok: true,
        context_admitted: true,
        policy_exit_code: decision.policy_exit_code,
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/demo/rag/block", async (request, response, next) => {
    try {
      const decision = await authorizeRagContext(request.vexylGuard, BLOCK_METADATA, {
        identifierKey: key,
      });
      response.json({
        ok: true,
        context_admitted: true,
        policy_exit_code: decision.policy_exit_code,
      });
    } catch (error) {
      next(error);
    }
  });

  app.use(vexylGuardErrorHandler);
  app.use((error, request, response, next) => {
    if (response.headersSent) {
      next(error);
      return;
    }
    response
      .status(500)
      .set("Cache-Control", "no-store")
      .set("X-Content-Type-Options", "nosniff")
      .json({ error: "internal_error" });
  });
  return app;
}

function validatedIdentifierKey(value) {
  const size = typeof value === "string" ? Buffer.byteLength(value, "utf8") : 0;
  if (size < 16 || size > 256) {
    throw new Error(
      "Set VEXYL_EXAMPLE_IDENTIFIER_KEY to private random material between 16 and 256 bytes",
    );
  }
  return value;
}

function listen() {
  const rawPort = process.env.PORT ?? "8091";
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer from 1 to 65535");
  }
  const app = createApp();
  app.listen(port, "127.0.0.1", () => {
    process.stdout.write(`Vexyl Express example listening on http://127.0.0.1:${port}\n`);
  });
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  listen();
}
