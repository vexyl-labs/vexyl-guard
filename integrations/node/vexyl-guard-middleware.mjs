import {
  VexylGatewayClient,
  VexylGatewayError,
  mcpToolCallEvent,
  modelApiEvent,
  validateGatewayResponse,
} from "./vexyl-guard-client.mjs";

export class VexylPolicyError extends Error {
  constructor(
    message,
    { statusCode = 500, errorCode = "vexyl_policy_error", cause } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }

  publicPayload() {
    return { error: this.errorCode };
  }
}

export class VexylPolicyUnavailable extends VexylPolicyError {
  constructor(options = {}) {
    super("Local Vexyl Guard policy decision is unavailable", {
      statusCode: 503,
      errorCode: "vexyl_policy_unavailable",
      ...options,
    });
  }
}

export class VexylPolicyDenied extends VexylPolicyError {
  constructor(response) {
    const policyExitCode = Number(response?.policy_exit_code ?? 4);
    const decision = response?.decision ?? {};
    super(decision.suggested_action ?? "Policy denied", {
      statusCode: policyExitCode === 3 ? 409 : 403,
      errorCode: "vexyl_policy_denied",
    });
    this.response = response;
    this.policyExitCode = policyExitCode;
    this.decision = decision;
  }

  publicPayload() {
    const payload = {
      error: this.errorCode,
      policy_exit_code: this.policyExitCode,
      suggested_action: this.decision.suggested_action ?? "block and review",
    };
    if (typeof this.response?.request_id === "string" && this.response.request_id) {
      payload.request_id = this.response.request_id;
    }
    return payload;
  }
}

export class VexylRequestGuard {
  constructor(client) {
    this.client = client;
  }

  async score(event) {
    let response;
    try {
      response = await this.client.score(event);
      validateGatewayResponse(response);
    } catch (error) {
      if (error instanceof VexylGatewayError) {
        throw new VexylPolicyUnavailable({ cause: error });
      }
      throw error;
    }
    return response;
  }

  async requireAllowed(event) {
    const response = await this.score(event);
    if (response.policy_exit_code !== 0) {
      throw new VexylPolicyDenied(response);
    }
    return response;
  }
}

export function createVexylGuardMiddleware({
  client = new VexylGatewayClient(),
  requestProperty = "vexylGuard",
} = {}) {
  if (typeof requestProperty !== "string" || !/^[A-Za-z_$][\w$]*$/.test(requestProperty)) {
    throw new TypeError("requestProperty must be a valid JavaScript identifier");
  }
  return function vexylGuardMiddleware(request, response, next) {
    try {
      Object.defineProperty(request, requestProperty, {
        value: new VexylRequestGuard(client),
        enumerable: false,
        configurable: false,
        writable: false,
      });
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function vexylGuardErrorHandler(error, request, response, next) {
  if (!(error instanceof VexylPolicyError) || response.headersSent) {
    next(error);
    return;
  }
  response
    .status(error.statusCode)
    .set("Cache-Control", "no-store")
    .set("X-Content-Type-Options", "nosniff")
    .json(error.publicPayload());
}

export class MCPToolGuard {
  constructor(
    requestGuard,
    {
      serverName,
      toolName,
      toolAction,
      permissions = [],
      userAllowedActions = [],
      policyAllowedActions = [],
      verifiedMitigations = [],
    },
  ) {
    this.requestGuard = requestGuard;
    this.serverName = serverName;
    this.toolName = toolName;
    this.toolAction = toolAction;
    this.permissions = [...permissions];
    this.allowedTool = `mcp:${serverName}:${toolName}`;
    this.userAllowedActions = [...userAllowedActions];
    this.policyAllowedActions = [...policyAllowedActions];
    this.verifiedMitigations = [...verifiedMitigations];
  }

  authorize(
    securitySummary,
    {
      userIdHash,
      sessionIdHash,
      dataOrigin = "internal_db",
      dataClassification = "unknown",
      networkDestination,
      humanApproval = false,
      irreversible = false,
    } = {},
  ) {
    const event = mcpToolCallEvent(securitySummary, {
      serverName: this.serverName,
      toolName: this.toolName,
      toolAction: this.toolAction,
      permissions: this.permissions,
      allowedTools: [this.allowedTool],
      userAllowedActions: this.userAllowedActions,
      policyAllowedActions: this.policyAllowedActions,
      verifiedMitigations: this.verifiedMitigations,
      userIdHash,
      sessionIdHash,
      dataOrigin,
      dataClassification,
      networkDestination,
      humanApproval,
      irreversible,
    });
    return this.requestGuard.requireAllowed(event);
  }
}

export class ModelGatewayGuard {
  constructor(
    requestGuard,
    {
      expectedModelProvider,
      expectedModelName,
      runtimeTokenBudget = 250000,
      runtimeCostBudget = 25,
    },
  ) {
    this.requestGuard = requestGuard;
    this.expectedModelProvider = expectedModelProvider;
    this.expectedModelName = expectedModelName;
    this.runtimeTokenBudget = runtimeTokenBudget;
    this.runtimeCostBudget = runtimeCostBudget;
  }

  authorize(
    securitySummary,
    {
      modelProvider,
      modelName,
      userIdHash,
      sessionIdHash,
      tokenCountEstimate = 0,
      costEstimate = 0,
    },
  ) {
    const event = modelApiEvent(securitySummary, {
      modelProvider,
      modelName,
      expectedModelProvider: this.expectedModelProvider,
      expectedModelName: this.expectedModelName,
      userIdHash,
      sessionIdHash,
      tokenCountEstimate,
      costEstimate,
      runtimeTokenBudget: this.runtimeTokenBudget,
      runtimeCostBudget: this.runtimeCostBudget,
    });
    return this.requestGuard.requireAllowed(event);
  }
}
