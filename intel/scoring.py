from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

from .database import load_attack_index, load_runtime_history, record_runtime_event
from .models import RiskDecision, RuntimeAIEvent

EXTERNAL_ORIGINS = {"retrieved_external", "tool_output", "unknown"}
EXTERNAL_CHANNELS = {"rag", "file", "web", "email"}
SENSITIVE_CLASSES = {"confidential", "secret", "regulated"}
CODE_EXECUTION_TERMS = (
    "shell",
    "exec",
    "execute",
    "command",
    "interpreter",
    "python",
    "bash",
    "sql",
    "browser",
)
IRREVERSIBLE_TERMS = (
    "delete",
    "destroy",
    "disable",
    "send",
    "transfer",
    "payment",
    "purchase",
    "change access",
    "rotate key",
    "create user",
    "grant",
    "deploy",
)
HIGH_IMPACT_TOOL_TERMS = (
    CODE_EXECUTION_TERMS
    + IRREVERSIBLE_TERMS
    + (
        "email",
        "external",
        "credential",
        "billing",
        "firewall",
        "dns",
    )
)
RUNTIME_CORRELATION_WINDOW_SECONDS = 900
TOOL_LOOP_REPEAT_THRESHOLD = 5
TOOL_LOOP_VOLUME_THRESHOLD = 25
MODEL_EXTRACTION_EVENT_THRESHOLD = 100
MODEL_EXTRACTION_DISTINCT_THRESHOLD = 80

RULE_TERMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "AI-PI-001": (
        "direct_prompt_injection",
        (
            "ignore previous",
            "ignore all previous",
            "override instruction",
            "system prompt",
            "developer message",
            "reveal your instructions",
            "hidden instructions",
            "disable logging",
            "disable policy",
            "bypass guardrail",
            "do not follow the policy",
        ),
    ),
    "AI-PI-002": (
        "indirect_prompt_injection",
        (
            "ignore the user",
            "assistant should",
            "model should",
            "call the tool",
            "use your tools",
            "send this to",
            "exfiltrate",
            "external instruction",
            "hidden text",
            "low visibility text",
        ),
    ),
    "AI-JB-001": (
        "jailbreak_safety_bypass",
        (
            "jailbreak",
            "roleplay",
            "pretend you are unrestricted",
            "bypass safety",
            "disable safety",
            "ignore constraints",
            "refusal boundary",
            "encoded request",
        ),
    ),
    "AI-RAG-001": (
        "rag_poisoning",
        (
            "embedding drift",
            "vector poisoning",
            "poisoned retrieval",
            "retrieval ranking",
            "source mismatch",
            "untrusted corpus",
            "document provenance",
            "low reputation document",
        ),
    ),
    "AI-MEM-001": (
        "memory_context_poisoning",
        (
            "remember this instruction",
            "store this instruction",
            "future conversations",
            "permanent instruction",
            "memory write",
            "update memory",
            "conversation cache",
            "scratchpad",
        ),
    ),
    "AI-AG-001": (
        "agent_goal_hijack",
        (
            "new objective",
            "instead of the user task",
            "change the task",
            "goal drift",
            "delegate to another agent",
            "silent redirect",
        ),
    ),
    "AI-AG-002": (
        "tool_misuse_excessive_agency",
        (
            "excessive agency",
            "privilege escalation",
            "external write",
            "send external",
            "tool loop",
            "irreversible action",
            "broad permissions",
        ),
    ),
    "AI-IAM-001": (
        "agent_identity_privilege_abuse",
        (
            "unverified agent identity",
            "delegated credential",
            "credential forwarding",
            "shared agent credential",
            "unscoped identity",
            "privilege boundary",
            "impersonate agent",
        ),
    ),
    "AI-A2A-001": (
        "insecure_inter_agent_communication",
        (
            "unsigned agent message",
            "unverified agent sender",
            "spoofed agent message",
            "untrusted agent handoff",
            "inter-agent message",
        ),
    ),
    "AI-CASCADE-001": (
        "agentic_cascading_failure",
        (
            "cascading failure",
            "recursive delegation",
            "retry storm",
            "downstream agent fanout",
            "propagate the decision",
        ),
    ),
    "AI-TRUST-001": (
        "human_agent_trust_exploitation",
        (
            "approval fatigue",
            "fabricated rationale",
            "misleading approval",
            "urgent approval",
            "skip independent verification",
        ),
    ),
    "AI-ROGUE-001": (
        "rogue_agent_behavior",
        (
            "disable oversight",
            "disable audit",
            "conceal action",
            "self-modify policy",
            "unauthorized persistence",
            "hide from operator",
        ),
    ),
    "AI-OUT-001": (
        "insecure_output_handling",
        (
            "execute generated code",
            "run generated command",
            "generated shell",
            "code execution",
            "unsafe interpreter",
            "active content",
        ),
    ),
    "AI-PRIV-001": (
        "sensitive_data_disclosure",
        (
            "api key",
            "secret token",
            "password",
            "credential",
            "system prompt",
            "internal policy",
            "tenant data",
            "personal data",
        ),
    ),
    "AI-MOD-001": (
        "model_extraction_distillation",
        (
            "distill",
            "clone the model",
            "teacher model",
            "decision boundary",
            "exhaustive labels",
            "rubric extraction",
            "many diverse queries",
        ),
    ),
    "AI-DATA-001": (
        "training_data_model_poisoning",
        (
            "training data",
            "fine tuning corpus",
            "dataset poisoning",
            "model poisoning",
            "feedback manipulation",
            "backdoor behavior",
        ),
    ),
    "AI-DOS-001": (
        "unbounded_consumption",
        (
            "recursive prompt",
            "repeat until",
            "tool loop",
            "no stopping condition",
            "unbounded",
            "all possible",
            "fanout",
        ),
    ),
    "AI-SUP-001": (
        "ai_supply_chain_compromise",
        (
            "unsigned model",
            "unsigned plugin",
            "unapproved mcp",
            "prompt template update",
            "adapter update",
            "dependency drift",
            "untrusted dataset",
            "broad privileges",
        ),
    ),
    "AI-DARK-001": (
        "dark_ai_service_indicator",
        (
            "dark ai",
            "uncensored ai",
            "jailbroken api wrapper",
            "wormgpt",
            "fraudgpt",
            "xanthorox",
            "criminal ai service",
        ),
    ),
    "AI-MAL-001": (
        "ai_integrated_malware_behavior",
        (
            "unknown process calling llm",
            "llm api followed by script execution",
            "jit code generation",
            "adaptive malware",
            "model prompts in process memory",
        ),
    ),
    "AI-LURE-001": (
        "fake_ai_platform_malware_lure",
        (
            "fake ai platform",
            "lookalike ai domain",
            "ai tool download",
            "malvertising",
            "fake prompt submission",
            "infostealer",
        ),
    ),
    "AI-SOC-001": (
        "ai_social_engineering_fraud",
        (
            "deepfake",
            "voice clone",
            "synthetic voice",
            "urgent payment",
            "executive impersonation",
            "helpdesk reset",
            "fake identity",
        ),
    ),
}

SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]{8,}"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"(?i)\b(?:username|user|hostname|host)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE),
    re.compile(r"/(?:home|Users)/[^/\s]+"),
]

MITIGATION_DELTAS = {
    "sandbox": -12,
    "sandboxing": -12,
    "tool_sandbox": -12,
    "signed_trusted_corpus": -15,
    "signed_corpus": -15,
    "scoped_read_only_credentials": -10,
    "read_only_credentials": -10,
    "human_approval": -20,
    "human_approval_completed": -20,
    "policy_verifier": -10,
    "egress_deny_by_default": -10,
    "tool_allowlist": -8,
    "tenant_isolation": -10,
}


class _RiskAccumulator:
    def __init__(self, event: RuntimeAIEvent, db_path: str | None = None):
        self.event = event
        self.attack_index = load_attack_index(db_path)
        self.score = 0
        self.matched_attack_ids: list[str] = []
        self.matched_rules: list[str] = []
        self.reasons: list[str] = []
        self.mitigations_applied: list[str] = []
        self.trust_level = trust_level_for_event(event)
        self.deny_tool_call = False
        self.correlation_scope: str | None = None
        self.correlation_window_seconds = 0
        self.correlated_event_count = 0
        self.minimum_final_score = 0

    def add_attack(
        self, attack_id: str, rule_slug: str, reason: str, extra: int = 0
    ) -> None:
        if attack_id not in self.attack_index:
            return
        rule_id = f"rule:{attack_id}:{rule_slug}"
        if attack_id not in self.matched_attack_ids:
            severity = int(self.attack_index[attack_id].get("severity", 5))
            self.score += severity * 6
            self.matched_attack_ids.append(attack_id)
        if rule_id not in self.matched_rules:
            self.matched_rules.append(rule_id)
        if reason not in self.reasons:
            self.reasons.append(reason)
        if extra:
            self.score += extra

    def add_context_score(self, points: int, reason: str) -> None:
        self.score += points
        if reason not in self.reasons:
            self.reasons.append(reason)

    def require_score(self, minimum: int) -> None:
        self.score = max(self.score, minimum)

    def require_final_score(self, minimum: int) -> None:
        self.minimum_final_score = max(self.minimum_final_score, minimum)

    def apply_mitigation(self, name: str, delta: int) -> None:
        self.score += delta
        self.mitigations_applied.append(name)

    def set_correlation_context(self, history: dict[str, Any]) -> None:
        events = (
            history.get("events") if isinstance(history.get("events"), list) else []
        )
        if not events:
            return
        self.correlation_scope = str(history.get("scope") or "unknown")
        self.correlation_window_seconds = int(history.get("window_seconds") or 0)
        self.correlated_event_count = len(events)

    def decision(self) -> RiskDecision:
        final_score = max(0, min(100, max(self.score, self.minimum_final_score)))
        suggested_action = suggested_action_for_score(final_score)
        if self.event.tool_name and final_score >= 50:
            self.deny_tool_call = True
        return RiskDecision(
            event_id=self.event.event_id,
            score=final_score,
            suggested_action=suggested_action,
            matched_attack_ids=self.matched_attack_ids,
            matched_rules=self.matched_rules,
            reasons=self.reasons,
            mitigations_applied=self.mitigations_applied,
            trust_level=self.trust_level,
            redacted_excerpt=redact_text(self.event.text_excerpt_redacted or ""),
            deny_tool_call=self.deny_tool_call,
            correlation_scope=self.correlation_scope,
            correlation_window_seconds=self.correlation_window_seconds,
            correlated_event_count=self.correlated_event_count,
        )


def score_ai_event(
    event: RuntimeAIEvent | dict[str, Any], db_path: str | None = None
) -> RiskDecision:
    runtime_event = (
        event if isinstance(event, RuntimeAIEvent) else RuntimeAIEvent.from_dict(event)
    )
    acc = _RiskAccumulator(runtime_event, db_path)
    text = " ".join(
        part
        for part in (
            runtime_event.text_excerpt_redacted or "",
            runtime_event.tool_name or "",
            runtime_event.tool_action or "",
            " ".join(runtime_event.tool_permissions),
            " ".join(runtime_event.planned_actions),
            json.dumps(scannable_context(runtime_event.context), sort_keys=True),
        )
        if part
    )
    lowered = normalize(text)

    for attack_id, (rule_slug, terms) in RULE_TERMS.items():
        if contains_any(lowered, terms):
            acc.add_attack(
                attack_id, rule_slug, f"Matched defensive indicators for {attack_id}."
            )

    if is_external_event(runtime_event):
        acc.add_context_score(
            10, "Event content originated outside the trusted control plane."
        )
        if contains_any(
            lowered, RULE_TERMS["AI-PI-002"][1] + RULE_TERMS["AI-PI-001"][1]
        ):
            acc.add_attack(
                "AI-PI-002",
                "external_instruction_takeover",
                "External/RAG content attempted to provide model or tool instructions.",
                extra=6,
            )
            acc.require_score(70)
        if runtime_event.data_origin in {"system", "developer"}:
            acc.add_attack(
                "AI-PI-002",
                "external_claimed_control_trust",
                "External content was prevented from receiving system/developer trust.",
                extra=10,
            )

    if runtime_event.data_classification in SENSITIVE_CLASSES:
        points = (
            15 if runtime_event.data_classification in {"secret", "regulated"} else 10
        )
        acc.add_context_score(
            points,
            f"Sensitive data classification: {runtime_event.data_classification}.",
        )
        if runtime_event.network_destination or contains_any(
            lowered, ("send", "post", "upload", "email", "webhook")
        ):
            acc.add_attack(
                "AI-PRIV-001",
                "sensitive_read_external_write",
                "Sensitive data may cross an external boundary.",
                extra=15,
            )

    if (
        runtime_event.tool_name
        or runtime_event.tool_action
        or runtime_event.tool_permissions
    ):
        acc.add_context_score(8, "Event can influence a tool or external capability.")
        evaluate_tool_policy(runtime_event, acc, lowered)

    if runtime_event.network_destination:
        acc.add_context_score(10, "Network egress is present.")

    if is_memory_write(runtime_event, lowered):
        acc.add_context_score(10, "Event may persist into memory or long-term context.")
        if is_external_event(runtime_event):
            acc.add_attack(
                "AI-MEM-001",
                "untrusted_memory_write",
                "Untrusted content attempted a memory/context write.",
                extra=8,
            )

    if contains_any(lowered, CODE_EXECUTION_TERMS) and (
        runtime_event.tool_name or runtime_event.tool_action
    ):
        acc.add_attack(
            "AI-OUT-001",
            "tool_code_execution",
            "Tool action may execute generated code, commands, SQL, or browser automation.",
            extra=10,
        )

    if has_high_impact_action(runtime_event, lowered):
        acc.add_context_score(15, "High-impact or irreversible action is present.")
        if not human_approval_present(runtime_event):
            acc.add_attack(
                "AI-AG-002",
                "high_impact_without_approval",
                "High-impact tool or plan action requires explicit human approval.",
                extra=12,
            )
            acc.deny_tool_call = bool(runtime_event.tool_name)

    if runtime_event.context.get("cross_tenant") is True or contains_any(
        lowered, ("cross-tenant", "another tenant")
    ):
        acc.add_context_score(15, "Cross-tenant access risk is present.")
        acc.add_attack(
            "AI-PRIV-001",
            "cross_tenant_data_access",
            "Potential cross-tenant data exposure.",
            extra=8,
        )

    if runtime_event.token_count_estimate >= 32_000:
        acc.add_context_score(
            10, "Large token volume increases cost and availability risk."
        )
        acc.add_attack(
            "AI-DOS-001",
            "token_budget_exceeded",
            "Token count exceeds normal operating budget.",
            extra=5,
        )
    if (
        runtime_event.token_count_estimate >= 100_000
        or runtime_event.cost_estimate >= 25
    ):
        acc.add_context_score(
            10, "Extreme token or cost estimate requires a hard budget gate."
        )
        acc.add_attack(
            "AI-DOS-001",
            "extreme_cost_budget",
            "Extreme consumption estimate.",
            extra=8,
        )
    elif runtime_event.cost_estimate >= 5:
        acc.add_context_score(5, "Elevated model/API cost estimate.")

    evaluate_plan_scope(runtime_event, acc, lowered)
    evaluate_agentic_context_policy(runtime_event, acc)
    evaluate_runtime_correlation(runtime_event, acc, lowered, db_path)
    apply_verified_mitigations(runtime_event, acc)

    return acc.decision()


def score_and_record_ai_event(
    event: RuntimeAIEvent | dict[str, Any],
    db_path: str | None = None,
) -> RiskDecision:
    runtime_event = (
        event if isinstance(event, RuntimeAIEvent) else RuntimeAIEvent.from_dict(event)
    )
    decision = score_ai_event(runtime_event, db_path=db_path)
    record_runtime_event(runtime_event.to_dict(), decision.to_dict(), db_path=db_path)
    return decision


def scan_prompt(
    text: str, context: dict[str, Any] | None = None, db_path: str | None = None
) -> RiskDecision:
    ctx = dict(context or {})
    event = RuntimeAIEvent(
        tenant_id=optional_string(ctx.get("tenant_id")),
        tenant_id_hash=optional_string(ctx.get("tenant_id_hash")),
        user_id_hash=optional_string(ctx.get("user_id_hash")),
        session_id_hash=optional_string(ctx.get("session_id_hash")),
        model_provider=optional_string(ctx.get("model_provider")),
        model_name=optional_string(ctx.get("model_name")),
        input_channel=str(ctx.get("input_channel") or "chat"),
        data_origin=str(ctx.get("data_origin") or "user"),
        text_excerpt_redacted=text,
        data_classification=str(ctx.get("data_classification") or "unknown"),
        verified_mitigations=string_list(ctx.get("verified_mitigations")),
        context=ctx,
    )
    return score_ai_event(event, db_path=db_path)


def scan_external_content(
    text: str,
    source_metadata: dict[str, Any] | None = None,
    db_path: str | None = None,
) -> RiskDecision:
    metadata = dict(source_metadata or {})
    verified_mitigations = string_list(metadata.get("verified_mitigations"))
    if metadata.get("signed_trusted_corpus") is True:
        verified_mitigations.append("signed_trusted_corpus")
    event = RuntimeAIEvent(
        tenant_id=optional_string(metadata.get("tenant_id")),
        tenant_id_hash=optional_string(metadata.get("tenant_id_hash")),
        user_id_hash=optional_string(metadata.get("user_id_hash")),
        session_id_hash=optional_string(metadata.get("session_id_hash")),
        model_provider=optional_string(metadata.get("model_provider")),
        model_name=optional_string(metadata.get("model_name")),
        input_channel=str(metadata.get("input_channel") or "rag"),
        data_origin="retrieved_external",
        text_excerpt_redacted=text,
        retrieved_doc_ids=[str(item) for item in metadata.get("retrieved_doc_ids", [])],
        data_classification=str(metadata.get("data_classification") or "unknown"),
        verified_mitigations=verified_mitigations,
        context={**metadata, "external_content_forced_untrusted": True},
    )
    return score_ai_event(event, db_path=db_path)


def evaluate_agent_plan(
    plan: str | list[Any] | dict[str, Any],
    tool_manifest: dict[str, Any] | list[Any] | None = None,
    user_scope: dict[str, Any] | list[str] | str | None = None,
    db_path: str | None = None,
) -> RiskDecision:
    planned_actions = plan_to_actions(plan)
    context = {
        "tool_manifest": tool_manifest or {},
        "user_scope": normalize_scope(user_scope),
    }
    if isinstance(user_scope, dict):
        context.update(
            {
                key: user_scope[key]
                for key in (
                    "allowed_tools",
                    "tool_policy",
                    "verified_mitigations",
                    "human_approval",
                    "tenant_id",
                    "tenant_id_hash",
                    "user_id_hash",
                    "session_id_hash",
                    "model_provider",
                    "model_name",
                    "expected_model_provider",
                    "expected_model_name",
                )
                if key in user_scope
            }
        )
    event = RuntimeAIEvent(
        tenant_id=optional_string(context.get("tenant_id")),
        tenant_id_hash=optional_string(context.get("tenant_id_hash")),
        user_id_hash=optional_string(context.get("user_id_hash")),
        session_id_hash=optional_string(context.get("session_id_hash")),
        model_provider=optional_string(context.get("model_provider")),
        model_name=optional_string(context.get("model_name")),
        input_channel="agent_plan",
        data_origin="tool_output",
        text_excerpt_redacted="\n".join(planned_actions),
        planned_actions=planned_actions,
        context=context,
    )
    return score_ai_event(event, db_path=db_path)


def evaluate_tool_call(
    tool_call: dict[str, Any],
    event_context: dict[str, Any] | None = None,
    db_path: str | None = None,
) -> RiskDecision:
    context = dict(event_context or {})
    args = tool_call.get("args") if isinstance(tool_call.get("args"), dict) else {}
    event = RuntimeAIEvent(
        tenant_id=optional_string(context.get("tenant_id")),
        tenant_id_hash=optional_string(context.get("tenant_id_hash")),
        user_id_hash=optional_string(context.get("user_id_hash")),
        session_id_hash=optional_string(context.get("session_id_hash")),
        model_provider=optional_string(context.get("model_provider")),
        model_name=optional_string(context.get("model_name")),
        input_channel="tool",
        data_origin=str(context.get("data_origin") or "tool_output"),
        text_excerpt_redacted=json.dumps(args, sort_keys=True)
        if args
        else str(tool_call.get("description") or ""),
        tool_name=str(tool_call.get("name") or tool_call.get("tool_name") or ""),
        tool_action=str(tool_call.get("action") or tool_call.get("tool_action") or ""),
        tool_permissions=string_list(tool_call.get("permissions")),
        data_classification=str(
            context.get("data_classification")
            or tool_call.get("data_classification")
            or "unknown"
        ),
        network_destination=tool_call.get("network_destination")
        or context.get("network_destination"),
        cost_estimate=safe_float(
            context.get("cost_estimate") or tool_call.get("cost_estimate") or 0
        ),
        token_count_estimate=safe_int(
            context.get("token_count_estimate")
            or tool_call.get("token_count_estimate")
            or 0
        ),
        verified_mitigations=string_list(context.get("verified_mitigations")),
        context={**context, "tool_call": tool_call},
    )
    return score_ai_event(event, db_path=db_path)


def evaluate_runtime_correlation(
    event: RuntimeAIEvent,
    acc: _RiskAccumulator,
    lowered: str,
    db_path: str | None,
) -> None:
    history = load_runtime_history(
        event.to_dict(),
        db_path=db_path,
        window_seconds=RUNTIME_CORRELATION_WINDOW_SECONDS,
    )
    events = history.get("events") if isinstance(history.get("events"), list) else []
    if not events:
        evaluate_model_identity_policy(event, acc)
        return

    acc.set_correlation_context(history)
    same_session = [item for item in events if item.get("same_session")]
    # Stateful attack chains require an application-provided session boundary.
    # User hashes are used only for aggregate volume and budget controls.
    sequence_events = same_session
    risky_external = [
        item
        for item in sequence_events
        if event_flag(item, "external") and safe_int(item.get("risk_score")) >= 50
    ]
    poisoned_memory = [
        item for item in sequence_events if event_flag(item, "untrusted_memory_write")
    ]
    prior_sensitive = [
        item for item in sequence_events if event_flag(item, "sensitive")
    ]

    current_tool = bool(
        event.tool_name or event.tool_action or event.input_channel == "tool"
    )
    current_memory_write = is_memory_write(event, lowered)
    action_lowered = normalize(
        " ".join(
            part
            for part in (
                event.tool_name or "",
                event.tool_action or "",
                " ".join(event.planned_actions),
            )
            if part
        )
    )
    current_external_write = bool(event.network_destination) or contains_any(
        action_lowered,
        ("send", "upload", "post external", "email", "webhook", "transfer"),
    )
    current_high_impact = has_high_impact_action(event, action_lowered)

    if current_memory_write and risky_external:
        acc.add_attack(
            "AI-MEM-001",
            "correlated_untrusted_memory_write",
            "A recent high-risk external event in this session preceded a persistent memory write.",
            extra=12,
        )
        acc.add_attack(
            "AI-PI-002",
            "correlated_external_to_memory",
            "External content was not permitted to establish persistent instructions.",
            extra=8,
        )
        acc.require_score(70)
        acc.require_final_score(70)

    if current_tool and risky_external:
        acc.add_attack(
            "AI-PI-002",
            "correlated_external_to_tool",
            "A recent high-risk external event preceded a tool action in the same runtime scope.",
            extra=10,
        )
        acc.add_attack(
            "AI-AG-002",
            "correlated_tool_authorization_boundary",
            "External content cannot authorize a tool call.",
            extra=10,
        )
        acc.require_score(85 if current_high_impact else 70)
        acc.require_final_score(85 if current_high_impact else 70)
        acc.deny_tool_call = True

    if current_tool and poisoned_memory:
        acc.add_attack(
            "AI-MEM-001",
            "correlated_poisoned_memory_to_action",
            "A prior untrusted memory write may be influencing the current tool action.",
            extra=15,
        )
        acc.add_attack(
            "AI-AG-002",
            "correlated_memory_to_tool",
            "Tool execution was stopped at a persistent-context trust boundary.",
            extra=10,
        )
        acc.require_score(85)
        acc.require_final_score(85)
        acc.deny_tool_call = True

    if current_external_write and prior_sensitive:
        acc.add_attack(
            "AI-PRIV-001",
            "correlated_sensitive_read_to_egress",
            "Sensitive-data access in this session preceded an external write or network destination.",
            extra=15,
        )
        if not human_approval_present(event):
            acc.require_score(85 if current_high_impact else 70)
            acc.require_final_score(85 if current_high_impact else 70)
            acc.deny_tool_call = current_tool

    if current_tool:
        repeated = [
            item
            for item in sequence_events
            if same_tool_action(item, event.tool_name, event.tool_action)
        ]
        tool_events = [
            item for item in sequence_events if event_flag(item, "tool_event")
        ]
        if len(repeated) + 1 >= TOOL_LOOP_REPEAT_THRESHOLD and (
            current_high_impact
            or current_external_write
            or contains_any(action_lowered, CODE_EXECUTION_TERMS)
        ):
            acc.add_attack(
                "AI-DOS-001",
                "correlated_repeated_tool_action",
                "A repeated high-impact tool action reached the runtime loop threshold.",
                extra=12,
            )
            acc.require_score(70)
            acc.require_final_score(70)
            acc.deny_tool_call = True
        elif len(tool_events) + 1 >= TOOL_LOOP_VOLUME_THRESHOLD:
            acc.add_attack(
                "AI-DOS-001",
                "correlated_tool_volume",
                "Tool-call volume reached the bounded runtime threshold.",
                extra=10,
            )
            acc.require_score(70)
            acc.require_final_score(70)
            acc.deny_tool_call = True

    total_tokens = max(0, event.token_count_estimate) + sum(
        max(0, safe_int(item.get("token_count_estimate"))) for item in events
    )
    total_cost = max(0.0, event.cost_estimate) + sum(
        max(0.0, safe_float(item.get("cost_estimate"))) for item in events
    )
    token_budget = positive_int(event.context.get("runtime_token_budget"), 250_000)
    cost_budget = positive_float(event.context.get("runtime_cost_budget"), 25.0)
    if total_tokens >= token_budget or total_cost >= cost_budget:
        acc.add_attack(
            "AI-DOS-001",
            "correlated_runtime_budget",
            "Aggregate token or cost use exceeded the short runtime-window budget.",
            extra=12,
        )
        severe_budget_breach = (
            total_cost >= cost_budget * 4 or total_tokens >= token_budget * 4
        )
        acc.require_score(85 if severe_budget_breach else 70)
        acc.require_final_score(85 if severe_budget_breach else 70)
        acc.deny_tool_call = current_tool

    model_events = [
        item
        for item in events
        if item.get("input_channel") in {"api", "chat"}
        and item.get("content_fingerprint")
    ]
    fingerprints = {str(item["content_fingerprint"]) for item in model_events}
    current_fingerprint = content_fingerprint_for_event(event)
    if current_fingerprint:
        fingerprints.add(current_fingerprint)
    if (
        len(model_events) + 1 >= MODEL_EXTRACTION_EVENT_THRESHOLD
        and len(fingerprints) >= MODEL_EXTRACTION_DISTINCT_THRESHOLD
    ):
        acc.add_attack(
            "AI-MOD-001",
            "correlated_high_diversity_model_probing",
            "High-volume, high-diversity model requests matched the extraction-monitoring threshold.",
            extra=12,
        )
        acc.require_score(70)
        acc.require_final_score(70)

    evaluate_model_identity_policy(event, acc)


def evaluate_agentic_context_policy(
    event: RuntimeAIEvent, acc: _RiskAccumulator
) -> None:
    context = event.context
    action_text = normalize(
        " ".join(
            part
            for part in (
                event.tool_name or "",
                event.tool_action or "",
                " ".join(event.tool_permissions),
                " ".join(event.planned_actions),
            )
            if part
        )
    )
    uses_delegated_identity = context.get(
        "uses_delegated_identity"
    ) is True or contains_any(
        action_text,
        ("credential", "identity", "impersonate", "admin token", "delegated access"),
    )
    identity_verified = context.get("delegated_identity_verified") is True
    identity_scoped = context.get("identity_scope_verified") is True
    if uses_delegated_identity and (not identity_verified or not identity_scoped):
        acc.add_attack(
            "AI-IAM-001",
            "delegated_identity_not_verified",
            "A delegated agent identity or credential lacks verified identity and task scope.",
            extra=12,
        )
        acc.require_score(70)
        acc.require_final_score(70)
        acc.deny_tool_call = bool(event.tool_name)

    if context.get("inter_agent_message") is True:
        sender_verified = context.get("sender_identity_verified") is True
        integrity_verified = context.get("message_integrity_verified") is True
        if not sender_verified or not integrity_verified:
            acc.add_attack(
                "AI-A2A-001",
                "unverified_inter_agent_message",
                "An inter-agent message lacks verified sender identity or message integrity.",
                extra=12,
            )
            acc.require_score(70)
            acc.require_final_score(70)
            acc.deny_tool_call = bool(event.tool_name)

    delegation_depth = max(0, safe_int(context.get("delegation_depth")))
    fanout_count = max(0, safe_int(context.get("fanout_count")))
    retry_count = max(0, safe_int(context.get("retry_count")))
    max_depth = positive_int(context.get("max_delegation_depth"), 4)
    max_fanout = positive_int(context.get("max_fanout_count"), 16)
    max_retries = positive_int(context.get("max_retry_count"), 5)
    if (
        delegation_depth > max_depth
        or fanout_count > max_fanout
        or retry_count > max_retries
    ):
        acc.add_attack(
            "AI-CASCADE-001",
            "orchestration_boundary_exceeded",
            "Agent delegation, fanout, or retry activity exceeded the trusted orchestration policy.",
            extra=12,
        )
        acc.add_attack(
            "AI-DOS-001",
            "agentic_resource_cascade",
            "The orchestration boundary can amplify downstream resource consumption.",
            extra=8,
        )
        acc.require_score(70)
        acc.require_final_score(70)
        acc.deny_tool_call = bool(event.tool_name)

    high_impact = has_high_impact_action(event, action_text)
    rationale_from_model = normalize(
        str(context.get("approval_rationale_source") or "")
    ) in {
        "model",
        "agent",
        "model_output",
    }
    independently_verified = context.get("independent_verification_completed") is True
    if high_impact and rationale_from_model and not independently_verified:
        acc.add_attack(
            "AI-TRUST-001",
            "model_rationale_without_independent_verification",
            "A high-impact approval relies on model-generated rationale without independent verification.",
            extra=12,
        )
        acc.require_score(70)
        acc.require_final_score(70)
        acc.deny_tool_call = bool(event.tool_name)

    rogue_signals = (
        context.get("oversight_disabled") is True,
        context.get("audit_disabled") is True,
        context.get("policy_self_modified") is True,
        context.get("undeclared_action") is True,
    )
    if any(rogue_signals):
        acc.add_attack(
            "AI-ROGUE-001",
            "runtime_control_evasion",
            "Runtime metadata indicates an agent disabled oversight, changed policy, or took an undeclared action.",
            extra=15,
        )
        acc.require_score(85)
        acc.require_final_score(85)
        acc.deny_tool_call = bool(event.tool_name)


def evaluate_model_identity_policy(
    event: RuntimeAIEvent, acc: _RiskAccumulator
) -> None:
    expected_provider = str(event.context.get("expected_model_provider") or "").strip()
    expected_model = str(event.context.get("expected_model_name") or "").strip()
    provider_changed = bool(
        expected_provider
        and normalize(event.model_provider or "") != normalize(expected_provider)
    )
    model_changed = bool(
        expected_model
        and normalize(event.model_name or "") != normalize(expected_model)
    )
    if provider_changed or model_changed:
        acc.add_attack(
            "AI-SUP-001",
            "runtime_model_identity_mismatch",
            "Runtime model identity differs from the application-approved model policy.",
            extra=15,
        )
        acc.require_score(70)
        acc.require_final_score(70)


def event_flag(item: dict[str, Any], name: str) -> bool:
    flags = item.get("flags") if isinstance(item.get("flags"), dict) else {}
    return flags.get(name) is True


def same_tool_action(
    item: dict[str, Any], tool_name: str | None, tool_action: str | None
) -> bool:
    current_tool = normalize(tool_name or "")
    current_action = normalize(tool_action or "")
    if not current_tool and not current_action:
        return False
    return (
        normalize(str(item.get("tool_name") or "")) == current_tool
        and normalize(str(item.get("tool_action") or "")) == current_action
    )


def content_fingerprint_for_event(event: RuntimeAIEvent) -> str | None:
    text = redact_text(event.text_excerpt_redacted or "")
    if not text:
        return None
    normalized = normalize(text)
    return hashlib.sha256(f"vexyl:content:{normalized}".encode("utf-8")).hexdigest()


def evaluate_tool_policy(
    event: RuntimeAIEvent, acc: _RiskAccumulator, lowered: str
) -> None:
    allowed_tools = string_set(event.context.get("allowed_tools"))
    user_scope = normalize_scope(event.context.get("user_scope"))
    tool_policy = (
        event.context.get("tool_policy")
        if isinstance(event.context.get("tool_policy"), dict)
        else {}
    )
    tool_name = (event.tool_name or "").strip()
    tool_action = (event.tool_action or "").strip()

    if not tool_name:
        acc.add_attack(
            "AI-AG-002",
            "missing_tool_identity",
            "Tool calls are denied unless the requested tool is explicitly identified.",
            extra=18,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)
    elif not allowed_tools:
        acc.add_attack(
            "AI-AG-002",
            "missing_tool_allowlist",
            "Tool calls are denied unless an explicit task allowlist is present.",
            extra=18,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)
    elif tool_name and tool_name not in allowed_tools:
        acc.add_attack(
            "AI-AG-002",
            "tool_not_allowed",
            f"Tool {redact_text(tool_name, limit=120)} is outside the task allowlist.",
            extra=25,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)

    user_allowed_actions = string_set(user_scope.get("allowed_actions"))
    policy_allowed_actions = string_set(tool_policy.get("allowed_actions"))
    if not tool_action:
        acc.add_attack(
            "AI-AG-002",
            "missing_tool_action",
            "Tool calls are denied unless the requested action is explicitly identified.",
            extra=18,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)
    if not user_allowed_actions:
        acc.add_attack(
            "AI-AG-002",
            "missing_user_action_scope",
            "Tool action is denied until the user scope explicitly allows it.",
            extra=18,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)
    elif tool_action and not action_matches_scope(tool_action, user_allowed_actions):
        acc.add_attack(
            "AI-AG-002",
            "action_outside_user_scope",
            f"Tool action {redact_text(tool_action, limit=120)} is outside the approved user scope.",
            extra=25,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)

    if not policy_allowed_actions:
        acc.add_attack(
            "AI-AG-002",
            "missing_tool_action_policy",
            "Tool action is denied until the tool policy explicitly allows it.",
            extra=18,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)
    elif tool_action and not action_matches_scope(tool_action, policy_allowed_actions):
        acc.add_attack(
            "AI-AG-002",
            "action_outside_tool_policy",
            f"Tool action {redact_text(tool_action, limit=120)} is outside the approved tool policy.",
            extra=25,
        )
        acc.deny_tool_call = True
        acc.require_final_score(70)

    if contains_any(
        lowered,
        ("credential", "secret", "billing", "access control", "firewall", "dns"),
    ):
        acc.add_attack(
            "AI-AG-002",
            "privileged_tool_surface",
            "Tool call touches a privileged surface.",
            extra=10,
        )


def evaluate_plan_scope(
    event: RuntimeAIEvent, acc: _RiskAccumulator, lowered: str
) -> None:
    if not event.planned_actions:
        return
    user_scope = normalize_scope(event.context.get("user_scope"))
    allowed_actions = string_set(user_scope.get("allowed_actions"))
    if not allowed_actions:
        acc.add_attack(
            "AI-AG-001",
            "missing_plan_scope",
            "Agent plan cannot be authorized without explicit user/task scope.",
            extra=12,
        )
        return
    for action in event.planned_actions:
        if not action_matches_scope(action, allowed_actions):
            acc.add_attack(
                "AI-AG-001",
                "plan_goal_drift",
                "Agent plan includes an action outside the user's approved task scope.",
                extra=12,
            )
            break
    if contains_any(
        lowered, ("send", "delete", "grant", "deploy", "purchase", "external")
    ) and not human_approval_present(event):
        acc.add_attack(
            "AI-AG-002",
            "plan_high_impact_without_approval",
            "High-impact plan step requires human approval before execution.",
            extra=10,
        )


def apply_verified_mitigations(event: RuntimeAIEvent, acc: _RiskAccumulator) -> None:
    seen: set[str] = set()
    for raw in event.verified_mitigations:
        key = normalize_key(raw)
        if key in seen:
            continue
        seen.add(key)
        delta = MITIGATION_DELTAS.get(key)
        if delta is not None:
            acc.apply_mitigation(key, delta)
    if human_approval_present(event) and "human_approval" not in seen:
        acc.apply_mitigation("human_approval", MITIGATION_DELTAS["human_approval"])


def trust_level_for_event(event: RuntimeAIEvent) -> str:
    if is_external_event(event):
        return "untrusted_data"
    if event.data_origin in {"system", "developer"}:
        return "trusted_control"
    if event.data_origin == "user":
        return "user_instruction"
    if event.data_origin == "internal_db":
        return "internal_data"
    if event.data_origin == "memory":
        return "persistent_context"
    return "unknown"


def is_external_event(event: RuntimeAIEvent) -> bool:
    return (
        event.data_origin in EXTERNAL_ORIGINS
        or event.input_channel in EXTERNAL_CHANNELS
    )


def is_memory_write(event: RuntimeAIEvent, lowered: str) -> bool:
    if event.input_channel == "memory":
        return True
    return contains_any(
        lowered,
        ("memory write", "update memory", "remember this", "store this", "persistent"),
    )


def has_high_impact_action(event: RuntimeAIEvent, lowered: str) -> bool:
    if event.context.get("irreversible") is True:
        return True
    has_action_surface = bool(
        event.tool_name
        or event.tool_action
        or event.planned_actions
        or event.input_channel in {"tool", "agent_plan"}
    )
    if has_action_surface and contains_any(lowered, HIGH_IMPACT_TOOL_TERMS):
        return True
    return any(
        contains_any(normalize(action), IRREVERSIBLE_TERMS)
        for action in event.planned_actions
    )


def human_approval_present(event: RuntimeAIEvent) -> bool:
    if (
        event.context.get("human_approval") is True
        or event.context.get("human_approval_completed") is True
    ):
        return True
    return any(
        normalize_key(item) in {"human_approval", "human_approval_completed"}
        for item in event.verified_mitigations
    )


def plan_to_actions(plan: str | list[Any] | dict[str, Any]) -> list[str]:
    if isinstance(plan, str):
        return [line.strip("-* \t") for line in plan.splitlines() if line.strip()]
    if isinstance(plan, list):
        return [
            json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
            for item in plan
        ]
    if isinstance(plan, dict):
        for key in ("planned_actions", "actions", "steps", "plan"):
            if key in plan:
                return plan_to_actions(plan[key])
        return [json.dumps(plan, sort_keys=True)]
    return [str(plan)]


def normalize_scope(scope: dict[str, Any] | list[str] | str | None) -> dict[str, Any]:
    if isinstance(scope, dict):
        return scope
    if isinstance(scope, list):
        return {"allowed_actions": [str(item) for item in scope]}
    if isinstance(scope, str) and scope.strip():
        return {"allowed_actions": [scope]}
    return {}


def string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, set):
        return {str(item) for item in value if item is not None}
    return {str(value)}


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def positive_int(value: Any, fallback: int) -> int:
    parsed = safe_int(value)
    return parsed if parsed > 0 else fallback


def positive_float(value: Any, fallback: float) -> float:
    parsed = safe_float(value)
    return parsed if parsed > 0 else fallback


def scannable_context(context: dict[str, Any]) -> dict[str, Any]:
    policy_metadata = {
        "allowed_tools",
        "user_scope",
        "tool_policy",
        "verified_mitigations",
        "mitigations",
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
    }
    return {key: value for key, value in context.items() if key not in policy_metadata}


def action_matches_scope(action: str, allowed_actions: set[str]) -> bool:
    normalized_action = normalize(action)
    return normalized_action in {normalize(allowed) for allowed in allowed_actions}


def contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.lower()).strip()


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def suggested_action_for_score(score: int) -> str:
    if score <= 24:
        return "allow/log"
    if score <= 49:
        return "warn/log"
    if score <= 69:
        return "require human approval or policy verifier"
    if score <= 84:
        return "quarantine/block tool action"
    return "block and open incident"


def redact_text(text: str, limit: int = 500) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[redacted]", redacted)
    redacted = redact_ip_literals(redacted)
    redacted = re.sub(r"[\r\n\t]+", " ", redacted)
    redacted = re.sub(r"\s+", " ", redacted).strip()
    if len(redacted) > limit:
        return f"{redacted[:limit].rstrip()}..."
    return redacted


def redact_ip_literals(text: str) -> str:
    candidate_pattern = re.compile(
        r"(?<![A-Za-z0-9])\[?[A-Fa-f0-9:.]{3,}\]?(?![A-Za-z0-9])"
    )

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        unwrapped = (
            candidate[1:-1]
            if candidate.startswith("[") and candidate.endswith("]")
            else candidate
        )
        if "." not in unwrapped and ":" not in unwrapped:
            return candidate
        try:
            ipaddress.ip_address(unwrapped)
        except ValueError:
            return candidate
        return "[redacted]"

    return candidate_pattern.sub(replace, text)
