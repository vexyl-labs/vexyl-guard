from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from .client import GatewayClientError, validate_gateway_response
from .database import load_attack_index
from .integration import DECISION_SCHEMA
from .models import DecisionExplanation, ExplanationFactor, RiskDecision
from .scoring import suggested_action_for_score

EXPLANATION_SCHEMA = "vexyl.decision_explanation.v1"
MAX_RULE_FACTORS = 96

_DECISION_FIELDS = {
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
}
_TRUST_LEVELS = {
    "untrusted_data",
    "trusted_control",
    "user_instruction",
    "internal_data",
    "persistent_context",
    "unknown",
}
_RULE_CODE_PATTERN = re.compile(
    r"^rule:(AI-[A-Z0-9]+(?:-[A-Z0-9]+)*):([a-z0-9]+(?:_[a-z0-9]+)*)$"
)
_ATTACK_ID_PATTERN = re.compile(r"^AI-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_SENSITIVE_REASON_PATTERN = re.compile(
    r"^Sensitive data classification: (confidential|secret|regulated)\.$"
)

_CONTEXT_FACTORS: dict[str, tuple[str, str, str]] = {
    "Event content originated outside the trusted control plane.": (
        "context:external_origin",
        "External content",
        "The input originated outside the trusted control plane.",
    ),
    "Event can influence a tool or external capability.": (
        "context:tool_capability",
        "Tool capability",
        "The event can influence a tool or another external capability.",
    ),
    "Network egress is present.": (
        "context:network_egress",
        "Network egress",
        "The action includes an outbound network boundary.",
    ),
    "Event may persist into memory or long-term context.": (
        "context:memory_persistence",
        "Persistent context",
        "The event may be written into memory or another persistent context.",
    ),
    "High-impact or irreversible action is present.": (
        "context:high_impact_action",
        "High-impact action",
        "The plan or tool action may be difficult to reverse or materially consequential.",
    ),
    "Cross-tenant access risk is present.": (
        "context:cross_tenant_boundary",
        "Cross-tenant boundary",
        "The event indicates a possible boundary between tenant data scopes.",
    ),
    "Large token volume increases cost and availability risk.": (
        "context:large_token_volume",
        "Large token volume",
        "Estimated token use is high enough to affect cost or availability.",
    ),
    "Extreme token or cost estimate requires a hard budget gate.": (
        "context:hard_budget_gate",
        "Hard budget gate",
        "Estimated consumption crossed the configured hard-gate range.",
    ),
    "Elevated model/API cost estimate.": (
        "context:elevated_cost",
        "Elevated cost estimate",
        "Estimated model or API cost is above the normal low-cost range.",
    ),
}

_MITIGATION_FACTORS: dict[str, tuple[str, str]] = {
    "sandbox": ("Sandbox", "A verified sandbox control reduced the assessed risk."),
    "sandboxing": (
        "Sandboxing",
        "A verified sandboxing control reduced the assessed risk.",
    ),
    "tool_sandbox": (
        "Tool sandbox",
        "A verified tool sandbox reduced the assessed risk.",
    ),
    "signed_trusted_corpus": (
        "Signed trusted corpus",
        "Verified corpus signing reduced the assessed content risk.",
    ),
    "signed_corpus": (
        "Signed corpus",
        "Verified corpus signing reduced the assessed content risk.",
    ),
    "scoped_read_only_credentials": (
        "Scoped read-only credentials",
        "Verified read-only credential scope reduced the assessed action risk.",
    ),
    "read_only_credentials": (
        "Read-only credentials",
        "Verified read-only credentials reduced the assessed action risk.",
    ),
    "human_approval": (
        "Human approval",
        "Verified human approval reduced the assessed action risk.",
    ),
    "human_approval_completed": (
        "Completed human approval",
        "A completed human approval step reduced the assessed action risk.",
    ),
    "policy_verifier": (
        "Policy verifier",
        "An independent policy verifier reduced the assessed risk.",
    ),
    "egress_deny_by_default": (
        "Egress denied by default",
        "A verified deny-by-default egress control reduced the assessed risk.",
    ),
    "tool_allowlist": (
        "Tool allowlist",
        "A verified tool allowlist reduced the assessed action risk.",
    ),
    "tenant_isolation": (
        "Tenant isolation",
        "Verified tenant isolation reduced the assessed data-boundary risk.",
    ),
}


class ExplanationError(ValueError):
    """Raised when a decision cannot be explained safely."""


def is_decision_document(document: dict[str, Any]) -> bool:
    if "decision" in document:
        return True
    return {"score", "suggested_action", "matched_rules"} <= set(document)


def decision_from_document(document: dict[str, Any]) -> RiskDecision:
    """Parse a complete direct or enveloped v1 decision without copying raw fields."""

    if not isinstance(document, dict):
        raise ExplanationError("decision input must be a JSON object")

    if "decision" in document:
        if "schema" in document:
            try:
                validate_gateway_response(document)
            except GatewayClientError as exc:
                raise ExplanationError("gateway decision envelope is invalid") from exc
        else:
            unknown = sorted(set(document) - {"ok", "decision"})
            if unknown or document.get("ok") is not True:
                raise ExplanationError("CLI decision envelope is invalid")
        data = document.get("decision")
    else:
        data = document

    if not isinstance(data, dict):
        raise ExplanationError("decision input did not contain a decision object")
    unknown_fields = sorted(set(data) - _DECISION_FIELDS)
    if unknown_fields:
        raise ExplanationError(f"unsupported decision field: {unknown_fields[0]}")

    event_id = _required_string(data, "event_id", 128)
    score = _required_integer(data, "score", 0, 100)
    suggested_action = _required_string(data, "suggested_action", 80)
    if suggested_action != suggested_action_for_score(score):
        raise ExplanationError("decision action contradicted its score")

    matched_attack_ids = _required_string_list(data, "matched_attack_ids", 64, 64)
    if any(not _ATTACK_ID_PATTERN.fullmatch(item) for item in matched_attack_ids):
        raise ExplanationError("decision contained an invalid attack id")
    matched_rules = _required_string_list(data, "matched_rules", 128, 256)
    rule_attack_ids: set[str] = set()
    for rule_id in matched_rules:
        match = _RULE_CODE_PATTERN.fullmatch(rule_id)
        if not match:
            raise ExplanationError("decision contained an invalid rule id")
        rule_attack_ids.add(match.group(1))
    if not rule_attack_ids <= set(matched_attack_ids):
        raise ExplanationError("decision rule ids contradicted matched attack ids")
    reasons = _required_string_list(data, "reasons", 64, 512)
    mitigations = _required_string_list(data, "mitigations_applied", 32, 128)

    trust_level = _required_string(data, "trust_level", 32)
    if trust_level not in _TRUST_LEVELS:
        raise ExplanationError("decision contained an invalid trust level")
    if "redacted_excerpt" not in data:
        raise ExplanationError("decision did not include redacted_excerpt")
    excerpt = data["redacted_excerpt"]
    if excerpt is not None and (not isinstance(excerpt, str) or len(excerpt) > 500):
        raise ExplanationError("decision contained an invalid redacted excerpt")
    deny_tool_call = data.get("deny_tool_call")
    if not isinstance(deny_tool_call, bool):
        raise ExplanationError("decision contained an invalid tool boundary")

    if "correlation_scope" not in data:
        raise ExplanationError("decision did not include correlation_scope")
    correlation_scope = data["correlation_scope"]
    if correlation_scope is not None and correlation_scope not in {"session", "user"}:
        raise ExplanationError("decision contained an invalid correlation scope")
    correlation_window_seconds = _required_integer(
        data, "correlation_window_seconds", 0, 86_400
    )
    correlated_event_count = _required_integer(data, "correlated_event_count", 0, 2_000)

    return RiskDecision(
        event_id=event_id,
        score=score,
        suggested_action=suggested_action,
        matched_attack_ids=matched_attack_ids,
        matched_rules=matched_rules,
        reasons=reasons,
        mitigations_applied=mitigations,
        trust_level=trust_level,
        redacted_excerpt=excerpt,
        deny_tool_call=deny_tool_call,
        correlation_scope=correlation_scope,
        correlation_window_seconds=correlation_window_seconds,
        correlated_event_count=correlated_event_count,
    )


def explain_decision(
    decision: RiskDecision, *, db_path: str | None = None
) -> DecisionExplanation:
    """Build a bounded explanation from derived decision facts only."""

    if not isinstance(decision, RiskDecision):
        raise ExplanationError("explanation input must be a RiskDecision")
    decision = decision_from_document(decision.to_dict())
    attack_index = load_attack_index(db_path)
    factors: list[ExplanationFactor] = []
    seen_codes: set[str] = set()
    included_rule_count = 0

    for rule_id in decision.matched_rules:
        factor = _rule_factor(rule_id, attack_index)
        if (
            factor is not None
            and factor.code not in seen_codes
            and included_rule_count < MAX_RULE_FACTORS
        ):
            factors.append(factor)
            seen_codes.add(factor.code)
            included_rule_count += 1

    recognized_context_reasons = 0
    for reason in decision.reasons:
        factor = _context_factor(reason)
        if factor is None:
            continue
        recognized_context_reasons += 1
        if factor.code not in seen_codes:
            factors.append(factor)
            seen_codes.add(factor.code)

    included_mitigation_count = 0
    for mitigation in decision.mitigations_applied:
        factor = _mitigation_factor(mitigation)
        if factor is not None and factor.code not in seen_codes:
            factors.append(factor)
            seen_codes.add(factor.code)
            included_mitigation_count += 1

    if decision.correlation_scope and decision.correlated_event_count > 0:
        factor = ExplanationFactor(
            code="context:correlated_activity",
            category="correlation",
            title="Correlated activity",
            detail=(
                f"{decision.correlated_event_count} prior derived event(s) within "
                f"{decision.correlation_window_seconds} seconds contributed under the "
                f"{decision.correlation_scope} boundary."
            ),
            effect="raises_risk",
        )
        if factor.code not in seen_codes:
            factors.append(factor)
            seen_codes.add(factor.code)

    if decision.deny_tool_call:
        factors.append(
            ExplanationFactor(
                code="policy:tool_action_denied",
                category="policy",
                title="Tool boundary denied",
                detail="The associated tool action must not proceed under this decision.",
                effect="sets_boundary",
            )
        )

    if not factors:
        factors.append(
            ExplanationFactor(
                code="policy:no_elevated_factors",
                category="policy",
                title="No elevated factors",
                detail="No known defensive rule or scored context factor matched.",
                effect="informational",
            )
        )

    omitted_factor_count = max(
        0,
        len(decision.reasons)
        - recognized_context_reasons
        - len(decision.matched_rules),
    )
    omitted_factor_count += len(decision.matched_rules) - included_rule_count
    omitted_factor_count += (
        len(decision.mitigations_applied) - included_mitigation_count
    )
    policy_exit_code = _policy_exit_code(decision)
    risk_band, outcome = _risk_band_and_outcome(decision)
    event_ref = _opaque_event_ref(decision.event_id)
    return DecisionExplanation(
        schema=EXPLANATION_SCHEMA,
        decision_schema=DECISION_SCHEMA,
        event_ref=event_ref,
        score=decision.score,
        risk_band=risk_band,
        outcome=outcome,
        policy_exit_code=policy_exit_code,
        suggested_action=decision.suggested_action,
        operator_summary=_operator_summary(decision, policy_exit_code),
        trust_level=decision.trust_level,
        factors=factors,
        next_steps=_next_steps(decision, policy_exit_code),
        omitted_factor_count=omitted_factor_count,
        privacy={
            "derived_facts_only": True,
            "raw_content_included": False,
            "raw_tool_arguments_included": False,
            "raw_source_identifiers_included": False,
            "event_reference_is_opaque": event_ref is not None,
        },
    )


def _rule_factor(
    rule_id: str, attack_index: dict[str, dict[str, Any]]
) -> ExplanationFactor | None:
    match = _RULE_CODE_PATTERN.fullmatch(rule_id)
    if not match:
        return None
    attack_id, rule_slug = match.groups()
    attack = attack_index.get(attack_id)
    attack_name = _safe_attack_name(attack, attack_id)
    severity = _bounded_severity(attack)
    return ExplanationFactor(
        code=rule_id,
        category="rule",
        title=rule_slug.replace("_", " ").capitalize(),
        detail=f"Matched a defensive rule associated with {attack_name}.",
        effect="raises_risk",
        attack_id=attack_id,
        severity=severity,
    )


def _context_factor(reason: str) -> ExplanationFactor | None:
    definition = _CONTEXT_FACTORS.get(reason)
    if definition is not None:
        code, title, detail = definition
        return ExplanationFactor(
            code=code,
            category="context",
            title=title,
            detail=detail,
            effect="raises_risk",
        )

    sensitive = _SENSITIVE_REASON_PATTERN.fullmatch(reason)
    if sensitive:
        classification = sensitive.group(1)
        return ExplanationFactor(
            code="context:sensitive_data",
            category="context",
            title="Sensitive data",
            detail=f"The event carries the controlled {classification} classification.",
            effect="raises_risk",
        )
    return None


def _mitigation_factor(mitigation: str) -> ExplanationFactor | None:
    definition = _MITIGATION_FACTORS.get(mitigation)
    if definition is None:
        return None
    title, detail = definition
    return ExplanationFactor(
        code=f"mitigation:{mitigation}",
        category="mitigation",
        title=title,
        detail=detail,
        effect="reduces_risk",
    )


def _risk_band_and_outcome(decision: RiskDecision) -> tuple[str, str]:
    if decision.deny_tool_call:
        outcome = "block"
    elif decision.score <= 24:
        outcome = "allow"
    elif decision.score <= 49:
        outcome = "warn"
    elif decision.score <= 69:
        outcome = "approval_required"
    elif decision.score <= 84:
        outcome = "quarantine"
    else:
        outcome = "block"

    if decision.score <= 24:
        return "low", outcome
    if decision.score <= 49:
        return "guarded", outcome
    if decision.score <= 69:
        return "high", outcome
    if decision.score <= 84:
        return "severe", outcome
    return "critical", outcome


def _policy_exit_code(decision: RiskDecision) -> int:
    if decision.deny_tool_call or decision.score >= 70:
        return 4
    if decision.score >= 50:
        return 3
    return 0


def _operator_summary(decision: RiskDecision, policy_exit_code: int) -> str:
    if decision.deny_tool_call:
        return "Keep the associated tool action blocked and review the listed factors."
    if policy_exit_code == 4:
        return "Quarantine the affected action and open an incident when required by policy."
    if policy_exit_code == 3:
        return "Do not proceed without an independent policy verifier or authorized human approval."
    if decision.score >= 25:
        return (
            "The action may proceed only under normal policy with the warning recorded."
        )
    return "The action may proceed under normal policy with the decision recorded."


def _next_steps(decision: RiskDecision, policy_exit_code: int) -> list[str]:
    if decision.deny_tool_call or policy_exit_code == 4:
        return [
            "Keep the affected action blocked or quarantined.",
            "Review the stable factor codes against the authorized task and tool policy.",
            "Preserve only redacted decision facts in the incident record.",
        ]
    if policy_exit_code == 3:
        return [
            "Pause the action pending independent verification or authorized human approval.",
            "Confirm tool scope, data boundary, and reversibility before retrying.",
        ]
    if decision.score >= 25:
        return [
            "Record the warning and review the listed factor codes.",
            "Escalate if related events recur or the action gains additional capability.",
        ]
    return ["Record the decision under the normal retention policy."]


def _opaque_event_ref(event_id: str) -> str | None:
    try:
        return str(UUID(event_id))
    except (ValueError, AttributeError):
        return None


def _safe_attack_name(attack: dict[str, Any] | None, fallback: str) -> str:
    value = attack.get("name") if isinstance(attack, dict) else None
    if not isinstance(value, str):
        return fallback
    cleaned = re.sub(r"[^A-Za-z0-9 .()/_-]+", " ", value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:100] or fallback


def _bounded_severity(attack: dict[str, Any] | None) -> int | None:
    value = attack.get("severity") if isinstance(attack, dict) else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 10 else None


def _required_string(data: dict[str, Any], key: str, maximum_length: int) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum_length:
        raise ExplanationError(f"decision contained an invalid {key}")
    return value


def _required_integer(
    data: dict[str, Any], key: str, minimum: int, maximum: int
) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExplanationError(f"decision contained an invalid {key}")
    if not minimum <= value <= maximum:
        raise ExplanationError(f"decision contained an out-of-range {key}")
    return value


def _required_string_list(
    data: dict[str, Any],
    key: str,
    maximum_items: int,
    maximum_length: int,
) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ExplanationError(f"decision contained an invalid {key}")
    if any(
        not isinstance(item, str) or not item.strip() or len(item) > maximum_length
        for item in value
    ):
        raise ExplanationError(f"decision contained an invalid {key} item")
    return list(value)
