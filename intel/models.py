from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _float_value(value: Any, fallback: float = 0.0) -> float:
    if value is None:
        return fallback
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _int_value(value: Any, fallback: int = 0) -> int:
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


@dataclass(frozen=True)
class Source:
    source_id: str
    name: str
    publisher: str | None = None
    url: str | None = None
    source_type: str = "internal"
    trust_score: int = 80
    first_seen_utc: str | None = None
    last_checked_utc: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class Framework:
    framework_id: str
    name: str
    version: str | None = None
    url: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class AttackPattern:
    attack_id: str
    name: str
    family: str
    attack_surface: str
    lifecycle_stage: str
    summary: str
    status: str
    maturity: str
    severity: int
    likelihood: int
    confidence: int
    first_seen: str | None = None
    last_seen: str | None = None
    horizon: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TechniqueMapping:
    mapping_id: str
    attack_id: str
    framework_id: str
    technique_id: str | None = None
    technique_name: str | None = None
    mapping_confidence: int = 7
    notes: str | None = None


@dataclass(frozen=True)
class Observation:
    observation_id: str
    attack_id: str
    source_id: str
    observed_at: str | None
    title: str
    defensive_takeaway: str
    confidence: int
    notes: str | None = None


@dataclass(frozen=True)
class Indicator:
    indicator_id: str
    attack_id: str
    indicator_type: str
    pattern: str
    pattern_is_regex: bool = False
    safe_for_public: bool = True
    severity_delta: int = 0
    context: str | None = None
    false_positive_notes: str | None = None


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    attack_id: str
    name: str
    description: str
    event_schema: str = "vexyl.ai_event.v1"
    rule_logic: dict[str, Any] = field(default_factory=dict)
    min_score: int = 25
    action: str = "warn"
    enabled: bool = True


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str
    name: str
    control_type: str
    description: str
    implementation_notes: str | None = None
    priority: int = 5


@dataclass(frozen=True)
class WatchItem:
    watch_id: str
    name: str
    forecast_summary: str
    related_attack_ids: list[str] = field(default_factory=list)
    horizon: str = "0-12 months"
    confidence: int = 5
    collection_requirements: str | None = None


@dataclass(frozen=True)
class RuntimeAIEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp_utc: str = field(default_factory=utc_now_iso)
    tenant_id: str | None = None
    user_id_hash: str | None = None
    session_id_hash: str | None = None
    model_provider: str | None = None
    model_name: str | None = None
    input_channel: str = "other"
    data_origin: str = "unknown"
    text_excerpt_redacted: str | None = None
    full_text_ref: str | None = None
    retrieved_doc_ids: list[str] = field(default_factory=list)
    tool_name: str | None = None
    tool_action: str | None = None
    tool_permissions: list[str] = field(default_factory=list)
    data_classification: str = "unknown"
    planned_actions: list[str] = field(default_factory=list)
    network_destination: str | None = None
    cost_estimate: float = 0.0
    token_count_estimate: int = 0
    verified_mitigations: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeAIEvent":
        return cls(
            event_id=str(data.get("event_id") or uuid4()),
            timestamp_utc=str(
                data.get("timestamp_utc") or data.get("event_time_utc") or utc_now_iso()
            ),
            tenant_id=data.get("tenant_id"),
            user_id_hash=data.get("user_id_hash"),
            session_id_hash=data.get("session_id_hash"),
            model_provider=data.get("model_provider"),
            model_name=data.get("model_name"),
            input_channel=str(data.get("input_channel") or "other"),
            data_origin=str(data.get("data_origin") or "unknown"),
            text_excerpt_redacted=data.get("text_excerpt_redacted")
            or data.get("text")
            or data.get("prompt"),
            full_text_ref=data.get("full_text_ref"),
            retrieved_doc_ids=_string_list(data.get("retrieved_doc_ids")),
            tool_name=data.get("tool_name"),
            tool_action=data.get("tool_action"),
            tool_permissions=_string_list(data.get("tool_permissions")),
            data_classification=str(data.get("data_classification") or "unknown"),
            planned_actions=_string_list(data.get("planned_actions")),
            network_destination=data.get("network_destination"),
            cost_estimate=_float_value(data.get("cost_estimate")),
            token_count_estimate=_int_value(data.get("token_count_estimate")),
            verified_mitigations=_string_list(
                data.get("verified_mitigations") or data.get("mitigations")
            ),
            context=data.get("context")
            if isinstance(data.get("context"), dict)
            else {},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskDecision:
    event_id: str
    score: int
    suggested_action: str
    matched_attack_ids: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    mitigations_applied: list[str] = field(default_factory=list)
    trust_level: str = "unknown"
    redacted_excerpt: str | None = None
    deny_tool_call: bool = False
    correlation_scope: str | None = None
    correlation_window_seconds: int = 0
    correlated_event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExplanationFactor:
    code: str
    category: str
    title: str
    detail: str
    effect: str
    attack_id: str | None = None
    severity: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionExplanation:
    schema: str
    decision_schema: str
    event_ref: str | None
    score: int
    risk_band: str
    outcome: str
    policy_exit_code: int
    suggested_action: str
    operator_summary: str
    trust_level: str
    factors: list[ExplanationFactor] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    omitted_factor_count: int = 0
    privacy: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
