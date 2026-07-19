"""Defensive AI threat intelligence and scoring for Vexyl Guard."""

from .database import (
    default_db_path,
    init_db,
    purge_runtime_history,
    runtime_history_status,
    search_threats,
    seed_db,
)
from .models import RuntimeAIEvent, RiskDecision
from .scoring import (
    evaluate_agent_plan,
    evaluate_tool_call,
    scan_external_content,
    scan_prompt,
    score_ai_event,
    score_and_record_ai_event,
)
from .updates import (
    IntelUpdateError,
    apply_intel_bundle,
    intel_update_status,
    recover_intel_database,
    rollback_intel_bundle,
    sync_intel_bundle,
    verify_intel_bundle,
)

__all__ = [
    "RuntimeAIEvent",
    "RiskDecision",
    "IntelUpdateError",
    "apply_intel_bundle",
    "default_db_path",
    "evaluate_agent_plan",
    "evaluate_tool_call",
    "init_db",
    "intel_update_status",
    "purge_runtime_history",
    "recover_intel_database",
    "rollback_intel_bundle",
    "runtime_history_status",
    "scan_external_content",
    "scan_prompt",
    "score_ai_event",
    "score_and_record_ai_event",
    "search_threats",
    "seed_db",
    "sync_intel_bundle",
    "verify_intel_bundle",
]
