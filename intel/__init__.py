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

__all__ = [
    "RuntimeAIEvent",
    "RiskDecision",
    "default_db_path",
    "evaluate_agent_plan",
    "evaluate_tool_call",
    "init_db",
    "purge_runtime_history",
    "runtime_history_status",
    "scan_external_content",
    "scan_prompt",
    "score_ai_event",
    "score_and_record_ai_event",
    "search_threats",
    "seed_db",
]
