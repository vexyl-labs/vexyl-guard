from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .models import AttackPattern, Framework, Mitigation, Observation, Source, utc_now_iso

PACKAGE_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = PACKAGE_DIR / "migrations" / "vexyl_guard_ai_threat_schema.sql"
SEED_PATH = PACKAGE_DIR / "seeds" / "vexyl_guard_ai_threats_seed.jsonl"

SOURCE_ROWS = [
    Source(
        source_id="vexyl-ai-threat-seed-2026",
        name="Vexyl Guard AI threat seed",
        publisher="Vexyl",
        source_type="internal",
        trust_score=80,
        first_seen_utc="2026-06-27T00:00:00Z",
        last_checked_utc="2026-06-27T00:00:00Z",
        notes="Defensive summaries and indicators only; no runnable payloads.",
    ),
    Source(
        source_id="owasp-llm",
        name="OWASP Top 10 for LLM Applications",
        publisher="OWASP",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        source_type="framework",
        trust_score=95,
    ),
    Source(
        source_id="owasp-agentic",
        name="OWASP Agentic AI Security Initiative",
        publisher="OWASP",
        url="https://owasp.org/",
        source_type="framework",
        trust_score=90,
    ),
    Source(
        source_id="mitre-atlas",
        name="MITRE ATLAS",
        publisher="MITRE",
        url="https://atlas.mitre.org/",
        source_type="framework",
        trust_score=95,
    ),
]

FRAMEWORK_ROWS = [
    Framework(
        framework_id="owasp-llm",
        name="OWASP Top 10 for LLM Applications",
        description="Application-layer risks and controls for LLM-backed systems.",
    ),
    Framework(
        framework_id="owasp-agentic",
        name="OWASP Agentic AI Security Initiative",
        description="Agentic AI threat, control, and governance concepts.",
    ),
    Framework(
        framework_id="mitre-atlas",
        name="MITRE ATLAS",
        description="Adversarial tactics and techniques for AI-enabled systems.",
    ),
    Framework(
        framework_id="vexyl",
        name="Vexyl Guard AI Threat Taxonomy",
        description="Local Vexyl defensive AI threat taxonomy.",
    ),
]

OWASP_LLM_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}

OWASP_AGENTIC_NAMES = {
    "ASI01": "Agent Goal and Instruction Control",
    "ASI02": "Tool Misuse",
    "ASI03": "Excessive Agency",
    "ASI04": "Agent Supply Chain",
    "ASI06": "Memory and Context Poisoning",
}

FORBIDDEN_SEED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"```",
        r"#!\s*/(?:usr/)?bin/(?:sh|bash|python|perl|ruby)",
        r"\b(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)",
        r"\bpowershell\s+-(?:enc|encodedcommand|e)\b",
        r"\brm\s+-rf\s+/",
        r"<script\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bmsfvenom\b",
        r"\bnc\s+-e\b",
    )
]


def default_db_path() -> Path:
    configured = os.environ.get("VEXYL_THREAT_DB")
    if configured:
        return Path(configured).expanduser()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/vexyl/ai_threats.sqlite")
    return Path.home() / ".local" / "share" / "vexyl" / "ai_threats.sqlite"


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return path


def seed_db(db_path: str | Path | None = None, seed_path: str | Path | None = None) -> dict[str, int]:
    path = init_db(db_path)
    seed_records = load_seed_records(seed_path)
    with connect(path) as conn:
        insert_sources(conn, SOURCE_ROWS)
        insert_frameworks(conn, FRAMEWORK_ROWS)
        attack_count = 0
        indicator_count = 0
        rule_count = 0
        mitigation_count = 0
        mapping_count = 0
        observation_count = 0
        watch_count = 0

        for record in seed_records:
            attack = attack_from_seed(record)
            insert_attack_pattern(conn, attack)
            attack_count += 1
            observation_count += insert_observation(conn, record)
            indicator_count += insert_indicators(conn, record)
            rule_count += insert_detection_rule(conn, record)
            mitigation_count += insert_mitigations(conn, record)
            mapping_count += insert_framework_mappings(conn, record)
            if record.get("status") in {"emerging", "forecast"} or "forecast" in str(record.get("horizon", "")).lower():
                watch_count += insert_watch_item(conn, record)

    return {
        "attacks": attack_count,
        "indicators": indicator_count,
        "rules": rule_count,
        "mitigations": mitigation_count,
        "mappings": mapping_count,
        "observations": observation_count,
        "watch_items": watch_count,
    }


def load_seed_records(seed_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(seed_path) if seed_path else SEED_PATH
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            validate_seed_record(record, line_number)
            records.append(record)
    return records


def validate_seed_file(seed_path: str | Path | None = None) -> int:
    return len(load_seed_records(seed_path))


def validate_seed_record(record: dict[str, Any], line_number: int) -> None:
    required = {"attack_id", "name", "family", "summary", "severity", "likelihood", "confidence"}
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(f"seed line {line_number} is missing required field(s): {', '.join(missing)}")

    for value in _walk_text(record):
        for pattern in FORBIDDEN_SEED_PATTERNS:
            if pattern.search(value):
                raise ValueError(
                    f"seed line {line_number} contains disallowed runnable/offensive content near pattern {pattern.pattern!r}"
                )


def _walk_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_text(item)


def attack_from_seed(record: dict[str, Any]) -> AttackPattern:
    return AttackPattern(
        attack_id=record["attack_id"],
        name=record["name"],
        family=record["family"],
        attack_surface=record.get("attack_surface", "unknown"),
        lifecycle_stage=record.get("lifecycle_stage", "unknown"),
        summary=record["summary"],
        status=record.get("status", "known"),
        maturity=record.get("maturity", "observed"),
        severity=int(record["severity"]),
        likelihood=int(record["likelihood"]),
        confidence=int(record["confidence"]),
        first_seen=record.get("first_seen"),
        last_seen=record.get("last_seen"),
        horizon=record.get("horizon"),
        tags=[str(tag) for tag in record.get("tags", [])],
    )


def insert_sources(conn: sqlite3.Connection, sources: Iterable[Source]) -> None:
    conn.executemany(
        """INSERT OR REPLACE INTO sources (
          source_id, name, publisher, url, source_type, trust_score,
          first_seen_utc, last_checked_utc, notes
        ) VALUES (
          :source_id, :name, :publisher, :url, :source_type, :trust_score,
          :first_seen_utc, :last_checked_utc, :notes
        )""",
        [asdict(source) for source in sources],
    )


def insert_frameworks(conn: sqlite3.Connection, frameworks: Iterable[Framework]) -> None:
    conn.executemany(
        """INSERT OR REPLACE INTO frameworks (
          framework_id, name, version, url, description
        ) VALUES (
          :framework_id, :name, :version, :url, :description
        )""",
        [asdict(framework) for framework in frameworks],
    )


def insert_attack_pattern(conn: sqlite3.Connection, attack: AttackPattern) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO attack_patterns (
          attack_id, name, family, attack_surface, lifecycle_stage, summary,
          status, maturity, severity, likelihood, confidence, first_seen, last_seen,
          horizon, tags_json, updated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            attack.attack_id,
            attack.name,
            attack.family,
            attack.attack_surface,
            attack.lifecycle_stage,
            attack.summary,
            attack.status,
            attack.maturity,
            attack.severity,
            attack.likelihood,
            attack.confidence,
            attack.first_seen,
            attack.last_seen,
            attack.horizon,
            json.dumps(attack.tags, sort_keys=True),
            utc_now_iso(),
        ),
    )


def insert_observation(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    conn.execute(
        """INSERT OR REPLACE INTO observations (
          observation_id, attack_id, source_id, observed_at, title,
          defensive_takeaway, confidence, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f"obs:{record['attack_id']}:seed",
            record["attack_id"],
            "vexyl-ai-threat-seed-2026",
            record.get("last_seen") or record.get("first_seen"),
            f"Seed observation for {record['name']}",
            record["summary"],
            int(record.get("confidence", 7)),
            "Generated from defensive seed record.",
        ),
    )
    return 1


def insert_indicators(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    count = 0
    for index, signal in enumerate(record.get("defensive_signals", []), start=1):
        conn.execute(
            """INSERT OR REPLACE INTO indicators (
              indicator_id, attack_id, indicator_type, pattern, pattern_is_regex,
              safe_for_public, severity_delta, context, false_positive_notes
            ) VALUES (?, ?, ?, ?, 0, 1, ?, ?, ?)""",
            (
                f"ind:{record['attack_id']}:{index}",
                record["attack_id"],
                "semantic",
                str(signal),
                min(4, max(1, int(record.get("severity", 5)) - 5)),
                "Defensive semantic indicator from seed record.",
                "Treat as a clue, not a standalone verdict.",
            ),
        )
        count += 1
    return count


def insert_detection_rule(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    severity = int(record.get("severity", 5))
    min_score = min(100, max(15, severity * 6))
    action = "require_human_approval" if severity >= 8 else "warn"
    if severity >= 10:
        action = "quarantine"
    conn.execute(
        """INSERT OR REPLACE INTO detection_rules (
          rule_id, attack_id, name, description, event_schema, rule_logic_json,
          min_score, action, enabled, updated_at_utc
        ) VALUES (?, ?, ?, ?, 'vexyl.ai_event.v1', ?, ?, ?, 1, ?)""",
        (
            f"rule:{record['attack_id']}:semantic",
            record["attack_id"],
            f"{record['name']} semantic indicator rule",
            "Match defensive semantic indicators and contextual risk signals; does not store exploit payloads.",
            json.dumps(
                {
                    "attack_id": record["attack_id"],
                    "tags": record.get("tags", []),
                    "signals": record.get("defensive_signals", []),
                    "safety_boundary": "defensive summaries only",
                },
                sort_keys=True,
            ),
            min_score,
            action,
            utc_now_iso(),
        ),
    )
    return 1


def insert_mitigations(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    count = 0
    for action in record.get("default_actions", []):
        mitigation_id = f"mit:{slugify(action)}"
        mitigation = Mitigation(
            mitigation_id=mitigation_id,
            name=action.replace("_", " ").strip().title(),
            control_type=mitigation_control_type(action),
            description=f"Recommended defensive control for {record['name']}: {action.replace('_', ' ')}.",
            implementation_notes="Verify implementation before using it as a score-reducing mitigation.",
            priority=max(1, min(10, int(record.get("severity", 5)))),
        )
        conn.execute(
            """INSERT OR REPLACE INTO mitigations (
              mitigation_id, name, control_type, description, implementation_notes, priority
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                mitigation.mitigation_id,
                mitigation.name,
                mitigation.control_type,
                mitigation.description,
                mitigation.implementation_notes,
                mitigation.priority,
            ),
        )
        conn.execute(
            """INSERT OR REPLACE INTO attack_mitigation_map (
              attack_id, mitigation_id, effectiveness, notes
            ) VALUES (?, ?, ?, ?)""",
            (
                record["attack_id"],
                mitigation_id,
                max(3, min(10, int(record.get("confidence", 7)))),
                "Generated from seed default action.",
            ),
        )
        count += 1
    return count


def insert_framework_mappings(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    count = 0
    for tag in record.get("tags", []):
        parsed = framework_mapping_from_tag(str(tag), record["attack_id"])
        if not parsed:
            continue
        conn.execute(
            """INSERT OR REPLACE INTO technique_mappings (
              mapping_id, attack_id, framework_id, technique_id,
              technique_name, mapping_confidence, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            parsed,
        )
        count += 1
    return count


def insert_watch_item(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    conn.execute(
        """INSERT OR REPLACE INTO watch_items (
          watch_id, name, forecast_summary, related_attack_ids_json, horizon,
          confidence, collection_requirements, updated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f"watch:{record['attack_id']}",
            f"Monitor {record['name']}",
            record["summary"],
            json.dumps([record["attack_id"]]),
            record.get("horizon") or "0-12 months",
            int(record.get("confidence", 6)),
            "Track vendor, framework, abuse telemetry, and incident reports for defensive indicators.",
            utc_now_iso(),
        ),
    )
    return 1


def framework_mapping_from_tag(tag: str, attack_id: str) -> tuple[Any, ...] | None:
    if tag.startswith("OWASP:"):
        technique_id = tag.split(":", 1)[1]
        return (
            f"map:{attack_id}:owasp-llm:{technique_id}",
            attack_id,
            "owasp-llm",
            technique_id,
            OWASP_LLM_NAMES.get(technique_id, technique_id.replace("_", " ").title()),
            8,
            "Mapped from seed tag.",
        )
    if tag.startswith("OWASP_AGENTIC:"):
        technique_id = tag.split(":", 1)[1]
        return (
            f"map:{attack_id}:owasp-agentic:{technique_id}",
            attack_id,
            "owasp-agentic",
            technique_id,
            OWASP_AGENTIC_NAMES.get(technique_id, technique_id.replace("_", " ").title()),
            8,
            "Mapped from seed tag.",
        )
    if tag.startswith("MITRE_ATLAS:"):
        technique_id = tag.split(":", 1)[1]
        return (
            f"map:{attack_id}:mitre-atlas:{slugify(technique_id)}",
            attack_id,
            "mitre-atlas",
            technique_id,
            technique_id.replace("_", " ").title(),
            7,
            "Mapped from seed tag.",
        )
    return None


def mitigation_control_type(action: str) -> str:
    lowered = action.lower()
    if any(token in lowered for token in ("allowlist", "credentials", "privilege", "auth", "mfa")):
        return "iam"
    if any(token in lowered for token in ("sandbox", "egress", "runtime", "loop", "token_budget", "rate_limit")):
        return "runtime"
    if any(token in lowered for token in ("provenance", "hash", "data", "retrieval", "tenant", "memory")):
        return "data"
    if any(token in lowered for token in ("monitor", "watch", "review", "audit", "analysis")):
        return "monitoring"
    if any(token in lowered for token in ("incident", "playbook", "quarantine")):
        return "incident_response"
    if any(token in lowered for token in ("policy", "human", "verifier", "approval")):
        return "policy"
    return "architecture"


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "item"


def search_threats(query: str, db_path: str | Path | None = None, limit: int = 25) -> list[dict[str, Any]]:
    path = Path(db_path) if db_path else default_db_path()
    if not path.exists():
        records = load_seed_records()
        lowered = query.lower()
        return [
            seed_search_result(record)
            for record in records
            if lowered in json.dumps(record, sort_keys=True).lower()
        ][:limit]

    like = f"%{query.lower()}%"
    with connect(path) as conn:
        rows = conn.execute(
            """SELECT DISTINCT
                    a.attack_id, a.name, a.family, a.attack_surface, a.lifecycle_stage,
                    a.summary, a.status, a.maturity, a.severity, a.likelihood,
                    a.confidence, a.horizon, a.tags_json
               FROM attack_patterns a
               LEFT JOIN indicators i ON i.attack_id = a.attack_id
               LEFT JOIN technique_mappings m ON m.attack_id = a.attack_id
              WHERE lower(a.attack_id) LIKE ?
                 OR lower(a.name) LIKE ?
                 OR lower(a.family) LIKE ?
                 OR lower(a.summary) LIKE ?
                 OR lower(a.tags_json) LIKE ?
                 OR lower(i.pattern) LIKE ?
                 OR lower(m.technique_id) LIKE ?
                 OR lower(m.technique_name) LIKE ?
              ORDER BY a.severity DESC, a.attack_id ASC
              LIMIT ?""",
            (like, like, like, like, like, like, like, like, limit),
        ).fetchall()
        return [attack_row_to_dict(row) for row in rows]


def attack_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["tags"] = json.loads(result.pop("tags_json") or "[]")
    return result


def seed_search_result(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "attack_id": record["attack_id"],
        "name": record["name"],
        "family": record["family"],
        "attack_surface": record.get("attack_surface"),
        "lifecycle_stage": record.get("lifecycle_stage"),
        "summary": record["summary"],
        "status": record.get("status"),
        "maturity": record.get("maturity"),
        "severity": record.get("severity"),
        "likelihood": record.get("likelihood"),
        "confidence": record.get("confidence"),
        "horizon": record.get("horizon"),
        "tags": record.get("tags", []),
    }


def load_attack_index(db_path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    path = Path(db_path) if db_path else default_db_path()
    if path.exists():
        try:
            with connect(path) as conn:
                rows = conn.execute(
                    """SELECT attack_id, name, family, summary, severity, likelihood, confidence, tags_json
                       FROM attack_patterns"""
                ).fetchall()
                if rows:
                    return {
                        row["attack_id"]: {
                            "attack_id": row["attack_id"],
                            "name": row["name"],
                            "family": row["family"],
                            "summary": row["summary"],
                            "severity": int(row["severity"]),
                            "likelihood": int(row["likelihood"]),
                            "confidence": int(row["confidence"]),
                            "tags": json.loads(row["tags_json"] or "[]"),
                        }
                        for row in rows
                    }
        except sqlite3.DatabaseError:
            pass

    return {
        record["attack_id"]: {
            "attack_id": record["attack_id"],
            "name": record["name"],
            "family": record["family"],
            "summary": record["summary"],
            "severity": int(record["severity"]),
            "likelihood": int(record["likelihood"]),
            "confidence": int(record["confidence"]),
            "tags": record.get("tags", []),
        }
        for record in load_seed_records()
    }


def record_runtime_event(
    event: dict[str, Any],
    decision: dict[str, Any],
    db_path: str | Path | None = None,
) -> None:
    path = init_db(db_path)
    with connect(path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO runtime_events (
              event_id, event_time_utc, tenant_id, user_id_hash, session_id_hash,
              model_provider, model_name, input_channel, data_origin, retrieved_doc_ids_json,
              tool_name, tool_action, data_classification, policy_decision, risk_score,
              matched_rule_ids_json, redacted_prompt_excerpt, redacted_output_excerpt, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)""",
            (
                event.get("event_id"),
                event.get("timestamp_utc"),
                event.get("tenant_id"),
                event.get("user_id_hash"),
                event.get("session_id_hash"),
                event.get("model_provider"),
                event.get("model_name"),
                event.get("input_channel"),
                event.get("data_origin"),
                json.dumps(event.get("retrieved_doc_ids") or []),
                event.get("tool_name"),
                event.get("tool_action"),
                event.get("data_classification"),
                decision.get("suggested_action"),
                decision.get("score"),
                json.dumps(decision.get("matched_rules") or []),
                decision.get("redacted_excerpt"),
                "Stored redacted runtime event only.",
            ),
        )
