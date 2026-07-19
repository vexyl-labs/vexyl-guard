from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .models import AttackPattern, Framework, Mitigation, Source, utc_now_iso

PACKAGE_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = PACKAGE_DIR / "migrations" / "vexyl_guard_ai_threat_schema.sql"
SEED_PATH = PACKAGE_DIR / "seeds" / "vexyl_guard_ai_threats_seed.jsonl"

PUBLIC_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  publisher TEXT,
  url TEXT,
  source_type TEXT NOT NULL DEFAULT 'internal',
  trust_score INTEGER NOT NULL DEFAULT 80,
  first_seen_utc TEXT,
  last_checked_utc TEXT,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS frameworks (
  framework_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT,
  url TEXT,
  description TEXT
);

CREATE TABLE IF NOT EXISTS attack_patterns (
  attack_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  family TEXT NOT NULL,
  attack_surface TEXT NOT NULL,
  lifecycle_stage TEXT NOT NULL,
  summary TEXT NOT NULL,
  status TEXT NOT NULL,
  maturity TEXT NOT NULL,
  severity INTEGER NOT NULL,
  likelihood INTEGER NOT NULL,
  confidence INTEGER NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  horizon TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
  observation_id TEXT PRIMARY KEY,
  attack_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  observed_at TEXT,
  title TEXT NOT NULL,
  defensive_takeaway TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS indicators (
  indicator_id TEXT PRIMARY KEY,
  attack_id TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  pattern TEXT NOT NULL,
  pattern_is_regex INTEGER NOT NULL DEFAULT 0,
  safe_for_public INTEGER NOT NULL DEFAULT 1,
  severity_delta INTEGER NOT NULL DEFAULT 0,
  context TEXT,
  false_positive_notes TEXT
);

CREATE TABLE IF NOT EXISTS detection_rules (
  rule_id TEXT PRIMARY KEY,
  attack_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  event_schema TEXT NOT NULL,
  rule_logic_json TEXT NOT NULL,
  min_score INTEGER NOT NULL,
  action TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitigations (
  mitigation_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  control_type TEXT NOT NULL,
  description TEXT NOT NULL,
  implementation_notes TEXT,
  priority INTEGER NOT NULL DEFAULT 5
);

CREATE TABLE IF NOT EXISTS attack_mitigation_map (
  attack_id TEXT NOT NULL,
  mitigation_id TEXT NOT NULL,
  effectiveness INTEGER NOT NULL,
  notes TEXT,
  PRIMARY KEY (attack_id, mitigation_id)
);

CREATE TABLE IF NOT EXISTS technique_mappings (
  mapping_id TEXT PRIMARY KEY,
  attack_id TEXT NOT NULL,
  framework_id TEXT NOT NULL,
  technique_id TEXT,
  technique_name TEXT,
  mapping_confidence INTEGER NOT NULL DEFAULT 7,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS watch_items (
  watch_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  forecast_summary TEXT NOT NULL,
  related_attack_ids_json TEXT NOT NULL DEFAULT '[]',
  horizon TEXT NOT NULL DEFAULT '0-12 months',
  confidence INTEGER NOT NULL DEFAULT 5,
  collection_requirements TEXT,
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_events (
  event_id TEXT PRIMARY KEY,
  event_time_utc TEXT,
  tenant_id TEXT,
  tenant_id_hash TEXT,
  user_id_hash TEXT,
  session_id_hash TEXT,
  model_provider TEXT,
  model_name TEXT,
  input_channel TEXT,
  data_origin TEXT,
  retrieved_doc_ids_json TEXT NOT NULL DEFAULT '[]',
  tool_name TEXT,
  tool_action TEXT,
  data_classification TEXT,
  policy_decision TEXT,
  risk_score INTEGER,
  matched_rule_ids_json TEXT NOT NULL DEFAULT '[]',
  redacted_prompt_excerpt TEXT,
  redacted_output_excerpt TEXT,
  recorded_at_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  network_destination_hash TEXT,
  content_fingerprint TEXT,
  token_count_estimate INTEGER NOT NULL DEFAULT 0,
  cost_estimate REAL NOT NULL DEFAULT 0,
  event_flags_json TEXT NOT NULL DEFAULT '{}',
  notes TEXT
);
"""

PUBLIC_SEED_RECORDS = [
    {
        "attack_id": "AI-PI-001",
        "name": "Direct Prompt Injection",
        "family": "prompt_injection",
        "attack_surface": "prompt",
        "lifecycle_stage": "runtime",
        "summary": "User-controlled instructions attempt to override trusted application or policy instructions.",
        "severity": 8,
        "likelihood": 8,
        "confidence": 8,
        "tags": ["OWASP:LLM01"],
        "defensive_signals": [
            "trusted instruction override language",
            "system or developer instruction disclosure request",
        ],
        "default_actions": ["policy_verifier", "human_approval"],
    },
    {
        "attack_id": "AI-PI-002",
        "name": "Indirect Prompt Injection",
        "family": "prompt_injection",
        "attack_surface": "external_content",
        "lifecycle_stage": "runtime",
        "summary": "Untrusted retrieved or external content carries instructions that should never inherit system trust.",
        "severity": 8,
        "likelihood": 7,
        "confidence": 8,
        "tags": ["OWASP:LLM01"],
        "defensive_signals": [
            "external content tries to instruct the assistant",
            "retrieved data requests tool use",
        ],
        "default_actions": ["signed_trusted_corpus", "policy_verifier"],
    },
    {
        "attack_id": "AI-JB-001",
        "name": "Jailbreak or Safety Bypass",
        "family": "policy_bypass",
        "attack_surface": "prompt",
        "lifecycle_stage": "runtime",
        "summary": "Input attempts to bypass established policy, audit, or safety boundaries.",
        "severity": 7,
        "likelihood": 7,
        "confidence": 7,
        "tags": ["OWASP:LLM01"],
        "defensive_signals": ["policy bypass request", "unrestricted-role framing"],
        "default_actions": ["policy_verifier", "human_approval"],
    },
    {
        "attack_id": "AI-RAG-001",
        "name": "RAG Poisoning",
        "family": "retrieval_integrity",
        "attack_surface": "rag",
        "lifecycle_stage": "ingestion",
        "summary": "Retrieved content or vector records are manipulated to influence model behavior or output trust.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP:LLM08"],
        "defensive_signals": ["untrusted corpus", "document provenance mismatch"],
        "default_actions": ["signed_trusted_corpus", "tenant_isolation"],
    },
    {
        "attack_id": "AI-MEM-001",
        "name": "Memory or Context Poisoning",
        "family": "memory_integrity",
        "attack_surface": "memory",
        "lifecycle_stage": "runtime",
        "summary": "Untrusted input attempts to persist instructions, preferences, or state that can affect future sessions.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI06"],
        "defensive_signals": [
            "persistent instruction request",
            "memory update from untrusted content",
        ],
        "default_actions": ["human_approval", "tenant_isolation"],
    },
    {
        "attack_id": "AI-AG-001",
        "name": "Agent Goal Hijack",
        "family": "agent_control",
        "attack_surface": "agent_plan",
        "lifecycle_stage": "planning",
        "summary": "A plan attempts to redirect the agent away from the authorized user task or operating scope.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI01"],
        "defensive_signals": ["task redirection", "unauthorized objective change"],
        "default_actions": ["policy_verifier", "human_approval"],
    },
    {
        "attack_id": "AI-AG-002",
        "name": "Tool Misuse or Excessive Agency",
        "family": "agent_control",
        "attack_surface": "tool_call",
        "lifecycle_stage": "action",
        "summary": "Tool access exceeds the task, user scope, or policy for high-impact actions.",
        "severity": 9,
        "likelihood": 7,
        "confidence": 8,
        "tags": ["OWASP:LLM06", "OWASP_AGENTIC:ASI02"],
        "defensive_signals": [
            "irreversible tool action",
            "broad external write permission",
        ],
        "default_actions": ["tool_allowlist", "human_approval"],
    },
    {
        "attack_id": "AI-OUT-001",
        "name": "Insecure Output Handling",
        "family": "execution_safety",
        "attack_surface": "output",
        "lifecycle_stage": "action",
        "summary": "Generated output is passed into interpreters, shells, browsers, or other execution paths without controls.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP:LLM05", "OWASP_AGENTIC:ASI05"],
        "defensive_signals": ["generated command execution", "active content handling"],
        "default_actions": ["sandbox", "policy_verifier"],
    },
    {
        "attack_id": "AI-PRIV-001",
        "name": "Sensitive Data Disclosure",
        "family": "data_exposure",
        "attack_surface": "prompt",
        "lifecycle_stage": "runtime",
        "summary": "Input or tool flow creates risk of exposing credentials, internal policy, tenant data, or regulated data.",
        "severity": 9,
        "likelihood": 7,
        "confidence": 8,
        "tags": ["OWASP:LLM02", "OWASP:LLM07"],
        "defensive_signals": ["secret request", "cross-tenant data access"],
        "default_actions": ["scoped_read_only_credentials", "tenant_isolation"],
    },
    {
        "attack_id": "AI-MOD-001",
        "name": "Model Extraction or Distillation Misuse",
        "family": "model_protection",
        "attack_surface": "model_api",
        "lifecycle_stage": "runtime",
        "summary": "Repeated model access appears intended to copy behavior, policies, labels, or decision boundaries.",
        "severity": 7,
        "likelihood": 5,
        "confidence": 6,
        "tags": ["MITRE_ATLAS:model_extraction"],
        "defensive_signals": ["high-volume label probing", "model behavior cloning"],
        "default_actions": ["rate_limit", "policy_verifier"],
    },
    {
        "attack_id": "AI-DATA-001",
        "name": "Training Data or Model Poisoning",
        "family": "model_integrity",
        "attack_surface": "training_data",
        "lifecycle_stage": "ingestion",
        "summary": "Training, tuning, or feedback data may be manipulated to degrade or backdoor model behavior.",
        "severity": 9,
        "likelihood": 5,
        "confidence": 7,
        "tags": ["OWASP:LLM04"],
        "defensive_signals": ["dataset integrity change", "feedback manipulation"],
        "default_actions": ["data_provenance", "human_approval"],
    },
    {
        "attack_id": "AI-DOS-001",
        "name": "Unbounded Token, Cost, or Tool Consumption",
        "family": "resource_exhaustion",
        "attack_surface": "runtime",
        "lifecycle_stage": "runtime",
        "summary": "Prompts, plans, or tool loops risk runaway token spend, fanout, or repeated external actions.",
        "severity": 7,
        "likelihood": 7,
        "confidence": 7,
        "tags": ["OWASP:LLM10"],
        "defensive_signals": ["recursive loop", "missing stopping condition"],
        "default_actions": ["token_budget", "rate_limit"],
    },
    {
        "attack_id": "AI-SUP-001",
        "name": "AI Supply-Chain Compromise",
        "family": "supply_chain",
        "attack_surface": "dependency",
        "lifecycle_stage": "deployment",
        "summary": "Models, prompts, adapters, tools, plugins, or datasets change without expected provenance or review.",
        "severity": 9,
        "likelihood": 5,
        "confidence": 7,
        "tags": ["OWASP:LLM03", "OWASP_AGENTIC:ASI04"],
        "defensive_signals": [
            "unsigned AI component",
            "unreviewed prompt or tool update",
        ],
        "default_actions": ["provenance_verification", "human_approval"],
    },
    {
        "attack_id": "AI-DARK-001",
        "name": "Malicious LLM Service Indicator",
        "family": "hostile_ai_service",
        "attack_surface": "model_api",
        "lifecycle_stage": "runtime",
        "summary": "Signals suggest use of malicious or policy-evading LLM services in activity targeting the host.",
        "severity": 8,
        "likelihood": 5,
        "confidence": 6,
        "tags": ["vexyl:hostile_ai_service"],
        "defensive_signals": [
            "criminal AI service reference",
            "policy-evading AI wrapper",
        ],
        "default_actions": ["monitor", "incident_review"],
    },
    {
        "attack_id": "AI-MAL-001",
        "name": "AI-Integrated Malware Behavior",
        "family": "malware",
        "attack_surface": "host_runtime",
        "lifecycle_stage": "execution",
        "summary": "Host activity suggests generated or model-guided behavior tied to scripts, tools, or process execution.",
        "severity": 10,
        "likelihood": 4,
        "confidence": 6,
        "tags": ["vexyl:ai_integrated_malware"],
        "defensive_signals": [
            "LLM call followed by execution",
            "adaptive script behavior",
        ],
        "default_actions": ["sandbox", "quarantine"],
    },
    {
        "attack_id": "AI-LURE-001",
        "name": "Fake AI Platform Malware Lure",
        "family": "social_engineering",
        "attack_surface": "web",
        "lifecycle_stage": "delivery",
        "summary": "Activity resembles AI-branded lure infrastructure, fake tools, or credential capture targeting operators.",
        "severity": 7,
        "likelihood": 6,
        "confidence": 6,
        "tags": ["vexyl:fake_ai_platform"],
        "defensive_signals": ["AI tool lure", "lookalike AI domain"],
        "default_actions": ["monitor", "incident_review"],
    },
    {
        "attack_id": "AI-SOC-001",
        "name": "AI-Enabled Social Engineering Fraud",
        "family": "social_engineering",
        "attack_surface": "identity",
        "lifecycle_stage": "runtime",
        "summary": "Synthetic identity, voice, or impersonation signals may be used to pressure high-impact actions.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 6,
        "tags": ["vexyl:social_engineering"],
        "defensive_signals": [
            "synthetic identity pressure",
            "urgent high-impact request",
        ],
        "default_actions": ["human_approval", "policy_verifier"],
    },
    {
        "attack_id": "AI-IAM-001",
        "name": "Agent Identity or Privilege Abuse",
        "family": "agent_attack",
        "attack_surface": "identity",
        "lifecycle_stage": "action",
        "summary": "An agent or delegated tool operates with an unverified identity, excessive privilege, or unsafe credential delegation.",
        "severity": 9,
        "likelihood": 6,
        "confidence": 8,
        "tags": ["OWASP_AGENTIC:ASI03"],
        "defensive_signals": [
            "unverified delegated identity",
            "credential scope exceeds task scope",
        ],
        "default_actions": ["scoped_read_only_credentials", "human_approval"],
    },
    {
        "attack_id": "AI-A2A-001",
        "name": "Insecure Inter-Agent Communication",
        "family": "agent_attack",
        "attack_surface": "inter_agent",
        "lifecycle_stage": "runtime",
        "summary": "An inter-agent message or handoff lacks verified sender identity, integrity, provenance, or an explicit trust boundary.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI07"],
        "defensive_signals": ["unverified agent sender", "unsigned agent handoff"],
        "default_actions": ["policy_verifier", "tenant_isolation"],
    },
    {
        "attack_id": "AI-CASCADE-001",
        "name": "Agentic Cascading Failure",
        "family": "availability",
        "attack_surface": "multi_agent",
        "lifecycle_stage": "runtime",
        "summary": "An incorrect or hostile decision propagates through recursive delegation, excessive fanout, retries, or downstream agents.",
        "severity": 9,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI08"],
        "defensive_signals": [
            "recursive agent delegation",
            "unbounded downstream fanout",
        ],
        "default_actions": ["rate_limit", "human_approval"],
    },
    {
        "attack_id": "AI-TRUST-001",
        "name": "Human-Agent Trust Exploitation",
        "family": "identity_social_engineering",
        "attack_surface": "approval",
        "lifecycle_stage": "action",
        "summary": "Model-generated rationale or urgency pressures a person to approve a high-impact action without independent verification.",
        "severity": 8,
        "likelihood": 6,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI09"],
        "defensive_signals": [
            "model-authored approval rationale",
            "approval pressure without independent evidence",
        ],
        "default_actions": ["human_approval", "policy_verifier"],
    },
    {
        "attack_id": "AI-ROGUE-001",
        "name": "Rogue or Uncontrolled Agent Behavior",
        "family": "agent_attack",
        "attack_surface": "agent_runtime",
        "lifecycle_stage": "runtime",
        "summary": "An agent acts outside declared policy, disables oversight, conceals actions, or modifies its own controls without authorization.",
        "severity": 10,
        "likelihood": 4,
        "confidence": 7,
        "tags": ["OWASP_AGENTIC:ASI10"],
        "defensive_signals": ["oversight disabled", "undeclared self-directed action"],
        "default_actions": ["quarantine", "incident_review"],
    },
]

SOURCE_ROWS = [
    Source(
        source_id="vexyl-ai-threat-seed-2026",
        name="Vexyl Guard AI threat seed",
        publisher="Vexyl",
        source_type="internal",
        trust_score=80,
        first_seen_utc="2026-06-27T00:00:00Z",
        last_checked_utc="2026-07-18T00:00:00Z",
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
        url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        source_type="framework",
        trust_score=95,
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
        name="OWASP Top 10 for Agentic Applications",
        version="2026",
        url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
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
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
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
    _prepare_database_file(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 3000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")
    return conn


def init_db(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    _prepare_database_file(path)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA busy_timeout = 3000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA secure_delete = ON")
        conn.executescript(load_schema_sql())
        migrate_runtime_event_schema(conn)
    return path


def _prepare_database_file(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    path.chmod(0o600)


def migrate_runtime_event_schema(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(runtime_events)")}
    additions = {
        "tenant_id_hash": "TEXT",
        "recorded_at_utc": "TEXT",
        "network_destination_hash": "TEXT",
        "content_fingerprint": "TEXT",
        "token_count_estimate": "INTEGER NOT NULL DEFAULT 0",
        "cost_estimate": "REAL NOT NULL DEFAULT 0",
        "event_flags_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for column, declaration in additions.items():
        if column not in columns:
            conn.execute(
                f"ALTER TABLE runtime_events ADD COLUMN {column} {declaration}"
            )

    conn.execute(
        "UPDATE runtime_events SET recorded_at_utc = COALESCE(event_time_utc, CURRENT_TIMESTAMP) "
        "WHERE recorded_at_utc IS NULL OR recorded_at_utc = ''"
    )

    conn.execute(
        "UPDATE runtime_events SET tenant_id = NULL, tenant_id_hash = NULL "
        "WHERE tenant_id IS NOT NULL OR tenant_id_hash IS NOT NULL"
    )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_recorded ON runtime_events(recorded_at_utc DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_session_recorded "
        "ON runtime_events(session_id_hash, recorded_at_utc DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_user_recorded "
        "ON runtime_events(user_id_hash, recorded_at_utc DESC)"
    )


def seed_db(
    db_path: str | Path | None = None, seed_path: str | Path | None = None
) -> dict[str, int]:
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
            if (
                record.get("status") in {"emerging", "forecast"}
                or "forecast" in str(record.get("horizon", "")).lower()
            ):
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
    if not path.exists() and seed_path is None:
        records = [dict(record) for record in PUBLIC_SEED_RECORDS]
        for line_number, record in enumerate(records, start=1):
            validate_seed_record(record, line_number)
        return records
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


def load_schema_sql() -> str:
    if SCHEMA_PATH.exists():
        return SCHEMA_PATH.read_text(encoding="utf-8")
    return PUBLIC_SCHEMA_SQL


def validate_seed_file(seed_path: str | Path | None = None) -> int:
    return len(load_seed_records(seed_path))


def validate_seed_record(record: dict[str, Any], line_number: int) -> None:
    required = {
        "attack_id",
        "name",
        "family",
        "summary",
        "severity",
        "likelihood",
        "confidence",
    }
    missing = sorted(required - set(record))
    if missing:
        raise ValueError(
            f"seed line {line_number} is missing required field(s): {', '.join(missing)}"
        )

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


def insert_frameworks(
    conn: sqlite3.Connection, frameworks: Iterable[Framework]
) -> None:
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
            "Track vendor, framework, threat reporting, and incident reports for defensive indicators.",
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
            OWASP_AGENTIC_NAMES.get(
                technique_id, technique_id.replace("_", " ").title()
            ),
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
    if any(
        token in lowered
        for token in ("allowlist", "credentials", "privilege", "auth", "mfa")
    ):
        return "iam"
    if any(
        token in lowered
        for token in (
            "sandbox",
            "egress",
            "runtime",
            "loop",
            "token_budget",
            "rate_limit",
        )
    ):
        return "runtime"
    if any(
        token in lowered
        for token in ("provenance", "hash", "data", "retrieval", "tenant", "memory")
    ):
        return "data"
    if any(
        token in lowered
        for token in ("monitor", "watch", "review", "audit", "analysis")
    ):
        return "monitoring"
    if any(token in lowered for token in ("incident", "playbook", "quarantine")):
        return "incident_response"
    if any(token in lowered for token in ("policy", "human", "verifier", "approval")):
        return "policy"
    return "architecture"


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "item"


def search_threats(
    query: str, db_path: str | Path | None = None, limit: int = 25
) -> list[dict[str, Any]]:
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


def load_runtime_history(
    event: dict[str, Any],
    db_path: str | Path | None = None,
    window_seconds: int = 900,
    limit: int = 500,
) -> dict[str, Any]:
    path = Path(db_path) if db_path else default_db_path()
    if not path.exists():
        return {"scope": None, "window_seconds": window_seconds, "events": []}

    session_id_hash = (
        _privacy_fingerprint(event.get("session_id_hash"), "session")
        if event.get("session_id_hash")
        else None
    )
    user_id_hash = (
        _privacy_fingerprint(event.get("user_id_hash"), "user")
        if event.get("user_id_hash")
        else None
    )
    clauses: list[str] = []
    params: list[Any] = []
    if session_id_hash:
        clauses.append("session_id_hash = ?")
        params.append(session_id_hash)
    if user_id_hash:
        clauses.append("user_id_hash = ?")
        params.append(user_id_hash)
    if not clauses:
        return {"scope": None, "window_seconds": window_seconds, "events": []}

    scope = "session" if session_id_hash else "user"
    bounded_window = max(60, min(86_400, int(window_seconds)))
    bounded_limit = max(1, min(2_000, int(limit)))
    cutoff = f"-{bounded_window} seconds"

    try:
        with connect(path) as conn:
            migrate_runtime_event_schema(conn)
            rows = conn.execute(
                f"""SELECT event_id, recorded_at_utc, user_id_hash, session_id_hash,
                           model_provider, model_name, input_channel, data_origin,
                           tool_name, tool_action, data_classification, risk_score,
                           content_fingerprint, token_count_estimate, cost_estimate,
                           event_flags_json
                      FROM runtime_events
                     WHERE datetime(recorded_at_utc) >= datetime('now', ?)
                       AND ({" OR ".join(clauses)})
                     ORDER BY datetime(recorded_at_utc) DESC
                     LIMIT ?""",
                (cutoff, *params, bounded_limit),
            ).fetchall()
    except sqlite3.DatabaseError:
        return {"scope": scope, "window_seconds": bounded_window, "events": []}

    events: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            flags = json.loads(item.pop("event_flags_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            flags = {}
        item["flags"] = flags if isinstance(flags, dict) else {}
        item["same_session"] = bool(
            session_id_hash and item.get("session_id_hash") == session_id_hash
        )
        item["same_user"] = bool(
            user_id_hash and item.get("user_id_hash") == user_id_hash
        )
        events.append(item)

    return {"scope": scope, "window_seconds": bounded_window, "events": events}


def record_runtime_event(
    event: dict[str, Any],
    decision: dict[str, Any],
    db_path: str | Path | None = None,
) -> None:
    path = init_db(db_path)
    redacted_excerpt = str(decision.get("redacted_excerpt") or "")
    flags = _runtime_event_flags(event)
    recorded_at = utc_now_iso()
    event_identifier = event.get("event_id") or f"{recorded_at}:{os.urandom(16).hex()}"
    with connect(path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO runtime_events (
              event_id, event_time_utc, tenant_id, tenant_id_hash, user_id_hash, session_id_hash,
              model_provider, model_name, input_channel, data_origin, retrieved_doc_ids_json,
              tool_name, tool_action, data_classification, policy_decision, risk_score,
              matched_rule_ids_json, redacted_prompt_excerpt, redacted_output_excerpt,
              recorded_at_utc, network_destination_hash, content_fingerprint,
              token_count_estimate, cost_estimate, event_flags_json, notes
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _privacy_fingerprint(event_identifier, "event"),
                _safe_timestamp(event.get("timestamp_utc")),
                None,
                _privacy_fingerprint(event.get("user_id_hash"), "user")
                if event.get("user_id_hash")
                else None,
                _privacy_fingerprint(event.get("session_id_hash"), "session")
                if event.get("session_id_hash")
                else None,
                _redact_fact_label(event.get("model_provider")),
                _redact_fact_label(event.get("model_name")),
                _safe_choice(
                    event.get("input_channel"),
                    {
                        "chat",
                        "api",
                        "rag",
                        "memory",
                        "tool",
                        "agent_plan",
                        "file",
                        "web",
                        "email",
                        "other",
                    },
                    "other",
                ),
                _safe_choice(
                    event.get("data_origin"),
                    {
                        "user",
                        "developer",
                        "system",
                        "retrieved_external",
                        "internal_db",
                        "tool_output",
                        "memory",
                        "unknown",
                    },
                    "unknown",
                ),
                json.dumps(
                    [
                        _privacy_fingerprint(item, "document")
                        for item in event.get("retrieved_doc_ids") or []
                    ],
                    separators=(",", ":"),
                ),
                _redact_fact_label(event.get("tool_name")),
                _redact_fact_label(event.get("tool_action")),
                _safe_choice(
                    event.get("data_classification"),
                    {
                        "public",
                        "internal",
                        "confidential",
                        "secret",
                        "regulated",
                        "unknown",
                    },
                    "unknown",
                ),
                decision.get("suggested_action"),
                decision.get("score"),
                json.dumps(decision.get("matched_rules") or []),
                redacted_excerpt,
                recorded_at,
                _privacy_fingerprint(event.get("network_destination"), "destination")
                if event.get("network_destination")
                else None,
                _privacy_fingerprint(redacted_excerpt, "content")
                if redacted_excerpt
                else None,
                _safe_int(event.get("token_count_estimate")),
                _safe_float(event.get("cost_estimate")),
                json.dumps(flags, sort_keys=True, separators=(",", ":")),
                "Stored redacted runtime facts only; raw text, destination, arguments, and context omitted.",
            ),
        )
        retention_hours = _runtime_history_retention_hours()
        conn.execute(
            "DELETE FROM runtime_events WHERE datetime(recorded_at_utc) < datetime('now', ?)",
            (f"-{retention_hours} hours",),
        )


def runtime_history_status(db_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(db_path) if db_path else default_db_path()
    retention_hours = _runtime_history_retention_hours()
    if not path.exists():
        return {
            "db": str(path),
            "exists": False,
            "retention_hours": retention_hours,
            "event_count": 0,
            "high_risk_event_count": 0,
            "oldest_recorded_at_utc": None,
            "newest_recorded_at_utc": None,
        }

    init_db(path)
    with connect(path) as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS event_count,
                      SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) AS high_risk_event_count,
                      MIN(recorded_at_utc) AS oldest_recorded_at_utc,
                      MAX(recorded_at_utc) AS newest_recorded_at_utc
                 FROM runtime_events"""
        ).fetchone()
    return {
        "db": str(path),
        "exists": True,
        "retention_hours": retention_hours,
        "event_count": int(row["event_count"] or 0),
        "high_risk_event_count": int(row["high_risk_event_count"] or 0),
        "oldest_recorded_at_utc": row["oldest_recorded_at_utc"],
        "newest_recorded_at_utc": row["newest_recorded_at_utc"],
    }


def purge_runtime_history(db_path: str | Path | None = None) -> int:
    path = Path(db_path) if db_path else default_db_path()
    if not path.exists():
        return 0
    init_db(path)
    with connect(path) as conn:
        count = int(conn.execute("SELECT COUNT(*) FROM runtime_events").fetchone()[0])
        conn.execute("DELETE FROM runtime_events")
    with connect(path) as conn:
        conn.execute("VACUUM")
    return count


def _runtime_history_retention_hours() -> int:
    raw = os.environ.get("VEXYL_AI_HISTORY_RETENTION_HOURS", "24")
    try:
        return max(1, min(720, int(raw)))
    except (TypeError, ValueError):
        return 24


def _runtime_event_flags(event: dict[str, Any]) -> dict[str, bool]:
    input_channel = str(event.get("input_channel") or "").lower()
    data_origin = str(event.get("data_origin") or "").lower()
    classification = str(event.get("data_classification") or "").lower()
    tool_name = str(event.get("tool_name") or "").lower()
    tool_action = str(event.get("tool_action") or "").lower()
    planned_actions = " ".join(
        str(item).lower() for item in event.get("planned_actions") or []
    )
    action_text = " ".join((tool_name, tool_action, planned_actions))
    context = event.get("context") if isinstance(event.get("context"), dict) else {}

    external = data_origin in {
        "retrieved_external",
        "tool_output",
        "unknown",
    } or input_channel in {
        "rag",
        "file",
        "web",
        "email",
    }
    memory_write = (
        input_channel == "memory"
        or context.get("memory_write") is True
        or any(
            term in action_text
            for term in (
                "memory write",
                "update memory",
                "store memory",
                "persist context",
            )
        )
    )
    network_egress = (
        bool(event.get("network_destination")) or context.get("network_egress") is True
    )
    external_write = network_egress or any(
        term in action_text
        for term in ("send", "upload", "post external", "email", "webhook", "transfer")
    )
    high_impact = context.get("irreversible") is True or any(
        term in action_text
        for term in (
            "delete",
            "destroy",
            "disable",
            "transfer",
            "payment",
            "purchase",
            "rotate key",
            "create user",
            "grant",
            "deploy",
            "firewall",
            "dns",
        )
    )
    code_execution = any(
        term in action_text
        for term in (
            "shell",
            "exec",
            "execute",
            "command",
            "interpreter",
            "python",
            "bash",
            "sql",
        )
    )

    return {
        "external": external,
        "sensitive": classification in {"confidential", "secret", "regulated"},
        "memory_write": memory_write,
        "untrusted_memory_write": external and memory_write,
        "tool_event": bool(tool_name or tool_action or input_channel == "tool"),
        "network_egress": network_egress,
        "external_write": external_write,
        "high_impact": high_impact,
        "code_execution": code_execution,
    }


def _privacy_fingerprint(value: Any, namespace: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip().lower())
    return hashlib.sha256(f"vexyl:{namespace}:{text}".encode("utf-8")).hexdigest()


def _redact_fact_label(value: Any, limit: int = 160) -> str | None:
    if value is None:
        return None
    text = re.sub(r"[\r\n\t]+", " ", str(value))
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "[redacted-email]",
        text,
        flags=re.I,
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or None


def _safe_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", text
    ):
        return text
    return None


def _safe_choice(value: Any, allowed: set[str], fallback: str) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in allowed else fallback


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return max(0.0, float(value or 0))
    except (TypeError, ValueError):
        return 0.0
