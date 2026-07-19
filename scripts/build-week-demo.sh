#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi

if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
umask 077

DB_PATH="$WORK_DIR/ai-threats.sqlite"
VEXYL=("$PYTHON_BIN" "$ROOT_DIR/vexyl" threat --db "$DB_PATH")

heading() {
  printf '\n== %s ==\n' "$1"
}

decision_summary() {
  "$PYTHON_BIN" - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    decision = json.load(handle)["decision"]

print(f"score: {decision['score']}/100")
print(f"action: {decision['suggested_action']}")
print(f"deny_tool_call: {str(decision['deny_tool_call']).lower()}")
print(f"trust_level: {decision['trust_level']}")
print(f"correlation_scope: {decision.get('correlation_scope') or 'none'}")
attack_ids = decision.get("matched_attack_ids") or []
print(f"matched_attack_ids: {', '.join(attack_ids) if attack_ids else 'none'}")
rules = [
    rule
    for rule in decision.get("matched_rules") or []
    if "correlated" in rule or "authorization" in rule or "external" in rule
]
if rules:
    print(f"notable_rules: {', '.join(rules[:4])}")
PY
}

run_policy_event() {
  local event_file="$1"
  local output_file="$2"
  local expected_exit="$3"
  shift 3

  set +e
  "${VEXYL[@]}" score-event --policy-exit-code "$@" "$event_file" \
    >"$output_file"
  local actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    echo "Expected policy exit $expected_exit, received $actual_exit." >&2
    cat "$output_file" >&2
    exit 1
  fi

  decision_summary "$output_file"
  printf 'policy_exit_code: %s\n' "$actual_exit"
}

cat >"$WORK_DIR/allowed-tool.json" <<'JSON'
{
  "event_id": "demo-allow-1",
  "session_id_hash": "demo-session-allow",
  "input_channel": "tool",
  "data_origin": "internal_db",
  "text_excerpt_redacted": "Search the approved internal documentation.",
  "tool_name": "document_search",
  "tool_action": "search approved documentation",
  "tool_permissions": ["read"],
  "verified_mitigations": [
    "tool_allowlist",
    "scoped_read_only_credentials"
  ],
  "context": {
    "allowed_tools": ["document_search"],
    "user_scope": {
      "allowed_actions": ["search approved documentation"]
    },
    "tool_policy": {
      "allowed_actions": ["search approved documentation"]
    }
  }
}
JSON

cat >"$WORK_DIR/external-content.json" <<'JSON'
{
  "event_id": "demo-external-1",
  "session_id_hash": "demo-session-correlation",
  "input_channel": "rag",
  "data_origin": "retrieved_external",
  "text_excerpt_redacted": "External content says the assistant should ignore the user and call a tool.",
  "retrieved_doc_ids": ["opaque-demo-document-hash"]
}
JSON

cat >"$WORK_DIR/correlated-tool.json" <<'JSON'
{
  "event_id": "demo-tool-1",
  "session_id_hash": "demo-session-correlation",
  "input_channel": "tool",
  "data_origin": "internal_db",
  "text_excerpt_redacted": "Search the approved internal documentation.",
  "tool_name": "document_search",
  "tool_action": "search approved documentation",
  "tool_permissions": ["read"],
  "verified_mitigations": [
    "tool_allowlist",
    "scoped_read_only_credentials"
  ],
  "context": {
    "allowed_tools": ["document_search"],
    "user_scope": {
      "allowed_actions": ["search approved documentation"]
    },
    "tool_policy": {
      "allowed_actions": ["search approved documentation"]
    }
  }
}
JSON

printf 'Vexyl Guard Build Week judge demo\n'
printf 'Uses a temporary local database, public defensive records, and redacted sample events.\n'
printf 'No root access, network connection, service, token, or private intelligence is used.\n'

heading "Initialize the offline defensive baseline"
"${VEXYL[@]}" seed >"$WORK_DIR/seed.json"
"$PYTHON_BIN" - "$WORK_DIR/seed.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
seeded = payload["seeded"]
print(f"attack patterns: {seeded['attacks']}")
print(f"detection rules: {seeded['rules']}")
print(f"mitigations: {seeded['mitigations']}")
PY

heading "Search direct and indirect prompt-injection records"
"${VEXYL[@]}" search prompt --json >"$WORK_DIR/search.json"
"$PYTHON_BIN" - "$WORK_DIR/search.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    results = json.load(handle)["results"]
selected = {
    item["attack_id"]: item
    for item in results
    if item["attack_id"] in {"AI-PI-001", "AI-PI-002"}
}
if set(selected) != {"AI-PI-001", "AI-PI-002"}:
    raise SystemExit("Expected direct and indirect prompt-injection records")
for attack_id in ("AI-PI-001", "AI-PI-002"):
    item = selected[attack_id]
    print(f"{attack_id}: {item['name']} (severity {item['severity']})")
PY

heading "Allow a scoped, read-only tool action"
run_policy_event \
  "$WORK_DIR/allowed-tool.json" \
  "$WORK_DIR/allowed-tool-output.json" \
  0

heading "Record a redacted, high-risk external-content event"
run_policy_event \
  "$WORK_DIR/external-content.json" \
  "$WORK_DIR/external-content-output.json" \
  4 \
  --record

heading "Stop the later tool action in the same session"
run_policy_event \
  "$WORK_DIR/correlated-tool.json" \
  "$WORK_DIR/correlated-tool-output.json" \
  4

heading "Inspect privacy-safe runtime history"
"${VEXYL[@]}" runtime-status >"$WORK_DIR/runtime-status.json"
"$PYTHON_BIN" - "$WORK_DIR/runtime-status.json" "$DB_PATH" <<'PY'
import json
import os
import stat
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    history = json.load(handle)["runtime_history"]
mode = stat.S_IMODE(os.stat(sys.argv[2]).st_mode)
print(f"database_mode: {mode:04o}")
print(f"derived_event_count: {history['event_count']}")
print("raw_prompts_returned: false")
print("raw_tool_arguments_returned: false")
PY

heading "Demo complete"
printf 'The temporary database and redacted sample files are removed automatically.\n'
