#!/usr/bin/env bash
set -uo pipefail

VERSION="0.2.10"
CONFIG_FILE="${VEXYL_CONFIG_FILE:-/etc/vexyl/guard.conf}"

VEXYL_MODE="${VEXYL_MODE:-monitor}"
VEXYL_API_URL="${VEXYL_API_URL:-}"
VEXYL_API_TOKEN="${VEXYL_API_TOKEN:-}"
VEXYL_THRESHOLD="${VEXYL_THRESHOLD:-5}"
VEXYL_WINDOW_SECONDS="${VEXYL_WINDOW_SECONDS:-900}"
VEXYL_BLOCK_SECONDS="${VEXYL_BLOCK_SECONDS:-86400}"
VEXYL_STATE_DIR="${VEXYL_STATE_DIR:-/var/lib/vexyl}"
VEXYL_CONFIG_DIR="${VEXYL_CONFIG_DIR:-/etc/vexyl}"
VEXYL_AGENT_BIN="${VEXYL_AGENT_BIN:-/usr/local/sbin/vexyl-guard}"
VEXYL_UPGRADE_BASE_URL="${VEXYL_UPGRADE_BASE_URL:-https://vexyl.dev}"
VEXYL_UPGRADE_ALLOW_NONROOT="${VEXYL_UPGRADE_ALLOW_NONROOT:-false}"
VEXYL_UPGRADE_ALLOW_DOWNGRADE="${VEXYL_UPGRADE_ALLOW_DOWNGRADE:-false}"
VEXYL_UPGRADE_FORCE="${VEXYL_UPGRADE_FORCE:-false}"
VEXYL_RELEASE_PUBLIC_KEY_FILE="${VEXYL_RELEASE_PUBLIC_KEY_FILE:-}"
VEXYL_FIREWALL="${VEXYL_FIREWALL:-auto}"
VEXYL_ALLOWLIST="${VEXYL_ALLOWLIST:-127.0.0.1 ::1}"
VEXYL_AUTH_LOGS="${VEXYL_AUTH_LOGS:-/var/log/auth.log /var/log/secure /var/log/messages}"
VEXYL_WEB_LOGS="${VEXYL_WEB_LOGS:-/var/log/nginx/access.log /var/log/nginx/*access.log /var/log/apache2/access.log /var/log/httpd/access_log /var/log/caddy/access.log}"
VEXYL_MAIL_LOGS="${VEXYL_MAIL_LOGS:-/var/log/mail.log /var/log/maillog}"
VEXYL_FIREWALL_LOGS="${VEXYL_FIREWALL_LOGS:-/var/log/kern.log /var/log/ufw.log}"
VEXYL_VPN_LOGS="${VEXYL_VPN_LOGS:-/var/log/openvpn.log /var/log/openvpn/*.log /var/log/strongswan.log /var/log/charon.log /var/log/wireguard.log}"
VEXYL_DATABASE_LOGS="${VEXYL_DATABASE_LOGS:-/var/log/postgresql/*.log /var/log/mysql/error.log /var/log/mysqld.log /var/log/mariadb/mariadb.log /var/log/mongodb/mongod.log}"
VEXYL_OBJECT_STORAGE_LOGS="${VEXYL_OBJECT_STORAGE_LOGS:-/var/log/minio.log /var/log/minio/*.log /var/log/s3/access.log /var/log/s3/*.log /var/log/aws/s3*.log}"
VEXYL_EDGE_LOGS="${VEXYL_EDGE_LOGS:-/var/log/cloudflare.log /var/log/cloudflare/*.log /var/log/cdn/*.log /var/log/edge/*.log /var/log/waf/*.log}"
VEXYL_BOOTSTRAP_LINES="${VEXYL_BOOTSTRAP_LINES:-1500}"
VEXYL_JSON_USE_JQ="${VEXYL_JSON_USE_JQ:-auto}"
VEXYL_POLICY_SYNC_SECONDS="${VEXYL_POLICY_SYNC_SECONDS:-300}"
VEXYL_HEARTBEAT_SECONDS="${VEXYL_HEARTBEAT_SECONDS:-300}"
VEXYL_POLICY_BUNDLE_ENABLED="${VEXYL_POLICY_BUNDLE_ENABLED:-auto}"
VEXYL_POLICY_PUBLIC_KEY_DIR="${VEXYL_POLICY_PUBLIC_KEY_DIR:-}"
VEXYL_POLICY_PUBLIC_KEY_FILE="${VEXYL_POLICY_PUBLIC_KEY_FILE:-}"
VEXYL_POLICY_REVOKED_KEY_IDS="${VEXYL_POLICY_REVOKED_KEY_IDS:-}"
VEXYL_POLICY_REVOKED_KEYS_FILE="${VEXYL_POLICY_REVOKED_KEYS_FILE:-}"
VEXYL_POLICY_SIGNING_SECRET="${VEXYL_POLICY_SIGNING_SECRET:-}"
VEXYL_POLICY_KEY_ID="${VEXYL_POLICY_KEY_ID:-vexyl-policy-dev-1}"
VEXYL_DECEPTION_PATHS="${VEXYL_DECEPTION_PATHS:-/.vexyl-canary /__vexyl/trap /vexyl-honey}"
VEXYL_MUTATION_CATEGORY_THRESHOLD="${VEXYL_MUTATION_CATEGORY_THRESHOLD:-3}"
VEXYL_MUTATION_WEIGHT="${VEXYL_MUTATION_WEIGHT:-3}"
VEXYL_AI_INTEL_ENABLED="${VEXYL_AI_INTEL_ENABLED:-auto}"
VEXYL_AI_INTEL_BIN="${VEXYL_AI_INTEL_BIN:-vexyl}"
VEXYL_AI_INTEL_DB="${VEXYL_AI_INTEL_DB:-}"
VEXYL_AI_INTEL_AUTO_SEED="${VEXYL_AI_INTEL_AUTO_SEED:-false}"
VEXYL_AI_INTEL_SIGNAL_SCORE="${VEXYL_AI_INTEL_SIGNAL_SCORE:-70}"
VEXYL_AI_INTEL_SIGNAL_WEIGHT="${VEXYL_AI_INTEL_SIGNAL_WEIGHT:-4}"

SCORES_FILE=""
BLOCKS_FILE=""
CATEGORIES_FILE=""
AI_DECISIONS_FILE=""
POLICY_BUNDLE_FILE=""
POLICY_PAYLOAD_FILE=""
RELEASE_STATE_FILE=""
RELEASE_UPGRADE_ACTION=""
HOSTNAME_CACHE=""

usage() {
  cat <<'EOF'
Usage: vexyl-guard <command>

Commands:
  daemon          Follow auth logs and protect continuously.
  once            Evaluate recent auth log lines once.
  sync            Pull shared policy from the configured API.
  upgrade [url]   Verify and install the latest signed preview release.
  verify-policy   Verify and apply a local signed policy bundle JSON file.
  status          Print local agent status.
  validate-config Validate configuration before starting or enabling enforcement.
  support-report  Print a redacted install and service report for public feedback.
  unblock <ip>    Remove a local firewall block and state entry.
  test-parse      Read log lines from stdin and print parsed IPs.
  test-classify   Read log lines from stdin and print defensive classifications.
  install-systemd Install the bundled systemd service when run from source.
EOF
}

log() {
  local level="$1"
  shift
  printf '%s [%s] %s\n' "$(date -Is)" "$level" "$*"
  if command -v logger >/dev/null 2>&1; then
    logger -t vexyl-guard "[$level] $*"
  fi
}

die() {
  log error "$*"
  exit 1
}

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
  fi
  VEXYL_RELEASE_PUBLIC_KEY_FILE="${VEXYL_RELEASE_PUBLIC_KEY_FILE:-$VEXYL_CONFIG_DIR/release-signing-public.pem}"
  VEXYL_POLICY_PUBLIC_KEY_DIR="${VEXYL_POLICY_PUBLIC_KEY_DIR:-$VEXYL_CONFIG_DIR/policy-keys.d}"
  VEXYL_POLICY_PUBLIC_KEY_FILE="${VEXYL_POLICY_PUBLIC_KEY_FILE:-$VEXYL_CONFIG_DIR/policy-signing-public.pem}"
  VEXYL_POLICY_REVOKED_KEYS_FILE="${VEXYL_POLICY_REVOKED_KEYS_FILE:-$VEXYL_CONFIG_DIR/revoked-policy-keys.txt}"
  VEXYL_AI_INTEL_DB="${VEXYL_AI_INTEL_DB:-$VEXYL_STATE_DIR/ai_threats.sqlite}"
  case "$VEXYL_AI_INTEL_SIGNAL_SCORE" in ''|*[!0-9]*) VEXYL_AI_INTEL_SIGNAL_SCORE=70 ;; esac
  case "$VEXYL_AI_INTEL_SIGNAL_WEIGHT" in ''|*[!0-9]*) VEXYL_AI_INTEL_SIGNAL_WEIGHT=4 ;; esac
  case "$VEXYL_HEARTBEAT_SECONDS" in ''|*[!0-9]*) VEXYL_HEARTBEAT_SECONDS=300 ;; esac
  [ "$VEXYL_HEARTBEAT_SECONDS" -ge 60 ] 2>/dev/null || VEXYL_HEARTBEAT_SECONDS=60

  SCORES_FILE="$VEXYL_STATE_DIR/scores.tsv"
  BLOCKS_FILE="$VEXYL_STATE_DIR/blocks.tsv"
  CATEGORIES_FILE="$VEXYL_STATE_DIR/categories.tsv"
  AI_DECISIONS_FILE="$VEXYL_STATE_DIR/ai-decisions.tsv"
  POLICY_BUNDLE_FILE="$VEXYL_STATE_DIR/policy.bundle.json"
  POLICY_PAYLOAD_FILE="$VEXYL_STATE_DIR/policy.payload.json"
  RELEASE_STATE_FILE="$VEXYL_STATE_DIR/release.json"
  HOSTNAME_CACHE="$(hostname 2>/dev/null || printf 'unknown')"
}

ensure_state() {
  mkdir -p "$VEXYL_STATE_DIR" || die "failed to create state dir: $VEXYL_STATE_DIR"
  touch "$SCORES_FILE" "$BLOCKS_FILE" "$CATEGORIES_FILE" "$AI_DECISIONS_FILE" || die "failed to initialize state files"
  chmod 0600 "$SCORES_FILE" "$BLOCKS_FILE" "$CATEGORIES_FILE" "$AI_DECISIONS_FILE" 2>/dev/null || true
}

is_ipv4() {
  local ip="$1" octet o1 o2 o3 o4
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r o1 o2 o3 o4 <<<"$ip"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [ "$((10#$octet))" -le 255 ] || return 1
  done
}

ipv4_to_number() {
  local ip="$1" o1 o2 o3 o4
  is_ipv4 "$ip" || return 1
  IFS=. read -r o1 o2 o3 o4 <<<"$ip"
  printf '%u' "$((
    (10#$o1 << 24) |
    (10#$o2 << 16) |
    (10#$o3 << 8) |
    10#$o4
  ))"
}

normalize_ipv6() {
  local ip="$1" ipv4_tail left right remainder part formatted
  local ipv4_high ipv4_low zero_count
  local o1 o2 o3 o4
  local -a left_parts=() right_parts=() normalized=()

  [[ "$ip" == *:* ]] || return 1
  [[ "$ip" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  [[ "$ip" != *:::* ]] || return 1

  if [[ "$ip" == *.* ]]; then
    ipv4_tail="${ip##*:}"
    is_ipv4 "$ipv4_tail" || return 1
    IFS=. read -r o1 o2 o3 o4 <<<"$ipv4_tail"
    ipv4_high="$((10#$o1 * 256 + 10#$o2))"
    ipv4_low="$((10#$o3 * 256 + 10#$o4))"
    printf -v ipv4_tail '%x:%x' "$ipv4_high" "$ipv4_low"
    ip="${ip%:*}:$ipv4_tail"
  fi

  if [[ "$ip" == *::* ]]; then
    left="${ip%%::*}"
    remainder="${ip#*::}"
    [[ "$remainder" != *::* ]] || return 1
    right="$remainder"
    [ -z "$left" ] || IFS=: read -r -a left_parts <<<"$left"
    [ -z "$right" ] || IFS=: read -r -a right_parts <<<"$right"
    zero_count="$((8 - ${#left_parts[@]} - ${#right_parts[@]}))"
    [ "$zero_count" -ge 1 ] || return 1
  else
    [[ "$ip" != :* && "$ip" != *: ]] || return 1
    IFS=: read -r -a left_parts <<<"$ip"
    [ "${#left_parts[@]}" -eq 8 ] || return 1
    zero_count=0
  fi

  for part in "${left_parts[@]}"; do
    [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    printf -v formatted '%04x' "$((16#$part))"
    normalized+=("$formatted")
  done
  while [ "$zero_count" -gt 0 ]; do
    normalized+=("0000")
    zero_count="$((zero_count - 1))"
  done
  for part in "${right_parts[@]}"; do
    [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    printf -v formatted '%04x' "$((16#$part))"
    normalized+=("$formatted")
  done

  [ "${#normalized[@]}" -eq 8 ] || return 1
  printf '%s ' "${normalized[@]}"
}

is_ipv6() {
  normalize_ipv6 "$1" >/dev/null
}

valid_ip() {
  is_ipv4 "$1" || is_ipv6 "$1"
}

ipv4_cidr_contains() {
  local ip="$1" network="$2" prefix="$3" prefix_number ip_number network_number shift
  [[ "$prefix" =~ ^[0-9]{1,3}$ ]] || return 1
  prefix_number="$((10#$prefix))"
  [ "$prefix_number" -le 32 ] || return 1
  ip_number="$(ipv4_to_number "$ip")" || return 1
  network_number="$(ipv4_to_number "$network")" || return 1
  [ "$prefix_number" -gt 0 ] || return 0
  shift="$((32 - prefix_number))"
  [ "$((ip_number >> shift))" -eq "$((network_number >> shift))" ]
}

ipv6_cidr_contains() {
  local ip="$1" network="$2" prefix="$3" prefix_number index bits mask ip_value network_value
  local -a ip_groups=() network_groups=()
  [[ "$prefix" =~ ^[0-9]{1,3}$ ]] || return 1
  prefix_number="$((10#$prefix))"
  [ "$prefix_number" -le 128 ] || return 1
  read -r -a ip_groups <<<"$(normalize_ipv6 "$ip")" || return 1
  read -r -a network_groups <<<"$(normalize_ipv6 "$network")" || return 1
  bits="$prefix_number"

  for ((index = 0; index < 8; index++)); do
    [ "$bits" -gt 0 ] || return 0
    if [ "$bits" -ge 16 ]; then
      [ "${ip_groups[index]}" = "${network_groups[index]}" ] || return 1
      bits="$((bits - 16))"
      continue
    fi

    mask="$(((0xffff << (16 - bits)) & 0xffff))"
    ip_value="$((16#${ip_groups[index]}))"
    network_value="$((16#${network_groups[index]}))"
    [ "$((ip_value & mask))" -eq "$((network_value & mask))" ]
    return
  done
  return 0
}

cidr_contains() {
  local ip="$1" cidr="$2" network prefix
  [[ "$cidr" == */* ]] || return 1
  network="${cidr%/*}"
  prefix="${cidr##*/}"
  [[ "$network" != */* ]] || return 1

  if is_ipv4 "$ip" && is_ipv4 "$network"; then
    ipv4_cidr_contains "$ip" "$network" "$prefix"
  elif is_ipv6 "$ip" && is_ipv6 "$network"; then
    ipv6_cidr_contains "$ip" "$network" "$prefix"
  else
    return 1
  fi
}

ip_equal() {
  local first="$1" second="$2" first_normalized second_normalized
  if is_ipv4 "$first" && is_ipv4 "$second"; then
    [ "$(ipv4_to_number "$first")" = "$(ipv4_to_number "$second")" ]
  elif is_ipv6 "$first" && is_ipv6 "$second"; then
    first_normalized="$(normalize_ipv6 "$first")" || return 1
    second_normalized="$(normalize_ipv6 "$second")" || return 1
    [ "$first_normalized" = "$second_normalized" ]
  else
    return 1
  fi
}

is_allowlisted() {
  local ip="$1" entry
  local -a entries=()
  read -r -a entries <<<"$VEXYL_ALLOWLIST"
  for entry in "${entries[@]}"; do
    [ "$entry" = "$ip" ] && return 0
    if [[ "$entry" == */* ]]; then
      cidr_contains "$ip" "$entry" && return 0
    else
      ip_equal "$ip" "$entry" && return 0
    fi
  done
  return 1
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'
}

json_safe_number() {
  case "$1" in
    ''|*[!0-9]*) printf '0' ;;
    *) printf '%s' "$1" ;;
  esac
}

sanitize_tsv_field() {
  printf '%s' "$1" | tr '\t\r\n' '   '
}

normalize_web_text_for_ai() {
  sed -E \
    -e 's/%20/ /Ig' \
    -e 's/%09/ /Ig' \
    -e 's/%0a/ /Ig' \
    -e 's/%0d/ /Ig' \
    -e 's/%2f/\//Ig' \
    -e 's/%3a/:/Ig' \
    -e 's/%3d/=/Ig' \
    -e 's/%26/\&/Ig' \
    -e 's/%3f/?/Ig' \
    -e 's/\+/ /g'
}

redact_ai_signal_text() {
  sed -E \
    -e 's/([?&](token|api[_-]?key|apikey|key|secret|password|pass|auth|code)=)[^&[:space:]]+/\1[redacted]/Ig' \
    -e 's/\b(Bearer|Basic)[[:space:]][A-Za-z0-9._~+\/=-]+/\1 [redacted]/Ig' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[redacted-email]/g'
}

ai_intel_disabled() {
  case "$VEXYL_AI_INTEL_ENABLED" in
    false|False|FALSE|no|No|NO|0|off|Off|OFF|disabled|Disabled|DISABLED) return 0 ;;
    *) return 1 ;;
  esac
}

ai_intel_required() {
  case "$VEXYL_AI_INTEL_ENABLED" in
    true|True|TRUE|yes|Yes|YES|1|on|On|ON|required|Required|REQUIRED) return 0 ;;
    *) return 1 ;;
  esac
}

ai_intel_ready() {
  ai_intel_disabled && return 1
  command -v "$VEXYL_AI_INTEL_BIN" >/dev/null 2>&1 || return 1

  if [ ! -s "$VEXYL_AI_INTEL_DB" ]; then
    if truthy "$VEXYL_AI_INTEL_AUTO_SEED"; then
      "$VEXYL_AI_INTEL_BIN" threat --db "$VEXYL_AI_INTEL_DB" seed >/dev/null 2>&1 || return 1
    else
      ai_intel_required || return 1
      return 1
    fi
  fi

  [ -s "$VEXYL_AI_INTEL_DB" ]
}

ai_intel_status() {
  if ai_intel_disabled; then
    printf 'disabled'
    return 0
  fi
  if ! command -v "$VEXYL_AI_INTEL_BIN" >/dev/null 2>&1; then
    printf 'missing_cli'
    return 0
  fi
  if [ -s "$VEXYL_AI_INTEL_DB" ]; then
    printf 'ready'
    return 0
  fi
  if truthy "$VEXYL_AI_INTEL_AUTO_SEED"; then
    printf 'will_seed'
    return 0
  fi
  printf 'unseeded'
}

ai_decision_summary_from_json() {
  python3 -c '
import json
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)

decision = data.get("decision") if isinstance(data, dict) else {}
if not isinstance(decision, dict):
    sys.exit(1)

def clean(value, limit=240):
    if value is None:
        return ""
    text = str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:limit]

score = decision.get("score", 0)
try:
    score = int(score)
except Exception:
    score = 0

attack_ids = ",".join(str(item) for item in decision.get("matched_attack_ids") or [])
rules = ",".join(str(item) for item in decision.get("matched_rules") or [])
fields = [
    str(score),
    clean(decision.get("suggested_action")),
    clean(attack_ids, 400),
    clean(decision.get("trust_level")),
    clean(rules, 400),
    clean(decision.get("redacted_excerpt")),
]
print("\t".join(fields))
'
}

score_ai_web_event() {
  local ip="$1" method="$2" uri="$3" status="$4" user_agent="$5" category="$6"
  local raw_text event_file output summary ai_score ai_action ai_attack_ids ai_trust ai_rules ai_excerpt
  ai_intel_ready || return 1
  command -v python3 >/dev/null 2>&1 || return 1

  raw_text="$(printf 'HTTP %s %s status=%s user_agent=%s' "$method" "$uri" "$status" "$user_agent" | normalize_web_text_for_ai | redact_ai_signal_text)"
  event_file="$(mktemp "${VEXYL_STATE_DIR}/ai-event.XXXXXX.json" 2>/dev/null || mktemp "/tmp/vexyl-ai-event.XXXXXX.json")" || return 1
  printf '{"input_channel":"web","data_origin":"user","text_excerpt_redacted":"%s","data_classification":"unknown","context":{"source":"web_log","source_ip":"%s","category":"%s","method":"%s","status":"%s"}}\n' \
    "$(json_escape "$raw_text")" \
    "$(json_escape "$ip")" \
    "$(json_escape "$category")" \
    "$(json_escape "$method")" \
    "$(json_escape "$status")" >"$event_file" || {
      rm -f "$event_file"
      return 1
    }

  output="$("$VEXYL_AI_INTEL_BIN" threat --db "$VEXYL_AI_INTEL_DB" score-event --record "$event_file" 2>/dev/null)" || {
    rm -f "$event_file"
    return 1
  }
  rm -f "$event_file"

  summary="$(printf '%s' "$output" | ai_decision_summary_from_json 2>/dev/null)" || return 1
  [ -n "$summary" ] || return 1
  IFS=$'\t' read -r ai_score ai_action ai_attack_ids ai_trust ai_rules ai_excerpt <<<"$summary"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -Is)" \
    "$(sanitize_tsv_field "$ip")" \
    "$(sanitize_tsv_field "$ai_score")" \
    "$(sanitize_tsv_field "$ai_action")" \
    "$(sanitize_tsv_field "$ai_attack_ids")" \
    "$(sanitize_tsv_field "$ai_trust")" \
    "$(sanitize_tsv_field "$ai_rules")" \
    "$(sanitize_tsv_field "$ai_excerpt")" >>"$AI_DECISIONS_FILE" 2>/dev/null || true

  printf '%s' "$summary"
}

send_event() {
  local event_type="$1" ip="$2" reason="$3" severity="$4" action="$5"
  local metadata="${6:-}"
  [ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0

  local observed_at payload url
  observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  url="${VEXYL_API_URL%/}/v1/events"
  payload=$(printf '{"event_type":"%s","source_ip":"%s","reason":"%s","severity":"%s","action":"%s","mode":"%s","hostname":"%s","agent_version":"%s","observed_at":"%s"' \
    "$(json_escape "$event_type")" \
    "$(json_escape "$ip")" \
    "$(json_escape "$reason")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$action")" \
    "$(json_escape "$VEXYL_MODE")" \
    "$(json_escape "$HOSTNAME_CACHE")" \
    "$(json_escape "$VERSION")" \
    "$observed_at")
  if [ -n "$metadata" ]; then
    payload="${payload},\"metadata\":$metadata"
  fi
  payload="${payload}}"

  curl -fsS --connect-timeout 2 --max-time 4 \
    -H "Authorization: Bearer $VEXYL_API_TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "$url" \
    --data "$payload" >/dev/null 2>&1 || true
}

detect_firewall() {
  case "$VEXYL_FIREWALL" in
    none) printf 'none'; return 0 ;;
    nft|iptables) printf '%s' "$VEXYL_FIREWALL"; return 0 ;;
    auto) ;;
    *) log warn "unknown VEXYL_FIREWALL=$VEXYL_FIREWALL, using auto" ;;
  esac

  if command -v nft >/dev/null 2>&1; then
    printf 'nft'
  elif command -v iptables >/dev/null 2>&1; then
    printf 'iptables'
  else
    printf 'none'
  fi
}

send_heartbeat() {
  [ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0

  local url backend payload
  url="${VEXYL_API_URL%/}/v1/fleet/heartbeat"
  backend="$(detect_firewall)"
  payload=$(printf '{"hostname":"%s","agent_version":"%s","mode":"%s","heartbeat_status":"ok","service_status":"running","firewall_status":"%s"}' \
    "$(json_escape "$HOSTNAME_CACHE")" \
    "$(json_escape "$VERSION")" \
    "$(json_escape "$VEXYL_MODE")" \
    "$(json_escape "$backend")")

  curl -fsS --connect-timeout 2 --max-time 5 \
    -H "Authorization: Bearer $VEXYL_API_TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "$url" \
    --data "$payload" >/dev/null 2>&1 || true
}

heartbeat_loop() {
  while :; do
    send_heartbeat
    sleep "$VEXYL_HEARTBEAT_SECONDS" || return 0
  done
}

nft_init() {
  nft add table inet vexyl >/dev/null 2>&1 || true
  nft 'add set inet vexyl deny4 { type ipv4_addr; flags timeout; }' >/dev/null 2>&1 || true
  nft 'add set inet vexyl deny6 { type ipv6_addr; flags timeout; }' >/dev/null 2>&1 || true
  nft 'add chain inet vexyl input { type filter hook input priority -100; policy accept; }' >/dev/null 2>&1 || true
  nft 'add rule inet vexyl input ip saddr @deny4 drop' >/dev/null 2>&1 || true
  nft 'add rule inet vexyl input ip6 saddr @deny6 drop' >/dev/null 2>&1 || true
}

record_block() {
  local ip="$1" backend="$2" reason="$3" now expires tmp
  now="$(date +%s)"
  expires=$((now + VEXYL_BLOCK_SECONDS))
  tmp="${BLOCKS_FILE}.$$"
  awk -F '\t' -v ip="$ip" '$1 != ip { print }' "$BLOCKS_FILE" >"$tmp" 2>/dev/null || true
  printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "$backend" "$now" "$expires" "$reason" >>"$tmp"
  mv "$tmp" "$BLOCKS_FILE"
}

is_blocked_state() {
  local ip="$1"
  awk -F '\t' -v ip="$ip" '$1 == ip { found=1 } END { exit found ? 0 : 1 }' "$BLOCKS_FILE"
}

block_ip() {
  local ip="$1" reason="$2" backend
  valid_ip "$ip" || return 1
  is_allowlisted "$ip" && return 0
  is_blocked_state "$ip" && return 0

  if [ "$VEXYL_MODE" != "enforce" ]; then
    log info "would block $ip reason=$reason mode=$VEXYL_MODE"
    send_event "block_decision" "$ip" "$reason" "high" "would_block"
    return 0
  fi

  backend="$(detect_firewall)"
  case "$backend" in
    nft)
      nft_init
      if is_ipv4 "$ip"; then
        nft add element inet vexyl deny4 "{ $ip timeout ${VEXYL_BLOCK_SECONDS}s }" >/dev/null 2>&1 || return 1
      else
        nft add element inet vexyl deny6 "{ $ip timeout ${VEXYL_BLOCK_SECONDS}s }" >/dev/null 2>&1 || return 1
      fi
      ;;
    iptables)
      if is_ipv4 "$ip"; then
        iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$ip" -j DROP
      else
        command -v ip6tables >/dev/null 2>&1 || return 1
        ip6tables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1 || ip6tables -I INPUT -s "$ip" -j DROP
      fi
      ;;
    none)
      log warn "no supported firewall backend; would block $ip reason=$reason"
      send_event "block_decision" "$ip" "$reason" "high" "would_block_no_firewall"
      return 0
      ;;
  esac

  record_block "$ip" "$backend" "$reason"
  log warn "blocked $ip backend=$backend reason=$reason ttl=${VEXYL_BLOCK_SECONDS}s"
  send_event "block_decision" "$ip" "$reason" "high" "blocked"
}

unblock_ip() {
  local ip="$1" tmp
  valid_ip "$ip" || die "invalid IP: $ip"

  if command -v nft >/dev/null 2>&1; then
    if is_ipv4 "$ip"; then
      nft delete element inet vexyl deny4 "{ $ip }" >/dev/null 2>&1 || true
    else
      nft delete element inet vexyl deny6 "{ $ip }" >/dev/null 2>&1 || true
    fi
  fi

  if command -v iptables >/dev/null 2>&1 && is_ipv4 "$ip"; then
    while iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; do
      iptables -D INPUT -s "$ip" -j DROP >/dev/null 2>&1 || break
    done
  fi

  if command -v ip6tables >/dev/null 2>&1 && is_ipv6 "$ip"; then
    while ip6tables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1; do
      ip6tables -D INPUT -s "$ip" -j DROP >/dev/null 2>&1 || break
    done
  fi

  tmp="${BLOCKS_FILE}.$$"
  awk -F '\t' -v ip="$ip" '$1 != ip { print }' "$BLOCKS_FILE" >"$tmp" 2>/dev/null || true
  mv "$tmp" "$BLOCKS_FILE"
  log info "unblocked $ip"
}

expire_iptables_blocks() {
  local now tmp
  now="$(date +%s)"
  tmp="${BLOCKS_FILE}.$$"
  while IFS=$'\t' read -r ip backend first_seen expires reason; do
    [ -n "${ip:-}" ] || continue
    if [ "${expires:-0}" -le "$now" ] 2>/dev/null; then
      if [ "$backend" = "iptables" ]; then
        unblock_ip "$ip"
      fi
    else
      printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "$backend" "$first_seen" "$expires" "$reason" >>"$tmp"
    fi
  done <"$BLOCKS_FILE"
  [ -f "$tmp" ] && mv "$tmp" "$BLOCKS_FILE"
}

score_ip() {
  local ip="$1" reason="$2" weight="${3:-1}" event_type="${4:-signal}" severity="${5:-medium}" metadata="${6:-}"
  local now tmp score_file score
  valid_ip "$ip" || return 0
  is_allowlisted "$ip" && return 0
  case "$weight" in
    ''|*[!0-9]*) weight=1 ;;
  esac
  now="$(date +%s)"
  tmp="${SCORES_FILE}.$$"
  score_file="${tmp}.score"

  awk -F '\t' -v OFS='\t' -v ip="$ip" -v now="$now" -v window="$VEXYL_WINDOW_SECONDS" -v reason="$reason" -v weight="$weight" -v score_file="$score_file" '
    BEGIN { score = weight; wrote = 0 }
    {
      if ($1 == "") next
      if (now - $4 > window) next
      if ($1 == ip) {
        score = $2 + weight
        print $1, score, $3, now, reason
        wrote = 1
      } else {
        print
      }
    }
    END {
      if (!wrote) print ip, score, now, now, reason
      print score > score_file
    }
  ' "$SCORES_FILE" >"$tmp"

  score="$(cat "$score_file" 2>/dev/null || printf 0)"

  awk -F '\t' 'NF >= 5 { print }' "$tmp" >"${tmp}.clean" 2>/dev/null || true
  mv "${tmp}.clean" "$SCORES_FILE"
  rm -f "$tmp" "$score_file"

  log info "signal ip=$ip event=$event_type reason=$reason weight=$weight score=$score threshold=$VEXYL_THRESHOLD"
  send_event "$event_type" "$ip" "$reason" "$severity" "scored" "$metadata"

  if [ "$score" -ge "$VEXYL_THRESHOLD" ] 2>/dev/null; then
    block_ip "$ip" "$reason"
  fi
}

record_probe_category() {
  local ip="$1" category="$2" now tmp seen count
  now="$(date +%s)"
  tmp="${CATEGORIES_FILE}.$$"

  awk -F '\t' -v OFS='\t' -v now="$now" -v window="$VEXYL_WINDOW_SECONDS" '
    NF >= 4 && now - $4 <= window { print }
  ' "$CATEGORIES_FILE" >"$tmp" 2>/dev/null || true
  mv "$tmp" "$CATEGORIES_FILE"

  if awk -F '\t' -v ip="$ip" -v category="$category" '$1 == ip && $2 == category { found=1 } END { exit found ? 0 : 1 }' "$CATEGORIES_FILE"; then
    seen="seen"
    tmp="${CATEGORIES_FILE}.$$"
    awk -F '\t' -v OFS='\t' -v ip="$ip" -v category="$category" -v now="$now" '
      $1 == ip && $2 == category { print $1, $2, $3, now; next }
      { print }
    ' "$CATEGORIES_FILE" >"$tmp"
    mv "$tmp" "$CATEGORIES_FILE"
  else
    seen="new"
    printf '%s\t%s\t%s\t%s\n' "$ip" "$category" "$now" "$now" >>"$CATEGORIES_FILE"
  fi

  count="$(awk -F '\t' -v ip="$ip" '$1 == ip { categories[$2]=1 } END { for (category in categories) total++; print total + 0 }' "$CATEGORIES_FILE")"
  printf '%s\t%s' "$count" "$seen"
}

extract_ip_from_line() {
  local line="$1" ip=""

  case "$line" in
    *"Failed password"*|*"invalid user"*|*"Invalid user"*|*"authentication failure"*|*"Did not receive identification string"*|*"Connection closed by authenticating user"*|*"Unable to negotiate"*)
      ip="$(printf '%s\n' "$line" | sed -nE 's/.* from ([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)( port |$).*/\1/p' | head -n 1)"
      [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.* with ([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)( port |$).*/\1/p' | head -n 1)"
      [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*rhost=([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+).*/\1/p' | head -n 1)"
      ;;
  esac

  if [ -n "$ip" ] && valid_ip "$ip"; then
    printf '%s' "$ip"
  fi
}

reason_from_line() {
  local line="$1"
  case "$line" in
    *"Failed password"*) printf 'ssh_failed_password' ;;
    *"invalid user"*|*"Invalid user"*) printf 'ssh_invalid_user' ;;
    *"authentication failure"*) printf 'auth_failure' ;;
    *"Did not receive identification string"*) printf 'ssh_no_ident' ;;
    *"Connection closed by authenticating user"*) printf 'ssh_auth_closed' ;;
    *"Unable to negotiate"*) printf 'ssh_negotiation_failure' ;;
    *) printf 'auth_signal' ;;
  esac
}

process_line() {
  local line="$1" ip reason classification event_type category weight severity metadata proto dpt
  ip="$(extract_ip_from_line "$line")"
  if [ -n "$ip" ]; then
    reason="$(reason_from_line "$line")"
    score_ip "$ip" "$reason" 1 "ssh_auth_attack" "medium"
    return 0
  fi

  classification="$(classify_mail_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"mail"}' "$(json_escape "$category")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  classification="$(classify_firewall_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity proto dpt <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"kernel_firewall","protocol":"%s","destination_port":"%s"}' \
      "$(json_escape "$category")" \
      "$(json_escape "$proto")" \
      "$(json_escape "$dpt")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  classification="$(classify_vpn_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"vpn"}' "$(json_escape "$category")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  classification="$(classify_database_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"database"}' "$(json_escape "$category")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  classification="$(classify_object_storage_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"object_storage"}' "$(json_escape "$category")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  classification="$(classify_edge_line "$line")" || classification=""
  if [ -n "$classification" ]; then
    IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
    metadata=$(printf '{"category":"%s","source":"edge"}' "$(json_escape "$category")")
    score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"
    return 0
  fi

  process_web_line "$line"
}

extract_bracket_ip() {
  local line="$1" ip
  ip="$(printf '%s\n' "$line" | sed -nE 's/.*\[([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)\].*/\1/p' | head -n 1)"
  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

extract_src_ip() {
  local line="$1" ip
  ip="$(printf '%s\n' "$line" | sed -nE 's/.*SRC=([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+).*/\1/p' | head -n 1)"
  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

extract_firewall_token() {
  local line="$1" token="$2"
  printf '%s\n' "$line" | sed -nE "s/.*(^|[[:space:]])$token=([^[:space:]]+).*/\\2/p" | head -n 1
}

classify_mail_line() {
  local line="$1" lower ip
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *"postfix/"*|*"postscreen"*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_bracket_ip "$line")"
  [ -n "$ip" ] || return 1

  case "$lower" in
    *"sasl"*authentication\ failed*|*"sasl"*login\ authentication\ failed*|*"sasl"*plain\ authentication\ failed*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "mail_auth_attack" "smtp_sasl_auth_failed" "mail_auth" "5" "medium"
      return 0
      ;;
    *"relay access denied"*|*"client host rejected: access denied"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "mail_relay_probe" "smtp_relay_denied" "mail_relay" "4" "medium"
      return 0
      ;;
    *"pregreet"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "mail_protocol_probe" "smtp_pregreet" "mail_protocol" "3" "medium"
      return 0
      ;;
    *"dnsbl rank"*|*"blocked using"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "mail_reputation_signal" "smtp_dnsbl_source" "mail_reputation" "3" "medium"
      return 0
      ;;
  esac

  return 1
}

classify_firewall_line() {
  local line="$1" lower ip proto dpt reason category weight severity
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *"src="*) ;;
    *) return 1 ;;
  esac
  case "$lower" in
    *"block"*|*"drop"*|*"deny"*|*"reject"*|*"ufw block"*|*"firewall"*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_src_ip "$line")"
  [ -n "$ip" ] || return 1
  proto="$(extract_firewall_token "$line" "PROTO")"
  dpt="$(extract_firewall_token "$line" "DPT")"
  proto="${proto:-unknown}"
  dpt="${dpt:-0}"
  reason="kernel_firewall_drop"
  category="firewall_drop"
  weight="1"
  severity="low"

  case "$dpt" in
    22|2222)
      reason="firewall_ssh_probe"
      category="firewall_ssh"
      weight="2"
      severity="medium"
      ;;
    25|465|587)
      reason="firewall_mail_probe"
      category="firewall_mail"
      weight="2"
      severity="medium"
      ;;
    80|443|8080|8443)
      reason="firewall_web_probe"
      category="firewall_web"
      weight="2"
      severity="medium"
      ;;
    23|2323|3389|5900|6379|9200|11211)
      reason="firewall_exposed_service_probe"
      category="firewall_exposed_service"
      weight="3"
      severity="medium"
      ;;
    0)
      case "$proto" in
        ICMP|icmp|IPv6-ICMP|ipv6-icmp)
          reason="firewall_icmp_probe"
          category="firewall_icmp"
          ;;
      esac
      ;;
  esac

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$ip" "firewall_drop" "$reason" "$category" "$weight" "$severity" "$proto" "$dpt"
}

extract_vpn_ip() {
  local line="$1" ip

  ip="$(printf '%s\n' "$line" | sed -nE 's/.*\[AF_INET6?\]([0-9]{1,3}(\.[0-9]{1,3}){3})(:|\]).*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.* from \[?([0-9]{1,3}(\.[0-9]{1,3}){3})\]?(\[[0-9]+\]|:[0-9]+| port |$).*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.* for ([0-9]{1,3}(\.[0-9]{1,3}){3})[.][.][.]([0-9]{1,3}(\.[0-9]{1,3}){3}).*/\3/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*(^|[[:space:]])([0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]+([[:space:]]|$).*/\2/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*\(([0-9]{1,3}(\.[0-9]{1,3}){3})\).*/\1/p' | head -n 1)"

  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

classify_vpn_line() {
  local line="$1" lower ip
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *openvpn*|*"tls error"*|*auth_failed*|*charon*|*strongswan*|*wireguard*|*wg[0-9]:*|*ipsec*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_vpn_ip "$line")"
  [ -n "$ip" ] || return 1

  case "$lower" in
    *auth_failed*|*"auth: received control message: auth_failed"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_auth_attack" "openvpn_auth_failed" "vpn_auth" "5" "medium"
      return 0
      ;;
    *"incoming packet authentication failed"*|*"authenticate/decrypt packet error"*|*"bad packet id"*|*"replay-window backtrack"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_packet_probe" "openvpn_packet_auth_failed" "vpn_packet" "3" "medium"
      return 0
      ;;
    *"tls error"*key\ negotiation*|*"tls error"*handshake\ failed*|*"tls handshake failed"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_tls_probe" "openvpn_tls_negotiation_failed" "vpn_tls" "3" "medium"
      return 0
      ;;
    *"verify error"*|*"certificate verify failed"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_certificate_probe" "openvpn_certificate_rejected" "vpn_cert" "4" "medium"
      return 0
      ;;
    *no\ ike\ config\ found*|*no_proposal_chosen*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_ike_probe" "ipsec_no_ike_config" "vpn_ike" "3" "medium"
      return 0
      ;;
    *authentication\ of*failed*|*eap*failed*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_auth_attack" "ipsec_auth_failed" "vpn_auth" "5" "medium"
      return 0
      ;;
    *invalid*payload*|*invalid*ike*|*message*invalid*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_ike_probe" "ipsec_invalid_payload" "vpn_ike" "3" "medium"
      return 0
      ;;
    *invalid\ handshake\ initiation*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "vpn_handshake_probe" "wireguard_invalid_handshake" "vpn_handshake" "3" "medium"
      return 0
      ;;
  esac

  return 1
}

extract_database_ip() {
  local line="$1" ip

  ip="$(printf '%s\n' "$line" | sed -nE 's/.*client=([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+).*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*host "([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)".*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE "s/.*@'([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)'.*/\\1/p" | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE "s/.*Host '([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)'.*/\\1/p" | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*"remote"[[:space:]]*:[[:space:]]*"\[?([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)\]?:[0-9]+".*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.* from client ([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+):[0-9]+.*/\1/p' | head -n 1)"

  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

classify_database_line() {
  local line="$1" lower ip
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *postgres*|*postgresql*|*mysqld*|*mysql*|*mariadb*|*mongodb*|*mongod*|*"access denied for user"*|*"no pg_hba.conf entry"*|*"password authentication failed for user"*|*"authentication failed"*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_database_ip "$line")"
  [ -n "$ip" ] || return 1

  case "$lower" in
    *"password authentication failed for user"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "db_auth_attack" "postgres_password_auth_failed" "db_postgres_auth" "5" "medium"
      return 0
      ;;
    *"no pg_hba.conf entry for host"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "db_access_probe" "postgres_no_hba_entry" "db_postgres_access" "4" "medium"
      return 0
      ;;
    *"access denied for user"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "db_auth_attack" "mysql_access_denied" "db_mysql_auth" "5" "medium"
      return 0
      ;;
    *"is not allowed to connect to this mysql server"*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "db_access_probe" "mysql_host_not_allowed" "db_mysql_access" "4" "medium"
      return 0
      ;;
    *mongodb*authentication\ failed*|*mongod*authentication\ failed*|*"\"msg\":\"authentication failed\""*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "db_auth_attack" "mongodb_auth_failed" "db_mongodb_auth" "5" "medium"
      return 0
      ;;
  esac

  return 1
}

extract_object_storage_ip() {
  local line="$1" ip

  ip="$(json_line_field "$line" remotehost remoteHost remote_host sourceIPAddress sourceIp source_ip clientIP client_ip requesterIp requester_ip || true)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.*\][[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)[[:space:]].*/\1/p' | head -n 1)"
  [ -n "$ip" ] || ip="$(printf '%s\n' "$line" | sed -nE 's/.* from ([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]+)( port |:[0-9]+|$).*/\1/p' | head -n 1)"

  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

classify_object_storage_line() {
  local line="$1" lower ip status_code
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *minio*|*s3*|*"eventsource":"s3.amazonaws.com"*|*"remotehost"*|*"sourceipaddress"*|*rest.get.*|*rest.put.*|*rest.head.*|*rest.delete.*|*accessdenied*|*signaturedoesnotmatch*|*invalidaccesskeyid*|*nosuchbucket*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_object_storage_ip "$line")"
  [ -n "$ip" ] || return 1
  status_code="$(json_line_field "$line" statusCode status_code httpStatus http_status || true)"

  case "$lower" in
    *signaturedoesnotmatch*|*invalidaccesskeyid*|*authorizationheadermalformed*|*requesttimeskewed*|*malformedsecurityheader*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_auth_probe" "object_storage_signature_or_key_rejected" "object_storage_auth" "5" "medium"
      return 0
      ;;
    *accessdenied*|*allaccessdisabled*|*invalidtoken*|*expiredtoken*|*accountproblem*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_access_probe" "object_storage_access_denied" "object_storage_access" "4" "medium"
      return 0
      ;;
    *nosuchbucket*|*bucketnotfound*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_bucket_probe" "object_storage_bucket_probe" "object_storage_bucket_enum" "3" "medium"
      return 0
      ;;
    *nosuchkey*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_key_probe" "object_storage_key_probe" "object_storage_key_enum" "2" "low"
      return 0
      ;;
    *methodnotallowed*|*notimplemented*)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_method_probe" "object_storage_method_probe" "object_storage_method" "2" "low"
      return 0
      ;;
  esac

  case "$status_code" in
    401|403)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "storage_access_probe" "object_storage_access_denied" "object_storage_access" "4" "medium"
      return 0
      ;;
  esac

  return 1
}

extract_edge_ip() {
  local line="$1" ip

  ip="$(json_line_field "$line" ClientIP clientIP client_ip clientIp ip sourceIP sourceIp source_ip cfConnectingIp cf_connecting_ip CFConnectingIP remote_addr remoteAddress || true)"
  [ -n "$ip" ] && valid_ip "$ip" && printf '%s' "$ip"
}

lower_value() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

classify_edge_line() {
  local line="$1" lower ip action bot_score status
  lower="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *cloudflare*|*rayid*|*edgewaf*|*wafaction*|*securityaction*|*edgeresponsestatus*|*originresponsestatus*|*botscore*|*clientrequesturi*) ;;
    *) return 1 ;;
  esac

  ip="$(extract_edge_ip "$line")"
  [ -n "$ip" ] || return 1

  action="$(json_line_field "$line" SecurityAction WAFAction Action EdgeSecurityAction ClientRequestWAFAction || true)"
  action="$(lower_value "$action")"
  bot_score="$(json_line_field "$line" BotScore botScore bot_score cfBotScore || true)"
  status="$(json_line_field "$line" EdgeResponseStatus edgeResponseStatus edge_response_status status status_code OriginResponseStatus originResponseStatus || true)"

  case "$action" in
    block|blocked|drop|deny|denied)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "edge_security_action" "edge_waf_block" "edge_waf" "4" "medium"
      return 0
      ;;
    challenge|jschallenge|js_challenge|managed_challenge|managedchallenge)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "edge_security_action" "edge_challenge_issued" "edge_challenge" "3" "medium"
      return 0
      ;;
    ratelimit|rate_limit|rate-limited|rate_limited)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "edge_rate_limit" "edge_rate_limit_triggered" "edge_rate_limit" "3" "medium"
      return 0
      ;;
  esac

  case "$bot_score" in
    ''|*[!0-9]*) ;;
    *)
      if [ "$bot_score" -le 10 ] 2>/dev/null; then
        printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "edge_bot_signal" "edge_low_bot_score" "edge_bot" "3" "medium"
        return 0
      fi
      ;;
  esac

  case "$status" in
    520|521|522|523|524)
      printf '%s\t%s\t%s\t%s\t%s\t%s' "$ip" "edge_origin_pressure" "edge_origin_error_pressure" "edge_origin_error" "2" "low"
      return 0
      ;;
  esac

  return 1
}

json_jq_enabled() {
  case "$VEXYL_JSON_USE_JQ" in
    false|False|FALSE|no|No|NO|0|off|Off|OFF) return 1 ;;
    *) command -v jq >/dev/null 2>&1 ;;
  esac
}

json_line_field() {
  local line="$1" key value
  shift
  for key in "$@"; do
    value="$(printf '%s\n' "$line" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/p" | head -n 1)"
    if [ -z "$value" ]; then
      value="$(printf '%s\n' "$line" | sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*([0-9]+).*/\\1/p" | head -n 1)"
    fi
    [ -n "$value" ] && {
      printf '%s' "$value"
      return 0
    }
  done
  return 1
}

parse_request_line() {
  local request="$1" method uri
  [ -n "$request" ] || return 1
  method="${request%% *}"
  uri="${request#* }"
  [ "$uri" != "$request" ] || return 1
  uri="${uri%% *}"
  [ -n "$method" ] && [ -n "$uri" ] || return 1
  printf '%s\t%s' "$method" "$uri"
}

extract_json_web_fields() {
  local line="$1" fields ip method uri status user_agent request parsed sep

  if json_jq_enabled; then
    sep=$'\037'
    fields="$(printf '%s\n' "$line" | jq -r '
      def objfield($obj; $key): if ($obj | type) == "object" then $obj[$key] else empty end;
      [
        (.remote_addr // .remoteAddress // .client_ip // .clientIp // .clientIP // .ClientIP // .cf_connecting_ip // .cfConnectingIp // .CFConnectingIP // .["CF-Connecting-IP"] // .ip // .remote_ip // .source_ip // .sourceIp // ""),
        (.request_method // .requestMethod // .http_method // .httpMethod // .ClientRequestMethod // .method // objfield(.request; "method") // objfield(objfield(.http; "request"); "method") // ""),
        (.request_uri // .requestUri // .uri // .path // .url // .ClientRequestURI // .request_path // .requestPath // objfield(.request; "uri") // objfield(objfield(.http; "request"); "uri") // ""),
        ((.status // .status_code // .statusCode // .response_status // .responseStatus // .EdgeResponseStatus // .http.status_code // "") | tostring),
        (.http_user_agent // .user_agent // .userAgent // .ua // .ClientRequestUserAgent // .request_user_agent // .requestUserAgent // objfield(.headers; "user-agent") // objfield(objfield(.request; "headers"); "user-agent") // .http.user_agent // ""),
        (.request // .request_line // .requestLine // "")
      ] | join("\u001f")
    ' 2>/dev/null)" || return 1
    IFS="$sep" read -r ip method uri status user_agent request <<<"$fields"
  else
    ip="$(json_line_field "$line" remote_addr remoteAddress client_ip clientIp clientIP ClientIP cf_connecting_ip cfConnectingIp CFConnectingIP CF-Connecting-IP ip remote_ip source_ip sourceIp || true)"
    method="$(json_line_field "$line" request_method requestMethod http_method httpMethod ClientRequestMethod method || true)"
    uri="$(json_line_field "$line" request_uri requestUri uri path url ClientRequestURI request_path requestPath || true)"
    status="$(json_line_field "$line" status status_code statusCode response_status responseStatus EdgeResponseStatus || true)"
    user_agent="$(json_line_field "$line" http_user_agent user_agent userAgent ua ClientRequestUserAgent request_user_agent requestUserAgent || true)"
    request="$(json_line_field "$line" request request_line requestLine || true)"
  fi

  valid_ip "$ip" || return 1
  if [ -z "$method" ] || [ -z "$uri" ]; then
    parsed="$(parse_request_line "$request")" || return 1
    IFS=$'\t' read -r method uri <<<"$parsed"
  fi
  [ -n "$method" ] && [ -n "$uri" ] || return 1

  printf '%s\t%s\t%s\t%s\t%s' "$ip" "$method" "$uri" "${status:-000}" "$user_agent"
}

extract_combined_web_fields() {
  local line="$1" ip request method uri status user_agent
  ip="$(printf '%s\n' "$line" | awk '{ print $1 }')"
  valid_ip "$ip" || return 1

  request="$(printf '%s\n' "$line" | sed -nE 's/^[^"]*"([^"]*)".*/\1/p')"
  [ -n "$request" ] || return 1
  method="${request%% *}"
  uri="${request#* }"
  uri="${uri%% *}"
  [ -n "$method" ] && [ -n "$uri" ] || return 1

  status="$(printf '%s\n' "$line" | sed -nE 's/^[^"]*"[^"]*" ([0-9]{3}).*/\1/p')"
  user_agent="$(printf '%s\n' "$line" | sed -nE 's/.*"([^"]*)"[[:space:]]*$/\1/p')"
  printf '%s\t%s\t%s\t%s\t%s' "$ip" "$method" "$uri" "${status:-000}" "$user_agent"
}

extract_web_fields() {
  local line="$1" trimmed
  trimmed="$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
  case "$trimmed" in
    \{*) extract_json_web_fields "$line" && return 0 ;;
  esac
  extract_combined_web_fields "$line"
}

classify_web_request() {
  local method="$1" uri="$2" status="$3" user_agent="$4" lower path trap
  lower="$(printf '%s %s' "$uri" "$user_agent" | tr '[:upper:]' '[:lower:]')"
  path="${uri%%\?*}"

  for trap in $VEXYL_DECEPTION_PATHS; do
    case "$path" in
      "$trap"|"$trap"/*)
        printf '%s\t%s\t%s\t%s\t%s' "deception_trip" "deception_path_touched" "deception" "8" "high"
        return 0
        ;;
    esac
  done

  case "$lower" in
    *"/.env"*|*"/.git"*|*"wp-config.php"*|*"config.php"*|*"config.json"*|*"secrets"*|*"id_rsa"*|*"docker-compose"*|*"kubeconfig"*|*"backup.zip"*|*"dump.sql"*)
      printf '%s\t%s\t%s\t%s\t%s' "exploit_probe" "secret_harvest_probe" "secret_harvest" "6" "high"
      return 0
      ;;
    *"%2e%2e"*|*"..%2f"*|*"%2f..%2f"*|*"../"*|*"/etc/passwd"*|*"/proc/self/environ"*|*"jndi:ldap"*|*"union%20select"*|*"select%20"*|*"cmd="*|*"exec="*|*"powershell"*|*";wget"*|*";curl"*|*"base64,"*)
      printf '%s\t%s\t%s\t%s\t%s' "exploit_probe" "payload_exploit_probe" "exploit_payload" "7" "high"
      return 0
      ;;
    *"ignore%20previous"*|*"ignore previous"*|*"system%20prompt"*|*"system prompt"*|*"developer%20message"*|*"developer message"*|*"reveal%20your%20instructions"*|*"reveal your instructions"*|*"prompt%20injection"*|*"prompt injection"*|*"jailbreak"*|*"act%20as%20"*|*"act as "*)
      printf '%s\t%s\t%s\t%s\t%s' "llm_app_probe" "prompt_injection_probe" "ai_app_attack" "6" "high"
      return 0
      ;;
    *"/wp-login.php"*|*"/xmlrpc.php"*|*"/wp-admin"*|*"/wordpress/"*|*"/wp-content/"*)
      printf '%s\t%s\t%s\t%s\t%s' "web_recon" "cms_wordpress_probe" "cms_probe" "4" "medium"
      return 0
      ;;
    *"/phpmyadmin"*|*"/adminer"*|*"/actuator"*|*"/server-status"*|*"/manager/html"*|*"/solr/admin"*|*"/debug"*|*"/swagger"*|*"/openapi.json"*|*"/graphql"*|*"/.well-known/security.txt"*)
      printf '%s\t%s\t%s\t%s\t%s' "web_recon" "tech_stack_enumeration" "tech_stack_enum" "3" "medium"
      return 0
      ;;
    *"/login"*|*"/signin"*|*"/admin"*|*"/user/login"*|*"/api/login"*)
      if [ "$status" = "401" ] || [ "$status" = "403" ] || [ "$status" = "429" ]; then
        printf '%s\t%s\t%s\t%s\t%s' "credential_attack" "web_credential_surface_probe" "credential_surface" "3" "medium"
        return 0
      fi
      ;;
    *"sqlmap"*|*"nikto"*|*"nuclei"*|*"acunetix"*|*"masscan"*|*"zgrab"*|*"python-requests"*|*"go-http-client"*|*"curl/"*|*"wget/"*)
      printf '%s\t%s\t%s\t%s\t%s' "web_recon" "scanner_user_agent" "scanner_identity" "2" "low"
      return 0
      ;;
  esac

  case "$status" in
    401|403|404)
      case "$path" in
        *".php"|*".asp"|*".aspx"|*".jsp"|*".cgi")
          printf '%s\t%s\t%s\t%s\t%s' "web_recon" "wordlist_probe" "wordlist_scanning" "2" "low"
          return 0
          ;;
      esac
      ;;
  esac

  return 1
}

process_web_line() {
  local line="$1" fields ip method uri status user_agent classification event_type reason category weight severity metadata category_result category_count category_state
  local safe_uri safe_user_agent ai_result ai_score ai_action ai_attack_ids ai_trust ai_rules ai_excerpt ai_metadata
  fields="$(extract_web_fields "$line")" || return 0
  IFS=$'\t' read -r ip method uri status user_agent <<<"$fields"
  is_allowlisted "$ip" && return 0

  classification="$(classify_web_request "$method" "$uri" "$status" "$user_agent")" || return 0
  IFS=$'\t' read -r event_type reason category weight severity <<<"$classification"
  safe_uri="$(printf '%s' "$uri" | redact_ai_signal_text)"
  safe_user_agent="$(printf '%s' "$user_agent" | redact_ai_signal_text)"
  metadata=$(printf '{"category":"%s","method":"%s","path":"%s","status":"%s","user_agent":"%s"}' \
    "$(json_escape "$category")" \
    "$(json_escape "$method")" \
    "$(json_escape "$safe_uri")" \
    "$(json_escape "$status")" \
    "$(json_escape "$safe_user_agent")")

  category_result="$(record_probe_category "$ip" "$category")"
  IFS=$'\t' read -r category_count category_state <<<"$category_result"

  score_ip "$ip" "$reason" "$weight" "$event_type" "$severity" "$metadata"

  if [ "$event_type" = "llm_app_probe" ] || [ "$category" = "ai_app_attack" ]; then
    ai_result="$(score_ai_web_event "$ip" "$method" "$uri" "$status" "$user_agent" "$category")" || ai_result=""
    if [ -n "$ai_result" ]; then
      IFS=$'\t' read -r ai_score ai_action ai_attack_ids ai_trust ai_rules ai_excerpt <<<"$ai_result"
      ai_metadata=$(printf '{"category":"ai_intel","web_category":"%s","ai_score":%s,"ai_action":"%s","matched_attack_ids":"%s","trust_level":"%s"}' \
        "$(json_escape "$category")" \
        "$(json_safe_number "$ai_score")" \
        "$(json_escape "$ai_action")" \
        "$(json_escape "$ai_attack_ids")" \
        "$(json_escape "$ai_trust")")
      if [ "$ai_score" -ge "$VEXYL_AI_INTEL_SIGNAL_SCORE" ] 2>/dev/null; then
        score_ip "$ip" "ai_intel_high_risk" "$VEXYL_AI_INTEL_SIGNAL_WEIGHT" "ai_intel_runtime_risk" "high" "$ai_metadata"
      fi
    fi
  fi

  if [ "$category_state" = "new" ] && [ "$category_count" -ge "$VEXYL_MUTATION_CATEGORY_THRESHOLD" ] 2>/dev/null; then
    metadata=$(printf '{"category":"mutation","unique_probe_categories":%s,"window_seconds":%s}' \
      "$category_count" \
      "$VEXYL_WINDOW_SECONDS")
    score_ip "$ip" "rapid_probe_mutation" "$VEXYL_MUTATION_WEIGHT" "ai_assisted_suspected" "high" "$metadata"
  fi
}

existing_auth_logs() {
  local file
  for file in $VEXYL_AUTH_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_web_logs() {
  local file
  for file in $VEXYL_WEB_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_mail_logs() {
  local file
  for file in $VEXYL_MAIL_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_firewall_logs() {
  local file
  for file in $VEXYL_FIREWALL_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_vpn_logs() {
  local file
  for file in $VEXYL_VPN_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_database_logs() {
  local file
  for file in $VEXYL_DATABASE_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_object_storage_logs() {
  local file
  for file in $VEXYL_OBJECT_STORAGE_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

existing_edge_logs() {
  local file
  for file in $VEXYL_EDGE_LOGS; do
    [ -r "$file" ] && printf '%s\n' "$file"
  done
}

run_once() {
  local file found=0
  while IFS= read -r file; do
    found=1
    log info "evaluating recent lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_auth_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent web lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_web_line "$line"
    done
  done < <(existing_web_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent mail lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_mail_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent firewall lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_firewall_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent VPN lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_vpn_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent database lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_database_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent object storage lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_object_storage_logs)

  while IFS= read -r file; do
    found=1
    log info "evaluating recent edge lines from $file"
    tail -n "$VEXYL_BOOTSTRAP_LINES" "$file" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  done < <(existing_edge_logs)

  if [ "$found" -eq 0 ] && command -v journalctl >/dev/null 2>&1; then
    log info "no readable auth logs found; evaluating recent ssh journal entries"
    journalctl -u ssh -u sshd -n "$VEXYL_BOOTSTRAP_LINES" --no-pager 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
    done
  fi
}

policy_bundle_secret_configured() {
  [ -n "$VEXYL_POLICY_SIGNING_SECRET" ]
}

policy_kid_safe() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

policy_key_revoked() {
  local kid="$1" entry line
  for entry in $VEXYL_POLICY_REVOKED_KEY_IDS; do
    [ "$entry" = "$kid" ] && return 0
  done

  [ -r "$VEXYL_POLICY_REVOKED_KEYS_FILE" ] || return 1
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [ -n "$line" ] || continue
    [ "$line" = "$kid" ] && return 0
  done <"$VEXYL_POLICY_REVOKED_KEYS_FILE"

  return 1
}

policy_public_key_count() {
  local count=0 key
  if [ -n "$VEXYL_POLICY_PUBLIC_KEY_DIR" ] && [ -d "$VEXYL_POLICY_PUBLIC_KEY_DIR" ]; then
    for key in "$VEXYL_POLICY_PUBLIC_KEY_DIR"/*.pem; do
      [ -r "$key" ] || continue
      count=$((count + 1))
    done
  fi

  if [ "$count" -eq 0 ] && [ -n "$VEXYL_POLICY_PUBLIC_KEY_FILE" ] && [ -r "$VEXYL_POLICY_PUBLIC_KEY_FILE" ]; then
    count=1
  fi
  printf '%s' "$count"
}

policy_revoked_key_count() {
  local count=0 entry line
  for entry in $VEXYL_POLICY_REVOKED_KEY_IDS; do
    [ -n "$entry" ] || continue
    count=$((count + 1))
  done

  [ -r "$VEXYL_POLICY_REVOKED_KEYS_FILE" ] || {
    printf '%s' "$count"
    return 0
  }
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [ -n "$line" ] || continue
    count=$((count + 1))
  done <"$VEXYL_POLICY_REVOKED_KEYS_FILE"
  printf '%s' "$count"
}

policy_bundle_public_key_configured() {
  [ "$(policy_public_key_count)" -gt 0 ] 2>/dev/null
}

policy_bundle_verifier_configured() {
  policy_bundle_public_key_configured || policy_bundle_secret_configured
}

policy_bundle_disabled() {
  case "$VEXYL_POLICY_BUNDLE_ENABLED" in
    false|False|FALSE|no|No|NO|0|off|Off|OFF) return 0 ;;
    *) return 1 ;;
  esac
}

policy_bundle_required_without_verifier() {
  case "$VEXYL_POLICY_BUNDLE_ENABLED" in
    true|True|TRUE|yes|Yes|YES|1|on|On|ON) return 0 ;;
    *) return 1 ;;
  esac
}

json_string_field() {
  local file="$1" field="$2"
  sed -nE "s/.*\"$field\":\"([^\"]*)\".*/\\1/p" "$file" 2>/dev/null | head -n 1
}

json_bool_field() {
  local file="$1" field="$2"
  sed -nE "s/.*\"$field\":(true|false).*/\\1/p" "$file" 2>/dev/null | head -n 1
}

truthy() {
  case "$1" in
    true|True|TRUE|yes|Yes|YES|1|on|On|ON) return 0 ;;
    *) return 1 ;;
  esac
}

version_core() {
  local version="${1#v}"
  version="${version%%+*}"
  version="${version%%-*}"
  printf '%s' "$version"
}

version_part() {
  local version="$1" position="$2" major minor patch extra
  version="$(version_core "$version")"
  IFS=. read -r major minor patch extra <<EOF
$version
EOF
  [ -z "${extra:-}" ] || return 1
  case "$position" in
    1) printf '%s' "${major:-0}" ;;
    2) printf '%s' "${minor:-0}" ;;
    3) printf '%s' "${patch:-0}" ;;
    *) return 1 ;;
  esac
}

version_compare() {
  local left="$1" right="$2" index left_part right_part
  for index in 1 2 3; do
    left_part="$(version_part "$left" "$index")" || return 1
    right_part="$(version_part "$right" "$index")" || return 1
    case "$left_part" in ''|*[!0-9]*) return 1 ;; esac
    case "$right_part" in ''|*[!0-9]*) return 1 ;; esac
    left_part=$((10#$left_part))
    right_part=$((10#$right_part))
    if [ "$left_part" -lt "$right_part" ]; then
      printf '%s' "-1"
      return 0
    fi
    if [ "$left_part" -gt "$right_part" ]; then
      printf '%s' "1"
      return 0
    fi
  done
  printf '%s' "0"
}

policy_number_field() {
  local file="$1" field="$2"
  if command -v jq >/dev/null 2>&1; then
    jq -r ".policy.$field // empty" "$file" 2>/dev/null
    return 0
  fi
  sed -nE "s/.*\"$field\":([0-9]+).*/\\1/p" "$file" 2>/dev/null | head -n 1
}

policy_deny_ips() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.policy.deny_ips[]?' "$file" 2>/dev/null
    return 0
  fi
  sed -nE 's/.*"deny_ips":\[([^]]*)\].*/\1/p' "$file" 2>/dev/null |
    tr ',' '\n' |
    sed -E 's/^"//; s/"$//; s/\\"/"/g'
}

base64url_decode() {
  local input="$1" value remainder
  value="$(printf '%s' "$input" | tr '_-' '/+')"
  remainder=$((${#value} % 4))
  case "$remainder" in
    0) ;;
    2) value="${value}==" ;;
    3) value="${value}=" ;;
    *) return 1 ;;
  esac

  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$value" | base64 -d 2>/dev/null && return 0
  fi
  printf '%s' "$value" | openssl base64 -d -A 2>/dev/null
}

hmac_sha256_base64url() {
  local secret="$1" message="$2" value
  value="$(printf '%s' "$message" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | openssl base64 -A 2>/dev/null)" || return 1
  [ -n "$value" ] || return 1
  printf '%s' "$value" | tr '+/' '-_' | tr -d '='
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

manifest_hash() {
  local manifest_file="$1" entry_path="$2"
  awk -v path="$entry_path" '$2 == path { print $1; exit }' "$manifest_file" 2>/dev/null
}

release_public_key_file() {
  if [ -n "$VEXYL_RELEASE_PUBLIC_KEY_FILE" ] && [ -r "$VEXYL_RELEASE_PUBLIC_KEY_FILE" ]; then
    printf '%s' "$VEXYL_RELEASE_PUBLIC_KEY_FILE"
    return 0
  fi
  log error "release public key is not readable: ${VEXYL_RELEASE_PUBLIC_KEY_FILE:-missing}"
  return 1
}

fetch_verified_manifest_entry() {
  local base_url="$1" manifest_file="$2" entry_path="$3" output_path="$4"
  local expected_hash actual_hash

  expected_hash="$(manifest_hash "$manifest_file" "$entry_path")"
  [ -n "$expected_hash" ] || {
    log error "release manifest missing $entry_path"
    return 1
  }

  curl -fsSL "$base_url/$entry_path" -o "$output_path" 2>/dev/null || {
    log error "failed to download $entry_path"
    return 1
  }
  actual_hash="$(sha256sum "$output_path" 2>/dev/null | awk '{ print $1 }')"
  [ "$expected_hash" = "$actual_hash" ] || {
    log error "release checksum verification failed for $entry_path"
    return 1
  }
}

release_upgrade_action() {
  local release_file="$1" release_version min_upgrade_from rollback_allowed compare min_compare
  RELEASE_UPGRADE_ACTION=""
  release_version="$(json_string_field "$release_file" "version")"
  min_upgrade_from="$(json_string_field "$release_file" "min_upgrade_from")"
  rollback_allowed="$(json_bool_field "$release_file" "rollback_allowed")"

  [ -n "$release_version" ] || {
    log error "release metadata missing version"
    return 1
  }
  compare="$(version_compare "$release_version" "$VERSION")" || {
    log error "release metadata has invalid version: $release_version"
    return 1
  }

  if [ -n "$min_upgrade_from" ]; then
    min_compare="$(version_compare "$VERSION" "$min_upgrade_from")" || {
      log error "release metadata has invalid min_upgrade_from: $min_upgrade_from"
      return 1
    }
    if [ "$min_compare" -lt 0 ]; then
      log error "release $release_version requires agent >= $min_upgrade_from; current is $VERSION"
      return 1
    fi
  fi

  if [ "$compare" -lt 0 ]; then
    if [ "$rollback_allowed" = "true" ] && truthy "$VEXYL_UPGRADE_ALLOW_DOWNGRADE"; then
      RELEASE_UPGRADE_ACTION="install"
      return 0
    fi
    log error "release $release_version is older than current agent $VERSION; downgrade refused"
    return 1
  fi

  if [ "$compare" -eq 0 ] && [ -e "$VEXYL_AGENT_BIN" ] && ! truthy "$VEXYL_UPGRADE_FORCE"; then
    RELEASE_UPGRADE_ACTION="skip"
    return 0
  fi

  RELEASE_UPGRADE_ACTION="install"
}

policy_public_key_for_kid() {
  local kid="$1" candidate
  [ -n "$kid" ] || {
    log error "policy bundle missing key id"
    return 1
  }
  policy_kid_safe "$kid" || {
    log error "unsafe policy key id: $kid"
    return 1
  }
  policy_key_revoked "$kid" && {
    log error "policy key id is revoked: $kid"
    return 1
  }

  if [ -n "$VEXYL_POLICY_PUBLIC_KEY_DIR" ]; then
    candidate="$VEXYL_POLICY_PUBLIC_KEY_DIR/$kid.pem"
    if [ -r "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  fi

  if [ -n "$VEXYL_POLICY_PUBLIC_KEY_FILE" ] && [ -r "$VEXYL_POLICY_PUBLIC_KEY_FILE" ] &&
     [ -n "$VEXYL_POLICY_KEY_ID" ] && [ "$kid" = "$VEXYL_POLICY_KEY_ID" ]; then
    printf '%s' "$VEXYL_POLICY_PUBLIC_KEY_FILE"
    return 0
  fi

  log error "no trusted policy public key for id: $kid"
  return 1
}

verify_rs256_signature() {
  local message="$1" signature="$2" kid="$3" public_key tmp_signature tmp_message
  public_key="$(policy_public_key_for_kid "$kid")" || return 1

  tmp_signature="${POLICY_BUNDLE_FILE}.sig.$$"
  tmp_message="${POLICY_BUNDLE_FILE}.msg.$$"
  printf '%s' "$message" >"$tmp_message" || {
    rm -f "$tmp_signature" "$tmp_message"
    log error "failed to prepare policy signature verification"
    return 1
  }
  base64url_decode "$signature" >"$tmp_signature" || {
    rm -f "$tmp_signature" "$tmp_message"
    log error "failed to decode policy signature"
    return 1
  }

  if openssl dgst -sha256 -verify "$public_key" -signature "$tmp_signature" "$tmp_message" >/dev/null 2>&1; then
    rm -f "$tmp_signature" "$tmp_message"
    return 0
  fi

  rm -f "$tmp_signature" "$tmp_message"
  log error "policy signature verification failed"
  return 1
}

apply_policy_int() {
  local name="$1" value="$2" min="$3" max="$4"
  case "$value" in
    ''|*[!0-9]*) return 0 ;;
  esac
  [ "$value" -ge "$min" ] 2>/dev/null && [ "$value" -le "$max" ] 2>/dev/null || return 0

  case "$name" in
    threshold) VEXYL_THRESHOLD="$value" ;;
    window_seconds) VEXYL_WINDOW_SECONDS="$value" ;;
    block_seconds) VEXYL_BLOCK_SECONDS="$value" ;;
    sync_after_seconds) VEXYL_POLICY_SYNC_SECONDS="$value" ;;
    mutation_category_threshold) VEXYL_MUTATION_CATEGORY_THRESHOLD="$value" ;;
    mutation_weight) VEXYL_MUTATION_WEIGHT="$value" ;;
  esac
}

apply_policy_payload() {
  local payload_file="$1" ip count=0

  apply_policy_int threshold "$(policy_number_field "$payload_file" "score_threshold")" 1 100
  apply_policy_int window_seconds "$(policy_number_field "$payload_file" "window_seconds")" 60 86400
  apply_policy_int block_seconds "$(policy_number_field "$payload_file" "block_seconds")" 60 31536000
  apply_policy_int sync_after_seconds "$(policy_number_field "$payload_file" "sync_after_seconds")" 60 3600
  apply_policy_int mutation_category_threshold "$(policy_number_field "$payload_file" "mutation_category_threshold")" 2 20
  apply_policy_int mutation_weight "$(policy_number_field "$payload_file" "mutation_weight")" 1 50

  while IFS= read -r ip; do
    ip="${ip%%#*}"
    ip="${ip//[[:space:]]/}"
    [ -n "$ip" ] || continue
    valid_ip "$ip" || continue
    block_ip "$ip" "signed_policy"
    count=$((count + 1))
  done < <(policy_deny_ips "$payload_file")

  log info "applied signed policy bundle deny_ips=$count threshold=$VEXYL_THRESHOLD block_seconds=$VEXYL_BLOCK_SECONDS sync_seconds=$VEXYL_POLICY_SYNC_SECONDS"
}

verify_policy_bundle_file() {
  local bundle_file="$1" alg kid payload_b64 signature expected tmp_payload expires expires_epoch now
  [ -r "$bundle_file" ] || {
    log error "policy bundle file is not readable: $bundle_file"
    return 1
  }
  command -v openssl >/dev/null 2>&1 || {
    log error "openssl is required for signed policy verification"
    return 1
  }

  alg="$(json_string_field "$bundle_file" "alg")"
  kid="$(json_string_field "$bundle_file" "kid")"
  payload_b64="$(json_string_field "$bundle_file" "payload_b64")"
  signature="$(json_string_field "$bundle_file" "signature")"

  [ -n "$payload_b64" ] || {
    log error "policy bundle missing payload"
    return 1
  }
  [ -n "$signature" ] || {
    log error "policy bundle missing signature"
    return 1
  }
  [ -n "$kid" ] || {
    log error "policy bundle missing key id"
    return 1
  }
  policy_kid_safe "$kid" || {
    log error "unsafe policy key id: $kid"
    return 1
  }
  policy_key_revoked "$kid" && {
    log error "policy key id is revoked: $kid"
    return 1
  }

  case "$alg" in
    RS256)
      verify_rs256_signature "$payload_b64" "$signature" "$kid" || return 1
      ;;
    HS256)
      if [ -n "$VEXYL_POLICY_KEY_ID" ] && [ "$kid" != "$VEXYL_POLICY_KEY_ID" ]; then
        log error "policy bundle key id mismatch: $kid"
        return 1
      fi
      policy_bundle_secret_configured || {
        log error "VEXYL_POLICY_SIGNING_SECRET is required for HS256 policy verification"
        return 1
      }
      expected="$(hmac_sha256_base64url "$VEXYL_POLICY_SIGNING_SECRET" "$payload_b64")" || {
        log error "failed to compute policy signature"
        return 1
      }
      [ "$expected" = "$signature" ] || {
        log error "policy signature verification failed"
        return 1
      }
      ;;
    *)
      log error "unsupported policy signature algorithm: ${alg:-missing}"
      return 1
      ;;
  esac

  tmp_payload="${POLICY_PAYLOAD_FILE}.$$"
  base64url_decode "$payload_b64" >"$tmp_payload" || {
    rm -f "$tmp_payload"
    log error "failed to decode policy payload"
    return 1
  }

  expires="$(json_string_field "$tmp_payload" "expires_at")"
  expires_epoch="$(date -u -d "$expires" +%s 2>/dev/null || true)"
  now="$(date -u +%s)"
  if [ -z "$expires_epoch" ] || [ "$expires_epoch" -le "$now" ] 2>/dev/null; then
    rm -f "$tmp_payload"
    log error "policy bundle expired or has invalid expiry"
    return 1
  fi

  apply_policy_payload "$tmp_payload"
  mv "$tmp_payload" "$POLICY_PAYLOAD_FILE"
  chmod 0600 "$POLICY_PAYLOAD_FILE" 2>/dev/null || true
  if [ "$bundle_file" != "$POLICY_BUNDLE_FILE" ]; then
    cp "$bundle_file" "$POLICY_BUNDLE_FILE" 2>/dev/null || true
    chmod 0600 "$POLICY_BUNDLE_FILE" 2>/dev/null || true
  fi
}

sync_signed_policy_bundle() {
  [ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0
  command -v openssl >/dev/null 2>&1 || {
    log warn "openssl is required for signed policy bundles"
    return 1
  }

  local url tmp_bundle
  url="${VEXYL_API_URL%/}/v1/policy.bundle.json"
  tmp_bundle="${POLICY_BUNDLE_FILE}.$$"
  curl -fsS --connect-timeout 2 --max-time 8 \
    -H "Authorization: Bearer $VEXYL_API_TOKEN" "$url" -o "$tmp_bundle" 2>/dev/null || {
      rm -f "$tmp_bundle"
      return 1
    }

  if verify_policy_bundle_file "$tmp_bundle"; then
    rm -f "$tmp_bundle"
    return 0
  fi
  rm -f "$tmp_bundle"
  return 1
}

sync_legacy_deny_policy() {
  [ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] || return 0
  command -v curl >/dev/null 2>&1 || return 0

  local url
  url="${VEXYL_API_URL%/}/v1/denylist.txt"
  curl -fsS --connect-timeout 2 --max-time 8 \
    -H "Authorization: Bearer $VEXYL_API_TOKEN" "$url" 2>/dev/null |
    while IFS= read -r ip; do
      ip="${ip%%#*}"
      ip="${ip//[[:space:]]/}"
      [ -n "$ip" ] || continue
      valid_ip "$ip" || continue
      block_ip "$ip" "cloud_policy"
    done
}

sync_policy() {
  if policy_bundle_disabled; then
    sync_legacy_deny_policy
    return 0
  fi

  if policy_bundle_verifier_configured; then
    sync_signed_policy_bundle || log warn "signed policy bundle sync failed; keeping existing local policy"
    return 0
  fi

  if policy_bundle_required_without_verifier; then
    log warn "signed policy bundle is enabled but no verifier is configured; refusing unsigned policy"
    return 0
  fi

  sync_legacy_deny_policy
}

daemon() {
  local logs auth_logs web_logs mail_logs firewall_logs vpn_logs database_logs object_storage_logs edge_logs last_sync now heartbeat_pid
  ensure_state
  sync_policy
  send_heartbeat
  heartbeat_loop &
  heartbeat_pid="$!"
  trap 'kill "$heartbeat_pid" 2>/dev/null || true' EXIT INT TERM
  last_sync="$(date +%s)"

  mapfile -t auth_logs < <(existing_auth_logs)
  mapfile -t web_logs < <(existing_web_logs)
  mapfile -t mail_logs < <(existing_mail_logs)
  mapfile -t firewall_logs < <(existing_firewall_logs)
  mapfile -t vpn_logs < <(existing_vpn_logs)
  mapfile -t database_logs < <(existing_database_logs)
  mapfile -t object_storage_logs < <(existing_object_storage_logs)
  mapfile -t edge_logs < <(existing_edge_logs)
  logs=("${auth_logs[@]}" "${web_logs[@]}" "${mail_logs[@]}" "${firewall_logs[@]}" "${vpn_logs[@]}" "${database_logs[@]}" "${object_storage_logs[@]}" "${edge_logs[@]}")
  if [ "${#logs[@]}" -gt 0 ]; then
    log info "following logs: ${logs[*]}"
    tail -n 0 -F "${logs[@]}" 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
      now="$(date +%s)"
      if [ $((now - last_sync)) -ge "$VEXYL_POLICY_SYNC_SECONDS" ] 2>/dev/null; then
        sync_policy
        expire_iptables_blocks
        last_sync="$now"
      fi
    done
  elif command -v journalctl >/dev/null 2>&1; then
    log info "following ssh journal entries"
    journalctl -f -u ssh -u sshd -n 0 2>/dev/null | while IFS= read -r line; do
      process_line "$line"
      now="$(date +%s)"
      if [ $((now - last_sync)) -ge "$VEXYL_POLICY_SYNC_SECONDS" ] 2>/dev/null; then
        sync_policy
        expire_iptables_blocks
        last_sync="$now"
      fi
    done
  else
    die "no readable auth logs and journalctl is unavailable"
  fi
}

status() {
  local backend blocked scores categories ai_decisions ai_status policy_mode policy_payload trusted_keys revoked_keys release_key release_version
  backend="$(detect_firewall)"
  blocked="$(awk 'END { print NR + 0 }' "$BLOCKS_FILE" 2>/dev/null || printf 0)"
  scores="$(awk 'END { print NR + 0 }' "$SCORES_FILE" 2>/dev/null || printf 0)"
  categories="$(awk 'END { print NR + 0 }' "$CATEGORIES_FILE" 2>/dev/null || printf 0)"
  ai_decisions="$(awk 'END { print NR + 0 }' "$AI_DECISIONS_FILE" 2>/dev/null || printf 0)"
  ai_status="$(ai_intel_status)"
  trusted_keys="$(policy_public_key_count)"
  revoked_keys="$(policy_revoked_key_count)"
  release_key="$([ -r "$VEXYL_RELEASE_PUBLIC_KEY_FILE" ] && printf yes || printf no)"
  release_version="$(json_string_field "$RELEASE_STATE_FILE" "version")"
  [ -n "$release_version" ] || release_version="$VERSION"
  if policy_bundle_disabled; then
    policy_mode="legacy"
  elif policy_bundle_public_key_configured; then
    policy_mode="signed-rs256"
  elif policy_bundle_secret_configured; then
    policy_mode="signed-hs256"
  elif policy_bundle_required_without_verifier; then
    policy_mode="missing_verifier"
  else
    policy_mode="legacy_auto"
  fi
  policy_payload="$([ -s "$POLICY_PAYLOAD_FILE" ] && printf yes || printf no)"
  cat <<EOF
Vexyl Guard $VERSION
mode: $VEXYL_MODE
firewall: $backend
state_dir: $VEXYL_STATE_DIR
tracked_scores: $scores
tracked_probe_categories: $categories
tracked_blocks: $blocked
ai_intel: $ai_status
ai_intel_db: $VEXYL_AI_INTEL_DB
tracked_ai_decisions: $ai_decisions
api_configured: $([ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] && printf yes || printf no)
policy_mode: $policy_mode
signed_policy_applied: $policy_payload
trusted_policy_keys: $trusted_keys
revoked_policy_keys: $revoked_keys
release_key_configured: $release_key
release_version: $release_version
EOF
}

VALIDATION_ERRORS=0
VALIDATION_WARNINGS=0
VALIDATION_CHECKS=0

validation_emit() {
  local level="$1"
  shift
  VALIDATION_CHECKS=$((VALIDATION_CHECKS + 1))
  case "$level" in
    error) VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1)) ;;
    warning) VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1)) ;;
  esac
  printf '%-7s %s\n' "[$level]" "$*"
}

validate_integer_setting() {
  local name="$1" value="$2" minimum="$3" maximum="$4" number
  [[ "$value" =~ ^[0-9]{1,10}$ ]] || {
    validation_emit error "$name must be an integer between $minimum and $maximum."
    return
  }
  number="$((10#$value))"
  if [ "$number" -lt "$minimum" ] || [ "$number" -gt "$maximum" ]; then
    validation_emit error "$name must be between $minimum and $maximum."
  else
    validation_emit ok "$name is within its supported range."
  fi
}

validate_allowlist() {
  local entry network prefix prefix_number index=0
  local -a entries=()
  read -r -a entries <<<"$VEXYL_ALLOWLIST"
  if [ "${#entries[@]}" -eq 0 ]; then
    validation_emit warning "The allowlist is empty; confirm operator access before enforcement."
    return
  fi

  for entry in "${entries[@]}"; do
    index=$((index + 1))
    if [[ "$entry" == */* ]]; then
      network="${entry%/*}"
      prefix="${entry##*/}"
      if [[ "$network" == */* ]] || ! cidr_contains "$network" "$entry"; then
        validation_emit error "Allowlist entry $index is not a valid IPv4 or IPv6 CIDR."
        continue
      fi
      prefix_number="$((10#$prefix))"
      if [ "$prefix_number" -eq 0 ]; then
        validation_emit error "Allowlist entry $index covers an entire address family and disables protection for it."
      elif { is_ipv4 "$network" && [ "$prefix_number" -lt 8 ]; } || { is_ipv6 "$network" && [ "$prefix_number" -lt 16 ]; }; then
        validation_emit warning "Allowlist entry $index covers an unusually broad network."
      else
        validation_emit ok "Allowlist entry $index is valid."
      fi
    elif valid_ip "$entry"; then
      validation_emit ok "Allowlist entry $index is valid."
    else
      validation_emit error "Allowlist entry $index is not a valid IP address."
    fi
  done
}

count_readable_log_sources() {
  local file count=0
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    count=$((count + 1))
  done < <(
    existing_auth_logs
    existing_web_logs
    existing_mail_logs
    existing_firewall_logs
    existing_vpn_logs
    existing_database_logs
    existing_object_storage_logs
    existing_edge_logs
  )
  printf '%s' "$count"
}

validate_config_file_permissions() {
  local permissions group_digit other_digit
  if [ ! -r "$CONFIG_FILE" ]; then
    validation_emit error "The configuration file is missing or unreadable."
    return
  fi
  validation_emit ok "The configuration file is readable."

  command -v stat >/dev/null 2>&1 || return 0
  permissions="$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || true)"
  [[ "$permissions" =~ ^[0-7]{3,4}$ ]] || return 0
  group_digit="${permissions: -2:1}"
  other_digit="${permissions: -1}"
  case "$group_digit:$other_digit" in
    2:*|3:*|6:*|7:*|*:2|*:3|*:6|*:7)
      validation_emit error "The configuration file must not be group- or world-writable."
      ;;
    *) validation_emit ok "The configuration file is not group- or world-writable." ;;
  esac
}

validate_firewall_config() {
  local backend
  case "$VEXYL_FIREWALL" in
    auto|nft|iptables|none) ;;
    *)
      validation_emit error "VEXYL_FIREWALL must be auto, nft, iptables, or none."
      return
      ;;
  esac

  backend="$(detect_firewall)"
  if [ "$VEXYL_MODE" = "enforce" ] && [ "$backend" = "none" ]; then
    validation_emit error "Enforcement requires nftables or iptables, but neither is selected and available."
    return
  fi
  if [ "$VEXYL_FIREWALL" = "nft" ] && ! command -v nft >/dev/null 2>&1; then
    validation_emit error "The nft firewall backend is selected but the nft command is unavailable."
    return
  fi
  if [ "$VEXYL_FIREWALL" = "iptables" ] && ! command -v iptables >/dev/null 2>&1; then
    validation_emit error "The iptables firewall backend is selected but the iptables command is unavailable."
    return
  fi
  if [ "$backend" = "none" ]; then
    validation_emit warning "No firewall backend is available; monitor mode can run but cannot enforce blocks."
  else
    validation_emit ok "Firewall backend $backend is available."
  fi
}

validate_api_config() {
  if { [ -n "$VEXYL_API_URL" ] && [ -z "$VEXYL_API_TOKEN" ]; } || { [ -z "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ]; }; then
    validation_emit error "VEXYL_API_URL and VEXYL_API_TOKEN must be configured together."
    return
  fi
  if [ -z "$VEXYL_API_URL" ]; then
    validation_emit ok "The agent is configured for local-only operation."
    return
  fi

  if [[ "$VEXYL_API_URL" =~ ^https://[^/?#[:space:]]+([/?#][^[:space:]]*)?$ ]]; then
    validation_emit ok "The companion API uses HTTPS."
  elif [[ "$VEXYL_API_URL" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?([/?#][^[:space:]]*)?$ ]]; then
    validation_emit warning "The companion API uses loopback HTTP; use HTTPS outside local development."
  elif [[ "$VEXYL_API_URL" == http://* ]]; then
    validation_emit error "The companion API must use HTTPS outside loopback development."
  else
    validation_emit error "VEXYL_API_URL must be a valid HTTP or HTTPS URL."
  fi

  if ! command -v curl >/dev/null 2>&1; then
    validation_emit error "The companion API is configured but curl is unavailable."
  fi
}

public_key_file_valid() {
  openssl pkey -pubin -in "$1" -noout >/dev/null 2>&1
}

invalid_policy_public_key_count() {
  local checked=0 invalid=0 key
  if [ -n "$VEXYL_POLICY_PUBLIC_KEY_DIR" ] && [ -d "$VEXYL_POLICY_PUBLIC_KEY_DIR" ]; then
    for key in "$VEXYL_POLICY_PUBLIC_KEY_DIR"/*.pem; do
      [ -r "$key" ] || continue
      checked=$((checked + 1))
      public_key_file_valid "$key" || invalid=$((invalid + 1))
    done
  fi
  if [ "$checked" -eq 0 ] && [ -n "$VEXYL_POLICY_PUBLIC_KEY_FILE" ] && [ -r "$VEXYL_POLICY_PUBLIC_KEY_FILE" ]; then
    public_key_file_valid "$VEXYL_POLICY_PUBLIC_KEY_FILE" || invalid=$((invalid + 1))
  fi
  printf '%s' "$invalid"
}

validate_trust_config() {
  local trusted_keys invalid_keys
  trusted_keys="$(policy_public_key_count)"
  if [ -s "$VEXYL_RELEASE_PUBLIC_KEY_FILE" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
      validation_emit error "The release verification key is configured but openssl is unavailable."
    elif public_key_file_valid "$VEXYL_RELEASE_PUBLIC_KEY_FILE"; then
      validation_emit ok "The release verification key is valid and readable."
    else
      validation_emit error "The release verification key is not a valid PEM public key."
    fi
  else
    validation_emit warning "The release verification key is unavailable; signed upgrades cannot run."
  fi

  if policy_bundle_required_without_verifier && ! policy_bundle_verifier_configured; then
    validation_emit error "Signed policy bundles are required but no verifier is configured."
  elif policy_bundle_public_key_configured; then
    if ! command -v openssl >/dev/null 2>&1; then
      validation_emit error "Policy verification keys are configured but openssl is unavailable."
    else
      invalid_keys="$(invalid_policy_public_key_count)"
      if [ "$invalid_keys" -gt 0 ]; then
        validation_emit error "$invalid_keys policy verification key(s) are not valid PEM public keys."
      else
        validation_emit ok "$trusted_keys valid policy verification key(s) are available."
      fi
    fi
  elif policy_bundle_secret_configured; then
    if command -v openssl >/dev/null 2>&1; then
      validation_emit warning "Legacy shared-secret policy verification is configured; public-key verification is preferred."
    else
      validation_emit error "Shared-secret policy verification is configured but openssl is unavailable."
    fi
  elif [ -n "$VEXYL_API_URL" ] && ! policy_bundle_disabled; then
    validation_emit warning "No signed policy verifier is configured; remote policy will use legacy compatibility mode."
  else
    validation_emit ok "No remote signed-policy verifier is required for this local configuration."
  fi

}

validate_ai_intel_config() {
  local status
  status="$(ai_intel_status)"
  case "$status" in
    disabled) validation_emit ok "Local AI threat-intelligence scoring is disabled by policy." ;;
    ready) validation_emit ok "Local AI threat-intelligence scoring is ready." ;;
    will_seed) validation_emit warning "The AI threat database is absent and will be seeded at first use." ;;
    missing_cli)
      if ai_intel_required; then
        validation_emit error "AI threat-intelligence scoring is required but the vexyl CLI is unavailable."
      else
        validation_emit warning "The vexyl CLI is unavailable; AI threat-intelligence enrichment will remain inactive."
      fi
      ;;
    unseeded)
      if ai_intel_required; then
        validation_emit error "AI threat-intelligence scoring is required but its database is unseeded."
      else
        validation_emit warning "The AI threat database is unseeded; core host detection remains active."
      fi
      ;;
  esac
}

validate_config() {
  local readable_logs state_parent
  VALIDATION_ERRORS=0
  VALIDATION_WARNINGS=0
  VALIDATION_CHECKS=0
  printf 'Vexyl Guard configuration preflight\n'

  validate_config_file_permissions

  case "$VEXYL_MODE" in
    monitor|enforce) validation_emit ok "Operating mode is $VEXYL_MODE." ;;
    *) validation_emit error "VEXYL_MODE must be monitor or enforce." ;;
  esac

  validate_integer_setting VEXYL_THRESHOLD "$VEXYL_THRESHOLD" 1 1000000
  validate_integer_setting VEXYL_WINDOW_SECONDS "$VEXYL_WINDOW_SECONDS" 1 31536000
  validate_integer_setting VEXYL_BLOCK_SECONDS "$VEXYL_BLOCK_SECONDS" 1 315360000
  validate_integer_setting VEXYL_BOOTSTRAP_LINES "$VEXYL_BOOTSTRAP_LINES" 1 10000000
  validate_integer_setting VEXYL_POLICY_SYNC_SECONDS "$VEXYL_POLICY_SYNC_SECONDS" 1 31536000
  validate_integer_setting VEXYL_HEARTBEAT_SECONDS "$VEXYL_HEARTBEAT_SECONDS" 60 31536000
  validate_integer_setting VEXYL_MUTATION_CATEGORY_THRESHOLD "$VEXYL_MUTATION_CATEGORY_THRESHOLD" 2 1000000
  validate_integer_setting VEXYL_MUTATION_WEIGHT "$VEXYL_MUTATION_WEIGHT" 1 1000000
  validate_integer_setting VEXYL_AI_INTEL_SIGNAL_SCORE "$VEXYL_AI_INTEL_SIGNAL_SCORE" 0 100
  validate_integer_setting VEXYL_AI_INTEL_SIGNAL_WEIGHT "$VEXYL_AI_INTEL_SIGNAL_WEIGHT" 1 1000000

  validate_allowlist
  validate_firewall_config
  validate_api_config

  if [ -d "$VEXYL_STATE_DIR" ]; then
    if [ -w "$VEXYL_STATE_DIR" ]; then
      validation_emit ok "The state directory is writable by the current user."
    else
      validation_emit warning "The state directory is not writable by the current user; verify the service account can write it."
    fi
  else
    state_parent="$(dirname "$VEXYL_STATE_DIR")"
    if [ -d "$state_parent" ] && [ -w "$state_parent" ]; then
      validation_emit ok "The state directory can be created by the current user."
    else
      validation_emit warning "The state directory does not exist; verify the service can create it."
    fi
  fi

  readable_logs="$(count_readable_log_sources)"
  if [ "$readable_logs" -gt 0 ]; then
    validation_emit ok "$readable_logs readable log source(s) were found."
  elif command -v journalctl >/dev/null 2>&1; then
    validation_emit warning "No configured log files are readable; the agent will fall back to SSH journal entries."
  else
    validation_emit error "No configured log files are readable and journalctl is unavailable."
  fi

  validate_trust_config
  validate_ai_intel_config

  printf 'summary: %s check(s), %s warning(s), %s error(s)\n' "$VALIDATION_CHECKS" "$VALIDATION_WARNINGS" "$VALIDATION_ERRORS"
  if [ "$VALIDATION_ERRORS" -gt 0 ]; then
    printf 'result: invalid configuration\n'
    return 78
  fi
  printf 'result: valid configuration\n'
}

safe_os_field() {
  local field="$1" value
  value="$(sed -nE "s/^${field}=//p" /etc/os-release 2>/dev/null | head -n 1)"
  value="${value%\"}"
  value="${value#\"}"
  value="$(printf '%s' "$value" | redact_ai_signal_text | tr '\t\r\n' '   ')"
  [ -n "$value" ] || value="unknown"
  printf '%s' "$value"
}

count_command_lines() {
  local count=0 _line
  while IFS= read -r _line; do
    count=$((count + 1))
  done
  printf '%s' "$count"
}

systemd_unit_property() {
  local property="$1" value
  command -v systemctl >/dev/null 2>&1 || {
    printf 'unavailable'
    return 0
  }
  value="$(systemctl show vexyl-guard --property="$property" --value 2>/dev/null | head -n 1)"
  [ -n "$value" ] || value="unknown"
  printf '%s' "$value"
}

systemd_unit_enabled() {
  local value
  command -v systemctl >/dev/null 2>&1 || {
    printf 'unavailable'
    return 0
  }
  value="$(systemctl is-enabled vexyl-guard 2>/dev/null || true)"
  [ -n "$value" ] || value="unknown"
  printf '%s' "$value"
}

support_report() {
  local backend blocked scores categories ai_decisions ai_status policy_mode policy_payload trusted_keys revoked_keys release_key release_version
  local os_name os_id os_version os_version_id kernel arch euid_label service_load service_active service_sub service_enabled
  local auth_count web_count mail_count firewall_count vpn_count database_count object_storage_count edge_count

  backend="$(detect_firewall)"
  blocked="$(awk 'END { print NR + 0 }' "$BLOCKS_FILE" 2>/dev/null || printf 0)"
  scores="$(awk 'END { print NR + 0 }' "$SCORES_FILE" 2>/dev/null || printf 0)"
  categories="$(awk 'END { print NR + 0 }' "$CATEGORIES_FILE" 2>/dev/null || printf 0)"
  ai_decisions="$(awk 'END { print NR + 0 }' "$AI_DECISIONS_FILE" 2>/dev/null || printf 0)"
  ai_status="$(ai_intel_status)"
  trusted_keys="$(policy_public_key_count)"
  revoked_keys="$(policy_revoked_key_count)"
  release_key="$([ -r "$VEXYL_RELEASE_PUBLIC_KEY_FILE" ] && printf yes || printf no)"
  release_version="$(json_string_field "$RELEASE_STATE_FILE" "version")"
  [ -n "$release_version" ] || release_version="$VERSION"

  if policy_bundle_disabled; then
    policy_mode="legacy"
  elif policy_bundle_public_key_configured; then
    policy_mode="signed-rs256"
  elif policy_bundle_secret_configured; then
    policy_mode="signed-hs256"
  elif policy_bundle_required_without_verifier; then
    policy_mode="missing_verifier"
  else
    policy_mode="legacy_auto"
  fi

  policy_payload="$([ -s "$POLICY_PAYLOAD_FILE" ] && printf yes || printf no)"
  os_name="$(safe_os_field NAME)"
  os_id="$(safe_os_field ID)"
  os_version="$(safe_os_field VERSION)"
  os_version_id="$(safe_os_field VERSION_ID)"
  kernel="$(uname -srm 2>/dev/null | redact_ai_signal_text | tr '\t\r\n' '   ')"
  [ -n "$kernel" ] || kernel="unknown"
  arch="$(uname -m 2>/dev/null | tr '\t\r\n' '   ')"
  [ -n "$arch" ] || arch="unknown"

  if [ "$(id -u 2>/dev/null || printf 1)" -eq 0 ] 2>/dev/null; then
    euid_label="root"
  else
    euid_label="non_root"
  fi

  service_load="$(systemd_unit_property LoadState)"
  service_active="$(systemd_unit_property ActiveState)"
  service_sub="$(systemd_unit_property SubState)"
  service_enabled="$(systemd_unit_enabled)"

  auth_count="$(existing_auth_logs | count_command_lines)"
  web_count="$(existing_web_logs | count_command_lines)"
  mail_count="$(existing_mail_logs | count_command_lines)"
  firewall_count="$(existing_firewall_logs | count_command_lines)"
  vpn_count="$(existing_vpn_logs | count_command_lines)"
  database_count="$(existing_database_logs | count_command_lines)"
  object_storage_count="$(existing_object_storage_logs | count_command_lines)"
  edge_count="$(existing_edge_logs | count_command_lines)"

  cat <<EOF
Vexyl Guard support report
safe_to_post: yes_redacted_summary_only
report_notes: no raw logs, hostnames, IP addresses, usernames, tokens, API URLs, or custom local paths are included
agent_version: $VERSION
release_version: $release_version
generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
effective_user: $euid_label

system:
  os_name: $os_name
  os_id: $os_id
  os_version: $os_version
  os_version_id: $os_version_id
  kernel: $kernel
  arch: $arch

service:
  systemd_available: $(command -v systemctl >/dev/null 2>&1 && printf yes || printf no)
  unit_load_state: $service_load
  unit_active_state: $service_active
  unit_sub_state: $service_sub
  unit_enabled: $service_enabled

agent:
  mode: $VEXYL_MODE
  firewall_backend: $backend
  api_configured: $([ -n "$VEXYL_API_URL" ] && [ -n "$VEXYL_API_TOKEN" ] && printf yes || printf no)
  release_key_configured: $release_key
  ai_intel: $ai_status
  tracked_scores: $scores
  tracked_probe_categories: $categories
  tracked_blocks: $blocked
  tracked_ai_decisions: $ai_decisions

policy:
  policy_mode: $policy_mode
  signed_policy_applied: $policy_payload
  trusted_policy_keys: $trusted_keys
  revoked_policy_keys: $revoked_keys

log_sources:
  auth_logs_found: $auth_count
  web_logs_found: $web_count
  mail_logs_found: $mail_count
  firewall_logs_found: $firewall_count
  vpn_logs_found: $vpn_count
  database_logs_found: $database_count
  object_storage_logs_found: $object_storage_count
  edge_logs_found: $edge_count

feedback:
  public_issue: https://github.com/vexyl-labs/vexyl-guard/issues/1
  structured_install_report: https://github.com/vexyl-labs/vexyl-guard/issues/new?template=install_feedback.yml
  sensitive_reports: security@vexyl.dev
EOF
}

test_parse() {
  local line ip
  while IFS= read -r line; do
    ip="$(extract_ip_from_line "$line")"
    [ -n "$ip" ] && printf '%s\n' "$ip"
  done
  return 0
}

test_classify() {
  local line ip reason fields classification event_type category weight severity proto dpt
  while IFS= read -r line; do
    ip="$(extract_ip_from_line "$line")"
    if [ -n "$ip" ]; then
      reason="$(reason_from_line "$line")"
      printf 'ssh_auth_attack\t%s\t%s\n' "$ip" "$reason"
      continue
    fi
    classification="$(classify_mail_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    classification="$(classify_firewall_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity proto dpt <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    classification="$(classify_vpn_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    classification="$(classify_database_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    classification="$(classify_object_storage_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    classification="$(classify_edge_line "$line")" || classification=""
    if [ -n "$classification" ]; then
      IFS=$'\t' read -r ip event_type reason category weight severity <<<"$classification"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
      continue
    fi
    fields="$(extract_web_fields "$line")" || continue
    IFS=$'\t' read -r ip method uri status user_agent <<<"$fields"
    classification="$(classify_web_request "$method" "$uri" "$status" "$user_agent")" || continue
    IFS=$'\t' read -r event_type reason category weight severity <<<"$classification"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$event_type" "$ip" "$reason" "$category" "$weight" "$severity"
  done
  return 0
}

install_systemd() {
  [ "$(id -u)" -eq 0 ] || die "install-systemd must run as root"
  install -m 0755 "$0" /usr/local/sbin/vexyl-guard
  install -d -m 0750 "$VEXYL_CONFIG_DIR" "$VEXYL_STATE_DIR"
  if [ ! -f "$CONFIG_FILE" ]; then
    cat >"$CONFIG_FILE" <<'EOF'
VEXYL_MODE=monitor
VEXYL_API_URL=
VEXYL_API_TOKEN=
VEXYL_THRESHOLD=5
VEXYL_WINDOW_SECONDS=900
VEXYL_BLOCK_SECONDS=86400
VEXYL_STATE_DIR=/var/lib/vexyl
VEXYL_CONFIG_DIR=/etc/vexyl
VEXYL_AGENT_BIN=/usr/local/sbin/vexyl-guard
VEXYL_UPGRADE_BASE_URL=https://vexyl.dev
VEXYL_UPGRADE_ALLOW_DOWNGRADE=false
VEXYL_UPGRADE_FORCE=false
VEXYL_RELEASE_PUBLIC_KEY_FILE=/etc/vexyl/release-signing-public.pem
VEXYL_FIREWALL=auto
VEXYL_ALLOWLIST="127.0.0.1 ::1"
VEXYL_AUTH_LOGS="/var/log/auth.log /var/log/secure /var/log/messages"
VEXYL_WEB_LOGS="/var/log/nginx/access.log /var/log/nginx/*access.log /var/log/apache2/access.log /var/log/httpd/access_log /var/log/caddy/access.log"
VEXYL_MAIL_LOGS="/var/log/mail.log /var/log/maillog"
VEXYL_FIREWALL_LOGS="/var/log/kern.log /var/log/ufw.log"
VEXYL_VPN_LOGS="/var/log/openvpn.log /var/log/openvpn/*.log /var/log/strongswan.log /var/log/charon.log /var/log/wireguard.log"
VEXYL_DATABASE_LOGS="/var/log/postgresql/*.log /var/log/mysql/error.log /var/log/mysqld.log /var/log/mariadb/mariadb.log /var/log/mongodb/mongod.log"
VEXYL_OBJECT_STORAGE_LOGS="/var/log/minio.log /var/log/minio/*.log /var/log/s3/access.log /var/log/s3/*.log /var/log/aws/s3*.log"
VEXYL_EDGE_LOGS="/var/log/cloudflare.log /var/log/cloudflare/*.log /var/log/cdn/*.log /var/log/edge/*.log /var/log/waf/*.log"
VEXYL_BOOTSTRAP_LINES=1500
VEXYL_POLICY_SYNC_SECONDS=300
VEXYL_HEARTBEAT_SECONDS=300
VEXYL_POLICY_BUNDLE_ENABLED=auto
VEXYL_POLICY_PUBLIC_KEY_DIR=/etc/vexyl/policy-keys.d
VEXYL_POLICY_PUBLIC_KEY_FILE=/etc/vexyl/policy-signing-public.pem
VEXYL_POLICY_REVOKED_KEYS_FILE=/etc/vexyl/revoked-policy-keys.txt
VEXYL_POLICY_REVOKED_KEY_IDS=
VEXYL_POLICY_SIGNING_SECRET=
VEXYL_POLICY_KEY_ID=vexyl-policy-dev-1
VEXYL_DECEPTION_PATHS="/.vexyl-canary /__vexyl/trap /vexyl-honey"
VEXYL_MUTATION_CATEGORY_THRESHOLD=3
VEXYL_MUTATION_WEIGHT=3
VEXYL_AI_INTEL_ENABLED=auto
VEXYL_AI_INTEL_BIN=vexyl
VEXYL_AI_INTEL_DB=/var/lib/vexyl/ai_threats.sqlite
VEXYL_AI_INTEL_AUTO_SEED=false
VEXYL_AI_INTEL_SIGNAL_SCORE=70
VEXYL_AI_INTEL_SIGNAL_WEIGHT=4
EOF
    chmod 0640 "$CONFIG_FILE"
  fi
  cat >/etc/systemd/system/vexyl-guard.service <<'EOF'
[Unit]
Description=Vexyl Guard host agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/vexyl/guard.conf
ExecStartPre=/usr/local/sbin/vexyl-guard validate-config
ExecStart=/usr/local/sbin/vexyl-guard daemon
Restart=always
RestartPreventExitStatus=78
RestartSec=5s
StateDirectory=vexyl
ConfigurationDirectory=vexyl
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable vexyl-guard
  log info "installed systemd service; start with: systemctl start vexyl-guard"
}

upgrade_agent() {
  local base_url="${1:-$VEXYL_UPGRADE_BASE_URL}" release_key tmp_dir manifest signature release agent trusted revoked release_key_new key_id installed_keys release_version action

  if [ "$(id -u)" -ne 0 ]; then
    truthy "$VEXYL_UPGRADE_ALLOW_NONROOT" || die "upgrade must run as root"
  fi

  need_command curl
  need_command install
  need_command openssl
  need_command sha256sum
  need_command awk
  need_command sed
  need_command tr
  need_command mktemp
  need_command bash

  release_key="$(release_public_key_file)" || return 1
  tmp_dir="$(mktemp -d)" || die "failed to create upgrade temp dir"
  manifest="$tmp_dir/SHA256SUMS"
  signature="$tmp_dir/SHA256SUMS.sig"
  release="$tmp_dir/RELEASE.json"
  agent="$tmp_dir/vexyl-guard"
  trusted="$tmp_dir/TRUSTED_KEYS"
  revoked="$tmp_dir/revoked-policy-keys.txt"
  release_key_new="$tmp_dir/release-signing-public.pem"

  curl -fsSL "$base_url/downloads/SHA256SUMS" -o "$manifest" 2>/dev/null || {
    rm -rf "$tmp_dir"
    log error "failed to download release manifest"
    return 1
  }
  curl -fsSL "$base_url/downloads/SHA256SUMS.sig" -o "$signature" 2>/dev/null || {
    rm -rf "$tmp_dir"
    log error "failed to download release manifest signature"
    return 1
  }
  openssl dgst -sha256 -verify "$release_key" -signature "$signature" "$manifest" >/dev/null 2>&1 || {
    rm -rf "$tmp_dir"
    log error "release manifest signature verification failed"
    return 1
  }

  fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/RELEASE.json" "$release" || { rm -rf "$tmp_dir"; return 1; }
  release_upgrade_action "$release" || { rm -rf "$tmp_dir"; return 1; }
  action="$RELEASE_UPGRADE_ACTION"
  release_version="$(json_string_field "$release" "version")"

  fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/vexyl-guard.sh" "$agent" || { rm -rf "$tmp_dir"; return 1; }
  fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/policy-keys/TRUSTED_KEYS" "$trusted" || { rm -rf "$tmp_dir"; return 1; }
  fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/revoked-policy-keys.txt" "$revoked" || { rm -rf "$tmp_dir"; return 1; }
  fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/release-signing-public.pem" "$release_key_new" || { rm -rf "$tmp_dir"; return 1; }

  bash -n "$agent" || {
    rm -rf "$tmp_dir"
    log error "downloaded agent failed syntax validation"
    return 1
  }

  install -d -m 0750 "$VEXYL_CONFIG_DIR" "$VEXYL_STATE_DIR" || {
    rm -rf "$tmp_dir"
    log error "failed to prepare Vexyl directories"
    return 1
  }
  install -d -m 0755 "$VEXYL_POLICY_PUBLIC_KEY_DIR" || {
    rm -rf "$tmp_dir"
    log error "failed to prepare policy key directory"
    return 1
  }
  install -m 0644 "$revoked" "$VEXYL_POLICY_REVOKED_KEYS_FILE" || {
    rm -rf "$tmp_dir"
    log error "failed to install policy key revocation list"
    return 1
  }
  install -m 0644 "$release_key_new" "$VEXYL_RELEASE_PUBLIC_KEY_FILE" || {
    rm -rf "$tmp_dir"
    log error "failed to install release public key"
    return 1
  }
  install -m 0644 "$release" "$RELEASE_STATE_FILE" 2>/dev/null || true

  installed_keys=0
  while IFS= read -r key_id; do
    key_id="${key_id%%#*}"
    key_id="${key_id//[[:space:]]/}"
    [ -n "$key_id" ] || continue
    policy_kid_safe "$key_id" || {
      rm -rf "$tmp_dir"
      log error "unsafe policy key id in trusted key set: $key_id"
      return 1
    }
    fetch_verified_manifest_entry "$base_url" "$manifest" "downloads/policy-keys/$key_id.pem" "$tmp_dir/policy-key-$key_id.pem" || {
      rm -rf "$tmp_dir"
      return 1
    }
    install -m 0644 "$tmp_dir/policy-key-$key_id.pem" "$VEXYL_POLICY_PUBLIC_KEY_DIR/$key_id.pem" || {
      rm -rf "$tmp_dir"
      log error "failed to install policy key: $key_id"
      return 1
    }
    if [ -n "$VEXYL_POLICY_KEY_ID" ] && [ "$key_id" = "$VEXYL_POLICY_KEY_ID" ]; then
      install -m 0644 "$tmp_dir/policy-key-$key_id.pem" "$VEXYL_POLICY_PUBLIC_KEY_FILE" 2>/dev/null || true
    fi
    installed_keys=$((installed_keys + 1))
  done <"$trusted"

  [ "$installed_keys" -gt 0 ] || {
    rm -rf "$tmp_dir"
    log error "trusted key set was empty"
    return 1
  }

  if [ "$action" = "skip" ]; then
    rm -rf "$tmp_dir"
    log info "release $release_version matches current agent $VERSION; refreshed trust material; agent replacement skipped"
    return 0
  fi

  install -m 0755 "$agent" "$VEXYL_AGENT_BIN" || {
    rm -rf "$tmp_dir"
    log error "failed to install upgraded agent"
    return 1
  }

  rm -rf "$tmp_dir"
  log info "upgraded Vexyl Guard to $release_version from $base_url keys=$installed_keys target=$VEXYL_AGENT_BIN"
}

main() {
  local command="${1:-daemon}"
  load_config

  case "$command" in
    daemon) ensure_state; daemon ;;
    once) ensure_state; run_once ;;
    sync) ensure_state; sync_policy ;;
    upgrade) upgrade_agent "${2:-}" ;;
    verify-policy) ensure_state; [ -n "${2:-}" ] || die "verify-policy requires a bundle JSON file"; verify_policy_bundle_file "$2" || exit 1 ;;
    status) ensure_state; status ;;
    validate-config) validate_config ;;
    support-report) ensure_state; support_report ;;
    unblock) ensure_state; [ -n "${2:-}" ] || die "unblock requires an IP"; unblock_ip "$2" ;;
    test-parse) test_parse ;;
    test-classify) test_classify ;;
    install-systemd) install_systemd ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
