#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT_DIR/agent/vexyl-guard.sh"
FIXTURES="$ROOT_DIR/tests/fixtures/agent"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

EMPTY_CONFIG="$TMP_DIR/empty.conf"
touch "$EMPTY_CONFIG"

compare() {
  local expected="$1" actual="$2" label="$3"
  if ! diff -u "$expected" "$actual"; then
    printf 'not ok - %s\n' "$label" >&2
    return 1
  fi
  printf 'ok - %s\n' "$label"
}

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-parse \
  <"$FIXTURES/auth.log" >"$TMP_DIR/parse.out"
compare "$FIXTURES/expected-parse.txt" "$TMP_DIR/parse.out" "ssh auth IP parsing"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-classify \
  <"$FIXTURES/classify.log" >"$TMP_DIR/classify.out"
compare "$FIXTURES/expected-classify.tsv" "$TMP_DIR/classify.out" "auth and web classification"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-classify \
  <"$FIXTURES/json-access.log" >"$TMP_DIR/json-classify.out"
compare "$FIXTURES/expected-json-classify.tsv" "$TMP_DIR/json-classify.out" "JSON access-log classification"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" VEXYL_JSON_USE_JQ=false "$AGENT" test-classify \
  <"$FIXTURES/json-access.log" >"$TMP_DIR/json-classify-fallback.out"
compare "$FIXTURES/expected-json-classify.tsv" "$TMP_DIR/json-classify-fallback.out" "JSON access-log fallback classification"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-classify \
  <"$FIXTURES/mail-firewall.log" >"$TMP_DIR/mail-firewall-classify.out"
compare "$FIXTURES/expected-mail-firewall-classify.tsv" "$TMP_DIR/mail-firewall-classify.out" "mail and firewall classification"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-classify \
  <"$FIXTURES/vpn-database.log" >"$TMP_DIR/vpn-database-classify.out"
compare "$FIXTURES/expected-vpn-database-classify.tsv" "$TMP_DIR/vpn-database-classify.out" "VPN and database classification"

VEXYL_CONFIG_FILE="$EMPTY_CONFIG" "$AGENT" test-classify \
  <"$FIXTURES/storage-edge.log" >"$TMP_DIR/storage-edge-classify.out"
compare "$FIXTURES/expected-storage-edge-classify.tsv" "$TMP_DIR/storage-edge-classify.out" "object storage and edge classification"

STATE_DIR="$TMP_DIR/state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$FIXTURES/mutation-web.log" \
VEXYL_MAIL_LOGS="$TMP_DIR/missing-mail.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$TMP_DIR/missing-vpn.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$TMP_DIR/missing-object-storage.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
VEXYL_MUTATION_CATEGORY_THRESHOLD=3 \
VEXYL_MUTATION_WEIGHT=3 \
"$AGENT" once >"$TMP_DIR/mutation.log"

if ! grep -q 'event=ai_assisted_suspected reason=rapid_probe_mutation' "$TMP_DIR/mutation.log"; then
  printf 'not ok - rapid mutation event emitted\n' >&2
  sed -n '1,120p' "$TMP_DIR/mutation.log" >&2
  exit 1
fi
printf 'ok - rapid mutation event emitted\n'

awk -F '\t' '$1 == "203.0.113.77" { print $2 }' "$STATE_DIR/categories.tsv" |
  sort >"$TMP_DIR/mutation-categories.out"
compare "$FIXTURES/expected-mutation-categories.txt" "$TMP_DIR/mutation-categories.out" "mutation category tracking"

awk -F '\t' '$1 == "203.0.113.77" { print $1 "\t" $2 "\t" $5 }' "$STATE_DIR/scores.tsv" \
  >"$TMP_DIR/mutation-score.out"
compare "$FIXTURES/expected-mutation-score.tsv" "$TMP_DIR/mutation-score.out" "mutation scoring"

MAIL_FW_STATE_DIR="$TMP_DIR/mail-firewall-state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$MAIL_FW_STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$TMP_DIR/missing-web.log" \
VEXYL_MAIL_LOGS="$FIXTURES/mail-firewall.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$TMP_DIR/missing-vpn.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$TMP_DIR/missing-object-storage.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
"$AGENT" once >"$TMP_DIR/mail-firewall-once.log"

awk -F '\t' '{ print $1 "\t" $2 "\t" $5 }' "$MAIL_FW_STATE_DIR/scores.tsv" |
  sort >"$TMP_DIR/mail-firewall-score.out"
sort "$FIXTURES/expected-mail-firewall-score.tsv" >"$TMP_DIR/expected-mail-firewall-score.sorted"
compare "$TMP_DIR/expected-mail-firewall-score.sorted" "$TMP_DIR/mail-firewall-score.out" "mail and firewall scoring"

VPN_DB_STATE_DIR="$TMP_DIR/vpn-database-state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$VPN_DB_STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$TMP_DIR/missing-web.log" \
VEXYL_MAIL_LOGS="$TMP_DIR/missing-mail.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$FIXTURES/vpn-database.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$TMP_DIR/missing-object-storage.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
"$AGENT" once >"$TMP_DIR/vpn-database-once.log"

awk -F '\t' '{ print $1 "\t" $2 "\t" $5 }' "$VPN_DB_STATE_DIR/scores.tsv" |
  sort >"$TMP_DIR/vpn-database-score.out"
sort "$FIXTURES/expected-vpn-database-score.tsv" >"$TMP_DIR/expected-vpn-database-score.sorted"
compare "$TMP_DIR/expected-vpn-database-score.sorted" "$TMP_DIR/vpn-database-score.out" "VPN and database scoring"

STORAGE_EDGE_STATE_DIR="$TMP_DIR/storage-edge-state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$STORAGE_EDGE_STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$TMP_DIR/missing-web.log" \
VEXYL_MAIL_LOGS="$TMP_DIR/missing-mail.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$TMP_DIR/missing-vpn.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$FIXTURES/storage-edge.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
"$AGENT" once >"$TMP_DIR/storage-edge-once.log"

awk -F '\t' '{ print $1 "\t" $2 "\t" $5 }' "$STORAGE_EDGE_STATE_DIR/scores.tsv" |
  sort >"$TMP_DIR/storage-edge-score.out"
sort "$FIXTURES/expected-storage-edge-score.tsv" >"$TMP_DIR/expected-storage-edge-score.sorted"
compare "$TMP_DIR/expected-storage-edge-score.sorted" "$TMP_DIR/storage-edge-score.out" "object storage and edge scoring"

ALLOWLIST_LOG="$TMP_DIR/allowlist-web.log"
cat >"$ALLOWLIST_LOG" <<'EOF'
192.0.2.25 - - [12/Jul/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
192.0.2.200 - - [12/Jul/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
2001:db8:abcd:a000::25 - - [12/Jul/2026:12:00:02 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
2001:db8:abcd:4000::25 - - [12/Jul/2026:12:00:03 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
198.51.100.7 - - [12/Jul/2026:12:00:04 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
0:0:0:0:0:0:0:1 - - [12/Jul/2026:12:00:05 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
203.0.113.8 - - [12/Jul/2026:12:00:06 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
EOF

ALLOWLIST_STATE_DIR="$TMP_DIR/allowlist-state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$ALLOWLIST_STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$ALLOWLIST_LOG" \
VEXYL_MAIL_LOGS="$TMP_DIR/missing-mail.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$TMP_DIR/missing-vpn.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$TMP_DIR/missing-object-storage.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_ALLOWLIST="192.0.2.0/25 2001:db8:abcd:8000::/49 198.51.100.7 ::1 203.0.113.0/not-a-prefix" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
"$AGENT" once >"$TMP_DIR/allowlist-once.log"

cut -f 1 "$ALLOWLIST_STATE_DIR/scores.tsv" | sort >"$TMP_DIR/allowlist-score-ips.out"
cat >"$TMP_DIR/allowlist-score-ips.expected" <<'EOF'
192.0.2.200
2001:db8:abcd:4000::25
203.0.113.8
EOF
compare "$TMP_DIR/allowlist-score-ips.expected" "$TMP_DIR/allowlist-score-ips.out" "IPv4 and IPv6 CIDR allowlists"

ALLOWLIST_ZERO_LOG="$TMP_DIR/allowlist-zero-web.log"
cat >"$ALLOWLIST_ZERO_LOG" <<'EOF'
198.18.0.1 - - [12/Jul/2026:12:01:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
fd00:1234::1 - - [12/Jul/2026:12:01:01 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"
EOF

ALLOWLIST_ZERO_STATE_DIR="$TMP_DIR/allowlist-zero-state"
VEXYL_CONFIG_FILE="$EMPTY_CONFIG" \
VEXYL_STATE_DIR="$ALLOWLIST_ZERO_STATE_DIR" \
VEXYL_AUTH_LOGS="$TMP_DIR/missing-auth.log" \
VEXYL_WEB_LOGS="$ALLOWLIST_ZERO_LOG" \
VEXYL_MAIL_LOGS="$TMP_DIR/missing-mail.log" \
VEXYL_FIREWALL_LOGS="$TMP_DIR/missing-firewall.log" \
VEXYL_VPN_LOGS="$TMP_DIR/missing-vpn.log" \
VEXYL_DATABASE_LOGS="$TMP_DIR/missing-database.log" \
VEXYL_OBJECT_STORAGE_LOGS="$TMP_DIR/missing-object-storage.log" \
VEXYL_EDGE_LOGS="$TMP_DIR/missing-edge.log" \
VEXYL_ALLOWLIST="0.0.0.0/00 ::/000" \
VEXYL_MODE=monitor \
VEXYL_FIREWALL=none \
VEXYL_THRESHOLD=999 \
"$AGENT" once >"$TMP_DIR/allowlist-zero-once.log"

if [ -s "$ALLOWLIST_ZERO_STATE_DIR/scores.tsv" ]; then
  printf 'not ok - zero-prefix CIDR allowlists\n' >&2
  sed -n '1,80p' "$ALLOWLIST_ZERO_STATE_DIR/scores.tsv" >&2
  exit 1
fi
printf 'ok - zero-prefix CIDR allowlists\n'

VALIDATION_STATE_DIR="$TMP_DIR/validation-state"
VALIDATION_KEY_DIR="$TMP_DIR/validation-policy-keys"
mkdir -p "$VALIDATION_STATE_DIR" "$VALIDATION_KEY_DIR"
cp "$ROOT_DIR/config/release-signing-public.pem" "$TMP_DIR/validation-release.pem"
cp "$ROOT_DIR/config/policy-signing-public.pem" "$VALIDATION_KEY_DIR/test-key.pem"
VALID_CONFIG="$TMP_DIR/valid.conf"
cat >"$VALID_CONFIG" <<EOF
VEXYL_MODE=monitor
VEXYL_FIREWALL=none
VEXYL_ALLOWLIST="127.0.0.1 192.0.2.0/24 ::1"
VEXYL_STATE_DIR=$VALIDATION_STATE_DIR
VEXYL_AUTH_LOGS=$FIXTURES/auth.log
VEXYL_WEB_LOGS=$TMP_DIR/missing-web.log
VEXYL_MAIL_LOGS=$TMP_DIR/missing-mail.log
VEXYL_FIREWALL_LOGS=$TMP_DIR/missing-firewall.log
VEXYL_VPN_LOGS=$TMP_DIR/missing-vpn.log
VEXYL_DATABASE_LOGS=$TMP_DIR/missing-database.log
VEXYL_OBJECT_STORAGE_LOGS=$TMP_DIR/missing-object-storage.log
VEXYL_EDGE_LOGS=$TMP_DIR/missing-edge.log
VEXYL_RELEASE_PUBLIC_KEY_FILE=$TMP_DIR/validation-release.pem
VEXYL_POLICY_PUBLIC_KEY_DIR=$VALIDATION_KEY_DIR
VEXYL_AI_INTEL_ENABLED=false
EOF
chmod 0600 "$VALID_CONFIG"

VEXYL_CONFIG_FILE="$VALID_CONFIG" "$AGENT" validate-config >"$TMP_DIR/valid-config.out"
if ! grep -q '^result: valid configuration$' "$TMP_DIR/valid-config.out"; then
  printf 'not ok - valid configuration preflight\n' >&2
  sed -n '1,160p' "$TMP_DIR/valid-config.out" >&2
  exit 1
fi
printf 'ok - valid configuration preflight\n'

INVALID_CONFIG="$TMP_DIR/invalid.conf"
cat >"$INVALID_CONFIG" <<EOF
VEXYL_MODE=enforce
VEXYL_FIREWALL=none
VEXYL_ALLOWLIST="0.0.0.0/0 not-a-network"
VEXYL_THRESHOLD=invalid
VEXYL_API_URL=https://api.example.test
VEXYL_STATE_DIR=$VALIDATION_STATE_DIR
VEXYL_AUTH_LOGS=$FIXTURES/auth.log
VEXYL_RELEASE_PUBLIC_KEY_FILE=$TMP_DIR/missing-release.pem
VEXYL_POLICY_PUBLIC_KEY_DIR=$TMP_DIR/missing-policy-keys
VEXYL_POLICY_PUBLIC_KEY_FILE=$TMP_DIR/missing-policy.pem
VEXYL_POLICY_BUNDLE_ENABLED=true
VEXYL_AI_INTEL_ENABLED=false
EOF
chmod 0600 "$INVALID_CONFIG"

set +e
VEXYL_CONFIG_FILE="$INVALID_CONFIG" "$AGENT" validate-config >"$TMP_DIR/invalid-config.out"
INVALID_CONFIG_STATUS=$?
set -e
if [ "$INVALID_CONFIG_STATUS" -ne 78 ]; then
  printf 'not ok - invalid configuration rejected\n' >&2
  printf 'expected exit 78, received %s\n' "$INVALID_CONFIG_STATUS" >&2
  sed -n '1,200p' "$TMP_DIR/invalid-config.out" >&2
  exit 1
fi
for expected in \
  'VEXYL_THRESHOLD must be an integer' \
  'covers an entire address family' \
  'is not a valid IP address' \
  'Enforcement requires nftables or iptables' \
  'VEXYL_API_URL and VEXYL_API_TOKEN must be configured together' \
  'Signed policy bundles are required but no verifier is configured' \
  'result: invalid configuration'; do
  if ! grep -q "$expected" "$TMP_DIR/invalid-config.out"; then
    printf 'not ok - invalid configuration reports %s\n' "$expected" >&2
    sed -n '1,200p' "$TMP_DIR/invalid-config.out" >&2
    exit 1
  fi
done
printf 'ok - invalid configuration rejected with actionable errors\n'

UNSAFE_URL_CONFIG="$TMP_DIR/unsafe-url.conf"
cp "$VALID_CONFIG" "$UNSAFE_URL_CONFIG"
cat >>"$UNSAFE_URL_CONFIG" <<'EOF'
VEXYL_API_URL=http://localhost.evil.example/v1
VEXYL_API_TOKEN=must-not-appear-in-output
EOF
set +e
VEXYL_CONFIG_FILE="$UNSAFE_URL_CONFIG" "$AGENT" validate-config >"$TMP_DIR/unsafe-url-config.out"
UNSAFE_URL_STATUS=$?
set -e
if [ "$UNSAFE_URL_STATUS" -ne 78 ] || ! grep -q 'must use HTTPS outside loopback' "$TMP_DIR/unsafe-url-config.out"; then
  printf 'not ok - loopback lookalike API URL rejected\n' >&2
  sed -n '1,200p' "$TMP_DIR/unsafe-url-config.out" >&2
  exit 1
fi
if grep -q 'must-not-appear-in-output' "$TMP_DIR/unsafe-url-config.out"; then
  printf 'not ok - configuration preflight redacts API token\n' >&2
  exit 1
fi
printf 'ok - loopback lookalike API URL rejected without exposing credentials\n'

SUPPORT_STATE_DIR="$TMP_DIR/support-state"
mkdir -p "$SUPPORT_STATE_DIR"
cat >"$SUPPORT_STATE_DIR/release.json" <<'JSON'
{"version":"0.2.9"}
JSON
printf '203.0.113.10\t1\t2\t3\tssh\n' >"$SUPPORT_STATE_DIR/scores.tsv"
printf '203.0.113.10\tprobe\t1\t2\t3\n' >"$SUPPORT_STATE_DIR/categories.tsv"
printf '203.0.113.10\tnone\t1\t2\tssh\n' >"$SUPPORT_STATE_DIR/blocks.tsv"
printf '2026-07-01T00:00:00Z\t203.0.113.10\t80\twarn\tATTACK\tlow\tRULE\tredacted\n' >"$SUPPORT_STATE_DIR/ai-decisions.tsv"

SUPPORT_CONFIG="$TMP_DIR/support.conf"
cat >"$SUPPORT_CONFIG" <<EOF
VEXYL_MODE=monitor
VEXYL_API_URL=https://api.example.test/private/path
VEXYL_API_TOKEN=secret-token-value
VEXYL_FIREWALL=none
VEXYL_STATE_DIR=$SUPPORT_STATE_DIR
VEXYL_RELEASE_PUBLIC_KEY_FILE=$TMP_DIR/release-signing-public.pem
EOF
touch "$TMP_DIR/release-signing-public.pem"

VEXYL_CONFIG_FILE="$SUPPORT_CONFIG" "$AGENT" support-report >"$TMP_DIR/support-report.out"

if ! grep -q '^Vexyl Guard support report$' "$TMP_DIR/support-report.out"; then
  printf 'not ok - support report header\n' >&2
  sed -n '1,120p' "$TMP_DIR/support-report.out" >&2
  exit 1
fi
printf 'ok - support report header\n'

for forbidden in 'secret-token-value' 'api.example.test' '203.0.113.10' "$SUPPORT_STATE_DIR" "$TMP_DIR"; do
  if grep -q "$forbidden" "$TMP_DIR/support-report.out"; then
    printf 'not ok - support report redacts %s\n' "$forbidden" >&2
    sed -n '1,160p' "$TMP_DIR/support-report.out" >&2
    exit 1
  fi
done
printf 'ok - support report omits secrets and host-specific paths\n'

if ! grep -q '^  api_configured: yes$' "$TMP_DIR/support-report.out"; then
  printf 'not ok - support report API configured flag\n' >&2
  sed -n '1,160p' "$TMP_DIR/support-report.out" >&2
  exit 1
fi
printf 'ok - support report API configured flag\n'

if ! grep -q '^  tracked_scores: 1$' "$TMP_DIR/support-report.out"; then
  printf 'not ok - support report tracked scores\n' >&2
  sed -n '1,160p' "$TMP_DIR/support-report.out" >&2
  exit 1
fi
printf 'ok - support report tracked scores\n'
