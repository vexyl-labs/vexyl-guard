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
