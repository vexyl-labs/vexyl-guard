#!/bin/sh
set -e

REPORT_API_URL="${VEXYL_INSTALL_REPORT_API_URL:-https://api.vexyl.dev}"
INSTALL_ID_FILE="${VEXYL_INSTALL_ID_FILE:-/var/lib/vexyl/install-id}"
EVENT_TYPE="${VEXYL_REPORT_EVENT_TYPE:-install_completed}"
INSTALL_METHOD="${VEXYL_REPORT_INSTALL_METHOD:-package}"
PHASE="${VEXYL_REPORT_PHASE:-package_configure}"
ERROR_CODE="${VEXYL_REPORT_ERROR_CODE:-}"
SERVICE_STATUS="${VEXYL_REPORT_SERVICE_STATUS:-}"
SOURCE="${VEXYL_INSTALL_SOURCE:-package_repo}"
CAMPAIGN="${VEXYL_INSTALL_CAMPAIGN:-public_preview}"
CONTENT="${VEXYL_INSTALL_CONTENT:-}"

install_reporting_disabled() {
  case "${VEXYL_INSTALL_REPORT:-on}" in
    0|false|False|FALSE|no|No|NO|off|Off|OFF|disabled|Disabled|DISABLED) return 0 ;;
    *) return 1 ;;
  esac
}

json_escape() {
  printf '%s' "$1" | tr '\r\n\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

os_release_field() {
  key="$1"
  [ -f /etc/os-release ] || return 0
  sed -n "s/^${key}=//p" /etc/os-release | sed -n '1p' | sed 's/^"//; s/"$//'
}

detect_package_manager() {
  if [ -n "${VEXYL_REPORT_PACKAGE_MANAGER:-}" ]; then
    printf '%s' "$VEXYL_REPORT_PACKAGE_MANAGER"
  elif command -v apt-get >/dev/null 2>&1; then
    printf 'apt'
  elif command -v dnf >/dev/null 2>&1; then
    printf 'dnf'
  elif command -v yum >/dev/null 2>&1; then
    printf 'yum'
  elif command -v rpm >/dev/null 2>&1; then
    printf 'rpm'
  else
    printf 'unknown'
  fi
}

detect_init_system() {
  if command -v systemctl >/dev/null 2>&1; then
    printf 'systemd'
  else
    printf 'unknown'
  fi
}

detect_agent_version() {
  if [ -n "${VEXYL_REPORT_AGENT_VERSION:-}" ]; then
    printf '%s' "$VEXYL_REPORT_AGENT_VERSION"
  elif [ -f /usr/sbin/vexyl-guard ]; then
    sed -n 's/^VERSION="\([^"]*\)".*/\1/p' /usr/sbin/vexyl-guard | sed -n '1p'
  else
    printf 'unknown'
  fi
}

detect_release_version() {
  if [ -n "${VEXYL_REPORT_RELEASE_VERSION:-}" ]; then
    printf '%s' "$VEXYL_REPORT_RELEASE_VERSION"
  else
    detect_agent_version
  fi
}

random_suffix() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    tr -d '-\n' </proc/sys/kernel/random/uuid
  elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  else
    printf '%s_%s' "$(date +%s 2>/dev/null || printf 0)" "$$"
  fi
}

ensure_install_id() {
  if [ -n "${VEXYL_INSTALL_ID:-}" ]; then
    printf '%s' "$VEXYL_INSTALL_ID" | tr -cd 'A-Za-z0-9_.:-'
    return 0
  fi

  if [ -f "$INSTALL_ID_FILE" ]; then
    install_id="$(sed -n '1p' "$INSTALL_ID_FILE" | tr -cd 'A-Za-z0-9_.:-')"
    if [ -n "$install_id" ]; then
      printf '%s' "$install_id"
      return 0
    fi
  fi

  install_id="vxi_$(random_suffix)"
  install -d -m 0750 "$(dirname "$INSTALL_ID_FILE")" >/dev/null 2>&1 || true
  (umask 077 && printf '%s\n' "$install_id" >"$INSTALL_ID_FILE") >/dev/null 2>&1 || true
  printf '%s' "$install_id"
}

send_with_python() {
  url="$1"
  payload="$2"
  VEXYL_INSTALL_REPORT_URL="$url" VEXYL_INSTALL_REPORT_PAYLOAD="$payload" python3 - <<'PY' >/dev/null 2>&1 || true
import os
import urllib.request

url = os.environ["VEXYL_INSTALL_REPORT_URL"]
payload = os.environ["VEXYL_INSTALL_REPORT_PAYLOAD"].encode("utf-8")
request = urllib.request.Request(
    url,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
urllib.request.urlopen(request, timeout=4).read()
PY
}

send_payload() {
  url="$1"
  payload="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --connect-timeout 2 --max-time 4 \
      -H "Content-Type: application/json" \
      -X POST "$url" \
      --data "$payload" >/dev/null 2>&1 || true
  elif command -v python3 >/dev/null 2>&1; then
    send_with_python "$url" "$payload"
  fi
}

case "$EVENT_TYPE" in
  install_*) ;;
  *) exit 0 ;;
esac

install_reporting_disabled && exit 0

INSTALL_ID="$(ensure_install_id)"
[ -n "$INSTALL_ID" ] || exit 0

PACKAGE_MANAGER="$(detect_package_manager)"
MEDIUM="${VEXYL_INSTALL_MEDIUM:-$PACKAGE_MANAGER}"
AGENT_VERSION="$(detect_agent_version)"
[ -n "$AGENT_VERSION" ] || AGENT_VERSION="unknown"
RELEASE_VERSION="$(detect_release_version)"
[ -n "$RELEASE_VERSION" ] || RELEASE_VERSION="$AGENT_VERSION"
DISTRO_ID="$(os_release_field ID)"
DISTRO_VERSION_ID="$(os_release_field VERSION_ID)"

payload=$(printf '{"event_type":"%s","install_id":"%s","install_method":"%s","source":"%s","medium":"%s","campaign":"%s","content":"%s","agent_version":"%s","release_version":"%s","distro_id":"%s","distro_version_id":"%s","package_manager":"%s","init_system":"%s","service_status":"%s","phase":"%s","error_code":"%s"}' \
  "$(json_escape "$EVENT_TYPE")" \
  "$(json_escape "$INSTALL_ID")" \
  "$(json_escape "$INSTALL_METHOD")" \
  "$(json_escape "$SOURCE")" \
  "$(json_escape "$MEDIUM")" \
  "$(json_escape "$CAMPAIGN")" \
  "$(json_escape "$CONTENT")" \
  "$(json_escape "$AGENT_VERSION")" \
  "$(json_escape "$RELEASE_VERSION")" \
  "$(json_escape "$DISTRO_ID")" \
  "$(json_escape "$DISTRO_VERSION_ID")" \
  "$(json_escape "$PACKAGE_MANAGER")" \
  "$(json_escape "$(detect_init_system)")" \
  "$(json_escape "$SERVICE_STATUS")" \
  "$(json_escape "$PHASE")" \
  "$(json_escape "$ERROR_CODE")")

send_payload "${REPORT_API_URL%/}/v1/growth/install" "$payload"
