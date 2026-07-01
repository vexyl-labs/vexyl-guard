#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${VEXYL_LIVE_REPO_BASE_URL:-https://vexyl.dev/repo}"
APT_IMAGE="${VEXYL_APT_SMOKE_IMAGE:-debian:12-slim}"
DNF_IMAGE="${VEXYL_DNF_SMOKE_IMAGE:-rockylinux:9}"
RUN_APT=true
RUN_DNF=true

usage() {
  cat <<'EOF'
Usage: packaging/smoke-install-live-repositories.sh [options]

Install Vexyl Guard from the live public APT and DNF repositories inside
disposable Docker containers. This catches CDN, signing, and repository
publishing drift after release assets are promoted.

Options:
  --base-url URL     Live repository base URL. Default: https://vexyl.dev/repo
  --apt-image IMAGE  Debian/Ubuntu image for APT canary.
  --dnf-image IMAGE  Fedora/RHEL-compatible image for DNF canary.
  --apt-only         Run only the APT canary.
  --dnf-only         Run only the DNF canary.
  -h, --help         Show this help.

Environment:
  VEXYL_LIVE_REPO_BASE_URL
  VEXYL_APT_SMOKE_IMAGE
  VEXYL_DNF_SMOKE_IMAGE
EOF
}

log() {
  printf '[live-install-canary] %s\n' "$*"
}

die() {
  printf '[live-install-canary] error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-url)
      shift
      [ "${1:-}" ] || die "--base-url requires a value"
      BASE_URL="$1"
      ;;
    --apt-image)
      shift
      [ "${1:-}" ] || die "--apt-image requires a value"
      APT_IMAGE="$1"
      ;;
    --dnf-image)
      shift
      [ "${1:-}" ] || die "--dnf-image requires a value"
      DNF_IMAGE="$1"
      ;;
    --apt-only)
      RUN_APT=true
      RUN_DNF=false
      ;;
    --dnf-only)
      RUN_APT=false
      RUN_DNF=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
  shift
done

BASE_URL="${BASE_URL%/}"

require_command docker

docker_run() {
  local image="$1"
  shift
  docker run --rm \
    --env VEXYL_INSTALL_REPORT=off \
    --env VEXYL_REPO_BASE_URL="$BASE_URL" \
    --tmpfs /tmp:exec \
    "$image" "$@"
}

run_apt_canary() {
  log "running live APT install canary with $APT_IMAGE from $BASE_URL"
  docker_run "$APT_IMAGE" bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    export VEXYL_INSTALL_REPORT=off

    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl gnupg

    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "$VEXYL_REPO_BASE_URL/vexyl-packages.asc" \
      -o /etc/apt/keyrings/vexyl-packages.asc
    curl -fsSL "$VEXYL_REPO_BASE_URL/vexyl.sources" \
      -o /etc/apt/sources.list.d/vexyl.sources

    grep -q "URIs: $VEXYL_REPO_BASE_URL/apt" /etc/apt/sources.list.d/vexyl.sources
    grep -q "Signed-By: /etc/apt/keyrings/vexyl-packages.asc" /etc/apt/sources.list.d/vexyl.sources

    apt-get update
    apt-get install -y --no-install-recommends vexyl-guard

    dpkg-query -W vexyl-guard
    test -x /usr/sbin/vexyl-guard
    test -x /usr/bin/vexyl
    test -x /usr/lib/vexyl/install-report.sh
    test -f /usr/lib/systemd/system/vexyl-guard.service
    test -f /etc/vexyl/guard.conf
    test -f /etc/vexyl/release-signing-public.pem
    test -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
    /usr/sbin/vexyl-guard status | grep -q "Vexyl Guard"
    vexyl threat --db /var/lib/vexyl/ai_threats.sqlite search prompt | grep -qi prompt
  '
}

run_dnf_canary() {
  log "running live DNF install canary with $DNF_IMAGE from $BASE_URL"
  docker_run "$DNF_IMAGE" bash -ceu '
    export VEXYL_INSTALL_REPORT=off

    curl -fsSL "$VEXYL_REPO_BASE_URL/vexyl.repo" -o /etc/yum.repos.d/vexyl.repo
    grep -q "baseurl=$VEXYL_REPO_BASE_URL/rpm" /etc/yum.repos.d/vexyl.repo
    grep -q "^gpgcheck=1$" /etc/yum.repos.d/vexyl.repo
    grep -q "^repo_gpgcheck=1$" /etc/yum.repos.d/vexyl.repo

    dnf -y --setopt=install_weak_deps=False install vexyl-guard

    rpm -q vexyl-guard
    test -x /usr/sbin/vexyl-guard
    test -x /usr/bin/vexyl
    test -x /usr/lib/vexyl/install-report.sh
    test -f /usr/lib/systemd/system/vexyl-guard.service
    test -f /etc/vexyl/guard.conf
    test -f /etc/vexyl/release-signing-public.pem
    test -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
    /usr/sbin/vexyl-guard status | grep -q "Vexyl Guard"
    vexyl threat --db /var/lib/vexyl/ai_threats.sqlite search prompt | grep -qi prompt
  '
}

[ "$RUN_APT" = true ] && run_apt_canary
[ "$RUN_DNF" = true ] && run_dnf_canary

log "live package-manager install canaries passed"
