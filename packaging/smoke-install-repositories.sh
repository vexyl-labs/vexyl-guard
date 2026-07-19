#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$ROOT_DIR/dist/repositories"
APT_IMAGE="${VEXYL_APT_SMOKE_IMAGE:-debian:12-slim}"
DNF_IMAGE="${VEXYL_DNF_SMOKE_IMAGE:-rockylinux:9}"
RUN_APT=true
RUN_DNF=true

usage() {
  cat <<'EOF'
Usage: packaging/smoke-install-repositories.sh [REPO_DIR] [options]

Install Vexyl Guard from generated APT and DNF repositories inside disposable
Docker containers. This verifies package-manager install behavior, not only
package file structure.

Options:
  --repo-dir DIR      Repository output root. Default: dist/repositories.
  --apt-image IMAGE   Debian/Ubuntu image for APT smoke test.
  --dnf-image IMAGE   Fedora/RHEL-compatible image for DNF smoke test.
  --apt-only          Run only the APT smoke test.
  --dnf-only          Run only the DNF smoke test.
  -h, --help          Show this help.

Environment:
  VEXYL_APT_SMOKE_IMAGE
  VEXYL_DNF_SMOKE_IMAGE
EOF
}

log() {
  printf '[install-smoke] %s\n' "$*"
}

die() {
  printf '[install-smoke] error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_file() {
  [ -f "$1" ] || die "missing required file: $1"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-dir)
      shift
      [ "${1:-}" ] || die "--repo-dir requires a value"
      REPO_DIR="$1"
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
    -*)
      die "unknown option: $1"
      ;;
    *)
      REPO_DIR="$1"
      ;;
  esac
  shift
done

REPO_DIR="$(cd "$REPO_DIR" && pwd -P)"

require_command docker
require_file "$REPO_DIR/vexyl-packages.asc"
require_file "$REPO_DIR/apt/dists/stable/InRelease"
require_file "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages"
require_file "$REPO_DIR/rpm/repodata/repomd.xml"
require_file "$REPO_DIR/rpm/repodata/repomd.xml.asc"

docker_run() {
  local image="$1"
  shift
  docker run --rm \
    --env VEXYL_INSTALL_REPORT=off \
    --volume "$REPO_DIR:/repo:ro" \
    --tmpfs /tmp:exec \
    "$image" "$@"
}

run_apt_smoke() {
  log "running APT install smoke test with $APT_IMAGE"
  docker_run "$APT_IMAGE" bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    export VEXYL_INSTALL_REPORT=off

    apt-get update
    apt-get install -y --no-install-recommends ca-certificates gnupg

    install -d -m 0755 /etc/apt/keyrings
    cp /repo/vexyl-packages.asc /etc/apt/keyrings/vexyl-packages.asc
    cat >/etc/apt/sources.list.d/vexyl.sources <<EOF
Types: deb
URIs: file:/repo/apt
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/vexyl-packages.asc
EOF

    apt-get update
    apt-get install -y --no-install-recommends vexyl-guard

    dpkg-query -W vexyl-guard
    test -x /usr/sbin/vexyl-guard
    test -x /usr/bin/vexyl
    test -x /usr/lib/vexyl/install-report.sh
    test -f /usr/lib/systemd/system/vexyl-guard.service
    test -f /etc/vexyl/guard.conf
    grep -q "^VEXYL_AI_HISTORY_RETENTION_HOURS=24$" /etc/vexyl/guard.conf || {
      printf "APT package is missing the AI history retention default.\n" >&2
      exit 1
    }
    test -f /etc/vexyl/release-signing-public.pem
    test -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
    agent_status="$(/usr/sbin/vexyl-guard status)"
    grep -q "Vexyl Guard" <<<"$agent_status" || {
      printf "APT package agent status check failed:\n%s\n" "$agent_status" >&2
      exit 1
    }
    threat_search="$(vexyl threat --db /var/lib/vexyl/ai_threats.sqlite search prompt)"
    grep -qi prompt <<<"$threat_search" || {
      printf "APT package threat database search returned no prompt records.\n" >&2
      exit 1
    }
    runtime_status="$(vexyl threat --db /var/lib/vexyl/ai_threats.sqlite runtime-status)"
    grep -q "\"retention_hours\": 24" <<<"$runtime_status" || {
      printf "APT package runtime history status check failed:\n%s\n" "$runtime_status" >&2
      exit 1
    }
  '
}

run_dnf_smoke() {
  log "running DNF install smoke test with $DNF_IMAGE"
  docker_run "$DNF_IMAGE" bash -ceu '
    export VEXYL_INSTALL_REPORT=off

    rpm --import /repo/vexyl-packages.asc
    cat >/etc/yum.repos.d/vexyl.repo <<EOF
[vexyl]
name=Vexyl Guard
baseurl=file:///repo/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///repo/vexyl-packages.asc
metadata_expire=1h
EOF

    dnf -y --setopt=install_weak_deps=False install vexyl-guard

    rpm -q vexyl-guard
    test -x /usr/sbin/vexyl-guard
    test -x /usr/bin/vexyl
    test -x /usr/lib/vexyl/install-report.sh
    test -f /usr/lib/systemd/system/vexyl-guard.service
    test -f /etc/vexyl/guard.conf
    grep -q "^VEXYL_AI_HISTORY_RETENTION_HOURS=24$" /etc/vexyl/guard.conf || {
      printf "DNF package is missing the AI history retention default.\n" >&2
      exit 1
    }
    test -f /etc/vexyl/release-signing-public.pem
    test -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
    agent_status="$(/usr/sbin/vexyl-guard status)"
    grep -q "Vexyl Guard" <<<"$agent_status" || {
      printf "DNF package agent status check failed:\n%s\n" "$agent_status" >&2
      exit 1
    }
    threat_search="$(vexyl threat --db /var/lib/vexyl/ai_threats.sqlite search prompt)"
    grep -qi prompt <<<"$threat_search" || {
      printf "DNF package threat database search returned no prompt records.\n" >&2
      exit 1
    }
    runtime_status="$(vexyl threat --db /var/lib/vexyl/ai_threats.sqlite runtime-status)"
    grep -q "\"retention_hours\": 24" <<<"$runtime_status" || {
      printf "DNF package runtime history status check failed:\n%s\n" "$runtime_status" >&2
      exit 1
    }
  '
}

[ "$RUN_APT" = true ] && run_apt_smoke
[ "$RUN_DNF" = true ] && run_dnf_smoke

log "package-manager install smoke tests passed"
