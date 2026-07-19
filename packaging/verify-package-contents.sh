#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  printf 'Usage: %s PACKAGE [...]\n' "$0" >&2
  exit 2
fi

for package in "$@"; do
  case "$package" in
    *.deb)
      command -v dpkg-deb >/dev/null 2>&1 || {
        printf 'dpkg-deb is required to inspect %s\n' "$package" >&2
        exit 1
      }
      contents="$(dpkg-deb -c "$package" | awk '{print $NF}')"
      ;;
    *.rpm)
      command -v rpm >/dev/null 2>&1 || {
        printf 'rpm is required to inspect %s\n' "$package" >&2
        exit 1
      }
      contents="$(rpm --nosignature -qpl "$package")"
      ;;
    *)
      printf 'Unsupported package type: %s\n' "$package" >&2
      exit 2
      ;;
  esac

  printf '%s\n' "$contents" | grep -En 'vexyl_guard_ai_threat_schema\.sql|vexyl_guard_ai_threats_seed\.jsonl|cloudflare/|docs/research/|codex_vexyl_guard_ai_threat_brief|\.env|\.dev\.vars|private\.pem|private\.der' && {
    printf 'Package includes private or intentionally excluded files: %s\n' "$package" >&2
    exit 1
  }

  for required in \
    "/usr/sbin/vexyl-guard" \
    "/usr/bin/vexyl" \
    "/usr/lib/vexyl/install-report.sh" \
    "/opt/vexyl/intel/cli.py" \
    "/opt/vexyl/intel/database.py" \
    "/opt/vexyl/intel/gateway.py" \
    "/opt/vexyl/intel/integration.py" \
    "/opt/vexyl/intel/middleware.py" \
    "/opt/vexyl/intel/updates.py" \
    "/usr/share/vexyl/integrations/node/vexyl-guard-client.mjs" \
    "/usr/share/vexyl/integrations/node/vexyl-guard-middleware.mjs" \
    "/etc/vexyl/guard.conf" \
    "/etc/vexyl/ai-gateway.conf" \
    "/etc/vexyl/intel-update.conf" \
    "/usr/lib/systemd/system/vexyl-ai-gateway.service" \
    "/usr/lib/systemd/system/vexyl-intel-update.service" \
    "/usr/lib/systemd/system/vexyl-intel-update.timer" \
    "/usr/lib/systemd/system/vexyl-guard.service"; do
    if ! printf '%s\n' "$contents" | sed 's#^\./#/#' | grep -Eq "^${required}$"; then
      printf 'Package is missing required path %s: %s\n' "$required" "$package" >&2
      exit 1
    fi
  done

  printf 'Verified package contents: %s\n' "$package"
done
