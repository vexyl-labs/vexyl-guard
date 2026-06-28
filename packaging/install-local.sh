#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_SOURCE="$ROOT_DIR/.vexyl-agent.conf"

ensure_setting() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" /etc/vexyl/guard.conf; then
    printf '%s=%s\n' "$key" "$value" >>/etc/vexyl/guard.conf
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  printf 'Run as root: sudo %s\n' "$0" >&2
  exit 1
fi

install -m 0755 "$ROOT_DIR/agent/vexyl-guard.sh" /usr/local/sbin/vexyl-guard
install -d -m 0750 /etc/vexyl /var/lib/vexyl
install -d -m 0755 /etc/vexyl/policy-keys.d
install -d -m 0755 /opt/vexyl
rm -rf /opt/vexyl/intel
cp -R "$ROOT_DIR/intel" /opt/vexyl/intel
find /opt/vexyl/intel -type d -exec chmod 0755 {} \;
find /opt/vexyl/intel -type f -exec chmod 0644 {} \;
install -m 0755 "$ROOT_DIR/vexyl" /usr/local/bin/vexyl
if [ -f "$ROOT_DIR/config/release-signing-public.pem" ]; then
  install -m 0644 "$ROOT_DIR/config/release-signing-public.pem" /etc/vexyl/release-signing-public.pem
fi
if [ -f "$ROOT_DIR/cloudflare/site/public/downloads/RELEASE.json" ]; then
  install -m 0644 "$ROOT_DIR/cloudflare/site/public/downloads/RELEASE.json" /var/lib/vexyl/release.json
fi
if [ -f "$ROOT_DIR/config/policy-signing-public.pem" ]; then
  install -m 0644 "$ROOT_DIR/config/policy-signing-public.pem" /etc/vexyl/policy-signing-public.pem
  install -m 0644 "$ROOT_DIR/config/policy-signing-public.pem" /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
fi
[ -f /etc/vexyl/revoked-policy-keys.txt ] || install -m 0644 /dev/null /etc/vexyl/revoked-policy-keys.txt

if [ -f "$CONFIG_SOURCE" ]; then
  install -m 0640 "$CONFIG_SOURCE" /etc/vexyl/guard.conf
  sed -i 's#^VEXYL_STATE_DIR=.*#VEXYL_STATE_DIR=/var/lib/vexyl#' /etc/vexyl/guard.conf
  sed -i 's#^VEXYL_CONFIG_DIR=.*#VEXYL_CONFIG_DIR=/etc/vexyl#' /etc/vexyl/guard.conf
else
  install -m 0640 "$ROOT_DIR/config/vexyl-guard.conf.example" /etc/vexyl/guard.conf
fi

ensure_setting "VEXYL_WEB_LOGS" '"/var/log/nginx/access.log /var/log/nginx/*access.log /var/log/apache2/access.log /var/log/httpd/access_log /var/log/caddy/access.log"'
ensure_setting "VEXYL_MAIL_LOGS" '"/var/log/mail.log /var/log/maillog"'
ensure_setting "VEXYL_FIREWALL_LOGS" '"/var/log/kern.log /var/log/ufw.log"'
ensure_setting "VEXYL_VPN_LOGS" '"/var/log/openvpn.log /var/log/openvpn/*.log /var/log/strongswan.log /var/log/charon.log /var/log/wireguard.log"'
ensure_setting "VEXYL_DATABASE_LOGS" '"/var/log/postgresql/*.log /var/log/mysql/error.log /var/log/mysqld.log /var/log/mariadb/mariadb.log /var/log/mongodb/mongod.log"'
ensure_setting "VEXYL_OBJECT_STORAGE_LOGS" '"/var/log/minio.log /var/log/minio/*.log /var/log/s3/access.log /var/log/s3/*.log /var/log/aws/s3*.log"'
ensure_setting "VEXYL_EDGE_LOGS" '"/var/log/cloudflare.log /var/log/cloudflare/*.log /var/log/cdn/*.log /var/log/edge/*.log /var/log/waf/*.log"'
ensure_setting "VEXYL_AGENT_BIN" "/usr/local/sbin/vexyl-guard"
ensure_setting "VEXYL_UPGRADE_BASE_URL" "https://vexyl.dev"
ensure_setting "VEXYL_UPGRADE_ALLOW_DOWNGRADE" "false"
ensure_setting "VEXYL_UPGRADE_FORCE" "false"
ensure_setting "VEXYL_RELEASE_PUBLIC_KEY_FILE" "/etc/vexyl/release-signing-public.pem"
ensure_setting "VEXYL_POLICY_BUNDLE_ENABLED" "auto"
ensure_setting "VEXYL_POLICY_PUBLIC_KEY_DIR" "/etc/vexyl/policy-keys.d"
ensure_setting "VEXYL_POLICY_PUBLIC_KEY_FILE" "/etc/vexyl/policy-signing-public.pem"
ensure_setting "VEXYL_POLICY_REVOKED_KEYS_FILE" "/etc/vexyl/revoked-policy-keys.txt"
ensure_setting "VEXYL_POLICY_REVOKED_KEY_IDS" ""
ensure_setting "VEXYL_POLICY_SIGNING_SECRET" ""
ensure_setting "VEXYL_POLICY_KEY_ID" "vexyl-policy-dev-1"
ensure_setting "VEXYL_DECEPTION_PATHS" '"/.vexyl-canary /__vexyl/trap /vexyl-honey"'
ensure_setting "VEXYL_MUTATION_CATEGORY_THRESHOLD" "3"
ensure_setting "VEXYL_MUTATION_WEIGHT" "3"
ensure_setting "VEXYL_AI_INTEL_ENABLED" "auto"
ensure_setting "VEXYL_AI_INTEL_BIN" "vexyl"
ensure_setting "VEXYL_AI_INTEL_DB" "/var/lib/vexyl/ai_threats.sqlite"
ensure_setting "VEXYL_AI_INTEL_AUTO_SEED" "false"
ensure_setting "VEXYL_AI_INTEL_SIGNAL_SCORE" "70"
ensure_setting "VEXYL_AI_INTEL_SIGNAL_WEIGHT" "4"

/usr/local/bin/vexyl threat --db /var/lib/vexyl/ai_threats.sqlite seed >/dev/null

install -m 0644 "$ROOT_DIR/packaging/vexyl-guard.service" /etc/systemd/system/vexyl-guard.service
systemctl daemon-reload
systemctl enable vexyl-guard

printf 'Installed Vexyl Guard. Start with: systemctl start vexyl-guard\n'
printf 'Current mode is set in /etc/vexyl/guard.conf. Use monitor first, then enforce.\n'
printf 'AI threat intelligence seeded at /var/lib/vexyl/ai_threats.sqlite. Search with: vexyl threat search prompt\n'
