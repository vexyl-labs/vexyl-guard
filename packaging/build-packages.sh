#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/dist/packages"
FORMAT="all"
RELEASE="1"
VERSION=""

usage() {
  cat <<'EOF'
Usage: packaging/build-packages.sh [options]

Options:
  --format deb|rpm|all     Package format to build. Default: all.
  --version VERSION        Version string. Default: agent VERSION.
  --release RELEASE        Package release number. Default: 1.
  --output-dir DIR         Output directory. Default: dist/packages.
  -h, --help               Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --release)
      RELEASE="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$FORMAT" in
  deb|rpm|all) ;;
  *)
    printf 'Unsupported --format: %s\n' "$FORMAT" >&2
    exit 2
    ;;
esac

if [ -z "$VERSION" ]; then
  VERSION="$(sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$ROOT_DIR/agent/vexyl-guard.sh" | head -n 1)"
fi
[ -n "$VERSION" ] || {
  printf 'Unable to detect agent version.\n' >&2
  exit 1
}

PACKAGE_VERSION="${VERSION#v}"
PACKAGE_RELEASE="${RELEASE#-}"
mkdir -p "$OUTPUT_DIR"

stage_tree() {
  dest="$1"
  agent_path="$2"
  cli_path="$3"
  service_path="$4"

  install -d -m 0755 "$dest/usr/share/doc/vexyl-guard"
  install -d -m 0755 "$dest/usr/lib/vexyl"
  install -d -m 0755 "$dest/opt/vexyl/intel"
  install -d -m 0755 "$dest/$(dirname "$agent_path")" "$dest/$(dirname "$cli_path")"
  install -d -m 0755 "$dest/$(dirname "$service_path")"
  install -d -m 0750 "$dest/etc/vexyl"
  install -d -m 0755 "$dest/etc/vexyl/policy-keys.d"
  install -d -m 0750 "$dest/var/lib/vexyl"

  install -m 0755 "$ROOT_DIR/agent/vexyl-guard.sh" "$dest/$agent_path"
  install -m 0755 "$ROOT_DIR/vexyl" "$dest/$cli_path"
  install -m 0755 "$ROOT_DIR/packaging/install-report.sh" "$dest/usr/lib/vexyl/install-report.sh"
  install -m 0644 "$ROOT_DIR"/intel/*.py "$dest/opt/vexyl/intel/"

  install -m 0640 "$ROOT_DIR/config/vexyl-guard.conf.example" "$dest/etc/vexyl/guard.conf"
  sed -i "s#^VEXYL_AGENT_BIN=.*#VEXYL_AGENT_BIN=/$agent_path#" "$dest/etc/vexyl/guard.conf"
  if [ -f "$ROOT_DIR/config/release-signing-public.pem" ]; then
    install -m 0644 "$ROOT_DIR/config/release-signing-public.pem" "$dest/etc/vexyl/release-signing-public.pem"
  fi
  if [ -f "$ROOT_DIR/config/policy-signing-public.pem" ]; then
    install -m 0644 "$ROOT_DIR/config/policy-signing-public.pem" "$dest/etc/vexyl/policy-signing-public.pem"
    install -m 0644 "$ROOT_DIR/config/policy-signing-public.pem" "$dest/etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem"
  fi
  : >"$dest/etc/vexyl/revoked-policy-keys.txt"
  chmod 0644 "$dest/etc/vexyl/revoked-policy-keys.txt"

  sed "s#^ExecStart=.*#ExecStart=/$agent_path daemon#" "$ROOT_DIR/packaging/vexyl-guard.service" >"$dest/$service_path"
  chmod 0644 "$dest/$service_path"

  install -m 0644 "$ROOT_DIR/LICENSE" "$dest/usr/share/doc/vexyl-guard/LICENSE"
  install -m 0644 "$ROOT_DIR/NOTICE" "$dest/usr/share/doc/vexyl-guard/NOTICE"
  install -m 0644 "$ROOT_DIR/README.md" "$dest/usr/share/doc/vexyl-guard/README.md"
}

write_postinst() {
  target="$1"
  cat >"$target" <<'EOF'
#!/bin/sh
set -e

report_install() {
  event_type="$1"
  phase="$2"
  error_code="${3:-}"
  service_status="${4:-}"
  if [ -x /usr/lib/vexyl/install-report.sh ]; then
    VEXYL_REPORT_INSTALL_METHOD=package \
      VEXYL_REPORT_PACKAGE_MANAGER=apt \
      VEXYL_REPORT_EVENT_TYPE="$event_type" \
      VEXYL_REPORT_PHASE="$phase" \
      VEXYL_REPORT_ERROR_CODE="$error_code" \
      VEXYL_REPORT_SERVICE_STATUS="$service_status" \
      /usr/lib/vexyl/install-report.sh >/dev/null 2>&1 || true
  fi
}

install -d -m 0750 /etc/vexyl /var/lib/vexyl
install -d -m 0755 /etc/vexyl/policy-keys.d
report_install install_started package_configure "" configuring

if [ ! -f /etc/vexyl/revoked-policy-keys.txt ]; then
  : >/etc/vexyl/revoked-policy-keys.txt
  chmod 0644 /etc/vexyl/revoked-policy-keys.txt
fi
if [ -f /etc/vexyl/policy-signing-public.pem ] && [ ! -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem ]; then
  cp /etc/vexyl/policy-signing-public.pem /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
  chmod 0644 /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
fi
if command -v vexyl >/dev/null 2>&1; then
  vexyl threat --db /var/lib/vexyl/ai_threats.sqlite seed >/dev/null 2>&1 || true
fi

service_status=systemctl_missing
service_error=
if command -v systemctl >/dev/null 2>&1; then
  service_status=unknown
  systemctl daemon-reload >/dev/null 2>&1 || service_error=daemon_reload_failed
  if systemctl enable vexyl-guard >/dev/null 2>&1; then
    service_status=enabled
  else
    service_status=enable_failed
    [ -n "$service_error" ] || service_error=systemd_enable_failed
  fi
fi

report_install install_completed package_configured "$service_error" "$service_status"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vexyl-guard >/dev/null 2>&1; then
  report_install install_service_started service_check "" running
elif [ -n "$service_error" ]; then
  report_install install_service_failed service_check "$service_error" "$service_status"
fi
EOF
  chmod 0755 "$target"
}

write_prerm() {
  target="$1"
  cat >"$target" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop vexyl-guard >/dev/null 2>&1 || true
  systemctl disable vexyl-guard >/dev/null 2>&1 || true
fi
EOF
  chmod 0755 "$target"
}

write_postrm() {
  target="$1"
  cat >"$target" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = "purge" ]; then
  rm -rf /etc/vexyl /var/lib/vexyl
fi
EOF
  chmod 0755 "$target"
}

build_deb() {
  command -v dpkg-deb >/dev/null 2>&1 || {
    printf 'dpkg-deb is required to build .deb packages.\n' >&2
    exit 1
  }

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  root="$tmp/vexyl-guard_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_all"
  stage_tree "$root" "usr/sbin/vexyl-guard" "usr/bin/vexyl" "usr/lib/systemd/system/vexyl-guard.service"

  install -d -m 0755 "$root/DEBIAN"
  installed_size="$(du -ks "$root" | awk '{print $1}')"
  cat >"$root/DEBIAN/control" <<EOF
Package: vexyl-guard
Version: ${PACKAGE_VERSION}-${PACKAGE_RELEASE}
Section: admin
Priority: optional
Architecture: all
Maintainer: Vexyl Labs <security@vexyl.dev>
Depends: bash, python3, systemd
Recommends: curl, nftables | iptables
Installed-Size: ${installed_size}
Homepage: https://vexyl.dev
License: Apache-2.0
Description: Lightweight Linux server security agent
 Vexyl Guard watches exposed Linux hosts for hostile automation and suspicious
 access patterns. It starts in monitor mode and can apply local firewall
 enforcement after operators enable policy.
EOF
  cat >"$root/DEBIAN/conffiles" <<'EOF'
/etc/vexyl/guard.conf
/etc/vexyl/revoked-policy-keys.txt
EOF
  write_postinst "$root/DEBIAN/postinst"
  write_prerm "$root/DEBIAN/prerm"
  write_postrm "$root/DEBIAN/postrm"

  package="$OUTPUT_DIR/vexyl-guard_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_all.deb"
  dpkg-deb --build --root-owner-group "$root" "$package" >/dev/null
  printf '%s\n' "$package"
}

build_rpm() {
  command -v rpmbuild >/dev/null 2>&1 || {
    if [ "$FORMAT" = "all" ]; then
      printf 'Skipping .rpm build because rpmbuild is not installed.\n' >&2
      return 0
    fi
    printf 'rpmbuild is required to build .rpm packages.\n' >&2
    exit 1
  }

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  topdir="$tmp/rpmbuild"
  sourcedir="$topdir/SOURCES"
  specdir="$topdir/SPECS"
  buildroot_source="$tmp/vexyl-guard-${PACKAGE_VERSION}"
  install -d -m 0755 "$sourcedir" "$specdir" "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SRPMS"
  stage_tree "$buildroot_source" "usr/sbin/vexyl-guard" "usr/bin/vexyl" "usr/lib/systemd/system/vexyl-guard.service"

  tar -C "$tmp" -czf "$sourcedir/vexyl-guard-${PACKAGE_VERSION}.tar.gz" "vexyl-guard-${PACKAGE_VERSION}"
  spec="$specdir/vexyl-guard.spec"
  cat >"$spec" <<EOF
Name: vexyl-guard
Version: ${PACKAGE_VERSION}
Release: ${PACKAGE_RELEASE}%{?dist}
Summary: Lightweight Linux server security agent
License: Apache-2.0
URL: https://vexyl.dev
BuildArch: noarch
Requires: bash
Requires: python3
Recommends: curl
Recommends: nftables
Source0: %{name}-%{version}.tar.gz

%description
Vexyl Guard watches exposed Linux hosts for hostile automation and suspicious
access patterns. It starts in monitor mode and can apply local firewall
enforcement after operators enable policy.

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}
cp -a . %{buildroot}/

%post
report_install() {
  event_type="\$1"
  phase="\$2"
  error_code="\${3:-}"
  service_status="\${4:-}"
  if [ -x /usr/lib/vexyl/install-report.sh ]; then
    VEXYL_REPORT_INSTALL_METHOD=package \\
      VEXYL_REPORT_PACKAGE_MANAGER=dnf \\
      VEXYL_REPORT_EVENT_TYPE="\$event_type" \\
      VEXYL_REPORT_PHASE="\$phase" \\
      VEXYL_REPORT_ERROR_CODE="\$error_code" \\
      VEXYL_REPORT_SERVICE_STATUS="\$service_status" \\
      /usr/lib/vexyl/install-report.sh >/dev/null 2>&1 || true
  fi
}

install -d -m 0750 /etc/vexyl /var/lib/vexyl
install -d -m 0755 /etc/vexyl/policy-keys.d
report_install install_started package_configure "" configuring

if [ ! -f /etc/vexyl/revoked-policy-keys.txt ]; then
  : >/etc/vexyl/revoked-policy-keys.txt
  chmod 0644 /etc/vexyl/revoked-policy-keys.txt
fi
if [ -f /etc/vexyl/policy-signing-public.pem ] && [ ! -f /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem ]; then
  cp /etc/vexyl/policy-signing-public.pem /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
  chmod 0644 /etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
fi
if command -v vexyl >/dev/null 2>&1; then
  vexyl threat --db /var/lib/vexyl/ai_threats.sqlite seed >/dev/null 2>&1 || true
fi
service_status=systemctl_missing
service_error=
if command -v systemctl >/dev/null 2>&1; then
  service_status=unknown
  systemctl daemon-reload >/dev/null 2>&1 || service_error=daemon_reload_failed
  if systemctl enable vexyl-guard >/dev/null 2>&1; then
    service_status=enabled
  else
    service_status=enable_failed
    [ -n "\$service_error" ] || service_error=systemd_enable_failed
  fi
fi
report_install install_completed package_configured "\$service_error" "\$service_status"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vexyl-guard >/dev/null 2>&1; then
  report_install install_service_started service_check "" running
elif [ -n "\$service_error" ]; then
  report_install install_service_failed service_check "\$service_error" "\$service_status"
fi

%preun
if [ "\$1" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop vexyl-guard >/dev/null 2>&1 || true
  systemctl disable vexyl-guard >/dev/null 2>&1 || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%license /usr/share/doc/vexyl-guard/LICENSE
%doc /usr/share/doc/vexyl-guard/NOTICE
%doc /usr/share/doc/vexyl-guard/README.md
%config(noreplace) /etc/vexyl/guard.conf
%config(noreplace) /etc/vexyl/revoked-policy-keys.txt
/etc/vexyl/release-signing-public.pem
/etc/vexyl/policy-signing-public.pem
/etc/vexyl/policy-keys.d/vexyl-policy-dev-1.pem
%dir /usr/lib/vexyl
/usr/lib/vexyl/install-report.sh
%dir /opt/vexyl
%dir /opt/vexyl/intel
/opt/vexyl/intel/*.py
/usr/bin/vexyl
/usr/sbin/vexyl-guard
/usr/lib/systemd/system/vexyl-guard.service
%dir /var/lib/vexyl
EOF

  rpmbuild --define "_topdir $topdir" -ba "$spec" >/dev/null
  cp "$topdir"/RPMS/noarch/vexyl-guard-"${PACKAGE_VERSION}"-"${PACKAGE_RELEASE}"*.noarch.rpm "$OUTPUT_DIR"/
  ls "$OUTPUT_DIR"/vexyl-guard-"${PACKAGE_VERSION}"-"${PACKAGE_RELEASE}"*.noarch.rpm
}

case "$FORMAT" in
  deb) build_deb ;;
  rpm) build_rpm ;;
  all)
    build_deb
    build_rpm
    ;;
esac
