#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGES_DIR="$ROOT_DIR/dist/packages"
OUTPUT_DIR="$ROOT_DIR/dist/repositories"
BASE_URL="https://vexyl.dev/repo"
SIGNING_KEY="${VEXYL_PACKAGE_REPO_SIGNING_KEY:-}"
PUBLIC_KEY="$ROOT_DIR/config/vexyl-package-repo-signing-public.asc"
SUITE="stable"
ARCH="amd64"
TMP_PATHS=()
GNUPGHOME_DIR=""
GPG_FINGERPRINT=""

usage() {
  cat <<'EOF'
Usage: packaging/build-repositories.sh [options]

Options:
  --packages-dir DIR      Directory containing vexyl-guard .deb and .rpm files.
                          Default: dist/packages.
  --output-dir DIR        Repository output root. Default: dist/repositories.
  --base-url URL          Public repository base URL. Default: https://vexyl.dev/repo.
  --signing-key FILE      ASCII-armored private GPG key for repo metadata signing.
                          Can also be set with VEXYL_PACKAGE_REPO_SIGNING_KEY.
  --public-key FILE       Public GPG key to publish when not signing. Default:
                          config/vexyl-package-repo-signing-public.asc.
  --suite NAME            APT suite/codename. Default: stable.
  --arch ARCH             APT architecture index to publish. Default: amd64.
  -h, --help              Show this help.
EOF
}

cleanup() {
  local path
  for path in "${TMP_PATHS[@]}"; do
    [ -n "$path" ] && rm -rf "$path"
  done
}
trap cleanup EXIT INT TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --packages-dir)
      PACKAGES_DIR="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --signing-key)
      SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --public-key)
      PUBLIC_KEY="${2:-}"
      shift 2
      ;;
    --suite)
      SUITE="${2:-}"
      shift 2
      ;;
    --arch)
      ARCH="${2:-}"
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

BASE_URL="${BASE_URL%/}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  }
}

require_package() {
  pattern="$1"
  matches="$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name "$pattern" | sort)"
  [ -n "$matches" ] || {
    printf 'No package matching %s in %s\n' "$pattern" "$PACKAGES_DIR" >&2
    exit 1
  }
  printf '%s\n' "$matches" | head -n 1
}

setup_gpg() {
  require_command gpg
  GNUPGHOME_DIR="$(mktemp -d)"
  chmod 0700 "$GNUPGHOME_DIR"
  TMP_PATHS+=("$GNUPGHOME_DIR")

  if [ -n "$SIGNING_KEY" ]; then
    [ -f "$SIGNING_KEY" ] || {
      printf 'Signing key does not exist: %s\n' "$SIGNING_KEY" >&2
      exit 1
    }
    GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --import "$SIGNING_KEY" >/dev/null
    GPG_FINGERPRINT="$(
      GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --with-colons --list-secret-keys |
        awk -F: '/^fpr:/ { print $10; exit }'
    )"
    [ -n "$GPG_FINGERPRINT" ] || {
      printf 'Signing key did not contain a usable secret key.\n' >&2
      exit 1
    }
    GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --armor --export "$GPG_FINGERPRINT" >"$OUTPUT_DIR/vexyl-packages.asc"
  else
    [ -f "$PUBLIC_KEY" ] || {
      printf 'Public key does not exist: %s\n' "$PUBLIC_KEY" >&2
      exit 1
    }
    cp "$PUBLIC_KEY" "$OUTPUT_DIR/vexyl-packages.asc"
  fi

  GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --yes --dearmor \
    -o "$OUTPUT_DIR/vexyl-packages.gpg" \
    "$OUTPUT_DIR/vexyl-packages.asc"
}

sign_file() {
  source_file="$1"
  output_file="$2"
  mode="$3"

  [ -n "$GPG_FINGERPRINT" ] || return 0
  case "$mode" in
    clearsign)
      GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --yes --local-user "$GPG_FINGERPRINT" \
        --clearsign -o "$output_file" "$source_file"
      ;;
    detach)
      GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --yes --local-user "$GPG_FINGERPRINT" \
        --armor --detach-sign -o "$output_file" "$source_file"
      ;;
    *)
      printf 'Unknown sign mode: %s\n' "$mode" >&2
      exit 2
      ;;
  esac
}

write_configs() {
  cat >"$OUTPUT_DIR/vexyl.sources" <<EOF
Types: deb
URIs: $BASE_URL/apt
Suites: $SUITE
Components: main
Architectures: $ARCH
Signed-By: /etc/apt/keyrings/vexyl-packages.asc
EOF

  cat >"$OUTPUT_DIR/vexyl.repo" <<EOF
[vexyl]
name=Vexyl Guard
baseurl=$BASE_URL/rpm
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=$BASE_URL/vexyl-packages.asc
metadata_expire=1h
EOF
}

build_apt_repo() {
  require_command dpkg-scanpackages
  require_command apt-ftparchive
  require_command gzip

  deb_package="$(require_package 'vexyl-guard_*_all.deb')"
  apt_root="$OUTPUT_DIR/apt"
  pool_dir="$apt_root/pool/main/v/vexyl-guard"
  binary_dir="$apt_root/dists/$SUITE/main/binary-$ARCH"

  install -d -m 0755 "$pool_dir" "$binary_dir"
  cp "$deb_package" "$pool_dir/"

  (
    cd "$apt_root"
    dpkg-scanpackages --multiversion pool /dev/null >"dists/$SUITE/main/binary-$ARCH/Packages"
    gzip -9fk "dists/$SUITE/main/binary-$ARCH/Packages"
  )

  release_conf="$(mktemp)"
  TMP_PATHS+=("$release_conf")
  cat >"$release_conf" <<EOF
APT::FTPArchive::Release::Origin "Vexyl Labs";
APT::FTPArchive::Release::Label "Vexyl Guard";
APT::FTPArchive::Release::Suite "$SUITE";
APT::FTPArchive::Release::Codename "$SUITE";
APT::FTPArchive::Release::Architectures "$ARCH";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "Vexyl Guard package repository";
EOF

  apt-ftparchive -c "$release_conf" release "$apt_root/dists/$SUITE" >"$apt_root/dists/$SUITE/Release"
  sign_file "$apt_root/dists/$SUITE/Release" "$apt_root/dists/$SUITE/InRelease" clearsign
  sign_file "$apt_root/dists/$SUITE/Release" "$apt_root/dists/$SUITE/Release.gpg" detach
}

build_rpm_repo() {
  require_command createrepo_c

  rpm_package="$(require_package 'vexyl-guard-*.noarch.rpm')"
  rpm_root="$OUTPUT_DIR/rpm"
  package_dir="$rpm_root/packages"

  install -d -m 0755 "$package_dir"
  cp "$rpm_package" "$package_dir/"
  createrepo_c --quiet "$rpm_root"
  sign_file "$rpm_root/repodata/repomd.xml" "$rpm_root/repodata/repomd.xml.asc" detach
}

rm -rf "$OUTPUT_DIR"
install -d -m 0755 "$OUTPUT_DIR"

setup_gpg
write_configs
build_apt_repo
build_rpm_repo

if [ -z "$GPG_FINGERPRINT" ]; then
  printf 'Built unsigned repository metadata in %s. Pass --signing-key for signed repos.\n' "$OUTPUT_DIR" >&2
else
  printf 'Built signed package repositories in %s\n' "$OUTPUT_DIR"
fi
