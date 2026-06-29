#!/usr/bin/env bash
set -euo pipefail

SIGNING_KEY="${VEXYL_PACKAGE_REPO_SIGNING_KEY:-}"
RPM_PACKAGES=()
TMP_PATHS=()
GNUPGHOME_DIR=""
GPG_FINGERPRINT=""

usage() {
  cat <<'EOF'
Usage: packaging/sign-rpm-packages.sh [options] RPM [...]

Options:
  --signing-key FILE      ASCII-armored private GPG key for RPM package signing.
                          Can also be set with VEXYL_PACKAGE_REPO_SIGNING_KEY.
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
    --signing-key)
      SIGNING_KEY="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        RPM_PACKAGES+=("$1")
        shift
      done
      ;;
    --*)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      RPM_PACKAGES+=("$1")
      shift
      ;;
  esac
done

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  }
}

[ -n "$SIGNING_KEY" ] || {
  printf 'Missing signing key. Pass --signing-key or set VEXYL_PACKAGE_REPO_SIGNING_KEY.\n' >&2
  exit 2
}

[ -f "$SIGNING_KEY" ] || {
  printf 'Signing key does not exist: %s\n' "$SIGNING_KEY" >&2
  exit 1
}

[ "${#RPM_PACKAGES[@]}" -gt 0 ] || {
  printf 'At least one RPM package is required.\n' >&2
  usage >&2
  exit 2
}

require_command gpg
require_command rpm
require_command rpmsign

GNUPGHOME_DIR="$(mktemp -d)"
TMP_PATHS+=("$GNUPGHOME_DIR")
chmod 0700 "$GNUPGHOME_DIR"

GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --import "$SIGNING_KEY" >/dev/null
GPG_FINGERPRINT="$(
  GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --with-colons --list-secret-keys |
    awk -F: '/^fpr:/ { print $10; exit }'
)"

[ -n "$GPG_FINGERPRINT" ] || {
  printf 'Signing key did not contain a usable secret key.\n' >&2
  exit 1
}

for package in "${RPM_PACKAGES[@]}"; do
  checksig_output=""

  case "$package" in
    *.rpm) ;;
    *)
      printf 'Not an RPM package: %s\n' "$package" >&2
      exit 2
      ;;
  esac

  [ -f "$package" ] || {
    printf 'RPM package does not exist: %s\n' "$package" >&2
    exit 1
  }

  GNUPGHOME="$GNUPGHOME_DIR" rpmsign --addsign \
    --define "_signature gpg" \
    --define "_gpg_name $GPG_FINGERPRINT" \
    --define "_gpg_path $GNUPGHOME_DIR" \
    --define "__gpg /usr/bin/gpg" \
    --define "_gpg_digest_algo sha256" \
    "$package" >/dev/null

  checksig_output="$(rpm --checksig -v "$package" || true)"
  printf '%s\n' "$checksig_output" | grep -Eq 'Signature, key ID [0-9A-Fa-f]+: (OK|NOKEY)' || {
    printf 'RPM package does not show a package signature after signing: %s\n' "$package" >&2
    exit 1
  }

  printf 'Signed RPM package: %s\n' "$package"
done
