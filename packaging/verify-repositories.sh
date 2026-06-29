#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-}"
PUBLIC_KEY="${2:-}"

if [ -z "$REPO_DIR" ]; then
  printf 'Usage: %s REPO_DIR [PUBLIC_KEY]\n' "$0" >&2
  exit 2
fi

[ -d "$REPO_DIR" ] || {
  printf 'Repository directory does not exist: %s\n' "$REPO_DIR" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || {
    printf 'Missing required repository file: %s\n' "$1" >&2
    exit 1
  }
}

require_file "$REPO_DIR/vexyl-packages.asc"
require_file "$REPO_DIR/vexyl-packages.gpg"
require_file "$REPO_DIR/vexyl.sources"
require_file "$REPO_DIR/vexyl.repo"
require_file "$REPO_DIR/apt/dists/stable/Release"
require_file "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages"
require_file "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages.gz"
require_file "$REPO_DIR/rpm/repodata/repomd.xml"

if find "$REPO_DIR" -type f | grep -E 'private|\.env|\.dev\.vars|codex_vexyl_guard_ai_threat_brief|vexyl_guard_ai_threats_seed|vexyl_guard_ai_threat_schema' >/dev/null; then
  printf 'Repository contains a private or intentionally excluded file name.\n' >&2
  exit 1
fi

gzip -t "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages.gz"
grep -q '^Package: vexyl-guard$' "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages"
grep -q '^Filename: pool/main/v/vexyl-guard/vexyl-guard_' "$REPO_DIR/apt/dists/stable/main/binary-amd64/Packages"
find "$REPO_DIR/apt/pool/main/v/vexyl-guard" -maxdepth 1 -type f -name 'vexyl-guard_*_all.deb' | grep -q .
find "$REPO_DIR/rpm/packages" -maxdepth 1 -type f -name 'vexyl-guard-*.noarch.rpm' | grep -q .
find "$REPO_DIR/rpm/repodata" -maxdepth 1 -type f -name '*primary.xml.gz' | grep -q .

if [ -n "$PUBLIC_KEY" ]; then
  require_file "$PUBLIC_KEY"
  require_file "$REPO_DIR/apt/dists/stable/InRelease"
  require_file "$REPO_DIR/apt/dists/stable/Release.gpg"
  require_file "$REPO_DIR/rpm/repodata/repomd.xml.asc"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  chmod 0700 "$tmp"
  GNUPGHOME="$tmp" gpg --batch --import "$PUBLIC_KEY" >/dev/null
  GNUPGHOME="$tmp" gpg --batch --verify "$REPO_DIR/apt/dists/stable/InRelease" >/dev/null
  GNUPGHOME="$tmp" gpg --batch --verify \
    "$REPO_DIR/apt/dists/stable/Release.gpg" \
    "$REPO_DIR/apt/dists/stable/Release" >/dev/null
  GNUPGHOME="$tmp" gpg --batch --verify \
    "$REPO_DIR/rpm/repodata/repomd.xml.asc" \
    "$REPO_DIR/rpm/repodata/repomd.xml" >/dev/null
fi

printf 'Verified package repositories: %s\n' "$REPO_DIR"
