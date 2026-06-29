#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""
TAG=""
BRANCH="${VEXYL_RELEASE_BRANCH:-main}"
DO_COMMIT=false
DO_TAG=false
DO_PUSH=false
ALLOW_DIRTY=false
RELEASE_NOTES_FILE=""
TMP_PATHS=()

usage() {
  cat <<'EOF'
Usage:
  scripts/prepare-release.sh --version 0.2.9 [options]

Options:
  --version VERSION   Release version, for example 0.2.9 or v0.2.9. Required.
  --commit           Commit the version bump after checks pass.
  --tag              Create an annotated vVERSION tag after checks pass.
  --push             Push the release commit and tag to origin.
  --branch NAME      Branch to push when --push is used. Default: main.
  --notes-file FILE  Markdown release notes for the annotated tag.
  --allow-dirty      Allow tracked working-tree changes before the script runs.
                     Intended only for temporary local validation.
  --help             Show this help.
EOF
}

log() {
  printf '[release-prep] %s\n' "$*"
}

die() {
  printf '[release-prep] error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local path
  for path in "${TMP_PATHS[@]}"; do
    [ -n "$path" ] && rm -rf "$path"
  done
}
trap cleanup EXIT INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        shift
        [ "${1:-}" ] || die "--version requires a value"
        VERSION="$1"
        ;;
      --commit)
        DO_COMMIT=true
        ;;
      --tag)
        DO_TAG=true
        ;;
      --push)
        DO_PUSH=true
        ;;
      --branch)
        shift
        [ "${1:-}" ] || die "--branch requires a value"
        BRANCH="$1"
        ;;
      --notes-file)
        shift
        [ "${1:-}" ] || die "--notes-file requires a value"
        RELEASE_NOTES_FILE="$1"
        ;;
      --allow-dirty)
        ALLOW_DIRTY=true
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
    shift
  done
}

normalize_version() {
  VERSION="${VERSION#v}"
  case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) die "version must look like 0.2.9, got: ${VERSION:-<empty>}" ;;
  esac

  old_ifs="$IFS"
  IFS=.
  set -- $VERSION
  IFS="$old_ifs"
  [ "$#" -eq 3 ] || die "version must have major.minor.patch format: $VERSION"
  for part in "$@"; do
    case "$part" in
      ''|*[!0-9]*) die "version contains a non-numeric segment: $VERSION" ;;
    esac
  done

  TAG="v$VERSION"
}

version_gt() {
  left="$1"
  right="$2"
  old_ifs="$IFS"
  IFS=.
  set -- $left
  left_major="$1"
  left_minor="$2"
  left_patch="$3"
  set -- $right
  right_major="$1"
  right_minor="$2"
  right_patch="$3"
  IFS="$old_ifs"

  [ "$left_major" -gt "$right_major" ] && return 0
  [ "$left_major" -lt "$right_major" ] && return 1
  [ "$left_minor" -gt "$right_minor" ] && return 0
  [ "$left_minor" -lt "$right_minor" ] && return 1
  [ "$left_patch" -gt "$right_patch" ]
}

current_agent_version() {
  sed -n 's/^VERSION="\([^"]*\)".*/\1/p' "$ROOT_DIR/agent/vexyl-guard.sh" | head -n 1
}

current_project_version() {
  sed -n 's/^version = "\([^"]*\)".*/\1/p' "$ROOT_DIR/pyproject.toml" | head -n 1
}

assert_clean_tree() {
  [ "$ALLOW_DIRTY" = true ] && return 0
  if ! git -C "$ROOT_DIR" diff --quiet || ! git -C "$ROOT_DIR" diff --cached --quiet; then
    git -C "$ROOT_DIR" status --short >&2
    die "tracked working tree must be clean before preparing a release"
  fi
}

assert_release_is_new() {
  local current_agent current_project
  current_agent="$(current_agent_version)"
  current_project="$(current_project_version)"

  [ -n "$current_agent" ] || die "could not read agent version"
  [ -n "$current_project" ] || die "could not read pyproject version"
  [ "$current_agent" = "$current_project" ] || {
    die "current versions disagree: agent=$current_agent pyproject=$current_project"
  }
  version_gt "$VERSION" "$current_agent" || {
    die "release version $VERSION must be greater than current version $current_agent"
  }

  if git -C "$ROOT_DIR" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    die "local tag already exists: $TAG"
  fi
  if git -C "$ROOT_DIR" ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    die "remote tag already exists: $TAG"
  fi
}

update_versions() {
  log "updating version files to $VERSION"
  sed -i -E "s/^VERSION=\"[^\"]+\"/VERSION=\"$VERSION\"/" "$ROOT_DIR/agent/vexyl-guard.sh"
  sed -i -E "s/^version = \"[^\"]+\"/version = \"$VERSION\"/" "$ROOT_DIR/pyproject.toml"

  [ "$(current_agent_version)" = "$VERSION" ] || die "agent version update failed"
  [ "$(current_project_version)" = "$VERSION" ] || die "pyproject version update failed"
}

generate_temp_repo_key() {
  local gnupg key_batch private_key
  gnupg="$(mktemp -d)"
  TMP_PATHS+=("$gnupg")
  chmod 0700 "$gnupg"
  key_batch="$(mktemp)"
  private_key="$(mktemp)"
  TMP_PATHS+=("$key_batch" "$private_key")

  cat >"$key_batch" <<'EOF'
Key-Type: RSA
Key-Length: 2048
Name-Real: Vexyl Release Readiness Package Repository
Name-Email: security@vexyl.dev
Expire-Date: 0
%no-protection
%commit
EOF

  GNUPGHOME="$gnupg" gpg --batch --generate-key "$key_batch" >/dev/null
  GNUPGHOME="$gnupg" gpg --armor --export-secret-keys security@vexyl.dev >"$private_key"
  printf '%s\n' "$private_key"
}

release_notes_file() {
  local notes_file
  if [ -n "$RELEASE_NOTES_FILE" ]; then
    [ -f "$RELEASE_NOTES_FILE" ] || die "release notes file does not exist: $RELEASE_NOTES_FILE"
    notes_file="$RELEASE_NOTES_FILE"
  else
    notes_file="$(mktemp)"
    TMP_PATHS+=("$notes_file")
    printf 'Maintenance release for Vexyl Guard %s.\n' "$TAG" >"$notes_file"
  fi

  if ! grep -q '[^[:space:]]' "$notes_file"; then
    die "release notes file must not be empty"
  fi

  if rg -n 'PRIVATE KEY|BEGIN [A-Z ]*PRIVATE|password[=:]|token[=:]|secret[=:]|api[_-]?key[=:]' "$notes_file" >/dev/null; then
    rg -n 'PRIVATE KEY|BEGIN [A-Z ]*PRIVATE|password[=:]|token[=:]|secret[=:]|api[_-]?key[=:]' "$notes_file" >&2 || true
    die "release notes look like they may contain secret material"
  fi

  printf '%s\n' "$notes_file"
}

run_checks() {
  local repo_private_key tmp_extract
  log "checking required tools"
  for command_name in \
    apt-ftparchive \
    bash \
    createrepo_c \
    dpkg-deb \
    dpkg-scanpackages \
    gpg \
    gzip \
    python3 \
    rg \
    rpm \
    rpmbuild \
    rpmsign; do
    require_command "$command_name"
  done

  log "checking shell syntax"
  bash -n "$ROOT_DIR/agent/vexyl-guard.sh"
  bash -n "$ROOT_DIR/packaging/build-packages.sh"
  bash -n "$ROOT_DIR/packaging/build-repositories.sh"
  bash -n "$ROOT_DIR/packaging/sign-rpm-packages.sh"
  bash -n "$ROOT_DIR/packaging/verify-package-contents.sh"
  bash -n "$ROOT_DIR/packaging/verify-repositories.sh"
  bash -n "$ROOT_DIR/scripts/prepare-release.sh"

  log "running agent fixtures"
  "$ROOT_DIR/tests/run-agent-fixtures.sh"

  log "building preview packages"
  rm -rf "$ROOT_DIR/dist/packages" "$ROOT_DIR/dist/repositories"
  "$ROOT_DIR/packaging/build-packages.sh" --format all --version "$VERSION"
  "$ROOT_DIR/packaging/verify-package-contents.sh" "$ROOT_DIR"/dist/packages/*

  log "building signed package repository with temporary release-readiness key"
  repo_private_key="$(generate_temp_repo_key)"
  "$ROOT_DIR/packaging/sign-rpm-packages.sh" \
    --signing-key "$repo_private_key" \
    "$ROOT_DIR"/dist/packages/*.rpm
  "$ROOT_DIR/packaging/build-repositories.sh" \
    --packages-dir "$ROOT_DIR/dist/packages" \
    --output-dir "$ROOT_DIR/dist/repositories" \
    --signing-key "$repo_private_key"
  "$ROOT_DIR/packaging/verify-repositories.sh" \
    "$ROOT_DIR/dist/repositories" \
    "$ROOT_DIR/dist/repositories/vexyl-packages.asc"

  log "checking packaged CLI fallback database"
  tmp_extract="$(mktemp -d)"
  TMP_PATHS+=("$tmp_extract")
  dpkg-deb -x "$ROOT_DIR"/dist/packages/*.deb "$tmp_extract"
  PYTHONPATH="$tmp_extract/opt/vexyl" "$tmp_extract/usr/bin/vexyl" \
    threat --db "$tmp_extract/var/lib/vexyl/ai_threats.sqlite" seed
  PYTHONPATH="$tmp_extract/opt/vexyl" "$tmp_extract/usr/bin/vexyl" \
    threat --db "$tmp_extract/var/lib/vexyl/ai_threats.sqlite" search prompt >/dev/null
}

commit_release() {
  [ "$DO_COMMIT" = true ] || return 0
  log "committing release bump"
  git -C "$ROOT_DIR" add agent/vexyl-guard.sh pyproject.toml
  git -C "$ROOT_DIR" diff --cached --quiet && die "version bump produced no commit changes"
  git -C "$ROOT_DIR" commit -m "Release Vexyl Guard $TAG"
}

tag_release() {
  local notes_file
  [ "$DO_TAG" = true ] || return 0
  log "creating annotated tag $TAG"
  if ! git -C "$ROOT_DIR" diff --quiet || ! git -C "$ROOT_DIR" diff --cached --quiet; then
    git -C "$ROOT_DIR" status --short >&2
    die "cannot tag with uncommitted tracked changes; use --commit or commit manually"
  fi
  notes_file="$(release_notes_file)"
  git -C "$ROOT_DIR" tag -a "$TAG" --cleanup=verbatim -F "$notes_file"
}

push_release() {
  [ "$DO_PUSH" = true ] || return 0
  [ "$DO_TAG" = true ] || die "--push requires --tag"
  log "pushing release commit and tag to origin/$BRANCH"
  git -C "$ROOT_DIR" push origin "HEAD:$BRANCH" "refs/tags/$TAG"
}

main() {
  parse_args "$@"
  normalize_version
  cd "$ROOT_DIR"
  assert_clean_tree
  assert_release_is_new
  update_versions
  run_checks
  commit_release
  tag_release
  push_release
  log "release readiness complete for $TAG"
}

main "$@"
