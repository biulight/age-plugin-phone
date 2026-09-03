#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 EXPECTED_COMMIT ACTUAL_COMMIT VERSION TAG_EXISTS RELEASE_EXISTS" >&2
  exit 64
fi

expected_commit=$1
actual_commit=$2
version=$3
tag_exists=$4
release_exists=$5

fail() {
  echo "alpha release candidate validation failed: $*" >&2
  exit 1
}

[[ $expected_commit =~ ^[0-9a-f]{40}$ ]] || fail "expected commit is not a full SHA-1"
[[ $actual_commit =~ ^[0-9a-f]{40}$ ]] || fail "workflow commit is not a full SHA-1"
[[ $actual_commit == "$expected_commit" ]] || fail "workflow commit does not match the selected candidate"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$ ]] || fail "version is not an Alpha SemVer prerelease"
[[ $tag_exists == false || $tag_exists == true ]] || fail "tag existence result is invalid"
[[ $release_exists == false || $release_exists == true ]] || fail "release existence result is invalid"

manifest_version="$(scripts/check-release-version.sh "$version")"
[[ $manifest_version == "$version" ]] || fail "manifest version check returned an unexpected value"
[[ -f "docs/releases/v$version.md" ]] || fail "release note is missing"
[[ $tag_exists == false ]] || fail "release tag already exists: v$version"
[[ $release_exists == false ]] || fail "GitHub release already exists: v$version"
