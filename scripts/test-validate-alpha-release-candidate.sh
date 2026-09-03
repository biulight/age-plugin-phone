#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
version=$(scripts/check-release-version.sh)
commit=0123456789abcdef0123456789abcdef01234567

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
}

scripts/validate-alpha-release-candidate.sh "$commit" "$commit" "$version" false false
expect_failure scripts/validate-alpha-release-candidate.sh "$commit" ffffffffffffffffffffffffffffffffffffffff "$version" false false
expect_failure scripts/validate-alpha-release-candidate.sh "$commit" "$commit" "$version" true false
expect_failure scripts/validate-alpha-release-candidate.sh "$commit" "$commit" "$version" false true
expect_failure scripts/validate-alpha-release-candidate.sh "$commit" "$commit" 0.1.0-beta.1 false false
