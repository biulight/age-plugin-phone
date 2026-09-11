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
expect_failure scripts/validate-alpha-release-candidate.sh "$commit" "$commit" 0.1.0 false false

# Exercise both supported channels against matching manifests, independently of
# the checkout's current release version. A version mismatch must not masquerade
# as channel validation coverage.
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/scripts" "$fixture/apps/mobile/src-tauri" "$fixture/docs/releases"
cp scripts/check-release-version.sh "$fixture/scripts/"
validator="$repo_root/scripts/validate-alpha-release-candidate.sh"
for candidate in 0.1.0-alpha.5 0.1.0-beta.2 0.1.0 0.1.0-rc.1 0.1.0-beta 0.1.0-beta.2.extra; do
  cat > "$fixture/Cargo.toml" <<EOF
[workspace.package]
version = "$candidate"
[workspace.dependencies]
age-plugin-phone-core = { path = "crates/core", version = "=$candidate" }
age-plugin-phone-platform-keys = { path = "crates/platform-keys", version = "=$candidate" }
age-plugin-phone-platform-storage = { path = "crates/platform-storage", version = "=$candidate" }
EOF
  printf '{\n  "version": "%s"\n}\n' "$candidate" > "$fixture/apps/mobile/package.json"
  cp "$fixture/apps/mobile/package.json" "$fixture/apps/mobile/src-tauri/tauri.conf.json"
  touch "$fixture/docs/releases/v$candidate.md"
  case "$candidate" in
    0.1.0-alpha.5|0.1.0-beta.2)
      (cd "$fixture" && "$validator" "$commit" "$commit" "$candidate" false false)
      rm "$fixture/docs/releases/v$candidate.md"
      (cd "$fixture" && expect_failure "$validator" "$commit" "$commit" "$candidate" false false)
      ;;
    *) (cd "$fixture" && expect_failure "$validator" "$commit" "$commit" "$candidate" false false) ;;
  esac
done
