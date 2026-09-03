#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 ARTIFACTS_DIR STAGE_DIR RELEASE_BODY VERSION COMMIT WORKFLOW_RUN" >&2
  exit 64
fi

artifacts_dir=$1
stage_dir=$2
release_body=$3
version=$4
expected_commit=$5
expected_run=$6
tag="v$version"

fail() {
  echo "alpha release artifact verification failed: $*" >&2
  exit 1
}

single_file() {
  local description=$1
  shift
  local matches=()
  while IFS= read -r match; do
    matches+=("$match")
  done < <(find "$artifacts_dir" -type f "$@" -print)
  [[ ${#matches[@]} -eq 1 ]] || fail "expected exactly one $description, found ${#matches[@]}"
  printf '%s\n' "${matches[0]}"
}

marker() {
  local file=$1
  local key=$2
  local values=()
  while IFS= read -r value; do
    value="${value%$'\r'}"
    values+=("$value")
  done < <(sed -nE "s/^${key}: (.*)$/\\1/p" "$file")
  [[ ${#values[@]} -eq 1 ]] || fail "expected exactly one $key marker in $(basename "$file")"
  printf '%s\n' "${values[0]}"
}

require_marker() {
  local file=$1
  local key=$2
  local expected=$3
  [[ $(marker "$file" "$key") == "$expected" ]] || fail "$key marker mismatch in $(basename "$file")"
}

require_sha256() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA-256 value"
}

hash_for_name() {
  local sums=$1
  local name=$2
  local values=()
  while IFS= read -r value; do
    values+=("$value")
  done < <(awk -v name="$name" '{ sub(/\r$/, "", $2); if ($2 == name) print $1 }' "$sums")
  [[ ${#values[@]} -eq 1 ]] || fail "expected exactly one digest for $name"
  require_sha256 "${values[0]}"
  printf '%s\n' "${values[0]}"
}

hash_from_single_entry() {
  local sums=$1
  local values=()
  while IFS= read -r value; do
    values+=("$value")
  done < <(awk 'NF == 2 { print $1 }' "$sums")
  [[ ${#values[@]} -eq 1 ]] || fail "expected exactly one digest in $(basename "$sums")"
  require_sha256 "${values[0]}"
  printf '%s\n' "${values[0]}"
}

actual_sha256() {
  sha256sum "$1" | awk '{ print $1 }'
}

[[ -d $artifacts_dir ]] || fail "artifact directory is missing"
[[ -f "docs/releases/$tag.md" ]] || fail "release note is missing"
[[ $expected_commit =~ ^[0-9a-f]{40}$ ]] || fail "expected commit is not a full SHA-1"
[[ $expected_run =~ ^[0-9]+$ ]] || fail "workflow run is invalid"

artifact_files=()
while IFS= read -r artifact_file; do
  artifact_files+=("$artifact_file")
done < <(find "$artifacts_dir" -type f -print)
[[ ${#artifact_files[@]} -eq 6 ]] || fail "expected exactly six source artifacts, found ${#artifact_files[@]}"

windows_zip=$(single_file "Windows ZIP" -name "age-plugin-phone-$version-windows-x64-alpha-test-signed.zip")
android_apk=$(single_file "Android APK" -name "age-plugin-phone-$version-android-arm64.apk")
windows_sums=$(single_file "Windows checksum record" -name "age-plugin-phone-$version-windows-SHA256SUMS.txt")
windows_evidence=$(single_file "Windows signature record" -name "age-plugin-phone-$version-windows-signature-verification.txt")
android_sums=$(single_file "Android checksum record" -name "age-plugin-phone-$version-android-SHA256SUMS.txt")
android_evidence=$(single_file "Android signature record" -name "age-plugin-phone-$version-android-signature-verification.txt")

for file in "$windows_sums" "$windows_evidence" "$android_sums" "$android_evidence"; do
  [[ -f $file ]] || fail "required evidence is missing: $(basename "$file")"
done

for evidence in "$windows_evidence" "$android_evidence"; do
  require_marker "$evidence" commit "$expected_commit"
  require_marker "$evidence" release_version "$version"
  require_marker "$evidence" workflow_run "$expected_run"
done

windows_attempt=$(marker "$windows_evidence" workflow_run_attempt)
android_attempt=$(marker "$android_evidence" workflow_run_attempt)
[[ $windows_attempt =~ ^[1-9][0-9]*$ && $windows_attempt == "$android_attempt" ]] || fail "workflow attempt markers differ"

windows_zip_name=$(basename "$windows_zip")
windows_zip_expected=$(hash_for_name "$windows_sums" "$windows_zip_name")
windows_exe_expected=$(hash_for_name "$windows_sums" "age-plugin-phone.exe")
[[ $(actual_sha256 "$windows_zip") == "$windows_zip_expected" ]] || fail "Windows ZIP digest mismatch"
unzip -t "$windows_zip" >/dev/null || fail "Windows ZIP integrity check failed"
windows_exe_actual=$(unzip -p "$windows_zip" age-plugin-phone.exe | sha256sum | awk '{ print $1 }')
[[ $windows_exe_actual == "$windows_exe_expected" ]] || fail "Windows executable digest mismatch"

android_expected=$(hash_from_single_entry "$android_sums")
[[ $(actual_sha256 "$android_apk") == "$android_expected" ]] || fail "Android APK digest mismatch"

require_marker "$windows_evidence" integrity_validation "Authenticode content and signature valid; public-trust verification rejected only the private test root"
public_trust_status=$(marker "$windows_evidence" public_trust_status)
[[ $public_trust_status == "UnknownError" || $public_trust_status == "NotTrusted" ]] || fail "unexpected Windows public-trust status"
require_marker "$windows_evidence" custom_root_chain_validation "Valid"
require_marker "$windows_evidence" trust_scope "private test root validated in memory and not installed in a Windows trust store"
windows_certificate=$(marker "$windows_evidence" certificate_sha256)
windows_root_certificate=$(marker "$windows_evidence" root_certificate_sha256)
android_certificate=$(marker "$android_evidence" certificate_sha256)
require_sha256 "$windows_certificate"
require_sha256 "$windows_root_certificate"
require_sha256 "$android_certificate"

rm -rf "$stage_dir"
mkdir -p "$stage_dir"
cp "$windows_zip" "$stage_dir/$windows_zip_name"
cp "$android_apk" "$stage_dir/$(basename "$android_apk")"
cp "$windows_sums" "$stage_dir/$(basename "$windows_sums")"
cp "$android_sums" "$stage_dir/$(basename "$android_sums")"
cp "$windows_evidence" "$stage_dir/$(basename "$windows_evidence")"
cp "$android_evidence" "$stage_dir/$(basename "$android_evidence")"

cat "docs/releases/$tag.md" > "$release_body"
cat >> "$release_body" <<EOF

## Signed artifact provenance

<!-- age-plugin-phone-alpha-provenance: commit=$expected_commit run=$expected_run attempt=$windows_attempt -->

- Immutable commit: \`$expected_commit\`
- Signing workflow: \`$expected_run\`, attempt \`$windows_attempt\`
- Windows executable SHA-256: \`$windows_exe_expected\`
- Windows ZIP SHA-256: \`$windows_zip_expected\`
- Android APK SHA-256: \`$android_expected\`
- Windows signing certificate SHA-256: \`$windows_certificate\`
- Windows test-root certificate SHA-256: \`$windows_root_certificate\`
- Android signing certificate SHA-256: \`$android_certificate\`

The Windows package is test-signed by a private root. Its Authenticode content and signature and
custom-root chain validation passed, but ordinary Windows installations do not trust that root.
This is a developer prerelease for synthetic or disposable data with a separately verified
independent recovery recipient; it is not a public-Alpha or production-secret claim.
EOF
