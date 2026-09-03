#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
temp_root=$(mktemp -d)
trap 'rm -rf "$temp_root"' EXIT
version=$(scripts/check-release-version.sh)
commit=0123456789abcdef0123456789abcdef01234567
run=123456
windows_dir="$temp_root/artifacts/windows"
android_dir="$temp_root/artifacts/android"
mkdir -p "$windows_dir" "$android_dir" "$temp_root/windows-contents"
printf 'synthetic Windows executable\n' > "$temp_root/windows-contents/age-plugin-phone.exe"
(cd "$temp_root/windows-contents" && zip -q "$windows_dir/age-plugin-phone-$version-windows-x64-alpha-test-signed.zip" age-plugin-phone.exe)
windows_zip="$windows_dir/age-plugin-phone-$version-windows-x64-alpha-test-signed.zip"
windows_exe="$temp_root/windows-contents/age-plugin-phone.exe"
{
  sha256sum "$windows_exe" | sed 's# .*#  age-plugin-phone.exe#'
  sha256sum "$windows_zip" | sed "s# .*#  age-plugin-phone-$version-windows-x64-alpha-test-signed.zip#"
} > "$windows_dir/SHA256SUMS.txt"
mv "$windows_dir/SHA256SUMS.txt" "$windows_dir/age-plugin-phone-$version-windows-SHA256SUMS.txt"
cat > "$windows_dir/signature-verification.txt" <<EOF
commit: $commit
release_version: $version
workflow_run: $run
workflow_run_attempt: 1
integrity_validation: Authenticode content and signature valid; public-trust verification rejected only the private test root
public_trust_status: UnknownError
custom_root_chain_validation: Valid
trust_scope: private test root validated in memory and not installed in a Windows trust store
certificate_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
root_certificate_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
windows_evidence="$windows_dir/age-plugin-phone-$version-windows-signature-verification.txt"
mv "$windows_dir/signature-verification.txt" "$windows_evidence"
# Windows PowerShell writes the real signing evidence with CRLF line endings.
awk '{ printf "%s\r\n", $0 }' "$windows_evidence" > "$temp_root/windows-evidence.crlf"
mv "$temp_root/windows-evidence.crlf" "$windows_evidence"
android_apk="$android_dir/age-plugin-phone-$version-android-arm64.apk"
printf 'synthetic Android APK\n' > "$android_apk"
sha256sum "$android_apk" > "$android_dir/age-plugin-phone-$version-android-SHA256SUMS.txt"
cat > "$android_dir/signature-verification.txt" <<EOF
commit: $commit
release_version: $version
workflow_run: $run
workflow_run_attempt: 1
certificate_sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
mv "$android_dir/signature-verification.txt" "$android_dir/age-plugin-phone-$version-android-signature-verification.txt"

stage="$temp_root/stage"
body="$temp_root/release-body.md"
scripts/prepare-alpha-release-publish.sh "$temp_root/artifacts" "$stage" "$body" "$version" "$commit" "$run"
[[ $(find "$stage" -type f | wc -l | tr -d ' ') == 6 ]]
grep -q "commit=$commit run=$run attempt=1" "$body"
grep -q 'Windows test-root certificate SHA-256' "$body"
grep -q 'synthetic or disposable data' "$body"
for asset in \
  "age-plugin-phone-$version-windows-x64-alpha-test-signed.zip" \
  "age-plugin-phone-$version-android-arm64.apk" \
  "age-plugin-phone-$version-windows-SHA256SUMS.txt" \
  "age-plugin-phone-$version-windows-signature-verification.txt" \
  "age-plugin-phone-$version-android-SHA256SUMS.txt" \
  "age-plugin-phone-$version-android-signature-verification.txt"; do
  test -f "$stage/$asset"
done

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
}

android_sums="$android_dir/age-plugin-phone-$version-android-SHA256SUMS.txt"
android_evidence="$android_dir/age-plugin-phone-$version-android-signature-verification.txt"
cp "$android_apk" "$temp_root/android-apk.backup"
printf 'tampered\n' >> "$android_apk"
expect_failure scripts/prepare-alpha-release-publish.sh "$temp_root/artifacts" "$stage" "$body" "$version" "$commit" "$run"
mv "$temp_root/android-apk.backup" "$android_apk"

sed "s/^commit: .*/commit: ffffffffffffffffffffffffffffffffffffffff/" "$android_evidence" > "$temp_root/android-evidence.mismatch"
mv "$temp_root/android-evidence.mismatch" "$android_evidence"
expect_failure scripts/prepare-alpha-release-publish.sh "$temp_root/artifacts" "$stage" "$body" "$version" "$commit" "$run"
sed "s/^commit: .*/commit: $commit/" "$android_evidence" > "$temp_root/android-evidence.restore"
mv "$temp_root/android-evidence.restore" "$android_evidence"

mkdir "$android_dir/duplicate"
cp "$android_apk" "$android_dir/duplicate/age-plugin-phone-$version-android-arm64.apk"
expect_failure scripts/prepare-alpha-release-publish.sh "$temp_root/artifacts" "$stage" "$body" "$version" "$commit" "$run"
rm -rf "$android_dir/duplicate"

rm "$android_sums"
expect_failure scripts/prepare-alpha-release-publish.sh "$temp_root/artifacts" "$stage" "$body" "$version" "$commit" "$run"
