#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 AGE AGE_KEYGEN RAGE RAGE_KEYGEN AGE_PLUGIN_PHONE" >&2
  exit 2
fi

age_bin=$1
age_keygen_bin=$2
rage_bin=$3
rage_keygen_bin=$4
plugin_bin=$5

for executable in "$age_bin" "$age_keygen_bin" "$rage_bin" "$rage_keygen_bin" "$plugin_bin"; do
  if [[ ! -x "$executable" ]]; then
    echo "required executable is unavailable" >&2
    exit 2
  fi
done
if [[ $(basename "$plugin_bin") != "age-plugin-phone" ]]; then
  echo "plugin executable must be named age-plugin-phone" >&2
  exit 2
fi

umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/age-plugin-phone-interop.XXXXXX")
cleanup() {
  case "$work_dir" in
    */age-plugin-phone-interop.*) rm -rf -- "$work_dir" ;;
    *) echo "refusing to remove unexpected temporary path" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

export PATH="$(dirname "$plugin_bin"):$PATH"
if [[ $(command -v age-plugin-phone) != "$plugin_bin" ]]; then
  echo "plugin discovery resolved a different executable" >&2
  exit 2
fi

# Public deterministic recipients exercise distinct phone identities and both recipient versions.
phone_recipient_a="age1phone1qypkk9737tsjcsj8lz7wdetr53q0yacr0kqjm6en5r62zw29mzvv99sa27n9c"
phone_recipient_b="age1phone1qyp9ajly6xnrxzjyerm7l9gaf0cktekxkus7ltdfsha5zesmcmnl6mqlcfacm"
phone_recipient_v2="age1phone1qgpkk9737tsjcsj8lz7wdetr53q0yacr0kqjm6en5r62zw29mzvv99sztm97f5dxxv9yfj8ha7236jl3vhnvddepa7k6np0mg9nph3h8l4kyysjzgfpyysjzgfpyysjzgfpyy9amcse"

"$age_keygen_bin" -o "$work_dir/recovery.identity" >/dev/null 2>&1
recovery_recipient=$("$age_keygen_bin" -y "$work_dir/recovery.identity")
if [[ -z "$recovery_recipient" ]]; then
  echo "recovery recipient generation failed" >&2
  exit 1
fi

printf 'x' > "$work_dir/tiny.input"
printf '%s\n' "synthetic interoperability input" > "$work_dir/text.input"
dd if=/dev/zero of="$work_dir/binary.input" bs=4096 count=1 status=none

clients=("$age_bin" "$rage_bin")
inputs=("$work_dir/tiny.input" "$work_dir/text.input" "$work_dir/binary.input")
case_count=0
for encryptor in "${clients[@]}"; do
  for decryptor in "${clients[@]}"; do
    for input in "${inputs[@]}"; do
      stem="case-${case_count}"
      ciphertext="$work_dir/${stem}.age"
      recovered="$work_dir/${stem}.recovered"
      env RUST_LOG=off "$encryptor" --encrypt \
        -r "$phone_recipient_a" \
        -r "$phone_recipient_b" \
        -r "$phone_recipient_v2" \
        -r "$recovery_recipient" \
        -o "$ciphertext" \
        "$input"
      if [[ $(grep -a -c '^-> phone-p256-v1 ' "$ciphertext") -ne 2 ]] ||
        [[ $(grep -a -c '^-> phone-p256-v2 ' "$ciphertext") -ne 1 ]]; then
        echo "client omitted or duplicated a phone recipient stanza" >&2
        exit 1
      fi
      env RUST_LOG=off "$decryptor" --decrypt \
        -i "$work_dir/recovery.identity" -o "$recovered" "$ciphertext"
      cmp --silent "$input" "$recovered"
      case_count=$((case_count + 1))
    done
  done
done

# Confirm rage-keygen can consume the same independent identity without disclosing it.
rage_recovery_recipient=$(env RUST_LOG=off "$rage_keygen_bin" -y "$work_dir/recovery.identity")
if [[ "$rage_recovery_recipient" != "$recovery_recipient" ]]; then
  echo "recovery identity interpretation differs between clients" >&2
  exit 1
fi

negative_count=0
for client in "${clients[@]}"; do
  rejected="$work_dir/rejected-${negative_count}.age"
  if env RUST_LOG=off "$client" --encrypt \
    -r "${phone_recipient_a}x" -o "$rejected" "$work_dir/text.input" \
    >/dev/null 2>&1; then
    echo "client accepted a malformed phone recipient" >&2
    exit 1
  fi
  if [[ -s "$rejected" ]]; then
    echo "client left partial ciphertext after recipient rejection" >&2
    exit 1
  fi
  negative_count=$((negative_count + 1))
done

echo "interoperability smoke passed: ${case_count} recoveries, ${negative_count} rejections"
