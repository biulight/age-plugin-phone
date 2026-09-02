#!/usr/bin/env bash
set -euo pipefail

expected_version="${1:-}"
workspace_version="$({ sed -nE 's/^version = "([^"]+)"$/\1/p' Cargo.toml; } | head -n 1)"
mobile_version="$({ sed -nE 's/^[[:space:]]*"version": "([^"]+)",?$/\1/p' apps/mobile/package.json; } | head -n 1)"
tauri_version="$({ sed -nE 's/^[[:space:]]*"version": "([^"]+)",?$/\1/p' apps/mobile/src-tauri/tauri.conf.json; } | head -n 1)"

if [[ -z "$workspace_version" || -z "$mobile_version" || -z "$tauri_version" ]]; then
  echo "release version is missing from one or more manifests" >&2
  exit 1
fi

if ! [[ "$workspace_version" == "$mobile_version" && "$workspace_version" == "$tauri_version" ]]; then
  echo "release versions differ: cargo=$workspace_version mobile=$mobile_version tauri=$tauri_version" >&2
  exit 1
fi

if [[ -n "$expected_version" && "$workspace_version" != "$expected_version" ]]; then
  echo "manifest version $workspace_version does not match requested release $expected_version" >&2
  exit 1
fi

if [[ ! "$workspace_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release version is not a supported SemVer value: $workspace_version" >&2
  exit 1
fi

printf '%s\n' "$workspace_version"
