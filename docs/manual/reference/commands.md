---
title: "Commands and environment variables"
sidebar_position: 1
---

# Commands and environment variables

Use this reference with **0.1.0-beta.2**. Public command options come from the CLI definitions; prefer managed `setup` for normal use. Run `age-plugin-phone --help` or `age-plugin-phone <command> --help` for usage. Running without a subcommand is equivalent to `status`.

## Everyday commands

| Command | Options and defaults | Result or restriction |
| --- | --- | --- |
| `status` | No options | Read-only implementation and platform capability report |
| `setup` | `--label LABEL`; `--recipient-type phone\|tag` (default `phone`); `--transport auto\|adb\|ble\|wifi\|qr` (default `auto`); optional `--adb-serial SERIAL`, `--json` | Creates a pairing using managed hardware paths; label is required for a new setup |
| `setup --resume` | Optional `--recipient-type`, `--json` | Finishes only a durably confirmed local attempt; cannot combine with label, cleanup, transport, or ADB serial |
| `setup --cleanup` | No JSON output | Removes the exact incomplete attempt after confirmation; cannot combine with resume, label, transport, or ADB serial |
| `recipients` | Required `-i` / `--identity PATH`; `--recipient-type phone\|tag` (default `phone`) | Prints one public address without phone access or private state |
| `wifi-doctor` | Optional `--identity-stub PATH` | One bounded discovery check; omitted path checks new-pairing mode; provided path checks that existing pairing |
| `remove-desktop-state` | Required `--identity-stub PATH` | Destructive exact-pairing cleanup with full-fingerprint confirmation |
| `remove-orphaned-desktop-state` | Required `--locator PATH` | Destructive orphan cleanup; canonical locator directly under protected root required |

See [recovery](../guides/recovery.md) before cleanup. `ble` is reserved and unavailable. A `status` availability hint does not establish physical-device acceptance.

## Setup JSON

New setup and resume accept `--json`. Successful stdout contains exactly one object:

```json
{"schema_version":1,"identity_path":"<public-stub-path>","recipient":"<public-recipient>"}
```

Prompts, QR presentation, fingerprint confirmation, and warnings remain on stderr. Failure emits no success object. Cleanup has no JSON mode. JSON does not bypass interaction or native phone verification.

## Advanced diagnostics

These commands are not the normal encryption/decryption interface; use age for files.

| Command | Required options | Optional options |
| --- | --- | --- |
| `pair` | `--label`, `--desktop-state`, `--identity-output`, `--replay-state` | `--recipient-type` (default `phone`), `--transport` (default `auto`), `--adb-serial` |
| `unwrap` | `--identity-stub`, `--desktop-state`, `--replay-state`, `--stanza-arg`, `--stanza-body` | `--caller-hint`, `--transport` (default `auto`), `--adb-serial`, `--wifi-address` |
| `qr-capture-probe` | None | `--label` (default `Desktop QR capture probe`), `--cycles` (default `12`), `--html-output PATH` |

`pair` uses create-only paths. On Windows/macOS, private desktop and replay state must be direct children of the protected configuration root; existing or uncertain state cannot be reused. `unwrap` operates on one stanza, not an encrypted file. Do not collect raw stanza or request values in reports. `qr-capture-probe` exercises capture, not a complete pairing or decryption; do not publish its QR output. Hidden age protocol and cleanup-helper commands are not user interfaces.

## Environment variables

Set these in the process that launches age. `setup` and explicit diagnostic commands use their own transport flags.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGE_PLUGIN_PHONE_TRANSPORT` | Saved pairing choice | Overrides standard-age transport; accepts `auto`, `adb`, `wifi`, `qr`, reserved `ble` |
| `AGE_PLUGIN_PHONE_ADB_SERIAL` | No explicit device | Chooses the intended Android device for standard-age calls; required with multiple ADB devices |
| `AGE_PLUGIN_PHONE_WIFI_ADDRESS` | Discovery when eligible | Diagnostic private IPv4 endpoint including port; no address is normally needed |
| `AGE_PLUGIN_PHONE_MESSAGES` | Off | Enables payload-free desktop guidance for `1`, `true`, `yes`, or `on` (case-insensitive, surrounding whitespace ignored); QR is still visible when off |
| `AGE_PLUGIN_PHONE_CONFIG_DIR` | Platform configuration root | Absolute alternate root; use the same value for pairing and subsequent age calls |

ADB and Wi-Fi hints cannot be combined. Explicit route hints can suppress automatic discovery and must match the selected transport. Empty/malformed selection values are not a way to clear an override: remove the environment variable instead. Do not move or restore plugin state to change configuration roots; see [recovery](../guides/recovery.md).

For multiple Android devices, PowerShell uses `$env:AGE_PLUGIN_PHONE_ADB_SERIAL = "SERIAL"`; remove it afterward with `Remove-Item Env:AGE_PLUGIN_PHONE_ADB_SERIAL`. On macOS, use a one-command assignment such as `AGE_PLUGIN_PHONE_ADB_SERIAL=SERIAL age -d -i phone-identity.txt -o recovered.txt example.age`. Replace `SERIAL` locally and never include it in a public report.
