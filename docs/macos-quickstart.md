# macOS source quick start — experimental acceptance

Use disposable data. The [macOS plan](macos-support-plan.md) is not fully accepted:
same-Mac replay snapshot rollback is unresolved, and the real-phone/transport/caller
matrix remains open. This guide describes the current source implementation, not
older published releases. It does not promise protection for production secrets.

## Build and inspect

The current hardware baseline is MacBookPro18,3 / Apple Silicon / macOS 26.6.2
(25G83), in a logged-in user session. macOS 14 is a compilation deployment floor,
not a tested minimum support version. Intel/T2, other OS versions, wrong-Mac copy
rejection and pre-login operation remain unverified. The plugin requires two real
Secure Enclave roles; failure never falls back to software desktop keys.

Install Rust 1.88+ and Xcode Command Line Tools with the macOS SDK and Swift compiler.
From a checkout containing the macOS implementation:

```console
xcrun swiftc --version
cargo install --path crates/desktop --locked
age-plugin-phone status
```

Cargo installs the executable under its normal `bin` directory; include that
directory in the PATH inherited by the age client. A GUI application's PATH may
differ from Terminal's. The archived Swift bridge builds with the libraries;
the desktop install does not need Android/iOS tooling or a Developer ID certificate.
`status` is read-only and does not create/open keys or request camera permission.
An availability hint does not replace the actual setup hardware operation.

## Pair the Android phone

The currently available acceptance phone is a StrongBox-capable Android device.
Its native capability checks must succeed. For explicit Developer USB, enable and
authorize USB debugging, then identify the single intended device:

```console
adb devices -l
age-plugin-phone setup --label "Mac acceptance" --transport adb --adb-serial SERIAL --json
```

Replace `SERIAL` with that device's serial. Compare the **complete transcript
fingerprint** displayed on both endpoints and complete the phone's native pairing
confirmation yourself. Desktop labels are untrusted hints. JSON success contains
only `schema_version`, `identity_path` and `recipient`; prompts use stderr. Save the
public identity path for the age client. Do not collect QR contents or raw traffic.

For Wi-Fi, first enter the phone's explicit **Pair via Wi-Fi** mode, then use
`--transport wifi`. For QR, use `--transport qr` with a supported camera and complete
both sides' scan flow. `auto` performs bounded Wi-Fi discovery and chooses QR only
when no listener is available; ambiguity and permission/network errors stop it.
After sending begins, it does not switch transports. ADB is Android-only; BLE is
unavailable. A successful Terminal flow does not establish GUI camera/network access.

## Exercise standard age and recovery

Use the `recipient` returned by setup with `-r` for encryption, and its
`identity_path` with `-i` for decryption. The identity file is not a recipient list
for `-R`. Include an independently verified recovery recipient when encrypting the
disposable acceptance file:

```console
age -r PHONE_RECIPIENT -r RECOVERY_RECIPIENT -o example.age example.txt
age -d -i /absolute/path/to/identity.txt -o recovered.txt example.age
```

The recovery identity is separate from plugin state and must work without the
original phone or Mac keys. Perform two separate decryptions and observe a fresh
phone verification each time. Cancel a third operation on the phone and verify
that the caller receives failure and no usable plaintext. A subsequent attempt
must create a new request and request new verification. Do not record plaintext
or file keys in acceptance logs. With foreground Wi-Fi auto-listen, enabling the
listener permits delivery only; it never caches approval.

## Interrupted attempts and reinstall

Use `setup --resume` only for an already confirmed journal. Use `setup --cleanup`
for an unconfirmed or abandoned attempt, typing the exact displayed confirmation
yourself. This also recovers current macOS explicit `pair` attempts. If the phone
committed the pairing, revoke it there as well. Never clear a replay pending marker
or restore earlier replay bytes to make an operation work.

Source reinstall and `cargo install --force` must retain the original hardware
references and replay state. `cargo uninstall` removes the executable only. Actual
published-version upgrades, other callers and other hardware need separate evidence;
see [M5 results](macos-m5-evidence.md). For normal/orphan removal, endpoint replacement,
legacy software state and independent recovery, follow [the recovery guide](macos-recovery.md).
