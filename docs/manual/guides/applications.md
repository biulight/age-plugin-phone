---
title: "Daily use and application integration"
sidebar_position: 3
---

# Daily use and application integration

After the [first round trip](../quick-start.md), configure compatible callers with public recipients for encryption and identity-stub paths for decryption. Callers must be able to find both `age` and `age-plugin-phone` on their `PATH`.

## Use age directly

```sh
age -e -r '<phone-recipient>' -r '<recovery-recipient>' -o example.age example.txt
age -d -i '<identity-stub-path>' -o recovered.txt example.age
```

The stub belongs in `-i`, not the recipient-list option `-R`. Encryption needs no phone authorization. Decryption is interactive: keep the phone reachable and approve each native verification. No unattended or cached-approval mode is provided. Use a fresh output filename and check the exit status before using decrypted data.

You can pass several identity files with repeated `-i` options. Beta 2 allows age to continue past a valid v2 phone stanza that does not target the current identity. Missing or corrupt private state is still fatal. Once a pairing is selected, cancellation or failure does not cause a fallback to another pairing.

## Use Shine or another compatible application

Shine uses the standard age CLI and does not need `rage`. Configure its public recipients and local identity-stub paths using the [Shine environment guide](https://biulight.github.io/shine/guides/environment) and [configuration reference](https://biulight.github.io/shine/reference/configuration). Check the installed Shine version before following its managed phone-setup workflow. Keep an independent recovery recipient in the encryption configuration.

Other applications need the same two values and an interactive age plugin path. They must support native tag recipients and age 1.3+ if you choose [tag mode](recipients.md). Integration does not introduce a separate phone-plugin protocol or ciphertext format.

For a GUI caller, check its inherited executable path, camera/network permissions, and transport settings separately from Terminal. USB and Wi-Fi plugin guidance is quiet by default; `AGE_PLUGIN_PHONE_MESSAGES=1` enables payload-free guidance. QR remains visible because the phone must scan the request. See the [environment reference](../reference/commands.md).

## Verify the caller

Use a disposable file and confirm a fresh phone prompt, byte-identical recovery, and failure on cancellation. Test independent recovery separately with the phone unavailable. A successful direct CLI test does not certify every application's integration.
