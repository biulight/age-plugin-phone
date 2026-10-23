# Beta 2 acceptance harness

This is preparation for owner-assisted Windows/Android acceptance, not a record of
physical passes. Use synthetic data only. The published Beta 2 ZIP contains an older
Alpha-only harness: run the current repository script against the unchanged published
EXE and APK. Do not replace or republish release assets.

Verify package signatures, signer certificate identities, checksums, source commit and
workflow attempt using [the signing runbook](release-signing.md) and
[Beta 2 publication evidence](beta-readiness.md#beta-2-publication-evidence--2026-09-11).
The EXE hash is the extracted executable hash, **not** the ZIP hash. Record signer
identities separately with the verification evidence; the harness hashes files and
asks for observation, but does not verify signatures or the installed APK itself.
Record the harness revision and SHA-256 alongside that evidence too.

## Inputs and execution

Use an interactive Windows PowerShell **7.2+** terminal without transcription. Keep
other ADB controllers closed. Complete managed setup with full fingerprint comparison
yourself; the script never confirms pairing or native phone authentication. Retain
an independently tested recovery recipient for existing data. The script also creates
a disposable recovery key for its own synthetic ciphertext and removes it afterward.

Supply two valid, distinct public identity stub files with available private state in
the selected configuration root. `IdentityStub` matches `PhoneRecipient`;
`NonmatchingIdentityStub` must not match. For `tag`, another pairing to the same phone
identity key is **not** a nonmatch. If a suitable identity is unavailable, leave the
physical test unexecuted; never fabricate a damaged stub or modify replay state.

```powershell
$parameters = @{
    PluginExe = '<absolute verified age-plugin-phone.exe>'
    Apk = '<absolute verified normal Beta 2 APK>'
    ExpectedExeSha256 = '<64 lowercase hex from verified EXE evidence>'
    ExpectedApkSha256 = '<64 lowercase hex from verified APK evidence>'
    Commit = 'e08d631b33bd0c16948ca26275bc851b0bf56c15'
    WorkflowRun = '34612479284'
    WorkflowAttempt = '1'
    Version = '0.1.0-beta.2'
    IdentityStub = '<absolute matching public stub>'
    NonmatchingIdentityStub = '<absolute valid nonmatching public stub>'
    RecipientMode = 'phone'
    PhoneRecipient = '<matching age1phone recipient>'
    ConfigRoot = '<absolute configuration root used for setup>'
    AdbSerial = '<locally selected ADB device>'
    ReportPath = '<absolute NEW report.json path>'
}
& .\scripts\windows-minimal-acceptance.ps1 @parameters
```

Run `tag` separately with `RecipientMode = 'tag'`, its matching `age1tag` recipient,
appropriate stubs, age 1.3+ and a new report path. One report covers one recipient mode;
success never implies the other mode passed. No mode conversion or fallback occurs.

## Cases and evidence limits

After encryption and independent recovery, the script runs nonmatch-only rejection,
nonmatch-then-match success, and nonmatch-then-cancel rejection. It then runs the
existing repeated USB, cancellation/recovery, foreground Wi-Fi, background/recovery
and paused-listener checks. Each successful phone operation needs fresh native
verification. The owner must observe the intended event: a generic command failure
without the expected phone behavior is not a pass. In particular, nonmatch-only
must be an identity miss, not unavailable state, malformed input or a transport error.
Before any phone attempt, the verified plugin's read-only `recipients --identity`
command strictly decodes each stub and derives its recipient in the selected mode.
The matching recipient must equal `PhoneRecipient`; the nonmatching recipient must
differ. Empty, malformed, multi-identity and ordinary software identity files are
rejected by the product decoder, not accepted merely because their paths exist.
This public validation does not establish private-state availability.

The isolated nonmatch additionally requires the exact reference-age ordinary-miss
diagnostic (LF or CRLF). Unknown or changed diagnostics fail closed and require a
harness compatibility review. Raw stderr is classified in memory and never returned
or written to evidence; only `identity-miss`, `none` or `other-error` is retained.
Cancellation/background/paused-listener rows still require the owner's observation:
the product's generic transport error cannot distinguish all those events. Every
decrypt, including independent recovery, requires empty stdout when using `-o`.
Observation of no prompt/contact does not prove absence of network I/O; retain the
separate source-level no-contact regression evidence.

Schema 2 reports include recipient mode, whether multi-identity cases were enabled,
artifact hashes, source provenance and per-case results. Later cases remain `not-run`
when execution stops. An unconfirmed observation fails the run; process timeouts and
abnormal exit codes cannot count as expected age rejection. Existing reports are never
overwritten. Alpha version syntax and the optional extra-stub parameter are retained;
all three multi-identity rows remain `not-run` when it is omitted. The executable must
provide `recipients --identity --recipient-type`; older Alpha 4 binaries lack this
command and fail the new preflight. Their historical harness/evidence remains separate
and cannot establish the Beta 2 regression. No weaker decoder fallback is used.

The report's `passed-minimal-unwrap-only` status is deliberately limited. Malformed
supported stanzas, unavailable private state, product timeout, hostile connections,
network changes, replay, upgrade and the broader Wi-Fi matrix still require separate
acceptance. Neither fixture tests nor this minimum smoke close those roadmap rows.
Only the allowlisted JSON is intended for sharing; do not collect plaintext, raw
protocol messages, QR contents, private keys or device serials in evidence.

## Harness tests

```powershell
pwsh -NoProfile -File scripts/test-windows-minimal-acceptance.ps1
# Also exercise installed age, age-keygen and age-plugin-phone (no phone operations):
pwsh -NoProfile -File scripts/test-windows-minimal-acceptance.ps1 -NativeClients
```

The suite uses real subprocess checks plus simulated Windows/age/ADB orchestration.
It verifies both recipient modes, identity order, Alpha parameter handling, invalid input,
failures, unexecuted rows, environment restoration, cleanup, redaction and report
preservation. It does not perform TPM, StrongBox, pairing or biometric acceptance.
The optional native checks use a public deterministic stub derived from the repository's
pairing-transcript vector and disposable software age keys. They reject invalid stub
types/checksums/multiple entries and distinguish actual age errors from ordinary
misses. Report redaction checks recursively inspect decoded JSON keys and values,
with deliberate Windows-path leak injections to exercise backslash escaping on any OS.
