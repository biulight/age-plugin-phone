# Alpha release signing setup

This runbook configures the credentials consumed by
`.github/workflows/alpha-release.yml`. Distribution signing is separate from the protocol key
boundary: Windows release signing never substitutes for the desktop TPM keys, and Android APK
signing never substitutes for the phone StrongBox identity and response-signing keys.

The workflow uses the protected GitHub environment `alpha-release`. Configure required reviewers
and restrict its deployment branches or tags before adding any signing configuration. Only dispatch
the workflow from an immutable commit selected for the release candidate.

## Windows test signing certificate

The pre-commercial RC workflow uses one persistent self-signed test certificate. It proves that the
selected executable was signed by the configured test key and was not modified afterward. Windows
does not trust this certificate on an ordinary user machine, so these packages must be labeled
test-signed and must not claim a publicly trusted publisher or warning-free installation.

Generate the certificate on a controlled Windows workstation with PowerShell. Replace the example
subject with a stable test-only project name; do not use a personal email address or private host
name.

```powershell
$certificate = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=age-plugin-phone Alpha Test Signing" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 3072 `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(2)

$password = Read-Host "PFX password" -AsSecureString
Export-PfxCertificate `
  -Cert $certificate `
  -FilePath ".\age-plugin-phone-alpha-test.pfx" `
  -Password $password
```

Generate a random PFX password of at least 24 characters in the organization password manager. Do
not pass it as a literal command-line argument or commit it to a script. Record the public
certificate SHA-256 fingerprint:

```powershell
$certificateSha256 = [BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData)
).Replace("-", "")
$certificateSha256
```

Encode the PFX without printing it to a shared terminal log:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\age-plugin-phone-alpha-test.pfx")
) | Set-Content -NoNewline ".\age-plugin-phone-alpha-test.pfx.base64"
```

Add these values to the protected GitHub `alpha-release` environment:

| Type | Name | Value |
| --- | --- | --- |
| Secret | `WINDOWS_TEST_CERTIFICATE_BASE64` | Contents of the one-line PFX Base64 file |
| Secret | `WINDOWS_TEST_CERTIFICATE_PASSWORD` | PFX password |
| Variable | `WINDOWS_TEST_CERTIFICATE_SHA256` | Registered certificate SHA-256 fingerprint |

The workflow validates that the PFX contains exactly one currently valid self-signed code-signing
certificate with a private key, binds it to the registered SHA-256 fingerprint, and imports its
public certificate into the runner's current-user trusted store only for the verification job. It
signs by certificate thumbprint, not by putting the PFX password on the `signtool` command line. An
unconditional cleanup removes the PFX and both temporary certificate-store entries.

The resulting `Valid` status proves only the job-local test trust configuration. Release evidence
records that limited trust scope. A user who has not explicitly installed this public test
certificate still sees the normal Windows warning for an untrusted publisher.

After the first public test-signed GitHub prerelease, apply to
[SignPath Foundation](https://signpath.org/) for the free open-source program. Its current terms
require an actively maintained, documented, already released project whose components use
OSI-approved licenses and contain no proprietary code. If accepted, the signing certificate is
issued to SignPath Foundation and its private key remains in their HSM-backed service. Follow their
required attribution, team-role, privacy, and code-signing-policy documentation before replacing
the test-signing steps. Do not silently treat a SignPath application as approval.

## Android signing key

For direct APK distribution, generate the long-lived app signing key on a controlled workstation.
The same key must sign future APK updates. Do not reuse the Android debug keystore.

```console
keytool -genkeypair \
  -keystore age-plugin-phone-alpha.p12 \
  -storetype PKCS12 \
  -alias age-plugin-phone-alpha \
  -keyalg RSA \
  -keysize 3072 \
  -sigalg SHA256withRSA \
  -validity 10000
```

Generate one random password of at least 24 characters in the organization password manager and use
it for both the PKCS#12 store and key-entry prompts. The workflow keeps separate Gradle variables
because both fields are mandatory, but both secrets contain this same value. Keep at least two
encrypted offline backups of the PKCS#12 file under separate custody. Losing this key prevents
normal upgrades of directly distributed APKs; disclosure permits malicious updates signed as this
application.

Inspect the public certificate and copy its SHA-256 fingerprint into the release credential record:

```console
keytool -list -v \
  -keystore age-plugin-phone-alpha.p12 \
  -storetype PKCS12 \
  -alias age-plugin-phone-alpha
```

Encode the binary PKCS#12 file as one Base64 line without printing it to a shared terminal log:

```console
openssl base64 -A \
  -in age-plugin-phone-alpha.p12 \
  -out age-plugin-phone-alpha.p12.base64
```

Add these secrets to the GitHub `alpha-release` environment:

| Secret | Value |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | Contents of the one-line Base64 file |
| `ANDROID_STORE_PASSWORD` | PKCS#12 store password |
| `ANDROID_KEY_ALIAS` | Alias selected during key generation |
| `ANDROID_KEY_PASSWORD` | Same password, supplied separately to Gradle for the key entry |
| `ANDROID_CERTIFICATE_SHA256` | Pre-registered SHA-256 certificate fingerprint, with or without colons |

After the secrets have been stored, securely delete the unencrypted Base64 transport file. Retain
the PKCS#12 file only in the approved offline backup locations. The workflow restores it with
owner-only permissions in runner-temporary storage and removes it in an `always()` cleanup step.

Before building, the workflow exports the PKCS#12 public certificate and requires its SHA-256
fingerprint to match `ANDROID_CERTIFICATE_SHA256`. After building, it requires exactly one APK
signer and compares the APK signer's certificate fingerprint with the same registered value. A
missing credential, malformed fingerprint, wrong PKCS#12 file, unexpected signer, or signature
verification failure stops the job without uploading an artifact.

If the application is later distributed through Google Play App Signing, document whether this
PKCS#12 key is the resettable upload key or the app signing key. Never assume that the upload APK
certificate and the certificate on a Play-delivered APK are identical.

## RC0 dispatch and evidence

1. Record the immutable candidate commit.
2. Confirm that the `alpha-release` environment requires an authorized reviewer.
3. Manually dispatch `Test-signed Alpha artifacts` for that commit.
4. Approve the environment only after reviewing the workflow diff and candidate commit.
5. Require both Windows and Android jobs to succeed, and label the Windows package test-signed.
6. Download both artifact groups and independently verify their SHA-256 files and signatures.
7. Compare the recorded certificate identities with the approved release credential records.
8. Run every required physical scenario in `alpha-matrix.md` against these exact packages.

Each job records the immutable commit, workflow run and attempt, signing certificate identity, exact
artifact hashes, and verification output. Release evidence must not contain private keys, passwords,
keystore contents, key aliases, raw protocol messages, QR contents, stanza bodies, file keys,
plaintext, device serials, or private state paths.
