# Alpha release signing setup

This runbook configures the credentials consumed by
`.github/workflows/alpha-release.yml`. Distribution signing is separate from the protocol key
boundary: Windows release signing never substitutes for the desktop TPM keys, and Android APK
signing never substitutes for the phone StrongBox identity and response-signing keys.

The workflow uses two protected GitHub environments. `alpha-release` contains the signing
configuration and is used only by the Windows and Android signing jobs. `alpha-release-publish`
has the same required-reviewer protection but **no signing secrets or variables**; it is used only
to promote a physically verified candidate. Configure both environments before dispatching a
candidate. Only dispatch the workflow from an immutable commit selected for the release candidate.

## Windows test signing certificate chain

The pre-commercial RC workflow uses a private test root CA and one persistent code-signing leaf
certificate. It proves that the selected executable was signed by the configured test key and was
not modified afterward. Windows does not trust this private root on an ordinary user machine, so
these packages must be labeled test-signed and must not claim a publicly trusted publisher or
warning-free installation.

Generate the certificate on a controlled Windows workstation with PowerShell. Replace the example
subject with a stable test-only project name; do not use a personal email address or private host
name.

```powershell
$root = New-SelfSignedCertificate `
  -Type Custom `
  -Subject "CN=age-plugin-phone Alpha Test Root" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyAlgorithm RSA `
  -KeyLength 3072 `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy Exportable `
  -KeyUsage CertSign,CRLSign,DigitalSignature `
  -TextExtension @("2.5.29.19={critical}{text}ca=1&pathlength=0") `
  -NotAfter (Get-Date).AddYears(5)

$certificate = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=age-plugin-phone Alpha Test Signing" `
  -Signer $root `
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
  -Password $password `
  -ChainOption EndEntityCertOnly
Export-Certificate `
  -Cert $root `
  -FilePath ".\age-plugin-phone-alpha-test-root.cer"
Export-PfxCertificate `
  -Cert $root `
  -FilePath ".\age-plugin-phone-alpha-test-root-private.pfx" `
  -Password $password `
  -ChainOption EndEntityCertOnly
```

Generate a random PFX password of at least 24 characters in the organization password manager. Do
not pass it as a literal command-line argument or commit it to a script. Back up the root private
key separately so the leaf can be renewed, but never upload the root private key to GitHub. Record
the leaf and root public-certificate SHA-256 fingerprints:

```powershell
$certificateSha256 = [BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData)
).Replace("-", "")
$certificateSha256
$rootCertificateSha256 = [BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash($root.RawData)
).Replace("-", "")
$rootCertificateSha256
```

Encode the PFX without printing it to a shared terminal log:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\age-plugin-phone-alpha-test.pfx")
) | Set-Content -NoNewline ".\age-plugin-phone-alpha-test.pfx.base64"
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\age-plugin-phone-alpha-test-root.cer")
) | Set-Content -NoNewline ".\age-plugin-phone-alpha-test-root.cer.base64"
```

Add these values to the protected GitHub `alpha-release` environment:

| Type | Name | Value |
| --- | --- | --- |
| Secret | `WINDOWS_TEST_CERTIFICATE_BASE64` | Contents of the one-line PFX Base64 file |
| Secret | `WINDOWS_TEST_CERTIFICATE_PASSWORD` | PFX password |
| Variable | `WINDOWS_TEST_CERTIFICATE_SHA256` | Registered leaf-certificate SHA-256 fingerprint |
| Variable | `WINDOWS_TEST_ROOT_CERTIFICATE_BASE64` | Contents of the one-line public root CER Base64 file |
| Variable | `WINDOWS_TEST_ROOT_CERTIFICATE_SHA256` | Registered root-certificate SHA-256 fingerprint |

Delete both Base64 transport files after provisioning. Keep the root-private PFX only in the
encrypted recovery backup; the workflow never needs it.

The workflow validates that the PFX contains exactly one currently valid code-signing certificate
with a private key, binds both certificates to their registered SHA-256 fingerprints, and requires
the leaf to form an exact two-certificate chain to the configured private root. It signs by
certificate thumbprint, not by putting the PFX password on the `signtool` command line. The root is
used only with .NET's in-memory custom-root validation and is never installed in a Windows trust
store. An unconditional cleanup removes the imported leaf certificate and temporary files.

Release verification requires SignTool to validate the Authenticode content and signature and to
reject only the untrusted private root, then separately validates the complete chain against that
root in memory. Release evidence records this limited trust scope. A user who has not explicitly
installed the public test root still sees the normal Windows warning for an untrusted publisher.

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

## Alpha candidate dispatch, physical gate, and publication

This is the only Alpha publication path:

1. Commit the Alpha candidate. Its full 40-character commit SHA, all three application manifests,
   and `docs/releases/vVERSION.md` must agree on one `X.Y.Z-alpha.N` version.
2. From that exact commit, manually dispatch `Publish test-signed Alpha prerelease`, supplying the
   same full SHA in `expected_commit`. The preflight rejects a branch snapshot that is not that SHA,
   inconsistent manifests, a missing release note, or an existing tag or GitHub release.
3. Approve the `alpha-release` signing jobs only after reviewing the candidate and workflow.
   Require both signing jobs to pass. Their versioned packages and four versioned evidence records
   are retained for 30 days.
4. While the `alpha-release-publish` job waits for its separate approval, download the Windows and
   Android artifacts from **that same workflow run**. Independently check the hashes and recorded
   certificate identities, label the Windows package test-signed, and complete every required
   physical row in `alpha-matrix.md` against those exact packages.
5. Only after the physical regression passes, approve `alpha-release-publish`. That job has only
   `contents: write`; it cannot read signing credentials. It rechecks the candidate commit,
   version, run/attempt agreement, APK/ZIP hashes, certificate fingerprints, ZIP contents, and the
   Windows in-memory private-root-only trust record. It then creates the annotated `vVERSION` tag,
   creates a draft prerelease, uploads the six verified assets, rechecks their remote SHA-256
   digests, and only then makes the prerelease public.

Do not manually create or move the final tag, create a release, upload release assets, or mix
packages/evidence from different workflow runs or attempts. A failure before public release remains
fail-closed. A run may only resume a matching, unpublished draft whose provenance marker binds it
to the same candidate and workflow run; never replace an asset or modify a public release.

Each job records the immutable commit, workflow run and attempt, signing certificate identity, exact
artifact hashes, and verification output. Release evidence must not contain private keys, passwords,
keystore contents, key aliases, raw protocol messages, QR contents, stanza bodies, file keys,
plaintext, device serials, or private state paths.
