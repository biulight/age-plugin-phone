# crates.io release pipeline

These packages remain experimental alpha software, unsuitable for real secrets.
This procedure does not claim that any version has been uploaded. Consult
[candidate evidence](desktop-refactor-evidence.md) for actual validation status.

## Installation after publication

Install an explicitly published prerelease:

```console
cargo install age-plugin-phone --version <published-version> --locked
```

Only the CLI is installed; Cargo builds its three library dependencies. Rust 1.88
or later, a native C/C++ compiler and platform SDK are needed. Windows requires
the MSVC Rust toolchain and Visual Studio C++ Build Tools/Windows SDK. Hardware
desktop use on Windows requires Windows 11+ x64, TPM 2.0 and Microsoft Platform
Crypto Provider. All hardware desktop use requires a compatible phone and fresh
native verification per unwrap. The Windows support probe must succeed before pairing.

Linux builds need a C toolchain, Clang/libclang and the Video4Linux headers for
camera support. macOS builds need Xcode Command Line Tools, the macOS SDK and
`xcrun swiftc` for the archived CryptoKit bridge. The current source implementation
uses distinct Secure Enclave desktop roles with no software fallback; other
non-Windows desktop targets retain software prototypes. macOS retains a known replay
snapshot limitation and unverified physical rows; the latter are deferred for the interim
experimental release by the [scope decision](macos-release-scope-decision.md).
A successful build is not full support.
See the [source quick start](macos-quickstart.md) and [installation evidence](macos-m5-evidence.md).
The PC archive builds independently of Tauri, Android and iOS tooling. Published
versions predating the macOS implementation must not be assumed to contain it.

## Preflight

Use Python 3.11+ and Cargo 1.88.0. Output directories must not exist and should be
outside the checkout. The script uses an isolated Cargo home and a localhost-only
sparse registry, including fresh downloads of locked third-party dependencies.

```console
scripts/check-release-version.sh
python3 scripts/check-package-layout.py --archives
cargo +1.88.0 fmt --all --check
cargo +1.88.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.88.0 test --workspace --locked
python3 scripts/registry-preflight.py --minimal --output /tmp/phone-minimal
python3 scripts/registry-preflight.py --output /tmp/phone-packages
```

Windows portable CI retains the seven native TPM skips listed in
`scripts/windows-portable-test-skips.txt`. Skipped hardware tests are not passes.
Run native tests and the PRD upgrade/phone/cancellation checks separately on the
designated hardware. Linux retains the fixed old Unix state tests. macOS runs its
native storage/journal tests; explicitly ignored Secure Enclave tests must be run
separately on the declared hardware baseline. Ignored tests do not count as passes.

The script rewrites only temporary package publish registries and the explicit
internal dependency registry, keeping exact versions and third-party crates.io
sources. Cargo 1.88 `package --registry` is unstable; the script instead uses each
temporary manifest's sole `publish` registry. It does not use nightly or bypass
verification. Normalized archives must have no path/Git dependencies. The script
checks source hashes, archived dependency versions, manifest differences, and
workspace lock changes, then builds/tests detached archives and installs from the
temporary registry. It records file inventories/digests in `archive-evidence.json`
and metadata changes in `manifest-differences.json`.

Run `scripts/interoperability-smoke.sh AGE AGE_KEYGEN RAGE RAGE_KEYGEN PLUGIN`
against the registry-installed binary. The CI uses pinned released clients and
also checks independent recovery. Preserve evidence for the final candidate;
temporary preflight archives contain alternate-registry metadata and must never
be uploaded to crates.io.

## Workflow and trust boundary

The new `.github/workflows/crates-release.yml` adds an explicitly dispatched
publication capability after the four-crate refactor. The PRD's original “no
automatic upload workflow” scope and the historical refactor/hardware evidence
remain historical facts; this document defines the later release capability.
`alpha-release.yml` continues to publish its existing Alpha binary artifacts.
This pipeline never increments a version, creates a tag or GitHub Release, or
changes protocol, custody, phone authentication, CLI behavior or platform support.

Both modes require `biulight/age-plugin-phone`, `refs/heads/main`, a protected
`main` branch, a full lowercase 40-character `expected_commit` equal to the
workflow dispatch SHA and actual clean checkout, and `expected_version` equal to
the workspace/mobile versions and all exact internal constraints. No tags,
`codex/alpha.*` branches, forks, PR events, `workflow_run` or
`pull_request_target` are accepted. The full **push CI run for that exact SHA**
must be completed with conclusion `success`: the gate checks the numeric workflow
identity resolved from `ci.yml`, its active path, both repository identities,
head branch/SHA, event and whole-run conclusion. It chooses the newest run for
that SHA, so an older successful run/job cannot hide a later failure or rerun.
The current CI still includes all platforms, mobile builds and interoperability.

The workflow-wide `crates-io-release` concurrency group serializes all versions,
all modes and the entire four-package chain, with `cancel-in-progress: false`.
GitHub concurrency is not a FIFO queue and can replace pending runs; inspect the
Actions UI. A canceled pending run is not a release. Branch protection and the
Environment are external security boundaries, not something this script creates.

## One-time external configuration

An authorized repository/crate administrator must configure these items; this
implementation does not change remote settings:

1. Protect `main` in **biulight/age-plugin-phone**. Require the full CI checks,
   restrict direct pushes/bypasses and review changes to the release workflow/scripts.
   For the current sole-maintainer setup, do not require another person's PR
   approval; inspect the diff and CI results yourself before merging.
   The gate additionally checks the branch API's `protected`
   flag. Ensure Actions can read repository contents and Actions run/artifact
   metadata (`contents: read`, `actions: read`).
2. Create the independent GitHub Environment **`crates-io-publish`**. For the
   current sole-maintainer setup, leave **Required reviewers** empty and
   **Prevent self-review** unchecked. Restrict deployment branches to
   **`main` only**, with no tag rule. Disable administrator bypass where supported.
   The environment must actually enforce these protections for this repository's
   plan; merely creating an environment with this name is insufficient.
   Review the candidate SHA, version and a completed preflight before explicitly
   dispatching `mode=publish`. After that run's automatic preflight passes, the
   publish job proceeds without a second manual approval. The Environment still
   restricts the branch and identifies the OIDC publisher. Default preflight runs
   do not use this Environment. If another maintainer joins later, you can add
   required reviewers and enable independent review.
3. Confirm ownership/availability of all four exact crate names below and the
   crates.io publisher account. **First create each crate using the separately
   authorized manual bootstrap below.** Uncreated crates cannot already have a
   Trusted Publisher configured.
4. In **each** crate's crates.io **Settings → Trusted Publishing → Add → GitHub**,
   set repository owner **`biulight`**, repository name **`age-plugin-phone`**,
   workflow filename **`crates-release.yml`**, environment **`crates-io-publish`**.
   All four entries are required, including the three libraries.
5. Permit GitHub OIDC for the protected job. Do not add a crates.io API token to
   repository/environment secrets for this workflow. The only publish credential
   is the auth action output passed to its adjacent upload step. There is no
   long-lived-token fallback. Keep release evidence for at least the 90-day
   artifact retention period, and download an independent archival copy.

Official behavior was checked on 2026-09-08 against
[crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing), its
[official source](https://github.com/rust-lang/crates.io/blob/main/svelte/src/routes/docs/trusted-publishing/+page.svelte),
and the [auth action implementation](https://github.com/rust-lang/crates-io-auth-action/tree/c6f97d42243bad5fab37ca0427f495c86d5b1a18).
Current tokens expire after 30 minutes; initial publication requires an API token.
The action masks its token and revokes it in a post-job hook. Each package gets a
fresh token **after** its potentially slow dry-run and persisted intent, immediately
before its upload. Cargo commands are limited to 20 minutes; only the upload
process inherits the token. Earlier tokens expire independently if a long chain
outlives them; post-job revocation still runs on normal failure. Abrupt runner
loss can prevent cleanup, so expiry remains the final limit. Do not rerun upload
because a token expired: inspect evidence and registry state first.

Every external Action in the new workflow is pinned to a full commit, resolved
through the official repository's GitHub API on that date:

| Action | Verified ref | Commit |
| --- | --- | --- |
| actions/checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
| dtolnay/rust-toolchain | stable | `6bed0761d98439e5a578e2877258200ad565ba87` |
| actions/upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| rust-lang/crates-io-auth-action | v1 | `c6f97d42243bad5fab37ca0427f495c86d5b1a18` |

## Dispatch a preflight

After the candidate is merged into protected `main` and its full push CI passes,
use Actions → **Publish crates.io packages** → Run workflow, select **main**,
and enter its exact SHA and current version. Leave `mode=preflight` (the default).
The preflight job has only read permissions, no Environment, no OIDC permission
and no production token. It runs offline control-flow fixtures and both the
minimal and complete alternate-registry rehearsals.

It also runs production dry-runs where prerequisites already exist. The script
records `blocked-unpublished-dependency` for dependent packages that cannot yet
run a production dry-run; that is **not** a passing production dry-run. The first
package can dry-run before its name exists. A failed attempted dry-run fails the
run. HTTP errors other than a registry 404 never count as “not published”. A green
preflight can include explicitly blocked production dry-runs: inspect result.json.
The alternate-registry evidence is separate and its archives are never uploaded.

## First creation: separately authorized manual bootstrap

Trusted Publishing cannot create these four previously unregistered crate names.
A crates.io owner must explicitly authorize a first publication outside this OIDC
workflow, on a trusted Linux x86_64 release host (Python 3.12+, Rust 1.88.0, desktop
build prerequisites). First run the preflight above. Use a **clean, exact-SHA**
checkout in an isolated directory with no ancestor `.cargo/config*`, an isolated
Cargo home and no saved registry credentials. Use a narrowly scoped, short-lived
API token permitted to create the four names; revoke it immediately after the
bootstrap. Never place this token in an artifact, shell argument, workflow secret
or `cargo login` file.

The same audited adapter/state machine can be used manually, retaining its JSON
reports and uploading nothing until the explicit `upload` command. In a shell
with `PYTHONDONTWRITEBYTECODE=1`, set `GITHUB_REPOSITORY=biulight/age-plugin-phone`,
`GITHUB_REF=refs/heads/main`, `GITHUB_EVENT_NAME=workflow_dispatch`,
`GITHUB_SHA=<full candidate SHA>`, and a read-only `GH_TOKEN` for GitHub metadata.
These variables supply the local gate's context; they do not create an actual
Actions run or authorize publishing. Leave `GITHUB_RUN_ID` unset and use
`GITHUB_RUN_ATTEMPT=1`. Initialize a new evidence directory outside the checkout:

```console
python3 scripts/release/crates_release.py init --mode publish \
  --expected-commit "$GITHUB_SHA" --expected-version 0.1.0-alpha.4 \
  --output /tmp/phone-bootstrap-evidence
```

Substitute the explicitly approved current version; no script edits versions.
For each name in this fixed order, execute `prepare`, preserve the resulting
`result.json` and `summary.md` in durable independent storage **before uploading**,
then supply the bootstrap API token only to the `upload` process environment:

1. `age-plugin-phone-platform-storage`
2. `age-plugin-phone-core`
3. `age-plugin-phone-platform-keys`
4. `age-plugin-phone`

```console
python3 scripts/release/crates_release.py prepare --package <name> --output /tmp/phone-bootstrap-evidence
# Archive the intent evidence; obtain explicit first-upload authorization.
# Supply CARGO_REGISTRY_TOKEN securely to this process only, never as an argument.
python3 scripts/release/crates_release.py upload --package <name> --output /tmp/phone-bootstrap-evidence
```

Do not advance after any failure. Retain the same evidence/work directories; do
not edit status fields. The adapter uses the original production manifests and
`cargo +1.88.0 publish --registry crates-io --locked -p <name> --dry-run`, followed
by the same command without `--dry-run`. It never uses `--no-verify` or
`--allow-dirty`; the two mobile `publish=false` packages are outside the command
allowlist. It hashes the production archive and verifies its VCS SHA, original
manifest, source files, normalized dependencies and published checksum/content.

The first bootstrap should finish all four packages, then run the `smoke`
operation below and configure their Trusted Publishers. Do not dispatch the
OIDC workflow to re-upload this bootstrap version: local bootstrap evidence is
not an authenticated Actions artifact and is deliberately not auto-imported.
For a bootstrap timeout or partial failure, an operator must reconcile the saved
archive/checksum and registry state; there is no automatic reset/retry command.
Finish/recover under separate explicit authorization or choose a separately
reviewed new coordinated version. Never upload alternate-registry archives.

## Normal publication

With all four Trusted Publishers configured, dispatch the same workflow on
**main** with the exact SHA/version and `mode=publish`. An independently protected
job waits for the preflight, without an Environment reviewer approval, then rechecks checkout,
versions, protection and exact-SHA CI. Only this job has `id-token: write`.

For each package, in storage → core → keys → CLI order, it:

1. Checks existing production version state and previous release evidence.
2. Runs production `--dry-run --locked` with Cargo 1.88.0; hashes/audits its archive.
3. Uploads immutable intent evidence before authentication. Artifact persistence
   failure prevents uploading. Obtains a fresh OIDC credential and invokes
   production publish once, explicitly targeting crates-io.
4. Checks the archive stayed identical, then verifies the crates.io version,
   checksum, downloaded package content and source SHA. Finally a fresh Cargo
   home resolves the exact version from crates.io using a new consumer lockfile
   and `cargo metadata --locked`; only then may the next package proceed.

Registry polling uses 5, 10, 20, 40, then 60-second backoff with a 600-second
polling deadline. HTTP requests have a 30-second timeout; each Cargo resolution
command has a 60-second timeout, so an in-flight probe may finish after the
polling deadline. Cargo has no transport retries (`CARGO_NET_RETRY=0`). 401/403,
429, 5xx, malformed replies and network errors stop the chain rather than imply
absence. Cargo index propagation failures are bounded polling failures, never a
successful visibility result. A successful HTTP upload alone is insufficient.

## Failure and recovery

The JSON schema records candidate SHA/version, order, CI run/attempt, per-package
production SHA-256 and file inventory, `dry_run`, `upload`, `visible`, failure
phase and post-install state. `crates-evidence-intent-*` artifacts are immutable
snapshots before upload; `crates-evidence-publish-*` and Actions summary preserve
available final results even on failure. Authentication failures are identified
by package. Raw subprocess output, HTTP bodies, credentials, Cargo homes and
production or rehearsal archives are not artifacts. A hard runner failure may
lose the final result, but the already-uploaded intent remains conservative proof
that an upload could have started. Auth action post-hook errors appear in Actions
logs after the report; review the whole job conclusion too.

Any error stops later uploads. An upload timeout/error triggers only read-only
registry reconciliation. Even if it proves the upload succeeded, that run stops
with `verified-after-error`; it does not silently continue. No yank, automatic
version change or automatic duplicate upload occurs.

To resume, create a **new workflow dispatch** for the **same SHA and version**;
do not use GitHub “Re-run jobs” (attempt > 1 is rejected). Optionally provide the
prior completed run's `recovery_run_id`. The gate scans **all same-version publish
runs even if the ID is omitted**, checks their workflow/repository/event/branch/SHA
and completion, downloads only their evidence artifacts via GitHub, validates
the API artifact SHA-256, and compares saved candidate/package evidence. A prior
attempt from a different SHA at this version prevents automatic continuation.

An existing version is reused only when the fresh production dry-run archive,
saved upload intent/receipt, registry checksum, downloaded content and embedded
source SHA all match, and Cargo can resolve it. Merely finding the name/version
(or matching only Git metadata) is insufficient. Reused versions are marked
`reused-verified` and never uploaded again. If prior intent exists but the version
is still absent, the runner refuses to retry an uncertain upload. If evidence is
missing/expired, content differs, a prior run remains incomplete, or identity
cannot be proven, stop and retain all logs/reports. The operator must check the
crates.io owner dashboard and saved production archive, resolve network/index
incidents, and establish provenance independently. Do not delete evidence or
alter JSON to force a retry. A new version requires separate review and explicit
manual version changes with renewed CI/preflight; this pipeline never does that.
GitHub runs/artifacts must not be deleted while their version remains a recovery
candidate. Evidence deliberately favors a safe stop over availability.

## Post-publication checks

After all four versions are verified, `smoke` installs the exact CLI using
`cargo +1.88.0 install --registry crates-io age-plugin-phone --version =<version>
--locked` into a temporary root with a fresh Cargo home outside the checkout.
It runs `--help` and `setup --help`, downloads the same SHA-256-pinned age 1.3.1
and rage 0.12.1 clients as CI, then reuses `scripts/interoperability-smoke.sh`
(12 independent recoveries and 2 expected rejections). On the bootstrap host:

```console
python3 scripts/release/crates_release.py smoke --output /tmp/phone-bootstrap-evidence
```

These checks exercise installed artifacts and synthetic independent recovery;
they are **not new real-phone/native-security acceptance**. The previous
[hardware acceptance record](desktop-refactor-evidence.md) remains unchanged.
A post-install failure leaves already published packages intact, records a failed
phase, and requires investigation; a verified resume can rerun install checks
without uploading any existing package again.

## Local validation of the release automation

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/release -p 'test_*.py' -v
actionlint
scripts/check-release-version.sh
python3 scripts/check-package-layout.py --archives
scripts/test-prepare-alpha-release-publish.sh
scripts/test-validate-alpha-release-candidate.sh
git diff --check
```

The fixture suite disables real subprocess/network access globally and injects
mock I/O into the actual release state machine and adapters. It covers candidate,
CI and recovery identity failures, ordering, delayed visibility, authentication,
accepted uploads followed by client timeouts, partial completion, matching and
mismatching existing versions, no duplicate upload, downstream stopping, and
credential-free diagnostics/artifacts. Local fixtures cannot establish remote
Environment rules, OIDC exchange or real crates.io upload success.

## Native tag candidate gate

The optional tag implementation is tracked in [candidate evidence](tagged-recipient-evidence.md)
and [ADR 0026](adr/0026-native-tagged-recipients.md). Desktop, Android and iOS must support
p256tag in the same compatible release batch. Preserve protocol v2 pairing and replay state;
phone remains the default. Age v1.3.2/rage 0.12.1 software interoperability does not satisfy
StrongBox/Secure Enclave physical authorization, cancellation, timeout, lifecycle, wrong-device,
upgrade, independent recovery or mixed phone/SE prompt tests. Run those on exact candidate
artifacts and record hashes before advertising tag support. Unrun hardware rows are unverified.
Shine acceptance is separate and does not authorize a plugin-specific application interface.
Signing, uploading and publication require their own authorization; this implementation does not
perform them or expand production support.
