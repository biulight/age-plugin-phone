# crates.io release automation implementation — 2026-09-08

This is the later release-automation implementation, following the four-crate
refactor. It does not change the historical [refactor evidence](desktop-refactor-evidence.md)
or its real-device acceptance claims. Usage and external configuration are in the
[release guide](crates-io-release.md).

The working tree adds an independent manual-dispatch workflow and Python release
gates/state machine, CI fixtures, OIDC permissions, evidence/recovery handling and
documentation. Alpha binary publishing, all Rust/product code, Cargo manifests,
Cargo.lock, versions, MSRV and dependencies remain unchanged.

Local validation on macOS arm64:

| Check | Actual outcome |
| --- | --- |
| Offline release fixtures | 29 tests passed; real network and subprocess execution disabled by the fixture harness. Includes production archive provenance rejection and alternate-registry archive rejection. |
| Workflow lint | `actionlint` passed across repository workflows. |
| Package contract | `check-release-version.sh` and `check-package-layout.py --archives` passed. |
| Existing Alpha fixture suites | Both release-candidate and asset-staging fixture suites passed. |
| Minimal alternate registry | Cargo 1.88.0 two-package rehearsal passed. |
| Complete alternate registry | All four packages packaged, detached tests passed, archive/source/lock rewrite audit passed, exact CLI installed; `--help` and `setup --help` passed. |
| Installed artifact interoperability | Existing smoke script passed 12 independent recoveries and 2 expected rejections, using the alternate-registry-installed CLI, local age 1.3.2 and rage 0.12.1. The new Linux production workflow retains CI's pinned age 1.3.1/rage 0.12.1. |
| Real production dry-run adapter | Storage dry-run with unchanged production manifests, Cargo 1.88.0, explicit crates-io and `--locked` passed twice; audited archive bytes were identical. No upload was invoked. |
| Rust formatting / whitespace | Formatting and `git diff --check` passed. New files were also checked for whitespace. |

The production dry-run used a disposable clean local clone at
`afa6c177e2680decb25f0b92d34d18a5e5d0bd83`, the existing repository HEAD, whose
packaged Rust/manifests are unchanged by this implementation. Storage archive
SHA-256: `87602e9a8769c9c43114693a5287d03e6faf710356365f7abd27ab03ff00059b`.
This proves adapter compatibility/reproducibility for that source on this host;
it is not evidence for an uncommitted future release SHA or a Linux archive.
Each actual candidate must pass its own exact-SHA CI and production checks.

During the initial implementation, no actual crates.io upload, OIDC exchange, production workflow dispatch,
production registry installation, remote setting change, push, tag, GitHub
Release or version upgrade was performed. Production dependent-package dry-runs
remain unexecuted while their dependencies are unpublished; local alternate
registry success does not replace them. No new phone/native security acceptance
was performed. Required external branch/Environment/publisher configuration is
listed precisely in the release guide; its live remote state is not asserted here.

Subsequent owner-authorized configuration on 2026-09-08 created the GitHub
`crates-io-publish` Environment. Its final settings were read back: no required
reviewers, exactly one deployment rule (`main`, type `branch`), and no tag rule.
The existing `main` branch protection was not changed. Publication remains an
explicit manual dispatch with OIDC and automatic checks; there is no second
manual approval. The four crates.io Trusted Publishers and first publication
remain pending. This follow-up did not trigger a workflow or upload a crate.
