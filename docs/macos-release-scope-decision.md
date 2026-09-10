# macOS interim release and next-stage decision

Date: 2026-09-10. Status: user-approved scope and sequencing decision.

The user stopped further macOS acceptance work for the current release and decided
that the existing implementation and recorded evidence are sufficient to proceed
with version 0.1.0-alpha.5 on crates.io and GitHub prereleases. The next implementation
priority is the [tagged-recipient PRD](tagged-recipient-prd.md); completion of that
PRD, rather than this interim release, defines the end of the current development stage.

## Current release boundary

- Do not schedule additional macOS physical acceptance runs for this interim
  release. Retain the existing M0–M6 evidence, failed attempts and unverified rows.
  Those remaining rows are deferred, not passed or fixed, and no longer block this
  experimental release solely because they are untested.
- The measured Mac baseline remains MacBookPro18,3 / arm64 / macOS 26.6.2
  (25G83), in a logged-in user session. Android and iPhone results retain their
  exact caller, transport and artifact scope. No broader hardware, OS, GUI,
  camera, durability or production-secrets support is established.
- The valid-snapshot replay limitation and deferred cross-platform POC remain
  unchanged. Fresh native phone verification, complete session/response binding,
  durable consumption and rejection of uncertain state remain requirements.
- Normal version consistency, build, packaging, automated CI and release-integrity
  checks still apply. The user authorized both publication channels; this decision
  does not itself record a successful upload, signature or release.

## Next-stage boundary

The interim release contains the current phone recipient behavior, not tagged
recipient support. Follow the PRD's implementation order and completion definition
for the next stage. Its tag-specific compatibility, mobile authentication,
negative-test, interoperability and coordinated-consumer release requirements
remain in force; this macOS acceptance stop does not waive them.

Historical statements that macOS acceptance is incomplete remain true. Where older
documents make every remaining physical row a prerequisite to the next experimental
version, this release-scope decision supersedes that timing. Neither this interim
release nor this decision completes the full original macOS matrix or the PRD.
