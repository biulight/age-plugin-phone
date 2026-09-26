# Documentation maintenance

The public manual lives in `docs/manual/` (English) and
`website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/` (Simplified Chinese).
Both locales describe the same released behavior. Keep page IDs, routes, examples,
warnings and navigation aligned. The locale checker verifies structure and command
blocks; a human semantic review is still necessary.

Only these manual directories are published. Architecture, protocols, ADRs,
acceptance records, PRDs and release runbooks remain outside the website content root.
The Biulight blog owns the product portal, not another copy of this manual.

## Local checks

With Node.js 22+ and pnpm 11.7.0, run from `website/`:

```sh
pnpm install --frozen-lockfile
pnpm check:locales
pnpm typecheck
pnpm build
pnpm serve
```

The site uses `/age-plugin-phone/` for English and `/age-plugin-phone/zh-Hans/`
for Chinese. Builds reject broken internal links. Inspect both homepages, a quick
start, the command reference, language switching and mobile navigation.

## Publication

The Documentation workflow builds pull requests and publishes `main` through
GitHub Pages. Enable Pages with **GitHub Actions** as its build source before the
first deployment. A manual dispatch from another branch builds but never deploys.
The intended URLs are `https://biulight.github.io/age-plugin-phone/` and its
`zh-Hans/` counterpart. Verify the deployed URLs before changing the blog portal
from repository-manual links to hosted links. Do not claim a site is live from a
successful local build alone.

Keep existing quickstart/recovery Markdown paths and their section anchors;
each now has a notice directing current users to the new manual. Do not rewrite
historical acceptance claims or immutable release bodies to appear current.

## Initial manual fact review

Baseline: `v0.1.0-beta.2` (`e08d631b33bd0c16948ca26275bc851b0bf56c15`).
At review time, HEAD differed from this tag only in README; pre-existing pending
release-policy documentation was preserved. GitHub release metadata confirmed
publication on 2026-09-11 and the Windows/Android assets. The immutable release
body retains candidate wording and is not changed by this documentation migration.

| Manual topic | Authority reviewed |
| --- | --- |
| Commands, setup JSON | `crates/desktop/src/main.rs`, `setup.rs` |
| Recipient choices | `pairing.rs`, `age_recipient.rs`, `docs/tagged-recipient-quickstart.md` |
| Route selection and environment | `transport_policy.rs`, `age_identity.rs`, `locator.rs` |
| Cleanup and replacement | `desktop_cleanup.rs`, `docs/macos-recovery.md` |
| Wi-Fi diagnosis | `scripts/windows-wifi-firewall.ps1`, `docs/windows-wifi.md` |
| Scope and delivery | `docs/beta-readiness.md`, `docs/releases/v0.1.0-beta.2.md`, GitHub release metadata |

The new manual does not turn deferred hardware, exact-package, QR/tag or lifecycle
checks into passes. No new runtime or real-device acceptance is claimed.
