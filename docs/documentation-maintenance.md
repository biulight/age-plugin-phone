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

## Optional server deployment

Like Shine, the workflow can deploy the same build to GitHub Pages and an SSH
server. Pages remains enabled. Server deployment runs only for `main` when the
repository variable `SERVER_DEPLOY_ENABLED` is exactly `true`.

Configure the `docs-server` GitHub environment before enabling this variable:

| Kind | Name | Purpose |
| --- | --- | --- |
| Variable | `SERVER_HOST` | SSH hostname or IP address |
| Variable | `SERVER_USER` | SSH login user |
| Variable | `SERVER_PORT` | SSH port; defaults to `22` |
| Variable | `SERVER_PATH` | Dedicated absolute directory for this site's build |
| Variable | `SERVER_URL` | Optional public URL shown in the deployment record |
| Secret | `SERVER_SSH_KEY` | SSH private key authorized for this deployment |
| Secret | `SERVER_KNOWN_HOSTS` | Previously verified server host-key entries |

The server must serve this directory under `/age-plugin-phone/`; the Chinese
manual uses `/age-plugin-phone/zh-Hans/`. GitHub Pages remains the canonical
site. Verify both locales at the server URL after deployment.

Deployment uses `rsync --delete-delay`: files absent from the build are removed
from `SERVER_PATH`. Use a dedicated directory and a restricted SSH account;
never point it at the shared web root or another product's directory. Keep
private hostnames, credentials and server paths in GitHub configuration.

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
