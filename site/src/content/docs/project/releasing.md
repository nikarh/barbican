---
title: Releasing
description: How a release is made, what it publishes, and the one-time setup of the release bot and signing key.
sidebar:
  order: 3
---

## How a release happens

1. Run the **Create a release PR** workflow (Actions → Create a release PR → patch / minor / major). It bumps the workspace version in `Cargo.toml`, regenerates `CHANGELOG.md` with git-cliff from the conventional commits, and opens a pull request titled `Release vX.Y.Z` with the release notes as its body.
2. Review and merge it. The **Release** workflow tags the merge commit and creates the GitHub release with the notes.
3. The **Publish** workflow builds everything (static musl binaries, the agent with the UI embedded, packages, the UI's image), writes `SHA256SUMS` and its GPG signature, and uploads them to the release. The files are listed in [Verifying downloads](/install/verifying/#release-files).
4. The **Docs** workflow publishes the release's documentation as `/vX.Y.Z/`, and the site's root then leads to it. The [changelog](/reference/changelog/) is built from `CHANGELOG.md`.

Every push to `main` also updates the `latest` pre-release (the **Latest** workflow): the tag moves to the new commit, the notes list the unreleased changes, and Publish uploads the same files, signed the same way, with the version marked as a build of main (`0.1.1-dev+abc1234`, from `BARBICAN_VERSION_SUFFIX`). The pre-release is never marked as GitHub's latest release, so `releases/latest` keeps pointing at the newest `vX.Y.Z`.

The UI's container image, `ghcr.io/nikarh/barbican` (linux/amd64 and linux/arm64), is tagged `X.Y.Z`, `X.Y` and `latest` for releases, and `main` and `sha-<commit>` for builds of main. Before it is pushed, Publish runs it read-only, without capabilities, as nobody, in front of an agent on the runner, and checks the page, the WebSocket and the Origin check through it.

Dependabot's pull requests are merged by the **Auto-merge** workflow once every required check is green.

## One-time setup

### Release bot and the `release` environment

The release workflows act as a GitHub App (`nikarh-release-bot`): the app needs *Contents* and *Pull requests* read & write, and to be installed on the repository. The `release` environment (Settings → Environments) only allows the `main` and `release` branches and `v*` tags, and holds these secrets:

| Secret | Value |
| --- | --- |
| `APP_CLIENT_ID` | The app's client ID (`Iv…`, on the app's settings page) |
| `APP_PRIVATE_KEY` | A private key of the app (PEM) |
| `GPG_PRIVATE_KEY` | ASCII armored private key that signs `SHA256SUMS` |
| `GPG_PASSPHRASE` | Its passphrase |

```bash
gh secret set APP_CLIENT_ID --env release --repo nikarh/barbican --body <client id>
gh secret set APP_PRIVATE_KEY --env release --repo nikarh/barbican < release-bot.private-key.pem
```

### GPG signing key

"barbican releases" (`2DED94B14E12F49939656D6611E3B0A85A53607A`, ed25519, until 2029-11-09) is in the maintainer's GPG keyring, its passphrase in the desktop keyring (`secret-tool lookup service barbican-release-gpg`). The public key is [`docs/signing-key.asc`](https://github.com/nikarh/barbican/blob/main/docs/signing-key.asc). To set the secrets again:

```bash
secret-tool lookup service barbican-release-gpg | gh secret set GPG_PASSPHRASE --env release --repo nikarh/barbican
secret-tool lookup service barbican-release-gpg \
  | gpg --batch --pinentry-mode loopback --passphrase-fd 0 --armor \
    --export-secret-keys 2DED94B14E12F49939656D6611E3B0A85A53607A \
  | gh secret set GPG_PRIVATE_KEY --env release --repo nikarh/barbican
```

### The documentation site

GitHub Pages (Settings → Pages) deploys the `gh-pages` branch, from its root, which the Docs workflow creates on its first run; the custom domain is `barbican.arhipov.net` (the branch's `CNAME` file), with a DNS `CNAME` record pointing it at `nikarh.github.io`. See [Writing the docs](/project/docs/#versions).
