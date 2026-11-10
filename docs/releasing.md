# Releasing

## How a release happens

1. Run the **Create a release PR** workflow (Actions → Create a release PR → patch / minor / major). It bumps the
   workspace version in `Cargo.toml`, regenerates `CHANGELOG.md` with git-cliff from the conventional commits, and
   opens a pull request titled `Release vX.Y.Z` with the release notes as its body.
2. Review and merge it. The **Release** workflow tags the merge commit and creates the GitHub release with the notes.
3. The **Publish** workflow builds everything below (static musl binaries, the agent with the UI embedded, the UI's
   image), writes `SHA256SUMS` and its GPG signature, and uploads them to the release.

Every push to `main` also updates the `latest` pre-release (the **Latest** workflow): the tag moves to the new
commit, the notes list the unreleased changes, and Publish uploads the same files, signed the same way, with the
version marked as a build of main (`0.1.1-dev+abc1234`, from `BARBICAN_VERSION_SUFFIX`). The pre-release is never
marked as GitHub's latest release, so `releases/latest` keeps pointing at the newest `vX.Y.Z`.

Asset names never change, so `https://github.com/nikarh/barbican/releases/latest/download/<name>` always points at
the newest file:

| Asset | Contents |
| --- | --- |
| `barbican-{x86_64,aarch64}-linux-musl` | The agent |
| `barbican-{x86_64,aarch64}-linux-musl.tar.gz` | The agent, its systemd unit, the example config, the README and the licenses |
| `barbican_{amd64,arm64}.deb`, `barbican-{x86_64,aarch64}.pkg.tar.zst` | Debian and Arch Linux packages of the agent |
| `barbican-edge-{x86_64,aarch64,armv7}.apk`, `.ipk` | The edge agent for OpenWrt (25.12 and later, 24.10 and earlier) |
| `luci-app-barbican.apk`, `.ipk` | Its LuCI pages |
| `barbican-edge-{x86_64,aarch64,armv7}.tar.gz` | The same, with `install.sh`, for installing by hand |
| `barbican-edge-ipset-{armv7,x86_64}.tar.gz` | The ipset edge agent for Asuswrt-Merlin, with its supervisor and installer |
| `SHA256SUMS`, `SHA256SUMS.asc` | Checksums of all of the above and their detached GPG signature |

The UI's container image, `ghcr.io/nikarh/barbican` (linux/amd64 and linux/arm64), is tagged `X.Y.Z`, `X.Y` and
`latest` for releases, and `main` and `sha-<commit>` for builds of main. Before it is pushed, Publish runs it
read-only, without capabilities, as nobody, in front of an agent on the runner, and checks the page, the WebSocket
and the Origin check through it.

To check downloads:

```sh
curl -fsSLO https://github.com/nikarh/barbican/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/nikarh/barbican/releases/latest/download/SHA256SUMS.asc
curl -fsSL https://raw.githubusercontent.com/nikarh/barbican/main/docs/signing-key.asc | gpg --import
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Dependabot's pull requests are merged by the **Auto-merge** workflow once every required check is green.

## One-time setup

### Release bot and the `release` environment

The release workflows act as a GitHub App (`nikarh-release-bot`), like the other nikarh repositories: the app needs
*Contents* and *Pull requests* read & write, and to be installed on the repository. The `release` environment
(Settings → Environments) only allows the `main` and `release` branches and `v*` tags, and holds these secrets:

| Secret | Value |
| --- | --- |
| `APP_CLIENT_ID` | The app's client ID (`Iv…`, on the app's settings page) |
| `APP_PRIVATE_KEY` | A private key of the app (PEM) |
| `GPG_PRIVATE_KEY` | ASCII armored private key that signs `SHA256SUMS` |
| `GPG_PASSPHRASE` | Its passphrase |

```sh
gh secret set APP_CLIENT_ID --env release --repo nikarh/barbican --body <client id>
gh secret set APP_PRIVATE_KEY --env release --repo nikarh/barbican < release-bot.private-key.pem
```

### GPG signing key

"barbican releases" (`2DED94B14E12F49939656D6611E3B0A85A53607A`, ed25519, until 2029-11-09) is in the maintainer's
GPG keyring, its passphrase in the desktop keyring (`secret-tool lookup service barbican-release-gpg`). The public key
is [`signing-key.asc`](signing-key.asc). To set the secrets again:

```sh
secret-tool lookup service barbican-release-gpg | gh secret set GPG_PASSPHRASE --env release --repo nikarh/barbican
secret-tool lookup service barbican-release-gpg \
  | gpg --batch --pinentry-mode loopback --passphrase-fd 0 --armor \
    --export-secret-keys 2DED94B14E12F49939656D6611E3B0A85A53607A \
  | gh secret set GPG_PRIVATE_KEY --env release --repo nikarh/barbican
```
