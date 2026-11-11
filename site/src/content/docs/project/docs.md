---
title: Writing the docs
description: Where the documentation lives, how to preview it, the conventions it follows, its screenshots, and how versions are published.
sidebar:
  order: 2
---

The documentation is this site, an [Astro Starlight](https://starlight.astro.build) project in `site/`. Its pages are Markdown (and MDX) files in `site/src/content/docs/`; the README only has an overview and links here.

## Previewing

```bash
mise run docs          # dev server at http://localhost:4321, reloads on save
mise run docs:build    # build as CI does, and check every internal link and anchor
```

Both install the dependencies first. Node comes from `mise.toml`.

## Where things go

| Directory | Sidebar group | For |
| --- | --- | --- |
| `start/` | Getting started | introduction, quick start |
| `install/` | Install | one page per system, verifying downloads |
| `guides/` | Guides | sources, rules and policy, countries and feeds, the UI, reverse proxies, importing logs |
| `edge/` | Edge agents | connecting, configuring, LuCI, the protocol |
| `reference/` | Reference | configuration, command line, resource use, changelog |
| `internals/` | How it works | the engine, the firewall, security |
| `project/` | Project | development, docs, releasing |

The sidebar is generated from the directories; order pages with `sidebar.order` in their frontmatter. A new page needs `title` and `description` frontmatter, and no H1.

## When to update what

Every change to behaviour updates the docs in the same commit:

- A new or changed setting: `reference/configuration.md` and `dist/config.toml`.
- A new or changed source, parser or event: `guides/sources.md`, and `guides/rules.mdx` if rules can match it.
- A change to the default rules or the policy: `guides/rules.mdx`.
- A new or changed feed preset: `guides/feeds.mdx`.
- A new or changed edge option: `edge/configuration.md`, `dist/openwrt/barbican.config`, `dist/merlin/barbican.conf` and the LuCI settings page.
- A change to the edge protocol: `edge/protocol.md`.
- A new command or option: `reference/cli.md`.
- A visible change to the UI: `guides/ui.mdx`, and the screenshots.

## Conventions

- Plain, precise sentences, engineer to engineer. Say what happens, not how good it is.
- Internal links are site-absolute, without the version: `[sources](/guides/sources/)`, with the trailing slash. A plugin adds the base of the version being built. The build fails on a link to a page or anchor that doesn't exist.
- Code blocks have a language, and a `title` when they are a file.
- Examples use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and example domains (`example.com`, `example.org`, `example.net`), never a real deployment's.
- Don't document behaviour the code doesn't have. Check the source, or the end-to-end suite that covers it.

## Screenshots

The UI's screenshots in `site/src/assets/screenshots/` are generated, never taken by hand, and nothing of a real deployment or of the machine that makes them goes in:

```bash
mise run docs:screenshots    # scripts/screenshots.sh; KEEP_VM=1 leaves the VM running
```

1. It builds the UI and static binaries of the agent and the edge agent, and boots the end-to-end suites' server VM (`e2e/vm.sh`, see [Development](/project/development/)), which needs what `mise run e2e` needs.
2. `site/scripts/history.mjs` makes up a history from a fixed seed: Traefik, sshd and Authelia logs of scanners, password guessers and a few users, on `example.com`, `example.org` and `example.net`, from documentation addresses and random public-looking ones (so that geolocation spreads them over countries), ending now; the policy, feeds (the Cloudflare allow preset among them), allow and deny lists, and a ban by hand.
3. `scripts/screenshots-vm.sh`, in the VM, runs the agent in dry run, sets it up through the RPC, imports the history (`barbican import`), starts two edge agents in dry run that follow it, and appends a few lines while the screenshots are taken. Geolocation uses DB-IP's free databases; the VM reaches the internet only for the feeds' lists.
4. `site/scripts/screenshots.mjs` drives the system's Chromium (with `playwright-core`; no browser is downloaded, and it runs with a fresh profile) through an SSH port forward to the VM: every screen in the dark and the light scheme, on a desktop and some on a phone, encoded as WebP.
5. Before a screen is taken, its text is checked: every address, prefix and domain on it has to be one the history made up, and this machine's user, home and host names must not appear. Anything else fails the run, and nothing is written.

Then the VM is stopped, and its disk thrown away.

Each screenshot is `<name>-dark.webp` and `<name>-light.webp`; pages show the one of the reader's scheme with the `Screenshot` component:

```mdx
import Screenshot from '../../../components/Screenshot.astro';

<Screenshot name="bans" alt="The Bans screen: ..." />
```

## Versions

The site is published on GitHub Pages from the `gh-pages` branch, at `https://barbican.arhipov.net/` (the `CNAME` file), one directory per version:

| Path | Built from | Updated |
| --- | --- | --- |
| `/main/` | the tip of `main` | on every push to `main` |
| `/vX.Y.Z/` | the release tag | once, when the release is published; kept for good |
| `/` | | redirects to the newest release (to `/main/` while there is none) |
| `/versions.json` | | the list of versions, read by the version menu |

A path without a version (`/reference/configuration/`, what the config file and the README link to) goes to that page of the newest release, through `404.html`.

The **Docs** workflow (`.github/workflows/docs.yml`) builds the site with `DOCS_VERSION` set to the version, which sets the base path, and `scripts/docs-publish.sh` copies the build into the version's directory of `gh-pages`, rewrites `versions.json` and the root redirect, and pushes. Pull requests only build, so broken links fail them. The `latest` pre-release has no docs of its own: it is `main`.

A release's docs are its tag's `site/`, frozen when the release is published. To fix the docs of a release after the fact, run the workflow by hand with the tag (`gh workflow run docs.yml -f version=v0.2.0`): it rebuilds that version from the tag, so the fix has to be on the tag. Normally, fix `main` instead; the next release carries it. Don't edit the `gh-pages` branch by hand.

Old versions read `versions.json` when they load, so their version menu offers releases made after them.
