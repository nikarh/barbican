// @ts-check
import { defineConfig, passthroughImageService } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import baseLinks from './src/plugins/base-links.mjs';

// Every version of the docs is built on its own, into a directory of the gh-pages branch named after it
// (see scripts/docs-publish.sh): DOCS_VERSION is `main` or a release tag, and the base is /<version>/.
// Without DOCS_VERSION (mise run docs) the site is served at the root as `dev`.
const version = process.env.DOCS_VERSION || 'dev';
const base = process.env.DOCS_VERSION ? `/${version}` : '/';

export default defineConfig({
	site: 'https://barbican.arhipov.net',
	base,
	trailingSlash: 'always',
	// Pages that moved; the destination is a URL, so it carries the base.
	redirects: { '/edge/protocol/': `${base.replace(/\/$/, '')}/internals/edge-link/` },
	image: { service: passthroughImageService() },
	vite: { define: { 'import.meta.env.DOCS_VERSION': JSON.stringify(version) } },
	markdown: { processor: satteri({ mdastPlugins: [baseLinks(base)] }) },
	integrations: [
		starlight({
			title: 'Barbican',
			description:
				'Bans addresses that abuse your services, from the logs of a reverse proxy, SSH and an authentication portal, with nftables on the server and on routers.',
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/nikarh/barbican' }],
			editLink: { baseUrl: 'https://github.com/nikarh/barbican/edit/main/site/' },
			lastUpdated: false,
			customCss: [
				'@fontsource-variable/inter/wght.css',
				'@fontsource-variable/jetbrains-mono/wght.css',
				'./src/styles/theme.css',
			],
			components: {
				SiteTitle: './src/components/SiteTitle.astro',
				Banner: './src/components/Banner.astro',
			},
			expressiveCode: {
				themes: ['github-dark-default', 'github-light-default'],
				styleOverrides: {
					borderRadius: '6px',
					codeFontSize: '0.8125rem',
					frames: { editorActiveTabIndicatorTopColor: 'transparent', shadowColor: 'transparent' },
				},
			},
			sidebar: [
				{ label: 'Getting started', items: [{ autogenerate: { directory: 'start' } }] },
				{ label: 'Install', items: [{ autogenerate: { directory: 'install' } }] },
				{ label: 'Guides', items: [{ autogenerate: { directory: 'guides' } }] },
				{ label: 'Edge agents', items: [{ autogenerate: { directory: 'edge' } }] },
				{ label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
				{ label: 'How it works', items: [{ autogenerate: { directory: 'internals' } }] },
				{ label: 'Project', collapsed: true, items: [{ autogenerate: { directory: 'project' } }] },
			],
		}),
	],
});
