// Takes the docs' screenshots of the UI (run by scripts/screenshots.sh, against an agent in a VM fed with
// site/scripts/history.mjs): every screen in dark and light, on a desktop screen and some on a phone's, as WebP.
//
//   node site/scripts/screenshots.mjs --url <the UI> --chromium <path> --allow <allow.json> --out <dir>
//
// Before a page is taken, its text is checked: every address, domain and user name it shows has to be one the
// history made up (allow.json), and nothing of this machine (its user, home or host name) may show. One that isn't
// fails the run, and nothing is written.
import { chromium } from 'playwright-core';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync, cpSync, readdirSync } from 'node:fs';
import { tmpdir, userInfo, hostname, homedir } from 'node:os';
import { join } from 'node:path';
import { isIP } from 'node:net';

const args = Object.fromEntries(
	process.argv.slice(2).reduce((pairs, arg, i, all) => (arg.startsWith('--') ? [...pairs, [arg.slice(2), all[i + 1]]] : pairs), []),
);
for (const key of ['url', 'chromium', 'allow', 'out']) {
	if (!args[key]) {
		console.error('usage: screenshots.mjs --url <url> --chromium <path> --allow <allow.json> --out <dir>');
		process.exit(1);
	}
}
const url = args.url.replace(/\/?$/, '/');
const allow = JSON.parse(readFileSync(args.allow, 'utf8'));

// --- What a page may show -------------------------------------------------------------------------------------

/** An IPv6 address the way the UI writes it, so that both sides compare. */
const canonical = (ip) => (isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip);
const v4number = (ip) => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);
const v6bits = (ip) => {
	const [head, tail = ''] = canonical(ip).split('::');
	const h = head ? head.split(':') : [];
	const t = tail ? tail.split(':') : [];
	const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
	return groups.map((g) => parseInt(g, 16).toString(2).padStart(16, '0')).join('');
};
const within = (ip, prefix) => {
	const [net, bits] = prefix.split('/');
	if (isIP(ip) !== isIP(net)) return false;
	if (isIP(ip) === 4) {
		const shift = 32 - Number(bits);
		return Math.floor(v4number(ip) / 2 ** shift) === Math.floor(v4number(net) / 2 ** shift);
	}
	return v6bits(ip).slice(0, Number(bits)) === v6bits(net).slice(0, Number(bits));
};
const addresses = new Set(allow.addresses.map(canonical));
const addressAllowed = (ip) => addresses.has(canonical(ip)) || allow.prefixes.some((p) => within(ip, p));
// IPv6 bans are of the /64 (`2001:db8:1:2::`): one of the history's addresses has to be in it.
const prefixAllowed = (net, bits) => allow.prefixes.some((p) => within(net, p)) || allow.addresses.some((ip) => within(ip, `${net}/${bits}`));
const domainAllowed = (name) => {
	const lower = name.toLowerCase();
	// innerText runs neighbouring elements' text together: `LiteDB-IP.com`.
	return allow.domains.some((d) => lower === d || lower.endsWith(`.${d}`) || (lower.endsWith(d) && !lower.slice(0, -d.length).includes('.')));
};
// Names with a dot that aren't domains: files, paths the visitors asked for, settings and user agents.
const NOT_DOMAINS = new Set([
	'toml', 'db', 'mmdb', 'log', 'php', 'json', 'txt', 'netset', 'sock', 'env', 'git', 'html', 'htm', 'asp', 'aspx', 'cgi',
	'xml', 'yml', 'yaml', 'sh', 'bak', 'sql', 'zip', 'js', 'css', 'ico', 'pdf', 'production', 'store', 'ds_store',
	'credentials', 'conf', 'gz', 'mjs', 'ts', 'service', 'socket', 'token', 'pem', 'crt', 'key',
]);
// Settings, as in `geoip.download`.
const SETTINGS = new Set(['database', 'ui', 'edge', 'firewall', 'geoip', 'docker', 'exempt', 'source']);
const local = [userInfo().username, hostname(), homedir()].filter((s) => s && s.length > 2);

/** What the page shows that the history didn't make up. */
function foreign(text, extra) {
	const found = new Set();
	for (const name of extra) text = text.split(name).join(' ');
	for (const [, ip, bits] of text.matchAll(/(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?(?![\w.])/g)) {
		if (isIP(ip) !== 4) continue;
		if (!(addressAllowed(ip) || (bits && prefixAllowed(ip, bits)))) found.add(ip);
	}
	for (const [token] of text.matchAll(/[0-9a-f]*:[0-9a-f:]*[0-9a-f]*(?:\/\d{1,3})?/gi)) {
		const [ip, bits = '64'] = token.split('/');
		if (!(ip.includes('::') || ip.split(':').length >= 5) || isIP(ip) !== 6) continue;
		if (!(addressAllowed(ip) || (ip.endsWith('::') && prefixAllowed(ip, bits)))) found.add(token);
	}
	for (const [name] of text.matchAll(/(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9](?![\w-])/gi)) {
		const labels = name.toLowerCase().split('.');
		if (NOT_DOMAINS.has(labels.at(-1)) || SETTINGS.has(labels[0]) || domainAllowed(name)) continue;
		found.add(name);
	}
	for (const s of local) if (text.toLowerCase().includes(s.toLowerCase())) found.add(`(this machine) ${s}`);
	return [...found];
}

// --- The agent's own view, for the names of networks and an address worth showing -----------------------------

async function rpc(method, params) {
	const socket = new WebSocket(`${url.replace(/^http/, 'ws')}api/ws`);
	await new Promise((resolve, reject) => {
		socket.onopen = resolve;
		socket.onerror = () => reject(new Error(`can't connect to ${url}api/ws`));
	});
	const answer = await new Promise((resolve, reject) => {
		socket.onmessage = (message) => {
			const data = JSON.parse(message.data);
			if (data.id !== '1') return;
			if (data.type === 'error') reject(new Error(`${method}: ${data.error.message}`));
			else resolve(data.result);
		};
		socket.send(JSON.stringify({ id: '1', method, params }));
	});
	socket.close();
	return answer;
}

const networks = new Set();
for (let offset = 0; ; ) {
	const page = await rpc('ips.list', { offset, limit: 500 });
	for (const row of page.rows) if (row.asName) networks.add(row.asName);
	offset += page.rows.length;
	if (!page.rows.length || offset >= page.total) break;
}
const banned = await rpc('ips.list', { filter: 'banned', sort: 'hits', limit: 100 });
const featured = banned.rows.find((row) => row.country && row.asName && row.ip.includes('.'))?.ip ?? banned.rows[0]?.ip;
if (!featured) throw new Error('nothing was banned: did the import work?');
// Longest first, so that a name containing another one goes as a whole.
const extra = [...networks].sort((a, b) => b.length - a.length);

// --- The screens -------------------------------------------------------------------------------------------------

const DESKTOP = [
	{ name: 'overview', hash: '#/overview' },
	{ name: 'addresses', hash: '#/addresses' },
	{ name: 'address', hash: `#/addresses?ip=${encodeURIComponent(featured)}` },
	{ name: 'events', hash: '#/events' },
	{ name: 'bans', hash: '#/bans' },
	{ name: 'rules', hash: '#/rules' },
	{
		name: 'rule',
		hash: '#/rules',
		act: async (page) => {
			await page.getByRole('button', { name: 'Edit' }).first().click();
			await page.locator('.mantine-Modal-content').waitFor();
		},
	},
	{ name: 'settings-policy', hash: '#/settings?tab=policy' },
	{ name: 'settings-lists', hash: '#/settings?tab=lists' },
	{ name: 'settings-feeds', hash: '#/settings?tab=feeds' },
	{ name: 'settings-geoip', hash: '#/settings?tab=geoip' },
	{ name: 'settings-edges', hash: '#/settings?tab=edges' },
	{ name: 'settings-about', hash: '#/settings?tab=about' },
];
const PHONE = [
	{ name: 'overview-phone', hash: '#/overview' },
	{ name: 'address-phone', hash: `#/addresses?ip=${encodeURIComponent(featured)}` },
	{ name: 'bans-phone', hash: '#/bans' },
];
const SCREENS = [
	// Drawn at twice the size, and scaled to `width` pixels.
	{ shots: DESKTOP, viewport: { width: 1280, height: 800 }, scale: 2, width: 1600, mobile: false },
	{ shots: PHONE, viewport: { width: 390, height: 844 }, scale: 2, width: 780, mobile: true },
];

/** Until the page has its data and stops changing. */
async function settle(page) {
	await page.evaluate(() => document.fonts.ready);
	let last = '';
	let same = 0;
	for (let i = 0; i < 100 && same < 6; i++) {
		await page.waitForTimeout(250);
		const now = await page.evaluate(() =>
			document.querySelector('.mantine-Loader-root, .ag-overlay-loading-wrapper, .mantine-Skeleton-root')
				? `loading ${Math.random()}`
				: document.body.innerText.replace(/\d+/g, '#'),
		);
		same = now === last ? same + 1 : 0;
		last = now;
	}
}

async function webp(encoder, png, width) {
	return Buffer.from(
		await encoder.evaluate(
			async ([data, width]) => {
				const image = new Image();
				image.src = `data:image/png;base64,${data}`;
				await image.decode();
				const canvas = document.createElement('canvas');
				canvas.width = width;
				canvas.height = Math.round((image.height * width) / image.width);
				const context = canvas.getContext('2d');
				context.imageSmoothingQuality = 'high';
				context.drawImage(image, 0, 0, canvas.width, canvas.height);
				return canvas.toDataURL('image/webp', 0.86).split(',')[1];
			},
			[png.toString('base64'), width],
		),
		'base64',
	);
}

const staging = mkdtempSync(join(tmpdir(), 'barbican-screenshots-'));
const problems = [];
try {
	for (const screen of SCREENS) {
		// A profile of its own, thrown away afterwards; no keyring, no first-run dialogs.
		const profile = mkdtempSync(join(tmpdir(), 'barbican-chromium-'));
		const context = await chromium.launchPersistentContext(profile, {
			executablePath: args.chromium,
			headless: true,
			args: ['--password-store=basic', '--use-mock-keychain', '--no-first-run', '--no-default-browser-check'],
			viewport: screen.viewport,
			deviceScaleFactor: screen.scale,
			isMobile: screen.mobile,
			hasTouch: screen.mobile,
			reducedMotion: 'reduce',
			locale: 'en-GB',
			timezoneId: 'UTC',
		});
		try {
			const encoder = await context.newPage();
			for (const scheme of ['dark', 'light']) {
				const page = await context.newPage();
				await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
				await page.addInitScript((scheme) => localStorage.setItem('mantine-color-scheme-value', scheme), scheme);
				for (const shot of screen.shots) {
					await page.goto(`${url}${shot.hash}`);
					await page.reload();
					await settle(page);
					if (shot.act) {
						await shot.act(page);
						await settle(page);
					}
					const text = await page.evaluate(() =>
						[
							document.body.innerText,
							...[...document.querySelectorAll('input, textarea, select')].map((e) => e.value),
						].join('\n'),
					);
					const bad = foreign(text, extra);
					if (bad.length) problems.push(`${shot.name} (${scheme}): ${bad.join(', ')}`);
					const file = join(staging, `${shot.name}-${scheme}.webp`);
					// A desktop page shorter than the screen ends below its content.
					const bottom = screen.mobile
						? screen.viewport.height
						: await page.evaluate(() => {
								// Where the last text or control ends: wrappers may stretch to the screen's height, and the
								// screens of grids stay laid out while another one shows, hidden.
								const shown = (e) => e.checkVisibility({ visibilityProperty: true, opacityProperty: true });
								let bottom = 0;
								const range = document.createRange();
								for (const root of document.querySelectorAll('main, [role="dialog"]')) {
									const texts = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
									for (let node = texts.nextNode(); node; node = texts.nextNode()) {
										if (!node.textContent.trim() || !shown(node.parentElement)) continue;
										range.selectNodeContents(node);
										for (const box of range.getClientRects()) bottom = Math.max(bottom, box.bottom);
									}
									for (const e of root.querySelectorAll('input, button, select, textarea, svg, img, canvas')) {
										const box = e.getBoundingClientRect();
										if (box.width && box.height && shown(e)) bottom = Math.max(bottom, box.bottom);
									}
								}
								// Cards and panels end a little below their last line.
								return bottom + 24;
							});
					const clip = { x: 0, y: 0, width: screen.viewport.width, height: Math.min(screen.viewport.height, Math.ceil(bottom)) };
					writeFileSync(file, await webp(encoder, await page.screenshot({ type: 'png', clip }), screen.width));
					console.error(`  ${shot.name}-${scheme}.webp`);
				}
				await page.close();
			}
		} finally {
			await context.close();
			rmSync(profile, { recursive: true, force: true });
		}
	}
	if (problems.length) {
		console.error(`These pages show what the synthetic history didn't make up; nothing was written:\n${problems.join('\n')}`);
		process.exitCode = 1;
	} else {
		mkdirSync(args.out, { recursive: true });
		cpSync(staging, args.out, { recursive: true });
		console.error(`${readdirSync(staging).length} screenshots in ${args.out}`);
	}
} finally {
	rmSync(staging, { recursive: true, force: true });
}
