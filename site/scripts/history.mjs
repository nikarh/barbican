// A synthetic history for the screenshots of the docs (scripts/screenshots.sh): Traefik, sshd and Authelia logs of
// made-up visitors, the setup the agent gets through its RPC, and the allow-list of every address and domain any of
// it may show. Everything comes from a fixed seed: the same seed gives the same visitors, lines and setup, placed
// relative to `--now` so that the history ends when the screenshots are taken.
//
//   node site/scripts/history.mjs --now <unix seconds> --out <dir>
//
// Writes <dir>/history/{web,ssh,auth}.log (each line an RFC 3339 time and the log line, for `barbican import`),
// <dir>/live/{web,ssh,auth}.log (lines to append while the screenshots are taken, for the live view),
// <dir>/setup.json (RPC calls) and <dir>/allow.json (what the pages may show).
//
// Hosts are example.com, example.org and example.net. Visitors' addresses are random public-looking ones (so that
// geolocation spreads them over countries) and documentation ranges; users' names are made up.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isIP } from 'node:net';

const SEED = 0x6ba2b1ca;
const DAY = 86_400;
const HOUR = 3_600;

const args = Object.fromEntries(
	process.argv.slice(2).reduce((pairs, arg, i, all) => (arg.startsWith('--') ? [...pairs, [arg.slice(2), all[i + 1]]] : pairs), []),
);
const now = Math.floor(Number(args.now) / 600) * 600;
const out = args.out;
if (!Number.isFinite(now) || !out) {
	console.error('usage: history.mjs --now <unix seconds> --out <dir>');
	process.exit(1);
}

// mulberry32: small, fast and the same everywhere.
let state = SEED;
const random = () => {
	state = (state + 0x6d2b79f5) | 0;
	let t = Math.imul(state ^ (state >>> 15), 1 | state);
	t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
	return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
};
const int = (min, max) => min + Math.floor(random() * (max - min + 1));
const pick = (list) => list[Math.floor(random() * list.length)];
const chance = (p) => random() < p;

// Ranges no visitor on the internet comes from: private, shared, loopback, link-local, multicast and reserved,
// benchmarking, and the documentation ranges (used on purpose below).
const RESERVED_V4 = [
	[0, 8], [10, 8], [100 << 24 | 64 << 16, 10], [127 << 24, 8], [169 << 24 | 254 << 16, 16], [172 << 24 | 16 << 16, 12],
	[192 << 24, 24], [192 << 24 | 2 << 8, 24], [192 << 24 | 88 << 16 | 99 << 8, 24], [192 << 24 | 168 << 16, 16],
	[198 << 24 | 18 << 16, 15], [198 << 24 | 51 << 16 | 100 << 8, 24], [203 << 24 | 113 << 8, 24], [224 << 24, 3],
	// Blocks that are allocated but hardly ever seen on the internet.
	...[6, 7, 11, 21, 22, 26, 28, 29, 30, 33, 55, 214, 215].map((a) => [a << 24, 8]),
].map(([net, bits]) => [net >>> 0, bits]);
const reserved = (n) => RESERVED_V4.some(([net, bits]) => (n >>> (32 - bits)) === (net >>> (32 - bits)));
const v4 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
const used = new Set();
const unique = (make) => {
	for (;;) {
		const ip = make();
		if (!used.has(ip)) {
			used.add(ip);
			return ip;
		}
	}
};
const publicV4 = () =>
	unique(() => {
		let n;
		do n = Math.floor(random() * 2 ** 32);
		while (reserved(n));
		return v4(n);
	});
// IPv6 from the regional registries' big blocks, so that they geolocate.
const publicV6 = () =>
	unique(() => {
		const top = pick([0x2001, 0x2400, 0x2401, 0x2600, 0x2602, 0x2800, 0x2a00, 0x2a01, 0x2a02, 0x2a05, 0x2c0f]);
		const groups = [top, int(0x0100, 0xfff0), int(0, 0xffff), int(0, 0xffff)];
		if (top === 0x2001 && groups[1] === 0x0db8) groups[1] = 0x0db9;
		return `${groups.map((g) => g.toString(16)).join(':')}::${int(1, 0xff).toString(16)}`;
	});
const docV4 = () => unique(() => `${pick(['192.0.2', '198.51.100', '203.0.113'])}.${int(2, 254)}`);
const docV6 = () => unique(() => `2001:db8:${int(1, 0xfff).toString(16)}::${int(1, 0xff).toString(16)}`);

const SERVER = '192.0.2.1';
const HOSTS = ['example.com', 'www.example.com', 'app.example.com', 'cloud.example.org', 'git.example.net', 'auth.example.org'];
const ROUTERS = {
	'example.com': 'site@docker',
	'www.example.com': 'site@docker',
	'app.example.com': 'app@docker',
	'cloud.example.org': 'cloud@docker',
	'git.example.net': 'git@docker',
	'auth.example.org': 'auth@docker',
};
const UNKNOWN_HOSTS = [SERVER, 'old.example.net', 'mail.example.org', 'test.example.com'];
const PROBES = [
	'/.env', '/.git/config', '/.env.production', '/wp-login.php', '/wp-admin/setup-config.php', '/xmlrpc.php',
	'/phpmyadmin/index.php', '/cgi-bin/luci/;stok=/locale', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
	'/admin/config.php', '/boaform/admin/formLogin', '/.aws/credentials', '/config.json', '/actuator/env',
	'/server-status', '/HNAP1/', '/owa/auth/logon.aspx', '/../../../../etc/passwd', '/index.php?s=/Index/think/app/invokefunction',
	'/.DS_Store', '/backup.sql', '/wp-content/plugins/revslider/temp/update_extract/', '/geoserver/web/',
];
const GUESSES = [
	'/api/v1/users', '/login', '/admin', '/dashboard', '/api/health', '/console', '/manager/html', '/user/login',
	'/api/v2/config', '/static/js/main.js', '/remote/login', '/sitemap.xml', '/robots.txt', '/favicon.ico', '/api',
	'/graphql', '/jenkins/login', '/solr/', '/v2/_catalog', '/metrics', '/debug/vars', '/swagger-ui.html',
];
const PAGES = ['/', '/dashboard', '/api/items?page=2', '/settings', '/static/app.js', '/files/report.pdf', '/api/status'];
const AGENTS = {
	scanner: [
		'Mozilla/5.0 zgrab/0.x',
		'python-requests/2.32.3',
		'Go-http-client/1.1',
		'curl/8.5.0',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
		'libredtail-http',
		'Nuclei - Open-source project',
	],
	browser: [
		'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
	],
};
const SSH_USERS = ['ubnt', 'test', 'oracle', 'postgres', 'git', 'pi', 'ftpuser', 'user', 'deploy', 'guest', 'support', 'mysql', 'hadoop', 'steam', 'minecraft', 'ubuntu', 'debian', 'nagios'];
const ROOTS = ['root', 'admin', 'administrator'];
const PEOPLE = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank'];

const lines = { web: [], ssh: [], auth: [] };
const live = { web: [], ssh: [], auth: [] };
const iso = (t) => new Date(t * 1000).toISOString().replace(/\.\d+Z$/, `.${String(int(0, 999_999)).padStart(6, '0')}Z`);

const traefik = (t, ip, { method = 'GET', path, host, status, agent, routed = true }) =>
	JSON.stringify({
		ClientHost: ip,
		DownstreamStatus: status,
		RequestHost: host,
		RequestMethod: method,
		RequestPath: path,
		RequestProtocol: 'HTTP/1.1',
		RouterName: routed ? ROUTERS[host] ?? 'site@docker' : '',
		'request_User-Agent': agent,
		time: new Date(t * 1000).toISOString(),
	});
const port = () => int(1024, 65535);
const authelia = (t, ip, level, msg) =>
	`time="${new Date(t * 1000).toISOString().replace(/\.\d+Z$/, 'Z')}" level=${level} msg="${msg}" method=POST path=/api/firstfactor remote_ip=${ip}`;

const emit = (log, t, line) => lines[log].push([t, line]);

// When something happens: anywhere in the last 75 days, more of it recently, now and then a wave.
const WAVES = [3, 9, 17, 26, 41].map((d) => now - d * DAY - int(0, 20) * HOUR);
const when = () => {
	if (chance(0.15)) return pick(WAVES) + int(0, 6 * HOUR);
	const age = Math.floor(75 * DAY * random() ** 1.6);
	return now - age - int(0, 600);
};

// The kinds of visitors, and what each does.
const BEHAVIOURS = [
	[24, 'probe', (ip, t) => {
		const host = pick(HOSTS), agent = pick(AGENTS.scanner);
		for (let i = int(1, 6); i > 0; i--) emit('web', (t += int(0, 3)), traefik(t, ip, { path: pick(PROBES), host, status: 404, agent }));
	}],
	[16, 'unrouted', (ip, t) => {
		const host = pick(UNKNOWN_HOSTS), agent = pick(AGENTS.scanner);
		for (let i = int(1, 3); i > 0; i--) emit('web', (t += int(0, 5)), traefik(t, ip, { path: pick(['/', '/favicon.ico', ...PROBES]), host, status: 404, agent, routed: false }));
	}],
	[6, 'guesser', (ip, t) => {
		const host = pick(HOSTS), agent = pick(AGENTS.scanner);
		for (let i = int(42, 60); i > 0; i--) emit('web', (t += int(1, 9)), traefik(t, ip, { path: pick(GUESSES), host, status: pick([404, 404, 404, 403, 401]), agent }));
	}],
	[4, 'method', (ip, t) => {
		emit('web', t, traefik(t, ip, { method: pick(['CFKQ', 'XYZQ', 'TRACE', 'DEBUG']), path: '/', host: pick(HOSTS), status: 405, agent: '-' }));
	}],
	[16, 'ssh-users', (ip, t) => {
		for (let i = int(1, 4); i > 0; i--) emit('ssh', (t += int(2, 40)), `Invalid user ${pick(SSH_USERS)} from ${ip} port ${port()}`);
	}],
	[12, 'ssh-root', (ip, t) => {
		const user = pick(ROOTS);
		emit('ssh', t, `Disconnected from authenticating user ${user} ${ip} port ${port()} [preauth]`);
	}],
	[8, 'ssh-probe', (ip, t) => {
		emit('ssh', t, pick([
			`Did not receive identification string from ${ip} port ${port()}`,
			`Unable to negotiate with ${ip} port ${port()}: no matching key exchange method found`,
			`banner exchange: Connection from ${ip} port ${port()}: invalid format`,
		]));
	}],
	[5, 'login', (ip, t) => {
		const user = pick([...PEOPLE, 'admin', 'test']);
		for (let i = int(5, 9); i > 0; i--)
			emit('auth', (t += int(5, 50)), authelia(t, ip, 'error', `Unsuccessful 1FA authentication attempt by user '${user}'`));
	}],
	[9, 'noise', (ip, t) => {
		const host = pick(HOSTS), agent = pick(AGENTS.scanner);
		for (let i = int(1, 4); i > 0; i--) emit('web', (t += int(0, 30)), traefik(t, ip, { path: pick(GUESSES), host, status: 404, agent }));
	}],
];
const total = BEHAVIOURS.reduce((sum, [weight]) => sum + weight, 0);
const behaviour = () => {
	let r = random() * total;
	for (const b of BEHAVIOURS) if ((r -= b[0]) < 0) return b;
	return BEHAVIOURS[0];
};

const visitors = [];
for (let i = 0; i < 520; i++) {
	const ip = i % 40 === 7 ? docV4() : i % 40 === 19 ? docV6() : i % 9 === 4 ? publicV6() : publicV4();
	visitors.push(ip);
	const [, , act] = behaviour();
	act(ip, when());
	// Some come back with something else.
	if (chance(0.18)) behaviour()[2](ip, when());
}
// Today has to have something to show.
for (let i = 0; i < 14; i++) {
	const ip = i % 3 ? publicV4() : publicV6();
	visitors.push(ip);
	behaviour()[2](ip, now - int(60, 20 * HOUR));
}

// People who use the services: they log in (and are trusted from then on), browse, and get a 404 now and then.
const people = PEOPLE.map((user, i) => ({ user, ip: i === 5 ? docV4() : i === 4 ? publicV6() : publicV4() }));
for (const { user, ip } of people) {
	let t = now - int(20, 60) * DAY;
	while (t < now - HOUR) {
		emit('auth', t, authelia(t, ip, 'info', `Successful 1FA authentication attempt made by user '${user}'`));
		const host = pick(['app.example.com', 'cloud.example.org', 'git.example.net']);
		for (let i = int(3, 12); i > 0; i--) {
			t += int(5, 120);
			emit('web', t, traefik(t, ip, { path: pick(PAGES), host, status: chance(0.08) ? 404 : 200, agent: pick(AGENTS.browser) }));
		}
		t += int(1, 6) * DAY + int(0, 12) * HOUR;
	}
}
// An SSH user, trusted from their logins too.
const admin = { user: 'deploy', ip: publicV4() };
for (let t = now - 50 * DAY; t < now - HOUR; t += int(2, 9) * DAY)
	emit('ssh', t, `Accepted publickey for ${admin.user} from ${admin.ip} port ${port()} ssh2`);

// What arrives while the screenshots are taken: some of the visitors again, with nothing that bans.
for (const ip of visitors.slice(-60).filter((_, i) => i % 6 === 0)) {
	if (chance(0.6)) live.web.push(traefik(now, ip, { path: pick(GUESSES), host: pick(HOSTS), status: 404, agent: pick(AGENTS.scanner) }));
	else live.auth.push(authelia(now, ip, 'error', `Unsuccessful 1FA authentication attempt by user '${pick(PEOPLE)}'`));
}

// The setup, through the RPC. Before the import, so that its bans follow the policy and the lists.
const H = HOUR;
const before = [
	['policy.update', {
		banSecs: 90 * DAY,
		countryLengths: [{ country: 'CA', secs: 7 * DAY }],
		asnLengths: [{ asn: 13335, secs: DAY }],
		listLengths: [{ list: 'Tor exit nodes', secs: DAY }],
		repeatMultiplier: 2,
		maxBanSecs: 365 * DAY,
		trustSecs: 30 * DAY,
		blockedCountries: [],
		blockedContinents: ['AF', 'AS', 'SA'],
		retentionDays: 365,
	}],
	...[
		['Spamhaus DROP', 'https://www.spamhaus.org/drop/drop_v4.json', 'block', 12, ['spamhaus', 'drop_v4']],
		['FireHOL level 1', 'https://iplists.firehol.org/files/firehol_level1.netset', 'block', 1, ['firehol', 'firehol_level1']],
		['AbuseIPDB', 'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-7d.ipv4', 'block', 3, ['abuseipdb', '7d']],
		['blocklist.de', 'https://lists.blocklist.de/lists/all.txt', 'data', 6, ['blocklist.de', 'all']],
		['Tor exit nodes', 'https://check.torproject.org/torbulkexitlist', 'data', 1, ['tor', 'exits']],
		['Googlebot', 'https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json', 'allow', 24, ['ipverse-crawlers', 'Googlebot'], '/services/Googlebot'],
		['Bingbot', 'https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json', 'allow', 24, ['ipverse-crawlers', 'Bingbot'], '/services/Bingbot'],
		['AI user agents', 'https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.txt', 'data', 24, ['ai-agents', 'robots'], null, 'agents'],
		['Cloudflare', 'https://www.cloudflare.com/ips-v4', 'allow', 24, ['cloudflare', 'ips-v4']],
		['Cloudflare (IPv6)', 'https://www.cloudflare.com/ips-v6', 'allow', 24, ['cloudflare', 'ips-v6']],
	].map(([name, url, use, hours, [source, item], select = null, content = 'addresses']) => [
		'feed.save',
		{
			id: 0, name, url, enabled: true, block: use === 'block', allow: use === 'allow', refreshSecs: hours * H,
			content, select, catalog: { source, item },
		},
	]),
	['rule.save', {
		id: 0, name: 'AI crawlers', description: 'Requests whose user agent says they come from an AI crawler',
		enabled: true, kind: 'http', sources: [], conditions: { agents: ['AI user agents'] }, threshold: 1, windowSecs: 60,
		action: 'ban', ban: { type: 'secs', secs: 7 * DAY }, prefixV4: 32, prefixV6: 64,
	}],
	['entry.save', { net: '192.0.2.0/28', allow: true, note: 'Monitoring probes', secs: null }],
	['entry.save', { net: '198.51.100.64/26', allow: true, note: 'Partner office', secs: 30 * DAY }],
	['entry.save', { net: '203.0.113.128/25', allow: false, note: 'Abuse report', secs: 90 * DAY }],
];
const after = [
	['ban.create', { net: '198.51.100.200', secs: 14 * DAY, reason: 'Credential stuffing, seen in the application log' }],
];

// Everything a page may show: these addresses, the server's, the VM's own, and the documentation ranges.
const allow = {
	addresses: [...used, SERVER, '127.0.0.1', '0.0.0.0', '::', '::1', '10.99.0.1', '10.99.0.2', '10.0.2.15'],
	prefixes: ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'],
	domains: [
		'example.com', 'example.org', 'example.net',
		'spamhaus.org', 'firehol.org', 'blocklist.de', 'torproject.org', 'cloudflare.com', 'db-ip.com', 'github.com',
		'githubusercontent.com', 'sekuripy.hr', 'updown.io',
	],
};
for (const ip of allow.addresses) if (!isIP(ip)) throw new Error(`not an address: ${ip}`);

const write = (path, text) => {
	mkdirSync(join(out, path, '..'), { recursive: true });
	writeFileSync(join(out, path), text);
};
for (const [log, entries] of Object.entries(lines)) {
	entries.sort((a, b) => a[0] - b[0]);
	write(`history/${log}.log`, entries.filter(([t]) => t < now).map(([t, line]) => `${iso(t)} ${line}\n`).join(''));
}
for (const [log, entries] of Object.entries(live)) write(`live/${log}.log`, entries.map((line) => `${line}\n`).join(''));
const call = ([method, params]) => ({ method, params });
write('setup.json', JSON.stringify({ before: before.map(call), after: after.map(call) }, null, 1));
write('allow.json', JSON.stringify(allow));
console.error(
	`history: ${Object.values(lines).reduce((n, l) => n + l.length, 0)} lines, ${used.size} addresses, ending ${new Date(now * 1000).toISOString()}`,
);
