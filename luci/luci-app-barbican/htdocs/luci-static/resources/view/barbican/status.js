'use strict';
'require view';
'require fs';
'require poll';
'require ui';

// barbican-edge's status, from the file it keeps in /var/run (see barbican-edge status).

var STATUS = '/var/run/barbican-edge.json';

function ago(t) {
	if (!t) return _('never');
	var s = Math.max(0, Math.floor(Date.now() / 1000) - t);
	if (s < 60) return _('%d s ago').format(s);
	if (s < 3600) return _('%d min ago').format(Math.floor(s / 60));
	if (s < 86400) return _('%d h ago').format(Math.floor(s / 3600));
	return _('%d days ago').format(Math.floor(s / 86400));
}

function until(t) {
	if (t == null) return _('until lifted');
	var s = t - Math.floor(Date.now() / 1000);
	if (s <= 0) return _('ending');
	if (s < 3600) return _('%d more min').format(Math.ceil(s / 60));
	if (s < 86400) return _('%d more h').format(Math.ceil(s / 3600));
	return _('%d more days').format(Math.ceil(s / 86400));
}

function load() {
	return fs.read(STATUS).then(function(text) {
		return JSON.parse(text);
	}).catch(function() {
		return null;
	});
}

function summary(s) {
	if (!s) {
		return E('div', { 'class': 'alert-message warning' },
			_('barbican-edge isn\'t running (no %s). Check its settings and "logread -e barbican".').format(STATUS));
	}
	var rows = [
		[_('Blocked addresses and prefixes'), String(s.blocks)],
		[_('Listed prefixes (countries, blocklists)'), String(s.listed)],
		[_('Packets dropped'), _('%d blocked, %d listed').format(s.dropped_blocked, s.dropped_listed)],
		[_('Firewall'), s.enabled ? (s.error ? E('span', { 'style': 'color:#c33' }, s.error) : _('applied %s').format(ago(s.applied))) : _('off')],
		[_('Version'), s.version]
	];
	return E('table', { 'class': 'table' }, rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, r[0]),
			E('td', { 'class': 'td left' }, r[1])
		]);
	}));
}

function upstreams(s) {
	var head = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, _('Agent')),
		E('th', { 'class': 'th' }, _('State')),
		E('th', { 'class': 'th' }, _('Blocks')),
		E('th', { 'class': 'th' }, _('Allowed')),
		E('th', { 'class': 'th' }, _('Listed')),
		E('th', { 'class': 'th' }, _('Last heard from'))
	]);
	var rows = (s ? s.upstreams : []).map(function(u) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [ E('strong', {}, u.name), E('br'), E('small', {}, u.url) ]),
			E('td', { 'class': 'td' }, u.connected
				? E('span', { 'style': 'color:#393' }, _('following'))
				: E('span', { 'style': 'color:#c33' }, u.error || _('not reached yet'))),
			E('td', { 'class': 'td' }, String(u.blocks)),
			E('td', { 'class': 'td' }, String(u.allows)),
			E('td', { 'class': 'td' }, String(u.listed)),
			E('td', { 'class': 'td' }, ago(u.last_ok))
		]);
	});
	if (!rows.length)
		rows = [ E('tr', { 'class': 'tr placeholder' }, E('td', { 'class': 'td', 'colspan': 6 }, _('No agents configured: add one in Settings.'))) ];
	return E('table', { 'class': 'table' }, [ head ].concat(rows));
}

function blocks(s) {
	var head = E('tr', { 'class': 'tr table-titles' }, [
		E('th', { 'class': 'th' }, _('Address or prefix')),
		E('th', { 'class': 'th' }, _('Lasts')),
		E('th', { 'class': 'th' }, _('From'))
	]);
	var recent = s ? s.recent : [];
	var rows = recent.map(function(b) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('code', {}, b.net)),
			E('td', { 'class': 'td' }, until(b.until)),
			E('td', { 'class': 'td' }, b.upstream)
		]);
	});
	if (!rows.length)
		rows = [ E('tr', { 'class': 'tr placeholder' }, E('td', { 'class': 'td', 'colspan': 3 }, _('Nothing blocked.'))) ];
	var note = s && s.blocks > recent.length
		? E('p', {}, _('The first %d of %d.').format(recent.length, s.blocks))
		: '';
	return E('div', {}, [ E('table', { 'class': 'table' }, [ head ].concat(rows)), note ]);
}

function render(s) {
	return E('div', { 'id': 'barbican-status' }, [
		E('h3', {}, _('Overview')),
		summary(s),
		E('h3', {}, _('Agents')),
		upstreams(s),
		E('h3', {}, _('Blocks')),
		blocks(s)
	]);
}

return view.extend({
	load: load,

	render: function(s) {
		var node = render(s);
		poll.add(function() {
			return load().then(function(s) {
				var current = document.getElementById('barbican-status');
				if (current) current.replaceWith(render(s));
			});
		}, 5);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Barbican')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Blocks what barbican agents ban, for the whole network. Bans and lifts are made on the agents.')),
			node
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
