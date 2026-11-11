'use strict';
'require view';
'require form';

// The settings of barbican-edge, in /etc/config/barbican. Saving restarts it (procd's reload trigger).

return view.extend({
	render: function() {
		var m = new form.Map('barbican', _('Barbican'),
			_('Follows barbican agents and blocks what they ban, for the whole network. Each agent needs an edge client with a token in its configuration.'));

		var s = m.section(form.NamedSection, 'main', 'barbican', _('General'));
		s.addremove = false;

		var o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Flag, 'dry_run', _('Dry run'),
			_('Follow the agents and keep their state, but change nothing in the firewall: to see first what it would block, and what that costs.'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.Flag, 'ipv6', _('IPv6'),
			_('Block IPv6 too. Off, the agents send no IPv6 at all: on a router without IPv6 it would only take memory.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Flag, 'lists', _('Apply lists'),
			_('Also block the agents\' blocked countries and blocking lists, not only their bans.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'persist_interval', _('Also save every'),
			_('Seconds. The state is saved to flash when the agent stops cleanly (a reboot, an upgrade) and put back at boot, before any agent is reachable. 0: only then (flash wears; the agents send what changed once reachable).'));
		o.datatype = 'uinteger';
		o.placeholder = '0';

		o = s.option(form.Value, 'table', _('nftables table'));
		o.datatype = 'and(minlength(1),maxlength(64))';
		o.placeholder = 'barbican';

		o = s.option(form.Value, 'priority', _('Chain priority'),
			_('On the prerouting hook: after connection tracking (-200), before NAT (-100).'));
		o.datatype = 'range(-199,-101)';
		o.placeholder = '-190';

		s = m.section(form.GridSection, 'upstream', _('Agents'),
			_('The edge API of each agent: https://<address>:<port>, with the fingerprint of its certificate (barbican edge-fingerprint on the agent prints it).'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'url', _('URL'));
		o.placeholder = 'https://192.168.1.10:7380';
		o.rmempty = false;
		o.validate = function(section, value) {
			return /^https:\/\/[^\/\s]+(\/.*)?$/.test(value) || _('An https:// URL');
		};

		o = s.option(form.Value, 'fingerprint', _('Certificate fingerprint'),
			_('SHA-256 of the agent\'s certificate: only that certificate is accepted.'));
		o.rmempty = false;
		o.modalonly = true;
		o.validate = function(section, value) {
			return /^(SHA256:)?([0-9A-Fa-f]{2}:?){32}$/.test(value.trim()) || _('64 hex digits, colons optional');
		};

		o = s.option(form.Value, 'token', _('Token'));
		o.password = true;
		o.modalonly = true;

		o = s.option(form.Value, 'token_file', _('Token file'), _('Instead of the token: a file holding it.'));
		o.modalonly = true;
		o.placeholder = '/etc/barbican/agent.token';

		return m.render();
	}
});
