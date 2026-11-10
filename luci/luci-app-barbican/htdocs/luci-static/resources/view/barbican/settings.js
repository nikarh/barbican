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

		o = s.option(form.Flag, 'lists', _('Apply lists'),
			_('Also block the agents\' blocked countries and blocking lists, not only their bans.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'persist_interval', _('Save at most every'),
			_('Seconds. The state is put back at boot; it is written to flash only when it changed, and at most this often.'));
		o.datatype = 'uinteger';
		o.placeholder = '3600';

		o = s.option(form.Value, 'table', _('nftables table'));
		o.datatype = 'and(minlength(1),maxlength(64))';
		o.placeholder = 'barbican';

		o = s.option(form.Value, 'priority', _('Chain priority'),
			_('On the prerouting hook: after connection tracking (-200), before NAT (-100).'));
		o.datatype = 'range(-199,-101)';
		o.placeholder = '-190';

		s = m.section(form.GridSection, 'upstream', _('Agents'),
			_('The edge API of each agent: http://<address>:<port>, on the LAN.'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'url', _('URL'));
		o.placeholder = 'http://192.168.1.10:7380';
		o.rmempty = false;
		o.validate = function(section, value) {
			return /^http:\/\/[^\/\s]+(\/.*)?$/.test(value) || _('An http:// URL (TLS isn\'t supported on the router)');
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
