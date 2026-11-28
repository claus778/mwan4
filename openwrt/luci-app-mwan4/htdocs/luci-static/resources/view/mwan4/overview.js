'use strict';
'require view';
'require fs';
'require uci';
'require ui';
'require form';
'require poll';

var CLOCK_SKEW_TOLERANCE_SECS = 300;
var lastSeenUpdatedAt = null;
var TREND_LEN = 60;
var trendHistory = {};

function history2bars(iface) {
	var h = trendHistory[iface.name] || [];
	var max = 50;
	for (var i = 0; i < h.length; i++)
		if (h[i].rtt > max) max = h[i].rtt;

	var out = [];
	for (var n = 0; n < TREND_LEN; n++) {
		var s = h[n];
		if (!s || !s.up || s.rtt === null) {
			out.push({ pct: s ? 18 : 0, level: s ? 'bad' : 'empty', label: s ? _('Offline') : '' });
			continue;
		}
		var level = rttLevel(s.rtt);
		var l = lossLevel(s.loss);
		if (l === 'bad') level = 'bad';
		else if (l === 'warn' && level === 'ok') level = 'warn';
		out.push({
			pct: Math.max(10, Math.min(100, s.rtt / max * 100)),
			level: level,
			label: s.rtt.toFixed(1) + ' ms · ' + s.loss.toFixed(1) + '%'
		});
	}
	return out;
}

function trendEl(iface) {
	var bars = history2bars(iface).map(function(b) {
		return E('i', { 'class': 'mwan4-trend-bar ' + b.level, 'style': 'height:' + b.pct + '%', 'title': b.label });
	});
	return E('div', { 'class': 'mwan4-trend', 'data-role': 'trend' }, bars);
}

function updateTrend(el, iface) {
	var bars = history2bars(iface);
	for (var i = 0; i < el.children.length && i < bars.length; i++) {
		var node = el.children[i];
		var style = 'height:' + bars[i].pct + '%';
		if (node.getAttribute('style') !== style) node.setAttribute('style', style);
		var cls = 'mwan4-trend-bar ' + bars[i].level;
		if (node.className !== cls) node.className = cls;
		if (node.title !== bars[i].label) node.title = bars[i].label;
	}
}

function readStatusJson() {
	return fs.read('/tmp/mwan4_status.json').then(function(content) {
		try {
			return JSON.parse(content);
		} catch (e) {
			return null;
		}
	}).catch(function() {
		return null;
	});
}

function listNetdevs() {
	return fs.list('/sys/class/net').then(function(list) {
		return (list || []).filter(function(name) {
			return name !== 'lo' && name.indexOf('br-') !== 0;
		});
	}).catch(function() {
		return [];
	});
}

function freshnessOf(statusData) {
	if (!statusData || !statusData.updated_at)
		return 'missing';
	var staleAfter = statusData.stale_after_secs || 10;
	var updated = statusData.updated_at;
	var advanced = lastSeenUpdatedAt !== null && updated > lastSeenUpdatedAt;
	if (lastSeenUpdatedAt === null || updated > lastSeenUpdatedAt)
		lastSeenUpdatedAt = updated;
	if (advanced)
		return 'fresh';

	var age = Date.now() / 1000 - updated;
	if (age > staleAfter)
		return 'stale';
	if (age < -CLOCK_SKEW_TOLERANCE_SECS)
		return 'skew';
	return 'fresh';
}

function dot(level, role) {
	var attr = { 'class': 'mwan4-dot ' + (level || 'muted') };
	if (role) attr['data-role'] = role;
	return E('i', attr);
}

function rttLevel(ms) {
	if (ms > 150) return 'bad';
	if (ms > 60) return 'warn';
	return 'ok';
}

function lossLevel(pct) {
	if (pct > 50) return 'bad';
	if (pct > 10) return 'warn';
	return 'ok';
}

function loadLevel(pct) {
	if (pct >= 85) return 'bad';
	if (pct >= 65) return 'warn';
	return 'ok';
}

function runLevel(fresh) {
	if (fresh === 'fresh') return 'ok';
	if (fresh === 'stale') return 'bad';
	return 'muted';
}

function runText(fresh) {
	if (fresh === 'fresh') return _('Running');
	if (fresh === 'stale') return _('Stopped');
	if (fresh === 'missing') return _('No Status');
	return _('Clock Skew');
}

function stateLevel(iface) {
	if (iface.state !== 'UP') return 'bad';
	return iface.degraded ? 'warn' : 'ok';
}

function stateText(iface) {
	if (iface.state !== 'UP') return _('Offline');
	return iface.degraded ? _('Degraded') : _('Online');
}

function cardAlert(iface, fresh) {
	if (fresh === 'stale')
		return _('Status expired: daemon may have stopped.');
	if (fresh === 'skew')
		return _('Clock skew detected: status freshness cannot be verified.');
	if (fresh === 'missing')
		return _('Waiting for daemon status...');
	if (iface.local_condition && iface.last_error)
		return _('Local error: ') + iface.last_error;
	if (iface.last_error)
		return _('Probe error: ') + iface.last_error;
	if (iface.degraded)
		return _('Degraded: excluded from ECMP until packet loss recovers.');
	return '';
}

function cardClass(iface, fresh) {
	var cls = 'mwan4-card';
	if (iface.state !== 'UP')
		cls += ' mwan4-card-down';
	else if (iface.degraded)
		cls += ' mwan4-card-degraded';
	if (fresh === 'stale' || fresh === 'skew' || fresh === 'missing')
		cls += ' mwan4-card-stale';
	if (iface.local_condition)
		cls += ' mwan4-card-local';
	return cls;
}

function statusAgeText(statusData) {
	if (!statusData || !statusData.updated_at)
		return '--';
	var age = Date.now() / 1000 - statusData.updated_at;
	if (age < -CLOCK_SKEW_TOLERANCE_SECS)
		return _('Clock Skew');
	if (age < 60)
		return Math.max(0, Math.round(age)) + 's ' + _('ago');
	var minutes = Math.floor(age / 60);
	if (minutes < 60)
		return minutes + 'm ' + _('ago');
	return Math.floor(minutes / 60) + 'h ' + _('ago');
}

function routeInfo(statusData) {
	var text = (statusData && statusData.active_routes) ? statusData.active_routes : _('Unknown');
	var level = 'info';
	if (text.indexOf('ECMP') !== -1 || text.indexOf('Primary') !== -1) {
		level = 'ok';
	} else if (text.indexOf('Failover') !== -1 || text.indexOf('Backup') !== -1) {
		level = 'warn';
	} else if (text.indexOf('DOWN') !== -1) {
		level = 'bad';
	}
	var shortText = text.replace(/^Multipath\s+/, '');
	return { level: level, text: shortText, title: text };
}

function wanSummary(statusData) {
	var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
	var up = 0, degraded = 0;
	for (var i = 0; i < list.length; i++) {
		if (list[i].state === 'UP') up++;
		if (list[i].degraded) degraded++;
	}
	if (!list.length)
		return { level: 'muted', text: '0 / 0', tx: 0, rx: 0 };
	var tx = 0, rx = 0;
	for (var j = 0; j < list.length; j++) {
		if (list[j].state !== 'UP') continue;
		tx += list[j].tx_bps || 0;
		rx += list[j].rx_bps || 0;
	}
	return {
		level: up === 0 || up < list.length ? 'bad' : (degraded ? 'warn' : 'ok'),
		text: up + ' / ' + list.length,
		tx: tx,
		rx: rx
	};
}

function rttText(iface) { return iface.state === 'UP' ? iface.rtt_ms.toFixed(1) + ' ms' : '--'; }
function jitterText(iface) { return iface.state === 'UP' ? iface.jitter_ms.toFixed(1) + ' ms' : '--'; }
function lossText(iface) { return (iface.loss_rate || 0).toFixed(1) + '%'; }

function pwText(iface) {
	var w = String(iface.weight);
	if (iface.effective_weight !== undefined && iface.effective_weight !== iface.weight)
		w = iface.weight + ' \u2192 ' + iface.effective_weight;
	return iface.metric ? (w + '  (P:' + iface.metric + ')') : w;
}

function formatRate(bps) {
	if (!bps || bps < 1000) return '0 bps';
	var units = ['Kbps', 'Mbps', 'Gbps'];
	var v = bps / 1000, i = 0;
	while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
	return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
}

function loadBadgeText(iface) {
	if (iface.state !== 'UP' || iface.load_pct === undefined || iface.load_pct === null)
		return '';
	var text = iface.load_pct.toFixed(0) + '%';
	if (iface.offloaded) text += ' · ' + _('offloaded');
	return text;
}

function policyText(statusData) {
	var list = (statusData && statusData.policies) ? statusData.policies : [];
	if (!list.length) return null;
	return list.map(function(p) {
		return p.name + '\u2192' + p.interface + (p.active ? '' : _(' (inactive)'));
	}).join(', ');
}

function dnsText(statusData) {
	var parts = [];
	if (statusData && statusData.dns_listen)
		parts.push(statusData.dns_listen);
	var list = (statusData && statusData.dns) ? statusData.dns : [];
	for (var i = 0; i < list.length; i++) {
		var d = list[i];
		parts.push(d.server + '\u2192' + d.interface + (d.active ? '' : _(' (inactive)')));
	}
	return parts.length ? parts.join(', ') : null;
}

function validateDnsServer(section_id, value) {
	if (!value) return true;
	var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?$/.exec(value.trim());
	if (!m) return _('Expected IPv4 or IPv4:Port');
	for (var i = 1; i <= 4; i++) {
		if (parseInt(m[i], 10) > 255) return _('Expected IPv4 or IPv4:Port');
	}
	if (m[5] !== undefined) {
		var p = parseInt(m[5], 10);
		if (p < 1 || p > 65535) return _('Expected IPv4 or IPv4:Port');
	}
	return true;
}

function hashInfo(statusData) {
	var h = statusData && statusData.hash;
	if (!h) return { level: 'muted', text: _('Unknown'), title: '' };
	var policy = (h.policy === null || h.policy === undefined) ? 'n/a' : h.policy;
	var detail = 'policy=' + policy + ' fields=' + (h.fields_desc || 'n/a');
	return {
		level: h.l3_only ? 'warn' : 'ok',
		text: h.l3_only ? _('L3 Hash') : _('L4 Hash'),
		title: detail
	};
}

function succText(iface) { return _('OK') + ' ' + iface.consecutive_successes; }
function toText(iface) { return _('Timeout') + ' ' + iface.consecutive_timeouts; }

function setText(el, txt) {
	if (el && el.textContent !== txt) el.textContent = txt;
}
function setCls(el, cls) {
	if (el && el.className !== cls) el.className = cls;
}
function setW(el, w) {
	if (el && el.style.width !== w) el.style.width = w;
}
function setTitle(el, t) {
	if (el && el.title !== t) el.title = t;
}
function pick(root, role) {
	return root ? root.querySelector('[data-role="' + role + '"]') : null;
}

function alignDescrRows(root, tries) {
	var tables = root.querySelectorAll('table.cbi-section-table');
	var pending = false;

	for (var i = 0; i < tables.length; i++) {
		var titles = tables[i].querySelector('tr.cbi-section-table-titles:not(.cbi-section-table-filter)');
		var descr = tables[i].querySelector('tr.cbi-section-table-descr');
		if (!titles || !descr || descr.children.length === 0) continue;
		if (descr.hasAttribute('data-aligned')) continue;

		var t0 = titles.children[0].getBoundingClientRect();
		var d0 = descr.children[0].getBoundingClientRect();
		if (t0.width <= 0 || d0.width <= 0) { pending = true; continue; }

		var pads = (titles.children.length - descr.children.length) +
		           Math.round((t0.x - d0.x) / t0.width);
		if (pads < 0) pads = 0;

		for (var n = 0; n < pads; n++)
			descr.insertBefore(E('th', { 'class': 'th cbi-section-table-cell' }), descr.firstChild);

		descr.setAttribute('data-aligned', '1');
	}

	if (pending && (tries || 0) < 120)
		requestAnimationFrame(function() { alignDescrRows(root, (tries || 0) + 1); });
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('mwan4'),
			uci.load('network'),
			readStatusJson(),
			listNetdevs()
		]);
	},

	recordTrend: function(statusData) {
		var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
		for (var i = 0; i < list.length; i++) {
			var iface = list[i];
			var h = trendHistory[iface.name] || (trendHistory[iface.name] = []);
			h.push({
				up: iface.state === 'UP',
				rtt: iface.state === 'UP' ? iface.rtt_ms : null,
				loss: iface.loss_rate || 0
			});
			while (h.length > TREND_LEN) h.shift();
		}
	},

	renderStatusHeader: function(statusData) {
		var fresh = freshnessOf(statusData);
		var ri = routeInfo(statusData);
		var hi = hashInfo(statusData);
		var ws = wanSummary(statusData);
		var pt = policyText(statusData);
		var dt = dnsText(statusData);
		var rLevel = runLevel(fresh);

		return E('div', { 'id': 'mwan4_header_container' }, [
			E('div', { 'class': 'mwan4-header' }, [
				E('div', { 'class': 'mwan4-brand' }, [
					E('span', { 'class': 'mwan4-title' }, _('MWAN4 Load Balancing')),
					E('span', { 'class': 'mwan4-pill mwan4-pill-' + rLevel, 'data-role': 'run-pill' }, [
						dot(rLevel, 'run-dot'),
						E('span', { 'data-role': 'run-text' }, runText(fresh))
					])
				]),
				E('div', { 'class': 'mwan4-meta' }, [
					E('span', {
						'class': 'mwan4-pill mwan4-pill-' + hi.level,
						'data-role': 'hash-pill',
						'title': hi.title
					}, [
						dot(hi.level, 'hash-dot'),
						E('span', { 'data-role': 'hash-text' }, hi.text)
					]),
					E('span', {
						'class': 'mwan4-pill',
						'data-role': 'policy-item',
						'style': pt ? '' : 'display: none'
					}, [
						E('span', { 'class': 'mwan4-pill-key' }, _('Policy')),
						E('span', { 'data-role': 'policy-text' }, pt || '')
					]),
					E('span', {
						'class': 'mwan4-pill',
						'data-role': 'dns-item',
						'style': dt ? '' : 'display: none'
					}, [
						E('span', { 'class': 'mwan4-pill-key' }, _('DNS')),
						E('span', { 'data-role': 'dns-text' }, dt || '')
					]),
					E('span', { 'class': 'mwan4-age', 'data-role': 'age-text' }, statusAgeText(statusData))
				])
			]),
			E('div', { 'class': 'mwan4-summary' }, [
				E('div', { 'class': 'mwan4-tile' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('Online WANs')),
					E('span', { 'class': 'mwan4-tile-val' }, [
						dot(ws.level, 'wan-dot'),
						E('span', { 'data-role': 'wan-text' }, ws.text)
					])
				]),
				E('div', { 'class': 'mwan4-tile' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('Downlink')),
					E('span', { 'class': 'mwan4-tile-val mwan4-mono', 'data-role': 'agg-rx' },
						'\u2193 ' + formatRate(ws.rx))
				]),
				E('div', { 'class': 'mwan4-tile' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('Uplink')),
					E('span', { 'class': 'mwan4-tile-val mwan4-mono', 'data-role': 'agg-tx' },
						'\u2191 ' + formatRate(ws.tx))
				]),
				E('div', { 'class': 'mwan4-tile mwan4-tile-route' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('Active Route')),
					E('span', { 'class': 'mwan4-tile-val mwan4-tile-val-sm', 'title': ri.title, 'data-role': 'route-wrap' }, [
						dot(ri.level, 'route-dot'),
						E('span', { 'data-role': 'route-text' }, ri.text)
					])
				])
			])
		]);
	},

	renderCard: function(iface, fresh) {
		var up = iface.state === 'UP';
		var sLevel = stateLevel(iface);
		var loss = iface.loss_rate || 0;
		var lLevel = lossLevel(loss);
		var trust = fresh || 'fresh';
		var alert = cardAlert(iface, trust);
		var hasLoad = up && iface.load_pct !== undefined && iface.load_pct !== null;
		var loadPct = hasLoad ? Math.min(100, Math.max(0, iface.load_pct)) : 0;
		var ldLevel = loadLevel(loadPct);

		return E('div', {
			'class': cardClass(iface, trust),
			'data-iface': iface.name
		}, [
			E('div', { 'class': 'mwan4-card-head' }, [
				E('div', { 'class': 'mwan4-card-id' }, [
					E('span', { 'class': 'mwan4-card-title' }, iface.name),
					E('span', { 'class': 'mwan4-card-ip', 'data-role': 'ip' }, iface.ip ? iface.ip : _('(No IP)'))
				]),
				E('span', { 'class': 'mwan4-pill mwan4-pill-' + sLevel, 'data-role': 'state-pill' }, [
					dot(sLevel, 'state-dot'),
					E('span', { 'data-role': 'state-text' }, stateText(iface))
				])
			]),
			E('div', {
				'class': 'mwan4-card-alert',
				'data-role': 'alert',
				'style': alert ? '' : 'display: none'
			}, alert),
			E('div', { 'class': 'mwan4-stats-grid' }, [
				E('div', { 'class': 'mwan4-stat-item' }, [
					E('span', { 'class': 'mwan4-stat-label' }, _('RTT')),
					E('span', { 'class': 'mwan4-stat-val' }, [
						dot(up ? rttLevel(iface.rtt_ms) : 'muted', 'rtt-dot'),
						E('span', { 'data-role': 'rtt' }, rttText(iface))
					])
				]),
				E('div', { 'class': 'mwan4-stat-item' }, [
					E('span', { 'class': 'mwan4-stat-label' }, _('Jitter')),
					E('span', { 'class': 'mwan4-stat-val' }, [
						E('span', { 'data-role': 'jitter' }, jitterText(iface))
					])
				]),
				E('div', { 'class': 'mwan4-stat-item' }, [
					E('span', { 'class': 'mwan4-stat-label' }, _('Gateway')),
					E('span', { 'class': 'mwan4-stat-val mwan4-mono' }, [
						E('span', { 'data-role': 'gw' }, iface.gateway)
					])
				]),
				E('div', { 'class': 'mwan4-stat-item' }, [
					E('span', { 'class': 'mwan4-stat-label' }, _('Weight')),
					E('span', { 'class': 'mwan4-stat-val' }, [
						E('span', { 'data-role': 'pw' }, pwText(iface))
					])
				])
			]),
			E('div', { 'class': 'mwan4-rate-box' }, [
				E('div', { 'class': 'mwan4-rate-row' }, [
					E('span', { 'class': 'mwan4-rate-pair mwan4-mono' }, [
						E('span', { 'data-role': 'rate-rx' }, '\u2193 ' + (up ? formatRate(iface.rx_bps) : '--')),
						E('span', { 'class': 'mwan4-rate-sep' }, '/'),
						E('span', { 'data-role': 'rate-tx' }, '\u2191 ' + (up ? formatRate(iface.tx_bps) : '--'))
					]),
					E('span', {
						'class': 'mwan4-load-tag ' + (iface.offloaded ? 'warn' : ''),
						'data-role': 'load-badge',
						'style': hasLoad ? '' : 'display: none'
					}, loadBadgeText(iface))
				]),
				E('div', {
					'class': 'mwan4-meter mwan4-meter-load',
					'data-role': 'load-wrap',
					'style': hasLoad ? '' : 'display: none'
				}, [
					E('i', {
						'class': 'mwan4-meter-fill ' + ldLevel,
						'data-role': 'load-fill',
						'style': 'width: ' + loadPct + '%;'
					})
				])
			]),
			E('div', { 'class': 'mwan4-trend-wrap' }, [
				trendEl(iface)
			]),
			E('div', { 'class': 'mwan4-card-footer' }, [
				E('div', { 'class': 'mwan4-loss-inline' }, [
					E('span', { 'class': 'mwan4-loss-label' }, _('Loss')),
					dot(lLevel, 'loss-dot'),
					E('b', { 'class': 'mwan4-loss-val', 'data-role': 'loss' }, lossText(iface)),
					E('div', { 'class': 'mwan4-meter mwan4-meter-sm' }, [
						E('i', {
							'class': 'mwan4-meter-fill ' + lLevel,
							'data-role': 'meter',
							'style': 'width: ' + Math.min(100, Math.max(0, loss)) + '%;'
						})
					])
				]),
				E('div', { 'class': 'mwan4-counters' }, [
					E('span', { 'data-role': 'succ' }, succText(iface)),
					E('span', { 'class': 'mwan4-counters-sep' }, '·'),
					E('span', { 'data-role': 'to' }, toText(iface))
				])
			])
		]);
	},

	cardsContainer: function(statusData) {
		var container = E('div', { 'id': 'mwan4_cards_container', 'class': 'mwan4-cards-grid' });
		var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
		var fresh = freshnessOf(statusData);

		if (list.length === 0) {
			container.appendChild(E('div', { 'class': 'mwan4-empty' },
				_('No metrics available. Check that the MWAN4 service is running.')
			));
		} else {
			for (var i = 0; i < list.length; i++) {
				container.appendChild(this.renderCard(list[i], fresh));
			}
		}

		container.setAttribute('data-sig', list.map(function(iface) {
			return iface.name;
		}).join(','));

		return container;
	},

	updateCard: function(card, iface, fresh) {
		var up = iface.state === 'UP';
		var sLevel = stateLevel(iface);
		var loss = iface.loss_rate || 0;
		var lLevel = lossLevel(loss);
		var hasLoad = up && iface.load_pct !== undefined && iface.load_pct !== null;
		var loadPct = hasLoad ? Math.min(100, Math.max(0, iface.load_pct)) : 0;

		setText(pick(card, 'ip'), iface.ip ? iface.ip : _('(No IP)'));
		setText(pick(card, 'state-text'), stateText(iface));
		setCls(pick(card, 'state-dot'), 'mwan4-dot ' + sLevel);
		setCls(pick(card, 'state-pill'), 'mwan4-pill mwan4-pill-' + sLevel);

		var alert = cardAlert(iface, fresh);
		var alertEl = pick(card, 'alert');
		if (alertEl) {
			setText(alertEl, alert);
			var display = alert ? '' : 'none';
			if (alertEl.style.display !== display) alertEl.style.display = display;
		}
		setCls(card, cardClass(iface, fresh));

		setText(pick(card, 'rtt'), rttText(iface));
		setCls(pick(card, 'rtt-dot'), 'mwan4-dot ' + (up ? rttLevel(iface.rtt_ms) : 'muted'));
		setText(pick(card, 'jitter'), jitterText(iface));
		setText(pick(card, 'gw'), iface.gateway);
		setText(pick(card, 'pw'), pwText(iface));

		setText(pick(card, 'rate-rx'), '\u2193 ' + (up ? formatRate(iface.rx_bps) : '--'));
		setText(pick(card, 'rate-tx'), '\u2191 ' + (up ? formatRate(iface.tx_bps) : '--'));

		var loadBadge = pick(card, 'load-badge');
		if (loadBadge) {
			setText(loadBadge, loadBadgeText(iface));
			setCls(loadBadge, 'mwan4-load-tag ' + (iface.offloaded ? 'warn' : ''));
			loadBadge.style.display = hasLoad ? '' : 'none';
		}
		var loadWrap = pick(card, 'load-wrap');
		if (loadWrap) loadWrap.style.display = hasLoad ? '' : 'none';
		setCls(pick(card, 'load-fill'), 'mwan4-meter-fill ' + loadLevel(loadPct));
		setW(pick(card, 'load-fill'), loadPct + '%');

		var trend = pick(card, 'trend');
		if (trend) updateTrend(trend, iface);

		setText(pick(card, 'loss'), lossText(iface));
		setCls(pick(card, 'loss-dot'), 'mwan4-dot ' + lLevel);
		setCls(pick(card, 'meter'), 'mwan4-meter-fill ' + lLevel);
		setW(pick(card, 'meter'), Math.min(100, Math.max(0, loss)) + '%');

		setText(pick(card, 'succ'), succText(iface));
		setText(pick(card, 'to'), toText(iface));
	},

	applyStatus: function(statusData) {
		this.recordTrend(statusData);
		var fresh = freshnessOf(statusData);
		var rLevel = runLevel(fresh);
		var ws = wanSummary(statusData);
		var header = document.getElementById('mwan4_header_container');
		if (header) {
			var ri = routeInfo(statusData);
			setText(pick(header, 'run-text'), runText(fresh));
			setCls(pick(header, 'run-dot'), 'mwan4-dot ' + rLevel);
			setCls(pick(header, 'run-pill'), 'mwan4-pill mwan4-pill-' + rLevel);

			setText(pick(header, 'wan-text'), ws.text);
			setCls(pick(header, 'wan-dot'), 'mwan4-dot ' + ws.level);
			setText(pick(header, 'agg-rx'), '\u2193 ' + formatRate(ws.rx));
			setText(pick(header, 'agg-tx'), '\u2191 ' + formatRate(ws.tx));

			setText(pick(header, 'route-text'), ri.text);
			setCls(pick(header, 'route-dot'), 'mwan4-dot ' + ri.level);
			setTitle(pick(header, 'route-wrap'), ri.title);

			setText(pick(header, 'age-text'), statusAgeText(statusData));

			var pt = policyText(statusData);
			var policyItem = pick(header, 'policy-item');
			if (policyItem) policyItem.style.display = pt ? '' : 'none';
			setText(pick(header, 'policy-text'), pt || '');

			var dt = dnsText(statusData);
			var dnsItem = pick(header, 'dns-item');
			if (dnsItem) dnsItem.style.display = dt ? '' : 'none';
			setText(pick(header, 'dns-text'), dt || '');

			var hi = hashInfo(statusData);
			setText(pick(header, 'hash-text'), hi.text);
			setCls(pick(header, 'hash-dot'), 'mwan4-dot ' + hi.level);
			setCls(pick(header, 'hash-pill'), 'mwan4-pill mwan4-pill-' + hi.level);
			setTitle(pick(header, 'hash-pill'), hi.title);
		}

		var container = document.getElementById('mwan4_cards_container');
		if (!container || !container.parentNode) return;

		var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
		var sig = list.map(function(iface) { return iface.name; }).join(',');

		if (container.getAttribute('data-sig') !== sig) {
			container.parentNode.replaceChild(this.cardsContainer(statusData), container);
			return;
		}

		for (var i = 0; i < list.length; i++) {
			var card = container.querySelector('.mwan4-card[data-iface="' + list[i].name + '"]');
			if (card) this.updateCard(card, list[i], fresh);
		}
	},

	updateDashboard: function() {
		if (this.viewRoot && this.viewRoot.isConnected) {
			this.pollMisses = 0;
		} else if (++this.pollMisses >= 3) {
			poll.remove(this.pollFn);
			return Promise.resolve();
		} else {
			return Promise.resolve();
		}

		var self = this;
		return readStatusJson().then(function(statusData) {
			self.applyStatus(statusData);
		});
	},

	render: function(data) {
		var statusData = data[2];
		var netdevs = data[3] || [];
		var m, s, o;

		var styleNode = E('style', {}, `
			.mwan4-view {
				--mw-fg: #1f2937;
				--mw-muted: #6b7280;
				--mw-line: rgba(15, 23, 42, 0.09);
				--mw-line-strong: rgba(15, 23, 42, 0.16);
				--mw-surface: rgba(255, 255, 255, 0.72);
				--mw-surface-2: rgba(15, 23, 42, 0.035);
				--mw-track: rgba(15, 23, 42, 0.08);
				--mw-ok: #10b981;
				--mw-ok-bg: rgba(16, 185, 129, 0.12);
				--mw-warn: #f59e0b;
				--mw-warn-bg: rgba(245, 158, 11, 0.13);
				--mw-bad: #ef4444;
				--mw-bad-bg: rgba(239, 68, 68, 0.12);
				--mw-info: #3b82f6;
				--mw-info-bg: rgba(59, 130, 246, 0.12);
				--mw-radius: 10px;
				--mw-shadow: 0 1px 3px rgba(15, 23, 42, 0.04), 0 1px 2px rgba(15, 23, 42, 0.02);
				--mw-shadow-hover: 0 8px 20px rgba(15, 23, 42, 0.07);
			}

			@media (prefers-color-scheme: dark) {
				.mwan4-view {
					--mw-fg: #e5e7eb;
					--mw-muted: #9ca3af;
					--mw-line: rgba(255, 255, 255, 0.10);
					--mw-line-strong: rgba(255, 255, 255, 0.18);
					--mw-surface: rgba(255, 255, 255, 0.035);
					--mw-surface-2: rgba(255, 255, 255, 0.06);
					--mw-track: rgba(255, 255, 255, 0.11);
					--mw-ok: #34d399;
					--mw-ok-bg: rgba(52, 211, 153, 0.15);
					--mw-warn: #fbbf24;
					--mw-warn-bg: rgba(251, 191, 36, 0.15);
					--mw-bad: #f87171;
					--mw-bad-bg: rgba(248, 113, 113, 0.15);
					--mw-info: #60a5fa;
					--mw-info-bg: rgba(96, 165, 250, 0.15);
					--mw-shadow: 0 1px 3px rgba(0, 0, 0, 0.25);
					--mw-shadow-hover: 0 8px 22px rgba(0, 0, 0, 0.35);
				}
			}

			html[data-darkmode="true"] .mwan4-view,
			html[data-theme="dark"] .mwan4-view,
			body.dark .mwan4-view,
			.dark .mwan4-view {
				--mw-fg: #e5e7eb !important;
				--mw-muted: #9ca3af !important;
				--mw-line: rgba(255, 255, 255, 0.10) !important;
				--mw-line-strong: rgba(255, 255, 255, 0.18) !important;
				--mw-surface: rgba(255, 255, 255, 0.035) !important;
				--mw-surface-2: rgba(255, 255, 255, 0.06) !important;
				--mw-track: rgba(255, 255, 255, 0.11) !important;
				--mw-ok: #34d399 !important;
				--mw-ok-bg: rgba(52, 211, 153, 0.15) !important;
				--mw-warn: #fbbf24 !important;
				--mw-warn-bg: rgba(251, 191, 36, 0.15) !important;
				--mw-bad: #f87171 !important;
				--mw-bad-bg: rgba(248, 113, 113, 0.15) !important;
				--mw-info: #60a5fa !important;
				--mw-info-bg: rgba(96, 165, 250, 0.15) !important;
				--mw-shadow: 0 1px 3px rgba(0, 0, 0, 0.25) !important;
				--mw-shadow-hover: 0 8px 22px rgba(0, 0, 0, 0.35) !important;
			}

			.mwan4-dot {
				display: inline-block;
				width: 7px;
				height: 7px;
				border-radius: 50%;
				background: var(--mw-muted);
				flex: 0 0 auto;
			}
			.mwan4-dot.ok    { background: var(--mw-ok); box-shadow: 0 0 0 2px var(--mw-ok-bg); }
			.mwan4-dot.warn  { background: var(--mw-warn); box-shadow: 0 0 0 2px var(--mw-warn-bg); }
			.mwan4-dot.bad   { background: var(--mw-bad); box-shadow: 0 0 0 2px var(--mw-bad-bg); }
			.mwan4-dot.info  { background: var(--mw-info); box-shadow: 0 0 0 2px var(--mw-info-bg); }
			.mwan4-dot.muted { background: var(--mw-muted); opacity: .55; }

			.mwan4-pill {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				padding: 3px 10px;
				border-radius: 999px;
				font-size: 12px;
				font-weight: 600;
				color: var(--mw-fg);
				background: var(--mw-surface-2);
				border: 1px solid var(--mw-line);
				white-space: nowrap;
				line-height: 1.4;
			}
			.mwan4-pill-ok   { background: var(--mw-ok-bg); border-color: transparent; color: var(--mw-ok); }
			.mwan4-pill-warn { background: var(--mw-warn-bg); border-color: transparent; color: var(--mw-warn); }
			.mwan4-pill-bad  { background: var(--mw-bad-bg); border-color: transparent; color: var(--mw-bad); }
			.mwan4-pill-key  { color: var(--mw-muted); font-weight: 500; }

			/* ---- Header ---- */
			.mwan4-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				flex-wrap: wrap;
				gap: 10px 16px;
				padding: 12px 16px;
				margin-bottom: 12px;
				background: var(--mw-surface);
				border: 1px solid var(--mw-line);
				border-radius: var(--mw-radius);
				box-shadow: var(--mw-shadow);
			}
			.mwan4-brand {
				display: flex;
				align-items: center;
				gap: 10px;
				min-width: 0;
			}
			.mwan4-title {
				font-size: 16px;
				font-weight: 700;
				letter-spacing: .1px;
				color: var(--mw-fg);
			}
			.mwan4-meta {
				display: flex;
				align-items: center;
				flex-wrap: wrap;
				gap: 8px;
			}
			.mwan4-age {
				font-size: 11.5px;
				color: var(--mw-muted);
				font-variant-numeric: tabular-nums;
				padding-left: 2px;
			}

			/* ---- KPI Tiles ---- */
			.mwan4-summary {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
				gap: 10px;
				margin-bottom: 16px;
			}
			.mwan4-tile {
				display: flex;
				flex-direction: column;
				gap: 4px;
				padding: 12px 14px;
				background: var(--mw-surface);
				border: 1px solid var(--mw-line);
				border-radius: var(--mw-radius);
				box-shadow: var(--mw-shadow);
				min-width: 0;
			}
			.mwan4-tile-key {
				font-size: 11.5px;
				font-weight: 500;
				color: var(--mw-muted);
			}
			.mwan4-tile-val {
				display: inline-flex;
				align-items: center;
				gap: 8px;
				font-size: 17px;
				font-weight: 700;
				color: var(--mw-fg);
				font-variant-numeric: tabular-nums;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.mwan4-tile-val-sm {
				font-size: 14px;
				font-weight: 650;
			}

			/* ---- WAN Cards ---- */
			.mwan4-cards-grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
				gap: 14px;
				margin-bottom: 22px;
			}
			.mwan4-card {
				margin: 0 !important;
				padding: 15px 17px !important;
				background: var(--mw-surface) !important;
				border: 1px solid var(--mw-line) !important;
				border-top: 3px solid var(--mw-ok) !important;
				border-radius: var(--mw-radius) !important;
				box-shadow: var(--mw-shadow) !important;
				color: var(--mw-fg) !important;
				transition: box-shadow .18s ease, transform .18s ease, border-color .18s ease;
			}
			.mwan4-card:hover {
				box-shadow: var(--mw-shadow-hover) !important;
				transform: translateY(-1px);
			}
			.mwan4-card-down     { border-top-color: var(--mw-bad) !important; }
			.mwan4-card-degraded { border-top-color: var(--mw-warn) !important; }
			.mwan4-card-local    { border-top-color: var(--mw-warn) !important; }
			.mwan4-card-stale {
				border-style: dashed !important;
				opacity: .78;
			}
			.mwan4-card-head {
				display: flex;
				justify-content: space-between;
				align-items: center;
				gap: 10px;
				padding-bottom: 10px;
				margin-bottom: 12px;
				border-bottom: 1px solid var(--mw-line);
			}
			.mwan4-card-id {
				display: flex;
				align-items: center;
				gap: 8px;
				min-width: 0;
				overflow: hidden;
				white-space: nowrap;
			}
			.mwan4-card-title {
				font-size: 15.5px;
				font-weight: 700;
				color: var(--mw-fg);
			}
			.mwan4-card-ip {
				color: var(--mw-muted);
				font-size: 11.5px;
				font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
				padding: 1px 6px;
				border-radius: 4px;
				background: var(--mw-surface-2);
				overflow: hidden;
				text-overflow: ellipsis;
			}
			.mwan4-card-alert {
				margin: 0 0 11px 0;
				padding: 6px 10px;
				border-radius: 6px;
				background: var(--mw-warn-bg);
				color: var(--mw-fg);
				font-size: 11.5px;
				line-height: 1.45;
				word-break: break-word;
			}
			.mwan4-card-stale .mwan4-card-alert,
			.mwan4-card-down .mwan4-card-alert {
				background: var(--mw-bad-bg);
			}

			.mwan4-stats-grid {
				display: grid;
				grid-template-columns: repeat(4, minmax(0, 1fr));
				gap: 10px;
				margin-bottom: 12px;
			}
			.mwan4-stat-item {
				display: flex;
				flex-direction: column;
				min-width: 0;
			}
			.mwan4-stat-label {
				color: var(--mw-muted);
				font-size: 11px;
				margin-bottom: 2px;
			}
			.mwan4-stat-val {
				display: inline-flex;
				align-items: center;
				gap: 5px;
				font-size: 13.5px;
				font-weight: 650;
				color: var(--mw-fg);
				font-variant-numeric: tabular-nums;
				min-width: 0;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.mwan4-mono {
				font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
				font-size: 12.5px;
				font-weight: 550;
			}
			.mwan4-tile-val.mwan4-mono {
				font-size: 15.5px;
				font-weight: 700;
			}

			/* ---- Throughput & Load ---- */
			.mwan4-rate-box {
				padding: 8px 10px;
				margin-bottom: 10px;
				border-radius: 7px;
				background: var(--mw-surface-2);
			}
			.mwan4-rate-row {
				display: flex;
				justify-content: space-between;
				align-items: center;
				gap: 8px;
			}
			.mwan4-rate-pair {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				color: var(--mw-fg);
				font-size: 12.5px;
				font-variant-numeric: tabular-nums;
			}
			.mwan4-rate-sep {
				color: var(--mw-muted);
				opacity: .6;
			}
			.mwan4-load-tag {
				font-size: 11px;
				font-weight: 600;
				color: var(--mw-muted);
				font-variant-numeric: tabular-nums;
			}
			.mwan4-load-tag.warn {
				color: var(--mw-warn);
			}
			.mwan4-meter-load {
				margin-top: 6px;
			}

			/* ---- RTT Sparkline ---- */
			.mwan4-trend-wrap {
				margin: 4px 0 10px 0;
			}
			.mwan4-trend {
				display: flex;
				align-items: flex-end;
				gap: 1.5px;
				height: 30px;
				padding-bottom: 1px;
				border-bottom: 1px solid var(--mw-line);
			}
			.mwan4-trend-bar {
				flex: 1 1 0;
				min-width: 0;
				height: 0;
				border-radius: 2px 2px 0 0;
				background: var(--mw-muted);
				opacity: .35;
				transition: height .3s ease;
			}
			.mwan4-trend-bar.ok    { background: var(--mw-ok); opacity: .82; }
			.mwan4-trend-bar.warn  { background: var(--mw-warn); opacity: .9; }
			.mwan4-trend-bar.bad   { background: var(--mw-bad); opacity: .9; }
			.mwan4-trend-bar.empty { background: var(--mw-line-strong); opacity: .22; }

			/* ---- Meters & Footer ---- */
			.mwan4-meter {
				width: 100%;
				height: 4px;
				background: var(--mw-track);
				border-radius: 999px;
				overflow: hidden;
			}
			.mwan4-meter-sm {
				width: 56px;
				flex: 0 0 auto;
			}
			.mwan4-meter-fill {
				display: block;
				height: 100%;
				border-radius: 999px;
				background: var(--mw-muted);
				transition: width .3s ease;
			}
			.mwan4-meter-fill.ok   { background: var(--mw-ok); }
			.mwan4-meter-fill.warn { background: var(--mw-warn); }
			.mwan4-meter-fill.bad  { background: var(--mw-bad); }

			.mwan4-card-footer {
				display: flex;
				justify-content: space-between;
				align-items: center;
				gap: 10px;
				font-size: 11.5px;
				color: var(--mw-muted);
				font-variant-numeric: tabular-nums;
			}
			.mwan4-loss-inline {
				display: inline-flex;
				align-items: center;
				gap: 6px;
			}
			.mwan4-loss-label {
				color: var(--mw-muted);
			}
			.mwan4-loss-val {
				color: var(--mw-fg);
				font-weight: 600;
			}
			.mwan4-counters {
				display: inline-flex;
				align-items: center;
				gap: 5px;
			}
			.mwan4-counters-sep {
				opacity: .5;
			}

			.mwan4-empty {
				grid-column: 1 / -1;
				padding: 20px 16px;
				border: 1px dashed var(--mw-line-strong);
				border-radius: var(--mw-radius);
				color: var(--mw-muted);
				font-size: 13px;
				text-align: center;
			}

			/* ---- LuCI Form Polish ---- */
			.mwan4-view .cbi-map > h2 {
				font-size: 16px;
				font-weight: 700;
				margin-bottom: 12px;
			}
			.mwan4-view .cbi-section {
				border-radius: var(--mw-radius);
				border: 1px solid var(--mw-line);
				box-shadow: var(--mw-shadow);
				margin-bottom: 16px;
			}
			.mwan4-view .cbi-section > h3 {
				font-size: 14px;
				font-weight: 650;
			}
			.mwan4-view .cbi-section-node {
				overflow-x: auto;
			}
			.mwan4-view table.cbi-section-table {
				table-layout: auto;
				width: 100%;
			}
			.mwan4-view table.cbi-section-table th,
			.mwan4-view table.cbi-section-table td {
				padding: 4px 7px !important;
				font-size: 12.5px !important;
				line-height: 1.35 !important;
				vertical-align: middle !important;
			}
			.mwan4-view table.cbi-section-table tr.cbi-section-table-descr th {
				font-size: 11px !important;
				font-weight: 400 !important;
				color: var(--mw-muted) !important;
				padding-top: 0 !important;
				text-align: left;
				white-space: normal !important;
				overflow: hidden !important;
				word-break: break-word;
			}
			.mwan4-view .mwan4-header,
			.mwan4-view .mwan4-summary,
			.mwan4-view .mwan4-cards-grid,
			.mwan4-view table.cbi-section-table {
				-webkit-user-select: text;
				user-select: text;
			}
			.mwan4-view table.cbi-section-table input.cbi-input-text,
			.mwan4-view table.cbi-section-table input.cbi-input-select,
			.mwan4-view table.cbi-section-table .cbi-dropdown {
				width: 100% !important;
				min-width: 0 !important;
				height: auto !important;
				min-height: 26px !important;
				padding: 2px 7px !important;
				font-size: 12.5px !important;
				border-radius: 5px !important;
				box-shadow: none !important;
			}
			.mwan4-view table.cbi-section-table .cbi-dynlist {
				min-width: 0 !important;
			}
			.mwan4-view table.cbi-section-table .cbi-dynlist > .item {
				margin: 0 0 2px 0 !important;
			}
			.mwan4-view table.cbi-section-table .cbi-dynlist > .item > input {
				min-width: 0 !important;
			}
			.mwan4-view table.cbi-section-table .cbi-button {
				min-height: 0 !important;
				padding: 2px 9px !important;
				font-size: 12px !important;
				border-radius: 5px !important;
			}
			.mwan4-view input[id$="-name"],
			.mwan4-view select[id$="-name"] {
				max-width: 180px !important;
			}
			.mwan4-view .cbi-value-field > span.control-group > input[id$="-name"] {
				flex: 0 1 180px !important;
			}

			@media (max-width: 768px) {
				.mwan4-header { align-items: flex-start; }
				.mwan4-cards-grid { grid-template-columns: 1fr; }
				.mwan4-stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
			}

			.mwan4-view * {
				scrollbar-width: thin;
				scrollbar-color: var(--mw-line-strong) transparent;
			}
			.mwan4-view ::-webkit-scrollbar { width: 8px; height: 8px; }
			.mwan4-view ::-webkit-scrollbar-track { background: transparent; }
			.mwan4-view ::-webkit-scrollbar-thumb {
				background: var(--mw-line-strong);
				border-radius: 4px;
			}
		`);

		this.recordTrend(statusData);

		var viewRoot = E('div', { 'class': 'mwan4-view' }, [
			styleNode,
			this.renderStatusHeader(statusData),
			this.cardsContainer(statusData)
		]);

		this.viewRoot = viewRoot;
		this.pollMisses = 0;
		this.pollFn = this.updateDashboard.bind(this);
		poll.add(this.pollFn, 5);

		m = new form.Map('mwan4', _('MWAN4 Configuration'));

		s = m.section(form.NamedSection, 'global', 'global', _('Global Settings'));
		s.tab('basic', _('Basic'));
		s.tab('dns', _('DNS'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('basic', form.Flag, 'enabled', _('Enable Service'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('basic', form.ListValue, 'ecmp_mode', _('Routing Mode'));
		o.value('auto', _('Auto'));
		o.value('standard', _('Standard ECMP'));
		o.value('resilient', _('Resilient Nexthop'));
		o.default = 'auto';
		o.rmempty = false;

		o = s.taboption('basic', form.ListValue, 'weight_mode', _('Weight Mode'));
		o.value('static', _('Static'));
		o.value('quality', _('Quality-aware'));
		o.value('aggregate', _('Smart Aggregate'));
		o.default = 'static';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'check_interval_ms', _('Probe Interval (ms)'));
		o.datatype = 'uinteger';
		o.default = '1000';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'probe_timeout_ms', _('Probe Timeout (ms)'));
		o.datatype = 'uinteger';
		o.default = '800';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'consecutive_fail_down', _('Failure Threshold'));
		o.datatype = 'uinteger';
		o.default = '4';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'recovery_success_count', _('Recovery Threshold'));
		o.datatype = 'uinteger';
		o.default = '3';
		o.rmempty = false;

		o = s.taboption('dns', form.ListValue, 'probe_mode', _('Probe Protocol'));
		o.value('tcp', _('TCP SYN'));
		o.value('dns', _('DNS Query'));
		o.default = 'tcp';
		o.rmempty = false;

		o = s.taboption('dns', form.Value, 'dns_probe_domain', _('Probe Domain'));
		o.default = 'baidu.com';
		o.placeholder = 'baidu.com';
		o.depends('probe_mode', 'dns');

		o = s.taboption('dns', form.Value, 'dns_listen_port', _('Forward Port'));
		o.datatype = 'range(0,65535)';
		o.default = '0';
		o.placeholder = '5354';
		o.rmempty = false;

		o = s.taboption('dns', form.Value, 'dns_listen_addr', _('Listen Address'));
		o.datatype = 'ipaddr';
		o.default = '127.0.0.1';
		o.placeholder = '127.0.0.1';

		o = s.taboption('dns', form.Value, 'dns_forward_timeout_ms', _('Forward Timeout (ms)'));
		o.datatype = 'range(100,15000)';
		o.default = '2000';

		o = s.taboption('dns', form.Value, 'dns_resolv_file', _('DNS Export File'));
		o.placeholder = '/tmp/mwan4_resolv.conf';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'window_size', _('Window Size'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'loss_threshold_down', _('DOWN Loss Threshold'));
		o.default = '0.5';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'max_rtt_ms', _('Max RTT (ms)'));
		o.default = '1500';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'degrade_loss_threshold', _('Degrade Loss Threshold'));
		o.default = '0';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'resilient_idle_timer_secs', _('Resilient Idle Timer (s)'));
		o.datatype = 'range(1,3600)';
		o.default = '30';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'resilient_unbalanced_timer_secs', _('Resilient Rebalance Timer (s)'));
		o.datatype = 'range(0,3600)';
		o.default = '60';
		o.rmempty = false;

		o = s.taboption('advanced', form.ListValue, 'multipath_hash_policy', _('Hash Policy'));
		o.value('l4', _('L4 (Per-Connection)'));
		o.value('l3', _('L3 (Per-IP)'));
		o.value('inner', _('Inner (Tunnel)'));
		o.default = 'l4';
		o.rmempty = false;

		o = s.taboption('advanced', form.Flag, 'load_aware', _('Load-aware Shifting'));
		o.default = o.disabled;
		o.depends('weight_mode', 'static');
		o.depends('weight_mode', 'quality');

		o = s.taboption('advanced', form.Value, 'dynamic_weight_interval_ms', _('Weight Update Interval (ms)'));
		o.datatype = 'uinteger';
		o.default = '10000';
		o.depends('weight_mode', 'quality');
		o.depends('weight_mode', 'aggregate');
		o.depends('load_aware', '1');

		o = s.taboption('advanced', form.Flag, 'allow_dynamic_weights_on_standard', _('Dynamic Weights on Standard ECMP'));
		o.default = o.disabled;
		o.depends('ecmp_mode', 'standard');

		o = s.taboption('advanced', form.Flag, 'flush_conntrack', _('Flush Conntrack on DOWN'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.Flag, 'flush_conntrack_on_switch', _('Flush Conntrack on Switch'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.Flag, 'remove_routes_on_exit', _('Remove Routes on Exit'));
		o.default = o.disabled;

		s = m.section(form.GridSection, 'interface', _('WAN Interfaces'));
		s.addremove = true;
		s.anonymous = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Interface'));
		o.rmempty = false;
		o.editable = true;
		if (netdevs.length) {
			netdevs.forEach(function(dev) {
				o.value(dev);
			});
		} else {
			uci.sections('network', 'interface').forEach(function(sec) {
				if (sec['.name'] && sec['.name'] !== 'loopback' && sec['.name'] !== 'lan')
					o.value(sec['.name']);
			});
		}

		o = s.option(form.Value, 'gateway', _('Gateway'));
		o.datatype = 'ip4addr';
		o.placeholder = '0.0.0.0';
		o.rmempty = true;
		o.editable = true;

		o = s.option(form.Value, 'gateway6', _('IPv6 Gateway'));
		o.datatype = 'ip6addr';
		o.rmempty = true;
		o.modalonly = true;

		o = s.option(form.Value, 'metric', _('Priority'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.editable = true;

		o = s.option(form.Value, 'weight', _('Weight'));
		o.datatype = 'uinteger';
		o.default = '1';
		o.editable = true;

		o = s.option(form.Value, 'max_mbps', _('Bandwidth (Mbps)'));
		o.datatype = 'ufloat';
		o.editable = true;

		o = s.option(form.Value, 'up_mbps', _('Uplink (Mbps)'));
		o.datatype = 'ufloat';
		o.modalonly = true;

		o = s.option(form.ListValue, 'probe_mode', _('Probe Protocol'));
		o.value('', _('Global Default'));
		o.value('tcp', _('TCP SYN'));
		o.value('dns', _('DNS Query'));
		o.rmempty = true;
		o.modalonly = true;

		o = s.option(form.DynamicList, 'probe_targets', _('Probe Targets'));
		o.datatype = 'ipaddrport(1)';
		o.default = ['223.5.5.5:53', '114.114.114.114:53'];

		o = s.option(form.DynamicList, 'dns_servers', _('Upstream DNS'));
		o.placeholder = '202.96.128.86';
		o.validate = validateDnsServer;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'underlay_targets', _('Tunnel Peers'));
		o.datatype = 'ip4addr';
		o.rmempty = true;
		o.modalonly = true;

		s = m.section(form.GridSection, 'policy', _('Policy Routing'));
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;

		o = s.option(form.Value, 'name', _('Name'));
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.DynamicList, 'source', _('Source CIDR'));
		o.datatype = 'cidr4';
		o.placeholder = '192.168.3.0/24';
		o.editable = true;

		o = s.option(form.DynamicList, 'destination', _('Destination CIDR'));
		o.datatype = 'cidr4';
		o.editable = true;

		o = s.option(form.ListValue, 'interface', _('Target WAN'));
		o.rmempty = false;
		o.editable = true;
		uci.sections('mwan4', 'interface').forEach(function(sec) {
			var wanName = sec.name || sec['.name'];
			if (wanName) o.value(wanName, wanName);
		});

		o = s.option(form.Value, 'priority', _('Priority'));
		o.datatype = 'uinteger';
		o.editable = true;

		return m.render().then(function(formNode) {
			viewRoot.appendChild(formNode);
			alignDescrRows(formNode);
			return viewRoot;
		});
	},

	handleSaveApply: function(ev, mode) {
		return this.super('handleSaveApply', [ev, mode]).then(function() {
			ui.addNotification(null, E('p', _('MWAN4 configuration saved and applied.')), 'info');
		});
	}
});
