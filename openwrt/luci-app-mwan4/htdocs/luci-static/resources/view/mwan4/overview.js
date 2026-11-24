'use strict';
'require view';
'require fs';
'require uci';
'require ui';
'require form';
'require poll';

/* 容忍的时钟偏差（秒）。浏览器与路由器各自 NTP，差十几秒是常态，
   只有差距大到无法用时差解释时才说「不可判断」。 */
var CLOCK_SKEW_TOLERANCE_SECS = 300;

/* 上一次看到的 updated_at：只要它还在变大，daemon 就是活的（不受时差影响）。 */
var lastSeenUpdatedAt = null;

/* 每张卡片的 RTT/丢包趋势：轮询时累积，只存在于本页（重新载入即清空）。 */
var TREND_LEN = 60;
var trendHistory = {};

function history2bars(iface) {
	var h = trendHistory[iface.name] || [];
	var max = 50;
	for (var i = 0; i < h.length; i++)
		if (h[i].rtt > max) max = h[i].rtt;

	// 时间由左向右，最新一笔在最右侧的已填格；还没累积到的格子留白。
	var out = [];
	for (var n = 0; n < TREND_LEN; n++) {
		var s = h[n];
		if (!s || !s.up || s.rtt === null) {
			out.push({ pct: 0, level: s ? 'bad' : 'empty', label: s ? _('Offline (DOWN)') : '' });
			continue;
		}
		var level = rttLevel(s.rtt);
		var l = lossLevel(s.loss);
		if (l === 'bad') level = 'bad';
		else if (l === 'warn' && level === 'ok') level = 'warn';
		out.push({
			pct: Math.max(8, Math.min(100, s.rtt / max * 100)),
			level: level,
			label: s.rtt.toFixed(1) + ' ms / ' + s.loss.toFixed(1) + '%'
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

/* 核心设备名清单：daemon 用 SO_BINDTODEVICE / if_nametoindex 都需要核心设备名，
   而 UCI 的 network 逻辑名（wan/wanb…）经常不同名；桥接属于 LAN 侧，一律排除。 */
function listNetdevs() {
	return fs.list('/sys/class/net').then(function(list) {
		return (list || []).filter(function(name) {
			return name !== 'lo' && name.indexOf('br-') !== 0;
		});
	}).catch(function() {
		return [];
	});
}

/* 状态档新鲜度：'fresh' | 'stale' | 'skew' | 'missing'。
   daemon 被杀掉后，最后一次快照不能继续被当成即时状态显示。 */
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

function runLevel(fresh) {
	if (fresh === 'fresh') return 'ok';
	if (fresh === 'stale') return 'bad';
	return 'muted';
}

function runText(fresh) {
	if (fresh === 'fresh') return _('Running');
	if (fresh === 'stale') return _('Stopped (status is stale)');
	if (fresh === 'missing') return _('No status file');
	return _('Not trustworthy (clock skew)');
}

function stateText(iface) {
	if (iface.state !== 'UP') return _('Offline (DOWN)');
	return iface.degraded
		? _('Online (UP, degraded - not carrying traffic)')
		: _('Online (UP)');
}

function cardAlert(iface, fresh) {
	if (fresh === 'stale')
		return _('Status is stale: the daemon may have stopped. This is the last known state.');
	if (fresh === 'skew')
		return _('Router clock differs from this browser, so freshness cannot be judged. ' +
			'These values may be the last known state of a stopped daemon.');
	if (fresh === 'missing')
		return _('No status file yet: the daemon has not written one (or it just started).');
	if (iface.local_condition && iface.last_error)
		return _('Local problem (packets never left the device): ') + iface.last_error;
	if (iface.last_error)
		return _('Last probe error: ') + iface.last_error;
	if (iface.degraded)
		return _('Degraded: sliding-window packet loss reached the degrade threshold, so this WAN ' +
			'is excluded from the default route. It is still probed and rejoins automatically ' +
			'once its loss drops.');
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
		return _('missing');
	var age = Date.now() / 1000 - statusData.updated_at;
	if (age < -CLOCK_SKEW_TOLERANCE_SECS)
		return _('clock skew');
	if (age < 60)
		return Math.max(0, Math.round(age)) + ' s ' + _('ago');
	var minutes = Math.floor(age / 60);
	if (minutes < 60)
		return minutes + ' min ' + _('ago');
	return Math.floor(minutes / 60) + ' h ' + _('ago');
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
	return { level: level, text: text };
}

/* 承载线概况：全 UP 且无降级 = ok；有降级 = warn；有任何一条 DOWN = bad。 */
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
	var w = 'W:' + iface.weight;
	if (iface.effective_weight !== undefined && iface.effective_weight !== iface.weight)
		w = 'W:' + iface.weight + ' \u2192 ' + iface.effective_weight;
	return (iface.metric ? ('P:' + iface.metric + ' / ') : '') + w;
}

function formatRate(bps) {
	if (!bps || bps < 1000) return '0 bps';
	var units = ['Kbps', 'Mbps', 'Gbps'];
	var v = bps / 1000, i = 0;
	while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
	return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
}

function rateText(iface) {
	if (iface.state !== 'UP') return '\u2191 --  \u2193 --';
	var text = '\u2191 ' + formatRate(iface.tx_bps) + '  \u2193 ' + formatRate(iface.rx_bps);
	if (iface.load_pct !== undefined && iface.load_pct !== null) {
		text += '  (' + iface.load_pct.toFixed(0) + '%';
		if (iface.offloaded) text += ', ' + _('offloaded');
		text += ')';
	}
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

/* 核心「实际生效」的哈希粒度（读回值）：l3_only 就是「同一个目的 IP 的连线
   全挤一条 WAN」，也就是视频 CDN 卡顿最常见的成因。 */
function hashInfo(statusData) {
	var h = statusData && statusData.hash;
	if (!h) return { level: 'muted', text: _('Unknown') };
	var policy = (h.policy === null || h.policy === undefined) ? 'n/a' : h.policy;
	var detail = 'policy=' + policy + ' fields=' + (h.fields_desc || 'n/a');
	return {
		level: h.l3_only ? 'warn' : 'ok',
		text: (h.l3_only
			? _('L3 only: one WAN per destination IP')
			: _('l4: per-connection spreading')) + ' (' + detail + ')'
	};
}

function succText(iface) { return _('Consecutive Successes: ') + iface.consecutive_successes; }
function toText(iface) { return _('Consecutive Timeouts: ') + iface.consecutive_timeouts; }

/* 只在值真的变了才写 DOM，轮询才不会打断文字选取。 */
function setText(el, txt) {
	if (el && el.textContent !== txt) el.textContent = txt;
}
function setCls(el, cls) {
	if (el && el.className !== cls) el.className = cls;
}
function setW(el, w) {
	if (el && el.style.width !== w) el.style.width = w;
}
function pick(root, role) {
	return root ? root.querySelector('[data-role="' + role + '"]') : null;
}

/* LuCI 的描述列比标题列少一格，主题又可能只给标题/资料列加 ::before 假格，
   两边都会让提示文字左移。量到实际位置后补空格子，直到第一格对齐；
   form 还没挂上时 rect 全为 0，用 rAF 重试。 */
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

		return E('div', { 'id': 'mwan4_header_container' }, [
			E('div', { 'class': 'mwan4-header' }, [
				E('div', { 'class': 'mwan4-brand' }, [
					E('span', { 'class': 'mwan4-title' }, _('MWAN4 Load Balancing')),
					E('span', { 'class': 'mwan4-sub' }, _('MWAN4 Multi-WAN Failover & Health Monitor'))
				]),
				E('div', { 'class': 'mwan4-meta' }, [
					E('span', { 'class': 'mwan4-meta-item' }, [
						E('span', { 'class': 'mwan4-meta-key' }, _('Daemon:')),
						E('span', { 'class': 'mwan4-badge' }, [
							dot(runLevel(fresh), 'run-dot'),
							E('span', { 'data-role': 'run-text' }, runText(fresh))
						])
					]),
					E('span', { 'class': 'mwan4-meta-item' }, [
						E('span', { 'class': 'mwan4-meta-key' }, _('Kernel Default Route:')),
						E('span', { 'class': 'mwan4-badge' }, [
							dot(ri.level, 'route-dot'),
							E('span', { 'data-role': 'route-text' }, ri.text)
						])
					]),
					E('span', { 'class': 'mwan4-meta-item' }, [
						E('span', { 'class': 'mwan4-meta-key' }, _('Status File:')),
						E('span', { 'class': 'mwan4-badge' }, [
							E('span', { 'data-role': 'age-text' }, statusAgeText(statusData))
						])
					]),
					E('span', {
						'class': 'mwan4-meta-item',
						'data-role': 'policy-item',
						'style': pt ? '' : 'display: none'
					}, [
						E('span', { 'class': 'mwan4-meta-key' }, _('Policy Routing:')),
						E('span', { 'class': 'mwan4-badge' }, [
							E('span', { 'data-role': 'policy-text' }, pt || '')
						])
					]),
					E('span', {
						'class': 'mwan4-meta-item',
						'data-role': 'dns-item',
						'style': dt ? '' : 'display: none'
					}, [
						E('span', { 'class': 'mwan4-meta-key' }, _('DNS:')),
						E('span', { 'class': 'mwan4-badge' }, [
							E('span', { 'data-role': 'dns-text' }, dt || '')
						])
					]),
					E('span', { 'class': 'mwan4-meta-item' }, [
						E('span', { 'class': 'mwan4-meta-key' }, _('Hash Granularity:')),
						E('span', { 'class': 'mwan4-badge' }, [
							dot(hi.level, 'hash-dot'),
							E('span', { 'data-role': 'hash-text' }, hi.text)
						])
					])
				])
			]),
			E('div', { 'class': 'mwan4-summary' }, [
				E('div', { 'class': 'mwan4-tile' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('WAN Status:')),
					E('span', { 'class': 'mwan4-tile-val' }, [
						dot(ws.level, 'wan-dot'),
						E('span', { 'data-role': 'wan-text' }, ws.text)
					])
				]),
				E('div', { 'class': 'mwan4-tile' }, [
					E('span', { 'class': 'mwan4-tile-key' }, _('Aggregate')),
					E('span', { 'class': 'mwan4-tile-val mwan4-mono', 'data-role': 'agg-text' },
						'\u2191 ' + formatRate(ws.tx) + '  \u2193 ' + formatRate(ws.rx))
				])
			])
		]);
	},

	renderCard: function(iface, fresh) {
		var up = iface.state === 'UP';
		var loss = iface.loss_rate || 0;
		var trust = fresh || 'fresh';
		var alert = cardAlert(iface, trust);

		return E('div', {
			'class': cardClass(iface, trust),
			'data-iface': iface.name
		}, [
			E('div', { 'class': 'mwan4-card-head' }, [
				E('div', { 'class': 'mwan4-card-id' }, [
					E('span', { 'class': 'mwan4-card-title' }, iface.name),
					E('span', { 'class': 'mwan4-card-ip' }, iface.ip ? iface.ip : _('(No IP)'))
				]),
				E('span', { 'class': 'mwan4-badge mwan4-badge-state' }, [
					dot(up ? (iface.degraded ? 'warn' : 'ok') : 'bad', 'state-dot'),
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
					E('span', { 'class': 'mwan4-stat-label' }, _('Realtime RTT')),
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
					E('span', { 'class': 'mwan4-stat-label' }, _('Priority / Weight')),
					E('span', { 'class': 'mwan4-stat-val' }, [
						E('span', { 'data-role': 'pw' }, pwText(iface))
					])
				]),
				E('div', { 'class': 'mwan4-stat-item mwan4-stat-wide' }, [
					E('span', { 'class': 'mwan4-stat-label' }, _('Throughput (TX / RX)')),
					E('span', { 'class': 'mwan4-stat-val mwan4-mono' }, [
						E('span', { 'data-role': 'rate' }, rateText(iface))
					])
				])
			]),
			E('div', { 'class': 'mwan4-trend-wrap' }, [
				E('span', { 'class': 'mwan4-trend-label' }, _('RTT Trend')),
				trendEl(iface)
			]),
			E('div', { 'class': 'mwan4-loss-section' }, [
				E('div', { 'class': 'mwan4-loss-header' }, [
					E('span', {}, _('Sliding Window Packet Loss')),
					E('span', { 'class': 'mwan4-badge' }, [
						dot(lossLevel(loss), 'loss-dot'),
						E('b', { 'data-role': 'loss' }, lossText(iface))
					])
				]),
				E('div', { 'class': 'mwan4-meter' }, [
					E('i', {
						'class': 'mwan4-meter-fill ' + lossLevel(loss),
						'data-role': 'meter',
						'style': 'width: ' + Math.min(100, Math.max(0, loss)) + '%;'
					})
				])
			]),
			E('div', { 'class': 'mwan4-card-footer' }, [
				E('span', { 'class': 'mwan4-chip', 'data-role': 'succ' }, succText(iface)),
				E('span', { 'class': 'mwan4-chip', 'data-role': 'to' }, toText(iface))
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
		var loss = iface.loss_rate || 0;
		var lLevel = lossLevel(loss);

		setText(pick(card, 'state-text'), stateText(iface));
		setCls(pick(card, 'state-dot'), 'mwan4-dot ' + (up ? (iface.degraded ? 'warn' : 'ok') : 'bad'));

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

		var trend = pick(card, 'trend');
		if (trend) updateTrend(trend, iface);

		setText(pick(card, 'loss'), lossText(iface));
		setCls(pick(card, 'loss-dot'), 'mwan4-dot ' + lLevel);
		setCls(pick(card, 'meter'), 'mwan4-meter-fill ' + lLevel);
		setW(pick(card, 'meter'), Math.min(100, Math.max(0, loss)) + '%');

		setText(pick(card, 'succ'), succText(iface));
		setText(pick(card, 'to'), toText(iface));
		setText(pick(card, 'rate'), rateText(iface));
	},

	applyStatus: function(statusData) {
		this.recordTrend(statusData);
		var fresh = freshnessOf(statusData);
		var ws = wanSummary(statusData);
		var header = document.getElementById('mwan4_header_container');
		if (header) {
			var ri = routeInfo(statusData);
			setText(pick(header, 'run-text'), runText(fresh));
			setCls(pick(header, 'run-dot'), 'mwan4-dot ' + runLevel(fresh));
			setText(pick(header, 'wan-text'), ws.text);
			setCls(pick(header, 'wan-dot'), 'mwan4-dot ' + ws.level);
			setText(pick(header, 'agg-text'),
				'\u2191 ' + formatRate(ws.tx) + '  \u2193 ' + formatRate(ws.rx));
			setText(pick(header, 'route-text'), ri.text);
			setCls(pick(header, 'route-dot'), 'mwan4-dot ' + ri.level);
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
		}

		var container = document.getElementById('mwan4_cards_container');
		if (!container || !container.parentNode) return;

		var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
		var sig = list.map(function(iface) { return iface.name; }).join(',');

		// 介面集合没变就只更新数值，避免轮询时整页闪动
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
		// LuCI 的 view 没有卸载回调，让轮询自己退出：view 不在 document 里就不再入列。
		// 给两次宽限，因为 poll.add() 跑在 form promise 解析之前。
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
				--mw-fg: #2f3337;
				--mw-muted: #8a8f98;
				--mw-line: rgba(0, 0, 0, 0.11);
				--mw-line-strong: rgba(0, 0, 0, 0.20);
				--mw-surface: rgba(0, 0, 0, 0.018);
				--mw-surface-2: rgba(0, 0, 0, 0.04);
				--mw-track: rgba(0, 0, 0, 0.08);
				--mw-ok: #35a06a;
				--mw-warn: #c9821f;
				--mw-bad: #cf4436;
				--mw-info: #5b7fb9;
				--mw-radius: 8px;
			}

			@media (prefers-color-scheme: dark) {
				.mwan4-view {
					--mw-fg: #d6d6d6;
					--mw-muted: #8b8f96;
					--mw-line: rgba(255, 255, 255, 0.13);
					--mw-line-strong: rgba(255, 255, 255, 0.24);
					--mw-surface: rgba(255, 255, 255, 0.03);
					--mw-surface-2: rgba(255, 255, 255, 0.06);
					--mw-track: rgba(255, 255, 255, 0.12);
					--mw-ok: #4cb87c;
					--mw-warn: #d69a3a;
					--mw-bad: #e0685a;
					--mw-info: #7d9fd0;
				}
			}

			html[data-darkmode="true"] .mwan4-view,
			html[data-theme="dark"] .mwan4-view,
			body.dark .mwan4-view,
			.dark .mwan4-view {
				--mw-fg: #d6d6d6 !important;
				--mw-muted: #8b8f96 !important;
				--mw-line: rgba(255, 255, 255, 0.13) !important;
				--mw-line-strong: rgba(255, 255, 255, 0.24) !important;
				--mw-surface: rgba(255, 255, 255, 0.03) !important;
				--mw-surface-2: rgba(255, 255, 255, 0.06) !important;
				--mw-track: rgba(255, 255, 255, 0.12) !important;
				--mw-ok: #4cb87c !important;
				--mw-warn: #d69a3a !important;
				--mw-bad: #e0685a !important;
				--mw-info: #7d9fd0 !important;
			}

			.mwan4-dot {
				display: inline-block;
				width: 7px;
				height: 7px;
				border-radius: 50%;
				background: var(--mw-muted);
				flex: 0 0 auto;
			}
			.mwan4-dot.ok    { background: var(--mw-ok); }
			.mwan4-dot.warn  { background: var(--mw-warn); }
			.mwan4-dot.bad   { background: var(--mw-bad); }
			.mwan4-dot.info  { background: var(--mw-info); }
			.mwan4-dot.muted { background: var(--mw-muted); opacity: .55; }

			.mwan4-badge {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				font-size: 12.5px;
				font-weight: 600;
				color: var(--mw-fg);
				white-space: nowrap;
				line-height: 1.4;
			}

			/* ---- 页首 ---- */
			.mwan4-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				flex-wrap: wrap;
				gap: 12px 24px;
				padding: 14px 16px;
				margin-bottom: 12px;
				background: var(--mw-surface);
				border: 1px solid var(--mw-line);
				border-radius: var(--mw-radius);
			}
			.mwan4-brand {
				display: flex;
				flex-direction: column;
				gap: 2px;
				min-width: 0;
			}
			.mwan4-title {
				font-size: 16px;
				font-weight: 650;
				letter-spacing: .2px;
				color: var(--mw-fg);
			}
			.mwan4-sub {
				font-size: 11.5px;
				color: var(--mw-muted);
			}
			.mwan4-meta {
				display: flex;
				align-items: center;
				flex-wrap: wrap;
				gap: 8px;
			}
			.mwan4-meta-item {
				display: inline-flex;
				align-items: center;
				gap: 7px;
				padding: 4px 10px;
				font-size: 12px;
				background: var(--mw-surface-2);
				border: 1px solid var(--mw-line);
				border-radius: 999px;
			}
			.mwan4-meta-key {
				color: var(--mw-muted);
			}

			/* ---- 概况砖 ---- */
			.mwan4-summary {
				display: flex;
				flex-wrap: wrap;
				gap: 10px;
				margin-bottom: 16px;
			}
			.mwan4-tile {
				flex: 1 1 170px;
				display: flex;
				flex-direction: column;
				gap: 3px;
				padding: 10px 14px;
				background: var(--mw-surface);
				border: 1px solid var(--mw-line);
				border-radius: var(--mw-radius);
			}
			.mwan4-tile-key {
				font-size: 11.5px;
				color: var(--mw-muted);
			}
			.mwan4-tile-val {
				display: inline-flex;
				align-items: center;
				gap: 8px;
				font-size: 17px;
				font-weight: 650;
				color: var(--mw-fg);
				font-variant-numeric: tabular-nums;
			}

			/* ---- 卡片 ---- */
			.mwan4-cards-grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
				gap: 14px;
				margin-bottom: 24px;
			}
			.mwan4-card {
				margin: 0 !important;
				padding: 16px 18px !important;
				background: var(--mw-surface) !important;
				border: 1px solid var(--mw-line) !important;
				border-left: 3px solid var(--mw-ok) !important;
				border-radius: var(--mw-radius) !important;
				box-shadow: none !important;
				color: var(--mw-fg) !important;
				transition: box-shadow .15s ease, border-color .15s ease;
			}
			.mwan4-card:hover {
				box-shadow: 0 4px 16px rgba(0, 0, 0, 0.09) !important;
			}
			.mwan4-card-down     { border-left-color: var(--mw-bad) !important; }
			.mwan4-card-degraded { border-left-color: var(--mw-warn) !important; }
			.mwan4-card-local    { border-left-color: var(--mw-warn) !important; }
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
				align-items: baseline;
				gap: 8px;
				min-width: 0;
				overflow: hidden;
				white-space: nowrap;
			}
			.mwan4-card-title {
				font-size: 15px;
				font-weight: 650;
				color: var(--mw-fg);
			}
			.mwan4-card-ip {
				color: var(--mw-muted);
				font-size: 12px;
				font-family: monospace;
				overflow: hidden;
				text-overflow: ellipsis;
			}
			.mwan4-badge-state {
				padding: 3px 9px;
				border-radius: 999px;
				background: var(--mw-surface-2);
				font-size: 11.5px;
			}
			.mwan4-card-alert {
				margin: 0 0 10px 0;
				padding: 6px 9px;
				border-radius: 4px;
				background: var(--mw-surface-2);
				border-left: 3px solid var(--mw-warn);
				color: var(--mw-muted);
				font-size: 11.5px;
				line-height: 1.45;
				word-break: break-word;
			}
			.mwan4-card-stale .mwan4-card-alert {
				border-left-color: var(--mw-bad);
			}

			.mwan4-stats-grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
				gap: 12px 14px;
				margin-bottom: 10px;
			}
			.mwan4-stat-item {
				display: flex;
				flex-direction: column;
				min-width: 0;
			}
			.mwan4-stat-wide {
				grid-column: 1 / -1;
			}
			.mwan4-stat-label {
				color: var(--mw-muted);
				font-size: 11.5px;
				margin-bottom: 3px;
			}
			.mwan4-stat-val {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				font-size: 15px;
				font-weight: 600;
				color: var(--mw-fg);
				font-variant-numeric: tabular-nums;
				min-width: 0;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.mwan4-mono {
				font-family: monospace;
				font-size: 13px;
				font-weight: 500;
			}
			.mwan4-tile-val.mwan4-mono {
				font-size: 15px;
			}

			/* ---- RTT 趋势 ---- */
			.mwan4-trend-wrap {
				margin: 10px 0 2px 0;
			}
			.mwan4-trend-label {
				display: block;
				font-size: 11.5px;
				color: var(--mw-muted);
				margin-bottom: 4px;
			}
			.mwan4-trend {
				display: flex;
				align-items: flex-end;
				gap: 1px;
				height: 34px;
				border-bottom: 1px solid var(--mw-line);
			}
			.mwan4-trend-bar {
				flex: 1 1 0;
				min-width: 0;
				height: 0;
				border-radius: 1px 1px 0 0;
				background: var(--mw-muted);
				opacity: .35;
				transition: height .35s ease;
			}
			.mwan4-trend-bar.ok   { background: var(--mw-ok); opacity: .8; }
			.mwan4-trend-bar.warn { background: var(--mw-warn); opacity: .9; }
			.mwan4-trend-bar.bad  { background: var(--mw-bad); opacity: .9; }
			.mwan4-trend-bar.empty { background: var(--mw-line-strong); opacity: .25; }

			/* ---- 丢包条 ---- */
			.mwan4-loss-section {
				margin-top: 12px;
			}
			.mwan4-loss-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				font-size: 11.5px;
				color: var(--mw-muted);
				margin-bottom: 6px;
			}
			.mwan4-meter {
				width: 100%;
				height: 5px;
				background: var(--mw-track);
				border-radius: 3px;
				overflow: hidden;
			}
			.mwan4-meter-fill {
				display: block;
				height: 100%;
				border-radius: 3px;
				background: var(--mw-muted);
				transition: width .3s ease;
			}
			.mwan4-meter-fill.ok   { background: var(--mw-ok); }
			.mwan4-meter-fill.warn { background: var(--mw-warn); }
			.mwan4-meter-fill.bad  { background: var(--mw-bad); }

			.mwan4-card-footer {
				margin-top: 12px;
				padding-top: 10px;
				border-top: 1px solid var(--mw-line);
				display: flex;
				flex-wrap: wrap;
				gap: 8px;
			}
			.mwan4-chip {
				padding: 2px 8px;
				border-radius: 999px;
				background: var(--mw-surface-2);
				border: 1px solid var(--mw-line);
				font-size: 11px;
				color: var(--mw-muted);
				font-variant-numeric: tabular-nums;
			}

			.mwan4-empty {
				grid-column: 1 / -1;
				padding: 18px 16px;
				border: 1px dashed var(--mw-line);
				border-radius: var(--mw-radius);
				color: var(--mw-muted);
				font-size: 13px;
				text-align: center;
			}

			/* ---- WAN Interfaces / Policy 表格 ---- */
			.mwan4-view .cbi-section-node {
				overflow-x: auto;
			}
			.mwan4-view table.cbi-section-table {
				table-layout: auto;
				width: 100%;
			}
			.mwan4-view table.cbi-section-table th,
			.mwan4-view table.cbi-section-table td {
				padding: 3px 6px !important;
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
				min-height: 24px !important;
				padding: 2px 6px !important;
				font-size: 12.5px !important;
				border-radius: 3px !important;
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
				padding: 2px 8px !important;
				font-size: 12px !important;
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
			}

			/* 滚动条跟随主题，且只作用在本页 */
			.mwan4-view * {
				scrollbar-width: thin;
				scrollbar-color: var(--mw-line-strong) transparent;
			}
			.mwan4-view ::-webkit-scrollbar { width: 10px; height: 10px; }
			.mwan4-view ::-webkit-scrollbar-track { background: transparent; }
			.mwan4-view ::-webkit-scrollbar-thumb {
				background: var(--mw-line-strong);
				border-radius: 5px;
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
		// 与 LuCI 全域预设一致的 5 秒轮询（daemon 每秒写一次状态档）
		poll.add(this.pollFn, 5);

		m = new form.Map('mwan4', _('MWAN4 Configuration'));

		s = m.section(form.NamedSection, 'global', 'global', _('Global Settings'));
		s.tab('basic', _('Basic'));
		s.tab('dns', _('DNS'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('basic', form.Flag, 'enabled', _('Enable MWAN4 Daemon'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('basic', form.ListValue, 'ecmp_mode', _('Multi-WAN Routing Mode'));
		o.value('auto', _('Automatic (resilient when supported)'));
		o.value('standard', _('Standard ECMP (multipath route)'));
		o.value('resilient', _('Resilient nexthop group (require kernel support)'));
		o.default = 'auto';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'check_interval_ms', _('Probe Interval (ms)'));
		o.datatype = 'uinteger';
		o.default = '500';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'probe_timeout_ms', _('Probe Timeout (ms)'));
		o.datatype = 'uinteger';
		o.default = '400';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'consecutive_fail_down', _('Consecutive Failures for DOWN'));
		o.datatype = 'uinteger';
		o.default = '3';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'recovery_success_count', _('Recovery Success Count (Hysteresis)'));
		o.datatype = 'uinteger';
		o.default = '5';
		o.rmempty = false;

		o = s.taboption('dns', form.ListValue, 'probe_mode', _('Health Probe Protocol'));
		o.value('tcp', _('TCP SYN (default)'));
		o.value('dns', _('DNS Query (UDP)'));
		o.default = 'tcp';
		o.rmempty = false;

		o = s.taboption('dns', form.Value, 'dns_probe_domain', _('DNS Probe Domain'));
		o.default = 'baidu.com';
		o.placeholder = 'baidu.com';
		o.depends('probe_mode', 'dns');

		o = s.taboption('dns', form.Value, 'dns_listen_port', _('DNS Forward Port (0 = Off)'));
		o.datatype = 'range(0,65535)';
		o.default = '0';
		o.placeholder = '5354';
		o.rmempty = false;

		o = s.taboption('dns', form.Value, 'dns_listen_addr', _('DNS Listen Address'));
		o.datatype = 'ipaddr';
		o.default = '127.0.0.1';
		o.placeholder = '127.0.0.1';

		o = s.taboption('dns', form.Value, 'dns_forward_timeout_ms', _('DNS Forward Timeout (ms)'));
		o.datatype = 'range(100,15000)';
		o.default = '2000';

		o = s.taboption('dns', form.Value, 'dns_resolv_file', _('Healthy DNS Export File (Optional)'));
		o.placeholder = '/tmp/mwan4_resolv.conf';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'window_size', _('Sliding Window Size'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'loss_threshold_down', _('Packet Loss Threshold for DOWN'));
		o.default = '0.5';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'max_rtt_ms', _('Maximum Allowed RTT (ms)'));
		o.default = '1500';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'degrade_loss_threshold', _('Degrade Loss Threshold'));
		o.default = '0.2';
		o.rmempty = false;

		o = s.taboption('advanced', form.ListValue, 'multipath_hash_policy', _('Multipath Hash Policy'));
		o.value('l4', _('L4 (addresses + ports, the default)'));
		o.value('l3', _('L3 (addresses only)'));
		o.value('inner', _('L3 + tunnel inner headers'));
		o.default = 'l4';
		o.rmempty = false;

		o = s.taboption('advanced', form.ListValue, 'weight_mode', _('ECMP Weight Mode'));
		o.value('static', _('Static (configured weights)'));
		o.value('quality', _('Quality-aware (dynamic)'));
		o.value('aggregate', _('Aggregate spreading (headroom-aware)'));
		o.default = 'static';
		o.rmempty = false;

		o = s.taboption('advanced', form.Flag, 'load_aware', _('Load-aware Traffic Shifting'));
		o.default = o.disabled;

		o = s.taboption('advanced', form.Value, 'dynamic_weight_interval_ms',
			_('Dynamic Weight Update Interval (ms)'));
		o.datatype = 'uinteger';
		o.default = '10000';
		o.depends('weight_mode', 'quality');
		o.depends('weight_mode', 'aggregate');
		o.depends('load_aware', '1');

		o = s.taboption('advanced', form.Flag, 'allow_dynamic_weights_on_standard',
			_('Allow Dynamic Weights on Standard ECMP'));
		o.default = o.disabled;
		o.depends('ecmp_mode', 'standard');

		o = s.taboption('advanced', form.Flag, 'flush_conntrack', _('Flush Conntrack on DOWN'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.Flag, 'flush_conntrack_on_switch', _('Flush Conntrack on Active Set Change'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.Flag, 'remove_routes_on_exit', _('Remove Default Route on Exit'));
		o.default = o.disabled;

		s = m.section(form.GridSection, 'interface', _('WAN Interfaces'));
		s.addremove = true;
		s.anonymous = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Interface Name'));
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

		o = s.option(form.Value, 'gateway', _('Gateway IP'));
		o.datatype = 'ip4addr';
		o.placeholder = '0.0.0.0';
		o.rmempty = true;
		o.editable = true;

		o = s.option(form.Value, 'gateway6', _('IPv6 Gateway'));
		o.datatype = 'ip6addr';
		o.rmempty = true;
		o.modalonly = true;

		o = s.option(form.Value, 'metric', _('Metric (Priority)'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.editable = true;

		o = s.option(form.Value, 'weight', _('ECMP Weight'));
		o.datatype = 'uinteger';
		o.default = '1';
		o.editable = true;

		o = s.option(form.Value, 'max_mbps', _('Max Bandwidth (Mbps)'));
		o.datatype = 'ufloat';
		o.editable = true;

		o = s.option(form.Value, 'up_mbps', _('Up Capacity (Mbps)'));
		o.datatype = 'ufloat';
		o.modalonly = true;

		o = s.option(form.ListValue, 'probe_mode', _('Probe Protocol Override'));
		o.value('', _('Inherit global setting'));
		o.value('tcp', _('TCP SYN (default)'));
		o.value('dns', _('DNS Query (UDP)'));
		o.rmempty = true;
		o.modalonly = true;

		o = s.option(form.DynamicList, 'probe_targets', _('Probe Targets (IP:Port)'));
		o.datatype = 'ipaddrport(1)';
		o.default = ['223.5.5.5:53', '114.114.114.114:53'];

		o = s.option(form.DynamicList, 'dns_servers', _('Upstream DNS (IP[:Port])'));
		o.placeholder = '202.96.128.86';
		o.validate = validateDnsServer;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'underlay_targets', _('Tunnel Underlay Peers (IPv4)'));
		o.datatype = 'ip4addr';
		o.rmempty = true;
		o.modalonly = true;

		s = m.section(form.GridSection, 'policy', _('Policy Routing (Source / Destination)'));
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;

		o = s.option(form.Value, 'name', _('Rule Name'));
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.DynamicList, 'source', _('Source Prefixes (CIDR)'));
		o.datatype = 'cidr4';
		o.placeholder = '192.168.3.0/24';
		o.editable = true;

		o = s.option(form.DynamicList, 'destination', _('Destination Prefixes (CIDR)'));
		o.datatype = 'cidr4';
		o.editable = true;

		o = s.option(form.ListValue, 'interface', _('Target WAN'));
		o.rmempty = false;
		o.editable = true;
		uci.sections('mwan4', 'interface').forEach(function(sec) {
			var wanName = sec.name || sec['.name'];
			if (wanName) o.value(wanName, wanName);
		});

		o = s.option(form.Value, 'priority', _('Rule Priority'));
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
