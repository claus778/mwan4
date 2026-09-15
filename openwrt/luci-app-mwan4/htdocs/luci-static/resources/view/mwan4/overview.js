'use strict';
'require view';
'require fs';
'require uci';
'require ui';
'require form';
'require poll';

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

/* 內核設備名清單：daemon 用 SO_BINDTODEVICE + if_nametoindex 都需要「內核設備名」，
   而 UCI 裏的 network interface 是邏輯名（wan/wanb…），兩者經常不同名。
   橋接（br-*）是 LAN 側，當 WAN 用幾乎一定是選錯了，這裡直接排除。 */
function listNetdevs() {
	return fs.list('/sys/class/net').then(function(list) {
		return (list || []).filter(function(name) {
			return name !== 'lo' && name.indexOf('br-') !== 0;
		});
	}).catch(function() {
		return [];
	});
}

/* 狀態檔新鮮度：卡片與徽章都必須據此判斷，否則 daemon 被殺掉之後
   最後一次快照（可能剛好是兩條 DOWN）會被當成即時狀態一直顯示。
   回傳 'fresh' | 'stale' | 'skew' | 'missing' */
function freshnessOf(statusData) {
	if (!statusData || !statusData.updated_at)
		return 'missing';
	var staleAfter = statusData.stale_after_secs || 10;
	var age = Date.now() / 1000 - statusData.updated_at;
	if (age > staleAfter)
		return 'stale';
	// 路由器時鐘超前瀏覽器太多時無法斷定「還在跑」還是「時鐘不同步」；
	// 這種情況一律當作「不可信」處理（卡片同樣標成陳舊），不要假裝新鮮
	if (age < -staleAfter)
		return 'skew';
	return 'fresh';
}

/* status dot */
function dot(level, role) {
	var attr = { 'class': 'mwan4-dot ' + (level || 'muted') };
	if (role) attr['data-role'] = role;
	return E('i', attr);
}

/* ok / warn / bad */
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

function stateText(up) { return up ? _('Online (UP)') : _('Offline (DOWN)'); }

/* 卡片提示：資料不可信 > 本機條件錯誤 > 一般探針錯誤 */
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
	return '';
}

/* 狀態檔年齡（人看得懂的形式）；時鐘嚴重不同步時明說，不要瞎報秒數 */
function statusAgeText(statusData) {
	if (!statusData || !statusData.updated_at)
		return _('missing');
	var staleAfter = statusData.stale_after_secs || 10;
	var age = Date.now() / 1000 - statusData.updated_at;
	if (age < -staleAfter)
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

function rttText(iface) { return iface.state === 'UP' ? iface.rtt_ms.toFixed(1) + ' ms' : '--'; }
function jitterText(iface) { return iface.state === 'UP' ? iface.jitter_ms.toFixed(1) + ' ms' : '--'; }
function lossText(iface) { return (iface.loss_rate || 0).toFixed(1) + '%'; }
function pwText(iface) { return (iface.metric ? ('P:' + iface.metric + ' / ') : '') + 'W:' + iface.weight; }
function succText(iface) { return _('Consecutive Successes: ') + iface.consecutive_successes; }
function toText(iface) { return _('Consecutive Timeouts: ') + iface.consecutive_timeouts; }

/* write only when the value really changed, so text selection survives the poll */
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

/* LuCI's description row lacks the leading name cell the title row has, and
   themes may add a ::before ghost cell to the title/data rows but not to the
   description row; both shift every hint to the left. Pad until the first
   description cell lines up with the first title cell, retrying while the
   form is not attached/laid out yet (rects are all zero then). */
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

	renderStatusHeader: function(statusData) {
		var fresh = freshnessOf(statusData);
		var ri = routeInfo(statusData);

		return E('div', { 'id': 'mwan4_header_container', 'class': 'mwan4-header' }, [
			E('h3', { 'class': 'mwan4-title' }, _('MWAN4 Multi-WAN Failover & Health Monitor')),
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
				])
			])
		]);
	},

	renderCard: function(iface, fresh) {
		var up = iface.state === 'UP';
		var loss = iface.loss_rate || 0;
		// 首帧就要用真正的新鮮度，否則載入一個陳舊快照時第一眼會是「即時狀態」
		var trust = fresh || 'fresh';
		var alert = cardAlert(iface, trust);
		var stale = (trust === 'stale' || trust === 'skew' || trust === 'missing');

		return E('div', {
			'class': 'mwan4-card' + (stale ? ' mwan4-card-stale' : '') +
				(iface.local_condition ? ' mwan4-card-local' : ''),
			'data-iface': iface.name
		}, [
			E('div', { 'class': 'mwan4-card-head' }, [
				E('div', { 'class': 'mwan4-card-id' }, [
					E('span', { 'class': 'mwan4-card-title' }, iface.name),
					E('span', { 'class': 'mwan4-card-ip' }, iface.ip ? '(' + iface.ip + ')' : _('(No IP)'))
				]),
				E('span', { 'class': 'mwan4-badge' }, [
					dot(up ? 'ok' : 'bad', 'state-dot'),
					E('span', { 'data-role': 'state-text' }, stateText(up))
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
				])
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
				E('span', { 'data-role': 'succ' }, succText(iface)),
				E('span', { 'data-role': 'to' }, toText(iface))
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
		var stale = (fresh === 'stale' || fresh === 'skew');

		setText(pick(card, 'state-text'), stateText(up));
		setCls(pick(card, 'state-dot'), 'mwan4-dot ' + (up ? 'ok' : 'bad'));

		// 過期／本機條件錯誤一律標在卡片上：不要讓「最後一次快照」偽裝成即時狀態
		var alert = cardAlert(iface, fresh);
		var alertEl = pick(card, 'alert');
		if (alertEl) {
			setText(alertEl, alert);
			var display = alert ? '' : 'none';
			if (alertEl.style.display !== display) alertEl.style.display = display;
		}
		setCls(card, 'mwan4-card' + (stale ? ' mwan4-card-stale' : '') +
			(iface.local_condition ? ' mwan4-card-local' : ''));

		setText(pick(card, 'rtt'), rttText(iface));
		setCls(pick(card, 'rtt-dot'), 'mwan4-dot ' + (up ? rttLevel(iface.rtt_ms) : 'muted'));
		setText(pick(card, 'jitter'), jitterText(iface));
		setText(pick(card, 'gw'), iface.gateway);
		setText(pick(card, 'pw'), pwText(iface));

		setText(pick(card, 'loss'), lossText(iface));
		setCls(pick(card, 'loss-dot'), 'mwan4-dot ' + lLevel);
		setCls(pick(card, 'meter'), 'mwan4-meter-fill ' + lLevel);
		setW(pick(card, 'meter'), Math.min(100, Math.max(0, loss)) + '%');

		setText(pick(card, 'succ'), succText(iface));
		setText(pick(card, 'to'), toText(iface));
	},

	applyStatus: function(statusData) {
		var fresh = freshnessOf(statusData);
		var header = document.getElementById('mwan4_header_container');
		if (header) {
			var ri = routeInfo(statusData);
			setText(pick(header, 'run-text'), runText(fresh));
			setCls(pick(header, 'run-dot'), 'mwan4-dot ' + runLevel(fresh));
			setText(pick(header, 'route-text'), ri.text);
			setCls(pick(header, 'route-dot'), 'mwan4-dot ' + ri.level);
			setText(pick(header, 'age-text'), statusAgeText(statusData));
		}

		var container = document.getElementById('mwan4_cards_container');
		if (!container || !container.parentNode) return;

		var list = (statusData && statusData.interfaces) ? statusData.interfaces : [];
		var sig = list.map(function(iface) { return iface.name; }).join(',');

		// Only rebuild when the interface set itself changed; otherwise patch values in place.
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
		// LuCI views have no teardown hook, so let the poll detach itself: once this
		// view is no longer in the document it is dropped from the poll queue.
		// Allow a couple of ticks of grace for the async render to finish inserting
		// the view root (poll.add() runs before the form promise resolves); without
		// it, leaving the page within that window would leak both the poll entry
		// and the whole detached DOM forever.
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
				--mw-fg: #333333;
				--mw-muted: #8a8f98;
				--mw-line: rgba(0, 0, 0, 0.10);
				--mw-surface: rgba(0, 0, 0, 0.015);
				--mw-track: rgba(0, 0, 0, 0.07);
				--mw-ok: #35a06a;
				--mw-warn: #c9821f;
				--mw-bad: #cf4436;
				--mw-info: #5b7fb9;
			}

			@media (prefers-color-scheme: dark) {
				.mwan4-view {
					--mw-fg: #d4d4d4;
					--mw-muted: #8b8f96;
					--mw-line: rgba(255, 255, 255, 0.12);
					--mw-surface: rgba(255, 255, 255, 0.025);
					--mw-track: rgba(255, 255, 255, 0.10);
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
				--mw-fg: #d4d4d4 !important;
				--mw-muted: #8b8f96 !important;
				--mw-line: rgba(255, 255, 255, 0.12) !important;
				--mw-surface: rgba(255, 255, 255, 0.025) !important;
				--mw-track: rgba(255, 255, 255, 0.10) !important;
				--mw-ok: #4cb87c !important;
				--mw-warn: #d69a3a !important;
				--mw-bad: #e0685a !important;
				--mw-info: #7d9fd0 !important;
			}

			/* ---- dot ---- */
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

			/* ---- badge ---- */
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

			/* ---- header ---- */
			.mwan4-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				flex-wrap: wrap;
				gap: 12px 24px;
				padding: 0 0 14px 0;
				margin-bottom: 18px;
				border-bottom: 1px solid var(--mw-line);
			}
			.mwan4-title {
				margin: 0;
				font-size: 15px;
				font-weight: 600;
				color: var(--mw-fg);
			}
			.mwan4-meta {
				display: flex;
				align-items: center;
				flex-wrap: wrap;
				gap: 8px 22px;
			}
			.mwan4-meta-item {
				display: inline-flex;
				align-items: center;
				gap: 7px;
				font-size: 12.5px;
			}
			.mwan4-meta-key {
				color: var(--mw-muted);
			}

			/* ---- cards ---- */
			.mwan4-cards-grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
				gap: 14px;
				margin-bottom: 24px;
			}

			.mwan4-card {
				margin: 0 !important;
				padding: 16px !important;
				background: var(--mw-surface) !important;
				border: 1px solid var(--mw-line) !important;
				border-radius: 6px !important;
				box-shadow: none !important;
				color: var(--mw-fg) !important;
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
				min-width: 0;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.mwan4-card-title {
				font-size: 15px;
				font-weight: 600;
				color: var(--mw-fg);
				margin-right: 8px;
			}
			.mwan4-card-ip {
				color: var(--mw-muted);
				font-size: 12.5px;
				font-family: monospace;
			}

			/* 資料過期：虛線 + 淡化，避免「最後一次快照」被當成即時狀態 */
			.mwan4-card-stale {
				border-style: dashed !important;
				opacity: .75;
			}
			.mwan4-card-local {
				border-color: var(--mw-warn) !important;
			}
			.mwan4-card-alert {
				display: block;
				margin: 0 0 10px 0;
				padding: 6px 8px;
				border-radius: 4px;
				background: var(--mw-surface);
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
				grid-template-columns: 1fr 1fr;
				gap: 12px;
				margin-bottom: 12px;
			}
			.mwan4-stat-item {
				display: flex;
				flex-direction: column;
				min-width: 0;
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
			}
			.mwan4-mono {
				font-family: monospace;
				font-size: 13.5px;
				font-weight: 500;
			}

			/* ---- loss meter ---- */
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
				height: 3px;
				background: var(--mw-track);
				border-radius: 2px;
				overflow: hidden;
			}
			.mwan4-meter-fill {
				display: block;
				height: 100%;
				border-radius: 2px;
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
				font-size: 11.5px;
				color: var(--mw-muted);
				display: flex;
				justify-content: space-between;
				gap: 10px;
			}

			/* ---- empty state ---- */
			.mwan4-empty {
				grid-column: 1 / -1;
				padding: 18px 16px;
				border: 1px dashed var(--mw-line);
				border-radius: 6px;
				background: transparent;
				color: var(--mw-muted);
				font-size: 13px;
				text-align: center;
			}

			/* ---- WAN Interfaces grid: tighter rows, no sideways overflow ---- */
			.mwan4-view table.cbi-section-table {
				table-layout: fixed;
				width: 100%;
			}
			.mwan4-view table.cbi-section-table th,
			.mwan4-view table.cbi-section-table td {
				padding: 3px 6px !important;
				font-size: 12.5px !important;
				line-height: 1.35 !important;
				vertical-align: middle !important;
			}
			/* 8 columns: Name | Enable | Interface | Gateway | Metric | Weight | Targets | actions */
			.mwan4-view table.cbi-section-table th:nth-child(1) { width: 12%; }
			.mwan4-view table.cbi-section-table th:nth-child(2) { width: 6%; }
			.mwan4-view table.cbi-section-table th:nth-child(3) { width: 13%; }
			.mwan4-view table.cbi-section-table th:nth-child(4) { width: 14%; }
			.mwan4-view table.cbi-section-table th:nth-child(5) { width: 9%; }
			.mwan4-view table.cbi-section-table th:nth-child(6) { width: 9%; }
			.mwan4-view table.cbi-section-table th:nth-child(7) { width: 25%; }
			/* description row: LuCI renders it one cell short, alignDescrRows() pads it */
			.mwan4-view table.cbi-section-table tr.cbi-section-table-descr th {
				font-size: 11px !important;
				font-weight: 400 !important;
				color: var(--mw-muted) !important;
				padding-top: 0 !important;
				text-align: left;
				/* the theme sets nowrap on th, which makes long hints overlap */
				white-space: normal !important;
				overflow: hidden !important;
				word-break: break-word;
			}
			/* the page is static except the probe numbers, so let text stay selectable */
			.mwan4-view .mwan4-header,
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
			/* ---- Interface Name field: keep the box short (table cell + add form) ---- */
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

			/* ---- scrollbar: system default, not the themed purple pill ---- */
			:root {
				--mw-sb-track: #f1f1f1;
				--mw-sb-thumb: #c1c1c1;
				--mw-sb-thumb-hover: #a8a8a8;
			}

			@media (prefers-color-scheme: dark) {
				:root {
					--mw-sb-track: #262626;
					--mw-sb-thumb: #5a5a5a;
					--mw-sb-thumb-hover: #6e6e6e;
				}
			}

			html[data-darkmode="true"],
			html[data-theme="dark"] {
				--mw-sb-track: #262626 !important;
				--mw-sb-thumb: #5a5a5a !important;
				--mw-sb-thumb-hover: #6e6e6e !important;
			}

			html, body, .mwan4-view, .mwan4-view * {
				scrollbar-width: auto !important;
				scrollbar-color: var(--mw-sb-thumb) var(--mw-sb-track) !important;
			}

			::-webkit-scrollbar {
				width: 15px !important;
				height: 15px !important;
				background: var(--mw-sb-track) !important;
			}
			::-webkit-scrollbar-track,
			::-webkit-scrollbar-corner {
				background: var(--mw-sb-track) !important;
				border: 0 !important;
				border-radius: 0 !important;
				box-shadow: none !important;
			}
			::-webkit-scrollbar-thumb {
				background: var(--mw-sb-thumb) !important;
				border: 3px solid var(--mw-sb-track) !important;
				border-radius: 0 !important;
				box-shadow: none !important;
			}
			::-webkit-scrollbar-thumb:hover {
				background: var(--mw-sb-thumb-hover) !important;
			}
			::-webkit-scrollbar-button {
				display: none !important;
			}
		`);

		var viewRoot = E('div', { 'class': 'mwan4-view' }, [
			styleNode,
			this.renderStatusHeader(statusData),
			this.cardsContainer(statusData)
		]);

		// poll.remove() compares function references, so keep the bound handler.
		this.viewRoot = viewRoot;
		this.pollMisses = 0;
		this.pollFn = this.updateDashboard.bind(this);
		// 與 LuCI 全域預設一致的 5 秒輪詢：守護進程每秒寫一次狀態檔，
		// 2 秒一拉的頻率對低配路由器上的 uhttpd/rpcd 是純粹的常駐開銷
		poll.add(this.pollFn, 5);

		// Configuration form
		m = new form.Map('mwan4', _('MWAN4 Configuration'), _('Multi-WAN interfaces and health probes via UCI. Save & Apply reloads the daemon.'));

		// Global settings
		s = m.section(form.NamedSection, 'global', 'global', _('Global Settings'));

		o = s.option(form.Flag, 'enabled', _('Enable MWAN4 Daemon'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'check_interval_ms', _('Probe Interval (ms)'), _('Probe interval per interface (default: 500 ms)'));
		o.datatype = 'uinteger';
		o.default = '500';
		o.rmempty = false;

		o = s.option(form.Value, 'probe_timeout_ms', _('Probe Timeout (ms)'), _('Unanswered probe is considered lost after this duration (default: 400ms, must not exceed the probe interval)'));
		o.datatype = 'uinteger';
		o.default = '400';
		o.rmempty = false;

		o = s.option(form.Value, 'window_size', _('Sliding Window Size'), _('Number of probe samples to calculate loss rate and smoothed RTT (default: 10)'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.rmempty = false;

		o = s.option(form.Value, 'consecutive_fail_down', _('Consecutive Failures for DOWN'), _('Consecutive probe timeouts before interface is marked DOWN (default: 3)'));
		o.datatype = 'uinteger';
		o.default = '3';
		o.rmempty = false;

		o = s.option(form.Value, 'recovery_success_count', _('Recovery Success Count (Hysteresis)'), _('Consecutive successful probes required before recovering to UP. The sliding-window loss rate must also stay at or below the recovery loss threshold (default 0.10).'));
		o.datatype = 'uinteger';
		o.default = '5';
		o.rmempty = false;

		o = s.option(form.Value, 'loss_threshold_up', _('Recovery Loss Threshold'), _('Sliding-window loss rate must be AT OR BELOW this value to recover (default 0.10 = 10%). Raise it if a jittery line recovers too slowly.'));
		o.default = '0.1';
		o.rmempty = false;

		o = s.option(form.Flag, 'flush_conntrack', _('Flush Conntrack on DOWN'), _('Flush TCP/UDP connections on an interface when it goes down.'));
		o.default = o.enabled;

		o = s.option(form.Flag, 'flush_conntrack_on_switch', _('Flush Conntrack on Active Set Change'), _('Standard ECMP only: when the set of active WANs changes, the kernel rehashes multipath and existing flows may move. In primary/backup mode only the newly entered WAN is flushed, so a recovering primary no longer resets healthy backup connections.'));
		o.default = o.enabled;

		o = s.option(form.Flag, 'remove_routes_on_exit', _('Remove Default Route on Exit'), _('Leave disabled (recommended). Removing the default route on stop/restart leaves the whole router without an exit while the new instance starts, and cannot recover if that instance fails.'));
		o.default = o.disabled;

		o = s.option(form.ListValue, 'ecmp_mode', _('Multi-WAN Routing Mode'), _('standard keeps a single multipath route, so link changes rehash and may drop existing connections. resilient remaps only the failed links (Linux 5.14+).'));
		o.value('standard', _('Standard ECMP (multipath route)'));
		o.value('auto', _('Automatic (resilient when supported)'));
		o.value('resilient', _('Resilient nexthop group (require kernel support)'));
		o.default = 'standard';
		o.rmempty = false;

		// WAN interface list
		s = m.section(form.GridSection, 'interface', _('WAN Interfaces'), _('Gateway, ECMP weight and probe targets for each WAN interface.'));
		s.addremove = true;
		s.anonymous = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Interface Name'), _('KERNEL device name (e.g. eth1, vxlan, pppoe-wan), not the UCI network name. The daemon resolves it with if_nametoindex() and binds probes with SO_BINDTODEVICE; a UCI logical name (wan/wanb…) never works and shows up as a permanently offline card.'));
		o.rmempty = false;
		o.editable = true;
		// 候選值優先給「內核設備名」（/sys/class/net）；取不到才退回 UCI 邏輯名，
		// 但上面的說明已經明確警告兩者不同名
		if (netdevs.length) {
			netdevs.forEach(function(dev) {
				o.value(dev);
			});
		} else {
			var netSections = uci.sections('network', 'interface');
			netSections.forEach(function(sec) {
				if (sec['.name'] && sec['.name'] !== 'loopback' && sec['.name'] !== 'lan') {
					o.value(sec['.name']);
				}
			});
		}

		o = s.option(form.Value, 'gateway', _('Gateway IP'));
		o.datatype = 'ip4addr';
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'metric', _('Metric (Priority)'), _('Lower = higher priority. Same metric = ECMP aggregation, different metrics = primary/backup failover.'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.editable = true;

		o = s.option(form.Value, 'weight', _('ECMP Weight'), _('ECMP weight for interfaces with the same metric.'));
		o.datatype = 'uinteger';
		o.default = '1';
		o.editable = true;

		o = s.option(form.DynamicList, 'probe_targets', _('Probe Targets (IP:Port)'));
		o.datatype = 'ipaddrport(1)';
		o.default = ['1.1.1.1:443', '8.8.8.8:443'];

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
