// SPDX-License-Identifier: GPL-2.0-only
/*
 * mwan4_sched - Lightweight per-flow load-balancing scheduler for MWAN4
 *
 * Design:
 *   - Control plane (userspace mwan4 daemon) writes active WAN list, weights,
 *     capacities, RTT/loss metrics and fwmark values to /proc/net/mwan4_sched.
 *   - A 200ms workqueue samples true NIC RX/TX byte counters via dev_get_stats()
 *     (100% accurate even when Software/Hardware Flow Offload is enabled) and
 *     computes smoothed per-WAN utilization in permille (integer math only).
 *   - A single NF_INET_PRE_ROUTING hook intercepts IP_CT_NEW outbound flows
 *     (skipping WAN ingress, LAN/private/multicast destinations, and already
 *     marked packets) and picks the optimal WAN using:
 *       1) Latency-sensitive fast lane (ICMP/DNS/SSH/NTP/VoIP -> lowest RTT)
 *       2) Hybrid Least-Utilization + Weighted Flow-Burst Deficit (guarantees
 *          exact proportional spreading even when N concurrent flows start
 *          simultaneously before byte counters move)
 *   - The chosen fwmark is stored in ct->mark and skb->mark; subsequent packets
 *     of the flow reuse ct->mark (and can enter Flow Offload), while dead-WAN
 *     marks are automatically cleared on failover.
 */

#include <linux/atomic.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>

#define MWAN4_SCHED_VERSION	"1.0.0"
#define MWAN4_MAX_WANS		16
#define MWAN4_SAMPLE_MS		200
#define MWAN4_DEFAULT_MASK	0x00FF0000U
#define MWAN4_CMD_MAX_LEN	4096

enum mwan4_sched_mode {
	MWAN4_MODE_OFF = 0,
	MWAN4_MODE_BALANCED = 1,   /* Hybrid real-time utilization + weighted flow burst */
	MWAN4_MODE_LATENCY = 2,    /* Prefer lowest RTT unless heavily loaded */
};

struct mwan4_wan {
	char name[IFNAMSIZ];
	int ifindex;
	struct net_device *dev;
	u32 fwmark;         /* Already masked with mark_mask */
	u32 weight;         /* >= 1 */
	u64 down_bps_cap;   /* 0 = unknown */
	u64 up_bps_cap;     /* 0 = unknown */
	u32 rtt_us;         /* From mwan4 LQE */
	u32 loss_pm;        /* Packet loss in permille (0..1000) */
	u8 degraded;

	/* Updated by 200ms workqueue, read locklessly in NF hook */
	u64 last_rx_bytes;
	u64 last_tx_bytes;
	bool stats_valid;
	u64 rx_bps_ewma;
	u64 tx_bps_ewma;
	u32 util_pm;        /* Max(rx, tx) utilization in permille (0..2000+) */

	/* Burst flow counter: incremented on IP_CT_NEW, halved every 200ms */
	atomic_t burst_flows;
	atomic64_t total_flows;
};

struct mwan4_sched_cfg {
	struct rcu_head rcu;
	u32 mode;
	u32 mark_mask;
	u32 latency_fastlane; /* 1 = steer ICMP/DNS/SSH/NTP/VoIP to lowest-RTT WAN */
	u32 wan_count;
	u32 min_rtt_us;
	struct mwan4_wan wans[MWAN4_MAX_WANS];
};

static struct mwan4_sched_cfg __rcu *g_cfg;
static DEFINE_MUTEX(g_cfg_lock);
static struct delayed_work g_sample_work;
static struct proc_dir_entry *g_proc_entry;
static atomic64_t g_stat_new_flows = ATOMIC64_INIT(0);
static atomic64_t g_stat_sticky_hits = ATOMIC64_INIT(0);
static atomic64_t g_stat_failover_reselects = ATOMIC64_INIT(0);
static atomic64_t g_stat_fastlane_hits = ATOMIC64_INIT(0);

static void mwan4_cfg_free_rcu(struct rcu_head *head)
{
	struct mwan4_sched_cfg *cfg = container_of(head, struct mwan4_sched_cfg, rcu);
	u32 i;

	for (i = 0; i < cfg->wan_count; i++) {
		if (cfg->wans[i].dev)
			dev_put(cfg->wans[i].dev);
	}
	kfree(cfg);
}

static bool mwan4_is_local_or_private_v4(__be32 addr)
{
	u32 ip = ntohl(addr);

	if ((ip & 0xFF000000U) == 0x00000000U) /* 0.0.0.0/8 */
		return true;
	if ((ip & 0xFF000000U) == 0x0A000000U) /* 10.0.0.0/8 */
		return true;
	if ((ip & 0xFF000000U) == 0x7F000000U) /* 127.0.0.0/8 */
		return true;
	if ((ip & 0xFFFF0000U) == 0xA9FE0000U) /* 169.254.0.0/16 */
		return true;
	if ((ip & 0xFFF00000U) == 0xAC100000U) /* 172.16.0.0/12 */
		return true;
	if ((ip & 0xFFFF0000U) == 0xC0A80000U) /* 192.168.0.0/16 */
		return true;
	if ((ip & 0xF0000000U) == 0xE0000000U) /* 224.0.0.0/4 multicast */
		return true;
	if ((ip & 0xF0000000U) == 0xF0000000U) /* 240.0.0.0/4 reserved/broadcast */
		return true;
	return false;
}

static bool mwan4_is_latency_sensitive(const struct sk_buff *skb, const struct iphdr *iph)
{
	unsigned int l4_off = iph->ihl * 4;
	__be16 dport;
	u16 port;

	if (iph->protocol == IPPROTO_ICMP)
		return true;

	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr _uh, *uh;

		uh = skb_header_pointer(skb, l4_off, sizeof(_uh), &_uh);
		if (!uh)
			return false;
		dport = uh->dest;
		port = ntohs(dport);
		/* DNS, NTP, SIP/VoIP, common game/voice control ports */
		return port == 53 || port == 123 || port == 5060 || port == 5061 ||
		       (port >= 3478 && port <= 3481);
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr _th, *th;

		th = skb_header_pointer(skb, l4_off, sizeof(_th), &_th);
		if (!th)
			return false;
		dport = th->dest;
		port = ntohs(dport);
		return port == 22 || port == 53;
	}

	return false;
}

static bool mwan4_is_wan_ifindex(const struct mwan4_sched_cfg *cfg, int ifindex)
{
	u32 i;

	for (i = 0; i < cfg->wan_count; i++) {
		if (cfg->wans[i].ifindex == ifindex)
			return true;
	}
	return false;
}

static const struct mwan4_wan *mwan4_find_by_mark(const struct mwan4_sched_cfg *cfg, u32 mark)
{
	u32 i;

	for (i = 0; i < cfg->wan_count; i++) {
		if (cfg->wans[i].fwmark == mark && !cfg->wans[i].degraded)
			return &cfg->wans[i];
	}
	return NULL;
}

/*
 * Pick the best active WAN for a new flow (lockless, O(wan_count)).
 * Lower score wins.
 */
static struct mwan4_wan *mwan4_pick_wan(struct mwan4_sched_cfg *cfg, bool latency_sensitive)
{
	struct mwan4_wan *best = NULL;
	u64 best_score = U64_MAX;
	u32 min_rtt = cfg->min_rtt_us ? cfg->min_rtt_us : 1000;
	u32 i;
	bool any_undegraded = false;

	for (i = 0; i < cfg->wan_count; i++) {
		if (!cfg->wans[i].degraded) {
			any_undegraded = true;
			break;
		}
	}

	for (i = 0; i < cfg->wan_count; i++) {
		struct mwan4_wan *w = &cfg->wans[i];
		u32 util_pm;
		u32 burst;
		u64 score;

		if (any_undegraded && w->degraded)
			continue;

		util_pm = READ_ONCE(w->util_pm);
		burst = (u32)atomic_read(&w->burst_flows);

		if (latency_sensitive && cfg->latency_fastlane) {
			/*
			 * Latency fast lane: strongly prefer lowest RTT,
			 * only avoid links that are heavily congested (>85%) or losing packets.
			 */
			u64 rtt_score = w->rtt_us ? w->rtt_us : 50000;
			u64 cong_pen = util_pm > 850 ? (u64)(util_pm - 850) * 500 : 0;
			u64 loss_pen = (u64)w->loss_pm * 1000;

			score = rtt_score + cong_pen + loss_pen;
		} else if (cfg->mode == MWAN4_MODE_LATENCY) {
			u64 rtt_rel = min_rtt ? ((u64)w->rtt_us * 1000) / min_rtt : 1000;
			u64 burst_pen = ((u64)burst * 120) / w->weight;

			score = rtt_rel + util_pm + burst_pen + (u64)w->loss_pm * 4;
		} else {
			/*
			 * Balanced mode:
			 *   - util_pm (0..1000+): real-time smoothed bandwidth utilization
			 *   - burst_pen: weighted flow deficit so concurrent new flows
			 *     at t=0 split strictly by weight (e.g. 4:4 or 6:3) before
			 *     NIC byte counters catch up
			 *   - quality_pen: only penalize packet loss or severe RTT bloat (>2.5x)
			 */
			u64 burst_pen = ((u64)burst * 160) / w->weight;
			u64 quality_pen = (u64)w->loss_pm * 3;

			if (w->rtt_us > min_rtt * 5 / 2 && w->rtt_us > 80000) {
				u64 excess = ((u64)(w->rtt_us - min_rtt * 5 / 2)) / 1000;
				quality_pen += min_t(u64, excess * 2, 400);
			}

			score = (u64)util_pm + burst_pen + quality_pen;
		}

		if (score < best_score) {
			best_score = score;
			best = w;
		}
	}

	return best;
}

static unsigned int mwan4_prerouting_hook(void *priv,
					  struct sk_buff *skb,
					  const struct nf_hook_state *state)
{
	struct mwan4_sched_cfg *cfg;
	struct iphdr *iph;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	u32 mask, existing_mark;
	struct mwan4_wan *chosen;
	bool lat_fast;

	if (!skb || !state->in)
		return NF_ACCEPT;

	cfg = rcu_dereference(g_cfg);
	if (!cfg || cfg->mode == MWAN4_MODE_OFF || cfg->wan_count < 2)
		return NF_ACCEPT;

	/* Never schedule packets arriving from a WAN interface */
	if (mwan4_is_wan_ifindex(cfg, state->in->ifindex))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4)
		return NF_ACCEPT;

	/* Skip LAN, loopback, link-local, multicast and broadcast */
	if (mwan4_is_local_or_private_v4(iph->daddr))
		return NF_ACCEPT;

	mask = cfg->mark_mask;
	/* Respect marks already set by policy routing / user rules */
	if ((skb->mark & mask) != 0)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	existing_mark = ct->mark & mask;
	if (ctinfo != IP_CT_NEW && existing_mark != 0) {
		if (mwan4_find_by_mark(cfg, existing_mark)) {
			skb->mark = (skb->mark & ~mask) | existing_mark;
			atomic64_inc(&g_stat_sticky_hits);
			return NF_ACCEPT;
		}
		/* Previously selected WAN is gone/degraded -> reselect */
		atomic64_inc(&g_stat_failover_reselects);
	}

	if (ctinfo != IP_CT_NEW && existing_mark == 0)
		return NF_ACCEPT;

	lat_fast = cfg->latency_fastlane && mwan4_is_latency_sensitive(skb, iph);
	chosen = mwan4_pick_wan(cfg, lat_fast);
	if (!chosen)
		return NF_ACCEPT;

	atomic_inc(&chosen->burst_flows);
	atomic64_inc(&chosen->total_flows);
	atomic64_inc(&g_stat_new_flows);
	if (lat_fast)
		atomic64_inc(&g_stat_fastlane_hits);

	ct->mark = (ct->mark & ~mask) | chosen->fwmark;
	skb->mark = (skb->mark & ~mask) | chosen->fwmark;
	return NF_ACCEPT;
}

static const struct nf_hook_ops mwan4_nf_ops[] = {
	{
		.hook		= mwan4_prerouting_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_MANGLE - 1,
	},
};

/*
 * 200ms workqueue (process context): safely queries dev_get_stats() for every
 * active WAN (including Flow-Offloaded traffic), computes integer EWMA bps and
 * utilization permille, and decays burst_flows.
 */
static void mwan4_sample_work_fn(struct work_struct *work)
{
	struct mwan4_sched_cfg *cfg;
	u64 max_norm_bps = 1;
	u32 i;

	mutex_lock(&g_cfg_lock);
	cfg = rcu_dereference_protected(g_cfg, lockdep_is_held(&g_cfg_lock));
	if (cfg && cfg->mode != MWAN4_MODE_OFF && cfg->wan_count > 0) {
		for (i = 0; i < cfg->wan_count; i++) {
			struct mwan4_wan *w = &cfg->wans[i];
			struct rtnl_link_stats64 stats;
			u64 rx_bytes, tx_bytes;
			u32 old_burst;

			/* Exponentially decay burst flow counter every 200ms */
			old_burst = (u32)atomic_read(&w->burst_flows);
			if (old_burst > 0)
				atomic_set(&w->burst_flows, old_burst / 2);

			if (!w->dev)
				continue;

			dev_get_stats(w->dev, &stats);
			rx_bytes = stats.rx_bytes;
			tx_bytes = stats.tx_bytes;

			if (w->stats_valid) {
				u64 d_rx = rx_bytes >= w->last_rx_bytes ?
					   rx_bytes - w->last_rx_bytes : 0;
				u64 d_tx = tx_bytes >= w->last_tx_bytes ?
					   tx_bytes - w->last_tx_bytes : 0;
				/* 200ms interval -> bytes * 8 * 5 = bps */
				u64 inst_rx_bps = d_rx * 40ULL;
				u64 inst_tx_bps = d_tx * 40ULL;

				/* EWMA alpha = 3/8 (fast reaction, smooth jitter) */
				w->rx_bps_ewma = (w->rx_bps_ewma * 5ULL + inst_rx_bps * 3ULL) >> 3;
				w->tx_bps_ewma = (w->tx_bps_ewma * 5ULL + inst_tx_bps * 3ULL) >> 3;
			} else {
				w->stats_valid = true;
			}

			w->last_rx_bytes = rx_bytes;
			w->last_tx_bytes = tx_bytes;

			if (w->down_bps_cap == 0) {
				u64 peak = max(w->rx_bps_ewma, w->tx_bps_ewma);
				u64 norm = div_u64(peak, w->weight);

				if (norm > max_norm_bps)
					max_norm_bps = norm;
			}
		}

		for (i = 0; i < cfg->wan_count; i++) {
			struct mwan4_wan *w = &cfg->wans[i];
			u32 util_pm;

			if (w->down_bps_cap > 0) {
				u64 up_cap = w->up_bps_cap ? w->up_bps_cap : w->down_bps_cap;
				u64 rx_pm = div64_u64(w->rx_bps_ewma * 1000ULL, w->down_bps_cap);
				u64 tx_pm = div64_u64(w->tx_bps_ewma * 1000ULL, up_cap);

				util_pm = (u32)min_t(u64, max(rx_pm, tx_pm), 5000ULL);
			} else {
				/*
				 * No explicit max_mbps configured: normalize live throughput
				 * by weight so every unit of weight carries equal bps.
				 */
				u64 peak = max(w->rx_bps_ewma, w->tx_bps_ewma);
				u64 norm = div_u64(peak, w->weight);

				util_pm = (u32)min_t(u64,
						     div64_u64(norm * 1000ULL, max_norm_bps),
						     1000ULL);
			}
			WRITE_ONCE(w->util_pm, util_pm);
		}
	}
	mutex_unlock(&g_cfg_lock);

	schedule_delayed_work(&g_sample_work, msecs_to_jiffies(MWAN4_SAMPLE_MS));
}

/*
 * /proc/net/mwan4_sched protocol (text, atomic write):
 *
 *   mode <0|1|2> [mark_mask_hex] [latency_fastlane 0|1]
 *   wan <ifname> <ifindex> <fwmark_hex> <weight> <down_kbps> <up_kbps> <rtt_us> <loss_pm> <degraded>
 *   ...
 *
 * Writing "mode 0" disables scheduling and clears active WANs.
 */
static int mwan4_proc_show(struct seq_file *m, void *v)
{
	struct mwan4_sched_cfg *cfg;
	u32 i;

	rcu_read_lock();
	cfg = rcu_dereference(g_cfg);
	if (!cfg) {
		seq_puts(m, "version=" MWAN4_SCHED_VERSION " mode=0 wans=0\n");
		rcu_read_unlock();
		return 0;
	}

	seq_printf(m,
		   "version=%s mode=%u mark_mask=0x%08x fastlane=%u wans=%u new_flows=%lld sticky_hits=%lld failovers=%lld fastlane_hits=%lld\n",
		   MWAN4_SCHED_VERSION,
		   cfg->mode,
		   cfg->mark_mask,
		   cfg->latency_fastlane,
		   cfg->wan_count,
		   atomic64_read(&g_stat_new_flows),
		   atomic64_read(&g_stat_sticky_hits),
		   atomic64_read(&g_stat_failover_reselects),
		   atomic64_read(&g_stat_fastlane_hits));

	for (i = 0; i < cfg->wan_count; i++) {
		const struct mwan4_wan *w = &cfg->wans[i];

		seq_printf(m,
			   "wan name=%s ifindex=%d mark=0x%08x weight=%u util_pm=%u rx_bps=%llu tx_bps=%llu rtt_us=%u loss_pm=%u degraded=%u burst=%d flows=%lld\n",
			   w->name,
			   w->ifindex,
			   w->fwmark,
			   w->weight,
			   READ_ONCE(w->util_pm),
			   w->rx_bps_ewma,
			   w->tx_bps_ewma,
			   w->rtt_us,
			   w->loss_pm,
			   w->degraded,
			   atomic_read(&w->burst_flows),
			   atomic64_read(&w->total_flows));
	}
	rcu_read_unlock();
	return 0;
}

static int mwan4_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mwan4_proc_show, NULL);
}

static ssize_t mwan4_proc_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char *kbuf, *p, *line;
	struct mwan4_sched_cfg *new_cfg, *old_cfg;
	u32 i, j;

	if (count == 0 || count > MWAN4_CMD_MAX_LEN)
		return -EINVAL;

	kbuf = memdup_user_nul(ubuf, count);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
	if (!new_cfg) {
		kfree(kbuf);
		return -ENOMEM;
	}

	new_cfg->mode = MWAN4_MODE_BALANCED;
	new_cfg->mark_mask = MWAN4_DEFAULT_MASK;
	new_cfg->latency_fastlane = 1;
	new_cfg->min_rtt_us = U32_MAX;

	p = kbuf;
	while ((line = strsep(&p, "\n")) != NULL) {
		while (*line == ' ' || *line == '\t')
			line++;
		if (*line == '\0' || *line == '#')
			continue;

		if (strncmp(line, "mode ", 5) == 0) {
			u32 mode = 0, mask = MWAN4_DEFAULT_MASK, fastlane = 1;
			int n = sscanf(line + 5, "%u %x %u", &mode, &mask, &fastlane);

			if (n >= 1 && mode <= MWAN4_MODE_LATENCY)
				new_cfg->mode = mode;
			if (n >= 2 && mask != 0)
				new_cfg->mark_mask = mask;
			if (n >= 3)
				new_cfg->latency_fastlane = fastlane ? 1 : 0;
		} else if (strncmp(line, "wan ", 4) == 0) {
			struct mwan4_wan *w;
			char name[IFNAMSIZ] = {0};
			int ifindex = 0;
			u32 fwmark = 0, weight = 1, rtt_us = 0, loss_pm = 0, degraded = 0;
			unsigned long long down_kbps = 0, up_kbps = 0;
			int n;

			if (new_cfg->wan_count >= MWAN4_MAX_WANS)
				continue;

			n = sscanf(line + 4, "%15s %d %x %u %llu %llu %u %u %u",
				   name, &ifindex, &fwmark, &weight,
				   &down_kbps, &up_kbps, &rtt_us, &loss_pm, &degraded);
			if (n < 4 || ifindex <= 0 || fwmark == 0)
				continue;

			w = &new_cfg->wans[new_cfg->wan_count];
			strscpy(w->name, name, sizeof(w->name));
			w->ifindex = ifindex;
			w->dev = dev_get_by_index(&init_net, ifindex);
			w->fwmark = fwmark & new_cfg->mark_mask;
			if (w->fwmark == 0) {
				if (w->dev)
					dev_put(w->dev);
				continue;
			}
			w->weight = max_t(u32, weight, 1);
			w->down_bps_cap = down_kbps * 1000ULL;
			w->up_bps_cap = up_kbps * 1000ULL;
			w->rtt_us = rtt_us;
			w->loss_pm = min_t(u32, loss_pm, 1000U);
			w->degraded = degraded ? 1 : 0;
			atomic_set(&w->burst_flows, 0);
			atomic64_set(&w->total_flows, 0);

			if (!w->degraded && rtt_us > 0 && rtt_us < new_cfg->min_rtt_us)
				new_cfg->min_rtt_us = rtt_us;

			new_cfg->wan_count++;
		}
	}

	if (new_cfg->min_rtt_us == U32_MAX)
		new_cfg->min_rtt_us = 1000;

	/* Preserve live rate EWMA & counters for unchanged WANs across config updates */
	mutex_lock(&g_cfg_lock);
	old_cfg = rcu_dereference_protected(g_cfg, lockdep_is_held(&g_cfg_lock));
	if (old_cfg) {
		for (i = 0; i < new_cfg->wan_count; i++) {
			struct mwan4_wan *nw = &new_cfg->wans[i];

			for (j = 0; j < old_cfg->wan_count; j++) {
				struct mwan4_wan *ow = &old_cfg->wans[j];

				if (nw->ifindex == ow->ifindex) {
					nw->last_rx_bytes = ow->last_rx_bytes;
					nw->last_tx_bytes = ow->last_tx_bytes;
					nw->stats_valid = ow->stats_valid;
					nw->rx_bps_ewma = ow->rx_bps_ewma;
					nw->tx_bps_ewma = ow->tx_bps_ewma;
					nw->util_pm = READ_ONCE(ow->util_pm);
					atomic_set(&nw->burst_flows, atomic_read(&ow->burst_flows));
					atomic64_set(&nw->total_flows,
						     atomic64_read(&ow->total_flows));
					break;
				}
			}
		}
	}

	rcu_assign_pointer(g_cfg, new_cfg);
	mutex_unlock(&g_cfg_lock);

	if (old_cfg)
		call_rcu(&old_cfg->rcu, mwan4_cfg_free_rcu);

	kfree(kbuf);
	return count;
}

static const struct proc_ops mwan4_proc_ops = {
	.proc_open	= mwan4_proc_open,
	.proc_read	= seq_read,
	.proc_write	= mwan4_proc_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init mwan4_sched_init(void)
{
	int ret;

	g_proc_entry = proc_create("mwan4_sched", 0644, init_net.proc_net, &mwan4_proc_ops);
	if (!g_proc_entry) {
		pr_err("mwan4_sched: failed to create /proc/net/mwan4_sched\n");
		return -ENOMEM;
	}

	ret = nf_register_net_hooks(&init_net, mwan4_nf_ops, ARRAY_SIZE(mwan4_nf_ops));
	if (ret) {
		pr_err("mwan4_sched: failed to register netfilter hooks: %d\n", ret);
		proc_remove(g_proc_entry);
		return ret;
	}

	INIT_DELAYED_WORK(&g_sample_work, mwan4_sample_work_fn);
	schedule_delayed_work(&g_sample_work, msecs_to_jiffies(MWAN4_SAMPLE_MS));

	pr_info("mwan4_sched: v%s loaded (control: /proc/net/mwan4_sched)\n", MWAN4_SCHED_VERSION);
	return 0;
}

static void __exit mwan4_sched_exit(void)
{
	struct mwan4_sched_cfg *old_cfg;

	nf_unregister_net_hooks(&init_net, mwan4_nf_ops, ARRAY_SIZE(mwan4_nf_ops));
	cancel_delayed_work_sync(&g_sample_work);
	proc_remove(g_proc_entry);

	mutex_lock(&g_cfg_lock);
	old_cfg = rcu_dereference_protected(g_cfg, lockdep_is_held(&g_cfg_lock));
	RCU_INIT_POINTER(g_cfg, NULL);
	mutex_unlock(&g_cfg_lock);

	if (old_cfg)
		call_rcu(&old_cfg->rcu, mwan4_cfg_free_rcu);
	rcu_barrier();

	pr_info("mwan4_sched: unloaded\n");
}

module_init(mwan4_sched_init);
module_exit(mwan4_sched_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MWAN4 Project");
MODULE_DESCRIPTION("MWAN4 per-flow real-time load-balancing scheduler");
MODULE_VERSION(MWAN4_SCHED_VERSION);
