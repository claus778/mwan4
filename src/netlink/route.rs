// 本模组只在 Linux 上真正执行 netlink I/O；
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）会整批变成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use crate::config::EcmpMode;
use crate::netlink::util::{
    NlMsgHdr, read_i32, read_u16, read_u32, rta_align, set_socket_timeouts, write_u16, write_u32,
};
use log::{debug, info, warn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

// Linux Netlink 常数定义
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

// nexthop object（Linux 5.3+）；resilient group 需要 5.14+
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_REPLACE: u16 = 0x100;
/// NLM_F_ROOT | NLM_F_MATCH：请求内核把整张表 dump 出来
pub const NLM_F_DUMP: u16 = 0x300;
/// dump 进行中路由表被改动时，内核会把这个旗标标在 `NLMSG_DONE` 上（资料不完整）
pub const NLM_F_DUMP_INTR: u16 = 0x10;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_STATIC: u8 = 4;
/// 删除时代表「不比较 protocol」（通配符）；只用于启动清扫的旧版本残留。
pub const RTPROT_UNSPEC: u8 = 0;
/// 本程式下发路由的专属 protocol 标记（与探针规则的 FRA_PROTOCOL 同值）。
///
/// 为什么不用 RTPROT_STATIC：内核在 `RTM_DELROUTE` 时会比对 protocol，而
/// `RTA_PRIORITY = 0` 又是「不比较 metric」的通配符。若删除讯息带 RTPROT_UNSPEC，
/// 当我们那条 metric 0 的路由已被外部移除、而 netifd 刚好有一条同 metric 的预设
/// 路由时，就会把**别人的路由删掉**。带专属 protocol 后，删除只会命中自己下发的。
pub const RTPROT_MWAN4: u8 = 0x4D;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
/// 删除路由时使用：内核 `fib_table_delete()` 会比对路由既有的 scope，
/// 除非请求的 `fc_scope == RT_SCOPE_NOWHERE`（iproute2 删除时正是填这个值）。
/// 若删除时沿用建立时的 scope（UNIVERSE / LINK），无网关路由（scope=LINK）
/// 会因不匹配回 ESRCH 而被误当成「本来就不存在」，残留永远清不掉。
pub const RT_SCOPE_NOWHERE: u8 = 255;
pub const RTN_UNICAST: u8 = 1;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_MULTIPATH: u16 = 9;
/// 目的前缀（RTA_DST）
pub const RTA_DST: u16 = 1;
/// 路由所在表（表号 > 255 时必须用它；与 FRA_TABLE 同值但属不同列举）
pub const RTA_TABLE: u16 = 15;
/// 路由改为引用 nexthop object 时使用的属性（取代 RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH）
pub const RTA_NH_ID: u16 = 30;

// nexthop 专用的 rtattr 型别（enum nha_type）
pub const NHA_ID: u16 = 1;
pub const NHA_GROUP: u16 = 2;
pub const NHA_GROUP_TYPE: u16 = 3;
pub const NHA_OIF: u16 = 5;
pub const NHA_GATEWAY: u16 = 6;
pub const NHA_RES_GROUP: u16 = 12;

/// 巢状在 `NHA_RES_GROUP` 里的 bucket 数（`enum { NHA_RES_GROUP_BUCKETS }`，u16）。
///
/// ⚠️ 这是个踩过的坑：uapi 顶层列举的 13 是 `NHA_RES_BUCKET`（给
/// RTM_{NEW,DEL,GET}NEXTHOPBUCKET 用的 bucket 属性），**不是** group 的 bucket 数。
/// 旧版把顶层 13 当成 bucket 数塞进 `NHA_RES_GROUP` 巢状里，核心解析时找不到
/// `NHA_RES_GROUP_BUCKETS`，就当成「没给 bucket 数」回 EINVAL —— resilient 模式
/// 因此从来没成功过（症状：成员 nexthop 建得出来，group 建不出来，路由不下发）。
pub const NHA_RES_GROUP_BUCKETS: u16 = 1;

/// `SOL_NETLINK` / `NETLINK_EXT_ACK`（linux/netlink.h）。
/// 开了这个选项，核心才会在 netlink 错误回应里附上「为什么失败」的字串；
/// 不开的话只会得到一个没有上下文的 `EINVAL`，巢状属性写错时完全无从判断。
/// libc 未必每个版本都导出这两个常数，所以自备。
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;

/// `NLA_F_NESTED`（linux/netlink.h）：标记这是一个巢状属性。
///
/// 这是 resilient nexthop group 建不起来的**真正原因**（比 bucket 数常量更早踩到）：
/// `NHA_RES_GROUP` 是巢状属性，核心 5.2+ 会要求它带 `NLA_F_NESTED`；少了这个位元，
/// 核心不把它当巢状属性解析，也就看不到里面的 `NHA_RES_GROUP_BUCKETS`，
/// 直接回 `EINVAL`。实测对照：iproute2 送的是 `0x800c`，我们旧版送 `0x000c`。
/// 注意核心用 `nla_type()` 遮蔽高位后仍是 12，所以这个位元只影响「是否按巢状解析」。
const NLA_F_NESTED: u16 = 0x8000;

/// enum nexthop_grp_type：resilient group（只有故障链路的 bucket 会被重映射）
pub const NEXTHOP_GRP_TYPE_RES: u16 = 1;

/// 本程式保留的群组 ID，避开一般 nexthop id 的配置空间
pub const NH_GROUP_ID_V4: u32 = 0xFFFF_FF00;
pub const NH_GROUP_ID_V6: u32 = 0xFFFF_FF01;

/// resilient group 的 bucket 数上限：必须是 2 的幂、涵盖所有允许的成员数，
/// 且第一次建立后**不得再变**（核心不允许 REPLACE 时改变 bucket 数）。
/// 上限同时界定单一 netlink 讯息大小与核心记忆体用量；成员数超过上限时
/// 不支援 resilient（由呼叫端退回标准 ECMP）。
const RES_BUCKETS_MAX: usize = 256;

/// rtnexthop 的 weight 栏位（rtnh_hops）是 u8，核心语意为 weight - 1；
/// 上限与 `config::MAX_WEIGHT` 一致（resilient group 在旧核心只到 255）。
pub const MAX_NEXTHOP_WEIGHT: u32 = 255;

// ---------------------------------------------------------------------------
// 探针专用路由表 / 规则（RTM_NEWRULE）
//
// 为什么需要：SO_BINDTODEVICE 只是把路由查找的 oif 固定到该设备，**不代表找得到路**。
// 主表若没有「经该设备」的路由，内核会「假定目的地在链路上」把 SYN 直接丢进黑洞
// （实测：connect() 回 EINPROGRESS 后永远超时，不是 ENETUNREACH），
// 于是「预设路由被删掉／被切到别条线」就等于「该线永远回不去」——自锁。
//
// 解法：为每张 WAN 建一张独立表（表内 `default via <gw> dev <wan>`）＋一条
// `oif <wan> lookup <table>` 规则。规则只匹配「绑定该设备的本地封包」，所以：
//   * 探针一定有路，与主表那条预设路由完全无关；
//   * 转发流量（oif = br-lan）与路由器其它本地流量（oif 未绑定）走主表，不受影响。
//
// 表号与规则优先序都取 10000 起算的独立区段，优先序仍小于 main(32766)，
// 因此会在主表之前被求值。
// ---------------------------------------------------------------------------

/// RTM_NEWRULE / RTM_DELRULE（fib_rule）
/// 注意：不是 21/22（那是 RTM_DELADDR/RTM_GETADDR），照 linux/rtnetlink.h 是 32/33。
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

/// enum fib_rule_attr（照 linux/rtnetlink.h 抄：FWMARK=10, TABLE=15, FWMASK=16, OIFNAME=17）
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_OIFNAME: u16 = 17;
pub const FRA_TABLE: u16 = 15;
/// 规则的来源标记（u8）。我们用它把「自己的规则」与别人的规则区分开，
/// 清扫时只删带这个标记的，不会动到第三方（例如 mwan3 / VPN 的规则）。
pub const FRA_PROTOCOL: u16 = 21;

/// 本程式下发的规则所使用的 FRA_PROTOCOL 标记值（'M' = mwan4）
pub const PROBE_RULE_PROTOCOL: u8 = 0x4D;

/// enum fib_rule_action：把匹配的封包送到指定表
pub const FR_ACT_TO_TBL: u8 = 1;

/// 探针「出向」表号的起点（第 i 张 WAN 用 PROBE_TABLE_BASE + i）
pub const PROBE_TABLE_BASE: u32 = 10_000;
/// 探针出向规则的优先序起点（必须小于 main 表的 32766）
pub const PROBE_RULE_PRIORITY_BASE: u32 = 10_000;
/// 可用的 slot 数上限（= 可设定的 WAN 介面数上限）。
/// 启动时会清扫整个保留区段，避免上一次执行留下的规则指向旧闸道。
/// 刻意压在 64：真实路由器不会有这么多 WAN，而每次启动的清扫往返次数正比于它。
pub const PROBE_SLOT_MAX: u32 = 64;

// ---------------------------------------------------------------------------
// 策略分流规则（fib rule 的 from/to + 目标 WAN 的独立表）
//
// 为什么不用 fwmark/nftables（mwan3 的做法）：`ip rule` 的 `from`/`to` 本身就
// 支援来源/目的前缀匹配，转发封包在路由查找时就会命中，完全不需要在封包上打标。
// 这与本专案「转发面零封包标记、不破坏 Flow Offload」的架构一致。
//
// 规则优先序独立于探针规则（9000 起算，仍在 main 表 32766 之前）；
// 目标 WAN 的下一跳沿用该 WAN 的探针独立表（default via gw dev wan）。
// ---------------------------------------------------------------------------

/// 策略规则的优先序起点（第 i 条用 POLICY_RULE_PRIORITY_BASE + i）
pub const POLICY_RULE_PRIORITY_BASE: u32 = 9_000;
/// 策略规则数量上限（含来源/目的展开后的总条数）
pub const POLICY_SLOT_MAX: u32 = 64;
/// enum fib_rule_attr：来源/目的前缀
pub const FRA_DST: u16 = 1;
pub const FRA_SRC: u16 = 2;
/// 探针目标在主表的 /32 路由使用的 metric。
/// 与预设路由的 priority（通常 0）分开，便于辨识与精准删除。
pub const PROBE_MAIN_ROUTE_METRIC: u32 = 42_760;

/// 隧道 underlay 对端的 /32 路由在主表使用的 metric。
///
/// 与探针的 42760 分开，两者才能各自精准清扫（互不误删）。
/// 真正让它优先于预设路由的是「前缀更长」，metric 只作为辨识标记。
pub const UNDERLAY_ROUTE_METRIC: u32 = 42_761;

/// **启动前**那次清扫要扫掉的 metric（探针 + 隧道 underlay）。
///
/// 开机时连 underlay 一起清的理由：上次执行留下的 underlay /32 出口（ifindex / gateway）
/// 可能已经换了（隧道重建、物理线改 metric），逐条猜测不如一次清干净，
/// 之后由 `sync_underlay_routes` 按当前期望重新补回。
const STARTUP_SWEEP_METRICS: [(u32, &str); 2] = [
    (PROBE_MAIN_ROUTE_METRIC, "probe"),
    (UNDERLAY_ROUTE_METRIC, "underlay"),
];

/// **执行期**（`SetProbePaths(clean = true)`）那次清扫只扫探针 /32。
///
/// 为什么绝对不能连 underlay 一起清：worker 处理同一批指令时是 `Apply` 先、`SetProbePaths`
/// 后（`apply_default_routes` → `sync_underlay_routes` 才刚把 underlay /32 装好、
/// 并记进记忆体快取），清扫若顺手删掉它，`sync_underlay_routes` 只信快取
/// （「出口没变 → 不必重下」）就再也不会补——实测启动后 40 秒（含 30 秒心跳）
/// underlay /32 一直是 0 条，隧道的封装封包只能走 ECMP 预设路由，约 1/2 机率被塞回
/// 隧道自己（自环丢包），双线才丢包的元凶。
const RUNTIME_SWEEP_METRICS: [(u32, &str); 1] = [(PROBE_MAIN_ROUTE_METRIC, "probe")];

// 这些不变式是「规则一定会在 main 表之前被求值」与「/32 一定赢过预设路由」的前提，
// 直接在编译期钉死；改坏了会无法编译而不是上机才发现。
const _: () = {
    assert!(PROBE_TABLE_BASE > 255);
    assert!(PROBE_RULE_PRIORITY_BASE > 0);
    assert!(PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX < 32_766);
    // 策略规则的保留区段必须完整落在探针规则之前，两者不会互相覆盖
    assert!(POLICY_RULE_PRIORITY_BASE > 0);
    assert!(POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX <= PROBE_RULE_PRIORITY_BASE);
    assert!(PROBE_MAIN_ROUTE_METRIC != 0);
    // 探针 /32 的 metric 不能落在表号／规则优先序的保留区段里，否则清扫会误删
    assert!(PROBE_MAIN_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(PROBE_MAIN_ROUTE_METRIC < 0xFFFF_FF00);
    // underlay /32 用另一个 metric：与探针分开才能各自精准清扫
    assert!(UNDERLAY_ROUTE_METRIC != PROBE_MAIN_ROUTE_METRIC);
    assert!(UNDERLAY_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(UNDERLAY_ROUTE_METRIC < 0xFFFF_FF00);
    // 执行期清扫只能扫探针 /32：误删 underlay 会让隧道封装封包走 ECMP 自环
    assert!(RUNTIME_SWEEP_METRICS.len() == 1);
    assert!(RUNTIME_SWEEP_METRICS[0].0 == PROBE_MAIN_ROUTE_METRIC);
    assert!(RUNTIME_SWEEP_METRICS[0].0 != UNDERLAY_ROUTE_METRIC);
    // 启动清扫两者都要扫（残留的 underlay /32 出口可能已经失效）
    assert!(STARTUP_SWEEP_METRICS.len() == 2);
};

/// 等待核心 ACK 的最大轮询次数（配合 socket 上的 SO_RCVTIMEO 使用）
const ACK_RETRY_LIMIT: usize = 4;

#[cfg(target_os = "linux")]
const ESRCH: i32 = libc::ESRCH;
#[cfg(not(target_os = "linux"))]
const ESRCH: i32 = 3;

#[cfg(target_os = "linux")]
const ENOENT: i32 = libc::ENOENT;
#[cfg(not(target_os = "linux"))]
const ENOENT: i32 = 2;

#[cfg(target_os = "linux")]
const EEXIST: i32 = libc::EEXIST;
#[cfg(not(target_os = "linux"))]
const EEXIST: i32 = 17;

/// struct rtmsg（12 bytes）
#[derive(Debug, Clone, Copy)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

impl RtMsg {
    pub const LEN: usize = 12;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.rtm_family;
        b[1] = self.rtm_dst_len;
        b[2] = self.rtm_src_len;
        b[3] = self.rtm_tos;
        b[4] = self.rtm_table;
        b[5] = self.rtm_protocol;
        b[6] = self.rtm_scope;
        b[7] = self.rtm_type;
        crate::netlink::util::write_u32(&mut b, 8, self.rtm_flags);
        b
    }
}

/// struct rtattr（4 bytes）
#[derive(Debug, Clone, Copy)]
pub struct RtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

impl RtAttr {
    pub const LEN: usize = 4;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        write_u16(&mut b, 0, self.rta_len);
        write_u16(&mut b, 2, self.rta_type);
        b
    }
}

/// struct rtnexthop（8 bytes）
#[derive(Debug, Clone, Copy)]
pub struct RtNextHop {
    pub rtnh_len: u16,
    pub rtnh_flags: u8,
    pub rtnh_hops: u8, // 权重 weight - 1
    pub rtnh_ifindex: i32,
}

impl RtNextHop {
    pub const LEN: usize = 8;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        write_u16(&mut b, 0, self.rtnh_len);
        b[2] = self.rtnh_flags;
        b[3] = self.rtnh_hops;
        b[4..8].copy_from_slice(&self.rtnh_ifindex.to_ne_bytes());
        b
    }
}

/// struct nhmsg（8 bytes）—— RTM_NEWNEXTHOP / RTM_DELNEXTHOP 的固定标头
#[derive(Debug, Clone, Copy)]
pub struct NhMsg {
    pub nh_family: u8,
    pub nh_scope: u8,
    pub nh_protocol: u8,
    pub nh_resvd: u8,
    pub nh_flags: u32,
}

impl NhMsg {
    pub const LEN: usize = 8;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.nh_family;
        b[1] = self.nh_scope;
        b[2] = self.nh_protocol;
        b[3] = self.nh_resvd;
        write_u32(&mut b, 4, self.nh_flags);
        b
    }
}

/// struct fib_rule_hdr（12 bytes）—— RTM_NEWRULE / RTM_DELRULE 的固定标头
#[derive(Debug, Clone, Copy)]
pub struct FibRuleHdr {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub action: u8,
    pub flags: u32,
}

impl FibRuleHdr {
    pub const LEN: usize = 12;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.family;
        b[1] = self.dst_len;
        b[2] = self.src_len;
        b[3] = self.tos;
        b[4] = self.table;
        // b[5] / b[6] 是保留栏位
        b[7] = self.action;
        write_u32(&mut b, 8, self.flags);
        b
    }
}

/// struct nexthop_grp（8 bytes）—— NHA_GROUP 的每个成员。
/// `weight` 与 rtnh_hops 一样是「权重 - 1」。
#[derive(Debug, Clone, Copy)]
pub struct NextHopGrp {
    pub id: u32,
    pub weight: u8,
    pub resvd1: u8,
    pub resvd2: u16,
}

impl NextHopGrp {
    pub const LEN: usize = 8;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        write_u32(&mut b, 0, self.id);
        b[4] = self.weight;
        b[5] = self.resvd1;
        write_u16(&mut b, 6, self.resvd2);
        b
    }
}

/// 活跃 WAN 路由节点（IPv4）
#[derive(Debug, Clone)]
pub struct ActiveWanRoute {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
    pub weight: u32,
    /// 这条线的 metric：用来挑「underlay 出口」（非隧道线中 metric 最小者）
    pub metric: u32,
    /// 这条线若是隧道，列出其 underlay 对端位址；非隧道线留空。
    /// 两层用途：① 非空 = 这条是隧道（不能当别人的 underlay 出口）；
    /// ② 这些位址要补 /32 走真正的 underlay 出口，否则会自环。
    pub underlay_targets: Vec<Ipv4Addr>,
}

/// 活跃 WAN 路由节点（IPv6）
#[derive(Debug, Clone)]
pub struct ActiveWanRouteV6 {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv6Addr>,
    pub weight: u32,
}

/// 一条「探针路径」：让绑定某张 WAN 的探针**一定有路可走**，而且尽量不影响转发。
///
/// 两层保障（两者都是实测出来的，缺一不可）：
///
/// 1. **出向**：独立表（`default via gateway dev ifname`）＋ `oif ifname lookup table`
///    规则。`SO_BINDTODEVICE` 只固定查找的 oif，本身不会造出路由；没有这一步，
///    「主表那条预设路由被删掉或切到别条线」就等于「这条线永远回不去」。
///
/// 2. **回程**：需要时在主表补一条探针目标的 `/32`（走该 WAN）。
///    为什么是主表而不是另一张表：内核的反向路径检查（`rp_filter`）**只查主表**，
///    完全看不到 FIB 规则。实测：主表没有涵盖探针目标的路由时，即使出向那条路
///    完全正常、封包也确实送达对端，回来的 SYN-ACK 仍会被当成 martian 丢掉，
///    症状是探针「一直超时」。把 /32 放进主表即可修好（strict / loose 皆然）。
///
///    `main_route_targets` 由呼叫端决定「哪些目标」需要：只有
///    ① 主表没有**别人的**预设路由（此时不补就收不到回程），或
///    ② rp_filter 为 strict（1）且该目标没有被别的 WAN 共用 时才放进来；
///    其余情况不补，避免影响 LAN 转发路径。同一个共用目标只会有一个拥有者。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePath {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
    /// 这张 WAN 的探针目标（需要时会以 /32 放进主表）
    pub targets: Vec<Ipv4Addr>,
    /// 该 WAN 专用的出向表号（呼叫端以 PROBE_TABLE_BASE + slot 产生）
    pub table: u32,
    /// 该 WAN 专用出向规则的优先序（呼叫端以 PROBE_RULE_PRIORITY_BASE + slot 产生）
    pub priority: u32,
    /// **需要**在主表补 /32 的目标子集（见上方说明）。
    ///
    /// 用「子集」而不是单一 bool：同一个目标可能被多条线共用，而主表同一个前缀只能有
    /// 一条路由——只有「该目标的拥有者」（呼叫端按 metric 选出）才把它放进来。
    pub main_route_targets: Vec<Ipv4Addr>,
}

/// 一条策略分流规则（已展开）：`from`/`to` 为 None 代表不限制。
///
/// 主回圈负责把 `config.policies`（可含多个来源/目的）展开成这个形式，
/// 并在目标 WAN DOWN 时把它从期望集合移除（流量回退 ECMP）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// 规则名称（显示与日志用）
    pub name: String,
    /// 目标 WAN 的 ifindex（仅供日志；实际下一跳由 `table` 决定）
    pub ifindex: u32,
    /// 目标 WAN 的独立路由表（沿用探针表 PROBE_TABLE_BASE + slot）
    pub table: u32,
    /// fib rule 优先序
    pub priority: u32,
    /// 来源前缀（None = 不限制）
    pub source: Option<(Ipv4Addr, u8)>,
    /// 目的前缀（None = 不限制）
    pub destination: Option<(Ipv4Addr, u8)>,
}

/// 一条 fib_rule 的描述（出向用 oif、入向用 iif）
#[derive(Debug, Clone, Copy)]
struct RuleSpec<'a> {
    family: u8,
    table: u32,
    ifname: &'a str,
    priority: u32,
    /// true = `oif`（本机产生）、false = `iif`（进来）
    output: bool,
}

/// 路由查询（RTM_GETROUTE）的结果摘要
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLookup {
    /// 解析出来的出口设备（RTA_OIF）
    pub ifindex: Option<u32>,
    pub gateway: Option<Ipv4Addr>,
    /// 命中的表（RTA_TABLE，没有就是 rtmsg.rtm_table）
    pub table: u32,
}

/// 已正规化、与位址族无关的 nexthop 描述
struct RouteNexthop {
    ifindex: u32,
    /// 网关的原始位元组（IPv4 = 4 bytes，IPv6 = 16 bytes）；None 代表直连
    gateway: Option<Vec<u8>>,
    weight: u32,
}

/// 目前下发到核心的预设路由类型。
///
/// 两种路由的 netlink key 不同（有无 RTA_NH_ID），必要时得把另一种先删掉，
/// 否则同一条 default route 会残留两份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledVariant {
    None,
    /// RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH
    Standard,
    /// RTA_NH_ID 指向 resilient nexthop group
    Resilient,
}

/// 一条路由讯息的落点：`table = None` 代表主表（RT_TABLE_MAIN），
/// `dst = Some((位址位元组, 前缀长度))` 代表非预设路由。
#[derive(Debug, Clone, Copy)]
struct RouteTarget<'a> {
    table: Option<u32>,
    dst: Option<(&'a [u8], u8)>,
}

/// Netlink FIB 路由管理器
pub struct RouteManager {
    #[cfg(target_os = "linux")]
    sock_fd: libc::c_int,
    seq: u32,
    /// 下发预设路由时使用的 metric（RTA_PRIORITY）
    priority: u32,
    /// ECMP 行为：标准 multipath / 自动 / 强制 resilient nexthop group
    ecmp_mode: EcmpMode,
    /// None = 尚未探测；Some(true/false) = 核心是否支援 resilient nexthop group
    resilient_supported: Option<bool>,
    /// (family, ifindex, gateway bytes) -> nexthop object id。
    /// ID 必须跨次呼叫保持稳定，核心才只会重映射故障链路的 bucket。
    nh_ids: std::collections::HashMap<(u8, u32, Vec<u8>), u32>,
    next_nh_id: u32,
    installed_v4: InstalledVariant,
    installed_v6: InstalledVariant,
    /// 已下发的探针路径，key = 网卡名（用于差异比对与清理）
    probe_paths: std::collections::HashMap<String, ProbePath>,
    /// 已下发的隧道 underlay /32 路由：对端位址 -> (ifindex, gateway bytes)。
    /// 用来差异比对，避免每轮重下（见 `sync_underlay_routes`）。
    underlay_routes: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)>,
    /// 已下发的策略分流规则（差异比对与清理用）
    policy_rules: Vec<PolicyRule>,
}

impl RouteManager {
    /// 初始化 Netlink Route 套接字
    pub fn new(priority: u32, ecmp_mode: EcmpMode) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let sock_fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            };
            if sock_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            sa.nl_pid = 0; // 由内核自动分配
            sa.nl_groups = 0;

            let ret = unsafe {
                libc::bind(
                    sock_fd,
                    &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                unsafe { libc::close(sock_fd) };
                return Err(io::Error::last_os_error());
            }

            // 要求核心在错误回应里附上原因（extack）。
            // 旧版没开这个选项，resilient group 建失败时只看到 EINVAL，
            // 完全不知道是 bucket 数、group type 还是别的属性的问题。
            let enable: libc::c_int = 1;
            let ret = unsafe {
                libc::setsockopt(
                    sock_fd,
                    SOL_NETLINK,
                    NETLINK_EXT_ACK,
                    &enable as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                // 不影响功能，只是少一条排障线索
                debug!(
                    "[RouteManager] NETLINK_EXT_ACK unavailable: {}",
                    io::Error::last_os_error()
                );
            }

            // 避免核心异常时 recv 永久阻塞住整个 daemon
            if let Err(e) = set_socket_timeouts(
                sock_fd,
                Some(std::time::Duration::from_secs(2)),
                Some(std::time::Duration::from_secs(2)),
            ) {
                warn!("[RouteManager] Failed to set socket timeouts: {e}");
            }

            Ok(Self {
                sock_fd,
                seq: 1,
                priority,
                ecmp_mode,
                resilient_supported: None,
                nh_ids: std::collections::HashMap::new(),
                next_nh_id: 1,
                installed_v4: InstalledVariant::None,
                installed_v6: InstalledVariant::None,
                probe_paths: std::collections::HashMap::new(),
                underlay_routes: std::collections::HashMap::new(),
                policy_rules: Vec::new(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                seq: 1,
                priority,
                ecmp_mode,
                resilient_supported: None,
                nh_ids: std::collections::HashMap::new(),
                next_nh_id: 1,
                installed_v4: InstalledVariant::None,
                installed_v6: InstalledVariant::None,
                probe_paths: std::collections::HashMap::new(),
                underlay_routes: std::collections::HashMap::new(),
                policy_rules: Vec::new(),
            })
        }
    }

    /// 调整 netlink socket 的收发逾时（非 Linux 为 no-op）。
    ///
    /// 事件回圈上的「查询用」manager 要用短逾时：内核一时不回应时，查询是同步阻塞
    /// caller 的，2 秒 × N 张网卡会把 current_thread runtime 整段冻住（讯号、探针、
    /// link 事件全部延后）。正常 netlink 往返是微秒级，缩到数百毫秒不影响成功率，
    /// 逾时则由呼叫端用保守值（当成「没有路」）继续。
    pub fn set_netlink_timeout(&self, timeout: std::time::Duration) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            set_socket_timeouts(self.sock_fd, Some(timeout), Some(timeout))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = timeout;
            Ok(())
        }
    }

    /// 取得（必要时配置）某个 nexthop 的稳定 ID
    fn alloc_nh_id(&mut self, family: u8, ifindex: u32, gateway: Option<&Vec<u8>>) -> u32 {
        let key = (family, ifindex, gateway.cloned().unwrap_or_default());
        if let Some(&id) = self.nh_ids.get(&key) {
            return id;
        }
        let id = self.next_nh_id;
        self.next_nh_id += 1;
        self.nh_ids.insert(key, id);
        id
    }

    /// 某个位址族目前配置出去的成员 ID（family, ifindex, gateway bytes）
    fn member_keys_for_family(&self, family: u8) -> Vec<(u8, u32, Vec<u8>)> {
        self.nh_ids
            .keys()
            .filter(|k| k.0 == family)
            .cloned()
            .collect()
    }

    /// 发送 Netlink 请求并等待内核 ACK 回应（会校验 nlmsg_seq 是否匹配）
    #[cfg(target_os = "linux")]
    fn send_and_wait_ack(&mut self, buf: &[u8]) -> io::Result<()> {
        let sent = unsafe {
            libc::send(
                self.sock_fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut recv_buf = [0u8; 4096];

        for _ in 0..ACK_RETRY_LIMIT {
            let n = unsafe {
                libc::recv(
                    self.sock_fd,
                    recv_buf.as_mut_ptr() as *mut libc::c_void,
                    recv_buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // SO_RCVTIMEO 到期会回传 EAGAIN / EWOULDBLOCK
                return Err(io::Error::new(
                    e.kind(),
                    format!("Netlink recv failed: {e}"),
                ));
            }

            let len = n as usize;
            let nlhdr = match NlMsgHdr::from_bytes(&recv_buf[..len]) {
                Some(h) => h,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Netlink response truncated",
                    ));
                }
            };

            // 忽略滞留的旧回应，只处理与本次请求 seq 相同的 ACK
            if nlhdr.nlmsg_seq != self.seq {
                debug!(
                    "[RouteManager] Skipping stale netlink message (seq {} != {})",
                    nlhdr.nlmsg_seq, self.seq
                );
                continue;
            }

            if nlhdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
                let err = read_i32(&recv_buf[..len], NlMsgHdr::LEN).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Netlink error response truncated",
                    )
                })?;
                if err != 0 {
                    // 内核会把「为什么失败」放在 extack（NLMSGERR_ATTR_MSG）里，例如
                    // "Invalid scope" / "Can not change number of buckets" / "Nexthop has
                    // invalid gateway"。旧版直接丢掉，只剩一个没有上下文的 EINVAL——这里记下来。
                    // 用 warn 而不是 debug：这是排障时唯一能说明「哪个属性写错」的线索，
                    // 放在 debug 会在正式环境（预设 info）里被完全吃掉。
                    if let Some(msg) = Self::parse_extack(&recv_buf[..len], len) {
                        warn!("[RouteManager] kernel rejected the request: {msg}");
                    }
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "No matching netlink acknowledgement received",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn send_and_wait_ack(&mut self, _buf: &[u8]) -> io::Result<()> {
        Ok(())
    }

    /// 组出 RTM_NEWROUTE / RTM_DELROUTE 讯息。
    /// IPv4 与 IPv6 只差在 family 与网关位元组长度，其余结构完全一致，
    /// 因此在这里统一处理，避免两份逻辑走样。
    fn build_route_msg(
        priority: u32,
        family: u8,
        hops: &[RouteNexthop],
        msg_type: u16,
        flags: u16,
        seq: u32,
    ) -> Vec<u8> {
        Self::build_route_msg_ex(
            priority,
            family,
            RouteTarget {
                table: None,
                dst: None,
            },
            hops,
            msg_type,
            flags,
            seq,
        )
    }

    /// `build_route_msg` 的完整版：`RouteTarget` 把「表号 + 目的前缀」收敛成一个参数。
    fn build_route_msg_ex(
        priority: u32,
        family: u8,
        target: RouteTarget<'_>,
        hops: &[RouteNexthop],
        msg_type: u16,
        flags: u16,
        seq: u32,
    ) -> Vec<u8> {
        Self::build_route_msg_ex_proto(
            priority,
            family,
            target,
            hops,
            msg_type,
            flags,
            seq,
            RTPROT_MWAN4,
        )
    }

    /// 同 `build_route_msg_ex`，但可指定**删除**讯息使用的 protocol。
    ///
    /// 一般删除用 `RTPROT_MWAN4`（只删自己的路由）；启动清扫需要用
    /// `RTPROT_UNSPEC`（0 = 通配符），否则清不掉旧版本以 RTPROT_STATIC 留下的残留。
    #[allow(clippy::too_many_arguments)]
    fn build_route_msg_ex_proto(
        priority: u32,
        family: u8,
        target: RouteTarget<'_>,
        hops: &[RouteNexthop],
        msg_type: u16,
        flags: u16,
        seq: u32,
        delete_protocol: u8,
    ) -> Vec<u8> {
        let RouteTarget { table, dst } = target;
        let mut buffer: Vec<u8> = Vec::with_capacity(512);
        // 预留 nlmsghdr 空间
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        // 删除时 scope 一律填 RT_SCOPE_NOWHERE（与 iproute2 相同），
        // 否则内核会拿它与路由既有的 scope 比对，无网关路由（RT_SCOPE_LINK）
        // 会删不掉。建立时：若唯一存活路由没有网关（点对点 / PPPoE），
        // 其 scope 应为 RT_SCOPE_LINK。
        let rtm_scope = if msg_type == RTM_DELROUTE {
            RT_SCOPE_NOWHERE
        } else if hops.len() == 1 && hops[0].gateway.is_none() {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };

        let dst_len = dst.map_or(0, |(_, len)| len);
        // 下发时一率带专属 protocol；删除时用呼叫端指定的值（一般为 RTPROT_MWAN4，
        // 启动清扫为 RTPROT_UNSPEC）。内核 `fib_table_delete()` 在 `fc_protocol != 0`
        // 时会比对 protocol，因此带 0x4D 的删除只会命中我们自己下发的路由。
        let rtm_protocol = if msg_type == RTM_DELROUTE {
            delete_protocol
        } else {
            RTPROT_MWAN4
        };
        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            // 表号 > 255 时只能靠 RTA_TABLE 表达；这里两个栏位都填一致的值，
            // 核心以 RTA_TABLE 为准（rtm_table 的低位元组在 >255 时会被截断）
            rtm_table: table.map_or(RT_TABLE_MAIN, |t| (t & 0xFF) as u8),
            rtm_protocol,
            rtm_scope,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        buffer.extend_from_slice(&rtmsg.to_bytes());

        if let Some(t) = table {
            Self::append_attr(&mut buffer, RTA_TABLE, &t.to_ne_bytes());
        }
        // 目的前缀必须在 OIF / GATEWAY 之前比较好读，顺序核心不敏感
        if let Some((addr, _)) = dst {
            Self::append_attr(&mut buffer, RTA_DST, addr);
        }

        // 显式带上 metric，确保 NLM_F_REPLACE / RTM_DELROUTE 能命中同一个路由 key
        Self::append_attr(&mut buffer, RTA_PRIORITY, &priority.to_ne_bytes());

        if hops.len() == 1 {
            let hop = &hops[0];
            if let Some(gw) = &hop.gateway {
                Self::append_attr(&mut buffer, RTA_GATEWAY, gw);
            }
            Self::append_attr(&mut buffer, RTA_OIF, &hop.ifindex.to_ne_bytes());
        } else if hops.len() > 1 {
            // Multipath ECMP
            let mut mp_buffer: Vec<u8> = Vec::with_capacity(256);
            for hop in hops {
                let hop_start = mp_buffer.len();
                // weight 必须落在 1..=255，否则 rtnh_hops 会静默截断
                let weight = hop.weight.clamp(1, MAX_NEXTHOP_WEIGHT);
                let rtnh = RtNextHop {
                    rtnh_len: 0, // 待计算
                    rtnh_flags: 0,
                    rtnh_hops: (weight - 1) as u8,
                    rtnh_ifindex: hop.ifindex as i32,
                };
                mp_buffer.extend_from_slice(&rtnh.to_bytes());

                if let Some(gw) = &hop.gateway {
                    Self::append_attr(&mut mp_buffer, RTA_GATEWAY, gw);
                }

                // 回填此 nexthop 的长度（核心要求 rtnh_len 为未对齐的实际长度）
                let hop_len = mp_buffer.len() - hop_start;
                mp_buffer.resize(hop_start + rta_align(hop_len), 0);
                write_u16(&mut mp_buffer, hop_start, hop_len as u16);
            }
            Self::append_attr(&mut buffer, RTA_MULTIPATH, &mp_buffer);
        }
        let total_len = buffer.len() as u32;
        let nlhdr = NlMsgHdr {
            nlmsg_len: total_len,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        buffer[0..NlMsgHdr::LEN].copy_from_slice(&nlhdr.to_bytes());
        buffer
    }

    // -----------------------------------------------------------------------
    // nexthop object / resilient nexthop group（Linux 5.3+；resilient 需 5.14+）
    //
    // 为什么要用它：标准 RTA_MULTIPATH 路由在 nexthop 集合改变时（包含线路恢复
    // UP 加入新成员），核心会对「整条路由」重算 multipath hash，既有 flow 可能被
    // 改送到另一条 WAN、源 IP 一变 TCP 连线就死。resilient group 只会重新分配
    // 「故障成员」占用的 bucket，其余 flow 完全不受影响，真正做到连接粘滞。
    // -----------------------------------------------------------------------

    /// 组出单一 nexthop object 讯息（NHA_ID + NHA_OIF [+ NHA_GATEWAY]）
    fn build_nexthop_id_msg(
        seq: u32,
        family: u8,
        id: u32,
        ifindex: u32,
        gateway: Option<&[u8]>,
        msg_type: u16,
        flags: u16,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        buffer.extend_from_slice(&Self::nhmsg_bytes(family).to_bytes());

        Self::append_attr(&mut buffer, NHA_ID, &id.to_ne_bytes());
        Self::append_attr(&mut buffer, NHA_OIF, &ifindex.to_ne_bytes());
        if let Some(gw) = gateway {
            Self::append_attr(&mut buffer, NHA_GATEWAY, gw);
        }

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 组出 nexthop group 讯息。
    ///
    /// `buckets = Some(n)` 时附上 NHA_RES_GROUP / NHA_RES_GROUP_BUCKETS 与
    /// NHA_GROUP_TYPE = RES，形成 resilient group；`None` 则是一般 multipath group。
    ///
    /// bucket 数是 u16，且必须是 2 的幂、不小于成员数（核心会拒绝其它值）。
    fn build_nexthop_group_msg(
        seq: u32,
        group_id: u32,
        members: &[(u32, u32)],
        buckets: Option<u16>,
        msg_type: u16,
        flags: u16,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        // group 本身跨越位址族，nh_family 固定为 AF_UNSPEC
        buffer.extend_from_slice(&Self::nhmsg_bytes(AF_UNSPEC).to_bytes());

        Self::append_attr(&mut buffer, NHA_ID, &group_id.to_ne_bytes());

        // NHA_GROUP_TYPE 要在 NHA_GROUP 之前；核心靠它判定 resilient
        if buckets.is_some() {
            Self::append_attr(
                &mut buffer,
                NHA_GROUP_TYPE,
                &NEXTHOP_GRP_TYPE_RES.to_ne_bytes(),
            );
        }

        let mut grp: Vec<u8> = Vec::with_capacity(members.len() * NextHopGrp::LEN);
        for &(id, weight) in members {
            let w = weight.clamp(1, MAX_NEXTHOP_WEIGHT);
            let entry = NextHopGrp {
                id,
                weight: (w - 1) as u8,
                resvd1: 0,
                resvd2: 0,
            };
            grp.extend_from_slice(&entry.to_bytes());
        }
        Self::append_attr(&mut buffer, NHA_GROUP, &grp);

        if let Some(bucket_count) = buckets {
            // NHA_RES_GROUP 是巢状属性，内含 NHA_RES_GROUP_BUCKETS（u16，见该常数的注解）
            let mut res: Vec<u8> = Vec::with_capacity(16);
            Self::append_attr(&mut res, NHA_RES_GROUP_BUCKETS, &bucket_count.to_ne_bytes());
            // 必须带 NLA_F_NESTED，否则核心不按巢状属性解析（见该常数的注解）
            Self::append_attr(&mut buffer, NHA_RES_GROUP | NLA_F_NESTED, &res);
        }

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 组出删除单一 nexthop object 的讯息（只需要 NHA_ID）
    ///
    /// `family` 必须与「建立时」一致：成员是用 `AF_INET`/`AF_INET6` 建的，
    /// group 才是 `AF_UNSPEC`。内核查找待删物件时会比对 family，
    /// 写死 `AF_UNSPEC` 会让成员永远删不掉（回 `EINVAL`），
    /// 于是每轮重试都留下一个孤儿 nexthop object —— 实测堆到 69 个。
    /// 组出删除 nexthop object 的讯息。
    ///
    /// ⚠️ 内核 `nh_valid_get_del_req()` 要求 DELNEXTHOP 的 `nhmsg` 除了 family 以外
    /// **全部为零**（`nh_protocol || nh_resvd || nh_scope || nh_flags` 任一非零就回
    /// EINVAL "Invalid values in header"）。因此这里不能沿用 `nhmsg_bytes()`（它带
    /// RTPROT_STATIC）。旧版就是这样：删除请求被内核拒绝，而 `is_absent_object` 又把
    /// EINVAL 当成「本来就不存在」，于是 group/成员永远删不掉（netns 实测发现）。
    fn build_nexthop_del_msg(seq: u32, family: u8, id: u32) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        buffer.extend_from_slice(
            &NhMsg {
                nh_family: family,
                nh_scope: 0,
                nh_protocol: 0,
                nh_resvd: 0,
                nh_flags: 0,
            }
            .to_bytes(),
        );
        Self::append_attr(&mut buffer, NHA_ID, &id.to_ne_bytes());
        Self::finish_msg(&mut buffer, RTM_DELNEXTHOP, NLM_F_REQUEST | NLM_F_ACK, seq);
        buffer
    }

    /// 组出「引用 nexthop object」的预设路由讯息（RTA_PRIORITY + RTA_NH_ID）
    fn build_route_msg_via_nh(
        priority: u32,
        family: u8,
        nh_id: u32,
        msg_type: u16,
        flags: u16,
        seq: u32,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            // 建立/删除都用专属 protocol：删除只命中自己的路由（见 RTPROT_MWAN4）
            rtm_protocol: RTPROT_MWAN4,
            // 删除时 scope 必须是 NOWHERE（理由同 build_route_msg_ex）
            rtm_scope: if msg_type == RTM_DELROUTE {
                RT_SCOPE_NOWHERE
            } else {
                RT_SCOPE_UNIVERSE
            },
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        buffer.extend_from_slice(&rtmsg.to_bytes());

        // 删除时 nh_id 也是路由 key 的一部分，两种讯息务必带一致
        Self::append_attr(&mut buffer, RTA_PRIORITY, &priority.to_ne_bytes());
        Self::append_attr(&mut buffer, RTA_NH_ID, &nh_id.to_ne_bytes());

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    // -----------------------------------------------------------------------
    // 探针路径：`oif <wan> lookup <table>` 规则
    // -----------------------------------------------------------------------

    /// 组出 RTM_NEWRULE / RTM_DELRULE 讯息。
    ///
    /// 规则内容：family=AF_INET、`oif|iif <ifname>`、`lookup <table>`、指定 priority。
    /// 用 oif／iif 而不是 fwmark：探针 socket 正是 `SO_BINDTODEVICE` 绑定该装置，
    /// 而转发流量（oif = br-lan）自然不会命中。
    fn build_rule_msg(seq: u32, spec: RuleSpec<'_>, msg_type: u16, flags: u16) -> Vec<u8> {
        let RuleSpec {
            family,
            table,
            ifname,
            priority,
            output,
        } = spec;

        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        let hdr = FibRuleHdr {
            family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            // 表号一律用 FRA_TABLE 表达，这里留 0（RT_TABLE_UNSPEC）
            table: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        buffer.extend_from_slice(&hdr.to_bytes());

        Self::append_attr(&mut buffer, FRA_TABLE, &table.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &priority.to_ne_bytes());
        // 打上我们的来源标记：清扫时只删带这个标记的规则，不会误删第三方的规则
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);
        // 字串属性必须含结尾 NUL（长度 = 4 + name.len() + 1）
        let mut name = Vec::with_capacity(ifname.len() + 1);
        name.extend_from_slice(ifname.as_bytes());
        name.push(0);
        let name_attr = if output { FRA_OIFNAME } else { FRA_IIFNAME };
        Self::append_attr(&mut buffer, name_attr, &name);

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 组出策略分流规则（fib rule 的 `from`/`to` + 目标表；不含 oif）。
    fn build_policy_rule_msg(seq: u32, rule: &PolicyRule, msg_type: u16, flags: u16) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        let hdr = FibRuleHdr {
            family: AF_INET,
            dst_len: rule.destination.map_or(0, |(_, len)| len),
            src_len: rule.source.map_or(0, |(_, len)| len),
            tos: 0,
            // 表号一律用 FRA_TABLE 表达
            table: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        buffer.extend_from_slice(&hdr.to_bytes());

        Self::append_attr(&mut buffer, FRA_TABLE, &rule.table.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &rule.priority.to_ne_bytes());
        if let Some((addr, _)) = rule.source {
            Self::append_attr(&mut buffer, FRA_SRC, &addr.octets());
        }
        if let Some((addr, _)) = rule.destination {
            Self::append_attr(&mut buffer, FRA_DST, &addr.octets());
        }
        // 与探针规则共用来源标记：清扫时只删本程式下发的规则
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 同步策略分流规则：删掉不再需要的，安装/更新期望的。
    ///
    /// 与探针路径不同，这里做**差异比对**而不是每次全量重下：策略规则的优先序
    /// 与内容在执行期很少变动（只有目标 WAN 上下线会触发），全量重下只会制造
    /// 无谓的 netlink 往返与规则闪断。
    pub fn set_policy_rules(&mut self, wanted: &[PolicyRule]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;

        // 1) 删除不再需要的（wanted 以集合语意比对：内容改动＝旧的删、新的装）
        let stale: Vec<PolicyRule> = self
            .policy_rules
            .iter()
            .filter(|old| !wanted.contains(old))
            .cloned()
            .collect();
        for rule in stale {
            if let Err(e) = self.delete_policy_rule(&rule) {
                warn!(
                    "[RouteManager] Failed to remove policy rule '{}' (priority {}): {e}",
                    rule.name, rule.priority
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
                continue;
            }
            self.policy_rules.retain(|r| r != &rule);
        }

        // 2) 安装缺的
        for rule in wanted {
            if self.policy_rules.contains(rule) {
                continue;
            }
            match self.install_policy_rule(rule) {
                Ok(()) => self.policy_rules.push(rule.clone()),
                Err(e) => {
                    warn!(
                        "[RouteManager] Failed to install policy rule '{}' (priority {}): {e}",
                        rule.name, rule.priority
                    );
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn install_policy_rule(&mut self, rule: &PolicyRule) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_policy_rule_msg(
            seq,
            rule,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        self.commit_rule_msg(
            &msg,
            &format!(
                "policy rule '{}' (from {:?} to {:?} lookup {})",
                rule.name, rule.source, rule.destination, rule.table
            ),
        )
    }

    fn delete_policy_rule(&mut self, rule: &PolicyRule) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_policy_rule_msg(seq, rule, RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK);
        self.commit_rule_msg(
            &msg,
            &format!(
                "policy rule removal '{}' (priority {})",
                rule.name, rule.priority
            ),
        )
    }

    /// 清扫策略规则保留区段内本程式留下的所有规则（启动与退出共用）。
    pub fn sweep_policy_rules(&mut self) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let mut removed = 0usize;
        for slot in 0..POLICY_SLOT_MAX {
            match self.delete_own_rule_by_priority(POLICY_RULE_PRIORITY_BASE + slot) {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if removed > 0 {
            info!(
                "[RouteManager] Removed {removed} leftover policy rule(s) from the reserved band"
            );
        }
        self.policy_rules.clear();
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 把「期望的探针路径集合」与目前已下发的做差异比对：删掉多的，并**重下所有期望的**。
    ///
    /// 这是**幂等**操作（规则与表内路由都用 CREATE|REPLACE），可以每个心跳周期重复呼叫；
    /// 「全部重下」而不只补缺的，是因为规则／表内路由也可能被外部（其它程序、内核事件、
    /// 手工 `ip rule del`）改掉，只比对自己的记录就永远修不回来。
    /// 任何一步失败都只记录第一条错误，好让下个周期重试。
    pub fn set_probe_paths(&mut self, wanted: &[ProbePath]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let wanted_names: std::collections::HashSet<&str> =
            wanted.iter().map(|p| p.ifname.as_str()).collect();

        // 1) 先删掉不再需要的（先删规则再删表内路由）
        let stale: Vec<ProbePath> = self
            .probe_paths
            .iter()
            .filter(|(name, _)| !wanted_names.contains(name.as_str()))
            .map(|(_, p)| p.clone())
            .collect();
        for path in stale {
            if let Err(e) = self.remove_probe_path(&path) {
                warn!(
                    "[RouteManager] Failed to remove probe path for {}: {e}",
                    path.ifname
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
                continue;
            }
            self.probe_paths.remove(&path.ifname);
        }

        // 2) 重下所有期望的（含已经下发过的；内容有变也一并覆盖）
        for path in wanted {
            // 内容有变（含主表 /32 子集变动）时，必须先把旧的
            // 完整拆掉再装，否则主表那条 /32 会留在不该留的时候。
            if let Some(prev) = self.probe_paths.get(&path.ifname) {
                if prev != path {
                    if let Err(e) = self.remove_probe_path(&prev.clone()) {
                        warn!(
                            "[RouteManager] Failed to update probe path for {}: {e}",
                            path.ifname
                        );
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                        continue;
                    }
                    self.probe_paths.remove(&path.ifname);
                }
            }
            match self.install_probe_path(path) {
                Ok(()) => {
                    self.probe_paths.insert(path.ifname.clone(), path.clone());
                }
                Err(e) => {
                    debug!(
                        "[RouteManager] Probe path for {} not ready yet ({e}); will retry",
                        path.ifname
                    );
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // -----------------------------------------------------------------------
    // 路由查询 / 转储：用来「问内核」而不是靠猜
    //
    // 为什么需要：
    //   * 探针路径要不要补主表 /32，取决于「主表到底有没有涵盖这个目标」；
    //   * 探针以「超时」失败时，要能分辨「线路真的不通」与「本机根本没路」
    //     （后者内核会按 on-link 把封包丢进黑洞，表现就是超时）。
    // -----------------------------------------------------------------------

    /// 组出 RTM_GETROUTE 请求（`oif` 有值时一并带上 RTA_OIF，模拟绑定该设备的查找）
    fn build_getroute_msg(
        family: u8,
        seq: u32,
        dst: Option<(Ipv4Addr, u8)>,
        oif: Option<u32>,
        dump: bool,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        let dst_len = dst.map_or(0, |(_, len)| len);
        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        buffer.extend_from_slice(&rtmsg.to_bytes());

        if let Some((addr, _)) = dst {
            Self::append_attr(&mut buffer, RTA_DST, &addr.octets());
        }
        if let Some(index) = oif {
            Self::append_attr(&mut buffer, RTA_OIF, &index.to_ne_bytes());
        }

        let flags = if dump {
            NLM_F_REQUEST | NLM_F_DUMP
        } else {
            NLM_F_REQUEST
        };
        Self::finish_msg(&mut buffer, RTM_GETROUTE, flags, seq);
        buffer
    }

    /// 内核在「查不到路由」时回的 errno（是查询结果，不是失败）
    #[cfg(target_os = "linux")]
    fn is_no_route_errno(errno: i32) -> bool {
        matches!(
            errno,
            libc::ENETUNREACH | libc::ENETDOWN | libc::EHOSTUNREACH
        )
    }

    /// 解析一则 RTM_NEWROUTE 讯息 → RouteLookup
    fn parse_route_reply(buf: &[u8], len: usize) -> Option<RouteLookup> {
        if len < NlMsgHdr::LEN + RtMsg::LEN {
            return None;
        }
        let mut table = u32::from(buf[NlMsgHdr::LEN + 4]);
        let mut ifindex = None;
        let mut gateway = None;

        let mut off = NlMsgHdr::LEN + RtMsg::LEN;
        while off + RtAttr::LEN <= len {
            let rta_len = read_u16(buf, off)? as usize;
            let rta_type = read_u16(buf, off + 2)?;
            if rta_len < RtAttr::LEN || off + rta_len > len {
                break;
            }
            let data = &buf[off + RtAttr::LEN..off + rta_len];
            match rta_type {
                RTA_TABLE => {
                    if let Some(v) = read_u32(data, 0) {
                        table = v;
                    }
                }
                RTA_OIF => {
                    ifindex = read_u32(data, 0);
                }
                RTA_GATEWAY if data.len() == 4 => {
                    gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                }
                _ => {}
            }
            off += rta_align(rta_len);
        }
        Some(RouteLookup {
            ifindex,
            gateway,
            table,
        })
    }

    /// 询问内核：到 `dst` 的路由是什么？`oif` 有值时模拟「绑定该设备」的查找。
    ///
    /// 回传 `Ok(None)` 代表内核说「没有可用的路」（ENETUNREACH 等）——这正是
    /// 「探针会一直超时」的本机讯号，呼叫端可据此设定 local_condition。
    #[cfg(target_os = "linux")]
    pub fn lookup_route(
        &mut self,
        dst: Ipv4Addr,
        oif: Option<u32>,
    ) -> io::Result<Option<RouteLookup>> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_getroute_msg(AF_INET, seq, Some((dst, 32)), oif, false);

        let sent = unsafe {
            libc::send(
                self.sock_fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = [0u8; 4096];
        for _ in 0..ACK_RETRY_LIMIT {
            let n = unsafe {
                libc::recv(
                    self.sock_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let len = n as usize;
            let hdr = match NlMsgHdr::from_bytes(&buf[..len]) {
                Some(h) => h,
                None => continue,
            };
            if hdr.nlmsg_seq != self.seq {
                continue;
            }
            if hdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
                match read_i32(&buf[..len], NlMsgHdr::LEN) {
                    // 「没有路」是查询的正常结果，不是错误
                    Some(code) if code < 0 && Self::is_no_route_errno(code.saturating_neg()) => {
                        return Ok(None);
                    }
                    // 其它 errno（EINVAL/EPERM…）是真错误：不能当成「没有路由」，
                    // 否则呼叫端会把 query 失败误判成路径缺失而乱补 /32
                    Some(code) if code < 0 => {
                        return Err(io::Error::from_raw_os_error(code.saturating_neg()));
                    }
                    _ => {
                        return Err(io::Error::other(
                            "route lookup rejected by the kernel without an errno",
                        ));
                    }
                }
            }
            if hdr.nlmsg_type == RTM_NEWROUTE {
                return Ok(Self::parse_route_reply(&buf[..len], len));
            }
            return Ok(None);
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no route lookup reply",
        ))
    }

    /// 发送 route dump 并收集所有 `RTM_NEWROUTE` 的原始讯息。
    ///
    /// 比逐字重写两个 dump 回圈多做了两件事：
    /// - **只认 seq 相符的 `NLMSG_DONE`**：上一次逾时中断的 dump 会在接收伫列留下
    ///   一则旧 `NLMSG_DONE`，下一次 dump 读到它就会提早结束（假阴性）。
    /// - **`NLM_F_DUMP_INTR` 自动重试一次**：dump 期间路由表变动时内核会把资料
    ///   标成不完整；重试一次通常能拿到一致快照。
    #[cfg(target_os = "linux")]
    fn dump_route_messages(&mut self, family: u8) -> io::Result<Vec<Vec<u8>>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        for attempt in 0..2 {
            self.seq += 1;
            let seq = self.seq;
            let msg = Self::build_getroute_msg(family, seq, None, None, true);
            let sent = unsafe {
                libc::send(
                    self.sock_fd,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            if sent as usize != msg.len() {
                return Err(io::Error::other("short netlink send for route dump"));
            }

            let mut out: Vec<Vec<u8>> = Vec::new();
            let mut buf = [0u8; 8192];
            // 回圈的唯一出口是读到本次 seq 的 NLMSG_DONE；中断旗标由内核标在 DONE 上
            let interrupted = 'outer: loop {
                let n = unsafe {
                    libc::recv(
                        self.sock_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                let len = n as usize;
                let mut offset = 0usize;
                while offset + NlMsgHdr::LEN <= len {
                    let hdr = match NlMsgHdr::from_bytes(&buf[offset..len]) {
                        Some(h) => h,
                        None => break,
                    };
                    let msg_len = hdr.nlmsg_len as usize;
                    if msg_len < NlMsgHdr::LEN || offset + msg_len > len {
                        break;
                    }
                    if hdr.nlmsg_type == libc::NLMSG_DONE as u16 {
                        if hdr.nlmsg_seq == seq {
                            break 'outer (hdr.nlmsg_flags & NLM_F_DUMP_INTR) != 0;
                        }
                        // 旧 dump 残留的 DONE（seq 不符）：跳过，继续等本次的
                    } else if hdr.nlmsg_type == libc::NLMSG_ERROR as u16 && hdr.nlmsg_seq == seq {
                        let code = read_i32(&buf[offset..offset + msg_len], NlMsgHdr::LEN);
                        return Err(match code {
                            Some(c) if c < 0 => io::Error::from_raw_os_error(c.saturating_neg()),
                            _ => io::Error::other("route dump rejected by the kernel"),
                        });
                    } else if hdr.nlmsg_type == RTM_NEWROUTE && hdr.nlmsg_seq == seq {
                        out.push(buf[offset..offset + msg_len].to_vec());
                    }
                    offset += crate::netlink::util::nlmsg_align(msg_len);
                }
            };
            result = out;
            if !interrupted {
                return Ok(result);
            }
            if attempt == 0 {
                debug!(
                    "[RouteManager] route dump was interrupted (NLM_F_DUMP_INTR); retrying once"
                );
            }
        }
        Ok(result)
    }

    /// 转储主表中 metric == `metric` 的所有路由（用于清扫自己留下的探针 /32）。
    ///
    /// 回传 `(表号, 目的位址, 前缀长度)`；只认 32 位元前缀（我们只下发 /32）。
    #[cfg(target_os = "linux")]
    pub fn dump_host_routes_with_metric(
        &mut self,
        metric: u32,
    ) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        let mut out = Vec::new();
        for body in self.dump_route_messages(AF_INET)? {
            // 内核正常不会送出短于 rtmsg 的讯息，但这是「靠内核保证」的不变量：
            // 少一个位元组就会 panic（release 下 panic=abort，整个 daemon 直接死）。
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let msg_len = body.len();
            let dst_len = body[NlMsgHdr::LEN + 1];
            let mut priority = None;
            let mut dst = None;
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let mut off = NlMsgHdr::LEN + RtMsg::LEN;
            while off + RtAttr::LEN <= msg_len {
                let rta_len = read_u16(&body, off).unwrap_or(0) as usize;
                let rta_type = read_u16(&body, off + 2).unwrap_or(0);
                if rta_len < RtAttr::LEN || off + rta_len > msg_len {
                    break;
                }
                let data = &body[off + RtAttr::LEN..off + rta_len];
                match rta_type {
                    RTA_PRIORITY => priority = read_u32(data, 0),
                    RTA_DST if data.len() == 4 => {
                        dst = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
                    }
                    RTA_TABLE => table = read_u32(data, 0).unwrap_or(table),
                    _ => {}
                }
                off += rta_align(rta_len);
            }
            if priority == Some(metric) && dst_len == 32 {
                if let Some(addr) = dst {
                    out.push((table, addr, dst_len));
                }
            }
        }
        Ok(out)
    }

    /// 主表有没有**任何**预设路由（含我们自己下发的那条）。
    ///
    /// 这是「非活跃线需不需要补 /32」的正确判据：
    /// - loose/off：只要主表有预设路由，任何设备的回程都能通过反向检查 → 不需要补；
    /// - 完全没有预设路由（全断、或唯一存活线故障）→ 才需要补，否则那条线永远收不到回程。
    ///
    /// 注意**不能**用「有没有到目标的路」来判断：我们自己下发的探针 /32 也是「到目标的路」，
    /// 会形成自我参照（补了 → 认为已涵盖 → 删掉 → 又没涵盖 → 再补）而造成振荡。
    /// 预设路由（dst_len = 0）永远不会是我们的 /32，因此没有这个问题。
    #[cfg(target_os = "linux")]
    pub fn has_main_default_route(&mut self, family: u8) -> io::Result<bool> {
        Ok(!self.dump_default_routes(family)?.is_empty())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_main_default_route(&mut self, _family: u8) -> io::Result<bool> {
        Ok(false)
    }

    /// 转储主表中「不是我们的」预设路由（用于判断全断时有没有兜底可接手）。
    ///
    /// 回传 `(表号, metric)`；已排除 `skip_metric`（我们自己那条）。
    #[cfg(target_os = "linux")]
    pub fn dump_other_default_routes(
        &mut self,
        family: u8,
        skip_metric: u32,
    ) -> io::Result<Vec<(u32, u32)>> {
        Ok(self
            .dump_default_routes(family)?
            .into_iter()
            .filter(|(_, metric)| *metric != skip_metric)
            .collect())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn dump_other_default_routes(
        &mut self,
        _family: u8,
        _skip_metric: u32,
    ) -> io::Result<Vec<(u32, u32)>> {
        Ok(Vec::new())
    }

    /// 转储主表里的所有预设路由 → `(表号, metric)`
    #[cfg(target_os = "linux")]
    fn dump_default_routes(&mut self, family: u8) -> io::Result<Vec<(u32, u32)>> {
        let mut out = Vec::new();
        for body in self.dump_route_messages(family)? {
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let msg_len = body.len();
            let dst_len = body[NlMsgHdr::LEN + 1];
            let mut priority = None;
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let mut off = NlMsgHdr::LEN + RtMsg::LEN;
            while off + RtAttr::LEN <= msg_len {
                let rta_len = read_u16(&body, off).unwrap_or(0) as usize;
                let rta_type = read_u16(&body, off + 2).unwrap_or(0);
                if rta_len < RtAttr::LEN || off + rta_len > msg_len {
                    break;
                }
                let data = &body[off + RtAttr::LEN..off + rta_len];
                match rta_type {
                    RTA_PRIORITY => priority = read_u32(data, 0),
                    RTA_TABLE => table = read_u32(data, 0).unwrap_or(table),
                    _ => {}
                }
                off += rta_align(rta_len);
            }
            let prio = priority.unwrap_or(0);
            // 只认主表：(1) 我们的探针表里也有 default，若不按表号过滤会被误判成
            // 「主表有预设路由」（实测踩过），(2) 全断时的兜底判断也靠这个。
            if dst_len == 0 && table == u32::from(RT_TABLE_MAIN) {
                out.push((table, prio));
            }
        }
        debug!("[RouteManager] main-table default routes: {out:?}");
        Ok(out)
    }

    /// 非 Linux 平台（只在 Windows 上 `cargo check` 用）没有 netlink，查询一律回「查不到」
    #[cfg(not(target_os = "linux"))]
    pub fn lookup_route(
        &mut self,
        _dst: Ipv4Addr,
        _oif: Option<u32>,
    ) -> io::Result<Option<RouteLookup>> {
        Ok(None)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn dump_host_routes_with_metric(
        &mut self,
        _metric: u32,
    ) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        Ok(Vec::new())
    }

    /// 清掉主表里**探针**的 /32（metric `PROBE_MAIN_ROUTE_METRIC`），不论目标是否还在
    /// 设定里。
    ///
    /// 这是执行期（`SetProbePaths(clean = true)`）该用的入口：**不含 underlay /32**，
    /// 因为 underlay 是执行期资产，同一批指令里才刚由 `Apply` 装好（见
    /// `RUNTIME_SWEEP_METRICS` 的说明）。启动时要清干净请用 `sweep_all_own_host_routes`。
    pub fn sweep_own_probe_host_routes(&mut self) -> io::Result<usize> {
        self.sweep_host_routes_for(&RUNTIME_SWEEP_METRICS)
    }

    /// 清掉主表里所有属于本程式的 /32（探针 + 隧道 underlay），不论目标是否还在设定里。
    ///
    /// **只供启动前使用**：上次执行留下的 underlay /32 出口可能已经失效，而
    /// `sync_underlay_routes` 的快取是空的（重启后），不清就会留下指向旧网关的 /32。
    pub fn sweep_all_own_host_routes(&mut self) -> io::Result<usize> {
        self.sweep_host_routes_for(&STARTUP_SWEEP_METRICS)
    }

    /// 依给定的 metric 清单清扫主表 /32（探针与 underlay 共用这段逻辑）
    fn sweep_host_routes_for(&mut self, metrics: &[(u32, &str)]) -> io::Result<usize> {
        let mut removed = 0;
        for (metric, kind) in metrics {
            removed += self.sweep_host_routes_with_metric(*metric, kind)?;
        }
        Ok(removed)
    }

    /// 依 metric 把主表里属于我们的 /32 清干净（探针与 underlay 共用这段逻辑）
    fn sweep_host_routes_with_metric(&mut self, metric: u32, kind: &str) -> io::Result<usize> {
        let victims = self.dump_host_routes_with_metric(metric)?;
        let mut removed = 0;
        for (table, dst, dst_len) in victims {
            // 只清主表：我们所有探针 /32 与 underlay /32 都下发在主表；其它表里
            // 刚好同 metric 的 /32 是第三方的，不该碰（dump 不过滤表号）。
            if table != u32::from(RT_TABLE_MAIN) {
                debug!(
                    "[RouteManager] Ignoring non-main-table {kind} host route {dst}/{dst_len} in table {table}"
                );
                continue;
            }
            // 主表用 rtm_table（254）表达、不带 RTA_TABLE——与我们下发时的形式一致。
            // 实测：对主表的路由带 RTA_TABLE 去删，内核会回 ESRCH 而路由仍在。
            debug!(
                "[RouteManager] Removing stale {kind} host route {dst}/{dst_len} in table {table} (metric {metric})"
            );
            self.seq += 1;
            let seq = self.seq;
            let octets = dst.octets();
            // 清扫专用：删除带 RTPROT_UNSPEC（通配符），才清得掉旧版本以
            // RTPROT_STATIC 留下的 /32；一般删除仍用专属 protocol（见 RTPROT_MWAN4）。
            let msg = Self::build_route_msg_ex_proto(
                metric,
                AF_INET,
                RouteTarget {
                    table: None,
                    dst: Some((&octets, dst_len)),
                },
                &[],
                RTM_DELROUTE,
                NLM_F_REQUEST | NLM_F_ACK,
                seq,
                RTPROT_UNSPEC,
            );
            match self.commit_probe_route(&msg, &format!("stale {kind} host route {dst}/{dst_len}"))
            {
                Ok(()) => removed += 1,
                Err(e) => {
                    warn!("[RouteManager] Failed to remove stale {kind} host route {dst}: {e}")
                }
            }
        }
        if removed > 0 {
            info!(
                "[RouteManager] Removed {removed} stale {kind} host route(s) from the main table"
            );
        }
        Ok(removed)
    }

    /// 清扫本程式保留区段内残留的探针规则。
    ///
    /// 为什么需要：表号／规则优先序是按介面在设定档中的顺序配置的。若上一次执行
    /// 的顺序与这次不同，就会留下「oif <wan> lookup <旧表>」的规则，而那个旧表里
    /// 是一条指向旧闸道的预设路由——探针会被导去错的闸道。启动时先扫干净最省事。
    ///
    /// **只删带 `PROBE_RULE_PROTOCOL` 标记的规则**：不会动到第三方（mwan3 / VPN 等）
    /// 即使它们刚好也用 10000..10063 这个优先序区段。表内残留的路由则不再主动扫
    /// （没有规则指向它就是惰性的，而我们重用该表时会直接 REPLACE）。
    pub fn sweep_probe_paths(&mut self) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let mut removed = 0usize;
        for slot in 0..PROBE_SLOT_MAX {
            match self.delete_own_rule_by_priority(PROBE_RULE_PRIORITY_BASE + slot) {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if removed > 0 {
            info!("[RouteManager] Removed {removed} leftover probe rule(s) from the reserved band");
        }
        // 清扫只是为了收拾残局，失败不应阻止启动
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 只靠「优先序 + 我们的来源标记」删除一条自己的规则（不需要知道它的 oif／表号）。
    /// 回传是否真的删掉了一条。
    fn delete_own_rule_by_priority(&mut self, priority: u32) -> io::Result<bool> {
        self.seq += 1;
        let seq = self.seq;
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        let hdr = FibRuleHdr {
            family: AF_INET,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        buffer.extend_from_slice(&hdr.to_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &priority.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);
        Self::finish_msg(&mut buffer, RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, seq);
        match self.send_and_wait_ack(&buffer) {
            Ok(()) => Ok(true),
            Err(e) if Self::is_absent_object(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 删掉「这次设定会用到」的所有探针目标在主表的 /32（不论是否需要）。
    ///
    /// 保留此函式是为了向后相容；新流程请用 `sweep_own_probe_host_routes`（按 metric
    /// 转储扫描，能清掉已从设定移除或当时设备不存在的残留）。
    ///
    /// **删除讯息刻意不带 nexthop**：只按 (table, dst, metric) 命中。带了 RTA_OIF /
    /// RTA_GATEWAY 时，若那条路由的闸道或 ifindex 后来变过（DHCP 续约、PPPoE 重拨、
    /// 设备重建），内核会回 ESRCH 而路由其实还在——残留就永远清不掉。
    #[allow(dead_code)]
    pub fn clear_probe_host_routes(&mut self, paths: &[ProbePath]) {
        for path in paths {
            for target in &path.targets {
                self.seq += 1;
                let seq = self.seq;
                let octets = target.octets();
                let msg = Self::build_route_msg_ex(
                    PROBE_MAIN_ROUTE_METRIC,
                    AF_INET,
                    RouteTarget {
                        table: None,
                        dst: Some((&octets, 32)),
                    },
                    &[],
                    RTM_DELROUTE,
                    NLM_F_REQUEST | NLM_F_ACK,
                    seq,
                );
                let _ =
                    self.commit_probe_route(&msg, &format!("probe host route cleanup {target}/32"));
            }
        }
    }

    /// 下发单一探针路径：出向规则 → 出向表内预设路由 →（必要时）主表探针目标 /32
    fn install_probe_path(&mut self, path: &ProbePath) -> io::Result<()> {
        // 1) 出向规则（oif）
        self.seq += 1;
        let seq = self.seq;
        let rule = Self::build_rule_msg(
            seq,
            RuleSpec {
                family: AF_INET,
                table: path.table,
                ifname: &path.ifname,
                priority: path.priority,
                output: true,
            },
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        self.commit_rule_msg(
            &rule,
            &format!("probe rule (oif {} lookup {})", path.ifname, path.table),
        )?;

        // 2) 出向表内的预设路由（探针要走的路）
        let hop = RouteNexthop {
            ifindex: path.ifindex,
            gateway: path.gateway.map(|g| g.octets().to_vec()),
            weight: 1,
        };
        self.seq += 1;
        let seq = self.seq;
        let route = Self::build_route_msg_ex(
            0,
            AF_INET,
            RouteTarget {
                table: Some(path.table),
                dst: None,
            },
            std::slice::from_ref(&hop),
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        );
        self.commit_probe_route(
            &route,
            &format!("probe default route in table {}", path.table),
        )?;

        // 3) 需要时在主表补探针目标的 /32（让 rp_filter 的反向路径查询找得到路）
        if !path.main_route_targets.is_empty() {
            let hop = RouteNexthop {
                ifindex: path.ifindex,
                gateway: path.gateway.map(|g| g.octets().to_vec()),
                weight: 1,
            };
            for target in &path.main_route_targets {
                self.seq += 1;
                let seq = self.seq;
                let octets = target.octets();
                let msg = Self::build_route_msg_ex(
                    PROBE_MAIN_ROUTE_METRIC,
                    AF_INET,
                    RouteTarget {
                        table: None,
                        dst: Some((&octets, 32)),
                    },
                    std::slice::from_ref(&hop),
                    RTM_NEWROUTE,
                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
                    seq,
                );
                self.commit_probe_route(
                    &msg,
                    &format!("probe host route {target}/32 via {}", path.ifname),
                )?;
            }
        }

        Ok(())
    }

    /// 拆除单一探针路径（顺序与安装相反）
    fn remove_probe_path(&mut self, path: &ProbePath) -> io::Result<()> {
        // 1) 主表的探针目标 /32
        //    删除讯息**不带 nexthop**：只按 (table, dst, metric) 命中。带了 OIF/GATEWAY
        //    时若该路由的闸道或 ifindex 后来变过，内核会回 ESRCH 而路由仍在。
        if !path.main_route_targets.is_empty() {
            for target in &path.main_route_targets {
                self.seq += 1;
                let seq = self.seq;
                let octets = target.octets();
                let msg = Self::build_route_msg_ex(
                    PROBE_MAIN_ROUTE_METRIC,
                    AF_INET,
                    RouteTarget {
                        table: None,
                        dst: Some((&octets, 32)),
                    },
                    &[],
                    RTM_DELROUTE,
                    NLM_F_REQUEST | NLM_F_ACK,
                    seq,
                );
                let _ =
                    self.commit_probe_route(&msg, &format!("probe host route removal {target}/32"));
            }
        }

        // 2) 出向表内预设路由
        self.seq += 1;
        let seq = self.seq;
        let route = Self::build_route_msg_ex(
            0,
            AF_INET,
            RouteTarget {
                table: Some(path.table),
                dst: None,
            },
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        let route_res = self.commit_probe_route(
            &route,
            &format!("probe default route removal (table {})", path.table),
        );

        // 3) 出向规则
        self.seq += 1;
        let seq = self.seq;
        let rule = Self::build_rule_msg(
            seq,
            RuleSpec {
                family: AF_INET,
                table: path.table,
                ifname: &path.ifname,
                priority: path.priority,
                output: true,
            },
            RTM_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
        );
        let rule_res = self.commit_rule_msg(
            &rule,
            &format!(
                "probe rule removal (oif {} lookup {})",
                path.ifname, path.table
            ),
        );

        route_res.and(rule_res)
    }

    /// 送出规则讯息；「本来就不存在」（删除时的 ESRCH/ENOENT）与「已经存在」（EEXIST）
    /// 都算成功，这样整个安装／清除流程就是幂等的。
    fn commit_rule_msg(&mut self, buffer: &[u8], label: &str) -> io::Result<()> {
        match self.send_and_wait_ack(buffer) {
            Ok(()) => {
                debug!("[RouteManager] {label} committed.");
                Ok(())
            }
            Err(e) if Self::message_is_delete(buffer) && Self::is_absent_object(&e) => {
                debug!("[RouteManager] {label}: rule already absent.");
                Ok(())
            }
            Err(e) if e.raw_os_error() == Some(EEXIST) => {
                debug!("[RouteManager] {label}: rule already present.");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// 送出探针路径的路由讯息。与 `commit_msg` 的差别只在于成功时记 debug：
    /// 探针路径每 30 秒就会重下一次，用 info 会把日志洗掉。
    fn commit_probe_route(&mut self, buffer: &[u8], label: &str) -> io::Result<()> {
        match self.send_and_wait_ack(buffer) {
            Ok(()) => {
                debug!("[RouteManager] {label} committed.");
                Ok(())
            }
            Err(e) if Self::message_is_delete(buffer) && Self::is_absent_object(&e) => {
                debug!("[RouteManager] {label}: route already absent.");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn nhmsg_bytes(family: u8) -> NhMsg {
        NhMsg {
            nh_family: family,
            nh_scope: RT_SCOPE_UNIVERSE,
            nh_protocol: RTPROT_STATIC,
            nh_resvd: 0,
            nh_flags: 0,
        }
    }

    /// 把 nlmsghdr 回填到缓冲区开头
    fn finish_msg(buffer: &mut [u8], msg_type: u16, flags: u16, seq: u32) {
        let total_len = buffer.len() as u32;
        let nlhdr = NlMsgHdr {
            nlmsg_len: total_len,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        buffer[0..NlMsgHdr::LEN].copy_from_slice(&nlhdr.to_bytes());
    }

    /// 从 NLMSG_ERROR 回应里取出内核的 extack 说明字串（NLMSGERR_ATTR_MSG = 1）。
    ///
    /// 格式：`nlmsghdr` + `i32 error` + 原始请求的 `nlmsghdr` + 属性串流。
    fn parse_extack(buf: &[u8], len: usize) -> Option<String> {
        let mut off = NlMsgHdr::LEN + 4;
        // 被回传的原始请求标头（通常也是 16 bytes）
        if off + NlMsgHdr::LEN <= len {
            off += NlMsgHdr::LEN;
        }
        while off + 4 <= len {
            let alen = read_u16(buf, off)? as usize;
            let atype = read_u16(buf, off + 2)? & 0x3fff;
            if alen < 4 || off + alen > len {
                break;
            }
            if atype == 1 {
                let data = &buf[off + 4..off + alen];
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                if end > 0 {
                    return Some(String::from_utf8_lossy(&data[..end]).into_owned());
                }
            }
            off += rta_align(alen);
        }
        None
    }

    /// 这则讯息是不是「删除」？（nlmsg_type 就在标头里，直接读出来判断，
    /// 这样所有删除路径都能共用同一套「本来就不存在」的容错）
    fn message_is_delete(buf: &[u8]) -> bool {
        matches!(
            read_u16(buf, 4),
            Some(RTM_DELROUTE) | Some(RTM_DELRULE) | Some(RTM_DELNEXTHOP)
        )
    }

    /// 内核在删除一个「本来就不存在」的物件时回：路由 → ESRCH、规则 → ENOENT。
    /// 只容忍这两种，**不再把 EINVAL 当成 absent**：EINVAL 代表请求本身有问题
    /// （例如 DELNEXTHOP 的 header 带了非零的 protocol），吞掉它会让删除永远
    /// 失败却毫无告警（netns 实测踩到：nexthop group/成员默默残留）。
    fn is_absent_object(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(ESRCH) | Some(ENOENT))
    }

    /// 送出 netlink 讯息并等待 ACK；「本来就不存在」（删除时）与「已经存在」
    /// （规则建立时）都算成功，让整个流程幂等。
    fn commit_msg(&mut self, buffer: &[u8], label: &str) -> io::Result<()> {
        debug!(
            "[RouteManager] Sending {label} (len: {} bytes)",
            buffer.len()
        );
        match self.send_and_wait_ack(buffer) {
            Ok(()) => {
                info!("[RouteManager] {label} committed.");
                Ok(())
            }
            Err(e) if Self::message_is_delete(buffer) && Self::is_absent_object(&e) => {
                debug!("[RouteManager] {label}: object already absent, nothing to do.");
                Ok(())
            }
            Err(e) => {
                // 旧版在这里静默回传 Err，导致「成员 nexthop 建成功、group 建失败」时
                // 日志里完全看不到是哪一步出问题，只剩上层一个没有上下文的 EINVAL。
                warn!("[RouteManager] {label} failed: {e}");
                Err(e)
            }
        }
    }

    /// 删除「本程式目前安装的」预设路由（IPv4 / IPv6 共用）。
    /// 用于「全部 WAN 断线」与「守护进程优雅退出」两种情境，
    /// 避免残留指向已失效链路的预设路由。
    ///
    /// 为什么要分派 variant：标准路由与 nh-id 路由是**不同的路由 key**，
    /// 用错删除报文内核只会回 ESRCH（然后被当成「本来就不存在」），
    /// 路由就永远留在核心里。只有删除成功（含本来就不存在）才清 bookkeeping，
    /// 失败时保留状态让后续心跳／清理能重试。
    fn remove_installed_default_route(&mut self, family: u8) -> io::Result<()> {
        match self.installed_variant(family) {
            InstalledVariant::None => {
                debug!(
                    "[RouteManager] {} default route was never installed by mwan4; leaving it alone",
                    Self::family_name(family)
                );
                Ok(())
            }
            InstalledVariant::Standard => {
                let res = self.delete_standard_route(family);
                if res.is_ok() {
                    self.set_installed_variant(family, InstalledVariant::None);
                }
                res
            }
            InstalledVariant::Resilient => {
                let group_id = Self::group_id_for(family);
                let res = self.delete_nh_route(family, group_id);
                if res.is_ok() {
                    self.set_installed_variant(family, InstalledVariant::None);
                    // 路由已不再引用 group，顺手把 group 与成员一起拆干净
                    self.teardown_resilient(family, group_id);
                }
                res
            }
        }
    }

    // -----------------------------------------------------------------------
    // 模式分派：标准 multipath vs. resilient nexthop group
    // -----------------------------------------------------------------------

    /// 计算隧道 underlay /32 路由的期望集合：`(对端, 出口 ifindex, 出口 gateway)`。
    ///
    /// 出口 = 非隧道的活跃 WAN 中 metric 最小者；同 metric 取先出现的（设定档顺序）。
    /// 刻意只挑「非隧道」的线：拿隧道去当另一条隧道的 underlay 会形成递回依赖。
    /// 若一条非隧道的线都没有（例如全部都是隧道），回传空集合 ——
    /// 此时不下发任何 /32，让预设路由自行决定，至少不比修复前更糟。
    fn plan_underlay_routes(
        active_wans: &[ActiveWanRoute],
    ) -> Vec<(Ipv4Addr, u32, Option<Vec<u8>>)> {
        let Some(exit) = active_wans
            .iter()
            .filter(|w| w.underlay_targets.is_empty())
            .min_by_key(|w| w.metric)
        else {
            return Vec::new();
        };

        let gw = exit.gateway.map(|g| g.octets().to_vec());
        let mut out = Vec::new();
        for wan in active_wans {
            for addr in &wan.underlay_targets {
                out.push((*addr, exit.ifindex, gw.clone()));
            }
        }
        out
    }

    /// 决定 `wanted` 里哪些 underlay /32 需要（重新）下发。
    ///
    /// `installed` 是本行程的记忆体快取，`kernel_present` 是刚从核心转储出来的实际集合。
    /// **不能只信快取**：启动清扫、外部 `ip route del`、别的行程覆盖都可能让核心里的 /32
    /// 消失，而快取仍记著「出口没变 → 已装好」→ 就再也不会补（实测：被清扫误删后
    /// 40 秒（含 30 秒心跳）一直是 0 条）。核心显示缺失时一律重下，`NLM_F_REPLACE`
    /// 本身幂等，重下的代价只有一个 netlink 往返。
    ///
    /// `kernel_present == None` 代表转储失败（查不到），此时退回快取判断：宁可这一轮
    /// 少下一次，也不要在每个心跳无条件重下全部（转储失败的告警已经另发）。
    fn plan_underlay_repairs(
        wanted: &[(Ipv4Addr, u32, Option<Vec<u8>>)],
        installed: &std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)>,
        kernel_present: Option<&std::collections::HashSet<Ipv4Addr>>,
    ) -> Vec<(Ipv4Addr, u32, Option<Vec<u8>>)> {
        wanted
            .iter()
            .filter(|(addr, ifindex, gateway)| {
                let cached_ok = installed
                    .get(addr)
                    .is_some_and(|(i, g)| i == ifindex && g == gateway);
                let in_kernel = kernel_present.is_none_or(|present| present.contains(addr));
                !(cached_ok && in_kernel)
            })
            .cloned()
            .collect()
    }

    /// 同步「隧道 underlay 对端」的 /32 路由（见 `UNDERLAY_ROUTE_METRIC`）。
    ///
    /// 为什么需要：隧道（VXLAN/WireGuard）的封装封包目的地是 underlay 对端，
    /// 而它得靠 main 表的预设路由送出。一旦预设路由是「含该隧道的 ECMP」，
    /// 就有约 1/N 的机率把封装封包再塞回同一条隧道 —— 自环。
    /// 症状是隧道大量丢包甚至完全不可用，而 `ip route get <对端>` 还会骗人：
    /// 它只反映固定哈希的单次采样，通常显示的是正确的那条。
    ///
    /// 解法：为每个对端补一条 /32（前缀比预设路由长，必然优先），
    /// 固定走「非隧道、metric 最小」的那条 WAN。
    fn sync_underlay_routes(&mut self, active_wans: &[ActiveWanRoute]) -> io::Result<()> {
        let wanted = Self::plan_underlay_routes(active_wans);

        // 0) 问核心「这些 /32 现在到底在不在」。记忆体快取只是快取：
        //    启动清扫、外部删除、或别的行程覆盖都会让它与现实脱节，
        //    只信快取就会卡在「自以为装好、其实一条都没有」的死状态。
        let kernel_present: Option<std::collections::HashSet<Ipv4Addr>> =
            match self.dump_host_routes_with_metric(UNDERLAY_ROUTE_METRIC) {
                Ok(rows) => Some(
                    rows.into_iter()
                        .filter(|(table, _, _)| *table == u32::from(RT_TABLE_MAIN))
                        .map(|(_, addr, _)| addr)
                        .collect(),
                ),
                Err(e) => {
                    warn!(
                        "[RouteManager] Could not dump underlay host routes ({e}); \
                         falling back to the in-memory cache for this round"
                    );
                    None
                }
            };

        // 1) 先删掉不再需要的（隧道下线、或出口换了）
        let stale: Vec<Ipv4Addr> = self
            .underlay_routes
            .keys()
            .filter(|addr| !wanted.iter().any(|(t, _, _)| t == *addr))
            .cloned()
            .collect();
        for addr in stale {
            if kernel_present
                .as_ref()
                .is_some_and(|present| !present.contains(&addr))
            {
                // 核心里已经没有这条：清掉快取即可，不必发一条注定 ESRCH 的删除
                debug!("[RouteManager] Underlay route {addr}/32 already gone from the kernel");
                self.underlay_routes.remove(&addr);
                continue;
            }
            if let Err(e) = self.delete_underlay_route(addr) {
                warn!("[RouteManager] Failed to remove underlay route {addr}/32: {e}");
                continue;
            }
            self.underlay_routes.remove(&addr);
        }

        // 2) 再补上缺的、出口变了的、以及核心其实没有的（自愈）
        for (addr, ifindex, gateway) in
            Self::plan_underlay_repairs(&wanted, &self.underlay_routes, kernel_present.as_ref())
        {
            self.install_underlay_route(addr, ifindex, gateway.clone())?;
            self.underlay_routes.insert(addr, (ifindex, gateway));
        }
        Ok(())
    }

    /// 下发一条隧道 underlay 对端的 /32 路由
    fn install_underlay_route(
        &mut self,
        target: Ipv4Addr,
        ifindex: u32,
        gateway: Option<Vec<u8>>,
    ) -> io::Result<()> {
        let hop = RouteNexthop {
            ifindex,
            gateway,
            weight: 1,
        };
        self.seq += 1;
        let seq = self.seq;
        let octets = target.octets();
        let msg = Self::build_route_msg_ex(
            UNDERLAY_ROUTE_METRIC,
            AF_INET,
            RouteTarget {
                table: None,
                dst: Some((&octets, 32)),
            },
            std::slice::from_ref(&hop),
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        );
        self.commit_msg(&msg, &format!("underlay route {target}/32 (oif {ifindex})"))
    }

    /// 删除一条隧道 underlay 对端的 /32 路由
    fn delete_underlay_route(&mut self, target: Ipv4Addr) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let octets = target.octets();
        let msg = Self::build_route_msg_ex(
            UNDERLAY_ROUTE_METRIC,
            AF_INET,
            RouteTarget {
                table: None,
                dst: Some((&octets, 32)),
            },
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        self.commit_msg(&msg, &format!("underlay route {target}/32 removal"))
    }

    // -----------------------------------------------------------------------
    /// 更新 IPv4 预设路由。实际下发方式由 `ecmp_mode` 决定。
    ///
    /// 传入空阵列代表「所有 WAN 皆断线」，此时会主动删除预设路由，
    /// 而不是什么都不做（旧行为会让流量继续送往已死的链路）。
    pub fn apply_default_routes(&mut self, active_wans: &[ActiveWanRoute]) -> io::Result<()> {
        Self::warn_out_of_range_weights(active_wans.iter().map(|w| (&w.ifname, w.weight)));
        if !active_wans.is_empty() {
            self.log_route_switch(
                "IPv4",
                &active_wans
                    .iter()
                    .map(|w| {
                        (
                            w.ifname.as_str(),
                            w.gateway.map(|g| g.to_string()),
                            w.weight,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }
        let hops = Self::normalize_v4(active_wans);

        // 先确保隧道 underlay 对端有 /32 可走：否则 ECMP 会依机率把封装封包
        // 再塞回隧道自己，形成自环（详见 `sync_underlay_routes`）。
        // 这里刻意只告警不中断：underlay /32 是「修正」，不该让预设路由因此不下发。
        if let Err(e) = self.sync_underlay_routes(active_wans) {
            warn!("[RouteManager] Failed to sync underlay routes: {e}");
        }

        match self.ecmp_mode {
            EcmpMode::Standard => {
                self.drop_resilient_if_active(AF_INET);
                self.apply_standard(AF_INET, &hops)
            }
            EcmpMode::Resilient => {
                self.apply_resilient_with_teardown(AF_INET, NH_GROUP_ID_V4, &hops)
            }
            EcmpMode::Auto => self.apply_auto(AF_INET, NH_GROUP_ID_V4, &hops),
        }
    }

    /// IPv6 版：只有当介面设定了 gateway6 时才会产生对应的 nexthop。
    /// IPv6 路由跟随同一个 IPv4 健康状态（实体是同一条链路），不另外探测。
    pub fn apply_ipv6_default_routes(
        &mut self,
        active_wans: &[ActiveWanRouteV6],
    ) -> io::Result<()> {
        Self::warn_out_of_range_weights(active_wans.iter().map(|w| (&w.ifname, w.weight)));
        if !active_wans.is_empty() {
            self.log_route_switch(
                "IPv6",
                &active_wans
                    .iter()
                    .map(|w| {
                        (
                            w.ifname.as_str(),
                            w.gateway.map(|g| g.to_string()),
                            w.weight,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }
        let hops = Self::normalize_v6(active_wans);
        match self.ecmp_mode {
            EcmpMode::Standard => {
                self.drop_resilient_if_active(AF_INET6);
                self.apply_standard(AF_INET6, &hops)
            }
            EcmpMode::Resilient => {
                self.apply_resilient_with_teardown(AF_INET6, NH_GROUP_ID_V6, &hops)
            }
            EcmpMode::Auto => self.apply_auto(AF_INET6, NH_GROUP_ID_V6, &hops),
        }
    }

    fn normalize_v4(active_wans: &[ActiveWanRoute]) -> Vec<RouteNexthop> {
        active_wans
            .iter()
            .map(|w| RouteNexthop {
                ifindex: w.ifindex,
                gateway: w
                    .gateway
                    .filter(|g| !g.is_unspecified())
                    .map(|g| g.octets().to_vec()),
                weight: w.weight,
            })
            .collect()
    }

    fn normalize_v6(active_wans: &[ActiveWanRouteV6]) -> Vec<RouteNexthop> {
        active_wans
            .iter()
            .map(|w| RouteNexthop {
                ifindex: w.ifindex,
                gateway: w
                    .gateway
                    .filter(|g| !g.is_unspecified())
                    .map(|g| g.octets().to_vec()),
                weight: w.weight,
            })
            .collect()
    }

    /// 全部 WAN 都判定 DOWN 时对预设路由的处理（IPv4/IPv6 共用）。
    ///
    /// 语意（实测决定，两边都是坑）：
    /// - **只有我们这一条预设路由** ⇒ 保留。删掉会让整机（含所有 LAN 客户端）完全没有出口，
    ///   而「线路回来时没人重下」正是原本自锁的成因之一。
    /// - **主表还有别人的预设路由**（例如 netifd 的 metric 10/50）⇒ 删掉我们这条，
    ///   让兜底接手。原因：载波掉（拔网线、对端下线）时内核**不会**自动移除
    ///   「dev 指到该设备」的路由，它只是标成 linkdown 并继续胜过 metric 更大的兜底，
    ///   流量会一直被送往死链路；删掉反而是救回上网的关键。
    ///
    /// 因为探针已经有自己的独立表（不依赖这条预设路由），删掉它不会让 daemon 失去探测能力。
    fn handle_all_links_down(&mut self, family: u8) -> io::Result<()> {
        let others = self
            .dump_other_default_routes(family, self.priority)
            .unwrap_or_default();

        if others.is_empty() {
            warn!(
                "[RouteManager] ALL WAN LINKS DOWN: keeping the {} default route (it is the only one; \
                 removing it would leave the router without any default route)",
                Self::family_name(family)
            );
            return Ok(());
        }

        let metrics: Vec<u32> = {
            let mut m: Vec<u32> = others.iter().map(|(_, priority)| *priority).collect();
            m.sort_unstable();
            m.dedup();
            m
        };
        warn!(
            "[RouteManager] ALL WAN LINKS DOWN: removing the mwan4 {} default route so the fallback \
             route(s) with metric {metrics:?} can take over (keeping it would blackhole traffic on \
             carrier-loss links, which the kernel does not remove by itself)",
            Self::family_name(family)
        );
        // 依实际安装的变体删除：resilient 是 nh-id 路由，标准删除报文的 key 对不上，
        // 会回 ESRCH 被当成「本来就不存在」，结果死链路的预设路由留在核心继续黑洞。
        // variant == None 时仍走标准删除：那可能是上一个进程留下的残留路由。
        match self.installed_variant(family) {
            InstalledVariant::Resilient => self.remove_installed_default_route(family)?,
            _ => {
                self.delete_standard_route(family)?;
                self.set_installed_variant(family, InstalledVariant::None);
            }
        }
        Ok(())
    }

    /// 标准 multipath 路由（RTA_MULTIPATH），也是 resilient 失败时的回退路径。
    /// 保持「原子 replace」语意，非模式切换时不会出现无预设路由的空窗。
    fn apply_standard(&mut self, family: u8, hops: &[RouteNexthop]) -> io::Result<()> {
        if hops.is_empty() {
            return self.handle_all_links_down(family);
        }

        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg(
            self.priority,
            family,
            hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        );
        self.commit_msg(
            &buffer,
            &format!("{} default route", Self::family_name(family)),
        )?;
        self.set_installed_variant(family, InstalledVariant::Standard);
        Ok(())
    }

    fn family_name(family: u8) -> &'static str {
        if family == AF_INET6 { "IPv6" } else { "IPv4" }
    }

    fn group_id_for(family: u8) -> u32 {
        if family == AF_INET6 {
            NH_GROUP_ID_V6
        } else {
            NH_GROUP_ID_V4
        }
    }

    /// 强制 resilient：失败时一定把残留清干净，避免半套状态卡住预设路由。
    fn apply_resilient_with_teardown(
        &mut self,
        family: u8,
        group_id: u32,
        hops: &[RouteNexthop],
    ) -> io::Result<()> {
        match self.apply_resilient(family, group_id, hops) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.teardown_resilient(family, group_id);
                Err(e)
            }
        }
    }

    /// Auto：先试 resilient，不行就（永久或暂时）退回标准 multipath。
    fn apply_auto(&mut self, family: u8, group_id: u32, hops: &[RouteNexthop]) -> io::Result<()> {
        if self.resilient_supported != Some(false) {
            match self.apply_resilient(family, group_id, hops) {
                Ok(()) => {
                    self.resilient_supported = Some(true);
                    return Ok(());
                }
                Err(e) => {
                    if Self::should_give_up_on_resilient(&e) {
                        warn!(
                            "[RouteManager] Resilient nexthop groups unavailable ({e}); \
                             falling back to standard ECMP for good"
                        );
                        self.resilient_supported = Some(false);
                    } else {
                        warn!(
                            "[RouteManager] Resilient nexthop update failed ({e}); \
                             falling back to standard ECMP for this round"
                        );
                    }
                    self.teardown_resilient(family, group_id);
                }
            }
        }
        self.apply_standard(family, hops)
    }

    /// 核心是否「根本不支援」nexthop object / resilient group。
    ///
    /// 只有真正的「不支援」才永久退回标准 ECMP。刻意**不把 EINVAL 算进来**：
    /// EINVAL 也涵盖「既有 group 的 bucket 数不同」「成员参数被拒」这类可用
    /// 拆除重建恢复的暂时性错误；把它当永久不支援会让 auto 模式一次失败就
    /// 再也不试 resilient（黏滞效果无声消失）。
    #[cfg(target_os = "linux")]
    fn should_give_up_on_resilient(e: &io::Error) -> bool {
        matches!(
            e.raw_os_error(),
            Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EAFNOSUPPORT)
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn should_give_up_on_resilient(_e: &io::Error) -> bool {
        true
    }

    fn installed_variant(&self, family: u8) -> InstalledVariant {
        if family == AF_INET6 {
            self.installed_v6
        } else {
            self.installed_v4
        }
    }

    /// 实际安装到核心的 IPv4 预设路由变体。
    ///
    /// 给主回圈判断 `flush_conntrack_on_switch` 是否该生效：`ecmp_mode=auto` 在
    /// 内核不支援 resilient 时会退回 standard，此时仍必须在切换瞬间清 conntrack
    /// （用设定值判断会误判成 resilient 而把清理关掉，见 FIX-8）。
    pub fn installed_ipv4_variant(&self) -> InstalledVariant {
        self.installed_v4
    }

    fn set_installed_variant(&mut self, family: u8, v: InstalledVariant) {
        if family == AF_INET6 {
            self.installed_v6 = v;
        } else {
            self.installed_v4 = v;
        }
    }

    fn has_any_member(&self, family: u8) -> bool {
        self.nh_ids.keys().any(|k| k.0 == family)
    }

    /// 从标准模式切走时，把残留的 resilient 产物（路由 + group + 成员）清掉
    fn drop_resilient_if_active(&mut self, family: u8) {
        let group_id = Self::group_id_for(family);
        if self.installed_variant(family) == InstalledVariant::Resilient
            || self.has_any_member(family)
        {
            self.teardown_resilient(family, group_id);
        }
    }

    /// 拆除 resilient 预设路由：先删路由（否则 group 仍被引用删不掉），
    /// 再删 group，最后才删成员。全程容忍「本来就不存在」。
    ///
    /// 只有原本真的是 Resilient 且**成功删除路由**时才会把 variant 清为 None；
    /// 原本是 Standard / None 时 variant 保持不变，否则标准路由的 bookkeeping
    /// 会被误清（`cleanup_routes` 就再也不会删它）。路由删除失败时直接返回，
    /// 此时删 group/成员只会拿到 EBUSY，且状态保留才能重试。
    fn teardown_resilient(&mut self, family: u8, group_id: u32) {
        if self.installed_variant(family) == InstalledVariant::Resilient {
            if let Err(e) = self.delete_nh_route(family, group_id) {
                warn!(
                    "[RouteManager] Failed to remove {} nexthop-group route ({e}); \
                     keeping the group for a later retry",
                    Self::family_name(family)
                );
                return;
            }
            self.set_installed_variant(family, InstalledVariant::None);
        }
        // group 本身是用 AF_UNSPEC 建的，删除时也要用 AF_UNSPEC
        let _ = self.delete_nexthop(AF_UNSPEC, group_id);
        for key in self.member_keys_for_family(family) {
            if let Some(id) = self.nh_ids.remove(&key) {
                if let Err(e) = self.delete_nexthop(family, id) {
                    warn!("[RouteManager] Failed to remove nexthop {id}: {e}");
                    self.nh_ids.insert(key, id);
                }
            }
        }
    }

    /// 用 resilient nexthop group 下发预设路由
    fn apply_resilient(
        &mut self,
        family: u8,
        group_id: u32,
        hops: &[RouteNexthop],
    ) -> io::Result<()> {
        // 全部断线时的处理与 apply_standard 一致（必须放在 variant 切换之前：
        // 否则会先把标准路由删掉再原地不动）
        if hops.is_empty() {
            return self.handle_all_links_down(family);
        }

        // bucket 上限检查必须在「删标准路由」之前：先删再发现无法用 resilient
        // 表达，会留下「没有预设路由」的空窗。
        if hops.len() > RES_BUCKETS_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} nexthops exceed the resilient bucket limit of {RES_BUCKETS_MAX}",
                    hops.len()
                ),
            ));
        }

        // 标准路由与 nh_id 路由的 key 不同，切换时必须先把旧的删掉，
        // 否则核心会保留两条 default route。
        if self.installed_variant(family) == InstalledVariant::Standard {
            self.delete_standard_route(family)?;
            self.set_installed_variant(family, InstalledVariant::None);
        }

        // 1) 确保成员 nexthop object 存在。ID 沿用既有配置，
        //    核心才会认为成员「没变」而保留它负责的 bucket。
        let mut members: Vec<(u32, u32)> = Vec::with_capacity(hops.len());
        for hop in hops {
            let id = self.alloc_nh_id(family, hop.ifindex, hop.gateway.as_ref());
            self.ensure_nexthop(family, id, hop.ifindex, hop.gateway.as_deref())?;
            members.push((id, hop.weight));
        }

        // bucket 数固定用上限（2 的幂、涵盖任何合法成员数）。
        // 为什么不按成员数取「最小的 2 的幂」：核心在 REPLACE 既有 group 时**不允许改变
        // bucket 数**（回 EINVAL "Can not change number of buckets"），而成员数跨越
        // 8→9 这类 2 的幂边界时 bucket 数会变动 → 当轮 resilient 失效；auto 模式若把
        // 这个 EINVAL 当成「核心不支援」还会永久退回 standard。固定上限同时让
        // bucket→成员的分配粒度更平滑（每个成员分到的桶更多）。
        let buckets = RES_BUCKETS_MAX as u16;
        self.ensure_nexthop_group(group_id, &members, buckets)?;

        // 3) 下发引用该 group 的预设路由
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg_via_nh(
            self.priority,
            family,
            group_id,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        );
        self.commit_msg(
            &buffer,
            &format!(
                "{} default route via resilient nexthop group",
                Self::family_name(family)
            ),
        )?;
        self.set_installed_variant(family, InstalledVariant::Resilient);

        // 4) group 已改指向新成员，这时删旧成员才不会拿到 EBUSY
        self.drop_unused_members(family, hops);
        Ok(())
    }

    fn ensure_nexthop(
        &mut self,
        family: u8,
        id: u32,
        ifindex: u32,
        gateway: Option<&[u8]>,
    ) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_nexthop_id_msg(
            seq,
            family,
            id,
            ifindex,
            gateway,
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        self.commit_msg(&buffer, &format!("nexthop {id} (oif {ifindex})"))
    }

    fn ensure_nexthop_group(
        &mut self,
        group_id: u32,
        members: &[(u32, u32)],
        buckets: u16,
    ) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_nexthop_group_msg(
            seq,
            group_id,
            members,
            Some(buckets),
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        self.commit_msg(
            &buffer,
            &format!(
                "resilient nexthop group {group_id} ({} members, {buckets} buckets)",
                members.len()
            ),
        )
    }

    /// 删除 nexthop object。`family` 要与建立时一致（见 `build_nexthop_del_msg`）。
    fn delete_nexthop(&mut self, family: u8, id: u32) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_nexthop_del_msg(seq, family, id);
        self.commit_msg(&buffer, &format!("nexthop {id} removal"))
    }

    /// 删掉已不在当前成员集合中的 nexthop object
    fn drop_unused_members(&mut self, family: u8, hops: &[RouteNexthop]) {
        let wanted: std::collections::HashSet<(u8, u32, Vec<u8>)> = hops
            .iter()
            .map(|h| (family, h.ifindex, h.gateway.clone().unwrap_or_default()))
            .collect();

        let stale: Vec<(u8, u32, Vec<u8>)> = self
            .nh_ids
            .keys()
            .filter(|k| k.0 == family && !wanted.contains(*k))
            .cloned()
            .collect();

        for key in stale {
            if let Some(id) = self.nh_ids.remove(&key) {
                if let Err(e) = self.delete_nexthop(family, id) {
                    warn!("[RouteManager] Failed to remove stale nexthop {id}: {e}");
                    self.nh_ids.insert(key, id);
                }
            }
        }
    }

    fn delete_standard_route(&mut self, family: u8) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg(
            self.priority,
            family,
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        self.commit_msg(
            &buffer,
            &format!("{} default route removal", Self::family_name(family)),
        )
    }

    fn delete_nh_route(&mut self, family: u8, group_id: u32) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg_via_nh(
            self.priority,
            family,
            group_id,
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        self.commit_msg(
            &buffer,
            &format!("{} nexthop-group route removal", Self::family_name(family)),
        )
    }

    /// 优雅退出时把本程式下发的所有路由 / nexthop 产物清干净。
    ///
    /// 注意：只有**我们真的下发过**预设路由时才删它。否则（例如开机至今全断、
    /// 从未接管的部署）那条 metric 0 的预设路由其实是 netifd 的，删掉就等于把
    /// 整台路由器的出口删了。
    pub fn cleanup_routes(&mut self) -> io::Result<()> {
        // 策略规则先拆：它们指向各 WAN 的探针表，必须在表被清空/拆除前移除
        if let Err(e) = self.sweep_policy_rules() {
            warn!("[RouteManager] Failed to remove policy rules on shutdown: {e}");
        }

        // 探针路径（规则 + 独立表内的路由）先拆，避免规则指向已空的表
        let _ = self.set_probe_paths(&[]);

        // 先按实际安装的变体删预设路由；这里不能先 teardown_resilient，
        // 否则 Standard 的 variant 会被清成 None，后面的 if 就永远不成立。
        let mut result = self.remove_installed_default_route(AF_INET);
        result = result.and(self.remove_installed_default_route(AF_INET6));

        // 隧道 underlay /32 也必须拆掉：它们指向的闸道可能已经失效，
        // 留著会让封装封包被黑洞到旧出口（优先于预设路由）。
        if let Err(e) = self.sync_underlay_routes(&[]) {
            warn!("[RouteManager] Failed to remove underlay routes on shutdown: {e}");
            if result.is_ok() {
                result = Err(e);
            }
        }

        // 无论预设路由删除成功与否，都再尝试拆掉残留的 resilient group / 成员。
        // 若上面删除失败，variant 仍是 Resilient，teardown 会先重试删路由。
        self.teardown_resilient(AF_INET, NH_GROUP_ID_V4);
        self.teardown_resilient(AF_INET6, NH_GROUP_ID_V6);
        result
    }

    fn warn_out_of_range_weights<'a>(weights: impl Iterator<Item = (&'a String, u32)>) {
        for (ifname, weight) in weights {
            if weight == 0 || weight > MAX_NEXTHOP_WEIGHT {
                warn!(
                    "[RouteManager] Interface {} weight {} out of range, clamped to 1~{}",
                    ifname, weight, MAX_NEXTHOP_WEIGHT
                );
            }
        }
    }

    fn log_route_switch(&self, family: &str, hops: &[(&str, Option<String>, u32)]) {
        if hops.len() == 1 {
            let (ifname, gw, _weight) = &hops[0];
            info!(
                "[RouteManager] Atomic FIB Switch: Single {} default route dev {} [gw: {}]",
                family,
                ifname,
                gw.as_deref().unwrap_or("direct")
            );
        } else if !hops.is_empty() {
            let desc: Vec<String> = hops
                .iter()
                .map(|(ifname, gw, weight)| {
                    format!(
                        "nexthop via {} dev {} (w:{})",
                        gw.as_deref().unwrap_or("direct"),
                        ifname,
                        weight
                    )
                })
                .collect();
            info!(
                "[RouteManager] Atomic FIB Switch: ECMP Multipath {} default route [{}]",
                family,
                desc.join(" ")
            );
        }
    }

    /// 附加 RtAttr 属性并处理 4 位元组对齐（纯函数，方便单测）
    fn append_attr(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
        let attr_hdr_size = RtAttr::LEN;
        let total_len = attr_hdr_size + data.len();
        let aligned_len = rta_align(total_len);

        let rta = RtAttr {
            rta_len: total_len as u16,
            rta_type: attr_type,
        };

        buf.extend_from_slice(&rta.to_bytes());
        buf.extend_from_slice(data);
        // 补零以对齐 4 bytes
        buf.resize(buf.len() + (aligned_len - total_len), 0);
    }
}

#[cfg(target_os = "linux")]
impl Drop for RouteManager {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock_fd);
        }
    }
}

/// 真实核心的 netns 整合测试（预设 ignore；见模组开头的执行方式）
#[cfg(all(test, target_os = "linux"))]
mod netns_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::util::{read_u16, read_u32};

    #[test]
    fn test_rtmsg_layout() {
        assert_eq!(RtMsg::LEN, 12);
        let m = RtMsg {
            rtm_family: AF_INET,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        let b = m.to_bytes();
        assert_eq!(&b[0..8], &[2, 0, 0, 0, 254, 4, 0, 1]);
        assert_eq!(read_u32(&b, 8), Some(0));
    }

    #[test]
    fn test_nexthop_weight_clamped() {
        // 超过上限（255）一律夹住，避免 `as u8` 静默截断。
        // 上限 255 而非 256：resilient group 的 nexthop_grp.weight 在 Linux < 6.9
        // 只到 254（weight-1），设 256 会让 RTM_NEWNEXTHOP 回 EINVAL。
        assert_eq!(300u32.clamp(1, MAX_NEXTHOP_WEIGHT), 255);
        assert_eq!(0u32.clamp(1, MAX_NEXTHOP_WEIGHT), 1);
        // 256 在旧程式码里会编成 255（合法），现在一律夹成 255
        assert_eq!((256u32.clamp(1, MAX_NEXTHOP_WEIGHT) - 1) as u8, 254);
        assert_eq!((255u32.clamp(1, MAX_NEXTHOP_WEIGHT) - 1) as u8, 254);
    }

    #[test]
    fn test_nlmsghdr_roundtrip() {
        let h = NlMsgHdr {
            nlmsg_len: 52,
            nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 7,
            nlmsg_pid: 0,
        };
        let parsed = NlMsgHdr::from_bytes(&h.to_bytes()).unwrap();
        assert_eq!(parsed, h);
        assert!(NlMsgHdr::from_bytes(&[0u8; 8]).is_none());
    }

    /// 解析讯息中的 rtattr 串流，回传 (type, payload) 列表
    fn parse_attrs(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut off = NlMsgHdr::LEN + RtMsg::LEN;
        while off + RtAttr::LEN <= buf.len() {
            let len = read_u16(buf, off).unwrap() as usize;
            let typ = read_u16(buf, off + 2).unwrap();
            if len < RtAttr::LEN || off + len > buf.len() {
                break;
            }
            out.push((typ, buf[off + RtAttr::LEN..off + len].to_vec()));
            off += rta_align(len);
        }
        out
    }

    #[test]
    fn test_ipv4_single_route_layout() {
        let hops = vec![RouteNexthop {
            ifindex: 3,
            gateway: Some(vec![192, 168, 1, 1]),
            weight: 1,
        }];
        let msg = RouteManager::build_route_msg(
            0,
            AF_INET,
            &hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            1,
        );

        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_len as usize, msg.len());
        assert_eq!(hdr.nlmsg_type, RTM_NEWROUTE);
        assert_eq!(hdr.nlmsg_seq, 1);
        // 讯息总长必须是 4 的倍数（netlink 对齐要求）
        assert_eq!(msg.len() % 4, 0);

        assert_eq!(&msg[NlMsgHdr::LEN], &AF_INET); // rtm_family
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0); // dst_len = 0 -> 预设路由

        let attrs = parse_attrs(&msg);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![RTA_PRIORITY, RTA_GATEWAY, RTA_OIF]);
        assert_eq!(attrs[1].1, vec![192, 168, 1, 1]);
        assert_eq!(read_u32(&attrs[2].1, 0), Some(3));
    }

    #[test]
    fn test_ipv6_single_route_layout() {
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let hops = vec![RouteNexthop {
            ifindex: 4,
            gateway: Some(gw.octets().to_vec()),
            weight: 1,
        }];
        let msg = RouteManager::build_route_msg(
            5,
            AF_INET6,
            &hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            2,
        );

        assert_eq!(msg[NlMsgHdr::LEN], AF_INET6);
        assert_eq!(msg.len() % 4, 0);

        let attrs = parse_attrs(&msg);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![RTA_PRIORITY, RTA_GATEWAY, RTA_OIF]);
        // IPv6 网关必须是 16 bytes
        assert_eq!(attrs[1].1.len(), 16);
        assert_eq!(attrs[1].1, gw.octets().to_vec());
        // metric 有带进去
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
    }

    #[test]
    fn test_ecmp_multipath_layout() {
        let hops = vec![
            RouteNexthop {
                ifindex: 3,
                gateway: Some(vec![192, 168, 1, 1]),
                weight: 1,
            },
            RouteNexthop {
                ifindex: 4,
                gateway: Some(vec![192, 168, 2, 1]),
                weight: 3,
            },
        ];
        let msg = RouteManager::build_route_msg(
            0,
            AF_INET,
            &hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            1,
        );

        let attrs = parse_attrs(&msg);
        let mp = attrs
            .iter()
            .find(|(t, _)| *t == RTA_MULTIPATH)
            .expect("RTA_MULTIPATH must be present")
            .1
            .clone();

        // 逐个走过 nexthop，验证 rtnh_len 与对齐（核心会用 NLMSG_ALIGN(rtnh_len) 前进）
        let mut off = 0usize;
        let mut lens = Vec::new();
        let mut hops_seen = Vec::new();
        while off + RtNextHop::LEN <= mp.len() {
            let rtnh_len = read_u16(&mp, off).unwrap() as usize;
            let rtnh_hops = mp[off + 3];
            let ifindex = read_u32(&mp, off + 4).unwrap();
            assert!(rtnh_len >= RtNextHop::LEN, "rtnh_len too small");
            assert!(
                off + rtnh_len <= mp.len(),
                "rtnh_len overruns multipath attr"
            );
            lens.push(rtnh_len);
            hops_seen.push((ifindex, rtnh_hops));
            off += rta_align(rtnh_len);
        }

        assert_eq!(hops_seen.len(), 2);
        assert_eq!(hops_seen[0], (3, 0)); // weight 1 -> hops 0
        assert_eq!(hops_seen[1], (4, 2)); // weight 3 -> hops 2
        // 走完后不应有残留位元组，否则核心 fib_get_nhs 会回 EINVAL
        assert_eq!(off, mp.len(), "trailing bytes after last nexthop");
        // 每个 nexthop：8 bytes 标头 + 4 bytes 属性头 + 4 bytes 网关
        assert!(lens.iter().all(|&l| l == RtNextHop::LEN + RtAttr::LEN + 4));
    }

    #[test]
    fn test_delete_message_has_no_nexthop_attrs() {
        let msg = RouteManager::build_route_msg(
            0,
            AF_INET,
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            9,
        );
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_DELROUTE);
        // 删除只需要 key（dst/table/priority），不应带任何 nexthop 属性
        let attrs = parse_attrs(&msg);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![RTA_PRIORITY]);
        // scope 必须是 NOWHERE，否则无网关路由（scope=LINK）会因不匹配而删不掉
        assert_eq!(msg[NlMsgHdr::LEN + 6], RT_SCOPE_NOWHERE);
    }

    #[test]
    fn test_delete_via_nh_message_uses_scope_nowhere() {
        let msg = RouteManager::build_route_msg_via_nh(
            0,
            AF_INET,
            42,
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            10,
        );
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_DELROUTE);
        assert_eq!(msg[NlMsgHdr::LEN + 6], RT_SCOPE_NOWHERE);
        let attrs = parse_attrs(&msg);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![RTA_PRIORITY, RTA_NH_ID]);
    }

    #[test]
    fn test_link_scope_when_no_gateway() {
        let hops = vec![RouteNexthop {
            ifindex: 5,
            gateway: None,
            weight: 1,
        }];
        let msg = RouteManager::build_route_msg(
            0,
            AF_INET,
            &hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            1,
        );
        // rtm_scope 位于 rtmsg 的第 6 个位元组
        assert_eq!(msg[NlMsgHdr::LEN + 6], RT_SCOPE_LINK);
    }

    // -----------------------------------------------------------------------
    // nexthop object / resilient nexthop group
    // -----------------------------------------------------------------------

    /// 从任意偏移解析 rtattr 串流（nexthop 讯息的固定标头是 nhmsg 而非 rtmsg）
    fn parse_attr_stream(buf: &[u8], mut off: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        while off + RtAttr::LEN <= buf.len() {
            let len = read_u16(buf, off).unwrap() as usize;
            let typ = read_u16(buf, off + 2).unwrap();
            if len < RtAttr::LEN || off + len > buf.len() {
                break;
            }
            out.push((typ, buf[off + RtAttr::LEN..off + len].to_vec()));
            off += rta_align(len);
        }
        out
    }

    fn nh_attrs(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
        parse_attr_stream(buf, NlMsgHdr::LEN + NhMsg::LEN)
    }

    fn attr_types(attrs: &[(u16, Vec<u8>)]) -> Vec<u16> {
        attrs.iter().map(|(t, _)| *t).collect()
    }

    /// 这些列举值是照 Linux uapi 抄的，抄错只会得到一个没有上下文的 EINVAL，
    /// 所以用测试把它钉住。
    #[test]
    fn test_nexthop_constants_match_linux_uapi() {
        assert_eq!(RTM_NEWNEXTHOP, 104);
        assert_eq!(RTM_DELNEXTHOP, 105);
        assert_eq!(RTA_NH_ID, 30);
        assert_eq!(NHA_ID, 1);
        assert_eq!(NHA_GROUP, 2);
        assert_eq!(NHA_GROUP_TYPE, 3);
        assert_eq!(NHA_OIF, 5);
        assert_eq!(NHA_GATEWAY, 6);
        assert_eq!(NHA_RES_GROUP, 12);
        // bucket 数是巢状列举里的 NHA_RES_GROUP_BUCKETS（u16），不是顶层的 13
        assert_eq!(NHA_RES_GROUP_BUCKETS, 1);
        assert_eq!(NEXTHOP_GRP_TYPE_RES, 1);
    }

    #[test]
    fn test_nhmsg_and_nexthop_grp_layout() {
        assert_eq!(NhMsg::LEN, 8);
        let b = NhMsg {
            nh_family: AF_INET,
            nh_scope: RT_SCOPE_UNIVERSE,
            nh_protocol: RTPROT_STATIC,
            nh_resvd: 0,
            nh_flags: 0,
        }
        .to_bytes();
        assert_eq!(b[0], AF_INET);
        assert_eq!(b[1], 0);
        assert_eq!(b[2], RTPROT_STATIC);
        assert_eq!(read_u32(&b, 4), Some(0));

        assert_eq!(NextHopGrp::LEN, 8);
        let g = NextHopGrp {
            id: 7,
            weight: 2,
            resvd1: 0,
            resvd2: 0,
        }
        .to_bytes();
        assert_eq!(read_u32(&g, 0), Some(7));
        assert_eq!(g[4], 2);
        assert_eq!(read_u16(&g, 6), Some(0));
    }

    #[test]
    fn test_nexthop_member_msg_layout() {
        let msg = RouteManager::build_nexthop_id_msg(
            7,
            AF_INET,
            42,
            3,
            Some(&[192, 168, 1, 1]),
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );

        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_len as usize, msg.len());
        assert_eq!(hdr.nlmsg_type, RTM_NEWNEXTHOP);
        assert_eq!(hdr.nlmsg_seq, 7);
        assert_eq!(msg.len() % 4, 0, "netlink 讯息必须 4 bytes 对齐");
        assert_eq!(msg[NlMsgHdr::LEN], AF_INET); // nh_family
        assert_eq!(msg[NlMsgHdr::LEN + 2], RTPROT_STATIC);

        let attrs = nh_attrs(&msg);
        assert_eq!(attr_types(&attrs), vec![NHA_ID, NHA_OIF, NHA_GATEWAY]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(42)); // NHA_ID
        assert_eq!(read_u32(&attrs[1].1, 0), Some(3)); // NHA_OIF
        assert_eq!(attrs[2].1, vec![192, 168, 1, 1]); // NHA_GATEWAY
    }

    #[test]
    fn test_nexthop_member_without_gateway_omits_gateway_attr() {
        let msg = RouteManager::build_nexthop_id_msg(
            1,
            AF_INET,
            1,
            9,
            None,
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST,
        );
        assert_eq!(attr_types(&nh_attrs(&msg)), vec![NHA_ID, NHA_OIF]);
    }

    #[test]
    fn test_nexthop_del_msg_carries_only_id() {
        let msg = RouteManager::build_nexthop_del_msg(3, AF_UNSPEC, 5);
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_DELNEXTHOP);
        assert_eq!(msg[NlMsgHdr::LEN], AF_UNSPEC);

        // 除了 nh_family，nhmsg 其余栏位必须全零：内核 nh_valid_get_del_req()
        // 对 nh_protocol / nh_scope / nh_flags 任一非零都回 EINVAL
        // "Invalid values in header"，删除会静默失败（netns 实测抓到过）。
        assert_eq!(
            &msg[NlMsgHdr::LEN + 1..NlMsgHdr::LEN + NhMsg::LEN],
            &[0u8; NhMsg::LEN - 1],
            "DELNEXTHOP 的 nhmsg 除了 family 必须全零"
        );

        let attrs = nh_attrs(&msg);
        // 删除时多带 NHA_OIF 会被核心视为无效；只允许 NHA_ID
        assert_eq!(attr_types(&attrs), vec![NHA_ID]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
    }

    #[test]
    fn test_nexthop_del_msg_uses_the_same_family_as_creation() {
        // 成员是以 AF_INET 建立的，删除时也必须带 AF_INET。
        // 成员是以 AF_INET 建立、group 是以 AF_UNSPEC 建立，删除时带上对应 family。
        // （内核 6.12 的 DELNEXTHOP 只验 header 其余栏位为零，不验 family；这里
        //   保留对称写法以防旧核心比对，且 deleted family 不影响正确性。）
        let msg = RouteManager::build_nexthop_del_msg(7, AF_INET, 42);
        assert_eq!(msg[NlMsgHdr::LEN], AF_INET);
        assert_eq!(read_u32(&nh_attrs(&msg)[0].1, 0), Some(42));

        let grp = RouteManager::build_nexthop_del_msg(8, AF_UNSPEC, 4294967040);
        assert_eq!(grp[NlMsgHdr::LEN], AF_UNSPEC);
    }

    #[test]
    fn test_resilient_group_msg_layout() {
        let members = [(1u32, 1u32), (2u32, 3u32)];
        let msg = RouteManager::build_nexthop_group_msg(
            9,
            NH_GROUP_ID_V4,
            &members,
            Some(16),
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST,
        );

        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_NEWNEXTHOP);
        assert_eq!(msg[NlMsgHdr::LEN], AF_UNSPEC); // group 跨越位址族

        let attrs = nh_attrs(&msg);
        assert_eq!(
            attr_types(&attrs),
            vec![
                NHA_ID,
                NHA_GROUP_TYPE,
                NHA_GROUP,
                // 巢状属性必须带 NLA_F_NESTED，少了它核心就不解析里面的 bucket 数
                NHA_RES_GROUP | NLA_F_NESTED
            ]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(NH_GROUP_ID_V4));
        // 没有 NHA_GROUP_TYPE=RES，核心不会把它当成 resilient group
        assert_eq!(read_u16(&attrs[1].1, 0), Some(NEXTHOP_GRP_TYPE_RES));

        // NHA_GROUP 是连续的 8-byte 成员
        let grp = &attrs[2].1;
        assert_eq!(grp.len(), 2 * NextHopGrp::LEN);
        assert_eq!(read_u32(grp, 0), Some(1));
        assert_eq!(grp[4], 0); // weight 1 -> hops 0
        assert_eq!(read_u32(grp, 8), Some(2));
        assert_eq!(grp[12], 2); // weight 3 -> hops 2

        // NHA_RES_GROUP 是巢状属性，内含 NHA_RES_GROUP_BUCKETS。
        // 这里曾经误用顶层的 NHA_RES_BUCKETS(13) 并以 u32 编码，核心因此回 EINVAL，
        // resilient 模式从未真正生效；下面两行就是为了防止它复发。
        let res = parse_attr_stream(&attrs[3].1, 0);
        assert_eq!(attr_types(&res), vec![NHA_RES_GROUP_BUCKETS]);
        assert_eq!(res[0].1.len(), 2, "bucket 数必须是 u16，不是 u32");
        assert_eq!(read_u16(&res[0].1, 0), Some(16));
    }

    #[test]
    fn test_plain_nexthop_group_has_no_res_group() {
        let members = [(1u32, 1u32)];
        let msg = RouteManager::build_nexthop_group_msg(
            1,
            77,
            &members,
            None,
            RTM_NEWNEXTHOP,
            NLM_F_REQUEST,
        );
        assert_eq!(attr_types(&nh_attrs(&msg)), vec![NHA_ID, NHA_GROUP]);
    }

    #[test]
    fn test_route_via_nexthop_layout() {
        let msg = RouteManager::build_route_msg_via_nh(
            5,
            AF_INET,
            NH_GROUP_ID_V4,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            11,
        );
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_NEWROUTE);
        assert_eq!(msg[NlMsgHdr::LEN], AF_INET);
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0); // dst_len = 0 -> 预设路由
        // 路由讯息用 rtmsg（12 bytes），不是 nhmsg
        let attrs = parse_attrs(&msg);
        assert_eq!(attr_types(&attrs), vec![RTA_PRIORITY, RTA_NH_ID]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
        assert_eq!(read_u32(&attrs[1].1, 0), Some(NH_GROUP_ID_V4));

        // 删除讯息必须带同一个 nh_id，否则核心的 fib key 对不上、路由删不掉
        let del = RouteManager::build_route_msg_via_nh(
            5,
            AF_INET,
            NH_GROUP_ID_V4,
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            12,
        );
        let del_attrs = parse_attrs(&del);
        assert_eq!(attr_types(&del_attrs), vec![RTA_PRIORITY, RTA_NH_ID]);
        assert_eq!(read_u32(&del_attrs[1].1, 0), Some(NH_GROUP_ID_V4));
    }

    #[test]
    fn test_resilient_buckets_are_fixed_power_of_two() {
        // bucket 数固定用 RES_BUCKETS_MAX：核心在 REPLACE 既有 group 时不允许改变
        // bucket 数，因此不能按成员数动态调整。必须是 2 的幂、涵盖 config 允许的
        // 最大网卡数（64），且能放进 u16。
        const { assert!(RES_BUCKETS_MAX.is_power_of_two()) };
        const { assert!(RES_BUCKETS_MAX >= 64, "必须涵盖 config 的网卡数上限") };
        const { assert!(RES_BUCKETS_MAX < u16::MAX as usize) };
    }

    #[test]
    fn test_resilient_give_up_only_for_real_unsupported_errors() {
        // 真正的「核心不支援」→ 永久退回标准 ECMP
        let unsupported = io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        assert!(RouteManager::should_give_up_on_resilient(&unsupported));

        // EINVAL（例如既有 group 的 bucket 数不同）可以靠拆除重建恢复，
        // 不能当成永久不支援，否则 auto 一次失败就再也不试 resilient
        let transient = io::Error::from_raw_os_error(libc::EINVAL);
        assert!(!RouteManager::should_give_up_on_resilient(&transient));
    }

    #[test]
    fn test_nexthop_ids_are_stable_per_member() {
        let mut rm = RouteManager::new(0, EcmpMode::Standard).unwrap();
        let a = rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1]));
        let b = rm.alloc_nh_id(AF_INET, 4, Some(&vec![192, 168, 2, 1]));
        assert_ne!(a, b);

        // 同一成员重复配置必须拿到同一个 ID；换 ID 等于换成员，
        // 核心会把该成员负责的 flow 全部重映射（正是我们要避免的事）
        assert_eq!(rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1])), a);

        // 位址族不同 / 同一 ifindex 但没有网关，都不能撞号
        let v6 = rm.alloc_nh_id(AF_INET6, 3, Some(&vec![0u8; 16]));
        let v4_direct = rm.alloc_nh_id(AF_INET, 3, None);
        assert!(![a, b].contains(&v6));
        assert!(![a, b, v6].contains(&v4_direct));

        // 群组 ID 保留在高位，不会与成员 ID 撞号
        assert!(NH_GROUP_ID_V4 > rm.next_nh_id);
        assert!(NH_GROUP_ID_V6 > rm.next_nh_id);
    }

    // -----------------------------------------------------------------------
    // 探针路径（独立表 + oif 规则）
    // -----------------------------------------------------------------------

    /// 解析 fib_rule 讯息：回传 (hdr 栏位, 属性列表)
    fn parse_rule(buf: &[u8]) -> (FibRuleHdr, Vec<(u16, Vec<u8>)>) {
        let hdr = FibRuleHdr {
            family: buf[NlMsgHdr::LEN],
            dst_len: buf[NlMsgHdr::LEN + 1],
            src_len: buf[NlMsgHdr::LEN + 2],
            tos: buf[NlMsgHdr::LEN + 3],
            table: buf[NlMsgHdr::LEN + 4],
            action: buf[NlMsgHdr::LEN + 7],
            flags: read_u32(buf, NlMsgHdr::LEN + 8).unwrap(),
        };
        (hdr, parse_attr_stream(buf, NlMsgHdr::LEN + FibRuleHdr::LEN))
    }

    #[test]
    fn test_probe_path_constants_do_not_collide() {
        // 表号必须 > 255 才能验证我们只用 RTA_TABLE 表达它；
        // 规则优先序必须落在 1..32766 之间才会在 main 表之前被求值。
        // （这两个不变式同时由模组层的 const assert 在编译期检查。）
        let tables: Vec<u32> = (0..8).map(|i| PROBE_TABLE_BASE + i).collect();
        assert!(tables.iter().all(|t| *t > 255));
        let priorities: Vec<u32> = (0..8).map(|i| PROBE_RULE_PRIORITY_BASE + i).collect();
        assert!(
            priorities
                .iter()
                .all(|p| *p > 0 && *p < 32_766 && *p != 32_766)
        );
        // 预设路由的 metric 0 与探针表是两套 namespace，不应互相影响
        assert_ne!(PROBE_TABLE_BASE, 254);
    }

    #[test]
    fn test_rule_constants_match_linux_uapi() {
        // 这几个值照 /usr/include/linux/rtnetlink.h 与 fib_rules.h 钉死。
        // 抄错的代价极高：RTM_NEWRULE 写成 21（= RTM_DELADDR）或把 FRA_OIFNAME
        // 写成 10（= FRA_FWMARK）时，内核会回一个毫无上下文的 ENODEV，
        // 症状是「探针路径永远装不上、两条线永远 DOWN」。
        assert_eq!(RTM_NEWRULE, 32);
        assert_eq!(RTM_DELRULE, 33);
        assert_eq!(FRA_PRIORITY, 6);
        assert_eq!(FRA_TABLE, 15);
        assert_eq!(FRA_OIFNAME, 17);
        assert_eq!(FR_ACT_TO_TBL, 1);
        // 既有 nexthop 常数也一并对照（104/105 与 NHA_* 都必须与 uapi 一致）
        assert_eq!(RTM_NEWNEXTHOP, 104);
        assert_eq!(RTM_DELNEXTHOP, 105);
        assert_eq!(NHA_RES_GROUP, 12);
        // bucket 数是巢状列举里的 NHA_RES_GROUP_BUCKETS（u16），不是顶层的 13
        assert_eq!(NHA_RES_GROUP_BUCKETS, 1);
        assert_eq!(NHA_OIF, 5);
        assert_eq!(NHA_GATEWAY, 6);
    }

    #[test]
    fn test_getroute_request_and_reply_parsing() {
        // 请求：RTM_GETROUTE + RTA_DST(/32) + 可选 RTA_OIF
        let msg = RouteManager::build_getroute_msg(
            AF_INET,
            3,
            Some((Ipv4Addr::new(203, 0, 113, 10), 32)),
            Some(7),
            false,
        );
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_GETROUTE);
        assert_eq!(hdr.nlmsg_flags & NLM_F_DUMP, 0);
        assert_eq!(msg[NlMsgHdr::LEN + 1], 32, "dst_len 必须是 32");
        let attrs = parse_attrs(&msg);
        assert_eq!(attr_types(&attrs), vec![RTA_DST, RTA_OIF]);
        assert_eq!(attrs[0].1, vec![203, 0, 113, 10]);

        // dump 请求：不带 dst，带 NLM_F_DUMP
        let dump = RouteManager::build_getroute_msg(AF_INET, 4, None, None, true);
        let dump_hdr = NlMsgHdr::from_bytes(&dump).unwrap();
        assert_eq!(dump_hdr.nlmsg_flags & NLM_F_DUMP, NLM_F_DUMP);
        assert_eq!(dump[NlMsgHdr::LEN + 1], 0);

        // 解析回复：rtmsg(table=254) + RTA_TABLE + RTA_OIF + RTA_GATEWAY
        let mut reply = vec![0u8; NlMsgHdr::LEN + RtMsg::LEN];
        reply[NlMsgHdr::LEN + 4] = 254; // rtm_table
        RouteManager::append_attr(&mut reply, RTA_TABLE, &10_000u32.to_ne_bytes());
        RouteManager::append_attr(&mut reply, RTA_OIF, &12u32.to_ne_bytes());
        RouteManager::append_attr(&mut reply, RTA_GATEWAY, &[10, 99, 1, 2]);
        let parsed = RouteManager::parse_route_reply(&reply, reply.len()).unwrap();
        assert_eq!(
            parsed,
            RouteLookup {
                ifindex: Some(12),
                gateway: Some(Ipv4Addr::new(10, 99, 1, 2)),
                table: 10_000,
            }
        );

        // 空属性串流也要能解析（只有 rtmsg）
        let bare = vec![0u8; NlMsgHdr::LEN + RtMsg::LEN];
        let parsed = RouteManager::parse_route_reply(&bare, bare.len()).unwrap();
        assert_eq!(parsed.ifindex, None);
        assert_eq!(parsed.table, 0);
    }

    /// 隧道 underlay /32 的出口选择：只能是「非隧道」的线，且取 metric 最小者。
    /// 这条规则直接对应实机上那个「切到 resilient 后隧道丢包 60%」的自环 bug。
    #[test]
    fn test_plan_underlay_routes_never_uses_a_tunnel_as_exit() {
        let wan = |ifname: &str,
                   ifindex: u32,
                   metric: u32,
                   gateway: Option<Ipv4Addr>,
                   underlay: Vec<Ipv4Addr>| ActiveWanRoute {
            ifname: ifname.to_string(),
            ifindex,
            gateway,
            weight: 1,
            metric,
            underlay_targets: underlay,
        };

        // 物理线 eth1（metric 10）+ 隧道 vxlan0（metric 10，列出自己的 underlay 对端）
        let wans = vec![
            wan(
                "eth1",
                3,
                10,
                Some(Ipv4Addr::new(10, 176, 255, 254)),
                Vec::new(),
            ),
            wan(
                "vxlan0",
                45,
                10,
                Some(Ipv4Addr::new(10, 77, 0, 1)),
                vec![Ipv4Addr::new(10, 128, 0, 20)],
            ),
        ];
        let plan = RouteManager::plan_underlay_routes(&wans);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, Ipv4Addr::new(10, 128, 0, 20));
        assert_eq!(plan[0].1, 3, "对端必须走物理线 eth1，而不是隧道自己");
        assert_eq!(plan[0].2, Some(vec![10, 176, 255, 254]));
    }

    #[test]
    fn test_plan_underlay_routes_edge_cases() {
        let wan = |ifname: &str,
                   ifindex: u32,
                   metric: u32,
                   gateway: Option<Ipv4Addr>,
                   underlay: Vec<Ipv4Addr>| ActiveWanRoute {
            ifname: ifname.to_string(),
            ifindex,
            gateway,
            weight: 1,
            metric,
            underlay_targets: underlay,
        };

        // 两条物理线：metric 小的 eth1 当出口（同 metric 才看设定档顺序）
        let wans = vec![
            wan("eth2", 5, 50, Some(Ipv4Addr::new(10, 0, 0, 1)), Vec::new()),
            wan(
                "eth1",
                3,
                10,
                Some(Ipv4Addr::new(10, 176, 255, 254)),
                Vec::new(),
            ),
            wan(
                "vxlan0",
                45,
                10,
                Some(Ipv4Addr::new(10, 77, 0, 1)),
                vec![Ipv4Addr::new(10, 128, 0, 20)],
            ),
        ];
        let plan = RouteManager::plan_underlay_routes(&wans);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].1, 3, "metric 最小的物理线 eth1 才是出口");

        // 只有隧道可选：不下发 /32（否则会形成隧道当隧道 underlay 的递回依赖）
        let only_tunnels = vec![wan("wg0", 7, 10, None, vec![Ipv4Addr::new(1, 2, 3, 4)])];
        assert!(RouteManager::plan_underlay_routes(&only_tunnels).is_empty());

        // 没有隧道：自然是空集合
        let no_tunnel = vec![wan("eth1", 3, 10, None, Vec::new())];
        assert!(RouteManager::plan_underlay_routes(&no_tunnel).is_empty());

        // 空集合也不该 panic
        assert!(RouteManager::plan_underlay_routes(&[]).is_empty());
    }

    /// FIX-1 回归钉：**执行期**那次清扫只能扫探针 /32。
    ///
    /// 修复前的 bug：worker 处理同一批指令时 `Apply` 先执行（刚把 underlay /32 装好）、
    /// `SetProbePaths(clean = true)` 后执行，而当时的清扫同时扫 42760 与 42761 →
    /// 把刚装好的 underlay /32 删掉，且记忆体快取还记著「已装」→ 永不重装。
    #[test]
    fn test_runtime_sweep_never_touches_underlay() {
        let runtime: Vec<u32> = RUNTIME_SWEEP_METRICS.iter().map(|(m, _)| *m).collect();
        assert_eq!(runtime, vec![PROBE_MAIN_ROUTE_METRIC]);
        assert!(
            !runtime.contains(&UNDERLAY_ROUTE_METRIC),
            "执行期清扫若扫到 underlay /32，就会把同一批 Apply 刚装好的路由删掉"
        );

        let startup: Vec<u32> = STARTUP_SWEEP_METRICS.iter().map(|(m, _)| *m).collect();
        assert!(startup.contains(&PROBE_MAIN_ROUTE_METRIC));
        assert!(
            startup.contains(&UNDERLAY_ROUTE_METRIC),
            "启动前必须连残留的 underlay /32 一起清（出口可能已经失效）"
        );
    }

    /// FIX-1 回归钉：核心说「这条 /32 不在」时，即使记忆体快取记著「已装、出口没变」，
    /// 也必须重下（自愈）。反例就是修复前的 `unchanged -> continue`。
    #[test]
    fn test_underlay_repair_reinstalls_when_kernel_lost_the_route() {
        let addr = Ipv4Addr::new(10, 128, 0, 20);
        let exit_gw = Some(vec![10u8, 176, 255, 254]);
        let wan = |ifname: &str,
                   ifindex: u32,
                   metric: u32,
                   gateway: Option<Ipv4Addr>,
                   underlay: Vec<Ipv4Addr>| ActiveWanRoute {
            ifname: ifname.to_string(),
            ifindex,
            gateway,
            weight: 1,
            metric,
            underlay_targets: underlay,
        };
        let wans = vec![
            wan(
                "eth1",
                3,
                10,
                Some(Ipv4Addr::new(10, 176, 255, 254)),
                Vec::new(),
            ),
            wan(
                "vxlan0",
                45,
                10,
                Some(Ipv4Addr::new(10, 77, 0, 1)),
                vec![addr],
            ),
        ];
        let wanted = RouteManager::plan_underlay_routes(&wans);
        assert_eq!(wanted.len(), 1);
        assert_eq!(wanted[0].1, 3);

        // 快取说「已装、出口 = eth1」
        let installed: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)> =
            [(addr, (3u32, exit_gw.clone()))].into_iter().collect();

        // 核心也还有一条 → 不必重下
        let present: std::collections::HashSet<Ipv4Addr> = [addr].into_iter().collect();
        assert!(
            RouteManager::plan_underlay_repairs(&wanted, &installed, Some(&present)).is_empty()
        );

        // 核心里没有了（被清扫／外部删除）→ 必须重装
        let absent: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
        let repairs = RouteManager::plan_underlay_repairs(&wanted, &installed, Some(&absent));
        assert_eq!(repairs.len(), 1, "核心缺失时必须重下");
        assert_eq!(repairs[0].0, addr);
        assert_eq!(repairs[0].1, 3);
        assert_eq!(repairs[0].2, exit_gw);

        // 转储失败（None）→ 这一轮退回快取判断，不无条件重下
        assert!(RouteManager::plan_underlay_repairs(&wanted, &installed, None).is_empty());

        // 快取记的出口与期望不符（隧道换了 underlay 出口）→ 即使核心有也要重下
        let moved: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)> =
            [(addr, (45u32, Some(vec![10, 77, 0, 1])))]
                .into_iter()
                .collect();
        let repairs = RouteManager::plan_underlay_repairs(&wanted, &moved, Some(&present));
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].1, 3, "期望的出口是物理线 eth1");
    }

    #[test]
    fn test_probe_main_route_metric_is_distinct() {
        // 探针 /32 的 metric 必须与预设路由的 priority 不同，否则会互相盖掉；
        // 也要与 slot 推导出的表号/优先序区段分开，避免误删。
        // （与 metric 0 / 区段不重叠的不变式同时由模组层 const assert 在编译期检查。）
        let metric = PROBE_MAIN_ROUTE_METRIC;
        let slot_max = PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX;
        assert!(metric != 0 && metric > slot_max && metric < 0xFFFF_FF00);
    }

    #[test]
    fn test_probe_rule_msg_layout() {
        let table = PROBE_TABLE_BASE + 3;
        let priority = PROBE_RULE_PRIORITY_BASE + 3;
        let spec = |output: bool| RuleSpec {
            family: AF_INET,
            table,
            ifname: "vxlan",
            priority,
            output,
        };
        let msg = RouteManager::build_rule_msg(
            7,
            spec(true),
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );

        let nlhdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(nlhdr.nlmsg_len as usize, msg.len());
        assert_eq!(nlhdr.nlmsg_type, RTM_NEWRULE);
        assert_eq!(nlhdr.nlmsg_seq, 7);
        assert_eq!(msg.len() % 4, 0, "netlink 讯息必须 4 bytes 对齐");

        let (hdr, attrs) = parse_rule(&msg);
        assert_eq!(hdr.family, AF_INET);
        assert_eq!(hdr.action, FR_ACT_TO_TBL);
        assert_eq!(hdr.dst_len, 0);
        assert_eq!(hdr.src_len, 0);

        assert_eq!(
            attr_types(&attrs),
            vec![FRA_TABLE, FRA_PRIORITY, FRA_PROTOCOL, FRA_OIFNAME]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(table));
        assert_eq!(read_u32(&attrs[1].1, 0), Some(priority));
        // 我们的规则会带来源标记，清扫时才能只删自己的
        assert_eq!(attrs[2].1, vec![PROBE_RULE_PROTOCOL]);
        // 字串属性必须带结尾 NUL（核心用 strlen 解析）
        assert_eq!(attrs[3].1, b"vxlan\0".to_vec());

        // 入向规则用的是 FRA_IIFNAME，抄错就会变成「规则装了但反向路径照样被挡」
        let in_msg = RouteManager::build_rule_msg(
            8,
            spec(false),
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        assert_eq!(
            attr_types(&parse_rule(&in_msg).1),
            vec![FRA_TABLE, FRA_PRIORITY, FRA_PROTOCOL, FRA_IIFNAME]
        );

        // 删除讯息除 type 外必须完全一致，否则核心的 rule key 对不上
        let del =
            RouteManager::build_rule_msg(9, spec(true), RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(NlMsgHdr::from_bytes(&del).unwrap().nlmsg_type, RTM_DELRULE);
        assert_eq!(parse_rule(&del).1, attrs);
    }

    #[test]
    fn test_policy_rule_msg_layout() {
        let rule = PolicyRule {
            name: "guest".to_string(),
            ifindex: 5,
            table: PROBE_TABLE_BASE + 1,
            priority: POLICY_RULE_PRIORITY_BASE + 2,
            source: Some(("192.168.3.0".parse().unwrap(), 24)),
            destination: Some(("10.0.0.0".parse().unwrap(), 8)),
        };
        let msg = RouteManager::build_policy_rule_msg(
            11,
            &rule,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );

        let (hdr, attrs) = parse_rule(&msg);
        assert_eq!(hdr.family, AF_INET);
        assert_eq!(hdr.action, FR_ACT_TO_TBL);
        assert_eq!(hdr.src_len, 24, "from 前缀长度必须进 fib_rule_hdr");
        assert_eq!(hdr.dst_len, 8, "to 前缀长度必须进 fib_rule_hdr");
        assert_eq!(
            attr_types(&attrs),
            vec![FRA_TABLE, FRA_PRIORITY, FRA_SRC, FRA_DST, FRA_PROTOCOL]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(PROBE_TABLE_BASE + 1));
        assert_eq!(
            read_u32(&attrs[1].1, 0),
            Some(POLICY_RULE_PRIORITY_BASE + 2)
        );
        assert_eq!(attrs[2].1, vec![192, 168, 3, 0]);
        assert_eq!(attrs[3].1, vec![10, 0, 0, 0]);
        assert_eq!(attrs[4].1, vec![PROBE_RULE_PROTOCOL]);

        // 不限制来源/目的时：长度 0、不带 FRA_SRC/FRA_DST（等同 match-all）
        let any = PolicyRule {
            name: "all".to_string(),
            ifindex: 5,
            table: PROBE_TABLE_BASE,
            priority: POLICY_RULE_PRIORITY_BASE,
            source: None,
            destination: None,
        };
        let msg = RouteManager::build_policy_rule_msg(
            12,
            &any,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        let (hdr, attrs) = parse_rule(&msg);
        assert_eq!((hdr.src_len, hdr.dst_len), (0, 0));
        assert_eq!(
            attr_types(&attrs),
            vec![FRA_TABLE, FRA_PRIORITY, FRA_PROTOCOL]
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_policy_rule_constants_do_not_collide() {
        // 策略规则的优先序区段必须完全在探针规则之前，且都在 main 表之前
        assert!(POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX <= PROBE_RULE_PRIORITY_BASE);
        assert!(POLICY_RULE_PRIORITY_BASE > 0);
        // 两者不能与探针的 metric 区段混淆
        assert!(POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX < PROBE_MAIN_ROUTE_METRIC);
    }

    #[test]
    fn test_probe_path_tables_are_derived_from_slot() {
        let path = ProbePath {
            ifname: "wan1".into(),
            ifindex: 7,
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            targets: vec![Ipv4Addr::new(1, 1, 1, 1)],
            table: PROBE_TABLE_BASE + 5,
            priority: PROBE_RULE_PRIORITY_BASE + 5,
            main_route_targets: Vec::new(),
        };
        // 不同 slot 必须拿到不同的表号／优先序，否则会互相覆盖
        assert_ne!(path.table, PROBE_TABLE_BASE);
        assert_ne!(path.priority, PROBE_RULE_PRIORITY_BASE);
        assert_eq!(path.table, 10_005);
        assert_eq!(path.priority, 10_005);
        // 主表 /32 的 metric 必须与预设路由的 priority 不同，否则会互相盖掉
        assert_ne!(PROBE_MAIN_ROUTE_METRIC, 0);
        assert_ne!(PROBE_MAIN_ROUTE_METRIC, 10_005);
    }

    #[test]
    fn test_probe_route_msg_lives_in_its_own_table() {
        let table = PROBE_TABLE_BASE + 1;
        let hop = RouteNexthop {
            ifindex: 12,
            gateway: Some(vec![10, 77, 0, 1]),
            weight: 1,
        };
        let msg = RouteManager::build_route_msg_ex(
            0,
            AF_INET,
            RouteTarget {
                table: Some(table),
                dst: None,
            },
            std::slice::from_ref(&hop),
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            3,
        );

        let attrs = parse_attrs(&msg);
        assert_eq!(
            attr_types(&attrs),
            vec![RTA_TABLE, RTA_PRIORITY, RTA_GATEWAY, RTA_OIF]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(table));
        // 表内路由的 metric 与主表预设路由（route_priority）无关，固定 0
        assert_eq!(read_u32(&attrs[1].1, 0), Some(0));
        assert_eq!(attrs[2].1, vec![10, 77, 0, 1]);
        assert_eq!(read_u32(&attrs[3].1, 0), Some(12));
        // 这是预设路由（dst_len = 0）
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0);
        // rtm_table 低位元组截断不影响核心（以 RTA_TABLE 为准），但仍保持一致
        assert_eq!(
            msg[NlMsgHdr::LEN + 4],
            (table & 0xFF) as u8,
            "rtm_table 应与 RTA_TABLE 的低位元组一致"
        );

        // 删除时不带任何 nexthop 属性，只靠 (table, dst, metric) 命中
        let del = RouteManager::build_route_msg_ex(
            0,
            AF_INET,
            RouteTarget {
                table: Some(table),
                dst: None,
            },
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            4,
        );
        assert_eq!(
            attr_types(&parse_attrs(&del)),
            vec![RTA_TABLE, RTA_PRIORITY]
        );
    }

    #[test]
    fn test_route_msg_with_dst_prefix() {
        // dst 参数是给未来扩充用的（目前探针路径只用表内预设路由），
        // 这里钉住编码：RTA_DST 必须存在且 rtm_dst_len 正确
        let hop = RouteNexthop {
            ifindex: 3,
            gateway: None,
            weight: 1,
        };
        let msg = RouteManager::build_route_msg_ex(
            0,
            AF_INET,
            RouteTarget {
                table: Some(PROBE_TABLE_BASE),
                dst: Some((&[1, 1, 1, 1], 32)),
            },
            std::slice::from_ref(&hop),
            RTM_NEWROUTE,
            NLM_F_REQUEST,
            5,
        );
        assert_eq!(msg[NlMsgHdr::LEN + 1], 32);
        let attrs = parse_attrs(&msg);
        let dst = attrs
            .iter()
            .find(|(t, _)| *t == RTA_DST)
            .expect("RTA_DST must be present");
        assert_eq!(dst.1, vec![1, 1, 1, 1]);
    }

    #[test]
    fn test_main_table_route_msg_has_no_table_attr() {
        // 主表那条预设路由的编码不能被改动（既有测试已钉栏位顺序，这里补 RTA_TABLE 不存在的检查）
        let hops = vec![RouteNexthop {
            ifindex: 3,
            gateway: Some(vec![192, 168, 1, 1]),
            weight: 1,
        }];
        let msg = RouteManager::build_route_msg(
            0,
            AF_INET,
            &hops,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            1,
        );
        assert!(
            !attr_types(&parse_attrs(&msg)).contains(&RTA_TABLE),
            "主表路由不应带 RTA_TABLE"
        );
    }
}
