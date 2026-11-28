#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use crate::config::EcmpMode;
use crate::netlink::util::{
    NlMsgHdr, read_i32, read_u16, read_u32, rta_align, set_socket_timeouts, write_u16, write_u32,
};
use log::{debug, info, warn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

// nexthop object + resilient nexthop group（OpenWrt 25+ / Linux 6.12+ 标准特性）
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
/// 用专属 protocol 删除只命中自己下发的路由：RTPROT_UNSPEC + metric 0 通配符会误删别人同 metric 的预设路由。
pub const RTPROT_MWAN4: u8 = 0x4D;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
/// 删除时必须填 RT_SCOPE_NOWHERE，否则无网关路由（scope=LINK）会因 scope 不匹配回 ESRCH、残留清不掉。
pub const RT_SCOPE_NOWHERE: u8 = 255;
pub const RTN_UNICAST: u8 = 1;
/// 路由/nexthop 的 linkdown 标志（`rtm_flags` 与 `rtnh_flags` 共用这一个位，`ip route show` 印成
/// `linkdown`）：核心用它表示「这个出口在链路层已经不可用」。这是「撤掉自己的预设路由让兜底接手」
/// 唯一该依据的信号——探针超时不等于链路失效。
pub const RTNH_F_LINKDOWN: u32 = 0x10;

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

/// 巢状于 NHA_RES_GROUP 的 bucket 数（u16）；顶层 13 是 NHA_RES_BUCKET，误用会让核心回 EINVAL。
pub const NHA_RES_GROUP_BUCKETS: u16 = 1;
/// 巢状于 NHA_RES_GROUP 的空闲桶迁移时间（u32，单位 1/100 秒 / centiseconds）。
pub const NHA_RES_GROUP_IDLE_TIMER: u16 = 2;
/// 巢状于 NHA_RES_GROUP 的失衡强制重平衡时间（u32，单位 1/100 秒 / centiseconds）；
/// 0 表示只迁移空闲桶，>0 表示经过该时长仍失衡时也会迁走活跃桶以恢复权重比例。
pub const NHA_RES_GROUP_UNBALANCED_TIMER: u16 = 3;

/// SOL_NETLINK / NETLINK_EXT_ACK：开了核心才会在错误回应附上原因；libc 未必导出故自备。
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;

/// NLA_F_NESTED：NHA_RES_GROUP 少了它核心就不按巢状解析、回 EINVAL（iproute2 送 0x800c）。
const NLA_F_NESTED: u16 = 0x8000;

/// enum nexthop_grp_type：resilient group（只有故障链路的 bucket 会被重映射）
pub const NEXTHOP_GRP_TYPE_RES: u16 = 1;

/// 本程式保留的群组 ID，避开一般 nexthop id 的配置空间
pub const NH_GROUP_ID_V4: u32 = 0xFFFF_FF00;
pub const NH_GROUP_ID_V6: u32 = 0xFFFF_FF01;

/// resilient 弹性哈希桶数量：选用 240（2/3/4/5/6/8/10/12 的公倍数）而非 256，
/// 让单数（3、5 线）与双数（2、4、6、8 线）多 WAN 等权分流时均能整除、零余数偏斜，且建立后固定不变（REPLACE 不允许改）。
const RES_BUCKETS_MAX: usize = 240;

/// rtnh_hops 是 u8、语意为 weight-1；上限与 config::MAX_WEIGHT 一致。
pub const MAX_NEXTHOP_WEIGHT: u32 = 255;

// 探针专用路由表 / 规则（RTM_NEWRULE）：SO_BINDTODEVICE 只固定 oif，故每张 WAN 建独立表 + oif 规则让探针必有路。

/// RTM_NEWRULE/RTM_DELRULE = 32/33（不是 21/22，那是 RTM_DELADDR/GETADDR）。
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

/// enum fib_rule_attr（照 linux/rtnetlink.h 抄：FWMARK=10, TABLE=15, FWMASK=16, OIFNAME=17）
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_OIFNAME: u16 = 17;
pub const FRA_TABLE: u16 = 15;
/// 规则来源标记（u8）：清扫只删带此标记的规则，不动 mwan3/VPN 的规则。
pub const FRA_PROTOCOL: u16 = 21;

/// 本程式下发的规则所使用的 FRA_PROTOCOL 标记值（'M' = mwan4）
pub const PROBE_RULE_PROTOCOL: u8 = 0x4D;

/// enum fib_rule_action：把匹配的封包送到指定表
pub const FR_ACT_TO_TBL: u8 = 1;

/// 探针「出向」表号的起点（第 i 张 WAN 用 PROBE_TABLE_BASE + i）
pub const PROBE_TABLE_BASE: u32 = 10_000;
/// 探针出向规则的优先序起点（必须小于 main 表的 32766）
pub const PROBE_RULE_PRIORITY_BASE: u32 = 10_000;
/// slot 上限（= WAN 数上限），刻意压 64：启动清扫往返次数正比于它。
pub const PROBE_SLOT_MAX: u32 = 64;

// 策略分流规则（fib rule 的 from/to + 目标 WAN 的独立表）：ip rule 前缀匹配即可命中转发封包、无需 fwmark。

/// 策略规则的优先序起点（第 i 条用 POLICY_RULE_PRIORITY_BASE + i）
pub const POLICY_RULE_PRIORITY_BASE: u32 = 9_000;
/// 策略规则数量上限（含来源/目的展开后的总条数）
pub const POLICY_SLOT_MAX: u32 = 64;
/// 内核调度模块 fwmark 路由规则的优先序起点（位于策略分流之后、探针规则之前）
pub const FWMARK_RULE_PRIORITY_BASE: u32 = 9_200;
/// fwmark 路由规则槽位上限（与 PROBE_SLOT_MAX 一致）
pub const FWMARK_SLOT_MAX: u32 = 64;
/// enum fib_rule_attr：来源/目的前缀与 fwmark/fwmask
pub const FRA_DST: u16 = 1;
pub const FRA_SRC: u16 = 2;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_FWMASK: u16 = 16;
/// 探针目标主表 /32 的 metric；与预设路由 priority 分开才能精准辨识删除。
pub const PROBE_MAIN_ROUTE_METRIC: u32 = 42_760;

/// 隧道 underlay /32 的 metric；与探针分开才能各自精准清扫。
pub const UNDERLAY_ROUTE_METRIC: u32 = 42_761;

/// 每 WAN 上游 DNS `/32` 出口绑定的 metric；与探针 / underlay 分开才能互不覆盖且各自精准清扫。
pub const DNS_ROUTE_METRIC: u32 = 42_762;

/// 启动前清扫要删的 metric（探针 + underlay + DNS）：上次留下的出口可能已失效。
const STARTUP_SWEEP_METRICS: [(u32, &str); 3] = [
    (PROBE_MAIN_ROUTE_METRIC, "probe"),
    (UNDERLAY_ROUTE_METRIC, "underlay"),
    (DNS_ROUTE_METRIC, "dns"),
];

/// 执行期清扫只扫探针 /32：误删刚装好的 underlay / DNS /32 会破坏隧道防自环或上游 DNS 出口绑定。
const RUNTIME_SWEEP_METRICS: [(u32, &str); 1] = [(PROBE_MAIN_ROUTE_METRIC, "probe")];

// 编译期钉死以下不变式（改坏会编译失败，而不是上机才发现）。
const _: () = {
    assert!(PROBE_TABLE_BASE > 255);
    assert!(PROBE_RULE_PRIORITY_BASE > 0);
    assert!(PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX < 32_766);
    // 策略规则与 fwmark 规则的保留区段必须互不重叠且完整落在探针规则之前
    assert!(POLICY_RULE_PRIORITY_BASE > 0);
    assert!(POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX <= FWMARK_RULE_PRIORITY_BASE);
    assert!(FWMARK_RULE_PRIORITY_BASE + FWMARK_SLOT_MAX <= PROBE_RULE_PRIORITY_BASE);
    assert!(PROBE_MAIN_ROUTE_METRIC != 0);
    // 探针 /32 的 metric 不能落在表号／规则优先序的保留区段里，否则清扫会误删
    assert!(PROBE_MAIN_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(PROBE_MAIN_ROUTE_METRIC < 0xFFFF_FF00);
    // underlay /32 用另一个 metric：与探针分开才能各自精准清扫
    assert!(UNDERLAY_ROUTE_METRIC != PROBE_MAIN_ROUTE_METRIC);
    assert!(UNDERLAY_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(UNDERLAY_ROUTE_METRIC < 0xFFFF_FF00);
    // DNS /32 用独立 metric：与探针及 underlay 分开，允许同一 IP 兼作探针目标与绑定 DNS
    assert!(DNS_ROUTE_METRIC != PROBE_MAIN_ROUTE_METRIC);
    assert!(DNS_ROUTE_METRIC != UNDERLAY_ROUTE_METRIC);
    assert!(DNS_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(DNS_ROUTE_METRIC < 0xFFFF_FF00);
    // 执行期清扫只能扫探针 /32：误删 underlay/dns 会破坏隧道防自环或 DNS 路由绑定
    assert!(RUNTIME_SWEEP_METRICS.len() == 1);
    assert!(RUNTIME_SWEEP_METRICS[0].0 == PROBE_MAIN_ROUTE_METRIC);
    assert!(RUNTIME_SWEEP_METRICS[0].0 != UNDERLAY_ROUTE_METRIC);
    assert!(RUNTIME_SWEEP_METRICS[0].0 != DNS_ROUTE_METRIC);
    // 启动清扫三者都要扫（残留的 underlay / dns /32 出口可能已经失效）
    assert!(STARTUP_SWEEP_METRICS.len() == 3);
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
        b[7] = self.action;
        write_u32(&mut b, 8, self.flags);
        b
    }
}

/// struct nexthop_grp（8 bytes）—— NHA_GROUP 的每个成员；weight 与 rtnh_hops 一样是「权重 - 1」。
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
    pub metric: u32,
    /// 这条线若是隧道，列出其 underlay 对端位址；非空 = 不能当别人的 underlay 出口，且这些对端要补 /32。
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

/// 一条「探针路径」：让绑定某张 WAN 的探针一定有路可走，且尽量不影响转发。
/// 出向 = 独立表 + oif 规则；回程 = 必要时在主表补 /32（rp_filter 只查主表，不补则 SYN-ACK 被当 martian 丢掉）。
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
    /// **需要**在主表补 /32 的目标子集：同一目标可能被多条线共用，只有按 metric 选出的拥有者才会放进来。
    pub main_route_targets: Vec<Ipv4Addr>,
}

/// 一条每 WAN 上游 DNS 的主表 `/32` 出口绑定路由：让第三方 DNS 软件访问运营商 DNS 时固定走指定健康 WAN。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRoute {
    pub server: Ipv4Addr,
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
}

/// 一条策略分流规则（已展开）：from/to 为 None 代表不限制；主回圈把 config.policies 展开成此形式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub name: String,
    /// 目标 WAN 的 ifindex（仅供日志；实际下一跳由 `table` 决定）
    pub ifindex: u32,
    /// 目标 WAN 的独立路由表（沿用探针表 PROBE_TABLE_BASE + slot）
    pub table: u32,
    pub priority: u32,
    /// 来源前缀（None = 不限制）
    pub source: Option<(Ipv4Addr, u8)>,
    /// 目的前缀（None = 不限制）
    pub destination: Option<(Ipv4Addr, u8)>,
}

/// 内核态调度模块（`kmod-mwan4-sched`）配套的 `fwmark/fwmask -> table` 规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwmarkRule {
    pub ifname: String,
    pub table: u32,
    pub priority: u32,
    pub fwmark: u32,
    pub fwmask: u32,
}

struct ProbeRouteKernelState {
    table_defaults: std::collections::HashMap<u32, (Option<u32>, Option<Ipv4Addr>)>,
    main_probe_hosts: std::collections::HashMap<Ipv4Addr, (Option<u32>, Option<Ipv4Addr>)>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteNexthop {
    ifindex: u32,
    /// 网关的原始位元组（IPv4 = 4 bytes，IPv6 = 16 bytes）；None 代表直连
    gateway: Option<Vec<u8>>,
    weight: u32,
}

/// 目前下发到核心的预设路由类型：两种路由的 netlink key 不同（有无 RTA_NH_ID），切换时必须先删另一种。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledVariant {
    None,
    /// RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH
    Standard,
    /// RTA_NH_ID 指向 resilient nexthop group
    Resilient,
}

/// 一条路由讯息的落点：table = None 代表主表；dst = Some((位址位元组, 前缀长度)) 代表非预设路由。
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
    /// resilient 空闲桶迁移时间（秒），下发时换算为 centiseconds（×100）写入 NHA_RES_GROUP_IDLE_TIMER。
    resilient_idle_timer_secs: u32,
    /// resilient 失衡强制迁移时间（秒），下发时换算为 centiseconds（×100）写入 NHA_RES_GROUP_UNBALANCED_TIMER。
    resilient_unbalanced_timer_secs: u32,
    /// None = 尚未探测；Some(true/false) = 核心是否支援 resilient nexthop group
    resilient_supported: Option<bool>,
    /// (family, ifindex, gateway bytes) -> nexthop object id；ID 必须跨次呼叫稳定，核心才只重映射故障链路的 bucket。
    nh_ids: std::collections::HashMap<(u8, u32, Vec<u8>), u32>,
    next_nh_id: u32,
    installed_v4: InstalledVariant,
    installed_v6: InstalledVariant,
    /// 已下发的探针路径，key = 网卡名（用于差异比对与清理）
    probe_paths: std::collections::HashMap<String, ProbePath>,
    /// 已下发的隧道 underlay /32：对端位址 -> (ifindex, gateway)；用来差异比对，避免每轮重下。
    underlay_routes: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)>,
    /// 已下发的上游 DNS /32：DNS 服务器 IP -> (ifindex, gateway)；差异比对与内核缺失自愈用。
    dns_routes: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)>,
    /// 已下发的策略分流规则（差异比对与清理用）
    policy_rules: Vec<PolicyRule>,
    /// 已下发的内核调度器 fwmark 规则（差异比对与清理用）
    fwmark_rules: Vec<FwmarkRule>,
    /// 上一次真正下发到核心的 nexthop 集合（含权重）。用来跳过「内容完全一样」的 FIB 重下：
    /// 探针路径每 48 秒的周期刷新、以及单成员时的权重变更，都会走到同一条下发路径，
    /// 实测让核心每分钟重下 5 次完全相同的预设路由（RIB 上是等价替换，纯粹是噪声）。
    last_hops_v4: Vec<RouteNexthop>,
    last_hops_v6: Vec<RouteNexthop>,
    /// 上一次真正承载的网卡名。探针判死时用它判断「链路层是否仍然可用」，决定能不能撤预设路由。
    last_active_v4: Vec<String>,
    last_active_v6: Vec<String>,
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
                resilient_idle_timer_secs: 30,
                resilient_unbalanced_timer_secs: 60,
                resilient_supported: None,
                nh_ids: std::collections::HashMap::new(),
                next_nh_id: 1,
                installed_v4: InstalledVariant::None,
                installed_v6: InstalledVariant::None,
                probe_paths: std::collections::HashMap::new(),
                underlay_routes: std::collections::HashMap::new(),
                dns_routes: std::collections::HashMap::new(),
                policy_rules: Vec::new(),
                fwmark_rules: Vec::new(),
                last_hops_v4: Vec::new(),
                last_hops_v6: Vec::new(),
                last_active_v4: Vec::new(),
                last_active_v6: Vec::new(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                seq: 1,
                priority,
                ecmp_mode,
                resilient_idle_timer_secs: 30,
                resilient_unbalanced_timer_secs: 60,
                resilient_supported: None,
                nh_ids: std::collections::HashMap::new(),
                next_nh_id: 1,
                installed_v4: InstalledVariant::None,
                installed_v6: InstalledVariant::None,
                probe_paths: std::collections::HashMap::new(),
                underlay_routes: std::collections::HashMap::new(),
                dns_routes: std::collections::HashMap::new(),
                policy_rules: Vec::new(),
                fwmark_rules: Vec::new(),
                last_hops_v4: Vec::new(),
                last_hops_v6: Vec::new(),
                last_active_v4: Vec::new(),
                last_active_v6: Vec::new(),
            })
        }
    }

    /// 设定 resilient 空闲桶迁移时间（秒，默认 30）；数值越小空闲桶越快向空闲 WAN 迁移，活跃流不受影响。
    pub fn with_resilient_idle_timer(mut self, secs: u32) -> Self {
        self.resilient_idle_timer_secs = secs.clamp(1, 3600);
        self
    }

    /// 设定 resilient 失衡强制迁移时间（秒，默认 60；0 表示不强制迁移活跃流）。
    pub fn with_resilient_unbalanced_timer(mut self, secs: u32) -> Self {
        self.resilient_unbalanced_timer_secs = secs.min(3600);
        self
    }

    /// 调整 netlink socket 收发逾时（非 Linux 为 no-op）；查询用 manager 要短逾时，避免冻住 current_thread runtime。
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
                    // 内核把失败原因放在 extack（NLMSGERR_ATTR_MSG）；用 warn 记下来，否则只剩一个没有上下文的 EINVAL。
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

    /// 组出 RTM_NEWROUTE / RTM_DELROUTE 讯息（IPv4/IPv6 只差 family 与网关位元组长度）。
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

    /// 同 build_route_msg_ex，但可指定删除讯息使用的 protocol：启动清扫用 RTPROT_UNSPEC 才清得掉旧版本残留。
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
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        // 删除时 scope 一律 RT_SCOPE_NOWHERE（理由见 RT_SCOPE_NOWHERE）；建立时无网关的单一路由用 RT_SCOPE_LINK。
        let rtm_scope = if msg_type == RTM_DELROUTE {
            RT_SCOPE_NOWHERE
        } else if hops.len() == 1 && hops[0].gateway.is_none() {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };

        let dst_len = dst.map_or(0, |(_, len)| len);
        // 下发一率带专属 protocol；删除用呼叫端指定的值（理由见 RTPROT_MWAN4）。
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
            // 表号 > 255 只能靠 RTA_TABLE；rtm_table 低位元组会被截断，核心以 RTA_TABLE 为准。
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
        if let Some((addr, _)) = dst {
            Self::append_attr(&mut buffer, RTA_DST, addr);
        }

        // 显式带上 metric，确保 NLM_F_REPLACE / RTM_DELROUTE 能命中同一个路由 key
        Self::append_attr(&mut buffer, RTA_PRIORITY, &priority.to_ne_bytes());

        match hops.len().cmp(&1) {
            std::cmp::Ordering::Equal => {
                let hop = &hops[0];
                if let Some(gw) = &hop.gateway {
                    Self::append_attr(&mut buffer, RTA_GATEWAY, gw);
                }
                Self::append_attr(&mut buffer, RTA_OIF, &hop.ifindex.to_ne_bytes());
            }
            std::cmp::Ordering::Greater => {
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
            std::cmp::Ordering::Less => {}
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

    // nexthop object / resilient nexthop group（Linux 5.3+ / 5.14+）：resilient 只重映射故障成员的 bucket，不重算整条路由 hash。

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

    /// 组出 nexthop group 讯息：buckets = Some(n) 则附 NHA_RES_GROUP(BUCKETS + IDLE_TIMER + UNBALANCED_TIMER) + NHA_GROUP_TYPE=RES（resilient）。
    fn build_nexthop_group_msg(
        seq: u32,
        group_id: u32,
        members: &[(u32, u32)],
        buckets: Option<u16>,
        idle_timer_secs: Option<u32>,
        unbalanced_timer_secs: Option<u32>,
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
            let mut res: Vec<u8> = Vec::with_capacity(32);
            Self::append_attr(&mut res, NHA_RES_GROUP_BUCKETS, &bucket_count.to_ne_bytes());
            if let Some(secs) = idle_timer_secs {
                let cs = secs.saturating_mul(100);
                Self::append_attr(&mut res, NHA_RES_GROUP_IDLE_TIMER, &cs.to_ne_bytes());
            }
            if let Some(secs) = unbalanced_timer_secs {
                let cs = secs.saturating_mul(100);
                Self::append_attr(&mut res, NHA_RES_GROUP_UNBALANCED_TIMER, &cs.to_ne_bytes());
            }
            Self::append_attr(&mut buffer, NHA_RES_GROUP | NLA_F_NESTED, &res);
        }

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 组出删除单一 nexthop object 的讯息（NHA_ID）：family 必须与建立时一致（成员 AF_INET/AF_INET6、group AF_UNSPEC）。
    /// 且 nhmsg 除 family 外必须全零，故不能沿用带 RTPROT_STATIC 的 nhmsg_bytes()。
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
            rtm_protocol: RTPROT_MWAN4,
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

    // 探针路径：用 `oif <wan> lookup <table>` 规则把探针封包固定到自己的表。

    /// 组出 RTM_NEWRULE / RTM_DELRULE 讯息：oif|iif <ifname> + lookup <table>（用 oif 而非 fwmark，转发流量自然不会命中）。
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
            table: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        buffer.extend_from_slice(&hdr.to_bytes());

        Self::append_attr(&mut buffer, FRA_TABLE, &table.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &priority.to_ne_bytes());
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

    fn build_policy_rule_msg(seq: u32, rule: &PolicyRule, msg_type: u16, flags: u16) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(128);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        let hdr = FibRuleHdr {
            family: AF_INET,
            dst_len: rule.destination.map_or(0, |(_, len)| len),
            src_len: rule.source.map_or(0, |(_, len)| len),
            tos: 0,
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
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 同步策略分流规则：差异比对（不做全量重下），避免无谓的 netlink 往返与规则闪断。
    pub fn set_policy_rules(&mut self, wanted: &[PolicyRule]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;

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

    fn build_fwmark_rule_msg(seq: u32, rule: &FwmarkRule, msg_type: u16, flags: u16) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(128);
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

        Self::append_attr(&mut buffer, FRA_TABLE, &rule.table.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &rule.priority.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_FWMARK, &rule.fwmark.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_FWMASK, &rule.fwmask.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 同步内核调度器配套的 fwmark 路由规则（差异比对，零闪烁）。
    pub fn set_fwmark_rules(&mut self, wanted: &[FwmarkRule]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;

        let stale: Vec<FwmarkRule> = self
            .fwmark_rules
            .iter()
            .filter(|old| !wanted.contains(old))
            .cloned()
            .collect();
        for rule in stale {
            if let Err(e) = self.delete_fwmark_rule(&rule) {
                warn!(
                    "[RouteManager] Failed to remove fwmark rule for '{}' (priority {}): {e}",
                    rule.ifname, rule.priority
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
                continue;
            }
            self.fwmark_rules.retain(|r| r != &rule);
        }

        for rule in wanted {
            if self.fwmark_rules.contains(rule) {
                continue;
            }
            match self.install_fwmark_rule(rule) {
                Ok(()) => self.fwmark_rules.push(rule.clone()),
                Err(e) => {
                    warn!(
                        "[RouteManager] Failed to install fwmark rule for '{}' (priority {}): {e}",
                        rule.ifname, rule.priority
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

    fn install_fwmark_rule(&mut self, rule: &FwmarkRule) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_fwmark_rule_msg(
            seq,
            rule,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        self.commit_rule_msg(
            &msg,
            &format!(
                "fwmark rule '{}' (mark 0x{:08x}/0x{:08x} lookup {})",
                rule.ifname, rule.fwmark, rule.fwmask, rule.table
            ),
        )
    }

    fn delete_fwmark_rule(&mut self, rule: &FwmarkRule) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_fwmark_rule_msg(seq, rule, RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK);
        self.commit_rule_msg(
            &msg,
            &format!(
                "fwmark rule removal '{}' (priority {})",
                rule.ifname, rule.priority
            ),
        )
    }

    /// 清扫 fwmark 规则保留区段内本程式留下的所有规则（启动与退出共用）。
    pub fn sweep_fwmark_rules(&mut self) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let mut removed = 0usize;
        for slot in 0..FWMARK_SLOT_MAX {
            match self.delete_own_rule_by_priority(FWMARK_RULE_PRIORITY_BASE + slot) {
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
                "[RouteManager] Removed {removed} leftover fwmark rule(s) from the reserved band"
            );
        }
        self.fwmark_rules.clear();
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 差异比对探针路径：删掉多的、校验未变更的内核状态并仅按需重下，
    /// 避免每 30s 周期刷新无谓下发 RTM_NEWROUTE(REPLACE) 抬高 rt_genid 冲毁 Flow Offload 缓存。
    pub fn set_probe_paths(&mut self, wanted: &[ProbePath]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let wanted_names: std::collections::HashSet<&str> =
            wanted.iter().map(|p| p.ifname.as_str()).collect();

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

        let probe_state = self.dump_probe_route_state();

        for path in wanted {
            // 内容有变（含主表 /32 子集）必须先完整拆掉再装，否则主表那条 /32 会留在不该留的时候。
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
                } else if self.probe_routes_present_in_kernel(path, probe_state.as_ref())
                    && self.ensure_probe_rule(path).is_ok()
                {
                    continue;
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

    #[cfg(target_os = "linux")]
    fn dump_probe_route_state(&mut self) -> Option<ProbeRouteKernelState> {
        let bodies = self.dump_route_messages(AF_INET).ok()?;
        let mut table_defaults = std::collections::HashMap::new();
        let mut main_probe_hosts = std::collections::HashMap::new();
        for body in bodies {
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let msg_len = body.len();
            let dst_len = body[NlMsgHdr::LEN + 1];
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let mut priority = 0u32;
            let mut oif = None;
            let mut gateway = None;
            let mut dst = None;
            let mut off = NlMsgHdr::LEN + RtMsg::LEN;
            while off + RtAttr::LEN <= msg_len {
                let rta_len = read_u16(&body, off).unwrap_or(0) as usize;
                let rta_type = read_u16(&body, off + 2).unwrap_or(0);
                if rta_len < RtAttr::LEN || off + rta_len > msg_len {
                    break;
                }
                let data = &body[off + RtAttr::LEN..off + rta_len];
                match rta_type {
                    RTA_TABLE => table = read_u32(data, 0).unwrap_or(table),
                    RTA_PRIORITY => priority = read_u32(data, 0).unwrap_or(priority),
                    RTA_OIF => oif = read_u32(data, 0),
                    RTA_GATEWAY if data.len() == 4 => {
                        gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                    }
                    RTA_DST if data.len() == 4 => {
                        dst = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                    }
                    _ => {}
                }
                off += rta_align(rta_len);
            }
            if dst_len == 0 && table >= PROBE_TABLE_BASE {
                table_defaults.insert(table, (oif, gateway));
            } else if dst_len == 32
                && table == u32::from(RT_TABLE_MAIN)
                && priority == PROBE_MAIN_ROUTE_METRIC
            {
                if let Some(addr) = dst {
                    main_probe_hosts.insert(addr, (oif, gateway));
                }
            }
        }
        Some(ProbeRouteKernelState {
            table_defaults,
            main_probe_hosts,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn dump_probe_route_state(&mut self) -> Option<ProbeRouteKernelState> {
        None
    }

    fn probe_routes_present_in_kernel(
        &self,
        path: &ProbePath,
        state: Option<&ProbeRouteKernelState>,
    ) -> bool {
        let Some(state) = state else {
            return false;
        };
        if state.table_defaults.get(&path.table) != Some(&(Some(path.ifindex), path.gateway)) {
            return false;
        }
        path.main_route_targets.iter().all(|target| {
            state.main_probe_hosts.get(target) == Some(&(Some(path.ifindex), path.gateway))
        })
    }

    fn ensure_probe_rule(&mut self, path: &ProbePath) -> io::Result<()> {
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
        )
    }

    // 路由查询 / 转储：用来「问内核」而不是靠猜（要不要补主表 /32、分辨线路不通与本机没路）。

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

    #[cfg(target_os = "linux")]
    fn is_no_route_errno(errno: i32) -> bool {
        matches!(
            errno,
            libc::ENETUNREACH | libc::ENETDOWN | libc::EHOSTUNREACH
        )
    }

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

    /// 问内核到 dst 的路由；oif 有值时模拟绑定该设备查找。Ok(None) = 没有可用的路（探针超时讯号）。
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
                    Some(code) if code < 0 && Self::is_no_route_errno(code.saturating_neg()) => {
                        return Ok(None);
                    }
                    // 其它 errno 是真错误：当成「没有路由」会让呼叫端误判路径缺失而乱补 /32
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

    /// 发送 route dump 并收集所有 RTM_NEWROUTE；只认 seq 相符的 DONE，NLM_F_DUMP_INTR 时自动重试一次。
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

    /// 转储主表中 metric == metric 的所有路由 → (表号, 目的位址, 前缀长度)；只认 32 位元前缀。
    #[cfg(target_os = "linux")]
    pub fn dump_host_routes_with_metric(
        &mut self,
        metric: u32,
    ) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        let mut out = Vec::new();
        for body in self.dump_route_messages(AF_INET)? {
            // 内核理论上传不出比 rtmsg 短的消息，但少一个位元组就会 panic（release 下 panic=abort，daemon 直接死）。
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

    /// 主表有没有任何预设路由（含我们自己发的）；别用「到目标的路」判断补不补 /32（自己的 /32 会振荡）。
    #[cfg(target_os = "linux")]
    pub fn has_main_default_route(&mut self, family: u8) -> io::Result<bool> {
        Ok(!self.dump_default_routes(family)?.is_empty())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_main_default_route(&mut self, _family: u8) -> io::Result<bool> {
        Ok(false)
    }

    /// 转储主表中「不是我们的」预设路由 → (表号, metric)；已排除 skip_metric（我们自己那条）。
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

    /// 转储主表中「非 mwan4 下发」的 IPv4 默认路由网关（ifindex -> gateway）。
    /// 用于 gateway 留空的 DHCP/以太网 WAN 自动探测网关，避免退化成无网关直连路由在广播网段断流。
    #[cfg(target_os = "linux")]
    pub fn dump_external_gateways(&mut self) -> io::Result<std::collections::HashMap<u32, Ipv4Addr>> {
        let mut out: std::collections::HashMap<u32, (u32, Ipv4Addr)> =
            std::collections::HashMap::new();
        for body in self.dump_route_messages(AF_INET)? {
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let dst_len = body[NlMsgHdr::LEN + 1];
            let proto = body[NlMsgHdr::LEN + 5];
            if dst_len != 0 || proto == RTPROT_MWAN4 {
                continue;
            }
            let msg_len = body.len();
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let mut priority = 0u32;
            let mut oif: Option<u32> = None;
            let mut gateway: Option<Ipv4Addr> = None;
            let mut multipath: Vec<(u32, Ipv4Addr)> = Vec::new();
            let mut off = NlMsgHdr::LEN + RtMsg::LEN;
            while off + RtAttr::LEN <= msg_len {
                let rta_len = read_u16(&body, off).unwrap_or(0) as usize;
                let rta_type = read_u16(&body, off + 2).unwrap_or(0);
                if rta_len < RtAttr::LEN || off + rta_len > msg_len {
                    break;
                }
                let data = &body[off + RtAttr::LEN..off + rta_len];
                match rta_type {
                    RTA_TABLE => table = read_u32(data, 0).unwrap_or(table),
                    RTA_PRIORITY => priority = read_u32(data, 0).unwrap_or(priority),
                    RTA_OIF => oif = read_u32(data, 0),
                    RTA_GATEWAY if data.len() == 4 => {
                        gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                    }
                    RTA_MULTIPATH => {
                        let mut mp_off = 0;
                        while mp_off + RtNextHop::LEN <= data.len() {
                            let rtnh_len = read_u16(data, mp_off).unwrap_or(0) as usize;
                            let rtnh_ifindex = read_i32(data, mp_off + 4).unwrap_or(0);
                            if rtnh_len < RtNextHop::LEN || mp_off + rtnh_len > data.len() {
                                break;
                            }
                            let mut a_off = mp_off + RtNextHop::LEN;
                            while a_off + RtAttr::LEN <= mp_off + rtnh_len {
                                let alen = read_u16(data, a_off).unwrap_or(0) as usize;
                                let atype = read_u16(data, a_off + 2).unwrap_or(0);
                                if alen < RtAttr::LEN || a_off + alen > mp_off + rtnh_len {
                                    break;
                                }
                                let adata = &data[a_off + RtAttr::LEN..a_off + alen];
                                if atype == RTA_GATEWAY && adata.len() == 4 && rtnh_ifindex > 0 {
                                    let gw = Ipv4Addr::new(adata[0], adata[1], adata[2], adata[3]);
                                    if !gw.is_unspecified() {
                                        multipath.push((rtnh_ifindex as u32, gw));
                                    }
                                }
                                a_off += rta_align(alen);
                            }
                            mp_off += rta_align(rtnh_len);
                        }
                    }
                    _ => {}
                }
                off += rta_align(rta_len);
            }
            if table != u32::from(RT_TABLE_MAIN) {
                continue;
            }
            if let (Some(idx), Some(gw)) = (oif, gateway) {
                if idx > 0 && !gw.is_unspecified() {
                    out.entry(idx)
                        .and_modify(|cur| {
                            if priority < cur.0 {
                                *cur = (priority, gw);
                            }
                        })
                        .or_insert((priority, gw));
                }
            }
            for (idx, gw) in multipath {
                out.entry(idx)
                    .and_modify(|cur| {
                        if priority < cur.0 {
                            *cur = (priority, gw);
                        }
                    })
                    .or_insert((priority, gw));
            }
        }
        Ok(out.into_iter().map(|(k, (_, gw))| (k, gw)).collect())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn dump_external_gateways(&mut self) -> io::Result<std::collections::HashMap<u32, Ipv4Addr>> {
        Ok(std::collections::HashMap::new())
    }

    #[cfg(target_os = "linux")]
    fn dump_default_routes(&mut self, family: u8) -> io::Result<Vec<(u32, u32)>> {
        Ok(self
            .dump_main_default_route_metas(family)?
            .into_iter()
            .map(|(table, prio, _, _)| (table, prio))
            .collect())
    }

    #[cfg(target_os = "linux")]
    fn dump_main_default_route_metas(
        &mut self,
        family: u8,
    ) -> io::Result<Vec<(u32, u32, u8, Option<u32>)>> {
        let mut out = Vec::new();
        for body in self.dump_route_messages(family)? {
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let msg_len = body.len();
            let dst_len = body[NlMsgHdr::LEN + 1];
            let proto = body[NlMsgHdr::LEN + 5];
            let mut priority = None;
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let mut nh_id = None;
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
                    RTA_NH_ID => nh_id = read_u32(data, 0),
                    _ => {}
                }
                off += rta_align(rta_len);
            }
            let prio = priority.unwrap_or(0);
            // 只认主表：探针表里也有 default，不按表号过滤会误判成「主表有预设路由」（实测踩过）。
            if dst_len == 0 && table == u32::from(RT_TABLE_MAIN) {
                out.push((table, prio, proto, nh_id));
            }
        }
        debug!("[RouteManager] main-table default routes: {out:?}");
        Ok(out)
    }

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

    /// 清掉主表里探针的 /32；执行期入口，不含 underlay /32（那是同一批 Apply 刚装好的资产）。
    pub fn sweep_own_probe_host_routes(&mut self) -> io::Result<usize> {
        self.sweep_host_routes_for(&RUNTIME_SWEEP_METRICS)
    }

    /// 清掉主表里所有属于本程式的 /32（探针 + 隧道 underlay）；只供启动前使用。
    pub fn sweep_all_own_host_routes(&mut self) -> io::Result<usize> {
        self.sweep_host_routes_for(&STARTUP_SWEEP_METRICS)
    }

    fn sweep_host_routes_for(&mut self, metrics: &[(u32, &str)]) -> io::Result<usize> {
        let mut removed = 0;
        for (metric, kind) in metrics {
            removed += self.sweep_host_routes_with_metric(*metric, kind)?;
        }
        Ok(removed)
    }

    fn sweep_host_routes_with_metric(&mut self, metric: u32, kind: &str) -> io::Result<usize> {
        let victims = self.dump_host_routes_with_metric(metric)?;
        let mut removed = 0;
        for (table, dst, dst_len) in victims {
            // 只清主表：探针与 underlay /32 都在主表；其它表里同 metric 的 /32 是第三方的（dump 不过滤表号）。
            if table != u32::from(RT_TABLE_MAIN) {
                debug!(
                    "[RouteManager] Ignoring non-main-table {kind} host route {dst}/{dst_len} in table {table}"
                );
                continue;
            }
            // 主表用 rtm_table(254) 表达；带 RTA_TABLE 去删主表路由内核会回 ESRCH 而路由仍在。
            debug!(
                "[RouteManager] Removing stale {kind} host route {dst}/{dst_len} in table {table} (metric {metric})"
            );
            self.seq += 1;
            let seq = self.seq;
            let octets = dst.octets();
            // 清扫用 RTPROT_UNSPEC 才清得掉旧版本以 RTPROT_STATIC 留下的 /32；一般删除用专属 protocol。
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

    /// 清扫保留区段内残留的探针规则（只删带 PROBE_RULE_PROTOCOL 标记的，不动第三方）。
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
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 只靠「优先序 + 来源标记」删自己的规则（不需知道 oif／表号）；回传是否真的删掉一条。
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

    /// 删掉「这次设定会用到」的探针目标在主表的 /32（向后相容）；删除不带 nexthop，否则闸道变过会回 ESRCH。
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
        // 主表探针目标 /32；删除不带 nexthop，只按 (table, dst, metric) 命中（否则闸道变过就删不掉）。
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

    /// 送出规则讯息；「本来就不存在」与「已经存在」都算成功，让安装／清除流程幂等。
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

    /// 送出探针路由讯息：成功时记 debug（探针每 30 秒重下一次，info 会洗掉日志）。
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

    /// 从 NLMSG_ERROR 回应取出内核 extack 字串（NLMSGERR_ATTR_MSG = 1）；格式：nlmsghdr + i32 + 原始请求 nlmsghdr + 属性。
    fn parse_extack(buf: &[u8], len: usize) -> Option<String> {
        let mut off = NlMsgHdr::LEN + 4;
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

    /// 这则讯息是不是「删除」？直接读 nlmsg_type，所有删除路径共用同一套「本来就不存在」容错。
    fn message_is_delete(buf: &[u8]) -> bool {
        matches!(
            read_u16(buf, 4),
            Some(RTM_DELROUTE) | Some(RTM_DELRULE) | Some(RTM_DELNEXTHOP)
        )
    }

    /// 删除「本来就不存在」时：路由回 ESRCH、规则回 ENOENT。刻意不把 EINVAL 当 absent——那代表请求本身有问题。
    fn is_absent_object(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(ESRCH) | Some(ENOENT))
    }

    /// 装置掉载波（或消失）时，核心会自己把 nexthop object 连同引用它的 nh-id 路由一起收走；
    /// 此后按 nhid 删路由会回 **EINVAL**（内核讯息 `Nexthop id does not exist`，实测 Linux 6.12）。
    /// 那个 EINVAL 不是「请求有问题」，而是「对象已经被核心收走」——必须当成成功，
    /// 否则 `installed_variant` 会永远停在 Resilient，每个 tick 重试一次注定失败的删除。
    fn nh_route_already_reclaimed(err: &io::Error) -> bool {
        err.raw_os_error() == Some(libc::EINVAL)
    }

    /// 送出 netlink 讯息并等 ACK；「本来就不存在」与「已经存在」都算成功，让整个流程幂等。
    fn commit_msg(&mut self, buffer: &[u8], label: &str) -> io::Result<()> {
        debug!(
            "[RouteManager] Sending {label} (len: {} bytes)",
            buffer.len()
        );
        match self.send_and_wait_ack(buffer) {
            Ok(()) => {
                // 每次下发都记 info 会让 OpenWrt 的 128KB 日志环被塞满（实测 91% 的条目来自本程式），
                // 详情降为 debug，真正重要的状态变化（链路上下、撤路由决策）才留在 info/warn。
                debug!("[RouteManager] {label} committed.");
                Ok(())
            }
            Err(e) if Self::message_is_delete(buffer) && Self::is_absent_object(&e) => {
                debug!("[RouteManager] {label}: object already absent, nothing to do.");
                Ok(())
            }
            Err(e) => {
                // 失败要 warn：静默回传 Err 会让上层只剩一个没有上下文的 EINVAL。
                warn!("[RouteManager] {label} failed: {e}");
                Err(e)
            }
        }
    }

    /// 删除本程式安装的预设路由（全断与优雅退出）；必须依实际 variant 分派，成功才清 bookkeeping。
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
                match self.delete_nh_route(family, group_id) {
                    Ok(()) => {
                        self.set_installed_variant(family, InstalledVariant::None);
                        self.teardown_resilient(family, group_id);
                        Ok(())
                    }
                    // 载波掉时核心已自行收走 nexthop object 与这条路由（见 helper 注解）：
                    // 当作成功，把状态清干净，否则会卡在 Resilient 反复重试。
                    Err(e) if Self::nh_route_already_reclaimed(&e) => {
                        debug!(
                            "[RouteManager] {} nexthop-group route was already reclaimed by the kernel ({e})",
                            Self::family_name(family)
                        );
                        self.set_installed_variant(family, InstalledVariant::None);
                        self.teardown_resilient(family, group_id);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    // 模式分派：标准 multipath vs. resilient nexthop group

    /// 计算隧道 underlay /32 的期望集合；出口取非隧道活跃 WAN 中 metric 最小者（拿隧道当隧道 underlay 会递回）。
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

    /// 决定哪些 underlay /32 需要重下发；不能只信快取（核心缺失时必须重下），转储失败则退回快取判断。
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

    /// 同步隧道 underlay 对端的 /32：封装封包走含该隧道的 ECMP 会约 1/N 自环，故补 /32 固定走非隧道线。
    fn sync_underlay_routes(&mut self, active_wans: &[ActiveWanRoute]) -> io::Result<()> {
        let wanted = Self::plan_underlay_routes(active_wans);

        // 先问核心这些 /32 到底在不在：只信快取会卡在「自以为装好、其实一条都没有」的死状态。
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

        for (addr, ifindex, gateway) in
            Self::plan_underlay_repairs(&wanted, &self.underlay_routes, kernel_present.as_ref())
        {
            self.install_underlay_route(addr, ifindex, gateway.clone())?;
            self.underlay_routes.insert(addr, (ifindex, gateway));
        }
        Ok(())
    }

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

    /// 退出时拆除所有本进程安装的隧道 underlay `/32`（即使 `remove_routes_on_exit = false` 也必须拆，避免黑洞到失效出口）。
    pub fn clear_underlay_routes(&mut self) -> io::Result<()> {
        self.sync_underlay_routes(&[])
    }

    /// 同步上游 DNS `/32` 出口绑定路由：不占本地 53 端口、不碰第三方 DNS 配置，仅在 FIB 层将各运营商 DNS 钉到对应健康 WAN。
    pub fn sync_dns_routes(&mut self, wanted_routes: &[DnsRoute]) -> io::Result<()> {
        let wanted: Vec<(Ipv4Addr, u32, Option<Vec<u8>>)> = wanted_routes
            .iter()
            .map(|r| {
                (
                    r.server,
                    r.ifindex,
                    r.gateway
                        .filter(|g| !g.is_unspecified())
                        .map(|g| g.octets().to_vec()),
                )
            })
            .collect();

        // 查询内核现存的 DNS /32 路由，防止被外部 flush 或链路重置后缓存失步。
        let kernel_present: Option<std::collections::HashSet<Ipv4Addr>> =
            match self.dump_host_routes_with_metric(DNS_ROUTE_METRIC) {
                Ok(rows) => Some(
                    rows.into_iter()
                        .filter(|(table, _, _)| *table == u32::from(RT_TABLE_MAIN))
                        .map(|(_, addr, _)| addr)
                        .collect(),
                ),
                Err(e) => {
                    debug!(
                        "[RouteManager] Could not dump DNS host routes ({e}); \
                         falling back to in-memory cache"
                    );
                    None
                }
            };

        let mut first_err: Option<io::Error> = None;

        let stale: Vec<Ipv4Addr> = self
            .dns_routes
            .keys()
            .filter(|addr| !wanted.iter().any(|(t, _, _)| t == *addr))
            .cloned()
            .collect();
        for addr in stale {
            if kernel_present
                .as_ref()
                .is_some_and(|present| !present.contains(&addr))
            {
                debug!("[RouteManager] DNS host route {addr}/32 already gone from kernel");
                self.dns_routes.remove(&addr);
                continue;
            }
            if let Err(e) = self.delete_dns_route(addr) {
                warn!("[RouteManager] Failed to remove DNS host route {addr}/32: {e}");
                if first_err.is_none() {
                    first_err = Some(e);
                }
                continue;
            }
            self.dns_routes.remove(&addr);
        }

        for (addr, ifindex, gateway) in
            Self::plan_underlay_repairs(&wanted, &self.dns_routes, kernel_present.as_ref())
        {
            match self.install_dns_route(addr, ifindex, gateway.clone()) {
                Ok(()) => {
                    self.dns_routes.insert(addr, (ifindex, gateway));
                }
                Err(e) => {
                    warn!(
                        "[RouteManager] Failed to install DNS host route {addr}/32 (oif {ifindex}): {e}"
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

    fn install_dns_route(
        &mut self,
        server: Ipv4Addr,
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
        let octets = server.octets();
        let msg = Self::build_route_msg_ex(
            DNS_ROUTE_METRIC,
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
        self.commit_msg(&msg, &format!("DNS route {server}/32 (oif {ifindex})"))
    }

    fn delete_dns_route(&mut self, server: Ipv4Addr) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let octets = server.octets();
        let msg = Self::build_route_msg_ex(
            DNS_ROUTE_METRIC,
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
        self.commit_msg(&msg, &format!("DNS route {server}/32 removal"))
    }

    /// 更新 IPv4 预设路由（方式由 ecmp_mode 决定）；空阵列 = 所有 WAN 断线，主动删除预设路由。
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

        // 先确保隧道 underlay 对端有 /32 可走（否则 ECMP 会把封装封包塞回隧道自环）；只告警不中断。
        if let Err(e) = self.sync_underlay_routes(active_wans) {
            warn!("[RouteManager] Failed to sync underlay routes: {e}");
        }

        // 记下「刚刚还在承载」的网卡：探针全部判死时要据此判断链路层是否还活着。
        if !active_wans.is_empty() {
            self.last_active_v4 = active_wans.iter().map(|w| w.ifname.clone()).collect();
        }
        if self.fib_rewrite_redundant(AF_INET, &hops) {
            debug!(
                "[RouteManager] IPv4 default route already matches ({} nexthop(s)); skipping FIB rewrite",
                hops.len()
            );
            return Ok(());
        }

        let result = match self.ecmp_mode {
            EcmpMode::Standard => {
                self.drop_resilient_if_active(AF_INET);
                self.apply_standard(AF_INET, &hops)
            }
            EcmpMode::Resilient => {
                self.apply_resilient_with_teardown(AF_INET, NH_GROUP_ID_V4, &hops)
            }
            EcmpMode::Auto => self.apply_auto(AF_INET, NH_GROUP_ID_V4, &hops),
        };
        if result.is_ok() && !hops.is_empty() {
            self.remember_applied(AF_INET, &hops);
        }
        result
    }

    /// IPv6 版：只有设定了 gateway6 才产生 nexthop；IPv6 跟随同一个 IPv4 健康状态，不另外探测。
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
        if !active_wans.is_empty() {
            self.last_active_v6 = active_wans.iter().map(|w| w.ifname.clone()).collect();
        }
        if self.fib_rewrite_redundant(AF_INET6, &hops) {
            debug!(
                "[RouteManager] IPv6 default route already matches ({} nexthop(s)); skipping FIB rewrite",
                hops.len()
            );
            return Ok(());
        }
        let result = match self.ecmp_mode {
            EcmpMode::Standard => {
                self.drop_resilient_if_active(AF_INET6);
                self.apply_standard(AF_INET6, &hops)
            }
            EcmpMode::Resilient => {
                self.apply_resilient_with_teardown(AF_INET6, NH_GROUP_ID_V6, &hops)
            }
            EcmpMode::Auto => self.apply_auto(AF_INET6, NH_GROUP_ID_V6, &hops),
        };
        if result.is_ok() && !hops.is_empty() {
            self.remember_applied(AF_INET6, &hops);
        }
        result
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

    /// 核心里是否确实存在我们那条预设路由（metric == `priority` 且 protocol == `RTPROT_MWAN4`）。
    /// dump 失败时保守回传 true：误判成「已存在」只损失一次自愈机会；误判成「不存在」会让每个 tick 都重下路由。
    #[cfg(target_os = "linux")]
    fn our_default_route_present(&mut self, family: u8) -> bool {
        match self.dump_main_default_route_metas(family) {
            Ok(routes) => routes
                .iter()
                .any(|(_, metric, proto, _)| *metric == self.priority && *proto == RTPROT_MWAN4),
            Err(e) => {
                debug!("[RouteManager] default-route dump failed ({e}); assuming ours is present");
                true
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn our_default_route_present(&mut self, _family: u8) -> bool {
        true
    }

    /// 核心里是否确实存在引用指定 resilient nexthop group 的预设路由。
    #[cfg(target_os = "linux")]
    fn our_resilient_route_present(&mut self, family: u8, group_id: u32) -> bool {
        match self.dump_main_default_route_metas(family) {
            Ok(routes) => routes.iter().any(|(_, metric, proto, nh_id)| {
                *metric == self.priority && *proto == RTPROT_MWAN4 && *nh_id == Some(group_id)
            }),
            Err(e) => {
                debug!("[RouteManager] resilient route dump failed ({e}); assuming ours is present");
                true
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn our_resilient_route_present(&mut self, _family: u8, _group_id: u32) -> bool {
        true
    }

    /// auto/resilient 下核心「应该」装成的变体。resilient 支援度还没探明（None）时不参与跳过判断，
    /// 否则 auto 模式会永远停在 standard 不再尝试升级。
    fn expected_variant(&self) -> InstalledVariant {
        match self.ecmp_mode {
            EcmpMode::Standard => InstalledVariant::Standard,
            EcmpMode::Resilient | EcmpMode::Auto => match self.resilient_supported {
                Some(true) => InstalledVariant::Resilient,
                _ => InstalledVariant::Standard,
            },
        }
    }

    /// 这次下发是否与核心现状完全等价：成员/权重一样、变体已落定、而且路由真的还在。
    /// 等价就直接跳过——动态权重被限速逻辑反复重算、探针路径每 48 秒周期刷新，都会走进来；
    /// 实测这些重下在 RIB 上是等价替换，只是把日志与 netlink 流量灌满。
    fn fib_rewrite_redundant(&mut self, family: u8, hops: &[RouteNexthop]) -> bool {
        let last = if family == AF_INET6 {
            &self.last_hops_v6
        } else {
            &self.last_hops_v4
        };
        !hops.is_empty()
            && hops == last.as_slice()
            && self.resilient_supported.is_some()
            && self.installed_variant(family) == self.expected_variant()
            && self.our_default_route_present(family)
    }

    fn remember_applied(&mut self, family: u8, hops: &[RouteNexthop]) {
        if family == AF_INET6 {
            self.last_hops_v6 = hops.to_vec();
        } else {
            self.last_hops_v4 = hops.to_vec();
        }
    }

    /// 我们那条预设路由现在是否被核心标记成 linkdown。
    ///
    /// 回传 `Some(true)` = 核心认为这条路由的出口在链路层已经不可用（网卡掉了载波／装置消失，
    /// `rtm_flags` 带 `RTNH_F_LINKDOWN`，`ip route show` 会印出 `linkdown`）；
    /// `Some(false)` = 路由还在且核心认为可用；`None` = 查不到（路由已撤掉，或 dump 失败）。
    ///
    /// 用核心自己的路由状态而不是 `/sys/class/net/*/operstate`：前者在网络命名空间内也正确
    /// （测试就是在 netns 里跑），后者在 netns 里读不到任何东西。
    #[cfg(target_os = "linux")]
    fn our_default_route_linkdown(&mut self, family: u8) -> Option<bool> {
        let bodies = self.dump_route_messages(family).ok()?;
        let mut found = None;
        for body in bodies {
            if body.len() < NlMsgHdr::LEN + RtMsg::LEN {
                continue;
            }
            let msg_len = body.len();
            let dst_len = body[NlMsgHdr::LEN + 1];
            let mut priority = None;
            let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
            let flags = read_u32(&body, NlMsgHdr::LEN + 8).unwrap_or(0);
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
            if dst_len == 0
                && table == u32::from(RT_TABLE_MAIN)
                && priority.unwrap_or(0) == self.priority
            {
                found = Some(flags & RTNH_F_LINKDOWN != 0);
            }
        }
        found
    }

    #[cfg(not(target_os = "linux"))]
    fn our_default_route_linkdown(&mut self, _family: u8) -> Option<bool> {
        None
    }

    /// 探针判死时，是否该「保留」预设路由而不是撤掉让兜底接手。
    ///
    /// 只有核心自己把这条路由标成 linkdown（载波真的掉了、装置消失）时才撤——那时我们这条
    /// 路由必然黑洞，兜底才有意义。反之，探针超时只证明「这一刻没收到回包」：撤掉唯一那条
    /// metric 0 的路由，会把全部流量交给另一张网卡上、我们从来没验证过能不能上网的兜底路由
    /// （换 device = 换 NAT 源 IP = 既有连线全断）。实测（校园网 + 单线）这个组合每 6 分钟断一次，
    /// 危害远大于误判本身。
    fn keep_route_on_probe_only_down(&mut self, family: u8) -> bool {
        matches!(self.our_default_route_linkdown(family), Some(false))
    }

    /// 全部 WAN 都 DOWN 时：只有我们这一条预设路由 ⇒ 保留；主表还有别人的 ⇒ 删掉我们这条让兜底接手。
    /// 删掉的理由：载波掉时内核不会自动移除「dev 指到该设备」的路由，它会继续胜过 metric 更大的兜底。
    fn handle_all_links_down(&mut self, family: u8) -> io::Result<()> {
        let others = self
            .dump_other_default_routes(family, self.priority)
            .unwrap_or_default();

        if self.keep_route_on_probe_only_down(family) {
            let prev = if family == AF_INET6 {
                &self.last_active_v6
            } else {
                &self.last_active_v4
            };
            let other_metrics: Vec<u32> = others.iter().map(|(_, metric)| *metric).collect();
            warn!(
                "[RouteManager] ALL WAN LINKS DOWN by probe, but every managed interface is still \
                 link-up ({prev:?}): KEEPING the {} default route instead of handing all traffic to \
                 the unverified fallback route(s) with metric {other_metrics:?}. Probe timeouts alone \
                 are not proof of carrier loss; withdrawing the metric-0 route would change the NAT \
                 source IP and break every established flow.",
                Self::family_name(family)
            );
            return Ok(());
        }

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
        // 依实际安装的 variant 删除：标准与 nh-id 路由 key 不同，用错会被当成「本来就不存在」而留下黑洞路由。
        match self.installed_variant(family) {
            InstalledVariant::Resilient => self.remove_installed_default_route(family)?,
            _ => {
                self.delete_standard_route(family)?;
                self.set_installed_variant(family, InstalledVariant::None);
            }
        }
        Ok(())
    }

    /// 标准 multipath 路由（RTA_MULTIPATH），resilient 失败时的回退；保持原子 replace 语意，不出现无预设路由的空窗。
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

    /// 只有真正的「不支援」才永久退回标准 ECMP；EINVAL 可靠拆除重建恢复，算进去会让 auto 永不重试。
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

    /// 实际安装到核心的 IPv4 预设路由变体；auto 退回 standard 时仍须清 conntrack（见 FIX-8）。
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

    fn drop_resilient_if_active(&mut self, family: u8) {
        let group_id = Self::group_id_for(family);
        if self.installed_variant(family) == InstalledVariant::Resilient
            || self.has_any_member(family)
        {
            self.teardown_resilient(family, group_id);
        }
    }

    /// 拆除顺序：路由 → group → 成员（否则 group 仍被引用删不掉）；只有原本是 Resilient 才清 variant。
    fn teardown_resilient(&mut self, family: u8, group_id: u32) {
        if self.installed_variant(family) == InstalledVariant::Resilient {
            match self.delete_nh_route(family, group_id) {
                Ok(()) => {}
                // 载波掉时核心已自行收走 nexthop object 与这条路由（见 helper 注解）：
                // 继续往下清成员即可，别把它当失败卡住。
                Err(e) if Self::nh_route_already_reclaimed(&e) => {
                    debug!(
                        "[RouteManager] {} nexthop-group route was already reclaimed by the kernel ({e})",
                        Self::family_name(family)
                    );
                }
                Err(e) => {
                    warn!(
                        "[RouteManager] Failed to remove {} nexthop-group route ({e}); \
                         keeping the group for a later retry",
                        Self::family_name(family)
                    );
                    return;
                }
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
        // 全断处理与 apply_standard 一致，必须放在 variant 切换之前，否则会先把标准路由删掉再原地不动。
        if hops.is_empty() {
            return self.handle_all_links_down(family);
        }

        // bucket 上限检查必须在删标准路由之前，否则会留下「没有预设路由」的空窗。
        if hops.len() > RES_BUCKETS_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} nexthops exceed the resilient bucket limit of {RES_BUCKETS_MAX}",
                    hops.len()
                ),
            ));
        }

        // 标准路由与 nh_id 路由 key 不同，切换时必须先删旧的，否则核心会保留两条 default route。
        if self.installed_variant(family) == InstalledVariant::Standard {
            self.delete_standard_route(family)?;
            self.set_installed_variant(family, InstalledVariant::None);
        }

        // 确保成员 nexthop object 存在；ID 沿用既有配置，核心才会认为成员没变而保留它负责的 bucket。
        let mut members: Vec<(u32, u32)> = Vec::with_capacity(hops.len());
        for hop in hops {
            let id = self.alloc_nh_id(family, hop.ifindex, hop.gateway.as_ref());
            self.ensure_nexthop(family, id, hop.ifindex, hop.gateway.as_deref())?;
            members.push((id, hop.weight));
        }

        // bucket 数固定用上限（2 的幂、涵盖任何合法成员数）。
        // 不按成员数取最小 2 的幂：核心 REPLACE 时不允许改变 bucket 数（回 EINVAL），跨边界会当轮失效。
        let buckets = RES_BUCKETS_MAX as u16;
        self.ensure_nexthop_group(group_id, &members, buckets)?;

        // 已用同一 resilient group 安装且内核里 mwan4 的默认路由仍在时，仅更新 group 成员/权重即可；
        // 避免无谓重下 RTM_NEWROUTE(REPLACE) 抬高 rt_genid 并失效 nf_flow_table / Flow Offload。
        if !(self.installed_variant(family) == InstalledVariant::Resilient
            && self.our_resilient_route_present(family, group_id))
        {
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
        }

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
            Some(self.resilient_idle_timer_secs),
            Some(self.resilient_unbalanced_timer_secs),
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

    /// 优雅退出时清干净所有产物；只有我们真的下发过预设路由时才删它（否则那条其实是 netifd 的）。
    pub fn cleanup_routes(&mut self) -> io::Result<()> {
        // 策略规则与 fwmark 规则先拆（指向探针表，须在表被清空前移除）。
        if let Err(e) = self.sweep_policy_rules() {
            warn!("[RouteManager] Failed to remove policy rules on shutdown: {e}");
        }
        if let Err(e) = self.sweep_fwmark_rules() {
            warn!("[RouteManager] Failed to remove fwmark rules on shutdown: {e}");
        }

        let _ = self.set_probe_paths(&[]);

        // 先按实际安装的 variant 删预设路由；不能先 teardown_resilient，否则 Standard 的 variant 会被清成 None。
        let mut result = self.remove_installed_default_route(AF_INET);
        result = result.and(self.remove_installed_default_route(AF_INET6));

        // underlay /32 与 DNS /32 也要拆：它们指向的闸道可能已失效，留着会让封装或 DNS 封包被黑洞到旧出口。
        if let Err(e) = self.sync_underlay_routes(&[]) {
            warn!("[RouteManager] Failed to remove underlay routes on shutdown: {e}");
            if result.is_ok() {
                result = Err(e);
            }
        }
        if let Err(e) = self.sync_dns_routes(&[]) {
            warn!("[RouteManager] Failed to remove DNS routes on shutdown: {e}");
            if result.is_ok() {
                result = Err(e);
            }
        }

        // 无论预设路由删除成功与否，都再尝试拆掉残留的 resilient group / 成员。
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
            debug!(
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
            debug!(
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

/// 真实核心的 netns 整合测试（预设 ignore）。
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
        // 超过上限一律夹住，避免 as u8 静默截断；上限 255 而非 256：Linux < 6.9 的 nexthop_grp.weight 只到 254。
        assert_eq!(300u32.clamp(1, MAX_NEXTHOP_WEIGHT), 255);
        assert_eq!(0u32.clamp(1, MAX_NEXTHOP_WEIGHT), 1);
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
        assert_eq!(attrs[1].1.len(), 16);
        assert_eq!(attrs[1].1, gw.octets().to_vec());
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

    /// 这些列举值照 Linux uapi 抄：抄错只会得到没有上下文的 EINVAL，故用测试钉住。
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

        // 除了 nh_family，nhmsg 其余栏位必须全零：nh_valid_get_del_req() 对 protocol/scope/flags 非零回 EINVAL。
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
        // 成员用 AF_INET 建立、group 用 AF_UNSPEC，删除时带对应 family（保留对称写法以防旧核心比对）。
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
            Some(240),
            Some(30),
            Some(60),
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
                NHA_RES_GROUP | NLA_F_NESTED
            ]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(NH_GROUP_ID_V4));
        assert_eq!(read_u16(&attrs[1].1, 0), Some(NEXTHOP_GRP_TYPE_RES));

        let grp = &attrs[2].1;
        assert_eq!(grp.len(), 2 * NextHopGrp::LEN);
        assert_eq!(read_u32(grp, 0), Some(1));
        assert_eq!(grp[4], 0); // weight 1 -> hops 0
        assert_eq!(read_u32(grp, 8), Some(2));
        assert_eq!(grp[12], 2); // weight 3 -> hops 2

        // NHA_RES_GROUP 是巢状属性；曾误用顶层 NHA_RES_BUCKETS(13) 并以 u32 编码，核心回 EINVAL。
        let res = parse_attr_stream(&attrs[3].1, 0);
        assert_eq!(
            attr_types(&res),
            vec![
                NHA_RES_GROUP_BUCKETS,
                NHA_RES_GROUP_IDLE_TIMER,
                NHA_RES_GROUP_UNBALANCED_TIMER
            ]
        );
        assert_eq!(res[0].1.len(), 2, "bucket 数必须是 u16，不是 u32");
        assert_eq!(read_u16(&res[0].1, 0), Some(240));
        assert_eq!(read_u32(&res[1].1, 0), Some(3000)); // 30s = 3000 centiseconds
        assert_eq!(read_u32(&res[2].1, 0), Some(6000)); // 60s = 6000 centiseconds
    }

    #[test]
    fn test_plain_nexthop_group_has_no_res_group() {
        let members = [(1u32, 1u32)];
        let msg = RouteManager::build_nexthop_group_msg(
            1,
            77,
            &members,
            None,
            None,
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
    fn test_resilient_buckets_balance_odd_and_even_wans() {
        // 240 桶可同时被单数(3/5)与双数(2/4/6/8/10/12)多 WAN 整除，消除余数桶偏斜；且涵盖 64 张网卡上限。
        const { assert!(RES_BUCKETS_MAX % 2 == 0) };
        const { assert!(RES_BUCKETS_MAX % 3 == 0) };
        const { assert!(RES_BUCKETS_MAX % 4 == 0) };
        const { assert!(RES_BUCKETS_MAX % 5 == 0) };
        const { assert!(RES_BUCKETS_MAX % 6 == 0) };
        const { assert!(RES_BUCKETS_MAX % 8 == 0) };
        const { assert!(RES_BUCKETS_MAX >= 64, "必须涵盖 config 的网卡数上限") };
        const { assert!(RES_BUCKETS_MAX < u16::MAX as usize) };
    }

    #[test]
    fn test_resilient_give_up_only_for_real_unsupported_errors() {
        let unsupported = io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        assert!(RouteManager::should_give_up_on_resilient(&unsupported));

        // EINVAL（如 bucket 数不同）可靠拆除重建恢复，不能当永久不支援，否则 auto 一次失败就再也不试。
        let transient = io::Error::from_raw_os_error(libc::EINVAL);
        assert!(!RouteManager::should_give_up_on_resilient(&transient));
    }

    #[test]
    fn test_nexthop_ids_are_stable_per_member() {
        let mut rm = RouteManager::new(0, EcmpMode::Standard).unwrap();
        let a = rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1]));
        let b = rm.alloc_nh_id(AF_INET, 4, Some(&vec![192, 168, 2, 1]));
        assert_ne!(a, b);

        // 同一成员重复配置必须拿到同一个 ID：换 ID 等于换成员，核心会重映射该成员负责的 flow。
        assert_eq!(rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1])), a);

        let v6 = rm.alloc_nh_id(AF_INET6, 3, Some(&vec![0u8; 16]));
        let v4_direct = rm.alloc_nh_id(AF_INET, 3, None);
        assert!(![a, b].contains(&v6));
        assert!(![a, b, v6].contains(&v4_direct));

        assert!(NH_GROUP_ID_V4 > rm.next_nh_id);
        assert!(NH_GROUP_ID_V6 > rm.next_nh_id);
    }

    // 探针路径（独立表 + oif 规则）

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
        // 表号必须 > 255（才验证只用 RTA_TABLE 表达）；优先序须在 1..32766 才会在 main 表之前被求值。
        let tables: Vec<u32> = (0..8).map(|i| PROBE_TABLE_BASE + i).collect();
        assert!(tables.iter().all(|t| *t > 255));
        let priorities: Vec<u32> = (0..8).map(|i| PROBE_RULE_PRIORITY_BASE + i).collect();
        assert!(
            priorities
                .iter()
                .all(|p| *p > 0 && *p < 32_766 && *p != 32_766)
        );
        assert_ne!(PROBE_TABLE_BASE, 254);
    }

    #[test]
    fn test_rule_constants_match_linux_uapi() {
        // 这些值照 linux/rtnetlink.h 与 fib_rules.h 钉死：抄错（如 NEWRULE=21、FRA_OIFNAME=10）会得到无上下文的 ENODEV。
        assert_eq!(RTM_NEWRULE, 32);
        assert_eq!(RTM_DELRULE, 33);
        assert_eq!(FRA_PRIORITY, 6);
        assert_eq!(FRA_TABLE, 15);
        assert_eq!(FRA_OIFNAME, 17);
        assert_eq!(FR_ACT_TO_TBL, 1);
        assert_eq!(RTM_NEWNEXTHOP, 104);
        assert_eq!(RTM_DELNEXTHOP, 105);
        assert_eq!(NHA_RES_GROUP, 12);
        assert_eq!(NHA_RES_GROUP_BUCKETS, 1);
        assert_eq!(NHA_OIF, 5);
        assert_eq!(NHA_GATEWAY, 6);
    }

    #[test]
    fn test_getroute_request_and_reply_parsing() {
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

        let dump = RouteManager::build_getroute_msg(AF_INET, 4, None, None, true);
        let dump_hdr = NlMsgHdr::from_bytes(&dump).unwrap();
        assert_eq!(dump_hdr.nlmsg_flags & NLM_F_DUMP, NLM_F_DUMP);
        assert_eq!(dump[NlMsgHdr::LEN + 1], 0);

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

        let bare = vec![0u8; NlMsgHdr::LEN + RtMsg::LEN];
        let parsed = RouteManager::parse_route_reply(&bare, bare.len()).unwrap();
        assert_eq!(parsed.ifindex, None);
        assert_eq!(parsed.table, 0);
    }

    /// 隧道 underlay /32 的出口选择：只能是非隧道的线且 metric 最小（对应实机 60% 丢包的自环 bug）。
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

        let only_tunnels = vec![wan("wg0", 7, 10, None, vec![Ipv4Addr::new(1, 2, 3, 4)])];
        assert!(RouteManager::plan_underlay_routes(&only_tunnels).is_empty());

        let no_tunnel = vec![wan("eth1", 3, 10, None, Vec::new())];
        assert!(RouteManager::plan_underlay_routes(&no_tunnel).is_empty());

        assert!(RouteManager::plan_underlay_routes(&[]).is_empty());
    }

    /// FIX-1 回归钉：执行期清扫只能扫探针 /32（修复前会误删刚装好的 underlay /32，且永不重装）。
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
        assert!(
            startup.contains(&DNS_ROUTE_METRIC),
            "启动前必须连残留的 DNS /32 一起清（出口可能已经失效）"
        );
        assert!(
            !runtime.contains(&DNS_ROUTE_METRIC),
            "执行期清扫不得误删上游 DNS /32 路由"
        );
    }

    /// FIX-1 回归钉：核心说「这条 /32 不在」时必须重下（自愈），即使快取记著「已装、出口没变」。
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

        let installed: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)> =
            [(addr, (3u32, exit_gw.clone()))].into_iter().collect();

        let present: std::collections::HashSet<Ipv4Addr> = [addr].into_iter().collect();
        assert!(
            RouteManager::plan_underlay_repairs(&wanted, &installed, Some(&present)).is_empty()
        );

        let absent: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
        let repairs = RouteManager::plan_underlay_repairs(&wanted, &installed, Some(&absent));
        assert_eq!(repairs.len(), 1, "核心缺失时必须重下");
        assert_eq!(repairs[0].0, addr);
        assert_eq!(repairs[0].1, 3);
        assert_eq!(repairs[0].2, exit_gw);

        assert!(RouteManager::plan_underlay_repairs(&wanted, &installed, None).is_empty());

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
        // 探针 /32 的 metric 必须非 0、大于 slot 区段、且与预设路由 priority 不同，否则会互相盖掉。
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
        assert_eq!(attrs[2].1, vec![PROBE_RULE_PROTOCOL]);
        // 字串属性必须带结尾 NUL（核心用 strlen 解析）
        assert_eq!(attrs[3].1, b"vxlan\0".to_vec());

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
        assert!(POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX <= PROBE_RULE_PRIORITY_BASE);
        assert!(POLICY_RULE_PRIORITY_BASE > 0);
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
        assert_ne!(path.table, PROBE_TABLE_BASE);
        assert_ne!(path.priority, PROBE_RULE_PRIORITY_BASE);
        assert_eq!(path.table, 10_005);
        assert_eq!(path.priority, 10_005);
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
        assert_eq!(read_u32(&attrs[1].1, 0), Some(0));
        assert_eq!(attrs[2].1, vec![10, 77, 0, 1]);
        assert_eq!(read_u32(&attrs[3].1, 0), Some(12));
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0);
        assert_eq!(
            msg[NlMsgHdr::LEN + 4],
            (table & 0xFF) as u8,
            "rtm_table 应与 RTA_TABLE 的低位元组一致"
        );

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
        // dst 参数是给未来扩充用的（目前探针路径只用表内预设路由）；这里钉住 RTA_DST 与 rtm_dst_len 的编码。
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
