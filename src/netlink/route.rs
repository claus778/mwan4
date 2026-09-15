// 本模組只在 Linux 上真正執行 netlink I/O；
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）會整批變成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use crate::config::EcmpMode;
use crate::netlink::util::{
    NlMsgHdr, read_i32, read_u16, read_u32, rta_align, set_socket_timeouts, write_u16, write_u32,
};
use log::{debug, info, warn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

// Linux Netlink 常數定義
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
/// NLM_F_ROOT | NLM_F_MATCH：請求內核把整張表 dump 出來
pub const NLM_F_DUMP: u16 = 0x300;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_STATIC: u8 = 4;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTN_UNICAST: u8 = 1;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_MULTIPATH: u16 = 9;
/// 目的前綴（RTA_DST）
pub const RTA_DST: u16 = 1;
/// 路由所在表（表號 > 255 時必須用它；與 FRA_TABLE 同值但屬不同列舉）
pub const RTA_TABLE: u16 = 15;
/// 路由改為引用 nexthop object 時使用的屬性（取代 RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH）
pub const RTA_NH_ID: u16 = 30;

// nexthop 專用的 rtattr 型別（enum nha_type）
pub const NHA_ID: u16 = 1;
pub const NHA_GROUP: u16 = 2;
pub const NHA_GROUP_TYPE: u16 = 3;
pub const NHA_OIF: u16 = 5;
pub const NHA_GATEWAY: u16 = 6;
pub const NHA_RES_GROUP: u16 = 12;

/// 巢狀在 `NHA_RES_GROUP` 裡的 bucket 數（`enum { NHA_RES_GROUP_BUCKETS }`，u16）。
///
/// ⚠️ 這是個踩過的坑：uapi 頂層列舉的 13 是 `NHA_RES_BUCKET`（給
/// RTM_{NEW,DEL,GET}NEXTHOPBUCKET 用的 bucket 屬性），**不是** group 的 bucket 數。
/// 舊版把頂層 13 當成 bucket 數塞進 `NHA_RES_GROUP` 巢狀裡，核心解析時找不到
/// `NHA_RES_GROUP_BUCKETS`，就當成「沒給 bucket 數」回 EINVAL —— resilient 模式
/// 因此從來沒成功過（症狀：成員 nexthop 建得出來，group 建不出來，路由不下發）。
pub const NHA_RES_GROUP_BUCKETS: u16 = 1;

/// `SOL_NETLINK` / `NETLINK_EXT_ACK`（linux/netlink.h）。
/// 開了這個選項，核心才會在 netlink 錯誤回應裡附上「為什麼失敗」的字串；
/// 不開的話只會得到一個沒有上下文的 `EINVAL`，巢狀屬性寫錯時完全無從判斷。
/// libc 未必每個版本都導出這兩個常數，所以自備。
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;

/// `NLA_F_NESTED`（linux/netlink.h）：標記這是一個巢狀屬性。
///
/// 這是 resilient nexthop group 建不起來的**真正原因**（比 bucket 數常量更早踩到）：
/// `NHA_RES_GROUP` 是巢狀屬性，核心 5.2+ 會要求它帶 `NLA_F_NESTED`；少了這個位元，
/// 核心不把它當巢狀屬性解析，也就看不到裡面的 `NHA_RES_GROUP_BUCKETS`，
/// 直接回 `EINVAL`。實測對照：iproute2 送的是 `0x800c`，我們舊版送 `0x000c`。
/// 注意核心用 `nla_type()` 遮蔽高位後仍是 12，所以這個位元只影響「是否按巢狀解析」。
const NLA_F_NESTED: u16 = 0x8000;

/// enum nexthop_grp_type：resilient group（只有故障鏈路的 bucket 會被重映射）
pub const NEXTHOP_GRP_TYPE_RES: u16 = 1;

/// 本程式保留的群組 ID，避開一般 nexthop id 的配置空間
pub const NH_GROUP_ID_V4: u32 = 0xFFFF_FF00;
pub const NH_GROUP_ID_V6: u32 = 0xFFFF_FF01;

/// resilient group 的 bucket 數：必須是 2 的冪，且不小於成員數。
/// 上限用來界定單一 netlink 訊息大小與核心記憶體用量；
/// 成員數超過上限時不支援 resilient（由呼叫端退回標準 ECMP）。
const RES_BUCKETS_MIN: usize = 8;
const RES_BUCKETS_MAX: usize = 256;

/// rtnexthop 的 weight 欄位（rtnh_hops）是 u8，核心語意為 weight - 1
pub const MAX_NEXTHOP_WEIGHT: u32 = 256;

// ---------------------------------------------------------------------------
// 探針專用路由表 / 規則（RTM_NEWRULE）
//
// 為什麼需要：SO_BINDTODEVICE 只是把路由查找的 oif 固定到該設備，**不代表找得到路**。
// 主表若沒有「經該設備」的路由，內核會「假定目的地在鏈路上」把 SYN 直接丟進黑洞
// （實測：connect() 回 EINPROGRESS 後永遠超時，不是 ENETUNREACH），
// 於是「預設路由被刪掉／被切到別條線」就等於「該線永遠回不去」——自鎖。
//
// 解法：為每張 WAN 建一張獨立表（表內 `default via <gw> dev <wan>`）＋一條
// `oif <wan> lookup <table>` 規則。規則只匹配「綁定該設備的本地封包」，所以：
//   * 探針一定有路，與主表那條預設路由完全無關；
//   * 轉發流量（oif = br-lan）與路由器其它本地流量（oif 未綁定）走主表，不受影響。
//
// 表號與規則優先序都取 10000 起算的獨立區段，優先序仍小於 main(32766)，
// 因此會在主表之前被求值。
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
/// 規則的來源標記（u8）。我們用它把「自己的規則」與別人的規則區分開，
/// 清掃時只刪帶這個標記的，不會動到第三方（例如 mwan3 / VPN 的規則）。
pub const FRA_PROTOCOL: u16 = 21;

/// 本程式下發的規則所使用的 FRA_PROTOCOL 標記值（'M' = mwan4）
pub const PROBE_RULE_PROTOCOL: u8 = 0x4D;

/// enum fib_rule_action：把匹配的封包送到指定表
pub const FR_ACT_TO_TBL: u8 = 1;

/// 探針「出向」表號的起點（第 i 張 WAN 用 PROBE_TABLE_BASE + i）
pub const PROBE_TABLE_BASE: u32 = 10_000;
/// 探針出向規則的優先序起點（必須小於 main 表的 32766）
pub const PROBE_RULE_PRIORITY_BASE: u32 = 10_000;
/// 可用的 slot 數上限（= 可設定的 WAN 介面數上限）。
/// 啟動時會清掃整個保留區段，避免上一次執行留下的規則指向舊閘道。
/// 刻意壓在 64：真實路由器不會有這麼多 WAN，而每次啟動的清掃往返次數正比於它。
pub const PROBE_SLOT_MAX: u32 = 64;
/// 探針目標在主表的 /32 路由使用的 metric。
/// 與預設路由的 priority（通常 0）分開，便於辨識與精準刪除。
pub const PROBE_MAIN_ROUTE_METRIC: u32 = 42_760;

/// 隧道 underlay 對端的 /32 路由在主表使用的 metric。
///
/// 與探針的 42760 分開，兩者才能各自精準清掃（互不誤刪）。
/// 真正讓它優先於預設路由的是「前綴更長」，metric 只作為辨識標記。
pub const UNDERLAY_ROUTE_METRIC: u32 = 42_761;

// 這些不變式是「規則一定會在 main 表之前被求值」與「/32 一定贏過預設路由」的前提，
// 直接在編譯期釘死；改壞了會無法編譯而不是上機才發現。
const _: () = {
    assert!(PROBE_TABLE_BASE > 255);
    assert!(PROBE_RULE_PRIORITY_BASE > 0);
    assert!(PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX < 32_766);
    assert!(PROBE_MAIN_ROUTE_METRIC != 0);
    // 探針 /32 的 metric 不能落在表號／規則優先序的保留區段裡，否則清掃會誤刪
    assert!(PROBE_MAIN_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(PROBE_MAIN_ROUTE_METRIC < 0xFFFF_FF00);
    // underlay /32 用另一個 metric：與探針分開才能各自精準清掃
    assert!(UNDERLAY_ROUTE_METRIC != PROBE_MAIN_ROUTE_METRIC);
    assert!(UNDERLAY_ROUTE_METRIC > PROBE_RULE_PRIORITY_BASE + PROBE_SLOT_MAX);
    assert!(UNDERLAY_ROUTE_METRIC < 0xFFFF_FF00);
};

/// 等待核心 ACK 的最大輪詢次數（配合 socket 上的 SO_RCVTIMEO 使用）
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
const EINVAL: i32 = libc::EINVAL;
#[cfg(not(target_os = "linux"))]
const EINVAL: i32 = 22;

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
    pub rtnh_hops: u8, // 權重 weight - 1
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

/// struct nhmsg（8 bytes）—— RTM_NEWNEXTHOP / RTM_DELNEXTHOP 的固定標頭
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

/// struct fib_rule_hdr（12 bytes）—— RTM_NEWRULE / RTM_DELRULE 的固定標頭
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
        // b[5] / b[6] 是保留欄位
        b[7] = self.action;
        write_u32(&mut b, 8, self.flags);
        b
    }
}

/// struct nexthop_grp（8 bytes）—— NHA_GROUP 的每個成員。
/// `weight` 與 rtnh_hops 一樣是「權重 - 1」。
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

/// 活躍 WAN 路由節點（IPv4）
#[derive(Debug, Clone)]
pub struct ActiveWanRoute {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
    pub weight: u32,
    /// 這條線的 metric：用來挑「underlay 出口」（非隧道線中 metric 最小者）
    pub metric: u32,
    /// 這條線若是隧道，列出其 underlay 對端位址；非隧道線留空。
    /// 兩層用途：① 非空 = 這條是隧道（不能當別人的 underlay 出口）；
    /// ② 這些位址要補 /32 走真正的 underlay 出口，否則會自環。
    pub underlay_targets: Vec<Ipv4Addr>,
}

/// 活躍 WAN 路由節點（IPv6）
#[derive(Debug, Clone)]
pub struct ActiveWanRouteV6 {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv6Addr>,
    pub weight: u32,
}

/// 一條「探針路徑」：讓綁定某張 WAN 的探針**一定有路可走**，而且盡量不影響轉發。
///
/// 兩層保障（兩者都是實測出來的，缺一不可）：
///
/// 1. **出向**：獨立表（`default via gateway dev ifname`）＋ `oif ifname lookup table`
///    規則。`SO_BINDTODEVICE` 只固定查找的 oif，本身不會造出路由；沒有這一步，
///    「主表那條預設路由被刪掉或切到別條線」就等於「這條線永遠回不去」。
///
/// 2. **回程**：需要時在主表補一條探針目標的 `/32`（走該 WAN）。
///    為什麼是主表而不是另一張表：內核的反向路徑檢查（`rp_filter`）**只查主表**，
///    完全看不到 FIB 規則。實測：主表沒有涵蓋探針目標的路由時，即使出向那條路
///    完全正常、封包也確實送達對端，回來的 SYN-ACK 仍會被當成 martian 丟掉，
///    症狀是探針「一直超時」。把 /32 放進主表即可修好（strict / loose 皆然）。
///
///    `main_route_targets` 由呼叫端決定「哪些目標」需要：只有
///    ① 主表沒有**別人的**預設路由（此時不補就收不到回程），或
///    ② rp_filter 為 strict（1）且該目標沒有被別的 WAN 共用 時才放進來；
///    其餘情況不補，避免影響 LAN 轉發路徑。同一個共用目標只會有一個擁有者。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePath {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
    /// 這張 WAN 的探針目標（需要時會以 /32 放進主表）
    pub targets: Vec<Ipv4Addr>,
    /// 該 WAN 專用的出向表號（呼叫端以 PROBE_TABLE_BASE + slot 產生）
    pub table: u32,
    /// 該 WAN 專用出向規則的優先序（呼叫端以 PROBE_RULE_PRIORITY_BASE + slot 產生）
    pub priority: u32,
    /// **需要**在主表補 /32 的目標子集（見上方說明）。
    ///
    /// 用「子集」而不是單一 bool：同一個目標可能被多條線共用，而主表同一個前綴只能有
    /// 一條路由——只有「該目標的擁有者」（呼叫端按 metric 選出）才把它放進來。
    pub main_route_targets: Vec<Ipv4Addr>,
}

/// 一條 fib_rule 的描述（出向用 oif、入向用 iif）
#[derive(Debug, Clone, Copy)]
struct RuleSpec<'a> {
    family: u8,
    table: u32,
    ifname: &'a str,
    priority: u32,
    /// true = `oif`（本機產生）、false = `iif`（進來）
    output: bool,
}

/// 路由查詢（RTM_GETROUTE）的結果摘要
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLookup {
    /// 解析出來的出口設備（RTA_OIF）
    pub ifindex: Option<u32>,
    pub gateway: Option<Ipv4Addr>,
    /// 命中的表（RTA_TABLE，沒有就是 rtmsg.rtm_table）
    pub table: u32,
}

/// 已正規化、與位址族無關的 nexthop 描述
struct RouteNexthop {
    ifindex: u32,
    /// 網關的原始位元組（IPv4 = 4 bytes，IPv6 = 16 bytes）；None 代表直連
    gateway: Option<Vec<u8>>,
    weight: u32,
}

/// 目前下發到核心的預設路由類型。
///
/// 兩種路由的 netlink key 不同（有無 RTA_NH_ID），必要時得把另一種先刪掉，
/// 否則同一條 default route 會殘留兩份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstalledVariant {
    None,
    /// RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH
    Standard,
    /// RTA_NH_ID 指向 resilient nexthop group
    Resilient,
}

/// 一條路由訊息的落點：`table = None` 代表主表（RT_TABLE_MAIN），
/// `dst = Some((位址位元組, 前綴長度))` 代表非預設路由。
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
    /// 下發預設路由時使用的 metric（RTA_PRIORITY）
    priority: u32,
    /// ECMP 行為：標準 multipath / 自動 / 強制 resilient nexthop group
    ecmp_mode: EcmpMode,
    /// None = 尚未探測；Some(true/false) = 核心是否支援 resilient nexthop group
    resilient_supported: Option<bool>,
    /// (family, ifindex, gateway bytes) -> nexthop object id。
    /// ID 必須跨次呼叫保持穩定，核心才只會重映射故障鏈路的 bucket。
    nh_ids: std::collections::HashMap<(u8, u32, Vec<u8>), u32>,
    next_nh_id: u32,
    installed_v4: InstalledVariant,
    installed_v6: InstalledVariant,
    /// 已下發的探針路徑，key = 網卡名（用於差異比對與清理）
    probe_paths: std::collections::HashMap<String, ProbePath>,
    /// 已下發的隧道 underlay /32 路由：對端位址 -> (ifindex, gateway bytes)。
    /// 用來差異比對，避免每輪重下（見 `sync_underlay_routes`）。
    underlay_routes: std::collections::HashMap<Ipv4Addr, (u32, Option<Vec<u8>>)>,
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
            sa.nl_pid = 0; // 由內核自動分配
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

            // 要求核心在錯誤回應裡附上原因（extack）。
            // 舊版沒開這個選項，resilient group 建失敗時只看到 EINVAL，
            // 完全不知道是 bucket 數、group type 還是別的屬性的問題。
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
                // 不影響功能，只是少一條排障線索
                debug!(
                    "[RouteManager] NETLINK_EXT_ACK unavailable: {}",
                    io::Error::last_os_error()
                );
            }

            // 避免核心異常時 recv 永久阻塞住整個 daemon
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
            })
        }
    }

    /// 取得（必要時配置）某個 nexthop 的穩定 ID
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

    /// 某個位址族目前配置出去的成員 ID（family, ifindex, gateway bytes）
    fn member_keys_for_family(&self, family: u8) -> Vec<(u8, u32, Vec<u8>)> {
        self.nh_ids
            .keys()
            .filter(|k| k.0 == family)
            .cloned()
            .collect()
    }

    /// 發送 Netlink 請求並等待內核 ACK 回應（會校驗 nlmsg_seq 是否匹配）
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
                // SO_RCVTIMEO 到期會回傳 EAGAIN / EWOULDBLOCK
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

            // 忽略滯留的舊回應，只處理與本次請求 seq 相同的 ACK
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
                    // 內核會把「為什麼失敗」放在 extack（NLMSGERR_ATTR_MSG）裡，例如
                    // "Invalid scope" / "Can not change number of buckets" / "Nexthop has
                    // invalid gateway"。舊版直接丟掉，只剩一個沒有上下文的 EINVAL——這裡記下來。
                    // 用 warn 而不是 debug：這是排障時唯一能說明「哪個屬性寫錯」的線索，
                    // 放在 debug 會在正式環境（預設 info）裡被完全吃掉。
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

    /// 組出 RTM_NEWROUTE / RTM_DELROUTE 訊息。
    /// IPv4 與 IPv6 只差在 family 與網關位元組長度，其餘結構完全一致，
    /// 因此在這裡統一處理，避免兩份邏輯走樣。
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

    /// `build_route_msg` 的完整版：`RouteTarget` 把「表號 + 目的前綴」收斂成一個參數。
    fn build_route_msg_ex(
        priority: u32,
        family: u8,
        target: RouteTarget<'_>,
        hops: &[RouteNexthop],
        msg_type: u16,
        flags: u16,
        seq: u32,
    ) -> Vec<u8> {
        let RouteTarget { table, dst } = target;
        let mut buffer: Vec<u8> = Vec::with_capacity(512);
        // 預留 nlmsghdr 空間
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        // 若唯一存活路由沒有網關（點對點 / PPPoE），其 scope 應為 RT_SCOPE_LINK
        let rtm_scope = if hops.len() == 1 && hops[0].gateway.is_none() {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };

        let dst_len = dst.map_or(0, |(_, len)| len);
        // 刪除訊息一律不指定 protocol（RTPROT_UNSPEC）：內核在 RTM_DELROUTE 時**會比對
        // protocol**。若我們送 RTPROT_STATIC 而該路由其實來自別的來源（iproute2 的預設是
        // `proto boot`），就會回 ESRCH 而路由仍在——殘留永遠清不掉（實測）。
        // 不指定時，key 只由 (表, 目的前綴, metric, type, tos) 決定。
        let rtm_protocol = if msg_type == RTM_DELROUTE {
            0
        } else {
            RTPROT_STATIC
        };
        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            // 表號 > 255 時只能靠 RTA_TABLE 表達；這裡兩個欄位都填一致的值，
            // 核心以 RTA_TABLE 為準（rtm_table 的低位元組在 >255 時會被截斷）
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
        // 目的前綴必須在 OIF / GATEWAY 之前比較好讀，順序核心不敏感
        if let Some((addr, _)) = dst {
            Self::append_attr(&mut buffer, RTA_DST, addr);
        }

        // 顯式帶上 metric，確保 NLM_F_REPLACE / RTM_DELROUTE 能命中同一個路由 key
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
                // weight 必須落在 1..=256，否則 rtnh_hops 會靜默截斷
                let weight = hop.weight.clamp(1, MAX_NEXTHOP_WEIGHT);
                let rtnh = RtNextHop {
                    rtnh_len: 0, // 待計算
                    rtnh_flags: 0,
                    rtnh_hops: (weight - 1) as u8,
                    rtnh_ifindex: hop.ifindex as i32,
                };
                mp_buffer.extend_from_slice(&rtnh.to_bytes());

                if let Some(gw) = &hop.gateway {
                    Self::append_attr(&mut mp_buffer, RTA_GATEWAY, gw);
                }

                // 回填此 nexthop 的長度（核心要求 rtnh_len 為未對齊的實際長度）
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
    // 為什麼要用它：標準 RTA_MULTIPATH 路由在 nexthop 集合改變時（包含線路恢復
    // UP 加入新成員），核心會對「整條路由」重算 multipath hash，既有 flow 可能被
    // 改送到另一條 WAN、源 IP 一變 TCP 連線就死。resilient group 只會重新分配
    // 「故障成員」佔用的 bucket，其餘 flow 完全不受影響，真正做到連接粘滯。
    // -----------------------------------------------------------------------

    /// 組出單一 nexthop object 訊息（NHA_ID + NHA_OIF [+ NHA_GATEWAY]）
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

    /// 組出 nexthop group 訊息。
    ///
    /// `buckets = Some(n)` 時附上 NHA_RES_GROUP / NHA_RES_GROUP_BUCKETS 與
    /// NHA_GROUP_TYPE = RES，形成 resilient group；`None` 則是一般 multipath group。
    ///
    /// bucket 數是 u16，且必須是 2 的冪、不小於成員數（核心會拒絕其它值）。
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
        // group 本身跨越位址族，nh_family 固定為 AF_UNSPEC
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
            // NHA_RES_GROUP 是巢狀屬性，內含 NHA_RES_GROUP_BUCKETS（u16，見該常數的註解）
            let mut res: Vec<u8> = Vec::with_capacity(16);
            Self::append_attr(&mut res, NHA_RES_GROUP_BUCKETS, &bucket_count.to_ne_bytes());
            // 必須帶 NLA_F_NESTED，否則核心不按巢狀屬性解析（見該常數的註解）
            Self::append_attr(&mut buffer, NHA_RES_GROUP | NLA_F_NESTED, &res);
        }

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 組出刪除單一 nexthop object 的訊息（只需要 NHA_ID）
    ///
    /// `family` 必須與「建立時」一致：成員是用 `AF_INET`/`AF_INET6` 建的，
    /// group 才是 `AF_UNSPEC`。內核查找待刪物件時會比對 family，
    /// 寫死 `AF_UNSPEC` 會讓成員永遠刪不掉（回 `EINVAL`），
    /// 於是每輪重試都留下一個孤兒 nexthop object —— 實測堆到 69 個。
    fn build_nexthop_del_msg(seq: u32, family: u8, id: u32) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        buffer.extend_from_slice(&Self::nhmsg_bytes(family).to_bytes());
        Self::append_attr(&mut buffer, NHA_ID, &id.to_ne_bytes());
        Self::finish_msg(&mut buffer, RTM_DELNEXTHOP, NLM_F_REQUEST | NLM_F_ACK, seq);
        buffer
    }

    /// 組出「引用 nexthop object」的預設路由訊息（RTA_PRIORITY + RTA_NH_ID）
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
            // 刪除時不指定 protocol，理由同 build_route_msg_ex
            rtm_protocol: if msg_type == RTM_DELROUTE {
                0
            } else {
                RTPROT_STATIC
            },
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        buffer.extend_from_slice(&rtmsg.to_bytes());

        // 刪除時 nh_id 也是路由 key 的一部分，兩種訊息務必帶一致
        Self::append_attr(&mut buffer, RTA_PRIORITY, &priority.to_ne_bytes());
        Self::append_attr(&mut buffer, RTA_NH_ID, &nh_id.to_ne_bytes());

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    // -----------------------------------------------------------------------
    // 探針路徑：`oif <wan> lookup <table>` 規則
    // -----------------------------------------------------------------------

    /// 組出 RTM_NEWRULE / RTM_DELRULE 訊息。
    ///
    /// 規則內容：family=AF_INET、`oif|iif <ifname>`、`lookup <table>`、指定 priority。
    /// 用 oif／iif 而不是 fwmark：探針 socket 正是 `SO_BINDTODEVICE` 綁定該裝置，
    /// 而轉發流量（oif = br-lan）自然不會命中。
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
            // 表號一律用 FRA_TABLE 表達，這裡留 0（RT_TABLE_UNSPEC）
            table: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        buffer.extend_from_slice(&hdr.to_bytes());

        Self::append_attr(&mut buffer, FRA_TABLE, &table.to_ne_bytes());
        Self::append_attr(&mut buffer, FRA_PRIORITY, &priority.to_ne_bytes());
        // 打上我們的來源標記：清掃時只刪帶這個標記的規則，不會誤刪第三方的規則
        Self::append_attr(&mut buffer, FRA_PROTOCOL, &[PROBE_RULE_PROTOCOL]);
        // 字串屬性必須含結尾 NUL（長度 = 4 + name.len() + 1）
        let mut name = Vec::with_capacity(ifname.len() + 1);
        name.extend_from_slice(ifname.as_bytes());
        name.push(0);
        let name_attr = if output { FRA_OIFNAME } else { FRA_IIFNAME };
        Self::append_attr(&mut buffer, name_attr, &name);

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 把「期望的探針路徑集合」與目前已下發的做差異比對：刪掉多的，並**重下所有期望的**。
    ///
    /// 這是**冪等**操作（規則與表內路由都用 CREATE|REPLACE），可以每個心跳週期重複呼叫；
    /// 「全部重下」而不只補缺的，是因為規則／表內路由也可能被外部（其它程序、內核事件、
    /// 手工 `ip rule del`）改掉，只比對自己的記錄就永遠修不回來。
    /// 任何一步失敗都只記錄第一條錯誤，好讓下個週期重試。
    pub fn set_probe_paths(&mut self, wanted: &[ProbePath]) -> io::Result<()> {
        let mut first_err: Option<io::Error> = None;
        let wanted_names: std::collections::HashSet<&str> =
            wanted.iter().map(|p| p.ifname.as_str()).collect();

        // 1) 先刪掉不再需要的（先刪規則再刪表內路由）
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

        // 2) 重下所有期望的（含已經下發過的；內容有變也一併覆蓋）
        for path in wanted {
            // 內容有變（含主表 /32 子集變動）時，必須先把舊的
            // 完整拆掉再裝，否則主表那條 /32 會留在不該留的時候。
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
    // 路由查詢 / 轉儲：用來「問內核」而不是靠猜
    //
    // 為什麼需要：
    //   * 探針路徑要不要補主表 /32，取決於「主表到底有沒有涵蓋這個目標」；
    //   * 探針以「超時」失敗時，要能分辨「線路真的不通」與「本機根本沒路」
    //     （後者內核會按 on-link 把封包丟進黑洞，表現就是超時）。
    // -----------------------------------------------------------------------

    /// 組出 RTM_GETROUTE 請求（`oif` 有值時一併帶上 RTA_OIF，模擬綁定該設備的查找）
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

    /// 解析一則 RTM_NEWROUTE 訊息 → RouteLookup
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

    /// 詢問內核：到 `dst` 的路由是什麼？`oif` 有值時模擬「綁定該設備」的查找。
    ///
    /// 回傳 `Ok(None)` 代表內核說「沒有可用的路」（ENETUNREACH 等）——這正是
    /// 「探針會一直超時」的本機訊號，呼叫端可據此設定 local_condition。
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
                // 沒有可用的路（ENETUNREACH / ENETDOWN…）→ 不是錯誤，是「沒有路由」
                return Ok(None);
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

    /// 轉儲主表中 metric == `metric` 的所有路由（用於清掃自己留下的探針 /32）。
    ///
    /// 回傳 `(表號, 目的位址, 前綴長度)`；只認 32 位元前綴（我們只下發 /32）。
    #[cfg(target_os = "linux")]
    pub fn dump_host_routes_with_metric(
        &mut self,
        metric: u32,
    ) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        self.seq += 1;
        let seq = self.seq;
        let msg = Self::build_getroute_msg(AF_INET, seq, None, None, true);
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

        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        'outer: loop {
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
                    break 'outer;
                }
                if hdr.nlmsg_type == RTM_NEWROUTE && hdr.nlmsg_seq == seq {
                    let body = &buf[offset..offset + msg_len];
                    let dst_len = body[NlMsgHdr::LEN + 1];
                    let mut priority = None;
                    let mut dst = None;
                    let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
                    let mut off = NlMsgHdr::LEN + RtMsg::LEN;
                    while off + RtAttr::LEN <= msg_len {
                        let rta_len = read_u16(body, off).unwrap_or(0) as usize;
                        let rta_type = read_u16(body, off + 2).unwrap_or(0);
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
                offset += crate::netlink::util::nlmsg_align(msg_len);
            }
        }
        Ok(out)
    }

    /// 主表有沒有**任何**預設路由（含我們自己下發的那條）。
    ///
    /// 這是「非活躍線需不需要補 /32」的正確判據：
    /// - loose/off：只要主表有預設路由，任何設備的回程都能通過反向檢查 → 不需要補；
    /// - 完全沒有預設路由（全斷、或唯一存活線故障）→ 才需要補，否則那條線永遠收不到回程。
    ///
    /// 注意**不能**用「有沒有到目標的路」來判斷：我們自己下發的探針 /32 也是「到目標的路」，
    /// 會形成自我參照（補了 → 認為已涵蓋 → 刪掉 → 又沒涵蓋 → 再補）而造成振盪。
    /// 預設路由（dst_len = 0）永遠不會是我們的 /32，因此沒有這個問題。
    #[cfg(target_os = "linux")]
    pub fn has_main_default_route(&mut self, family: u8) -> io::Result<bool> {
        Ok(!self.dump_default_routes(family)?.is_empty())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn has_main_default_route(&mut self, _family: u8) -> io::Result<bool> {
        Ok(false)
    }

    /// 轉儲主表中「不是我們的」預設路由（用於判斷全斷時有沒有兜底可接手）。
    ///
    /// 回傳 `(表號, metric)`；已排除 `skip_metric`（我們自己那條）。
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

    /// 轉儲主表裡的所有預設路由 → `(表號, metric)`
    #[cfg(target_os = "linux")]
    fn dump_default_routes(&mut self, family: u8) -> io::Result<Vec<(u32, u32)>> {
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

        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        'outer: loop {
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
                    break 'outer;
                }
                if hdr.nlmsg_type == RTM_NEWROUTE && hdr.nlmsg_seq == seq {
                    let body = &buf[offset..offset + msg_len];
                    let dst_len = body[NlMsgHdr::LEN + 1];
                    let mut priority = None;
                    let mut table = u32::from(body[NlMsgHdr::LEN + 4]);
                    let mut off = NlMsgHdr::LEN + RtMsg::LEN;
                    while off + RtAttr::LEN <= msg_len {
                        let rta_len = read_u16(body, off).unwrap_or(0) as usize;
                        let rta_type = read_u16(body, off + 2).unwrap_or(0);
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
                    // 只認主表：(1) 我們的探針表裡也有 default，若不按表號過濾會被誤判成
                    // 「主表有預設路由」（實測踩過），(2) F13 的兜底判斷也靠這個。
                    if dst_len == 0 && table == u32::from(RT_TABLE_MAIN) {
                        out.push((table, prio));
                    }
                }
                offset += crate::netlink::util::nlmsg_align(msg_len);
            }
        }
        debug!("[RouteManager] main-table default routes: {out:?}");
        Ok(out)
    }

    /// 非 Linux 平台（只在 Windows 上 `cargo check` 用）沒有 netlink，查詢一律回「查不到」
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

    /// 清掉主表裡所有屬於本程式的 /32（metric 為 `PROBE_MAIN_ROUTE_METRIC` 或
    /// `UNDERLAY_ROUTE_METRIC`），不論目標是否還在設定裡。
    ///
    /// 這是啟動時的正確做法：只依「metric 是我們專用的」來判斷歸屬，因此上一次執行
    /// 留下的、已從設定移除的目標，或當時設備還不存在的目標，都能一併清乾淨。
    /// 刪除訊息**不帶 nexthop**（只按 table + dst + metric 命中）——帶了 OIF/GATEWAY
    /// 時，若那條路由的閘道或 ifindex 後來變過，內核會回 ESRCH 而實際上沒刪掉。
    pub fn sweep_own_probe_host_routes(&mut self) -> io::Result<usize> {
        let probe = self.sweep_host_routes_with_metric(PROBE_MAIN_ROUTE_METRIC, "probe")?;
        let underlay = self.sweep_host_routes_with_metric(UNDERLAY_ROUTE_METRIC, "underlay")?;
        Ok(probe + underlay)
    }

    /// 依 metric 把主表裡屬於我們的 /32 清乾淨（探針與 underlay 共用這段邏輯）
    fn sweep_host_routes_with_metric(&mut self, metric: u32, kind: &str) -> io::Result<usize> {
        let victims = self.dump_host_routes_with_metric(metric)?;
        let mut removed = 0;
        for (table, dst, dst_len) in victims {
            // 主表用 rtm_table（254）表達、不帶 RTA_TABLE——與我們下發時的形式一致。
            // 實測：對主表的路由帶 RTA_TABLE 去刪，內核會回 ESRCH 而路由仍在。
            let target_table = if table == u32::from(RT_TABLE_MAIN) {
                None
            } else {
                Some(table)
            };
            debug!(
                "[RouteManager] Removing stale {kind} host route {dst}/{dst_len} in table {table} (metric {metric})"
            );
            self.seq += 1;
            let seq = self.seq;
            let octets = dst.octets();
            let msg = Self::build_route_msg_ex(
                metric,
                AF_INET,
                RouteTarget {
                    table: target_table,
                    dst: Some((&octets, dst_len)),
                },
                &[],
                RTM_DELROUTE,
                NLM_F_REQUEST | NLM_F_ACK,
                seq,
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

    /// 清掃本程式保留區段內殘留的探針規則。
    ///
    /// 為什麼需要：表號／規則優先序是按介面在設定檔中的順序配置的。若上一次執行
    /// 的順序與這次不同，就會留下「oif <wan> lookup <舊表>」的規則，而那個舊表裡
    /// 是一條指向舊閘道的預設路由——探針會被導去錯的閘道。啟動時先掃乾淨最省事。
    ///
    /// **只刪帶 `PROBE_RULE_PROTOCOL` 標記的規則**：不會動到第三方（mwan3 / VPN 等）
    /// 即使它們剛好也用 10000..10063 這個優先序區段。表內殘留的路由則不再主動掃
    /// （沒有規則指向它就是惰性的，而我們重用該表時會直接 REPLACE）。
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
        // 清掃只是為了收拾殘局，失敗不應阻止啟動
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 只靠「優先序 + 我們的來源標記」刪除一條自己的規則（不需要知道它的 oif／表號）。
    /// 回傳是否真的刪掉了一條。
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

    /// 刪掉「這次設定會用到」的所有探針目標在主表的 /32（不論是否需要）。
    ///
    /// 保留此函式是為了向後相容；新流程請用 `sweep_own_probe_host_routes`（按 metric
    /// 轉儲掃描，能清掉已從設定移除或當時設備不存在的殘留）。
    ///
    /// **刪除訊息刻意不帶 nexthop**：只按 (table, dst, metric) 命中。帶了 RTA_OIF /
    /// RTA_GATEWAY 時，若那條路由的閘道或 ifindex 後來變過（DHCP 續約、PPPoE 重撥、
    /// 設備重建），內核會回 ESRCH 而路由其實還在——殘留就永遠清不掉。
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

    /// 下發單一探針路徑：出向規則 → 出向表內預設路由 →（必要時）主表探針目標 /32
    fn install_probe_path(&mut self, path: &ProbePath) -> io::Result<()> {
        // 1) 出向規則（oif）
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

        // 2) 出向表內的預設路由（探針要走的路）
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

        // 3) 需要時在主表補探針目標的 /32（讓 rp_filter 的反向路徑查詢找得到路）
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

    /// 拆除單一探針路徑（順序與安裝相反）
    fn remove_probe_path(&mut self, path: &ProbePath) -> io::Result<()> {
        // 1) 主表的探針目標 /32
        //    刪除訊息**不帶 nexthop**：只按 (table, dst, metric) 命中。帶了 OIF/GATEWAY
        //    時若該路由的閘道或 ifindex 後來變過，內核會回 ESRCH 而路由仍在。
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

        // 2) 出向表內預設路由
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

        // 3) 出向規則
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

    /// 送出規則訊息；「本來就不存在」（刪除時的 ESRCH/ENOENT）與「已經存在」（EEXIST）
    /// 都算成功，這樣整個安裝／清除流程就是冪等的。
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

    /// 送出探針路徑的路由訊息。與 `commit_msg` 的差別只在於成功時記 debug：
    /// 探針路徑每 30 秒就會重下一次，用 info 會把日誌洗掉。
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

    /// 把 nlmsghdr 回填到緩衝區開頭
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

    /// resilient group 的 bucket 數：2 的冪、不小於成員數（核心要求 u16）
    fn res_bucket_count(members: usize) -> u16 {
        let mut b = RES_BUCKETS_MIN;
        while b < members.max(1) && b < RES_BUCKETS_MAX {
            b *= 2;
        }
        // RES_BUCKETS_MAX 遠小於 u16::MAX，這裡不可能截斷
        b as u16
    }

    /// 從 NLMSG_ERROR 回應裡取出內核的 extack 說明字串（NLMSGERR_ATTR_MSG = 1）。
    ///
    /// 格式：`nlmsghdr` + `i32 error` + 原始請求的 `nlmsghdr` + 屬性串流。
    fn parse_extack(buf: &[u8], len: usize) -> Option<String> {
        let mut off = NlMsgHdr::LEN + 4;
        // 被回傳的原始請求標頭（通常也是 16 bytes）
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

    /// 這則訊息是不是「刪除」？（nlmsg_type 就在標頭裡，直接讀出來判斷，
    /// 這樣所有刪除路徑都能共用同一套「本來就不存在」的容錯）
    fn message_is_delete(buf: &[u8]) -> bool {
        matches!(
            read_u16(buf, 4),
            Some(RTM_DELROUTE) | Some(RTM_DELRULE) | Some(RTM_DELNEXTHOP)
        )
    }

    /// 內核在刪除一個「本來就不存在」的物件時，不同物件回不同 errno：
    /// 路由 → ESRCH、規則 → **ENOENT**、整張表不存在 → ENOENT/EINVAL（實測）。
    /// 全部當成「沒有東西可刪」，否則每次啟動都會出現假警告，
    /// 而且 `set_probe_paths` 會把「規則已不存在」誤判成失敗而跳過重裝。
    fn is_absent_object(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(ESRCH) | Some(ENOENT) | Some(EINVAL)
        )
    }

    /// 送出 netlink 訊息並等待 ACK；「本來就不存在」（刪除時）與「已經存在」
    /// （規則建立時）都算成功，讓整個流程冪等。
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
                // 舊版在這裡靜默回傳 Err，導致「成員 nexthop 建成功、group 建失敗」時
                // 日誌裡完全看不到是哪一步出問題，只剩上層一個沒有上下文的 EINVAL。
                warn!("[RouteManager] {label} failed: {e}");
                Err(e)
            }
        }
    }

    /// 刪除核心 FIB 中的 IPv4 預設路由。
    /// 用於「全部 WAN 斷線」與「守護進程優雅退出」兩種情境，
    /// 避免殘留指向已失效鏈路的預設路由。
    pub fn delete_default_route(&mut self) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg(
            self.priority,
            AF_INET,
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        info!(
            "[RouteManager] Removing IPv4 default route from FIB (metric {})",
            self.priority
        );
        let res = self.commit_msg(&buffer, "IPv4 default route removal");
        self.installed_v4 = InstalledVariant::None;
        res
    }

    /// 刪除核心 FIB 中的 IPv6 預設路由（::/0）
    pub fn delete_ipv6_default_route(&mut self) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_route_msg(
            self.priority,
            AF_INET6,
            &[],
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        info!(
            "[RouteManager] Removing IPv6 default route from FIB (metric {})",
            self.priority
        );
        let res = self.commit_msg(&buffer, "IPv6 default route removal");
        self.installed_v6 = InstalledVariant::None;
        res
    }

    // -----------------------------------------------------------------------
    // 模式分派：標準 multipath vs. resilient nexthop group
    // -----------------------------------------------------------------------

    /// 計算隧道 underlay /32 路由的期望集合：`(對端, 出口 ifindex, 出口 gateway)`。
    ///
    /// 出口 = 非隧道的活躍 WAN 中 metric 最小者；同 metric 取先出現的（設定檔順序）。
    /// 刻意只挑「非隧道」的線：拿隧道去當另一條隧道的 underlay 會形成遞迴依賴。
    /// 若一條非隧道的線都沒有（例如全部都是隧道），回傳空集合 ——
    /// 此時不下發任何 /32，讓預設路由自行決定，至少不比修復前更糟。
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

    /// 同步「隧道 underlay 對端」的 /32 路由（見 `UNDERLAY_ROUTE_METRIC`）。
    ///
    /// 為什麼需要：隧道（VXLAN/WireGuard）的封裝封包目的地是 underlay 對端，
    /// 而它得靠 main 表的預設路由送出。一旦預設路由是「含該隧道的 ECMP」，
    /// 就有約 1/N 的機率把封裝封包再塞回同一條隧道 —— 自環。
    /// 症狀是隧道大量丟包甚至完全不可用，而 `ip route get <對端>` 還會騙人：
    /// 它只反映固定哈希的單次採樣，通常顯示的是正確的那條。
    ///
    /// 解法：為每個對端補一條 /32（前綴比預設路由長，必然優先），
    /// 固定走「非隧道、metric 最小」的那條 WAN。
    fn sync_underlay_routes(&mut self, active_wans: &[ActiveWanRoute]) -> io::Result<()> {
        let wanted = Self::plan_underlay_routes(active_wans);

        // 1) 先刪掉不再需要的（隧道下線、或出口換了）
        let stale: Vec<Ipv4Addr> = self
            .underlay_routes
            .keys()
            .filter(|addr| !wanted.iter().any(|(t, _, _)| t == *addr))
            .cloned()
            .collect();
        for addr in stale {
            if let Err(e) = self.delete_underlay_route(addr) {
                warn!("[RouteManager] Failed to remove underlay route {addr}/32: {e}");
                continue;
            }
            self.underlay_routes.remove(&addr);
        }

        // 2) 再補上缺的、或出口變了的
        for (addr, ifindex, gateway) in wanted {
            let unchanged = self
                .underlay_routes
                .get(&addr)
                .is_some_and(|(i, g)| *i == ifindex && *g == gateway);
            if unchanged {
                continue;
            }
            self.install_underlay_route(addr, ifindex, gateway.clone())?;
            self.underlay_routes.insert(addr, (ifindex, gateway));
        }
        Ok(())
    }

    /// 下發一條隧道 underlay 對端的 /32 路由
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

    /// 刪除一條隧道 underlay 對端的 /32 路由
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

    /// 更新 IPv4 預設路由。實際下發方式由 `ecmp_mode` 決定。
    ///
    /// 傳入空陣列代表「所有 WAN 皆斷線」，此時會主動刪除預設路由，
    /// 而不是什麼都不做（舊行為會讓流量繼續送往已死的鏈路）。
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

        // 先確保隧道 underlay 對端有 /32 可走：否則 ECMP 會依機率把封裝封包
        // 再塞回隧道自己，形成自環（詳見 `sync_underlay_routes`）。
        // 這裡刻意只告警不中斷：underlay /32 是「修正」，不該讓預設路由因此不下發。
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

    /// IPv6 版：只有當介面設定了 gateway6 時才會產生對應的 nexthop。
    /// IPv6 路由跟隨同一個 IPv4 健康狀態（實體是同一條鏈路），不另外探測。
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

    /// 全部 WAN 都判定 DOWN 時對預設路由的處理（IPv4/IPv6 共用）。
    ///
    /// 語意（實測決定，兩邊都是坑）：
    /// - **只有我們這一條預設路由** ⇒ 保留。刪掉會讓整機（含所有 LAN 客戶端）完全沒有出口，
    ///   而「線路回來時沒人重下」正是原本自鎖的成因之一。
    /// - **主表還有別人的預設路由**（例如 netifd 的 metric 10/50）⇒ 刪掉我們這條，
    ///   讓兜底接手。原因：載波掉（拔網線、對端下線）時內核**不會**自動移除
    ///   「dev 指到該設備」的路由，它只是標成 linkdown 並繼續勝過 metric 更大的兜底，
    ///   流量會一直被送往死鏈路；刪掉反而是救回上網的關鍵。
    ///
    /// 因為探針已經有自己的獨立表（不依賴這條預設路由），刪掉它不會讓 daemon 失去探測能力。
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
        self.delete_standard_route(family)?;
        self.set_installed_variant(family, InstalledVariant::None);
        Ok(())
    }

    /// 標準 multipath 路由（RTA_MULTIPATH），也是 resilient 失敗時的回退路徑。
    /// 保持「原子 replace」語意，非模式切換時不會出現無預設路由的空窗。
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

    /// 強制 resilient：失敗時一定把殘留清乾淨，避免半套狀態卡住預設路由。
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

    /// Auto：先試 resilient，不行就（永久或暫時）退回標準 multipath。
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

    /// 核心是否「根本不支援」nexthop object / resilient group，
    /// 或這個設定我們無法用 resilient 表達（成員數超過 bucket 上限）。
    /// 兩種情況都應該永久退回標準 ECMP，而不是每一輪都重試一次。
    #[cfg(target_os = "linux")]
    fn should_give_up_on_resilient(e: &io::Error) -> bool {
        if e.kind() == io::ErrorKind::InvalidInput {
            return true;
        }
        matches!(
            e.raw_os_error(),
            Some(libc::EINVAL)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::ENOSYS)
                | Some(libc::EAFNOSUPPORT)
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

    /// 從標準模式切走時，把殘留的 resilient 產物（路由 + group + 成員）清掉
    fn drop_resilient_if_active(&mut self, family: u8) {
        let group_id = Self::group_id_for(family);
        if self.installed_variant(family) == InstalledVariant::Resilient
            || self.has_any_member(family)
        {
            self.teardown_resilient(family, group_id);
        }
    }

    /// 拆除 resilient 預設路由：先刪路由（否則 group 仍被引用刪不掉），
    /// 再刪 group，最後才刪成員。全程容忍「本來就不存在」。
    fn teardown_resilient(&mut self, family: u8, group_id: u32) {
        if self.installed_variant(family) == InstalledVariant::Resilient {
            let _ = self.delete_nh_route(family, group_id);
        }
        // group 本身是用 AF_UNSPEC 建的，刪除時也要用 AF_UNSPEC
        let _ = self.delete_nexthop(AF_UNSPEC, group_id);
        for key in self.member_keys_for_family(family) {
            if let Some(id) = self.nh_ids.remove(&key) {
                if let Err(e) = self.delete_nexthop(family, id) {
                    warn!("[RouteManager] Failed to remove nexthop {id}: {e}");
                    self.nh_ids.insert(key, id);
                }
            }
        }
        self.set_installed_variant(family, InstalledVariant::None);
    }

    /// 用 resilient nexthop group 下發預設路由
    fn apply_resilient(
        &mut self,
        family: u8,
        group_id: u32,
        hops: &[RouteNexthop],
    ) -> io::Result<()> {
        // 全部斷線時的處理與 apply_standard 一致（必須放在 variant 切換之前：
        // 否則會先把標準路由刪掉再原地不動）
        if hops.is_empty() {
            return self.handle_all_links_down(family);
        }

        // 標準路由與 nh_id 路由的 key 不同，切換時必須先把舊的刪掉，
        // 否則核心會保留兩條 default route。
        if self.installed_variant(family) == InstalledVariant::Standard {
            self.delete_standard_route(family)?;
            self.set_installed_variant(family, InstalledVariant::None);
        }

        // bucket 必須同時是 2 的冪且涵蓋所有成員；超過上限就無法用 resilient 表達
        if hops.len() > RES_BUCKETS_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} nexthops exceed the resilient bucket limit of {RES_BUCKETS_MAX}",
                    hops.len()
                ),
            ));
        }

        // 1) 確保成員 nexthop object 存在。ID 沿用既有配置，
        //    核心才會認為成員「沒變」而保留它負責的 bucket。
        let mut members: Vec<(u32, u32)> = Vec::with_capacity(hops.len());
        for hop in hops {
            let id = self.alloc_nh_id(family, hop.ifindex, hop.gateway.as_ref());
            self.ensure_nexthop(family, id, hop.ifindex, hop.gateway.as_deref())?;
            members.push((id, hop.weight));
        }

        // 2) 建立 / 更新 resilient group
        let buckets = Self::res_bucket_count(members.len());
        self.ensure_nexthop_group(group_id, &members, buckets)?;

        // 3) 下發引用該 group 的預設路由
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

        // 4) group 已改指向新成員，這時刪舊成員才不會拿到 EBUSY
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

    /// 刪除 nexthop object。`family` 要與建立時一致（見 `build_nexthop_del_msg`）。
    fn delete_nexthop(&mut self, family: u8, id: u32) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_nexthop_del_msg(seq, family, id);
        self.commit_msg(&buffer, &format!("nexthop {id} removal"))
    }

    /// 刪掉已不在當前成員集合中的 nexthop object
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

    /// 優雅退出時把本程式下發的所有路由 / nexthop 產物清乾淨。
    ///
    /// 注意：只有**我們真的下發過**預設路由時才刪它。否則（例如開機至今全斷、
    /// 從未接管的部署）那條 metric 0 的預設路由其實是 netifd 的，刪掉就等於把
    /// 整台路由器的出口刪了。
    pub fn cleanup_routes(&mut self) -> io::Result<()> {
        // 探針路徑（規則 + 獨立表內的路由）先拆，避免規則指向已空的表
        let _ = self.set_probe_paths(&[]);
        self.teardown_resilient(AF_INET, NH_GROUP_ID_V4);
        self.teardown_resilient(AF_INET6, NH_GROUP_ID_V6);

        let mut result = Ok(());
        if self.installed_v4 != InstalledVariant::None {
            result = self.delete_default_route();
        } else {
            debug!(
                "[RouteManager] IPv4 default route was never installed by mwan4; leaving it alone"
            );
        }
        if self.installed_v6 != InstalledVariant::None {
            result = result.and(self.delete_ipv6_default_route());
        } else {
            debug!(
                "[RouteManager] IPv6 default route was never installed by mwan4; leaving it alone"
            );
        }
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

    /// 附加 RtAttr 屬性並處理 4 位元組對齊（純函數，方便單測）
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
        // 補零以對齊 4 bytes
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
        // weight > 256 會被夾住，避免 `as u8` 靜默截斷
        assert_eq!(300u32.clamp(1, MAX_NEXTHOP_WEIGHT), 256);
        assert_eq!(0u32.clamp(1, MAX_NEXTHOP_WEIGHT), 1);
        // 257 在舊程式碼裡會變成 0，等價於 weight=1，屬於靜默錯誤
        assert_eq!((257u32.clamp(1, MAX_NEXTHOP_WEIGHT) - 1) as u8, 255);
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

    /// 解析訊息中的 rtattr 串流，回傳 (type, payload) 列表
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
        // 訊息總長必須是 4 的倍數（netlink 對齊要求）
        assert_eq!(msg.len() % 4, 0);

        assert_eq!(&msg[NlMsgHdr::LEN], &AF_INET); // rtm_family
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0); // dst_len = 0 -> 預設路由

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
        // IPv6 網關必須是 16 bytes
        assert_eq!(attrs[1].1.len(), 16);
        assert_eq!(attrs[1].1, gw.octets().to_vec());
        // metric 有帶進去
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

        // 逐個走過 nexthop，驗證 rtnh_len 與對齊（核心會用 NLMSG_ALIGN(rtnh_len) 前進）
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
        // 走完後不應有殘留位元組，否則核心 fib_get_nhs 會回 EINVAL
        assert_eq!(off, mp.len(), "trailing bytes after last nexthop");
        // 每個 nexthop：8 bytes 標頭 + 4 bytes 屬性頭 + 4 bytes 網關
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
        // 刪除只需要 key（dst/table/priority），不應帶任何 nexthop 屬性
        let attrs = parse_attrs(&msg);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![RTA_PRIORITY]);
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
        // rtm_scope 位於 rtmsg 的第 6 個位元組
        assert_eq!(msg[NlMsgHdr::LEN + 6], RT_SCOPE_LINK);
    }

    // -----------------------------------------------------------------------
    // nexthop object / resilient nexthop group
    // -----------------------------------------------------------------------

    /// 從任意偏移解析 rtattr 串流（nexthop 訊息的固定標頭是 nhmsg 而非 rtmsg）
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

    /// 這些列舉值是照 Linux uapi 抄的，抄錯只會得到一個沒有上下文的 EINVAL，
    /// 所以用測試把它釘住。
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
        // bucket 數是巢狀列舉裡的 NHA_RES_GROUP_BUCKETS（u16），不是頂層的 13
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
        assert_eq!(msg.len() % 4, 0, "netlink 訊息必須 4 bytes 對齊");
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

        let attrs = nh_attrs(&msg);
        // 刪除時多帶 NHA_OIF 會被核心視為無效；只允許 NHA_ID
        assert_eq!(attr_types(&attrs), vec![NHA_ID]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
    }

    #[test]
    fn test_nexthop_del_msg_uses_the_same_family_as_creation() {
        // 成員是以 AF_INET 建立的，刪除時也必須帶 AF_INET。
        // 早期版本寫死 AF_UNSPEC，內核比對 family 失敗回 EINVAL，
        // 成員因此永遠刪不掉，每輪重試都留下一個孤兒 nexthop object。
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
                // 巢狀屬性必須帶 NLA_F_NESTED，少了它核心就不解析裡面的 bucket 數
                NHA_RES_GROUP | NLA_F_NESTED
            ]
        );
        assert_eq!(read_u32(&attrs[0].1, 0), Some(NH_GROUP_ID_V4));
        // 沒有 NHA_GROUP_TYPE=RES，核心不會把它當成 resilient group
        assert_eq!(read_u16(&attrs[1].1, 0), Some(NEXTHOP_GRP_TYPE_RES));

        // NHA_GROUP 是連續的 8-byte 成員
        let grp = &attrs[2].1;
        assert_eq!(grp.len(), 2 * NextHopGrp::LEN);
        assert_eq!(read_u32(grp, 0), Some(1));
        assert_eq!(grp[4], 0); // weight 1 -> hops 0
        assert_eq!(read_u32(grp, 8), Some(2));
        assert_eq!(grp[12], 2); // weight 3 -> hops 2

        // NHA_RES_GROUP 是巢狀屬性，內含 NHA_RES_GROUP_BUCKETS。
        // 這裡曾經誤用頂層的 NHA_RES_BUCKETS(13) 並以 u32 編碼，核心因此回 EINVAL，
        // resilient 模式從未真正生效；下面兩行就是為了防止它復發。
        let res = parse_attr_stream(&attrs[3].1, 0);
        assert_eq!(attr_types(&res), vec![NHA_RES_GROUP_BUCKETS]);
        assert_eq!(res[0].1.len(), 2, "bucket 數必須是 u16，不是 u32");
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
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0); // dst_len = 0 -> 預設路由
        // 路由訊息用 rtmsg（12 bytes），不是 nhmsg
        let attrs = parse_attrs(&msg);
        assert_eq!(attr_types(&attrs), vec![RTA_PRIORITY, RTA_NH_ID]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
        assert_eq!(read_u32(&attrs[1].1, 0), Some(NH_GROUP_ID_V4));

        // 刪除訊息必須帶同一個 nh_id，否則核心的 fib key 對不上、路由刪不掉
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
    fn test_res_bucket_count_is_power_of_two_and_covers_members() {
        for members in [0usize, 1, 2, 3, 8, 9, 16, 17, 64, 100, 256] {
            let b = RouteManager::res_bucket_count(members) as usize;
            assert!(b.is_power_of_two(), "buckets {b} must be a power of two");
            assert!(
                b >= members.max(1),
                "buckets {b} must cover {members} members"
            );
            assert!((RES_BUCKETS_MIN..=RES_BUCKETS_MAX).contains(&b));
        }

        // 超過上限時退回上限值；呼叫端（apply_resilient）會把這種設定判為不支援
        assert_eq!(
            RouteManager::res_bucket_count(10_000),
            RES_BUCKETS_MAX as u16
        );
        assert_eq!(
            RouteManager::res_bucket_count(RES_BUCKETS_MAX + 1),
            RES_BUCKETS_MAX as u16
        );

        assert_eq!(RouteManager::res_bucket_count(0), RES_BUCKETS_MIN as u16);
        assert_eq!(RouteManager::res_bucket_count(2), RES_BUCKETS_MIN as u16);
        assert_eq!(RouteManager::res_bucket_count(9), 16);
    }

    #[test]
    fn test_too_many_members_is_treated_as_unsupported() {
        // 成員數超過 bucket 上限時 apply_resilient 會回 InvalidInput；
        // auto 模式必須據此永久退回，否則每一輪都要重試一次失敗的 netlink 呼叫
        let e = io::Error::new(io::ErrorKind::InvalidInput, "too many nexthops");
        assert!(RouteManager::should_give_up_on_resilient(&e));
    }

    #[test]
    fn test_nexthop_ids_are_stable_per_member() {
        let mut rm = RouteManager::new(0, EcmpMode::Standard).unwrap();
        let a = rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1]));
        let b = rm.alloc_nh_id(AF_INET, 4, Some(&vec![192, 168, 2, 1]));
        assert_ne!(a, b);

        // 同一成員重複配置必須拿到同一個 ID；換 ID 等於換成員，
        // 核心會把該成員負責的 flow 全部重映射（正是我們要避免的事）
        assert_eq!(rm.alloc_nh_id(AF_INET, 3, Some(&vec![192, 168, 1, 1])), a);

        // 位址族不同 / 同一 ifindex 但沒有網關，都不能撞號
        let v6 = rm.alloc_nh_id(AF_INET6, 3, Some(&vec![0u8; 16]));
        let v4_direct = rm.alloc_nh_id(AF_INET, 3, None);
        assert!(![a, b].contains(&v6));
        assert!(![a, b, v6].contains(&v4_direct));

        // 群組 ID 保留在高位，不會與成員 ID 撞號
        assert!(NH_GROUP_ID_V4 > rm.next_nh_id);
        assert!(NH_GROUP_ID_V6 > rm.next_nh_id);
    }

    // -----------------------------------------------------------------------
    // 探針路徑（獨立表 + oif 規則）
    // -----------------------------------------------------------------------

    /// 解析 fib_rule 訊息：回傳 (hdr 欄位, 屬性列表)
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
        // 表號必須 > 255 才能驗證我們只用 RTA_TABLE 表達它；
        // 規則優先序必須落在 1..32766 之間才會在 main 表之前被求值。
        // （這兩個不變式同時由模組層的 const assert 在編譯期檢查。）
        let tables: Vec<u32> = (0..8).map(|i| PROBE_TABLE_BASE + i).collect();
        assert!(tables.iter().all(|t| *t > 255));
        let priorities: Vec<u32> = (0..8).map(|i| PROBE_RULE_PRIORITY_BASE + i).collect();
        assert!(
            priorities
                .iter()
                .all(|p| *p > 0 && *p < 32_766 && *p != 32_766)
        );
        // 預設路由的 metric 0 與探針表是兩套 namespace，不應互相影響
        assert_ne!(PROBE_TABLE_BASE, 254);
    }

    #[test]
    fn test_rule_constants_match_linux_uapi() {
        // 這幾個值照 /usr/include/linux/rtnetlink.h 與 fib_rules.h 釘死。
        // 抄錯的代價極高：RTM_NEWRULE 寫成 21（= RTM_DELADDR）或把 FRA_OIFNAME
        // 寫成 10（= FRA_FWMARK）時，內核會回一個毫無上下文的 ENODEV，
        // 症狀是「探針路徑永遠裝不上、兩條線永遠 DOWN」。
        assert_eq!(RTM_NEWRULE, 32);
        assert_eq!(RTM_DELRULE, 33);
        assert_eq!(FRA_PRIORITY, 6);
        assert_eq!(FRA_TABLE, 15);
        assert_eq!(FRA_OIFNAME, 17);
        assert_eq!(FR_ACT_TO_TBL, 1);
        // 既有 nexthop 常數也一併對照（104/105 與 NHA_* 都必須與 uapi 一致）
        assert_eq!(RTM_NEWNEXTHOP, 104);
        assert_eq!(RTM_DELNEXTHOP, 105);
        assert_eq!(NHA_RES_GROUP, 12);
        // bucket 數是巢狀列舉裡的 NHA_RES_GROUP_BUCKETS（u16），不是頂層的 13
        assert_eq!(NHA_RES_GROUP_BUCKETS, 1);
        assert_eq!(NHA_OIF, 5);
        assert_eq!(NHA_GATEWAY, 6);
    }

    #[test]
    fn test_getroute_request_and_reply_parsing() {
        // 請求：RTM_GETROUTE + RTA_DST(/32) + 可選 RTA_OIF
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
        assert_eq!(msg[NlMsgHdr::LEN + 1], 32, "dst_len 必須是 32");
        let attrs = parse_attrs(&msg);
        assert_eq!(attr_types(&attrs), vec![RTA_DST, RTA_OIF]);
        assert_eq!(attrs[0].1, vec![203, 0, 113, 10]);

        // dump 請求：不帶 dst，帶 NLM_F_DUMP
        let dump = RouteManager::build_getroute_msg(AF_INET, 4, None, None, true);
        let dump_hdr = NlMsgHdr::from_bytes(&dump).unwrap();
        assert_eq!(dump_hdr.nlmsg_flags & NLM_F_DUMP, NLM_F_DUMP);
        assert_eq!(dump[NlMsgHdr::LEN + 1], 0);

        // 解析回覆：rtmsg(table=254) + RTA_TABLE + RTA_OIF + RTA_GATEWAY
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

        // 空屬性串流也要能解析（只有 rtmsg）
        let bare = vec![0u8; NlMsgHdr::LEN + RtMsg::LEN];
        let parsed = RouteManager::parse_route_reply(&bare, bare.len()).unwrap();
        assert_eq!(parsed.ifindex, None);
        assert_eq!(parsed.table, 0);
    }

    /// 隧道 underlay /32 的出口選擇：只能是「非隧道」的線，且取 metric 最小者。
    /// 這條規則直接對應實機上那個「切到 resilient 後隧道丟包 60%」的自環 bug。
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

        // 物理線 eth1（metric 10）+ 隧道 vxlan0（metric 10，列出自己的 underlay 對端）
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
        assert_eq!(plan[0].1, 3, "對端必須走物理線 eth1，而不是隧道自己");
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

        // 兩條物理線：metric 小的 eth1 當出口（同 metric 才看設定檔順序）
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
        assert_eq!(plan[0].1, 3, "metric 最小的物理線 eth1 才是出口");

        // 只有隧道可選：不下發 /32（否則會形成隧道當隧道 underlay 的遞迴依賴）
        let only_tunnels = vec![wan("wg0", 7, 10, None, vec![Ipv4Addr::new(1, 2, 3, 4)])];
        assert!(RouteManager::plan_underlay_routes(&only_tunnels).is_empty());

        // 沒有隧道：自然是空集合
        let no_tunnel = vec![wan("eth1", 3, 10, None, Vec::new())];
        assert!(RouteManager::plan_underlay_routes(&no_tunnel).is_empty());

        // 空集合也不該 panic
        assert!(RouteManager::plan_underlay_routes(&[]).is_empty());
    }

    #[test]
    fn test_probe_main_route_metric_is_distinct() {
        // 探針 /32 的 metric 必須與預設路由的 priority 不同，否則會互相蓋掉；
        // 也要與 slot 推導出的表號/優先序區段分開，避免誤刪。
        // （與 metric 0 / 區段不重疊的不變式同時由模組層 const assert 在編譯期檢查。）
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
        assert_eq!(msg.len() % 4, 0, "netlink 訊息必須 4 bytes 對齊");

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
        // 我們的規則會帶來源標記，清掃時才能只刪自己的
        assert_eq!(attrs[2].1, vec![PROBE_RULE_PROTOCOL]);
        // 字串屬性必須帶結尾 NUL（核心用 strlen 解析）
        assert_eq!(attrs[3].1, b"vxlan\0".to_vec());

        // 入向規則用的是 FRA_IIFNAME，抄錯就會變成「規則裝了但反向路徑照樣被擋」
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

        // 刪除訊息除 type 外必須完全一致，否則核心的 rule key 對不上
        let del =
            RouteManager::build_rule_msg(9, spec(true), RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(NlMsgHdr::from_bytes(&del).unwrap().nlmsg_type, RTM_DELRULE);
        assert_eq!(parse_rule(&del).1, attrs);
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
        // 不同 slot 必須拿到不同的表號／優先序，否則會互相覆蓋
        assert_ne!(path.table, PROBE_TABLE_BASE);
        assert_ne!(path.priority, PROBE_RULE_PRIORITY_BASE);
        assert_eq!(path.table, 10_005);
        assert_eq!(path.priority, 10_005);
        // 主表 /32 的 metric 必須與預設路由的 priority 不同，否則會互相蓋掉
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
        // 表內路由的 metric 與主表預設路由（route_priority）無關，固定 0
        assert_eq!(read_u32(&attrs[1].1, 0), Some(0));
        assert_eq!(attrs[2].1, vec![10, 77, 0, 1]);
        assert_eq!(read_u32(&attrs[3].1, 0), Some(12));
        // 這是預設路由（dst_len = 0）
        assert_eq!(msg[NlMsgHdr::LEN + 1], 0);
        // rtm_table 低位元組截斷不影響核心（以 RTA_TABLE 為準），但仍保持一致
        assert_eq!(
            msg[NlMsgHdr::LEN + 4],
            (table & 0xFF) as u8,
            "rtm_table 應與 RTA_TABLE 的低位元組一致"
        );

        // 刪除時不帶任何 nexthop 屬性，只靠 (table, dst, metric) 命中
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
        // dst 參數是給未來擴充用的（目前探針路徑只用表內預設路由），
        // 這裡釘住編碼：RTA_DST 必須存在且 rtm_dst_len 正確
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
        // 主表那條預設路由的編碼不能被改動（既有測試已釘欄位順序，這裡補 RTA_TABLE 不存在的檢查）
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
            "主表路由不應帶 RTA_TABLE"
        );
    }
}
