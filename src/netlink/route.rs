// 本模組只在 Linux 上真正執行 netlink I/O；
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）會整批變成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use crate::config::EcmpMode;
use crate::netlink::util::{
    NlMsgHdr, read_i32, rta_align, set_socket_timeouts, write_u16, write_u32,
};
use log::{debug, error, info, warn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

// Linux Netlink 常數定義
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;

// nexthop object（Linux 5.3+）；resilient group 需要 5.14+
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_REPLACE: u16 = 0x100;

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
/// 路由改為引用 nexthop object 時使用的屬性（取代 RTA_OIF / RTA_GATEWAY / RTA_MULTIPATH）
pub const RTA_NH_ID: u16 = 30;

// nexthop 專用的 rtattr 型別（enum nha_type）
pub const NHA_ID: u16 = 1;
pub const NHA_GROUP: u16 = 2;
pub const NHA_GROUP_TYPE: u16 = 3;
pub const NHA_OIF: u16 = 5;
pub const NHA_GATEWAY: u16 = 6;
pub const NHA_RES_GROUP: u16 = 12;
pub const NHA_RES_BUCKETS: u16 = 13;

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

/// 等待核心 ACK 的最大輪詢次數（配合 socket 上的 SO_RCVTIMEO 使用）
const ACK_RETRY_LIMIT: usize = 4;

#[cfg(target_os = "linux")]
const ESRCH: i32 = libc::ESRCH;
#[cfg(not(target_os = "linux"))]
const ESRCH: i32 = 3;

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
}

/// 活躍 WAN 路由節點（IPv6）
#[derive(Debug, Clone)]
pub struct ActiveWanRouteV6 {
    pub ifname: String,
    pub ifindex: u32,
    pub gateway: Option<Ipv6Addr>,
    pub weight: u32,
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
        let mut buffer: Vec<u8> = Vec::with_capacity(512);
        // 預留 nlmsghdr 空間
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);

        // 若唯一存活路由沒有網關（點對點 / PPPoE），其 scope 應為 RT_SCOPE_LINK
        let rtm_scope = if hops.len() == 1 && hops[0].gateway.is_none() {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };

        let rtmsg = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0, // 預設路由
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_STATIC,
            rtm_scope,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };
        buffer.extend_from_slice(&rtmsg.to_bytes());

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
    /// `buckets = Some(n)` 時附上 NHA_RES_GROUP / NHA_RES_BUCKETS 與
    /// NHA_GROUP_TYPE = RES，形成 resilient group；`None` 則是一般 multipath group。
    fn build_nexthop_group_msg(
        seq: u32,
        group_id: u32,
        members: &[(u32, u32)],
        buckets: Option<u32>,
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
            // NHA_RES_GROUP 是巢狀屬性，內含 NHA_RES_BUCKETS
            let mut res: Vec<u8> = Vec::with_capacity(16);
            Self::append_attr(&mut res, NHA_RES_BUCKETS, &bucket_count.to_ne_bytes());
            Self::append_attr(&mut buffer, NHA_RES_GROUP, &res);
        }

        Self::finish_msg(&mut buffer, msg_type, flags, seq);
        buffer
    }

    /// 組出刪除單一 nexthop object 的訊息（只需要 NHA_ID）
    fn build_nexthop_del_msg(seq: u32, id: u32) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0u8; NlMsgHdr::LEN]);
        buffer.extend_from_slice(&Self::nhmsg_bytes(AF_UNSPEC).to_bytes());
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
            rtm_protocol: RTPROT_STATIC,
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

    /// resilient group 的 bucket 數：2 的冪、不小於成員數
    fn res_bucket_count(members: usize) -> u32 {
        let mut b = RES_BUCKETS_MIN;
        while b < members.max(1) && b < RES_BUCKETS_MAX {
            b *= 2;
        }
        b as u32
    }

    /// 送出 netlink 訊息並等待 ACK；目標本來就不存在（ESRCH）視為成功
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
            Err(e) if e.raw_os_error() == Some(ESRCH) => {
                debug!("[RouteManager] {label}: object already absent, nothing to do.");
                Ok(())
            }
            Err(e) => Err(e),
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

    /// 標準 multipath 路由（RTA_MULTIPATH），也是 resilient 失敗時的回退路徑。
    /// 保持「原子 replace」語意，非模式切換時不會出現無預設路由的空窗。
    fn apply_standard(&mut self, family: u8, hops: &[RouteNexthop]) -> io::Result<()> {
        if hops.is_empty() {
            error!("[RouteManager] ALL WAN LINKS DOWN! Removing stale default route from FIB.");
            return self.delete_standard_route(family);
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
        let _ = self.delete_nexthop(group_id);
        for key in self.member_keys_for_family(family) {
            if let Some(id) = self.nh_ids.remove(&key) {
                if let Err(e) = self.delete_nexthop(id) {
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
        // 標準路由與 nh_id 路由的 key 不同，切換時必須先把舊的刪掉，
        // 否則核心會保留兩條 default route。
        if self.installed_variant(family) == InstalledVariant::Standard {
            self.delete_standard_route(family)?;
            self.set_installed_variant(family, InstalledVariant::None);
        }

        if hops.is_empty() {
            error!(
                "[RouteManager] ALL WAN LINKS DOWN! Tearing down {} resilient default route.",
                Self::family_name(family)
            );
            self.teardown_resilient(family, group_id);
            return Ok(());
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
        buckets: u32,
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

    fn delete_nexthop(&mut self, id: u32) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let buffer = Self::build_nexthop_del_msg(seq, id);
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
                if let Err(e) = self.delete_nexthop(id) {
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

    /// 優雅退出時把本程式下發的所有路由 / nexthop 產物清乾淨
    pub fn cleanup_routes(&mut self) -> io::Result<()> {
        self.teardown_resilient(AF_INET, NH_GROUP_ID_V4);
        self.teardown_resilient(AF_INET6, NH_GROUP_ID_V6);
        self.delete_default_route()?;
        self.delete_ipv6_default_route()
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
        assert_eq!(NHA_RES_BUCKETS, 13);
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
        let msg = RouteManager::build_nexthop_del_msg(3, 5);
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_DELNEXTHOP);
        assert_eq!(msg[NlMsgHdr::LEN], AF_UNSPEC);

        let attrs = nh_attrs(&msg);
        // 刪除時多帶 NHA_OIF 會被核心視為無效；只允許 NHA_ID
        assert_eq!(attr_types(&attrs), vec![NHA_ID]);
        assert_eq!(read_u32(&attrs[0].1, 0), Some(5));
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
            vec![NHA_ID, NHA_GROUP_TYPE, NHA_GROUP, NHA_RES_GROUP]
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

        // NHA_RES_GROUP 是巢狀屬性，內含 NHA_RES_BUCKETS
        let res = parse_attr_stream(&attrs[3].1, 0);
        assert_eq!(attr_types(&res), vec![NHA_RES_BUCKETS]);
        assert_eq!(read_u32(&res[0].1, 0), Some(16));
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
            RES_BUCKETS_MAX as u32
        );
        assert_eq!(
            RouteManager::res_bucket_count(RES_BUCKETS_MAX + 1),
            RES_BUCKETS_MAX as u32
        );

        assert_eq!(RouteManager::res_bucket_count(0), RES_BUCKETS_MIN as u32);
        assert_eq!(RouteManager::res_bucket_count(2), RES_BUCKETS_MIN as u32);
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
}
