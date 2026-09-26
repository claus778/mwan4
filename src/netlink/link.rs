//! 订阅核心的网卡 / 位址变更事件。
//!
//! 之前是靠每 30 秒轮询一次 `if_nametoindex`、每 60 秒轮询一次介面 IP 来应付
//! PPPoE 重拨、USB 网卡重插这类 ifindex 会变的场景。订阅 RTNLGRP_LINK /
//! RTNLGRP_IPV4_IFADDR 之后，核心一有变动就能在毫秒级收到通知。

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::io;

use crate::netlink::util::{NlMsgHdr, read_u16, read_u32, rta_align};

// rtnetlink multicast groups
pub const RTNLGRP_LINK: u32 = 1;
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;

/// link 属性：介面名称（NUL 结尾字串）
const IFLA_IFNAME: u16 = 3;
/// netlink 属性类型遮罩（低位 14 bit）
const NLA_TYPE_MASK: u16 = 0x3fff;

/// IFF_UP / IFF_RUNNING（struct ifinfomsg 的 flags 栏位）
pub const IFF_UP: u32 = 0x1;
pub const IFF_RUNNING: u32 = 0x40;

/// 一次接收的最大位元组数
const RECV_BUF_SIZE: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// 网卡新增 / 删除 / 状态或 ifindex 变动。
    /// ifname 来自讯息中的 IFLA_IFNAME：网卡重建后 ifindex 会变、名称不变，
    /// 呼叫端需靠名称重新解析 ifindex，因此这里必须把名称带出来。
    Link {
        ifindex: u32,
        ifname: Option<String>,
        carrier_up: bool,
    },
    /// IPv4 / IPv6 位址变动
    Address { ifindex: u32 },
    /// 接收缓冲溢位（ENOBUFS）：部分组播事件已被核心丢弃。
    /// 这不是致命错误——呼叫端应做一次全量 resync 并保持订阅，
    /// 而不是放弃事件驱动退回长间隔轮询。
    Resync,
}

impl LinkEvent {
    pub fn ifindex(&self) -> u32 {
        match self {
            LinkEvent::Link { ifindex, .. } | LinkEvent::Address { ifindex } => *ifindex,
            LinkEvent::Resync => 0,
        }
    }
}

/// 网卡事件监看器（Linux 专用；非 Linux 平台不会建构）
#[cfg(target_os = "linux")]
pub struct LinkWatcher {
    afd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl LinkWatcher {
    /// 建立并订阅 link / ifaddr 事件的 netlink socket
    pub fn new() -> io::Result<Self> {
        use std::os::fd::{FromRawFd, OwnedFd};

        // SOCK_NONBLOCK 是 AsyncFd 的前置条件；SOCK_CLOEXEC 避免 fd 外泄给子行程
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0;
        // netlink group 是以 0 为起点的 bit number
        sa.nl_groups = (1 << (RTNLGRP_LINK - 1))
            | (1 << (RTNLGRP_IPV4_IFADDR - 1))
            | (1 << (RTNLGRP_IPV6_IFADDR - 1));

        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }

        // 适度加大接收缓冲，降低组播事件风暴（开机期 netifd 批量拉起介面、
        // PPPoE 反复重拨）时的 ENOBUFS 溢位机率。失败不致命，忽略即可。
        let rcvbuf: libc::c_int = 256 * 1024;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let afd = tokio::io::unix::AsyncFd::new(owned)?;

        Ok(Self {
            afd,
            buf: vec![0u8; RECV_BUF_SIZE],
        })
    }

    /// 等待下一批事件。回传空集合代表 socket 有状况，呼叫端应放弃订阅。
    pub async fn wait_events(&mut self) -> Vec<LinkEvent> {
        use std::os::fd::AsRawFd;

        loop {
            let mut guard = match self.afd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    log::warn!("[LinkWatcher] socket readable failed: {e}");
                    return Vec::new();
                }
            };

            // 分别借用不同栏位，避免与 guard 的可变借用冲突
            let raw_fd = self.afd.as_raw_fd();
            let buf = &mut self.buf;
            match Self::drain(raw_fd, buf) {
                Ok(events) if events.is_empty() => {
                    // 只有不感兴趣的讯息，清掉就绪状态后继续等
                    guard.clear_ready();
                }
                Ok(events) => return events,
                Err(e) => {
                    log::warn!("[LinkWatcher] drain failed: {e}");
                    guard.clear_ready();
                    return Vec::new();
                }
            }
        }
    }

    /// 非阻塞地把接收伫列读干净，回传感兴趣的事件
    fn drain(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<Vec<LinkEvent>> {
        let mut events = Vec::new();

        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    // 组播事件溢位：部分事件已被核心丢弃。回传 Resync 让呼叫端
                    // 做一次全量刷新，订阅保持有效——把 ENOBUFS 当致命错误会让
                    // 事件驱动永久退化成长间隔轮询。
                    return Ok(vec![LinkEvent::Resync]);
                }
                return Err(e);
            }
            if n == 0 {
                break;
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

                match hdr.nlmsg_type {
                    RTM_NEWLINK | RTM_DELLINK => {
                        // struct ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4)
                        let base = offset + NlMsgHdr::LEN;
                        let ifindex = read_u32(&buf[..len], base + 4);
                        // 属性区紧跟在 16 位元组的 ifinfomsg 之后
                        let attrs_base = base + 16;
                        let ifname = if attrs_base <= offset + msg_len {
                            Self::parse_ifla_ifname(&buf[attrs_base..offset + msg_len])
                        } else {
                            None
                        };
                        if let Some(ifindex) = ifindex {
                            let flags = read_u32(&buf[..len], base + 8).unwrap_or(0);
                            let carrier_up = hdr.nlmsg_type == RTM_NEWLINK
                                && (flags & IFF_UP) != 0
                                && (flags & IFF_RUNNING) != 0;
                            events.push(LinkEvent::Link {
                                ifindex,
                                ifname,
                                carrier_up,
                            });
                        }
                    }
                    RTM_NEWADDR | RTM_DELADDR => {
                        // struct ifaddrmsg: family(1) prefixlen(1) flags(1) scope(1) index(4)
                        let base = offset + NlMsgHdr::LEN;
                        if let Some(ifindex) = read_u32(&buf[..len], base + 4) {
                            events.push(LinkEvent::Address { ifindex });
                        }
                    }
                    _ => {}
                }

                offset += crate::netlink::util::nlmsg_align(msg_len);
            }
        }

        Ok(events)
    }

    /// 从 rtnetlink 属性流中取 IFLA_IFNAME（NUL 结尾字串）
    fn parse_ifla_ifname(attrs: &[u8]) -> Option<String> {
        let mut offset = 0usize;
        while offset + 4 <= attrs.len() {
            let rta_len = match read_u16(attrs, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let rta_type = match read_u16(attrs, offset + 2) {
                Some(v) => v & NLA_TYPE_MASK,
                None => break,
            };
            if rta_len < 4 || offset + rta_len > attrs.len() {
                break;
            }
            if rta_type == IFLA_IFNAME {
                let data = &attrs[offset + 4..offset + rta_len];
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                return Some(String::from_utf8_lossy(&data[..end]).into_owned());
            }
            offset += rta_align(rta_len);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_event_ifindex_accessor() {
        let e = LinkEvent::Link {
            ifindex: 7,
            ifname: Some("wan1".into()),
            carrier_up: true,
        };
        assert_eq!(e.ifindex(), 7);

        let a = LinkEvent::Address { ifindex: 9 };
        assert_eq!(a.ifindex(), 9);

        assert_eq!(LinkEvent::Resync.ifindex(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_ifla_ifname() {
        // nlattr { len=9, type=IFLA_IFNAME } + "wan1\0" + 3 bytes padding
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&9u16.to_ne_bytes());
        attrs.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        attrs.extend_from_slice(b"wan1\0");
        attrs.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            LinkWatcher::parse_ifla_ifname(&attrs).as_deref(),
            Some("wan1")
        );

        // 其他属性在前，IFLA_IFNAME 在后
        let mut mixed = Vec::new();
        mixed.extend_from_slice(&8u16.to_ne_bytes());
        mixed.extend_from_slice(&1u16.to_ne_bytes());
        mixed.extend_from_slice(&[0, 0, 0, 0]);
        mixed.extend_from_slice(&attrs);
        assert_eq!(
            LinkWatcher::parse_ifla_ifname(&mixed).as_deref(),
            Some("wan1")
        );

        // 没有 IFNAME 属性
        assert_eq!(LinkWatcher::parse_ifla_ifname(&[0, 0, 0, 0]), None);
    }

    #[test]
    fn test_iff_constants() {
        // Linux 的 IFF_UP / IFF_RUNNING 位元定义
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(IFF_RUNNING, 0x40);
    }

    #[test]
    fn test_group_bitmask() {
        // group N 对应 bit (N-1)
        let mask = (1u32 << (RTNLGRP_LINK - 1))
            | (1u32 << (RTNLGRP_IPV4_IFADDR - 1))
            | (1u32 << (RTNLGRP_IPV6_IFADDR - 1));
        assert_eq!(mask, (1 << 0) | (1 << 4) | (1 << 8));
        assert_eq!(mask & (1 << 0), 1 << 0);
    }
}
