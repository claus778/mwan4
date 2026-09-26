// 本模组只在 Linux 上真正执行 netlink I/O；
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）会整批变成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use log::{debug, info, warn};
use std::io;
use std::net::Ipv4Addr;

// 部分工具函数仅在 Linux 分支中使用
#[allow(unused_imports)]
use crate::netlink::util::{
    NlMsgHdr, nlmsg_align, read_i32, read_u16, rta_align, set_socket_timeouts, write_u16,
};
#[allow(dead_code)]
pub const NETLINK_NETFILTER: libc::c_int = 12;
#[allow(dead_code)]
pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;

#[allow(dead_code)]
pub const IPCTNL_MSG_CT_NEW: u16 = 0;
#[allow(dead_code)]
pub const IPCTNL_MSG_CT_GET: u16 = 1;
#[allow(dead_code)]
pub const IPCTNL_MSG_CT_DELETE: u16 = 2;

#[allow(dead_code)]
pub const NLM_F_REQUEST: u16 = 0x01;
#[allow(dead_code)]
pub const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH

// CtNetlink 属性定义
#[allow(dead_code)]
pub const CTA_UNSPEC: u16 = 0;
#[allow(dead_code)]
pub const CTA_TUPLE_ORIG: u16 = 1;
#[allow(dead_code)]
pub const CTA_TUPLE_REPLY: u16 = 2;
#[allow(dead_code)]
pub const CTA_TUPLE_IP: u16 = 1;
#[allow(dead_code)]
pub const CTA_IP_V4_SRC: u16 = 1;
#[allow(dead_code)]
pub const CTA_IP_V4_DST: u16 = 2;
#[allow(dead_code)]
pub const NLA_TYPE_MASK: u16 = 0x3fff;
/// conntrack zone（u16）。带 zone 的部署（nftables `ct zone`）若删除时不回填，
/// 内核会在 zone 0 找同 tuple 的连线：轻则 ENOENT 漏删，重则误删 zone 0 的条目。
#[allow(dead_code)]
pub const CTA_ZONE: u16 = 18;

/// struct nfgenmsg（4 bytes）
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16,
}

impl NfGenMsg {
    pub const LEN: usize = 4;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = self.nfgen_family;
        b[1] = self.version;
        write_u16(&mut b, 2, self.res_id);
        b
    }
}

/// dump 单次 recv 的缓冲区大小
const DUMP_BUF_SIZE: usize = 32 * 1024;
/// 批量删除时单次 send 的累积上限
const DELETE_BATCH_LIMIT: usize = 8 * 1024;
/// conntrack socket 的收/发逾时
const CT_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const CT_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Conntrack 管理器
pub struct ConntrackManager {
    #[cfg(target_os = "linux")]
    sock_fd: libc::c_int,
    seq: u32,
}

impl ConntrackManager {
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let sock_fd = Self::open_socket()?;
            Ok(Self { sock_fd, seq: 1 })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self { seq: 1 })
        }
    }

    #[cfg(target_os = "linux")]
    fn open_socket() -> io::Result<libc::c_int> {
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if sock_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0;
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

        if let Err(e) = set_socket_timeouts(sock_fd, Some(CT_RECV_TIMEOUT), Some(CT_SEND_TIMEOUT)) {
            warn!("[Conntrack] Failed to set socket timeouts: {e}");
        }

        Ok(sock_fd)
    }

    /// 关掉旧 socket 并重开。
    ///
    /// netlink 的 dump 状态是「socket 级」的：上一次 dump 没收到 `NLMSG_DONE` 就结束时，
    /// 核心会认为 dump 仍在进行中，之后同一 socket 上的 `NLM_F_DUMP` 一律回 `-EBUSY`
    /// —— flush 就变成永远扫不到东西的 no-op。逾时／错误后直接重建 socket 最干净。
    #[cfg(target_os = "linux")]
    fn reopen_socket(&mut self) {
        if self.sock_fd >= 0 {
            unsafe { libc::close(self.sock_fd) };
        }
        self.sock_fd = -1;
        match Self::open_socket() {
            Ok(fd) => self.sock_fd = fd,
            Err(e) => warn!("[Conntrack] Failed to reopen netlink socket: {e}"),
        }
    }

    /// 当 WAN 掉线 / 活跃集合变化时，精准清理这些网卡上的 conntrack 连接。
    ///
    /// 多张网卡合并为一次全表 dump（匹配任一 WAN IP 即删除），
    /// 避免每张网卡各扫一遍完整 conntrack 表。
    pub fn flush_interfaces_conntrack(
        &mut self,
        ifaces: &[(String, Option<Ipv4Addr>)],
    ) -> io::Result<usize> {
        let mut ips: Vec<Ipv4Addr> = Vec::with_capacity(ifaces.len());
        let mut names: Vec<&str> = Vec::with_capacity(ifaces.len());
        for (ifname, last_known) in ifaces {
            names.push(ifname.as_str());
            match crate::netlink::util::get_interface_ipv4(ifname) {
                Ok(ip) => ips.push(ip),
                Err(e) => {
                    // 介面已消失或正在重拨（PPPoE/USB）时现查会失败。用 DOWN 判定时
                    // 记下的最后已知 IP 才清得到 NAT 到旧位址的连线——这正是长连线
                    // 卡死最需要清理的场景。
                    if let Some(ip) = last_known {
                        debug!(
                            "[Conntrack] Could not query IP for {ifname} ({e}); \
                             using last known IP {ip}"
                        );
                        ips.push(*ip);
                    } else {
                        warn!(
                            "[Conntrack] Could not query IP for {ifname}: {e}. \
                             Skipping exact conntrack match."
                        );
                    }
                }
            }
        }
        if ips.is_empty() {
            // 全部介面都查不到 IPv4。回 Ok(0) 会让主回圈误以为「本次 DOWN 已清理完成」，
            // 整段 DOWN 期间不再重试；回 Err 让它保持 dirty，等位址回来或限流期过后再清。
            return Err(io::Error::other(format!(
                "no IPv4 address could be resolved for [{}]; will retry while the link stays down",
                names.join(", ")
            )));
        }

        info!(
            "[Conntrack] Flushing active conntrack sessions for {} ...",
            names.join(", ")
        );

        #[cfg(target_os = "linux")]
        {
            self.flush_by_ips(&ips)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = &ips;
            Ok(0)
        }
    }

    #[cfg(target_os = "linux")]
    fn flush_by_ips(&mut self, target_ips: &[Ipv4Addr]) -> io::Result<usize> {
        // socket 上次重建失败时在这里补救
        if self.sock_fd < 0 {
            self.reopen_socket();
            if self.sock_fd < 0 {
                return Err(io::Error::other(
                    "conntrack netlink socket is not available",
                ));
            }
        }

        // 1. 发送 DUMP 请求取得所有当前 conntrack 连线
        self.seq = self.seq.wrapping_add(1);
        let dump_seq = self.seq;
        let nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
        let req_buf = self.build_msg(nlmsg_type, NLM_F_REQUEST | NLM_F_DUMP, &[]);

        let sent = unsafe {
            libc::send(
                self.sock_fd,
                req_buf.as_ptr() as *const libc::c_void,
                req_buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != req_buf.len() {
            return Err(io::Error::other(format!(
                "short netlink send for conntrack dump ({sent}/{} bytes)",
                req_buf.len()
            )));
        }

        // 2. 边接收边下发删除，避免把整张表暂存在记忆体里。
        //
        //    注意：批量 send 之后「不能」顺手排空接收伫列——此时伫列里排著的
        //    不只是删除失败的错误回复，还有核心预先填充好的后续 dump 资料块
        //    （核心会把伫列填到接近 rcvbuf），整块丢弃会让 flush 只扫到表的
        //    一小部分，漏删后又得重扫全表。这里改为在解析循环内以 nlmsg_seq
        //    区分讯息：seq == dump_seq 的错误代表 dump 本身失败，
        //    其余错误（失败的删除回复）直接忽略继续收 dump。
        let mut recv_buf = vec![0u8; DUMP_BUF_SIZE];
        let expected_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
        let mut batch: Vec<u8> = Vec::with_capacity(DELETE_BATCH_LIMIT + 64);
        let mut deleted: usize = 0;
        // dump 是否确实收到 NLMSG_DONE（逾时／错误中断时为 false）
        let mut dump_done = false;
        // 第一个遇到的错误：删除发送失败、dump 被核心拒绝、逾时或讯息截断。
        // 有值就代表这次 flush 不完整，必须让呼叫端知道并重试。
        let mut first_err: Option<io::Error> = None;

        'outer: loop {
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
                // 逾时（SO_RCVTIMEO）或其它接收错误：dump 没有走完，资料不完整
                if first_err.is_none() {
                    first_err = Some(if e.kind() == io::ErrorKind::WouldBlock {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "conntrack dump timed out before NLMSG_DONE",
                        )
                    } else {
                        e
                    });
                }
                break;
            }
            if n == 0 {
                if first_err.is_none() {
                    first_err = Some(io::Error::other(
                        "netlink socket closed during conntrack dump",
                    ));
                }
                break;
            }

            let mut offset = 0;
            let len = n as usize;

            while offset + NlMsgHdr::LEN <= len {
                let msg_hdr = match NlMsgHdr::from_bytes(&recv_buf[offset..len]) {
                    Some(h) => h,
                    None => break,
                };
                let msg_len = msg_hdr.nlmsg_len as usize;
                if msg_len < NlMsgHdr::LEN || offset + msg_len > len {
                    // 讯息被截断（单则讯息大于接收缓冲区）：这一则会漏掉。
                    // datagram 框架本身仍是对齐的，继续收完 dump，最后回报失败重试。
                    if first_err.is_none() {
                        first_err = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "conntrack dump message truncated (larger than receive buffer)",
                        ));
                    }
                    break;
                }

                let next_offset = offset + nlmsg_align(msg_len);

                if msg_hdr.nlmsg_type == libc::NLMSG_DONE as u16 {
                    dump_done = true;
                    break 'outer;
                }
                if msg_hdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
                    if msg_hdr.nlmsg_seq == dump_seq {
                        // dump 请求本身失败（例如上一次未完成的 dump 残留 → EBUSY）
                        if first_err.is_none() {
                            first_err = Some(Self::nlmsgerr_to_io_error(
                                &recv_buf[offset..offset + msg_len],
                            ));
                        }
                        break 'outer;
                    }
                    // 失败的删除回复（如 ENOENT），忽略后继续收 dump
                    offset = next_offset;
                    continue;
                }

                if msg_hdr.nlmsg_type == expected_type {
                    // 上一轮 flush 残留的陈旧资料直接跳过（seq 对不上本次 dump）
                    if msg_hdr.nlmsg_seq != dump_seq {
                        offset = next_offset;
                        continue;
                    }
                    let attrs_offset = offset + NlMsgHdr::LEN + NfGenMsg::LEN;
                    if attrs_offset < offset + msg_len {
                        let attrs_slice = &recv_buf[attrs_offset..offset + msg_len];
                        if let Some((tuple_start, tuple_end, zone)) =
                            Self::extract_matching_orig_tuple(attrs_slice, target_ips)
                        {
                            self.seq = self.seq.wrapping_add(1);
                            // 就地把删除讯息写进批量缓冲（tuple 直接借用切片，零额外拷贝）
                            Self::append_delete_msg(
                                &mut batch,
                                self.seq,
                                &attrs_slice[tuple_start..tuple_end],
                                zone,
                            );
                            deleted += 1;

                            if batch.len() >= DELETE_BATCH_LIMIT {
                                // 单批发送失败不中断 dump：先把 dump 收完（否则核心
                                // 会卡在「dump 进行中」，下次 flush 永远 EBUSY），
                                // 记下第一个错误，函式最后一并回报。
                                if let Err(e) = Self::flush_delete_batch(self.sock_fd, &mut batch) {
                                    if first_err.is_none() {
                                        first_err = Some(e);
                                    }
                                }
                            }
                        }
                    }
                }

                offset = next_offset;
            }
        }

        if let Err(e) = Self::flush_delete_batch(self.sock_fd, &mut batch) {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }

        // dump 完整走完才排空残留回应。若中途失败，核心可能还在做这个 dump：
        // 重建 socket 把残留的 dump 状态连同资料一起丢弃，下一次 flush 才不会撞 EBUSY。
        if dump_done {
            Self::drain_nonblocking(self.sock_fd);
        } else {
            self.reopen_socket();
        }

        if let Some(e) = first_err {
            warn!(
                "[Conntrack] Flush did not complete (submitted {deleted} delete requests so far): {e}"
            );
            return Err(e);
        }

        if deleted == 0 {
            debug!("[Conntrack] No active sessions found matching {target_ips:?}");
        } else {
            info!(
                "[Conntrack] Submitted delete requests for {deleted} conntrack entries (IPs {target_ips:?}, dump seq {dump_seq})"
            );
        }
        Ok(deleted)
    }

    /// 把 NLMSG_ERROR 回应转成 `io::Error`（内核错误码放在标头后的第一个 i32）。
    #[cfg(target_os = "linux")]
    fn nlmsgerr_to_io_error(buf: &[u8]) -> io::Error {
        match read_i32(buf, NlMsgHdr::LEN) {
            Some(code) if code < 0 => io::Error::from_raw_os_error(code.saturating_neg()),
            Some(code) => io::Error::other(format!("conntrack dump rejected (error {code})")),
            None => io::Error::other("conntrack dump rejected (malformed NLMSG_ERROR)"),
        }
    }

    /// 就地把一条 DELETE 讯息写进批量缓冲区。
    /// 相比「每条讯息 build_msg 分配一个 Vec 再 extend 进 batch」，
    /// 省掉每条一次堆分配和两次 memcpy。
    #[cfg(target_os = "linux")]
    fn append_delete_msg(batch: &mut Vec<u8>, seq: u32, tuple_bytes: &[u8], zone: u16) {
        // tuple +（zone != 0 时）CTA_ZONE；zone 0 是预设值，不必显式带
        let zone_attr_len = if zone != 0 { 4 + 2 } else { 0 };
        let msg_len = NlMsgHdr::LEN + NfGenMsg::LEN + tuple_bytes.len() + zone_attr_len;
        // netlink 批次内每则讯息需 4 位元组对齐：nlmsg_len 填实际长度，
        // 剩余部分补零作为对齐填充（核心以 NLMSG_ALIGN 前进）
        let padded_len = nlmsg_align(msg_len);
        let start = batch.len();
        batch.resize(start + padded_len, 0);

        let hdr = NlMsgHdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            nlmsg_flags: NLM_F_REQUEST, // 不请求 ACK，避免回应堆满接收伫列
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let nfgen = NfGenMsg {
            nfgen_family: libc::AF_INET as u8,
            version: 0,
            res_id: 0,
        };

        let hdr_end = start + NlMsgHdr::LEN;
        batch[start..hdr_end].copy_from_slice(&hdr.to_bytes());
        let nfgen_end = hdr_end + NfGenMsg::LEN;
        batch[hdr_end..nfgen_end].copy_from_slice(&nfgen.to_bytes());
        let tuple_end = nfgen_end + tuple_bytes.len();
        batch[nfgen_end..tuple_end].copy_from_slice(tuple_bytes);
        if zone != 0 {
            batch[tuple_end..tuple_end + 2].copy_from_slice(&6u16.to_ne_bytes());
            batch[tuple_end + 2..tuple_end + 4].copy_from_slice(&CTA_ZONE.to_ne_bytes());
            batch[tuple_end + 4..tuple_end + 6].copy_from_slice(&zone.to_ne_bytes());
        }
    }

    /// 组出一则 nfnetlink 讯息（nlmsghdr + nfgenmsg + payload）
    #[cfg(target_os = "linux")]
    fn build_msg(&self, nlmsg_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = NlMsgHdr::LEN + NfGenMsg::LEN + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        let nlhdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };
        let nfgen = NfGenMsg {
            nfgen_family: libc::AF_INET as u8,
            version: 0,
            res_id: 0,
        };

        buf.extend_from_slice(&nlhdr.to_bytes());
        buf.extend_from_slice(&nfgen.to_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// 一次 send 把整批删除讯息送出去（netlink 允许单一 datagram 携带多则讯息）
    #[cfg(target_os = "linux")]
    fn flush_delete_batch(sock_fd: libc::c_int, batch: &mut Vec<u8>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let buf_len = batch.len();
        // netlink 对单一 datagram 是全有或全无。真的出现部分发送时，补送剩余位元组
        // 会让接收端把半条讯息当成新讯息解析；一律视为失败让呼叫端整批重试。
        let n = unsafe { libc::send(sock_fd, batch.as_ptr() as *const libc::c_void, buf_len, 0) };
        batch.clear();
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != buf_len {
            return Err(io::Error::other(format!(
                "short netlink send while flushing conntrack deletes ({n}/{buf_len} bytes)"
            )));
        }
        Ok(())
    }

    /// 以非阻塞方式把接收伫列读干净，避免核心回应堆积导致后续 send 阻塞
    #[cfg(target_os = "linux")]
    fn drain_nonblocking(sock_fd: libc::c_int) {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recv(
                    sock_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
        }
    }

    /// 从 ctnetlink 属性流中找出与任一 target_ip 匹配的 CTA_TUPLE_ORIG 属性块。
    /// 回传 `(start, end, zone)`：属性块区间由呼叫端以切片借用（零拷贝），
    /// zone 要原样带回删除讯息，否则非 0 zone 的条目删不到（甚至误删 zone 0）。
    fn extract_matching_orig_tuple(
        attrs: &[u8],
        target_ips: &[Ipv4Addr],
    ) -> Option<(usize, usize, u16)> {
        let mut orig_range: Option<(usize, usize)> = None;
        let mut zone: u16 = 0;
        let mut matched = false;

        let mut offset = 0;
        let nfa_hdr_len = 4; // struct nfattr { u16 nfa_len; u16 nfa_type; }

        while offset + nfa_hdr_len <= attrs.len() {
            let attr_len = match read_u16(attrs, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let attr_type = match read_u16(attrs, offset + 2) {
                Some(v) => v & NLA_TYPE_MASK,
                None => break,
            };

            if attr_len < nfa_hdr_len || offset + attr_len > attrs.len() {
                break;
            }

            let data = &attrs[offset + nfa_hdr_len..offset + attr_len];

            if attr_type == CTA_TUPLE_ORIG {
                // 记录整个 CTA_TUPLE_ORIG 属性块的位置
                orig_range = Some((offset, offset + attr_len));
                if Self::tuple_matches_ip(data, target_ips) {
                    matched = true;
                }
            } else if attr_type == CTA_TUPLE_REPLY && Self::tuple_matches_ip(data, target_ips) {
                matched = true;
            } else if attr_type == CTA_ZONE && data.len() >= 2 {
                zone = read_u16(data, 0).unwrap_or(0);
            }

            offset += rta_align(attr_len);
        }

        orig_range
            .map(|(start, end)| (start, end, zone))
            .filter(|_| matched)
    }

    /// 检查 tuple 内部 IP 是否命中任一 target_ip
    /// (SNAT 后的 WAN IP 会出现在 REPLY 的 dst 或 ORIG 的 src)
    fn tuple_matches_ip(tuple_data: &[u8], target_ips: &[Ipv4Addr]) -> bool {
        let nfa_hdr_len = 4;
        let mut offset = 0;

        while offset + nfa_hdr_len <= tuple_data.len() {
            let attr_len = match read_u16(tuple_data, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let attr_type = match read_u16(tuple_data, offset + 2) {
                Some(v) => v & NLA_TYPE_MASK,
                None => break,
            };

            if attr_len < nfa_hdr_len || offset + attr_len > tuple_data.len() {
                break;
            }

            let data = &tuple_data[offset + nfa_hdr_len..offset + attr_len];

            if attr_type == CTA_TUPLE_IP {
                // 解析 IP 内层属性
                let mut ip_offset = 0;
                while ip_offset + nfa_hdr_len <= data.len() {
                    let ip_attr_len = match read_u16(data, ip_offset) {
                        Some(v) => v as usize,
                        None => break,
                    };

                    if ip_attr_len < nfa_hdr_len || ip_offset + ip_attr_len > data.len() {
                        break;
                    }

                    let ip_data = &data[ip_offset + nfa_hdr_len..ip_offset + ip_attr_len];
                    if ip_data.len() == 4 {
                        let ip = Ipv4Addr::new(ip_data[0], ip_data[1], ip_data[2], ip_data[3]);
                        if target_ips.contains(&ip) {
                            return true;
                        }
                    }

                    ip_offset += rta_align(ip_attr_len);
                }
            }

            offset += rta_align(attr_len);
        }
        false
    }
}

#[cfg(target_os = "linux")]
impl Drop for ConntrackManager {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nf_attr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let len = (4 + payload.len()) as u16;
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&attr_type.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn test_tuple_matches_ip() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        // CTA_TUPLE_IP -> { CTA_IP_V4_SRC = 10.0.0.5 }
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[10, 0, 0, 5]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let tuple = nf_attr(CTA_TUPLE_IP, &inner);

        assert!(ConntrackManager::tuple_matches_ip(&tuple, &[ip]));
        assert!(ConntrackManager::tuple_matches_ip(
            &tuple,
            &[Ipv4Addr::new(9, 9, 9, 9), ip]
        ));
        assert!(!ConntrackManager::tuple_matches_ip(
            &tuple,
            &[Ipv4Addr::new(10, 0, 0, 6)]
        ));
    }

    #[test]
    fn test_extract_matching_orig_tuple() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[192, 168, 1, 100]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let orig = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &inner));

        let mut r_inner = nf_attr(CTA_IP_V4_SRC, &[8, 8, 8, 8]);
        r_inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[203, 0, 113, 9]));
        let reply = nf_attr(CTA_TUPLE_REPLY, &nf_attr(CTA_TUPLE_IP, &r_inner));

        let mut attrs = orig.clone();
        attrs.extend_from_slice(&reply);

        // REPLY tuple 里出现 WAN IP（SNAT 情境）时也应匹配，并回传 ORIG 区间
        let extracted = ConntrackManager::extract_matching_orig_tuple(&attrs, &[ip]);
        assert_eq!(extracted, Some((0, orig.len(), 0)));
        let (start, end, _zone) = extracted.unwrap();
        assert_eq!(&attrs[start..end], &orig[..]);

        // 多目标：任一 IP 命中即匹配
        assert!(
            ConntrackManager::extract_matching_orig_tuple(&attrs, &[Ipv4Addr::new(1, 2, 3, 4), ip])
                .is_some()
        );

        // 不相关的 IP 不应匹配
        assert!(
            ConntrackManager::extract_matching_orig_tuple(&attrs, &[Ipv4Addr::new(1, 2, 3, 4)])
                .is_none()
        );
    }

    #[test]
    fn test_extract_matching_orig_tuple_reads_zone() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let mut inner = nf_attr(CTA_IP_V4_SRC, &[203, 0, 113, 9]);
        inner.extend_from_slice(&nf_attr(CTA_IP_V4_DST, &[8, 8, 8, 8]));
        let orig = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &inner));
        let mut attrs = orig.clone();
        attrs.extend_from_slice(&nf_attr(CTA_ZONE, &7u16.to_ne_bytes()));

        let (_, _, zone) = ConntrackManager::extract_matching_orig_tuple(&attrs, &[ip]).unwrap();
        assert_eq!(zone, 7, "删除非 0 zone 的条目必须原样带回 CTA_ZONE");
    }

    #[test]
    fn test_delete_msg_carries_zone() {
        let tuple = nf_attr(CTA_TUPLE_ORIG, &nf_attr(CTA_TUPLE_IP, &[]));
        let mut batch = Vec::new();
        ConntrackManager::append_delete_msg(&mut batch, 5, &tuple, 3);

        let hdr = NlMsgHdr::from_bytes(&batch).unwrap();
        assert_eq!(
            hdr.nlmsg_type,
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE
        );
        let attrs_start = NlMsgHdr::LEN + NfGenMsg::LEN;
        let attrs = &batch[attrs_start..];
        // tuple 属性的 type 是 CTA_TUPLE_ORIG，紧接著是 CTA_ZONE=18 的 u16
        assert_eq!(read_u16(attrs, 2), Some(CTA_TUPLE_ORIG));
        let tuple_len = read_u16(attrs, 0).unwrap() as usize;
        assert_eq!(read_u16(attrs, tuple_len + 2), Some(CTA_ZONE));
        assert_eq!(read_u16(attrs, tuple_len + 4), Some(3));

        // zone 0 是预设值，不应多带属性（保持与旧版相同的报文）
        let mut batch0 = Vec::new();
        ConntrackManager::append_delete_msg(&mut batch0, 6, &tuple, 0);
        assert_eq!(
            NlMsgHdr::from_bytes(&batch0).unwrap().nlmsg_len + 6,
            hdr.nlmsg_len
        );
    }

    #[test]
    fn test_nfgenmsg_layout() {
        let m = NfGenMsg {
            nfgen_family: 2,
            version: 0,
            res_id: 0,
        };
        assert_eq!(m.to_bytes(), [2, 0, 0, 0]);
    }
}
