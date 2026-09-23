// 本模組只在 Linux 上真正執行 netlink I/O；
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）會整批變成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use log::{debug, info, warn};
use std::io;
use std::net::Ipv4Addr;

// 部分工具函數僅在 Linux 分支中使用
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

// CtNetlink 屬性定義
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
/// conntrack zone（u16）。帶 zone 的部署（nftables `ct zone`）若刪除時不回填，
/// 內核會在 zone 0 找同 tuple 的連線：輕則 ENOENT 漏刪，重則誤刪 zone 0 的條目。
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

/// dump 單次 recv 的緩衝區大小
const DUMP_BUF_SIZE: usize = 32 * 1024;
/// 批量刪除時單次 send 的累積上限
const DELETE_BATCH_LIMIT: usize = 8 * 1024;
/// conntrack socket 的收/發逾時
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

    /// 關掉舊 socket 並重開。
    ///
    /// netlink 的 dump 狀態是「socket 級」的：上一次 dump 沒收到 `NLMSG_DONE` 就結束時，
    /// 核心會認為 dump 仍在進行中，之後同一 socket 上的 `NLM_F_DUMP` 一律回 `-EBUSY`
    /// —— flush 就變成永遠掃不到東西的 no-op。逾時／錯誤後直接重建 socket 最乾淨。
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

    /// 當 WAN 掉線 / 活躍集合變化時，精準清理這些網卡上的 conntrack 連接。
    ///
    /// 多張網卡合併為一次全表 dump（匹配任一 WAN IP 即刪除），
    /// 避免每張網卡各掃一遍完整 conntrack 表。
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
                    // 介面已消失或正在重撥（PPPoE/USB）時現查會失敗。用 DOWN 判定時
                    // 記下的最後已知 IP 才清得到 NAT 到舊位址的連線——這正是長連線
                    // 卡死最需要清理的場景。
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
            // 全部介面都查不到 IPv4。回 Ok(0) 會讓主迴圈誤以為「本次 DOWN 已清理完成」，
            // 整段 DOWN 期間不再重試；回 Err 讓它保持 dirty，等位址回來或限流期過後再清。
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
        // socket 上次重建失敗時在這裡補救
        if self.sock_fd < 0 {
            self.reopen_socket();
            if self.sock_fd < 0 {
                return Err(io::Error::other(
                    "conntrack netlink socket is not available",
                ));
            }
        }

        // 1. 發送 DUMP 請求取得所有當前 conntrack 連線
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

        // 2. 邊接收邊下發刪除，避免把整張表暫存在記憶體裡。
        //
        //    注意：批量 send 之後「不能」順手排空接收佇列——此時佇列裡排著的
        //    不只是刪除失敗的錯誤回覆，還有核心預先填充好的後續 dump 資料塊
        //    （核心會把佇列填到接近 rcvbuf），整塊丟棄會讓 flush 只掃到表的
        //    一小部分，漏刪後又得重掃全表。這裡改為在解析循環內以 nlmsg_seq
        //    區分訊息：seq == dump_seq 的錯誤代表 dump 本身失敗，
        //    其餘錯誤（失敗的刪除回覆）直接忽略繼續收 dump。
        let mut recv_buf = vec![0u8; DUMP_BUF_SIZE];
        let expected_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
        let mut batch: Vec<u8> = Vec::with_capacity(DELETE_BATCH_LIMIT + 64);
        let mut deleted: usize = 0;
        // dump 是否確實收到 NLMSG_DONE（逾時／錯誤中斷時為 false）
        let mut dump_done = false;
        // 第一個遇到的錯誤：刪除發送失敗、dump 被核心拒絕、逾時或訊息截斷。
        // 有值就代表這次 flush 不完整，必須讓呼叫端知道並重試。
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
                // 逾時（SO_RCVTIMEO）或其它接收錯誤：dump 沒有走完，資料不完整
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
                    // 訊息被截斷（單則訊息大於接收緩衝區）：這一則會漏掉。
                    // datagram 框架本身仍是對齊的，繼續收完 dump，最後回報失敗重試。
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
                        // dump 請求本身失敗（例如上一次未完成的 dump 殘留 → EBUSY）
                        if first_err.is_none() {
                            first_err = Some(Self::nlmsgerr_to_io_error(
                                &recv_buf[offset..offset + msg_len],
                            ));
                        }
                        break 'outer;
                    }
                    // 失敗的刪除回覆（如 ENOENT），忽略後繼續收 dump
                    offset = next_offset;
                    continue;
                }

                if msg_hdr.nlmsg_type == expected_type {
                    // 上一輪 flush 殘留的陳舊資料直接跳過（seq 對不上本次 dump）
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
                            // 就地把刪除訊息寫進批量緩衝（tuple 直接借用切片，零額外拷貝）
                            Self::append_delete_msg(
                                &mut batch,
                                self.seq,
                                &attrs_slice[tuple_start..tuple_end],
                                zone,
                            );
                            deleted += 1;

                            if batch.len() >= DELETE_BATCH_LIMIT {
                                // 單批發送失敗不中斷 dump：先把 dump 收完（否則核心
                                // 會卡在「dump 進行中」，下次 flush 永遠 EBUSY），
                                // 記下第一個錯誤，函式最後一併回報。
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

        // dump 完整走完才排空殘留回應。若中途失敗，核心可能還在做這個 dump：
        // 重建 socket 把殘留的 dump 狀態連同資料一起丟棄，下一次 flush 才不會撞 EBUSY。
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

    /// 把 NLMSG_ERROR 回應轉成 `io::Error`（內核錯誤碼放在標頭後的第一個 i32）。
    #[cfg(target_os = "linux")]
    fn nlmsgerr_to_io_error(buf: &[u8]) -> io::Error {
        match read_i32(buf, NlMsgHdr::LEN) {
            Some(code) if code < 0 => io::Error::from_raw_os_error(code.saturating_neg()),
            Some(code) => io::Error::other(format!("conntrack dump rejected (error {code})")),
            None => io::Error::other("conntrack dump rejected (malformed NLMSG_ERROR)"),
        }
    }

    /// 就地把一條 DELETE 訊息寫進批量緩衝區。
    /// 相比「每條訊息 build_msg 分配一個 Vec 再 extend 進 batch」，
    /// 省掉每條一次堆分配和兩次 memcpy。
    #[cfg(target_os = "linux")]
    fn append_delete_msg(batch: &mut Vec<u8>, seq: u32, tuple_bytes: &[u8], zone: u16) {
        // tuple +（zone != 0 時）CTA_ZONE；zone 0 是預設值，不必顯式帶
        let zone_attr_len = if zone != 0 { 4 + 2 } else { 0 };
        let msg_len = NlMsgHdr::LEN + NfGenMsg::LEN + tuple_bytes.len() + zone_attr_len;
        // netlink 批次內每則訊息需 4 位元組對齊：nlmsg_len 填實際長度，
        // 剩餘部分補零作為對齊填充（核心以 NLMSG_ALIGN 前進）
        let padded_len = nlmsg_align(msg_len);
        let start = batch.len();
        batch.resize(start + padded_len, 0);

        let hdr = NlMsgHdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            nlmsg_flags: NLM_F_REQUEST, // 不請求 ACK，避免回應堆滿接收佇列
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

    /// 組出一則 nfnetlink 訊息（nlmsghdr + nfgenmsg + payload）
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

    /// 一次 send 把整批刪除訊息送出去（netlink 允許單一 datagram 攜帶多則訊息）
    #[cfg(target_os = "linux")]
    fn flush_delete_batch(sock_fd: libc::c_int, batch: &mut Vec<u8>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let buf_len = batch.len();
        // netlink 對單一 datagram 是全有或全無。真的出現部分發送時，補送剩餘位元組
        // 會讓接收端把半條訊息當成新訊息解析；一律視為失敗讓呼叫端整批重試。
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

    /// 以非阻塞方式把接收佇列讀乾淨，避免核心回應堆積導致後續 send 阻塞
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

    /// 從 ctnetlink 屬性流中找出與任一 target_ip 匹配的 CTA_TUPLE_ORIG 屬性塊。
    /// 回傳 `(start, end, zone)`：屬性塊區間由呼叫端以切片借用（零拷貝），
    /// zone 要原樣帶回刪除訊息，否則非 0 zone 的條目刪不到（甚至誤刪 zone 0）。
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
                // 記錄整個 CTA_TUPLE_ORIG 屬性塊的位置
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

    /// 檢查 tuple 內部 IP 是否命中任一 target_ip
    /// (SNAT 後的 WAN IP 會出現在 REPLY 的 dst 或 ORIG 的 src)
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
                // 解析 IP 內層屬性
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

        // REPLY tuple 裡出現 WAN IP（SNAT 情境）時也應匹配，並回傳 ORIG 區間
        let extracted = ConntrackManager::extract_matching_orig_tuple(&attrs, &[ip]);
        assert_eq!(extracted, Some((0, orig.len(), 0)));
        let (start, end, _zone) = extracted.unwrap();
        assert_eq!(&attrs[start..end], &orig[..]);

        // 多目標：任一 IP 命中即匹配
        assert!(
            ConntrackManager::extract_matching_orig_tuple(&attrs, &[Ipv4Addr::new(1, 2, 3, 4), ip])
                .is_some()
        );

        // 不相關的 IP 不應匹配
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
        assert_eq!(zone, 7, "刪除非 0 zone 的條目必須原樣帶回 CTA_ZONE");
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
        // tuple 屬性的 type 是 CTA_TUPLE_ORIG，緊接著是 CTA_ZONE=18 的 u16
        assert_eq!(read_u16(attrs, 2), Some(CTA_TUPLE_ORIG));
        let tuple_len = read_u16(attrs, 0).unwrap() as usize;
        assert_eq!(read_u16(attrs, tuple_len + 2), Some(CTA_ZONE));
        assert_eq!(read_u16(attrs, tuple_len + 4), Some(3));

        // zone 0 是預設值，不應多帶屬性（保持與舊版相同的報文）
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
