// 本模組絕大部分程式碼只在 Linux 上參與編譯，
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）會整批變成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// 位元組安全的讀寫工具
//
// 注意：netlink 訊息緩衝區來自 `Vec<u8>` 或 `[u8; N]`（align_of == 1）。
// 直接 `&*(ptr as *const NlMsgHdr)` 這種轉型在 x86/ARM64 上「碰巧能跑」，
// 但在 MIPS 等嚴格對齊的 OpenWrt 平台上會觸發 SIGBUS，且形式上是 UB。
// 因此所有 netlink 結構一律以「逐位元組 + from_ne_bytes / to_ne_bytes」
// 方式編解碼，完全不使用指標轉型。
// ---------------------------------------------------------------------------

#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let s = buf.get(off..off + 2)?;
    Some(u16::from_ne_bytes([s[0], s[1]]))
}

#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let s = buf.get(off..off + 4)?;
    Some(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    let s = buf.get(off..off + 4)?;
    Some(i32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    if let Some(slot) = buf.get_mut(off..off + 2) {
        slot.copy_from_slice(&v.to_ne_bytes());
    }
}

#[inline]
pub fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    if let Some(slot) = buf.get_mut(off..off + 4) {
        slot.copy_from_slice(&v.to_ne_bytes());
    }
}

/// Netlink 訊息標頭（struct nlmsghdr），以位元組方式序列化
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    pub const LEN: usize = 16;

    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        write_u32(&mut b, 0, self.nlmsg_len);
        write_u16(&mut b, 4, self.nlmsg_type);
        write_u16(&mut b, 6, self.nlmsg_flags);
        write_u32(&mut b, 8, self.nlmsg_seq);
        write_u32(&mut b, 12, self.nlmsg_pid);
        b
    }

    /// 從緩衝區開頭解析；長度不足回傳 None（不做任何指標轉型）
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        Some(Self {
            nlmsg_len: read_u32(buf, 0)?,
            nlmsg_type: read_u16(buf, 4)?,
            nlmsg_flags: read_u16(buf, 6)?,
            nlmsg_seq: read_u32(buf, 8)?,
            nlmsg_pid: read_u32(buf, 12)?,
        })
    }
}

/// 根據網卡名稱取得 Linux ifindex (例如 "wan1" -> 2)
pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let c_name =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(idx)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Ok(1)
    }
}

/// 透過 SIOCGIFADDR ioctl 快速取得網卡的 IPv4 地址（用於 Conntrack 精準連線清理）
pub fn get_interface_ipv4(name: &str) -> io::Result<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    unsafe {
        // SIOCGIFADDR 對任意 AF_INET/SOCK_DGRAM socket 都有效，
        // 用行程級長連 fd 避免「每次查詢都 socket()+close()」的系統呼叫開銷
        static IOCTL_FD: std::sync::OnceLock<libc::c_int> = std::sync::OnceLock::new();
        let sock = *IOCTL_FD
            .get_or_init(|| libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0));
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = std::mem::zeroed();
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interface name too long",
            ));
        }
        for (i, &b) in bytes.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        if libc::ioctl(sock, libc::SIOCGIFADDR as _, &mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }

        let sockaddr_in =
            &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in);
        let ip_bytes = sockaddr_in.sin_addr.s_addr.to_ne_bytes();
        Ok(Ipv4Addr::from(ip_bytes))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Ok(Ipv4Addr::new(127, 0, 0, 1))
    }
}

/// 設定 netlink socket 的收/發逾時，避免核心不回應時永久阻塞住整個 daemon
#[cfg(target_os = "linux")]
pub fn set_socket_timeouts(
    fd: libc::c_int,
    recv: Option<std::time::Duration>,
    send: Option<std::time::Duration>,
) -> io::Result<()> {
    // 用 `as _` 讓編譯器自行推導 timeval 欄位型別，
    // 避免直接引用 libc::time_t / suseconds_t（在 musl 上已標記 deprecated）
    unsafe {
        if let Some(d) = recv {
            let tv = libc::timeval {
                tv_sec: d.as_secs() as _,
                tv_usec: d.subsec_micros() as _,
            };
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if let Some(d) = send {
            let tv = libc::timeval {
                tv_sec: d.as_secs() as _,
                tv_usec: d.subsec_micros() as _,
            };
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_timeouts(
    _fd: std::os::raw::c_int,
    _recv: Option<std::time::Duration>,
    _send: Option<std::time::Duration>,
) -> io::Result<()> {
    Ok(())
}

/// Netlink 記憶體對齊工具函數
#[inline]
pub fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

#[allow(dead_code)]
#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}
