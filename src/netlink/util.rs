// 本模组绝大部分程式码只在 Linux 上参与编译，
// 在非 Linux 平台上（例如在 Windows 上 `cargo check`）会整批变成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// 位元组安全的读写工具
//
// 注意：netlink 讯息缓冲区来自 `Vec<u8>` 或 `[u8; N]`（align_of == 1）。
// 直接 `&*(ptr as *const NlMsgHdr)` 这种转型在 x86/ARM64 上「碰巧能跑」，
// 但在 MIPS 等严格对齐的 OpenWrt 平台上会触发 SIGBUS，且形式上是 UB。
// 因此所有 netlink 结构一律以「逐位元组 + from_ne_bytes / to_ne_bytes」
// 方式编解码，完全不使用指标转型。
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

/// Netlink 讯息标头（struct nlmsghdr），以位元组方式序列化
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

    /// 从缓冲区开头解析；长度不足回传 None（不做任何指标转型）
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

/// 根据网卡名称取得 Linux ifindex (例如 "wan1" -> 2)
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

/// 行程级长连 ioctl fd（每次查询都 socket()+close() 太昂贵）。
///
/// 用 `AtomicI32` 而不是 `OnceLock`：`OnceLock` 会把「第一次 socket() 失败」的
/// -1 永久快取，之后**所有**介面的 IP 查询都会失败（介面全显示 No IP、
/// conntrack 清理永久 no-op）。这里失败不写入，下次呼叫会重新尝试。
#[cfg(target_os = "linux")]
static IOCTL_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(target_os = "linux")]
fn ioctl_fd() -> io::Result<libc::c_int> {
    use std::sync::atomic::Ordering;

    let cached = IOCTL_FD.load(Ordering::Relaxed);
    if cached >= 0 {
        return Ok(cached);
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 只有抢到「从 -1 变成 fd」的执行绪保留这个 fd，其他执行绪关掉自己多开的
    match IOCTL_FD.compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Relaxed) {
        Ok(_) => Ok(fd),
        Err(existing) => {
            unsafe { libc::close(fd) };
            Ok(existing)
        }
    }
}

/// 透过 SIOCGIFADDR ioctl 快速取得网卡的 IPv4 地址（用于 Conntrack 精准连线清理）
pub fn get_interface_ipv4(name: &str) -> io::Result<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    unsafe {
        // SIOCGIFADDR 对任意 AF_INET/SOCK_DGRAM socket 都有效
        let sock = ioctl_fd()?;
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

/// 设定 netlink socket 的收/发逾时，避免核心不回应时永久阻塞住整个 daemon
#[cfg(target_os = "linux")]
pub fn set_socket_timeouts(
    fd: libc::c_int,
    recv: Option<std::time::Duration>,
    send: Option<std::time::Duration>,
) -> io::Result<()> {
    // 用 `as _` 让编译器自行推导 timeval 栏位型别，
    // 避免直接引用 libc::time_t / suseconds_t（在 musl 上已标记 deprecated）
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

/// Netlink 记忆体对齐工具函数
#[inline]
pub fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

#[allow(dead_code)]
#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}
