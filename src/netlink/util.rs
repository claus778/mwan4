// 非 Linux 平台上（例如在 Windows 上 `cargo check`）整批变成 dead code。
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;

// 缓冲区来自 `Vec<u8>`（align_of == 1）：指标转型在 x86/ARM64 碰巧能跑，但在 MIPS 等严格对齐平台会 SIGBUS 且形式上是 UB，因此一律逐位元组 + from_ne_bytes/to_ne_bytes 编解码。

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

/// 行程级长连 ioctl fd。用 `AtomicI32` 而非 `OnceLock`：后者会把首次 socket() 失败的 -1 永久快取，之后所有介面的 IP 查询都会失败；这里失败不写入，下次呼叫会重试。
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

pub fn get_interface_ipv4(name: &str) -> io::Result<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    unsafe {
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

/// 逾时避免核心不回应时永久阻塞整个 daemon。
#[cfg(target_os = "linux")]
pub fn set_socket_timeouts(
    fd: libc::c_int,
    recv: Option<std::time::Duration>,
    send: Option<std::time::Duration>,
) -> io::Result<()> {
    // 用 `as _` 让编译器推导 timeval 栏位型别，避免引用在 musl 上已 deprecated 的 libc::time_t / suseconds_t
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

#[inline]
pub fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

#[allow(dead_code)]
#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// 判断网卡是否为点对点接口（如 PPPoE、WireGuard），点对点接口无需网关 IP 即可路由。
pub fn is_interface_point_to_point(name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(raw) = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")) else {
            return false;
        };
        let trimmed = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(flags) = u32::from_str_radix(trimmed, 16) {
            return (flags & (libc::IFF_POINTOPOINT as u32)) != 0;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        false
    }
}

/// 从 `RTM_NEWLINK` 属性流解析 VXLAN 的远端 IPv4 地址（`IFLA_LINKINFO` -> `IFLA_INFO_KIND=="vxlan"` -> `IFLA_INFO_DATA` -> `IFLA_VXLAN_GROUP`）。
pub fn parse_vxlan_remote_from_link_attrs(attrs: &[u8]) -> Option<Ipv4Addr> {
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_INFO_KIND: u16 = 1;
    const IFLA_INFO_DATA: u16 = 2;
    const IFLA_VXLAN_GROUP: u16 = 2;
    const NLA_TYPE_MASK: u16 = 0x3fff;

    let mut off = 0usize;
    while off + 4 <= attrs.len() {
        let len = read_u16(attrs, off)? as usize;
        let typ = read_u16(attrs, off + 2)? & NLA_TYPE_MASK;
        if len < 4 || off + len > attrs.len() {
            break;
        }
        if typ == IFLA_LINKINFO {
            let linkinfo = &attrs[off + 4..off + len];
            let mut is_vxlan = false;
            let mut info_data: Option<&[u8]> = None;
            let mut ioff = 0usize;
            while ioff + 4 <= linkinfo.len() {
                let ilen = read_u16(linkinfo, ioff)? as usize;
                let ityp = read_u16(linkinfo, ioff + 2)? & NLA_TYPE_MASK;
                if ilen < 4 || ioff + ilen > linkinfo.len() {
                    break;
                }
                let idata = &linkinfo[ioff + 4..ioff + ilen];
                match ityp {
                    IFLA_INFO_KIND => {
                        let end = idata.iter().position(|&b| b == 0).unwrap_or(idata.len());
                        is_vxlan = &idata[..end] == b"vxlan";
                    }
                    IFLA_INFO_DATA => {
                        info_data = Some(idata);
                    }
                    _ => {}
                }
                ioff += rta_align(ilen);
            }
            if is_vxlan {
                if let Some(vdata) = info_data {
                    let mut voff = 0usize;
                    while voff + 4 <= vdata.len() {
                        let vlen = read_u16(vdata, voff)? as usize;
                        let vtyp = read_u16(vdata, voff + 2)? & NLA_TYPE_MASK;
                        if vlen < 4 || voff + vlen > vdata.len() {
                            break;
                        }
                        if vtyp == IFLA_VXLAN_GROUP && vlen == 8 {
                            let ip = Ipv4Addr::new(
                                vdata[voff + 4],
                                vdata[voff + 5],
                                vdata[voff + 6],
                                vdata[voff + 7],
                            );
                            if !ip.is_unspecified() && !ip.is_multicast() {
                                return Some(ip);
                            }
                        }
                        voff += rta_align(vlen);
                    }
                }
            }
        }
        off += rta_align(len);
    }
    None
}

/// 通过 Netlink `RTM_GETLINK` 查询 VXLAN 接口的对端 underlay IPv4（无需外部 `ip` 命令）。
pub fn get_vxlan_remote_ipv4(name: &str) -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        const RTM_GETLINK: u16 = 18;
        const RTM_NEWLINK: u16 = 16;
        const NLM_F_REQUEST: u16 = 0x01;
        const IFLA_IFNAME: u16 = 3;

        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return None;
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return None;
        }
        let _ = set_socket_timeouts(
            fd,
            Some(std::time::Duration::from_millis(200)),
            Some(std::time::Duration::from_millis(200)),
        );

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let bound = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            unsafe { libc::close(fd) };
            return None;
        }

        // struct ifinfomsg (16 bytes) + IFLA_IFNAME attr
        let name_bytes = name.as_bytes();
        let attr_len = 4 + name_bytes.len() + 1;
        let aligned_attr = rta_align(attr_len);
        let total_len = NlMsgHdr::LEN + 16 + aligned_attr;
        let mut req = vec![0u8; total_len];
        let hdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: RTM_GETLINK,
            nlmsg_flags: NLM_F_REQUEST,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        req[..NlMsgHdr::LEN].copy_from_slice(&hdr.to_bytes());
        let attr_off = NlMsgHdr::LEN + 16;
        write_u16(&mut req, attr_off, attr_len as u16);
        write_u16(&mut req, attr_off + 2, IFLA_IFNAME);
        req[attr_off + 4..attr_off + 4 + name_bytes.len()].copy_from_slice(name_bytes);

        let sent = unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) };
        if sent < 0 {
            unsafe { libc::close(fd) };
            return None;
        }

        let mut buf = [0u8; 8192];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        unsafe { libc::close(fd) };
        if n <= 0 {
            return None;
        }
        let len = n as usize;
        let r_hdr = NlMsgHdr::from_bytes(&buf[..len])?;
        if r_hdr.nlmsg_type != RTM_NEWLINK {
            return None;
        }
        let msg_len = (r_hdr.nlmsg_len as usize).min(len);
        let attrs_start = NlMsgHdr::LEN + 16;
        if attrs_start >= msg_len {
            return None;
        }
        parse_vxlan_remote_from_link_attrs(&buf[attrs_start..msg_len])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_attr(typ: u16, data: &[u8]) -> Vec<u8> {
        let len = 4 + data.len();
        let mut out = vec![0u8; rta_align(len)];
        write_u16(&mut out, 0, len as u16);
        write_u16(&mut out, 2, typ);
        out[4..4 + data.len()].copy_from_slice(data);
        out
    }

    #[test]
    fn test_parse_vxlan_remote_from_link_attrs() {
        let mut vxlan_data = Vec::new();
        vxlan_data.extend_from_slice(&mk_attr(1, &100u32.to_ne_bytes())); // IFLA_VXLAN_ID
        vxlan_data.extend_from_slice(&mk_attr(2, &[10, 128, 0, 20])); // IFLA_VXLAN_GROUP

        let mut linkinfo = Vec::new();
        linkinfo.extend_from_slice(&mk_attr(1, b"vxlan\0"));
        linkinfo.extend_from_slice(&mk_attr(2, &vxlan_data));

        let attrs = mk_attr(18, &linkinfo);
        assert_eq!(
            parse_vxlan_remote_from_link_attrs(&attrs),
            Some(Ipv4Addr::new(10, 128, 0, 20))
        );

        let mut wireguard_info = Vec::new();
        wireguard_info.extend_from_slice(&mk_attr(1, b"wireguard\0"));
        let wg_attrs = mk_attr(18, &wireguard_info);
        assert_eq!(parse_vxlan_remote_from_link_attrs(&wg_attrs), None);
    }
}
