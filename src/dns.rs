//! 非侵入式多 WAN DNS 辅助模块：
//! 1. 纯 Rust RFC 1035 DNS 报文编解码（供 UDP DNS 健康探测使用，不占用本地 53 端口）；
//! 2. 每 WAN 专属上游 DNS `/32` 路由规划（支持 `IP` 或 `IP:Port`，纯内核 FIB 出口绑定，不干预 AdGuardHome / SmartDNS / MosDNS / dnsmasq）；
//! 3. 可选的内置轻量级多线 UDP DNS 转发器（默认关闭 `dns_listen_port = 0`，可按需配置独立端口如 `5354` 供第三方 DNS 软件作上游）；
//! 4. 可选的独立 `resolv.conf` 状态导出（默认关闭，仅在用户显式指定独立路径时原子写入）。

use crate::config::DnsServer;
use crate::netlink::route::DnsRoute;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, oneshot, watch};

/// 单调递增的 DNS Transaction ID，避免上一拍延迟回包伪装成当前探测结果。
static NEXT_TXID: AtomicU16 = AtomicU16::new(1);

pub fn next_txid() -> u16 {
    let seq = NEXT_TXID.fetch_add(1, Ordering::Relaxed);
    let pid_mix = (std::process::id() as u16).wrapping_mul(0x9E37);
    let id = seq ^ pid_mix;
    if id == 0 { 1 } else { id }
}

/// 校验 DNS 探测域名是否符合 RFC 1035 / RFC 1123 基本格式。
pub fn validate_dns_domain(domain: &str) -> Result<(), String> {
    let trimmed = domain.strip_suffix('.').unwrap_or(domain);
    if trimmed.is_empty() {
        return Err("dns_probe_domain cannot be empty".into());
    }
    if trimmed.len() > 253 {
        return Err(format!(
            "dns_probe_domain '{domain}' is too long (max 253 characters)"
        ));
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!(
                "dns_probe_domain '{domain}' has an invalid label length"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "dns_probe_domain '{domain}' label '{label}' cannot start or end with '-'"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "dns_probe_domain '{domain}' contains invalid characters"
            ));
        }
    }
    Ok(())
}

/// 构造标准 UDP DNS 查询报文（IN / A，RD=1）。
pub fn build_dns_query(txid: u16, domain: &str) -> Result<Vec<u8>, String> {
    validate_dns_domain(domain)?;
    let trimmed = domain.strip_suffix('.').unwrap_or(domain);

    // Header (12) + QNAME (len + 2) + QTYPE (2) + QCLASS (2)
    let mut pkt = Vec::with_capacity(12 + trimmed.len() + 6);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in trimmed.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root terminator
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(pkt)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseStatus {
    /// 收到有效 DNS 响应（NOERROR 或 NXDOMAIN 均证明上游递归服务可达并正常处理了请求）。
    Valid { rcode: u8, ancount: u16 },
    /// 上游返回服务端错误（如 SERVFAIL / REFUSED / FORMERR / NOTIMP）。
    ServerError { rcode: u8 },
    /// Transaction ID 不匹配（可能是旧探针的迟到包，应忽略并继续等待）。
    WrongTransactionId,
    /// 报文格式非法（截断或 QR=0）。
    Malformed(&'static str),
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

/// 解析并校验 DNS 响应头部（只读前 12 字节即可安全判定，避免处理恶意压缩指针）。
pub fn parse_dns_response(packet: &[u8], expected_txid: u16) -> DnsResponseStatus {
    if packet.len() < 12 {
        return DnsResponseStatus::Malformed("DNS response shorter than 12-byte header");
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if txid != expected_txid {
        return DnsResponseStatus::WrongTransactionId;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return DnsResponseStatus::Malformed("DNS packet is not a response (QR=0)");
    }
    let rcode = (flags & 0x000F) as u8;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    match rcode {
        0 | 3 => DnsResponseStatus::Valid { rcode, ancount },
        _ => DnsResponseStatus::ServerError { rcode },
    }
}

/// 规划 DNS `/32` 路由时的接口快照。
pub struct DnsRouteCandidate<'a> {
    pub ifname: &'a str,
    pub ifindex: u32,
    pub gateway: Option<Ipv4Addr>,
    pub metric: u32,
    pub slot: usize,
    pub up: bool,
    pub degraded: bool,
    pub dns_servers: &'a [DnsServer],
}

/// 计算当前应下发到主表的上游 DNS `/32` 出口绑定路由：
/// - 仅纳入 `up && ifindex != 0` 的健康接口；
/// - 多个健康接口共用同一个 DNS IP 时，按 `(degraded, metric, slot)` 择优（未降级优先 -> metric 最小 -> 配置顺序）；
/// - 目标接口全部 DOWN 时该 DNS 的 `/32` 路由会被移除，避免黑洞到死链路。
pub fn plan_dns_routes(candidates: &[DnsRouteCandidate<'_>]) -> Vec<DnsRoute> {
    let mut seen = HashSet::new();
    let mut servers = Vec::new();
    for c in candidates {
        if !c.up || c.ifindex == 0 {
            continue;
        }
        for s in c.dns_servers {
            if seen.insert(s.ip) {
                servers.push(s.ip);
            }
        }
    }

    let mut routes = Vec::with_capacity(servers.len());
    for server in servers {
        if let Some(owner) = candidates
            .iter()
            .filter(|c| c.up && c.ifindex != 0 && c.dns_servers.iter().any(|s| s.ip == server))
            .min_by_key(|c| (c.degraded, c.metric, c.slot))
        {
            routes.push(DnsRoute {
                server,
                ifname: owner.ifname.to_string(),
                ifindex: owner.ifindex,
                gateway: owner.gateway,
            });
        }
    }
    routes
}

/// 内置 DNS 转发器使用的健康 WAN 上游描述（按 `(degraded, metric, slot)` 排好序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUpstreamWan {
    pub ifname: String,
    pub degraded: bool,
    pub metric: u32,
    pub slot: usize,
    pub targets: Vec<SocketAddr>,
}

/// 并发在途转发请求上限，防止 DNS 突发查询耗尽文件描述符。
const DNS_FORWARD_MAX_INFLIGHT: usize = 128;

/// 为无法转发的客户端请求构造标准 `SERVFAIL`（RCODE=2）响应，便于第三方 DNS 软件立刻切换其他上游。
pub fn build_servfail_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = Vec::with_capacity(12);
    resp.extend_from_slice(&query[0..2]); // 原样保留 Transaction ID
    let req_flags = u16::from_be_bytes([query[2], query[3]]);
    // QR=1, 保留 OPCODE 与 RD, RA=1, RCODE=2 (SERVFAIL)
    let resp_flags = 0x8080 | (req_flags & 0x7900) | 0x0002;
    resp.extend_from_slice(&resp_flags.to_be_bytes());
    resp.extend_from_slice(&[0u8; 8]); // QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    Some(resp)
}

fn create_forward_udp_socket(iface: &str, target: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    {
        if !iface.is_empty() {
            sock.bind_device(Some(iface.as_bytes()))?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
    }
    sock.connect(&target.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_udp)
}

async fn forward_once(
    iface: &str,
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let udp = create_forward_udp_socket(iface, target)?;
    udp.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, udp.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS timed out"))??;
    buf.truncate(n);
    Ok(buf)
}

async fn forward_query_across_wans(
    query: &[u8],
    upstreams: &[DnsUpstreamWan],
    rr_counter: &AtomicUsize,
    total_timeout: Duration,
) -> Option<Vec<u8>> {
    if upstreams.is_empty() || query.len() < 12 {
        return None;
    }
    // 优先在最高优先级（未降级且 metric 最小）的一组健康 WAN 之间做轮询，失败再顺次尝试其余健康 WAN。
    let best_key = (upstreams[0].degraded, upstreams[0].metric);
    let primary_len = upstreams
        .iter()
        .take_while(|u| (u.degraded, u.metric) == best_key)
        .count()
        .max(1);
    let start_idx = rr_counter.fetch_add(1, Ordering::Relaxed) % primary_len;

    let mut order: Vec<usize> = Vec::with_capacity(upstreams.len());
    for i in 0..primary_len {
        order.push((start_idx + i) % primary_len);
    }
    for i in primary_len..upstreams.len() {
        order.push(i);
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let attempts = order.len().min(3);
    let per_try = (total_timeout / attempts as u32).max(Duration::from_millis(200));

    for &wan_idx in order.iter().take(attempts) {
        let wan = &upstreams[wan_idx];
        let Some(&target) = wan.targets.first() else {
            continue;
        };
        let Some(rem) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
            break;
        };
        let wait = rem.min(per_try);
        match forward_once(&wan.ifname, target, query, wait).await {
            Ok(resp) if resp.len() >= 12 && resp[0..2] == query[0..2] => {
                return Some(resp);
            }
            Ok(_) => {
                debug!(
                    "[DNS] Ignoring malformed/mismatched reply from {} via {}",
                    target, wan.ifname
                );
            }
            Err(e) => {
                debug!("[DNS] Forward to {} via {} failed: {e}", target, wan.ifname);
            }
        }
    }
    None
}

pub struct DnsForwarderHandle {
    pub local_addr: SocketAddr,
    pub upstream_tx: watch::Sender<Vec<DnsUpstreamWan>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl DnsForwarderHandle {
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// 启动可选的内置轻量级多线 UDP DNS 转发器（仅在 `dns_listen_port > 0` 时调用）。
pub async fn spawn_dns_forwarder(
    bind_addr: SocketAddr,
    forward_timeout: Duration,
    initial_upstreams: Vec<DnsUpstreamWan>,
) -> io::Result<DnsForwarderHandle> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let local_addr = socket.local_addr()?;
    let (upstream_tx, upstream_rx) = watch::channel(initial_upstreams);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let semaphore = Arc::new(Semaphore::new(DNS_FORWARD_MAX_INFLIGHT));
    let rr_counter = Arc::new(AtomicUsize::new(0));

    info!(
        "Built-in multi-WAN UDP DNS forwarder listening on {local_addr} (timeout: {}ms)",
        forward_timeout.as_millis()
    );

    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("[DNS] Forwarder shutting down");
                    break;
                }
                res = socket.recv_from(&mut buf) => {
                    let (n, peer) = match res {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("[DNS] Forwarder recv_from error: {e}");
                            continue;
                        }
                    };
                    if n < 12 {
                        continue;
                    }
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        debug!("[DNS] Forwarder concurrency limit reached; dropping query from {peer}");
                        continue;
                    };
                    let query = buf[..n].to_vec();
                    let upstreams = upstream_rx.borrow().clone();
                    let sock = socket.clone();
                    let rr = rr_counter.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let reply = forward_query_across_wans(&query, &upstreams, &rr, forward_timeout)
                            .await
                            .or_else(|| build_servfail_reply(&query));
                        if let Some(resp) = reply {
                            if let Err(e) = sock.send_to(&resp, peer).await {
                                debug!("[DNS] Failed to send reply to {peer}: {e}");
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(DnsForwarderHandle {
        local_addr,
        upstream_tx,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

/// 检查路径是否指向系统默认 resolv 文件（提醒用户避免覆盖第三方 DNS / dnsmasq 配置）。
pub fn is_system_resolv_path(path: &str) -> bool {
    path == "/etc/resolv.conf"
        || path == "/tmp/resolv.conf"
        || path.starts_with("/tmp/resolv.conf.")
        || path.starts_with("/tmp/resolv.conf.d/")
}

/// 将当前存活 WAN 的上游 DNS 原子写入用户显式指定的独立文件（防符号链接覆写）。
pub fn write_resolv_file_atomic(path: &str, routes: &[DnsRoute]) -> io::Result<()> {
    use std::io::Write;
    use std::path::Path;

    let target = Path::new(path);
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut content = String::from(
        "# Generated by mwan4 (active healthy per-WAN upstream DNS servers)\n\
         # Managed only because dns_resolv_file is explicitly configured.\n",
    );
    if routes.is_empty() {
        content.push_str("# No healthy WAN DNS servers currently available\n");
    } else {
        for r in routes {
            content.push_str(&format!("nameserver {} # via {}\n", r.server, r.ifname));
        }
    }

    let tmp_path = format!("{path}.mwan4.tmp");
    let _ = std::fs::remove_file(&tmp_path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    file.write_all(content.as_bytes())?;
    drop(file);
    std::fs::rename(&tmp_path, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dns_domain() {
        assert!(validate_dns_domain("baidu.com").is_ok());
        assert!(validate_dns_domain("www.baidu.com.").is_ok());
        assert!(validate_dns_domain("a-1.b2.example.org").is_ok());
        assert!(validate_dns_domain("localhost").is_ok());

        for bad in [
            "",
            ".",
            "..",
            "-bad.com",
            "bad-.com",
            "bad..com",
            "bad domain.com",
            "bad_underscore.com",
            &"a".repeat(64),
        ] {
            assert!(validate_dns_domain(bad).is_err(), "should reject '{bad}'");
        }
    }

    #[test]
    fn test_build_and_parse_dns_packet() {
        let query = build_dns_query(0x1234, "www.baidu.com").unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(&query[2..4], &[0x01, 0x00]); // RD=1
        assert_eq!(&query[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // QNAME: 3www5baidu3com0 + QTYPE(1) + QCLASS(1)
        assert_eq!(&query[12..], b"\x03www\x05baidu\x03com\x00\x00\x01\x00\x01");

        // 模拟合法 NOERROR 响应（QR=1, RD=1, RA=1, ANCOUNT=2）
        let mut resp = [0u8; 12];
        resp[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        resp[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        resp[6..8].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            parse_dns_response(&resp, 0x1234),
            DnsResponseStatus::Valid {
                rcode: 0,
                ancount: 2
            }
        );

        // NXDOMAIN 也证明 DNS 服务器正常响应
        resp[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
        assert_eq!(
            parse_dns_response(&resp, 0x1234),
            DnsResponseStatus::Valid {
                rcode: 3,
                ancount: 2
            }
        );

        // SERVFAIL 视为失败
        resp[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
        assert_eq!(
            parse_dns_response(&resp, 0x1234),
            DnsResponseStatus::ServerError { rcode: 2 }
        );

        // REFUSED 视为失败
        resp[2..4].copy_from_slice(&0x8185u16.to_be_bytes());
        assert_eq!(
            parse_dns_response(&resp, 0x1234),
            DnsResponseStatus::ServerError { rcode: 5 }
        );

        // TXID 不匹配
        assert_eq!(
            parse_dns_response(&resp, 0x9999),
            DnsResponseStatus::WrongTransactionId
        );

        // QR=0（请求包而非响应）
        assert!(matches!(
            parse_dns_response(&query, 0x1234),
            DnsResponseStatus::Malformed(_)
        ));

        // 截断包
        assert!(matches!(
            parse_dns_response(&[0u8; 8], 0x1234),
            DnsResponseStatus::Malformed(_)
        ));
    }

    #[test]
    fn test_plan_dns_routes_selects_healthy_and_fails_over() {
        let dns_ct = DnsServer::new(Ipv4Addr::new(202, 96, 128, 86), 53);
        let dns_cu = DnsServer::new(Ipv4Addr::new(221, 6, 4, 66), 5353);
        let dns_shared = DnsServer::new(Ipv4Addr::new(223, 5, 5, 5), 53);

        let w1_dns = [dns_ct, dns_shared];
        let w2_dns = [dns_cu, dns_shared];

        // 两条都健康：各自独占 DNS 走各自线，共用 DNS 走 metric 小的 wan1
        let plan = plan_dns_routes(&[
            DnsRouteCandidate {
                ifname: "wan1",
                ifindex: 2,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                metric: 10,
                slot: 0,
                up: true,
                degraded: false,
                dns_servers: &w1_dns,
            },
            DnsRouteCandidate {
                ifname: "wan2",
                ifindex: 3,
                gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
                metric: 20,
                slot: 1,
                up: true,
                degraded: false,
                dns_servers: &w2_dns,
            },
        ]);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].server, dns_ct.ip);
        assert_eq!(plan[0].ifname, "wan1");
        assert_eq!(plan[1].server, dns_shared.ip);
        assert_eq!(plan[1].ifname, "wan1");
        assert_eq!(plan[2].server, dns_cu.ip);
        assert_eq!(plan[2].ifname, "wan2");

        // wan1 降级时：共享 DNS 优先切到未降级的 wan2，wan1 独占 DNS 仍保留（wan1 仍 UP）
        let plan_deg = plan_dns_routes(&[
            DnsRouteCandidate {
                ifname: "wan1",
                ifindex: 2,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                metric: 10,
                slot: 0,
                up: true,
                degraded: true,
                dns_servers: &w1_dns,
            },
            DnsRouteCandidate {
                ifname: "wan2",
                ifindex: 3,
                gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
                metric: 20,
                slot: 1,
                up: true,
                degraded: false,
                dns_servers: &w2_dns,
            },
        ]);
        let shared_owner = plan_deg.iter().find(|r| r.server == dns_shared.ip).unwrap();
        assert_eq!(shared_owner.ifname, "wan2");

        // wan1 DOWN 时：dns_ct 移除，shared 切到 wan2
        let plan_down = plan_dns_routes(&[
            DnsRouteCandidate {
                ifname: "wan1",
                ifindex: 2,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                metric: 10,
                slot: 0,
                up: false,
                degraded: false,
                dns_servers: &w1_dns,
            },
            DnsRouteCandidate {
                ifname: "wan2",
                ifindex: 3,
                gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
                metric: 20,
                slot: 1,
                up: true,
                degraded: false,
                dns_servers: &w2_dns,
            },
        ]);
        assert_eq!(plan_down.len(), 2);
        assert!(plan_down.iter().all(|r| r.ifname == "wan2"));
        assert!(!plan_down.iter().any(|r| r.server == dns_ct.ip));
    }

    #[tokio::test]
    async fn test_dns_forwarder_custom_port_and_failover() {
        // 模拟运行在自定义非 53 端口的上游 DNS 服务器
        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = mock_upstream.recv_from(&mut buf).await.unwrap();
            assert!(n >= 12);
            let mut resp = [0u8; 12];
            resp[0..2].copy_from_slice(&buf[0..2]);
            resp[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // NOERROR
            resp[6..8].copy_from_slice(&1u16.to_be_bytes());
            mock_upstream.send_to(&resp, peer).await.unwrap();
        });

        // 一个静默上游（模拟主线超时）+ 一个健康上游（测试故障自动切到第二条线）
        let silent_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent_upstream.local_addr().unwrap();

        let handle = spawn_dns_forwarder(
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_millis(800),
            vec![
                DnsUpstreamWan {
                    ifname: String::new(),
                    degraded: false,
                    metric: 10,
                    slot: 0,
                    targets: vec![silent_addr],
                },
                DnsUpstreamWan {
                    ifname: String::new(),
                    degraded: false,
                    metric: 20,
                    slot: 1,
                    targets: vec![upstream_addr],
                },
            ],
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query(0x4242, "baidu.com").unwrap();
        client.send_to(&query, handle.local_addr).await.unwrap();

        let mut resp = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut resp))
            .await
            .unwrap()
            .unwrap();
        srv.await.unwrap();
        assert_eq!(
            parse_dns_response(&resp[..n], 0x4242),
            DnsResponseStatus::Valid {
                rcode: 0,
                ancount: 1
            }
        );

        // 清空上游（模拟全线断网）-> 立刻返回 SERVFAIL，而不是让客户端干等超时
        let _ = handle.upstream_tx.send(Vec::new());
        let query2 = build_dns_query(0x5555, "baidu.com").unwrap();
        client.send_to(&query2, handle.local_addr).await.unwrap();
        let n2 = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            parse_dns_response(&resp[..n2], 0x5555),
            DnsResponseStatus::ServerError { rcode: 2 }
        );

        handle.shutdown().await;
    }

    #[test]
    fn test_is_system_resolv_path() {
        assert!(is_system_resolv_path("/etc/resolv.conf"));
        assert!(is_system_resolv_path("/tmp/resolv.conf"));
        assert!(is_system_resolv_path("/tmp/resolv.conf.auto"));
        assert!(is_system_resolv_path("/tmp/resolv.conf.d/resolv.conf.auto"));
        assert!(!is_system_resolv_path("/tmp/mwan4_resolv.conf"));
        assert!(!is_system_resolv_path("/var/run/mwan4/resolv.conf"));
    }
}
