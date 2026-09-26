use log::debug;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 探针失败的分类：决定「这是本机问题还是线路问题」。
///
/// 为什么不靠错误字串：`io::Error` 的 Display 是 libc `strerror` 的文案，
/// glibc 与 musl（OpenWrt 预设）用字不同（`Network is unreachable` vs
/// `Network unreachable`、`Cannot assign requested address` vs
/// `Address not available`），字串比对在目标平台上会整批失效，把本机路由问题
/// 误报成运营商丢包。直接比对 errno 才稳定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeErrorKind {
    /// 封包根本没出去：设备不存在、无经该设备的路由、权限不足、无目标设定
    Local,
    /// 逾时：上游黑洞／本机无路由／对端不回 SYN-ACK 表象相同，只能确定没收到回应
    Timeout,
    /// 其他／无法归类
    Other,
}

/// 依 errno 判断是否属于「本机条件」。
#[cfg(target_os = "linux")]
fn classify_io_error(err: &io::Error) -> ProbeErrorKind {
    match err.raw_os_error() {
        // 注意：EHOSTUNREACH 不算本机——它也可能是上游路由器回的 ICMP host-unreachable
        // （封包确实有出去），把它当本机问题会反过来误导。
        Some(libc::ENETUNREACH)
        | Some(libc::ENODEV)
        | Some(libc::EADDRNOTAVAIL)
        | Some(libc::EACCES)
        | Some(libc::EPERM)
        | Some(libc::ENETDOWN)
        | Some(libc::EAFNOSUPPORT)
        | Some(libc::EINVAL) => ProbeErrorKind::Local,
        _ => ProbeErrorKind::Other,
    }
}

#[cfg(not(target_os = "linux"))]
fn classify_io_error(_err: &io::Error) -> ProbeErrorKind {
    ProbeErrorKind::Other
}

/// 单次探测结果
#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub success: bool,
    pub rtt: Duration,
    pub target: SocketAddr,
    pub error_msg: Option<String>,
    /// 失败的分类（成功时为 None）。状态档的 `local_condition` 与告警都看它，
    /// 不再去猜 `error_msg` 的文案。
    pub error_kind: Option<ProbeErrorKind>,
}

/// 建立绑定到特定网卡的非阻塞 TCP 套接字
///
/// - 依目标地址选择 AF_INET / AF_INET6（旧版固定用 AF_INET，若使用者设定了 IPv6
///   探测目标会直接 EINVAL，导致该 WAN 永远判定为断线）
/// - 设定 SO_LINGER(0)：探测结束后直接发 RST 而不是 FIN。
///   这样不会在对端留下半关闭连线，也不会在本机产生 TIME_WAIT。
///   **注意**：RST 不能避免 conntrack 条目——SYN 一送出内核就已建立条目，
///   RST 只是让它快速进入 CLOSE 态（仍会保留数秒）。要压低连接数只能靠
///   `probe_interface` 的「主目标 + 失败才回退」策略减少实际发出的探针数。
fn create_bound_tcp_socket(iface: &str, target: &SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    socket.set_nonblocking(true)?;

    // 探测完立即以 RST 结束，避免本机留下 TIME_WAIT（conntrack 条目无法借此避免）
    if let Err(e) = socket.set_linger(Some(Duration::ZERO)) {
        debug!("[probe] set SO_LINGER(0) failed: {e}");
    }

    #[cfg(target_os = "linux")]
    {
        // 强制透过 SO_BINDTODEVICE 绑定到出口网卡，避免受预设路由影响
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
    }

    Ok(socket)
}

/// 对单一目标发送 TCP SYN 探针
pub async fn probe_single_target(
    iface: &str,
    target: SocketAddr,
    timeout: Duration,
) -> ProbeSample {
    let start = Instant::now();

    let socket = match create_bound_tcp_socket(iface, &target) {
        Ok(s) => s,
        Err(e) => {
            return ProbeSample {
                success: false,
                rtt: timeout,
                target,
                error_msg: Some(format!("Create socket failed: {e}")),
                error_kind: Some(ProbeErrorKind::Local),
            };
        }
    };

    // 发起非阻塞 connect (SYN 包发送)
    match socket.connect(&target.into()) {
        Ok(()) => {
            // 极罕见情况下直接成功
            let rtt = start.elapsed();
            ProbeSample {
                success: true,
                rtt,
                target,
                error_msg: None,
                error_kind: None,
            }
        }
        Err(e) => {
            let raw_err = e.raw_os_error();
            // EINPROGRESS (Linux 115) 代表非阻塞 SYN 已发出，正在等待回应
            let in_progress =
                raw_err == Some(libc::EINPROGRESS) || e.kind() == io::ErrorKind::WouldBlock;

            if !in_progress {
                return ProbeSample {
                    success: false,
                    rtt: start.elapsed(),
                    target,
                    error_msg: Some(format!("Connect immediate error: {e}")),
                    error_kind: Some(classify_io_error(&e)),
                };
            }

            // 将 std socket 转换至 tokio TcpStream 以进行非同步事件轮询
            let std_stream: std::net::TcpStream = socket.into();
            let tokio_stream = match tokio::net::TcpStream::from_std(std_stream) {
                Ok(s) => s,
                Err(e) => {
                    return ProbeSample {
                        success: false,
                        rtt: start.elapsed(),
                        target,
                        error_msg: Some(format!("Tokio from_std failed: {e}")),
                        error_kind: Some(ProbeErrorKind::Local),
                    };
                }
            };

            // 等待 socket 可写事件（收到 SYN-ACK 或 RST），或超时
            match tokio::time::timeout(timeout, tokio_stream.writable()).await {
                Ok(Ok(())) => {
                    let elapsed = start.elapsed();
                    // 检查 SO_ERROR 判断连线状态
                    match tokio_stream.take_error() {
                        Ok(None) => {
                            // 收到 SYN-ACK，握手完成，链路完全正常
                            ProbeSample {
                                success: true,
                                rtt: elapsed,
                                target,
                                error_msg: None,
                                error_kind: None,
                            }
                        }
                        Ok(Some(err)) => {
                            // 收到 RST (ECONNREFUSED) 亦代表资料包成功往返目标伺服器，证明链路正常！
                            if err.raw_os_error() == Some(libc::ECONNREFUSED) {
                                ProbeSample {
                                    success: true,
                                    rtt: elapsed,
                                    target,
                                    error_msg: None,
                                    error_kind: None,
                                }
                            } else {
                                ProbeSample {
                                    success: false,
                                    rtt: elapsed,
                                    target,
                                    error_msg: Some(format!("Socket error: {err}")),
                                    error_kind: Some(classify_io_error(&err)),
                                }
                            }
                        }
                        Err(err) => ProbeSample {
                            success: false,
                            rtt: elapsed,
                            error_msg: Some(format!("take_error failed: {err}")),
                            error_kind: Some(ProbeErrorKind::Local),
                            target,
                        },
                    }
                }
                Ok(Err(e)) => ProbeSample {
                    success: false,
                    rtt: start.elapsed(),
                    target,
                    error_msg: Some(format!("Poll writable error: {e}")),
                    error_kind: Some(classify_io_error(&e)),
                },
                Err(_) => {
                    // 超时：只说「没收到回应」，不要断言是「丢包」——
                    // 上游黑洞、本机缺少路由、对端不回 SYN-ACK 都是同样的表象
                    ProbeSample {
                        success: false,
                        rtt: timeout,
                        target,
                        error_msg: Some(format!(
                            "Timeout (no reply within {}ms)",
                            timeout.as_millis()
                        )),
                        error_kind: Some(ProbeErrorKind::Timeout),
                    }
                }
            }
        }
    }
}

/// 从多个候选样本里挑出「这一拍该回报的那一笔」。
///
/// 规则刻意与旧版（主目标 → 失败才依序回退）完全一致，只是不再受「先等主目标
/// 超时」的时序限制：
/// 1. 主目标成功 → 用主目标（保持 `preferred_target` 稳定、RTT 可比）；
/// 2. 否则用第一个成功的目标；
/// 3. 全失败 → 优先回传「非本机条件」的失败（逾时／对端拒绝才能代表线路状态；
///    本机 fast-fail 的 rtt≈0 会把状态档误导成「全是本机问题」），
///    没有任何非本机失败时回传主目标那一笔。
fn pick_sample(samples: Vec<ProbeSample>, primary_idx: usize) -> ProbeSample {
    if let Some(primary) = samples.get(primary_idx).filter(|s| s.success) {
        return primary.clone();
    }
    if let Some(success) = samples.iter().find(|s| s.success) {
        return success.clone();
    }
    // 主目标优先，其余照设定顺序：与旧版一致，避免同一个故障在不同拍回报不同原因
    let order =
        std::iter::once(primary_idx).chain((0..samples.len()).filter(|i| *i != primary_idx));
    let mut first_non_local: Option<ProbeSample> = None;
    for idx in order {
        if let Some(sample) = samples.get(idx) {
            if sample.error_kind != Some(ProbeErrorKind::Local) && first_non_local.is_none() {
                first_non_local = Some(sample.clone());
            }
        }
    }
    first_non_local.unwrap_or_else(|| {
        samples
            .get(primary_idx)
            .or_else(|| samples.first())
            .cloned()
            .expect("probe_interface 至少会回传一笔样本")
    })
}

/// 针对接口配置的多个目标探测，任一目标成功即回传该样本。
///
/// 策略是「主目标 + 失败才回退」：每个探测周期只先探 `targets[preferred]`，
/// 成功就结束（健康时每周期仅发出一条 TCP 连线）；只有主目标失败才探测其余
/// 目标。旧写法不论如何都先把所有目标的 SYN 发出去——即使第一个目标已经成功，
/// 被丢弃的 future 的 SYN 早已离机，于是在 conntrack / LuCI 连线列表里留下
/// 「每周期 × 每个目标」的大量短命连线，这正是要修掉的浪费。
///
/// `preferred` 由呼叫端维护（通常是「上次探通的目标」的下标），允许它成功一次后
/// 持续作为主目标，避免某个被过滤的目标每周期都白吃一次 probe_timeout。
///
/// `primary_suspect` = 上一拍的样本是失败的（呼叫端用
/// `consecutive_timeouts > 0` 判断）。此时**所有目标同时发出**，因为：
/// 「先等主目标 timeout、再并发探其余目标」在最坏的故障情形（全部目标都不回应）
/// 会让一个探测周期花掉 2 × timeout（预设 400ms → 800ms），比 `check_interval_ms`
/// （预设 500ms）还长；`tokio::time::interval` 的 `MissedTickBehavior::Skip` 会把
/// 错过的拍直接丢掉，于是**探测节奏被拉长**：3 拍判 DOWN 由 1.5 秒变 2.4 秒、
/// 5 拍恢复由 2.5 秒变 4 秒（本机实测 800ms 周期），而这段 await 还发生在主事件
/// 回圈的分支体内，期间讯号与 link 事件全部无法处理。
///
/// 并行发出**不会**让任何目标被缩短：每个目标仍拿到完整的 `timeout`，
/// 只是不再排队等主目标先超时。健康时（上一拍成功）仍只有一条连线，维持原本的
/// 「不灌满 conntrack / LuCI 连线列表」承诺。
pub async fn probe_interface(
    iface: &str,
    targets: &[SocketAddr],
    timeout: Duration,
    preferred: usize,
    primary_suspect: bool,
) -> ProbeSample {
    if targets.is_empty() {
        return ProbeSample {
            success: false,
            rtt: timeout,
            target: "0.0.0.0:0".parse().unwrap(),
            error_msg: Some("No targets configured".into()),
            error_kind: Some(ProbeErrorKind::Local),
        };
    }

    if targets.len() == 1 {
        return probe_single_target(iface, targets[0], timeout).await;
    }

    let primary_idx = if preferred < targets.len() {
        preferred
    } else {
        0
    };

    // 疑似故障：同时探所有目标，整拍最多只花 1 × timeout。
    // async fn 的 future 是 !Unpin，join_all 需要 Unpin，因此用 Box::pin 装箱。
    if primary_suspect {
        let futures: Vec<_> = targets
            .iter()
            .map(|&target| Box::pin(probe_single_target(iface, target, timeout)))
            .collect();
        let samples = futures_util::future::join_all(futures).await;
        let sample = pick_sample(samples, primary_idx);
        if sample.success {
            debug!(
                "[{}] Probe success to {} with RTT {:?} (hedged round)",
                iface, sample.target, sample.rtt
            );
        } else if let Some(err) = &sample.error_msg {
            debug!("[{}] Probe all failed to {}: {}", iface, sample.target, err);
        }
        return sample;
    }

    // 第一阶段：只探主目标。成功即结束，这是绝大多数周期唯一发出的探针。
    let primary = probe_single_target(iface, targets[primary_idx], timeout).await;
    if primary.success {
        debug!(
            "[{}] Probe success to {} with RTT {:?}",
            iface, primary.target, primary.rtt
        );
        return primary;
    }

    // 失败样本：主目标（时序上第一个失败）先留一份供除错；
    // 非本机条件的失败（例如逾时）比「本机快速失败」更能代表这条线的实际状态：
    // fast-fail（ENETUNREACH，rtt≈0）若被直接回传，真正在超时丢包的目标证据会被
    // 丢掉，状态档会误显示成纯本机问题。
    let first_fail = primary.clone();
    let mut preferred_fail: Option<ProbeSample> =
        if primary.error_kind != Some(ProbeErrorKind::Local) {
            Some(primary)
        } else {
            None
        };

    // 第二阶段：主目标失败才回退，并发探测其余目标。
    // async fn 的 future 是 !Unpin，select_all 要求 Unpin，因此用 Box::pin 装箱。
    let mut futures: Vec<_> = targets
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != primary_idx)
        .map(|(_, &target)| Box::pin(probe_single_target(iface, target, timeout)))
        .collect();

    while !futures.is_empty() {
        let (res, _idx, rest) = futures_util::future::select_all(futures).await;
        futures = rest;

        if res.success {
            debug!(
                "[{}] Probe fallback success to {} with RTT {:?}",
                iface, res.target, res.rtt
            );
            return res;
        }
        if res.error_kind != Some(ProbeErrorKind::Local) && preferred_fail.is_none() {
            preferred_fail = Some(res);
        }
    }

    let f = preferred_fail.unwrap_or(first_fail);
    if let Some(err) = &f.error_msg {
        debug!("[{}] Probe all failed to {}: {}", iface, f.target, err);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(last: u8) -> SocketAddr {
        format!("223.5.5.5:{last}").parse().unwrap()
    }

    fn ok(last: u8, rtt_ms: u64) -> ProbeSample {
        ProbeSample {
            success: true,
            rtt: Duration::from_millis(rtt_ms),
            target: target(last),
            error_msg: None,
            error_kind: None,
        }
    }

    fn fail(last: u8, kind: ProbeErrorKind) -> ProbeSample {
        ProbeSample {
            success: false,
            rtt: Duration::from_millis(400),
            target: target(last),
            error_msg: Some(format!("{kind:?}")),
            error_kind: Some(kind),
        }
    }

    /// 并行（hedged）一轮的结果选择必须与旧版「主目标优先」的语意完全一致，
    /// 否则同一个故障会在不同拍回报不同的原因，`preferred_target` 也会乱跳。
    #[test]
    fn test_pick_sample_prefers_primary_then_order_then_non_local_failure() {
        // 1) 主目标成功 → 一定用主目标，即使别的目标 RTT 更低
        let picked = pick_sample(vec![ok(53, 30), ok(54, 5), ok(55, 7)], 0);
        assert_eq!(picked.target, target(53));
        // 主目标不在下标 0 时也一样（preferred_target 可以指向任何一个）
        let picked = pick_sample(vec![ok(53, 5), ok(54, 30)], 1);
        assert_eq!(picked.target, target(54));

        // 2) 主目标失败、有备用目标成功 → 用第一个成功的目标（依设定顺序，结果稳定）
        let picked = pick_sample(
            vec![fail(53, ProbeErrorKind::Timeout), ok(54, 22), ok(55, 8)],
            0,
        );
        assert_eq!(picked.target, target(54));

        // 3) 全失败 → 优先回报「非本机条件」的失败（本机 fast-fail 会把状态档误导成
        //    「全是本机问题」，但主目标那一笔仍是第一顺位）
        let picked = pick_sample(
            vec![
                fail(53, ProbeErrorKind::Local),
                fail(54, ProbeErrorKind::Timeout),
                fail(55, ProbeErrorKind::Other),
            ],
            0,
        );
        assert_eq!(picked.target, target(54));
        assert_eq!(picked.error_kind, Some(ProbeErrorKind::Timeout));

        // 4) 只有本机条件的失败 → 回传主目标那一笔（与旧版 first_fail 一致）
        let picked = pick_sample(
            vec![
                fail(53, ProbeErrorKind::Local),
                fail(54, ProbeErrorKind::Local),
            ],
            0,
        );
        assert_eq!(picked.target, target(53));

        // 5) 主目标 index 超出范围时不 panic（设定改变/目标被移除的边界）
        let picked = pick_sample(vec![fail(53, ProbeErrorKind::Local)], 7);
        assert_eq!(picked.target, target(53));
    }
}
