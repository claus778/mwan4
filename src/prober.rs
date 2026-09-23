use log::debug;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 探針失敗的分類：決定「這是本機問題還是線路問題」。
///
/// 為什麼不靠錯誤字串：`io::Error` 的 Display 是 libc `strerror` 的文案，
/// glibc 與 musl（OpenWrt 預設）用字不同（`Network is unreachable` vs
/// `Network unreachable`、`Cannot assign requested address` vs
/// `Address not available`），字串比對在目標平台上會整批失效，把本機路由問題
/// 誤報成運營商丟包。直接比對 errno 才穩定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeErrorKind {
    /// 封包根本沒出去：設備不存在、無經該設備的路由、權限不足、無目標設定
    Local,
    /// 逾時：上游黑洞／本機無路由／對端不回 SYN-ACK 表象相同，只能確定沒收到回應
    Timeout,
    /// 其他／無法歸類
    Other,
}

/// 依 errno 判斷是否屬於「本機條件」。
#[cfg(target_os = "linux")]
fn classify_io_error(err: &io::Error) -> ProbeErrorKind {
    match err.raw_os_error() {
        // 注意：EHOSTUNREACH 不算本機——它也可能是上游路由器回的 ICMP host-unreachable
        // （封包確實有出去），把它當本機問題會反過來誤導。
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

/// 單次探測結果
#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub success: bool,
    pub rtt: Duration,
    pub target: SocketAddr,
    pub error_msg: Option<String>,
    /// 失敗的分類（成功時為 None）。狀態檔的 `local_condition` 與告警都看它，
    /// 不再去猜 `error_msg` 的文案。
    pub error_kind: Option<ProbeErrorKind>,
}

/// 建立綁定到特定網卡的非阻塞 TCP 套接字
///
/// - 依目標地址選擇 AF_INET / AF_INET6（舊版固定用 AF_INET，若使用者設定了 IPv6
///   探測目標會直接 EINVAL，導致該 WAN 永遠判定為斷線）
/// - 設定 SO_LINGER(0)：探測結束後直接發 RST 而不是 FIN。
///   這樣不會在對端留下半關閉連線，也不會在本機產生 TIME_WAIT。
///   **注意**：RST 不能避免 conntrack 條目——SYN 一送出內核就已建立條目，
///   RST 只是讓它快速進入 CLOSE 態（仍會保留數秒）。要壓低連接數只能靠
///   `probe_interface` 的「主目標 + 失敗才回退」策略減少實際發出的探針數。
fn create_bound_tcp_socket(iface: &str, target: &SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    socket.set_nonblocking(true)?;

    // 探測完立即以 RST 結束，避免本機留下 TIME_WAIT（conntrack 條目無法藉此避免）
    if let Err(e) = socket.set_linger(Some(Duration::ZERO)) {
        debug!("[probe] set SO_LINGER(0) failed: {e}");
    }

    #[cfg(target_os = "linux")]
    {
        // 強制透過 SO_BINDTODEVICE 綁定到出口網卡，避免受預設路由影響
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
    }

    Ok(socket)
}

/// 對單一目標發送 TCP SYN 探針
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

    // 發起非阻塞 connect (SYN 包發送)
    match socket.connect(&target.into()) {
        Ok(()) => {
            // 極罕見情況下直接成功
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
            // EINPROGRESS (Linux 115) 代表非阻塞 SYN 已發出，正在等待回應
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

            // 將 std socket 轉換至 tokio TcpStream 以進行非同步事件輪詢
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

            // 等待 socket 可寫事件（收到 SYN-ACK 或 RST），或超時
            match tokio::time::timeout(timeout, tokio_stream.writable()).await {
                Ok(Ok(())) => {
                    let elapsed = start.elapsed();
                    // 檢查 SO_ERROR 判斷連線狀態
                    match tokio_stream.take_error() {
                        Ok(None) => {
                            // 收到 SYN-ACK，握手完成，鏈路完全正常
                            ProbeSample {
                                success: true,
                                rtt: elapsed,
                                target,
                                error_msg: None,
                                error_kind: None,
                            }
                        }
                        Ok(Some(err)) => {
                            // 收到 RST (ECONNREFUSED) 亦代表資料包成功往返目標伺服器，證明鏈路正常！
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
                    // 超時：只說「沒收到回應」，不要斷言是「丟包」——
                    // 上游黑洞、本機缺少路由、對端不回 SYN-ACK 都是同樣的表象
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

/// 針對接口配置的多個目標探測，任一目標成功即回傳該樣本。
///
/// 策略是「主目標 + 失敗才回退」：每個探測週期只先探 `targets[preferred]`，
/// 成功就結束（健康時每週期僅發出一條 TCP 連線）；只有主目標失敗才並發探測其餘
/// 目標。舊寫法不論如何都先把所有目標的 SYN 發出去——即使第一個目標已經成功，
/// 被丟棄的 future 的 SYN 早已離機，於是在 conntrack / LuCI 連線列表裡留下
/// 「每週期 × 每個目標」的大量短命連線，這正是要修掉的浪費。
///
/// `preferred` 由呼叫端維護（通常是「上次探通的目標」的下標），允許它成功一次後
/// 持續作為主目標，避免某個被過濾的目標每週期都白吃一次 probe_timeout。
///
/// 為什麼主目標失敗後是並發而不是依序探其餘目標：只要有一個目標被黑洞
/// （被過濾 / 丟包，端口不通但鏈路活著的常見形態），依序探測會把每個週期拖滿
/// N × probe_timeout，而這段 await 發生在主事件循環的分支體內，期間訊號與 link
/// 事件全部無法處理。並發下最壞只多花一輪 timeout，且只有故障時才會走到。
pub async fn probe_interface(
    iface: &str,
    targets: &[SocketAddr],
    timeout: Duration,
    preferred: usize,
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

    // 第一階段：只探主目標。成功即結束，這是絕大多數週期唯一發出的探針。
    let primary = probe_single_target(iface, targets[primary_idx], timeout).await;
    if primary.success {
        debug!(
            "[{}] Probe success to {} with RTT {:?}",
            iface, primary.target, primary.rtt
        );
        return primary;
    }

    // 失敗樣本：主目標（時序上第一個失敗）先留一份供除錯；
    // 非本機條件的失敗（例如逾時）比「本機快速失敗」更能代表這條線的實際狀態：
    // fast-fail（ENETUNREACH，rtt≈0）若被直接回傳，真正在超時丟包的目標證據會被
    // 丟掉，狀態檔會誤顯示成純本機問題。
    let first_fail = primary.clone();
    let mut preferred_fail: Option<ProbeSample> =
        if primary.error_kind != Some(ProbeErrorKind::Local) {
            Some(primary)
        } else {
            None
        };

    // 第二階段：主目標失敗才回退，並發探測其餘目標。
    // async fn 的 future 是 !Unpin，select_all 要求 Unpin，因此用 Box::pin 裝箱。
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
    if let Some(ref err) = f.error_msg {
        debug!("[{}] Probe all failed to {}: {}", iface, f.target, err);
    }
    f
}
