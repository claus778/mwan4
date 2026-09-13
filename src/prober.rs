use log::debug;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 單次探測結果
#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub success: bool,
    pub rtt: Duration,
    pub target: SocketAddr,
    pub error_msg: Option<String>,
}

/// 建立綁定到特定網卡的非阻塞 TCP 套接字
///
/// - 依目標地址選擇 AF_INET / AF_INET6（舊版固定用 AF_INET，若使用者設定了 IPv6
///   探測目標會直接 EINVAL，導致該 WAN 永遠判定為斷線）
/// - 設定 SO_LINGER(0)：探測結束後直接發 RST 而不是 FIN。
///   這樣不會在對端留下半關閉連線，也不會在本機產生 TIME_WAIT /
///   conntrack 項目（原本每 500ms × N 個目標會持續累積上萬筆 TIME_WAIT）
fn create_bound_tcp_socket(iface: &str, target: &SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    socket.set_nonblocking(true)?;

    // 探測完立即以 RST 結束，避免佔用本機 conntrack / TIME_WAIT
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
                                }
                            } else {
                                ProbeSample {
                                    success: false,
                                    rtt: elapsed,
                                    target,
                                    error_msg: Some(format!("Socket error: {err}")),
                                }
                            }
                        }
                        Err(err) => ProbeSample {
                            success: false,
                            rtt: elapsed,
                            error_msg: Some(format!("take_error failed: {err}")),
                            target,
                        },
                    }
                }
                Ok(Err(e)) => ProbeSample {
                    success: false,
                    rtt: start.elapsed(),
                    target,
                    error_msg: Some(format!("Poll writable error: {e}")),
                },
                Err(_) => {
                    // 超時（丟包）
                    ProbeSample {
                        success: false,
                        rtt: timeout,
                        target,
                        error_msg: Some("Timeout (packet lost)".into()),
                    }
                }
            }
        }
    }
}

/// 針對接口配置的多個目標同時並行探測，任一目標成功即回傳該樣本。
///
/// 不能等所有目標跑完再挑選：只要有一個目標被黑洞（被過濾 / 丟包，端口不通
/// 但鏈路活著的常見形態），全等寫法會把每個探測週期拖滿 probe_timeout，
/// 而這段 await 發生在主事件循環的分支體內，期間訊號與 link 事件全部無法處理。
pub async fn probe_interface(
    iface: &str,
    targets: &[SocketAddr],
    timeout: Duration,
) -> ProbeSample {
    if targets.is_empty() {
        return ProbeSample {
            success: false,
            rtt: timeout,
            target: "0.0.0.0:0".parse().unwrap(),
            error_msg: Some("No targets configured".into()),
        };
    }

    if targets.len() == 1 {
        return probe_single_target(iface, targets[0], timeout).await;
    }

    // 多目標並發探測，select_all 競速：第一個完成的樣本若是成功直接返回，
    // 失敗樣本保留第一個供除錯，其餘繼續等。
    // async fn 的 future 是 !Unpin，select_all 要求 Unpin，因此用 Box::pin 裝箱。
    let mut futures: Vec<_> = targets
        .iter()
        .map(|&target| Box::pin(probe_single_target(iface, target, timeout)))
        .collect();
    let mut first_fail: Option<ProbeSample> = None;

    while !futures.is_empty() {
        let (res, _idx, rest) = futures_util::future::select_all(futures).await;
        futures = rest;

        if res.success {
            debug!(
                "[{}] Probe success to {} with RTT {:?}",
                iface, res.target, res.rtt
            );
            return res;
        }
        if first_fail.is_none() {
            first_fail = Some(res);
        }
    }

    let f = first_fail.expect("probe_interface always yields at least one sample");
    if let Some(ref err) = f.error_msg {
        debug!("[{}] Probe all failed to {}: {}", iface, f.target, err);
    }
    f
}
