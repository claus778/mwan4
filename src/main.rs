use log::{debug, error, info, warn};
use std::env;
use std::process;
use std::time::{Duration, Instant};

mod config;
mod lqe;
mod netlink;
mod prober;

use config::{DaemonConfig, EcmpMode};
use lqe::{LinkQualityEstimator, LinkState};
use netlink::conntrack::ConntrackManager;
use netlink::route::{
    AF_INET, ActiveWanRoute, ActiveWanRouteV6, PROBE_RULE_PRIORITY_BASE, PROBE_TABLE_BASE,
    ProbePath, RouteManager,
};
use netlink::util::if_nametoindex;

const STATUS_FILE: &str = "/tmp/mwan4_status.json";
const STATUS_TMP_FILE: &str = "/tmp/mwan4_status.json.tmp";
/// 單實例鎖：避免兩個 mwan4 行程互相搶奪同一條預設路由
const PID_FILE: &str = "/var/run/mwan4.pid";

/// 後備輪詢間隔（約 5 分鐘）。
/// 正常情況由 RTNLGRP_LINK / IFADDR 事件即時驅動，
/// 這裡只是訂閱失敗或事件遺漏時的安全網。
const IFINDEX_REFRESH_TICKS: u64 = 600;
/// netlink 指令佇列容量（worker 卡住時丟棄指令而不是無限堆積）
const NETLINK_QUEUE_CAPACITY: usize = 64;
/// 探針路徑（獨立表 + oif 規則）的定期重新校驗間隔（tick 數，約 30 秒）
const PROBE_PATH_REFRESH_TICKS: u64 = 60;
/// 存活集合沒有變化時，仍定期重下一次預設路由以自我修復（tick 數，約 30 秒）
const ROUTE_HEARTBEAT_TICKS: u64 = 60;
/// 狀態檔新鮮度門檻（秒）：超過這個時間沒有更新，LuCI 會標成「資料已過期」，
/// 而不是把最後一次快照（可能剛好是兩條 DOWN）當成即時狀態一直顯示。
const STATUS_STALE_SECS: u64 = 10;

/// link watcher 失效後的重訂閱間隔（tick 數，約 30 秒）
const LINK_WATCH_RETRY_TICKS: u64 = 60;

fn print_help(bin_name: &str) {
    println!(
        r#"MWAN4 - Ultra-lightweight Multi-WAN Failover & Health Daemon for Linux / OpenWrt

USAGE:
    {bin_name} [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Path to JSON configuration file (e.g. /etc/mwan4/mwan4.json)
    -t, --check-config <FILE>
                           Validate a configuration file and exit (0 = valid, 1 = invalid)
    --gen-config           Output default JSON configuration template to stdout
    -v, --version          Print version information
    -h, --help             Print this help message
"#
    );
}

/// 檢查是否已有另一個 mwan4 行程在跑，並寫入自己的 PID
fn acquire_pid_file() -> Result<(), String> {
    let path = std::path::Path::new(PID_FILE);

    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(pid) = content.trim().parse::<i64>() {
            if process_alive(pid) {
                return Err(format!(
                    "another mwan4 instance is already running (pid {pid}); remove {PID_FILE} if this is stale"
                ));
            }
        }
        // 殘留的舊 PID 檔案，直接覆寫
        warn!("Removing stale PID file {PID_FILE}");
    }

    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    std::fs::write(path, process::id().to_string())
        .map_err(|e| format!("failed to write {PID_FILE}: {e}"))?;
    Ok(())
}

fn release_pid_file() {
    let _ = std::fs::remove_file(PID_FILE);
}

/// 判斷行程是否存活（非 Linux 平台保守回傳 true，避免誤判）
fn process_alive(pid: i64) -> bool {
    #[cfg(target_os = "linux")]
    {
        if pid <= 0 {
            return false;
        }
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

/// 交給 netlink worker 執行緒處理的指令
///
/// Netlink 的 send/recv 都是阻塞式系統呼叫（conntrack 全表 dump 甚至可達數秒），
/// 若直接在 `current_thread` 的非同步主迴圈裡執行，會把整個探測週期卡住。
/// 因此統一丟到專屬執行緒處理，主迴圈只做非阻塞的 try_send。
enum NetlinkCmd {
    /// 下發（或於清單為空時刪除）IPv4 預設路由
    Apply(Vec<ActiveWanRoute>),
    /// 下發（或於清單為空時刪除）IPv6 預設路由
    ApplyV6(Vec<ActiveWanRouteV6>),
    /// 建立／更新「探針路徑」：每張 WAN 一張獨立表 + 一條 `oif <wan>` 規則，
    /// 必要時再於主表補探針目標的 /32（給 rp_filter 的反向路徑檢查用）。
    /// 這是讓探針不再依賴主表預設路由的關鍵（見 netlink::route 的說明）。
    ///
    /// `clean_host_routes` 只在啟動後第一次下發時為 true：把上一次執行可能殘留的
    /// 主表 /32 先清掉，之後才按需補回。
    SetProbePaths(Vec<ProbePath>, bool),
    /// 清理指定網卡們的 conntrack 連線（多張網卡合併為一次全表 dump）
    FlushConntrack(Vec<String>),
    /// 優雅退出：移除本程式下發的預設路由
    ClearRoutes,
}

type NetlinkSender = std::sync::mpsc::SyncSender<NetlinkCmd>;

/// worker 執行過的「全量期望狀態」操作種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkOp {
    Ipv4Routes,
    Ipv6Routes,
    ProbePaths,
    Conntrack,
}

/// 操作結果回報：主迴圈據此判斷「已入佇列」是否真的生效，
/// 失敗就強制下個 tick 重下（而不是像以前一樣只印一行 error 就永久停留）。
#[derive(Debug, Clone)]
struct NetlinkOutcome {
    op: NetlinkOp,
    ok: bool,
    /// 失敗原因（給主迴圈做去重告警用；成功時為 None）
    detail: Option<String>,
}

impl NetlinkOutcome {
    fn new(op: NetlinkOp, ok: bool, detail: Option<String>) -> Self {
        Self { op, ok, detail }
    }
}

type NetlinkResultSender = std::sync::mpsc::Sender<NetlinkOutcome>;
type NetlinkResultReceiver = std::sync::mpsc::Receiver<NetlinkOutcome>;

fn spawn_netlink_worker(
    route_mgr: RouteManager,
    conntrack_mgr: ConntrackManager,
) -> (
    NetlinkSender,
    NetlinkResultReceiver,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(NETLINK_QUEUE_CAPACITY);
    let (result_tx, result_rx): (NetlinkResultSender, NetlinkResultReceiver) =
        std::sync::mpsc::channel::<NetlinkOutcome>();

    let handle = std::thread::Builder::new()
        .name("mwan4-netlink".to_string())
        .spawn(move || {
            let mut route_mgr = route_mgr;
            let mut conntrack_mgr = conntrack_mgr;

            while let Ok(cmd) = rx.recv() {
                // worker 卡在耗時操作（如 conntrack 全表 dump）時，佇列裡可能積壓
                // 多條陳舊的 Apply。它們都是「全量期望狀態」且冪等，只有最新一條
                // 有意義——先排空佇列合併成一批再執行，避免把陳舊狀態逐條重放。
                let mut batch = vec![cmd];
                while let Ok(more) = rx.try_recv() {
                    batch.push(more);
                }

                let mut apply: Option<Vec<ActiveWanRoute>> = None;
                let mut apply_v6: Option<Vec<ActiveWanRouteV6>> = None;
                let mut probe_paths: Option<(Vec<ProbePath>, bool)> = None;
                let mut flush: Vec<String> = Vec::new();
                let mut clear_routes = false;
                for c in batch {
                    match c {
                        NetlinkCmd::Apply(wans) => apply = Some(wans),
                        NetlinkCmd::ApplyV6(wans) => apply_v6 = Some(wans),
                        NetlinkCmd::SetProbePaths(paths, clean) => {
                            probe_paths = Some((paths, clean))
                        }
                        NetlinkCmd::FlushConntrack(names) => {
                            for name in names {
                                if !flush.contains(&name) {
                                    flush.push(name);
                                }
                            }
                        }
                        NetlinkCmd::ClearRoutes => clear_routes = true,
                    }
                }

                if let Some(wans) = apply {
                    let (ok, detail) = match route_mgr.apply_default_routes(&wans) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Failed to update kernel IPv4 FIB routes: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Ipv4Routes, ok, detail));
                }
                if let Some(wans) = apply_v6 {
                    let (ok, detail) = match route_mgr.apply_ipv6_default_routes(&wans) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Failed to update kernel IPv6 FIB routes: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Ipv6Routes, ok, detail));
                }
                if let Some((paths, clean_host_routes)) = probe_paths {
                    if clean_host_routes {
                        // 按專屬 metric 轉儲掃描：連「已從設定移除的目標」留下的 /32
                        // 也一起清掉（只清當前設定裡有的目標是不夠的）
                        if let Err(e) = route_mgr.sweep_own_probe_host_routes() {
                            debug!("Probe host route cleanup failed: {e}");
                        }
                    }
                    // 單一網卡暫時不可用（ENODEV / ENETUNREACH）屬預期情況：
                    // 記 debug 並在下個週期重試，不要當成致命錯誤刷屏。
                    let (ok, detail) = match route_mgr.set_probe_paths(&paths) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Probe paths not fully applied yet: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::ProbePaths, ok, detail));
                }
                if !flush.is_empty() {
                    let (ok, detail) = match conntrack_mgr.flush_interfaces_conntrack(&flush) {
                        Ok(_) => (true, None),
                        Err(e) => {
                            debug!("[{}] Conntrack flush failed: {e}", flush.join(", "));
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Conntrack, ok, detail));
                }
                if clear_routes {
                    if let Err(e) = route_mgr.cleanup_routes() {
                        warn!("Failed to remove mwan4 routes / nexthops on shutdown: {e}");
                    }
                    break;
                }
            }
        })
        .expect("Failed to spawn netlink worker thread");

    (tx, result_rx, handle)
}

// ---------------------------------------------------------------------------
// 訊號處理：OpenWrt procd 停止服務時送的是 SIGTERM，
// 只監聽 ctrl_c()（SIGINT）會導致服務永遠無法優雅退出。
// ---------------------------------------------------------------------------

#[cfg(unix)]
type SigHandle = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type SigHandle = ();

#[cfg(unix)]
async fn recv_or_pending(slot: &mut SigHandle) {
    match slot {
        Some(sig) => {
            sig.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(unix)]
async fn wait_terminate(term: &mut SigHandle, int: &mut SigHandle) {
    tokio::select! {
        _ = recv_or_pending(term) => {}
        _ = recv_or_pending(int) => {}
    }
}

#[cfg(not(unix))]
async fn wait_terminate(_term: &mut SigHandle, _int: &mut SigHandle) {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
fn install_signal_handlers() -> (SigHandle, SigHandle) {
    use tokio::signal::unix::{SignalKind, signal};

    let term = match signal(SignalKind::terminate()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("Failed to install SIGTERM handler: {e}");
            None
        }
    };
    let int = match signal(SignalKind::interrupt()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("Failed to install SIGINT handler: {e}");
            None
        }
    };
    (term, int)
}

#[cfg(not(unix))]
fn install_signal_handlers() -> (SigHandle, SigHandle) {
    ((), ())
}

// ---------------------------------------------------------------------------
// 網卡事件監看：訂閱核心的 link / ifaddr 組播，取代定時輪詢 ifindex 與 IP
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
type LinkWatch = Option<netlink::link::LinkWatcher>;
/// 非 Linux 平台沒有 netlink 可用。這裡刻意用一個空哨兵型別而不是 `()`，
/// 好讓 `let mut link_watch = ...` 在所有平台都維持同樣的形狀
/// （`()` 會觸發 clippy::let_unit_value）。
#[cfg(not(target_os = "linux"))]
struct LinkWatch;

#[cfg(target_os = "linux")]
async fn wait_link_event(w: &mut LinkWatch) -> Vec<netlink::link::LinkEvent> {
    match w {
        Some(watcher) => watcher.wait_events().await,
        None => {
            std::future::pending::<()>().await;
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_link_event(_w: &mut LinkWatch) -> Vec<netlink::link::LinkEvent> {
    std::future::pending::<()>().await;
    Vec::new()
}

#[cfg(target_os = "linux")]
fn install_link_watcher() -> LinkWatch {
    match netlink::link::LinkWatcher::new() {
        Ok(w) => {
            info!("Subscribed to kernel link/address events (RTNLGRP_LINK + IFADDR)");
            Some(w)
        }
        Err(e) => {
            warn!(
                "Failed to subscribe to kernel link events ({e}); falling back to periodic refresh"
            );
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn install_link_watcher() -> LinkWatch {
    LinkWatch
}

#[cfg(target_os = "linux")]
fn disable_link_watch(w: &mut LinkWatch) {
    *w = None;
}

#[cfg(not(target_os = "linux"))]
fn disable_link_watch(_w: &mut LinkWatch) {}

/// 目前是否仍有可用的 link 事件訂閱（非 Linux 平台永遠沒有）
#[cfg(target_os = "linux")]
fn link_watch_active(w: &LinkWatch) -> bool {
    w.is_some()
}

#[cfg(not(target_os = "linux"))]
fn link_watch_active(_w: &LinkWatch) -> bool {
    false
}

/// 重新解析某張網卡的 ifindex；解析不到就把它標成「不可用」（0）。
///
/// 舊行為是「解析失敗就保留舊值」，於是网卡被刪除／改名後，一個已經不存在
/// （甚至可能被別的設備複用）的 ifindex 會被繼續寫進內核路由。這裡改成失敗即歸零，
/// 而 `is_active` / 路由下發都要求 `ifindex != 0`，因此不會再拿死 index 去下發。
///
/// 回傳 true 表示 ifindex 有變動（呼叫端可據此重下探針路徑）。
fn refresh_ifindex(monitor: &mut WanMonitor, reason: &str) -> bool {
    match if_nametoindex(&monitor.ifname) {
        Ok(idx) => {
            if idx != monitor.ifindex {
                info!(
                    "Interface {} ifindex changed: {} -> {} ({reason})",
                    monitor.ifname, monitor.ifindex, idx
                );
                monitor.ifindex = idx;
                return true;
            }
            false
        }
        Err(e) => {
            if monitor.ifindex != 0 {
                warn!(
                    "Interface {} is gone ({}); marking it unusable until it returns ({reason})",
                    monitor.ifname, e
                );
                monitor.ifindex = 0;
                return true;
            }
            false
        }
    }
}

/// 依據核心事件更新各網卡的 ifindex 與快取 IP
fn refresh_interface_state(monitors: &mut [WanMonitor], reason: &str) -> bool {
    let mut changed = false;
    for monitor in monitors.iter_mut() {
        changed |= refresh_ifindex(monitor, reason);
        monitor.cached_ip = crate::netlink::util::get_interface_ipv4(&monitor.ifname).ok();
    }
    changed
}

/// 依據核心事件只刷新「受影響的」網卡，而不是任何介面的事件都全量重查。
///
/// - Link 事件攜帶 IFLA_IFNAME：按名稱匹配（網卡重建後 ifindex 會變、名稱不變，
///   所以必須能用名稱重新解析 ifindex）
/// - Address 事件只有 ifindex：按當前 ifindex 匹配即可（位址變動不換 ifindex）
///
/// 路由器上 LAN 橋、wifi、IPv6 臨時位址的事件遠多於 WAN 事件，
/// 過濾掉不相關事件可避免每次都對全部網卡做 7~9 個系統呼叫。
#[cfg(target_os = "linux")]
fn refresh_affected_interfaces(
    monitors: &mut [WanMonitor],
    events: &[netlink::link::LinkEvent],
) -> bool {
    let mut changed = false;
    for monitor in monitors.iter_mut() {
        let mut touched = false;
        let mut reindex = false;
        for e in events {
            match e {
                netlink::link::LinkEvent::Link {
                    ifname: Some(name), ..
                } if name == &monitor.ifname => {
                    touched = true;
                    reindex = true;
                }
                netlink::link::LinkEvent::Address { ifindex } if *ifindex == monitor.ifindex => {
                    touched = true;
                }
                _ => {}
            }
        }
        if !touched {
            continue;
        }
        if reindex {
            changed |= refresh_ifindex(monitor, "kernel link event");
        }
        monitor.cached_ip = crate::netlink::util::get_interface_ipv4(&monitor.ifname).ok();
    }
    changed
}

#[cfg(not(target_os = "linux"))]
fn refresh_affected_interfaces(
    _monitors: &mut [WanMonitor],
    _events: &[netlink::link::LinkEvent],
) -> bool {
    false
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化日誌輸出（預設為 INFO 等級）
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // 2. 解析命令列參數
    let args: Vec<String> = env::args().collect();
    let bin_name = args.first().map(|s| s.as_str()).unwrap_or("mwan4");

    let mut config_path: Option<String> = None;
    let mut check_config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: --config requires a file path argument");
                    process::exit(1);
                }
            }
            other if other.starts_with("--config=") => {
                config_path = Some(other["--config=".len()..].to_string());
            }
            other if other.starts_with("-c=") => {
                config_path = Some(other["-c=".len()..].to_string());
            }
            "-t" | "--check-config" => {
                if i + 1 < args.len() {
                    check_config_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Error: --check-config requires a file path argument");
                    process::exit(1);
                }
            }
            other if other.starts_with("--check-config=") => {
                check_config_path = Some(other["--check-config=".len()..].to_string());
            }
            "--gen-config" => {
                let default_cfg = DaemonConfig::default();
                println!("{}", serde_json::to_string_pretty(&default_cfg).unwrap());
                return Ok(());
            }
            "-v" | "--version" => {
                println!("mwan4 v{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-h" | "--help" => {
                print_help(bin_name);
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_help(bin_name);
                process::exit(1);
            }
        }
        i += 1;
    }

    // 3a. 只驗證設定檔而不啟動（給 init 腳本 / CI 使用，避免設定錯誤時靠 procd 重啟硬試）
    if let Some(path) = check_config_path {
        match DaemonConfig::load_from_file(&path) {
            Ok(_) => {
                println!("Configuration OK: {path}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Configuration error in {path}: {e}");
                process::exit(1);
            }
        }
    }

    // 3. 載入配置
    let config = match config_path {
        Some(path) => {
            info!("Loading configuration from: {path}");
            DaemonConfig::load_from_file(&path).unwrap_or_else(|e| {
                error!("Failed to load configuration from {path}: {e}");
                process::exit(1);
            })
        }
        None => {
            info!(
                "No config file specified, checking /etc/mwan4/mwan4.json or fallback to defaults..."
            );
            if std::path::Path::new("/etc/mwan4/mwan4.json").exists() {
                DaemonConfig::load_from_file("/etc/mwan4/mwan4.json").unwrap_or_else(|e| {
                    error!("Failed to load /etc/mwan4/mwan4.json: {e}");
                    process::exit(1);
                })
            } else {
                warn!(
                    "Using default built-in configuration (wan1: 192.168.1.1, wan2: 192.168.2.1)"
                );
                DaemonConfig::default()
            }
        }
    };

    if config.probe_timeout_ms > config.check_interval_ms {
        warn!(
            "probe_timeout_ms ({}) is greater than check_interval_ms ({}): \
             the effective probe period will be stretched to the timeout",
            config.probe_timeout_ms, config.check_interval_ms
        );
    }

    // 3b. 單實例鎖：兩個 mwan4 同時操作同一條預設路由會互相覆蓋
    if let Err(e) = acquire_pid_file() {
        error!("{e}");
        process::exit(1);
    }

    info!(
        "Starting mwan4 daemon (Probe interval: {}ms, Timeout: {}ms, Window: {}, Hysteresis: {} success, ECMP mode: {:?})",
        config.check_interval_ms,
        config.probe_timeout_ms,
        config.window_size,
        config.recovery_success_count,
        config.ecmp_mode
    );

    // 4. 初始化 Linux 核心 Netlink 控制器，並交由專屬執行緒操作
    //    這裡用明確的錯誤訊息 + exit(1) 取代 expect()：
    //    release 版開了 panic=abort，panic 只會留下一行堆疊，procd 也拿不到有用的退出碼
    let route_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Route socket: {e} (is CAP_NET_ADMIN granted?)");
            release_pid_file();
            process::exit(1);
        }
    };
    // 啟動前先掃掉自己保留區段內殘留的探針規則／表內路由：上次執行的介面順序若與
    // 這次不同，殘留的 `oif <wan> lookup <舊表>` 會把探針導向舊閘道。
    let mut route_mgr = route_mgr;
    if let Err(e) = route_mgr.sweep_probe_paths() {
        warn!("Failed to sweep stale probe paths on startup: {e}");
    }
    // 清掉上一次執行可能留下的主表探針 /32（按專屬 metric 轉儲掃描，能涵蓋已從設定移除、
    // 或當時設備還不存在的目標）
    match route_mgr.sweep_own_probe_host_routes() {
        Ok(0) => {}
        Ok(n) => info!("Cleaned up {n} leftover probe host route(s) on startup"),
        Err(e) => warn!("Failed to clean up leftover probe host routes: {e}"),
    }
    // 只用來「問內核路徑」的查詢用 socket：判斷主表有沒有涵蓋目標、以及探針失敗時
    // 是不是「本機根本沒有路」。與 worker 的寫入 socket 分開，避免互相干擾。
    let mut query_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => Some(m),
        Err(e) => {
            warn!(
                "Route query socket unavailable ({e}); probe-path decisions fall back to estimates"
            );
            None
        }
    };
    let conntrack_mgr = match ConntrackManager::new() {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Conntrack socket: {e}");
            release_pid_file();
            process::exit(1);
        }
    };
    let (netlink_tx, netlink_rx, netlink_worker) = spawn_netlink_worker(route_mgr, conntrack_mgr);

    // 5. 初始化各 WAN 網卡的 LQE 狀態機與 ifindex 解析
    let mut monitors: Vec<WanMonitor> = Vec::new();
    for iface_cfg in &config.interfaces {
        let ifindex = match if_nametoindex(&iface_cfg.name) {
            Ok(idx) => {
                info!("Mapped interface {} -> ifindex {}", iface_cfg.name, idx);
                idx
            }
            Err(e) => {
                warn!(
                    "Could not resolve ifindex for interface {}: {}. Will try dynamically during runtime.",
                    iface_cfg.name, e
                );
                0
            }
        };

        monitors.push(WanMonitor {
            ifname: iface_cfg.name.clone(),
            ifindex,
            gateway: iface_cfg.gateway,
            gateway6: iface_cfg.gateway6,
            metric: iface_cfg.metric,
            weight: iface_cfg.weight,
            targets: iface_cfg.probe_targets.clone(),
            underlay_targets: iface_cfg.underlay_targets.clone(),
            cached_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_conntrack_flush: None,
            last_probe_error: None,
            local_condition_warned: false,
            probe_path_missing: false,
            last_path_check: None,
            lqe: LinkQualityEstimator::new(iface_cfg.name.clone(), &config),
        });
    }

    // 只有至少一張網卡設定了 gateway6 才需要處理 IPv6 路由
    let has_ipv6 = monitors.iter().any(|m| m.gateway6.is_some());
    if has_ipv6 {
        info!("IPv6 default route management enabled (interfaces with gateway6)");
    }

    // 6. 主非同步事件循環 (Single-threaded Non-blocking Event Loop)
    let probe_interval = Duration::from_millis(config.check_interval_ms);
    let probe_timeout = Duration::from_millis(config.probe_timeout_ms);
    let conntrack_flush_min_interval =
        Duration::from_millis(config.conntrack_flush_min_interval_ms);
    // 使用 resilient nexthop group 時，核心只會重映射故障成員的 flow，其餘連線本來
    // 就不會斷；這時若還在「成員變動」時清 conntrack，反而會親手打斷那些被保留的連線。
    // 因此非 standard 模式一律關閉 flush-on-switch（flush-on-down 仍然保留：
    // 已死鏈路上的連線本來就該清掉）。
    let flush_on_switch =
        config.flush_conntrack_on_switch && config.ecmp_mode == EcmpMode::Standard;
    if config.flush_conntrack_on_switch && !flush_on_switch {
        info!(
            "flush_conntrack_on_switch suppressed for ecmp_mode={:?}: \
             resilient nexthop groups already keep unaffected flows pinned",
            config.ecmp_mode
        );
    }
    let mut ticker = tokio::time::interval(probe_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let (mut sigterm, mut sigint) = install_signal_handlers();
    let mut link_watch = install_link_watcher();

    let mut tick_count: u64 = 0;
    // None 代表「尚未下發過任何路由」，與「已知沒有存活線路」區分開來，
    // 避免開機第一次探測就把別人（netifd）的預設路由刪掉
    let mut last_active_ifindexes: Option<Vec<u32>> = None;
    // IPv6 路由更新入隊失敗時暫存待重試的 payload。
    // last_active_ifindexes 只跟隨 IPv4 的入隊結果更新，若不顯式重試，
    // v6 更新在 need_apply 變回 false 後會永久丟失。
    let mut v6_pending: Option<Vec<ActiveWanRouteV6>> = None;
    // 探針路徑需要（重）下發：開機、ifindex 變動、上次失敗、或定期校驗
    let mut probe_paths_dirty = true;
    let mut probe_paths_inflight = false;
    let mut probe_paths_retry_at: u64 = 0;
    // 第一次下發探針路徑時，順手清掉上一次執行可能殘留的主表 /32
    let mut probe_host_routes_cleanup = true;
    // 預設路由下發失敗（worker 回報）或心跳到期時，即使存活集合沒變也要重下
    let mut v4_apply_dirty = false;
    let mut v4_apply_inflight = false;
    let mut v4_retry_at: u64 = 0;
    // link watcher 失效後的重訂閱時間點
    let mut link_watch_retry_at: u64 = 0;
    // 路由下發失敗的告警去重（避免永久失敗時刷屏沖掉 logd 環形緩衝）
    let mut route_fail_count: u64 = 0;
    let mut last_route_fail: Option<String> = None;
    // strict rp_filter + 共用探針目標的告警只說一次
    let mut strict_shared_warned = false;

    info!("mwan4 event loop running. Press Ctrl+C to terminate.");

    loop {
        tokio::select! {
            _ = wait_terminate(&mut sigterm, &mut sigint) => {
                info!("Received termination signal (SIGINT/SIGTERM), exiting cleanly...");
                break;
            }
            events = wait_link_event(&mut link_watch) => {
                if events.is_empty() {
                    // 訂閱失效是可恢復的：關掉它、退回輪詢，並在稍後嘗試重新訂閱
                    // （舊行為是永久放棄事件驅動，ifindex 最長 5 分鐘才被修正）
                    warn!(
                        "Link watcher stopped; falling back to periodic refresh, will retry subscribing shortly"
                    );
                    disable_link_watch(&mut link_watch);
                    link_watch_retry_at = tick_count + LINK_WATCH_RETRY_TICKS;
                    continue;
                }
                if log::log_enabled!(log::Level::Debug) {
                    let ifindexes: Vec<u32> = events.iter().map(|e| e.ifindex()).collect();
                    debug!("Kernel link/address events for ifindex {ifindexes:?}");
                }
                // 接收緩衝溢位（ENOBUFS）代表中間有事件遺失：
                // 做一次全量 resync，訂閱保持有效（低記憶體路由器開機期容易發生）
                let ifindex_changed = if events
                    .iter()
                    .any(|e| matches!(e, netlink::link::LinkEvent::Resync))
                {
                    warn!("Netlink event buffer overflowed (ENOBUFS); resynchronizing interface state");
                    refresh_interface_state(&mut monitors, "netlink overflow")
                } else {
                    refresh_affected_interfaces(&mut monitors, &events)
                };
                if ifindex_changed {
                    probe_paths_dirty = true;
                }
            }
            _ = ticker.tick() => {
                tick_count += 1;

                // 0) 收集 worker 的操作結果。失敗不再只是「印一行 error 就永久停留」：
                //    這裡把它標成 dirty，下個 tick 重下同一份期望狀態（Apply 是冪等的）。
                while let Ok(outcome) = netlink_rx.try_recv() {
                    match outcome.op {
                        NetlinkOp::Ipv4Routes => {
                            v4_apply_inflight = false;
                            if !outcome.ok {
                                // 去重告警：同一個錯誤只報一次（之後每 20 次提醒一次），
                                // 避免永久失敗時以每 2 秒一條的速度把 logd 環形緩衝沖掉，
                                // 反而蓋掉真正有用的訊息
                                let detail = outcome.detail.unwrap_or_else(|| "unknown".into());
                                route_fail_count += 1;
                                if last_route_fail.as_deref() != Some(detail.as_str())
                                    || route_fail_count % 20 == 1
                                {
                                    warn!(
                                        "Kernel IPv4 default route update failed ({detail}); \
                                         re-applying the expected state shortly \
                                         (self-heal, occurrence {route_fail_count})"
                                    );
                                    last_route_fail = Some(detail);
                                }
                                v4_apply_dirty = true;
                                v4_retry_at = tick_count + 4;
                            } else {
                                route_fail_count = 0;
                                last_route_fail = None;
                            }
                        }
                        NetlinkOp::Ipv6Routes => {
                            // IPv6 的期望狀態會在心跳或集合變動時一起重送
                            if !outcome.ok {
                                debug!("IPv6 FIB update failed; it will be re-applied with the next heartbeat");
                            }
                        }
                        NetlinkOp::ProbePaths => {
                            probe_paths_inflight = false;
                            if !outcome.ok {
                                // 網卡暫時不可用屬預期情況（設備已 down），退避後再試
                                probe_paths_dirty = true;
                                probe_paths_retry_at = tick_count + 6;
                            }
                        }
                        NetlinkOp::Conntrack => {}
                    }
                }

                // 0b) link watcher 若曾失效，這裡嘗試重新訂閱（不必等 5 分鐘輪詢）
                if !link_watch_active(&link_watch) && tick_count >= link_watch_retry_at {
                    link_watch = install_link_watcher();
                    if link_watch_active(&link_watch) {
                        info!("Link watcher re-subscribed successfully");
                    } else {
                        link_watch_retry_at = tick_count + LINK_WATCH_RETRY_TICKS;
                    }
                }

                // 上一個 tick 的 IPv6 路由更新若因佇列滿而未入隊，這裡補送
                if let Some(pending) = v6_pending.take() {
                    match netlink_tx.try_send(NetlinkCmd::ApplyV6(pending)) {
                        Ok(()) => {}
                        Err(err) => {
                            let err_desc = err.to_string();
                            if let std::sync::mpsc::TrySendError::Full(NetlinkCmd::ApplyV6(v6))
                            | std::sync::mpsc::TrySendError::Disconnected(NetlinkCmd::ApplyV6(v6)) = err
                            {
                                v6_pending = Some(v6);
                            }
                            debug!("IPv6 FIB update still queued; will retry next tick: {err_desc}");
                        }
                    }
                }

                // 並行探測所有 WAN 接口（直接借用 monitors，不再每個 tick clone 一份）
                let mut probe_futs = Vec::with_capacity(monitors.len());
                for monitor in monitors.iter() {
                    probe_futs.push(prober::probe_interface(&monitor.ifname, &monitor.targets, probe_timeout));
                }
                let samples = futures_util::future::join_all(probe_futs).await;
                let mut state_changed = false;
                // 本 tick 內需要清理 conntrack 的網卡（以 monitors 下標記錄）。
                // 統一延後到路由下發之後才入隊：conntrack 全表 dump 可達數秒，
                // 排在 Apply 前面（同一 worker 執行緒 FIFO）會拖慢故障切換的實際收斂。
                let mut flush_pending: Vec<usize> = Vec::new();

                // 餵入樣本更新各鏈路 LQE 狀態機
                for ((idx, monitor), sample) in
                    monitors.iter_mut().enumerate().zip(samples.into_iter())
                {
                    let (new_state, changed) = monitor.lqe.update(&sample);
                    if changed {
                        state_changed = true;
                        // 狀態切換時順勢刷新快取的 IP
                        monitor.cached_ip = crate::netlink::util::get_interface_ipv4(&monitor.ifname).ok();

                        if new_state == LinkState::Down && config.flush_conntrack_on_down {
                            // 鏈路斷開：稍後精準清理該網卡上的 conntrack 連線快取
                            flush_pending.push(idx);
                        }
                    }

                    // 記錄最近一次失敗原因：這是現場區分「線路真的丟包」與
                    // 「本機沒有路由／設備名錯誤」的唯一線索，必須進狀態檔。
                    match sample.error_msg.as_deref() {
                        Some(msg) => {
                            if is_local_probe_error(msg) && !monitor.local_condition_warned {
                                monitor.local_condition_warned = true;
                                warn!(
                                    "[{}] Probe cannot even leave the device ({msg}). \
                                     This is a local routing/interface problem, not carrier packet loss; \
                                     the per-WAN probe path will be re-applied.",
                                    monitor.ifname
                                );
                                probe_paths_dirty = true;
                            }
                            if monitor.last_probe_error.as_deref() != Some(msg) {
                                debug!("[{}] Probe error changed: {msg}", monitor.ifname);
                            }
                            monitor.last_probe_error = Some(msg.to_string());

                            // 「設備 UP 但沒有經它的路」時內核會按 on-link 送出，探針只會超時——
                            // 這與真正的丟包在日誌上長得一模一樣。連續失敗時主動問一次內核，
                            // 把這種情況標成 local_condition（每張網卡最多每 2 秒查一次）。
                            let due = monitor
                                .last_path_check
                                .is_none_or(|t| t.elapsed() >= Duration::from_secs(2));
                            if due && monitor.lqe.consecutive_timeouts >= 2 && monitor.ifindex != 0 {
                                monitor.last_path_check = Some(Instant::now());
                                let target = monitor.targets.iter().find_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                });
                                if let Some(target) = target {
                                    if let Some(has_route) = kernel_has_route(
                                        &mut query_mgr,
                                        target,
                                        Some(monitor.ifindex),
                                    ) {
                                        if !has_route && !monitor.probe_path_missing {
                                            monitor.probe_path_missing = true;
                                            warn!(
                                                "[{}] The kernel has NO route to {} via {}. \
                                                 Probes will look like packet loss (on-link blackhole) \
                                                 even though the link may be fine — this is a local \
                                                 routing problem.",
                                                monitor.ifname, target, monitor.ifname
                                            );
                                            probe_paths_dirty = true;
                                        } else if has_route {
                                            monitor.probe_path_missing = false;
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            monitor.last_probe_error = None;
                            monitor.local_condition_warned = false;
                            monitor.probe_path_missing = false;
                        }
                    }
                }

                // 啟動時解析不到 ifindex 的網卡，一旦可用就立刻補上（不必等輪詢）
                for monitor in monitors.iter_mut() {
                    if monitor.ifindex == 0 && refresh_ifindex(monitor, "retry after startup") {
                        info!(
                            "Resolved ifindex for {}: {}",
                            monitor.ifname, monitor.ifindex
                        );
                        probe_paths_dirty = true;
                    }
                }

                // 後備輪詢：只在沒訂閱到核心事件時才需要每 5 分鐘兜一次
                if tick_count % IFINDEX_REFRESH_TICKS == 0
                    && refresh_interface_state(&mut monitors, "periodic refresh")
                {
                    probe_paths_dirty = true;
                }

                // 依據 Metric 優先級挑選當前生效的網卡群：
                // 1. 若存活網卡 Metric 相同（例如皆為預設 10），全部加入 Multipath ECMP 做頻寬疊加分流
                // 2. 若存活網卡 Metric 不同，僅挑選 Metric 數值最小（優先級最高）的存活網卡下發為預設路由（完全主備容災）
                let min_up_metric = monitors
                    .iter()
                    .filter(|m| m.lqe.state == LinkState::Up && m.ifindex != 0)
                    .map(|m| m.metric)
                    .min();

                let is_active =
                    |m: &WanMonitor| m.lqe.state == LinkState::Up && m.ifindex != 0 && Some(m.metric) == min_up_metric;

                // 無分配的快速比較：多數 tick 存活集合其實沒變，
                // 先用迭代直接比對，只有真的變了才構建路由描述並入隊。
                let active_count = monitors.iter().filter(|m| is_active(m)).count();
                let set_unchanged = match &last_active_ifindexes {
                    // 尚未下發過任何路由：沒有存活線路時維持「不做」（不刪除既有路由）
                    None => active_count == 0,
                    Some(prev) => {
                        prev.len() == active_count
                            && monitors
                                .iter()
                                .filter(|m| is_active(m))
                                .map(|m| m.ifindex)
                                .eq(prev.iter().copied())
                    }
                };

                // 只有在指令真的進佇列時才更新 last_active_ifindexes。
                // 若佇列滿了就丟棄（worker 可能卡在 conntrack dump），
                // 保留舊值讓下一個 tick 重試，否則路由會永久停留在錯誤狀態。
                //
                // need_apply 除了「集合真的變了」以外，還包含兩種自我修復：
                //   * v4_apply_dirty：worker 回報內核拒絕（EINVAL/ENODEV…）後重下；
                //   * 心跳：集合沒變也定期重下，修復被別的程序／內核事件改掉的路由。
                let route_heartbeat =
                    tick_count % ROUTE_HEARTBEAT_TICKS == 0 && last_active_ifindexes.is_some();
                let need_apply = (!set_unchanged || (v4_apply_dirty && tick_count >= v4_retry_at)
                    || route_heartbeat)
                    && !v4_apply_inflight;

                if need_apply {
                    let new_set: Vec<u32> = monitors
                        .iter()
                        .filter(|m| is_active(m))
                        .map(|m| m.ifindex)
                        .collect();
                    if set_unchanged {
                        debug!(
                            "Re-applying IPv4 default route for {:?} (self-heal / heartbeat)",
                            new_set
                        );
                    } else {
                        info!(
                            "Active WAN set changed: {:?} -> {:?}",
                            last_active_ifindexes, new_set
                        );
                    }
                    // 存活集合一變，「哪些線需要主表 /32」也跟著變（見探針路徑那一段），
                    // 這裡標記重下，否則 /32 會停留在不該留的時候
                    probe_paths_dirty = true;

                    let current_active: Vec<ActiveWanRoute> = monitors
                        .iter()
                        .filter(|m| is_active(m))
                        .map(|m| ActiveWanRoute {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            weight: m.weight,
                            metric: m.metric,
                            underlay_targets: m.underlay_targets.clone(),
                        })
                        .collect();

                    // 只有設定了 gateway6 的網卡才會產生 IPv6 nexthop；
                    // IPv6 路由跟隨同一個 IPv4 健康狀態（同一條實體鏈路）
                    let current_active_v6: Vec<ActiveWanRouteV6> = if has_ipv6 {
                        monitors
                            .iter()
                            .filter(|m| is_active(m) && m.gateway6.is_some())
                            .map(|m| ActiveWanRouteV6 {
                                ifname: m.ifname.clone(),
                                ifindex: m.ifindex,
                                gateway: m.gateway6,
                                weight: m.weight,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    match netlink_tx.try_send(NetlinkCmd::Apply(current_active)) {
                        Ok(()) => {
                            v4_apply_inflight = true;
                            v4_apply_dirty = false;

                            // ECMP 的 nexthop 集合一變，核心就會重算 multipath hash，
                            // 既有連線可能被改送到另一條 WAN（源 IP 變了）而卡死。
                            // 因此「成員進出」時也要清一次 conntrack，而不只是 DOWN 的時候。
                            // 開機首次下發不算切換，跳過以免誤清。
                            //
                            // 清理範圍刻意收斂：
                            //   * 只有「新進入存活集合」的成員一定要清（它在 DOWN 期間
                            //     可能殘留了舊 IP 的連線，而且當時常常因為取不到 IP 而清不掉）；
                            //   * 只有真正涉及 multipath（變動前後任一側有多個成員）時，
                            //     才需要連其他存活成員一起清（內核會重算整張 hash 表）。
                            //   * 主備（metric 不同、兩側都只有一個成員）時不再波及倖存的那條，
                            //     否則「主線恢復」會無故 RST 掉備線上健康的連線。
                            if !set_unchanged && flush_on_switch && last_active_ifindexes.is_some() {
                                let prev: Vec<u32> =
                                    last_active_ifindexes.clone().unwrap_or_default();
                                let multipath_involved = prev.len() > 1 || new_set.len() > 1;
                                flush_pending.extend(
                                    monitors
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, m)| {
                                            is_active(m)
                                                && (multipath_involved
                                                    || !prev.contains(&m.ifindex))
                                        })
                                        .map(|(idx, _)| idx),
                                );
                            }
                            last_active_ifindexes = Some(new_set);

                            if has_ipv6 {
                                match netlink_tx.try_send(NetlinkCmd::ApplyV6(current_active_v6)) {
                                    Ok(()) => {
                                        v6_pending = None;
                                    }
                                    Err(err) => {
                                        let err_desc = err.to_string();
                                        // try_send 失敗時指令會原樣退回，暫存待下個 tick 重試，
                                        // 否則 v6 更新會隨 need_apply 變回 false 而永久丟失
                                        if let std::sync::mpsc::TrySendError::Full(
                                            NetlinkCmd::ApplyV6(v6),
                                        )
                                        | std::sync::mpsc::TrySendError::Disconnected(
                                            NetlinkCmd::ApplyV6(v6),
                                        ) = err
                                        {
                                            v6_pending = Some(v6);
                                        }
                                        error!(
                                            "Failed to queue kernel IPv6 FIB route update: {err_desc}. Will retry next tick."
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!(
                                "Failed to queue kernel FIB route update: {err}. Will retry next tick."
                            );
                        }
                    }
                }

                // 探針路徑（每張 WAN 一張獨立表 + `oif <wan>` 規則）：讓探針完全不依賴
                // 主表那條預設路由。這是「停線→恢復」不再自鎖的結構性保證。
                // 觸發時機：開機、ifindex 變動、上次失敗、每 30 秒定期校驗。
                if tick_count % PROBE_PATH_REFRESH_TICKS == 0 {
                    probe_paths_dirty = true;
                }
                if probe_paths_dirty && !probe_paths_inflight && tick_count >= probe_paths_retry_at {
                    // 「主表有沒有預設路由」是這一切的關鍵判斷，必須問內核，而且問的必須是
                    // **預設路由**（含我們自己下發的那條）——不能問「有沒有到目標的路」：
                    // 我們自己補的探針 /32 也是「到目標的路」，會形成自我參照
                    // （補了 → 認為已涵蓋 → 決定不補 → 把剛補的刪掉 → 又沒涵蓋 → 再補），
                    // 實測會變成裝/刪各 13 次的振盪，那條線永遠累積不到恢復所需的連續成功。
                    let main_has_default = match query_mgr
                        .as_mut()
                        .map(|q| q.has_main_default_route(AF_INET))
                    {
                        Some(Ok(has)) => has,
                        Some(Err(e)) => {
                            // 查不到時偏向「沒有」：多補一條 /32 只是短暫影響該目標的轉發，
                            // 而不補則可能讓線路永遠回不來（原本的 bug）
                            debug!("default-route query failed ({e}); assuming there is none");
                            false
                        }
                        None => false,
                    };

                    // 1) 先算每條線「想不想要」主表 /32
                    let mut wants: Vec<(usize, u32, bool, bool, bool, bool, bool)> = Vec::new();
                    for (slot, m) in monitors.iter().enumerate() {
                        if m.ifindex == 0 {
                            continue;
                        }
                        let active = is_active(m);
                        let strict = effective_rp_filter(&m.ifname) == 1;
                        let shared = monitors.iter().any(|o| {
                            o.ifname != m.ifname && o.targets.iter().any(|t| m.targets.contains(t))
                        });
                        // 活躍線走主表那條預設路由，反向檢查自然過，不需要補
                        let wants_it = !active && (!main_has_default || (strict && !shared));
                        // 「這條線能不能真的用」——用內核查詢判斷（綁定該設備時到目標有沒有路），
                        // 比看 sysfs 可靠（netns/精簡系統不一定有 /sys/class/net）：
                        // 設備已 down 時內核會回「沒有路」，我們就不該把唯一的 /32 給它。
                        let usable = match m.targets.iter().find_map(|t| match t.ip() {
                            std::net::IpAddr::V4(v4) => Some(v4),
                            std::net::IpAddr::V6(_) => None,
                        }) {
                            Some(target) => match kernel_has_route(&mut query_mgr, target, Some(m.ifindex))
                            {
                                Some(false) => false,
                                _ => interface_oper_usable(&m.ifname),
                            },
                            None => interface_oper_usable(&m.ifname),
                        };
                        wants.push((slot, m.metric, active, strict, shared, wants_it, usable));
                    }

                    // 2) 同一個目標只能有一個擁有者（主表同一前綴只有一條路由）：
                    //    在「想補」的線裡挑選，**優先挑設備真的可用的**（否則會把機會浪費在
                    //    已經 down 的線上，另一條拿不到回程路徑 → 兩條一起掉），同群再取
                    //    metric 最小者，讓主線優先被監測而不是取決於設定順序或競速。
                    let owner_of = |target: &std::net::SocketAddr| -> Option<usize> {
                        let mut pool: Vec<(usize, u32, bool)> = Vec::new();
                        for (slot, m) in monitors.iter().enumerate() {
                            if !m.targets.contains(target) {
                                continue;
                            }
                            if let Some(w) = wants.iter().find(|w| w.0 == slot) {
                                if w.5 {
                                    pool.push((slot, m.metric, w.6));
                                }
                            }
                        }
                        if pool.is_empty() {
                            return monitors
                                .iter()
                                .enumerate()
                                .filter(|(_, m)| m.targets.contains(target))
                                .min_by_key(|(slot, m)| (m.metric, *slot))
                                .map(|(slot, _)| slot);
                        }
                        let any_usable = pool.iter().any(|p| p.2);
                        pool.into_iter()
                            .filter(|p| !any_usable || p.2)
                            .min_by_key(|p| (p.1, p.0))
                            .map(|p| p.0)
                    };

                    debug!(
                        "probe-path decision: main_has_default={main_has_default}, \
                         lines=[{}]",
                        wants
                            .iter()
                            .map(|w| format!(
                                "{}:active={} strict={} shared={} want={} usable={}",
                                monitors[w.0].ifname, w.2, w.3, w.4, w.5, w.6
                            ))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );

                    let mut wanted: Vec<ProbePath> = Vec::with_capacity(monitors.len());
                    for (slot, m) in monitors.iter().enumerate() {
                        if m.ifindex == 0 {
                            continue;
                        }
                        let wants_it = wants
                            .iter()
                            .find(|w| w.0 == slot)
                            .map(|w| w.5)
                            .unwrap_or(false);
                        let main_route_targets: Vec<std::net::Ipv4Addr> = if wants_it {
                            m.targets
                                .iter()
                                .filter(|t| owner_of(t) == Some(slot))
                                .filter_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                        wanted.push(ProbePath {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            targets: m
                                .targets
                                .iter()
                                .filter_map(|t| match t.ip() {
                                    std::net::IpAddr::V4(v4) => Some(v4),
                                    std::net::IpAddr::V6(_) => None,
                                })
                                .collect(),
                            table: PROBE_TABLE_BASE + slot as u32,
                            priority: PROBE_RULE_PRIORITY_BASE + slot as u32,
                            main_route_targets,
                        });
                    }

                    let strict_shared_hit = wants
                        .iter()
                        .any(|w| !w.2 && w.3 && w.4 && main_has_default);
                    if strict_shared_hit && !strict_shared_warned {
                        strict_shared_warned = true;
                        warn!(
                            "strict rp_filter (net.ipv4.conf.<wan>.rp_filter=1) combined with SHARED probe \
                             targets cannot probe more than one WAN at a time: the reverse-path check only \
                             accepts a route via the receiving device. Set rp_filter=2 (loose) for the WAN \
                             interfaces, or give each WAN its own probe targets. Only the highest-priority \
                             (lowest metric) line will be monitored."
                        );
                    }
                    debug!(
                        "probe paths queued: [{}]",
                        wanted
                            .iter()
                            .map(|p| format!("{}->/32{:?}", p.ifname, p.main_route_targets))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );
                    match netlink_tx
                        .try_send(NetlinkCmd::SetProbePaths(wanted, probe_host_routes_cleanup))
                    {
                        Ok(()) => {
                            probe_host_routes_cleanup = false;
                            probe_paths_inflight = true;
                            probe_paths_dirty = false;
                        }
                        Err(err) => {
                            debug!("Probe path update still queued; will retry next tick: {err}");
                        }
                    }
                }

                // 路由下發之後才排程 conntrack 清理：多張網卡合併為一條指令、
                // worker 只掃一次全表。每網卡限流在這裡檢查，入隊成功才更新時間戳。
                if !flush_pending.is_empty() {
                    let now = Instant::now();
                    let mut names: Vec<String> = Vec::new();
                    let mut marked: Vec<usize> = Vec::new();
                    for idx in flush_pending {
                        let monitor = &monitors[idx];
                        if let Some(last) = monitor.last_conntrack_flush {
                            if now.duration_since(last) < conntrack_flush_min_interval {
                                debug!(
                                    "[{}] Skipping conntrack flush: within min interval",
                                    monitor.ifname
                                );
                                continue;
                            }
                        }
                        if !names.contains(&monitor.ifname) {
                            names.push(monitor.ifname.clone());
                            marked.push(idx);
                        }
                    }
                    if !names.is_empty() {
                        match netlink_tx.try_send(NetlinkCmd::FlushConntrack(names)) {
                            Ok(()) => {
                                for idx in marked {
                                    monitors[idx].last_conntrack_flush = Some(now);
                                }
                            }
                            Err(err) => {
                                warn!("Failed to queue conntrack flush: {err}");
                            }
                        }
                    }
                }

                // 每 2 個週期（約 1 秒）或狀態變更時，原子更新 /tmp/mwan4_status.json 提供給 LuCI 即時讀取
                if tick_count % 2 == 0 || state_changed {
                    let route_desc = build_route_desc(&monitors, min_up_metric);
                    write_status_file(&monitors, &route_desc);
                }

                // 每 10 個週期（約 5 秒）輸出一次所有 WAN 的即時品質摘要
                if tick_count % 10 == 0 {
                    for monitor in &monitors {
                        info!("[{}] {}", monitor.ifname, monitor.lqe.summary());
                    }
                }
            }
        }
    }

    // 7. 優雅退出
    if config.remove_routes_on_exit {
        // 移除本程式下發的預設路由，避免殘留指向已失效的鏈路。
        // 注意：這會在「舊實例已退出、新實例還沒下發」的窗口內讓整台路由器失去出口，
        // 因此預設是 false，需要明確開啟。
        if let Err(e) = netlink_tx.send(NetlinkCmd::ClearRoutes) {
            warn!("Failed to request default route cleanup: {e}");
        }
    } else {
        // 預設路由保留（避免重啟窗口斷網），但**探針路徑一定要拆掉**：
        // 那是一組 `oif <wan> lookup <table>` 規則與獨立表路由，留著會指向
        // 可能已經不存在的網關，也會讓下次啟動的規則語意變得不可預期。
        info!("Leaving the mwan4 default route in place (remove_routes_on_exit = false)");
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetProbePaths(Vec::new(), false)) {
            warn!("Failed to request probe path cleanup: {e}");
        }
    }
    // 斷開通道讓 worker 執行緒結束
    drop(netlink_tx);
    if netlink_worker.join().is_err() {
        warn!("Netlink worker thread panicked during shutdown");
    }

    let _ = std::fs::remove_file(STATUS_FILE);
    let _ = std::fs::remove_file(STATUS_TMP_FILE);
    release_pid_file();
    info!("mwan4 daemon stopped.");
    Ok(())
}

struct WanMonitor {
    ifname: String,
    ifindex: u32,
    gateway: Option<std::net::Ipv4Addr>,
    gateway6: Option<std::net::Ipv6Addr>,
    metric: u32,
    weight: u32,
    targets: Vec<std::net::SocketAddr>,
    /// 這條線若是隧道（VXLAN/WireGuard），其 underlay 對端位址；非隧道留空。
    /// 非空同時代表「不能拿這條線去當別條隧道的 underlay 出口」。
    underlay_targets: Vec<std::net::Ipv4Addr>,
    /// 快取的介面 IPv4（每次寫狀態檔都做 socket + ioctl 太昂貴）
    cached_ip: Option<std::net::Ipv4Addr>,
    /// 上次對這張網卡做 conntrack 清理的時間（用於限流）
    last_conntrack_flush: Option<Instant>,
    /// 最近一次探測失敗的原因（成功時清空）。
    /// 寫進狀態檔，讓「介面不存在／本機無路由」不再被誤認成「運營商丟包」。
    last_probe_error: Option<String>,
    /// 是否已針對「本機條件造成的失敗」告警過（同一輪只提醒一次）
    local_condition_warned: bool,
    /// 內核查詢的結論：經這張網卡到探針目標「根本沒有路」。
    /// 這種情況探針會以「超時」結束（內核按 on-link 丟進黑洞），必須另外標記，
    /// 否則日誌與介面都會把它誤報成運營商丟包。
    probe_path_missing: bool,
    /// 上次做「路徑是否存在」查詢的時間（限流，避免每 tick 都查）
    last_path_check: Option<Instant>,
    lqe: LinkQualityEstimator,
}

/// 產生 LuCI 顯示用的活躍路由描述字串。
/// 只在寫狀態檔的 tick（約每秒一次）才組裝，避免每 tick 都做字串分配。
fn build_route_desc(monitors: &[WanMonitor], min_up_metric: Option<u32>) -> String {
    let active_names: Vec<&str> = monitors
        .iter()
        .filter(|m| {
            m.lqe.state == LinkState::Up && m.ifindex != 0 && Some(m.metric) == min_up_metric
        })
        .map(|m| m.ifname.as_str())
        .collect();

    if active_names.len() > 1 {
        format!("Multipath ECMP ({})", active_names.join(", "))
    } else if active_names.len() == 1 {
        let active_wan = active_names[0];
        let min_cfg_metric = monitors.iter().map(|m| m.metric).min().unwrap_or(1);
        let max_cfg_metric = monitors.iter().map(|m| m.metric).max().unwrap_or(1);
        let my_metric = monitors
            .iter()
            .find(|m| m.ifname == active_wan)
            .map_or(1, |m| m.metric);

        if min_cfg_metric != max_cfg_metric {
            if my_metric == min_cfg_metric {
                format!("Primary Active ({active_wan})")
            } else {
                format!("Failover Active ({active_wan})")
            }
        } else {
            format!("Single Active ({active_wan})")
        }
    } else {
        "All Links DOWN".to_string()
    }
}

#[derive(serde::Serialize)]
struct InterfaceStatus {
    name: String,
    state: String,
    ip: Option<String>,
    gateway: String,
    metric: u32,
    weight: u32,
    rtt_ms: f64,
    jitter_ms: f64,
    loss_rate: f64,
    consecutive_successes: usize,
    consecutive_timeouts: usize,
    targets: Vec<String>,
    /// 內核 ifindex；0 = 這張網卡目前不存在（多半是名字寫錯或介面被停用）
    ifindex: u32,
    /// 最近一次探測失敗的原因（成功時為 null）。
    /// 用來區分「本機沒有路由／設備不存在」與「運營商丟包」。
    last_error: Option<String>,
    /// last_error 是否屬於本機條件（true 時介面上會給出不同提示）
    local_condition: bool,
}

#[derive(serde::Serialize)]
struct DaemonStatus {
    updated_at: u64,
    /// 前端據此判斷資料是否過期（秒），避免把陳舊快照當成即時狀態
    stale_after_secs: u64,
    active_routes: String,
    interfaces: Vec<InterfaceStatus>,
}

/// 判斷探針失敗是否屬於「本機條件」而非線路丟包。
///
/// 這類錯誤代表封包根本沒出去（設備不存在／本機沒有經該設備的路由／沒有權限），
/// 在日誌與狀態檔裡必須和「超時丟包」區分開——否則使用者會一直以為是運營商的問題。
fn is_local_probe_error(msg: &str) -> bool {
    const NEEDLES: [&str; 6] = [
        "No such device",
        "Network is unreachable",
        "Create socket failed",
        "Permission denied",
        "Cannot assign requested address",
        "Tokio from_std failed",
    ];
    NEEDLES.iter().any(|needle| msg.contains(needle))
}

/// 讀取某張網卡「有效」的 rp_filter 值（`all` 與該裝置取大者，與內核規則一致）。
///
/// 為什麼需要：內核的反向路徑檢查**只查主表**。strict（1）時回程必須走同一張
/// 網卡，因此非活躍線必須在主表有一條到探針目標的 /32 才收得到 SYN-ACK；
/// loose（2）時只要主表有任何到該目標的路由即可（有一條預設路由就夠）。
fn effective_rp_filter(ifname: &str) -> u8 {
    let read = |path: String| -> u8 {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0)
    };
    read("/proc/sys/net/ipv4/conf/all/rp_filter".to_string())
        .max(read(format!("/proc/sys/net/ipv4/conf/{ifname}/rp_filter")))
}

/// 這張網卡目前「可用」嗎（不是 admin down、也不是載波掉）？
///
/// 用途：主表同一個共用探針目標只能有一個 /32 擁有者，必須挑一條真的能把路由裝上的
/// 線——否則機會會浪費在已經 down 的那條上，另一條拿不到回程路徑，兩條會一起掉
/// （本地 netns 實測踩過這個坑）。讀不到（例如部分虛擬裝置沒有這個檔案）時保守回傳 true。
fn interface_oper_usable(ifname: &str) -> bool {
    match std::fs::read_to_string(format!("/sys/class/net/{ifname}/operstate")) {
        Ok(state) => {
            let state = state.trim();
            state != "down" && state != "lowerlayerdown"
        }
        Err(_) => true,
    }
}

/// 問內核「這個目標有沒有路」。`oif` 有值時問的是「綁定該設備時有沒有路」。
///
/// 回傳 `None` = 查不到（socket 不可用或查詢失敗），呼叫端要保守處理。
fn kernel_has_route(
    mgr: &mut Option<RouteManager>,
    target: std::net::Ipv4Addr,
    oif: Option<u32>,
) -> Option<bool> {
    let mgr = mgr.as_mut()?;
    match mgr.lookup_route(target, oif) {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(e) => {
            debug!("route lookup for {target} (oif {oif:?}) failed: {e}");
            None
        }
    }
}

fn write_status_file(monitors: &[WanMonitor], active_routes: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut iface_statuses = Vec::with_capacity(monitors.len());
    for m in monitors {
        iface_statuses.push(InterfaceStatus {
            name: m.ifname.clone(),
            state: m.lqe.state.to_string(),
            ip: m.cached_ip.map(|ip| ip.to_string()),
            gateway: m.gateway.map_or_else(|| "-".to_string(), |g| g.to_string()),
            metric: m.metric,
            weight: m.weight,
            rtt_ms: (m.lqe.rtt_ewma_ms.unwrap_or(0.0) * 100.0).round() / 100.0,
            jitter_ms: (m.lqe.jitter_ewma_ms * 100.0).round() / 100.0,
            loss_rate: (m.lqe.loss_rate() * 10000.0).round() / 100.0,
            consecutive_successes: m.lqe.consecutive_successes,
            consecutive_timeouts: m.lqe.consecutive_timeouts,
            targets: m.targets.iter().map(|t| t.to_string()).collect(),
            ifindex: m.ifindex,
            last_error: m.last_probe_error.clone(),
            local_condition: m
                .last_probe_error
                .as_deref()
                .is_some_and(is_local_probe_error)
                || m.probe_path_missing,
        });
    }

    let status = DaemonStatus {
        updated_at: now,
        stale_after_secs: STATUS_STALE_SECS,
        active_routes: active_routes.to_string(),
        interfaces: iface_statuses,
    };

    if let Ok(json) = serde_json::to_string(&status) {
        if std::fs::write(STATUS_TMP_FILE, json).is_ok() {
            let _ = std::fs::rename(STATUS_TMP_FILE, STATUS_FILE);
        }
    }
}
