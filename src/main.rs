use log::{debug, error, info, warn};
use std::env;
use std::io;
use std::process;
use std::time::{Duration, Instant};

mod config;
mod lqe;
mod netlink;
mod prober;

use config::{DaemonConfig, MultipathHashPolicy, WeightMode};
use lqe::{LinkQualityEstimator, LinkState};
use netlink::conntrack::ConntrackManager;
use netlink::route::{
    AF_INET, ActiveWanRoute, ActiveWanRouteV6, InstalledVariant, POLICY_RULE_PRIORITY_BASE,
    PROBE_RULE_PRIORITY_BASE, PROBE_TABLE_BASE, PolicyRule, ProbePath, RouteManager,
};
use netlink::util::if_nametoindex;

const STATUS_FILE: &str = "/tmp/mwan4_status.json";
const STATUS_TMP_FILE: &str = "/tmp/mwan4_status.json.tmp";
/// 單實例鎖：避免兩個 mwan4 行程互相搶奪同一條預設路由
const PID_FILE: &str = "/var/run/mwan4.pid";

/// PID 檔路徑（可用 `MWAN4_PID_FILE` 覆蓋）。
/// 供整合測試在 userns/netns 裡跑（那些環境寫不進 /var/run）。
fn pid_file_path() -> String {
    std::env::var("MWAN4_PID_FILE").unwrap_or_else(|_| PID_FILE.to_string())
}

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

/// PID 檔案持有的 flock；行程存活期間一直開著（行程結束由核心自動釋放）。
static PID_FILE_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// 檢查是否已有另一個 mwan4 行程在跑，並取得 PID 檔案的獨佔鎖。
///
/// 為什麼用 `flock` 而不是「讀 PID → 查 /proc/<pid>」：
/// - 兩個實例同時啟動時，讀-判斷-寫之間有 race，可能都通過檢查；
/// - 行程被 abort（panic=abort）後舊 PID 會被核心複用，新實例看到 /proc/<pid>
///   存在就誤判「已經有實例在跑」而拒絕啟動，procd 進入無盡重試。
///
/// flock 隨行程結束自動釋放，兩種問題都不存在。檔案內容只是給人看的。
fn acquire_pid_file() -> Result<(), String> {
    let pid_file = pid_file_path();
    let path = std::path::Path::new(&pid_file);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("failed to open {pid_file}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                let existing = std::fs::read_to_string(path).unwrap_or_default();
                return Err(format!(
                    "another mwan4 instance is already running (pid {}); refusing to start",
                    existing.trim()
                ));
            }
            return Err(format!("failed to lock {pid_file}: {e}"));
        }
    }

    {
        use std::io::Write;
        file.set_len(0)
            .map_err(|e| format!("failed to truncate {pid_file}: {e}"))?;
        write!(file, "{}", process::id())
            .map_err(|e| format!("failed to write {pid_file}: {e}"))?;
        file.flush()
            .map_err(|e| format!("failed to flush {pid_file}: {e}"))?;
    }

    let _ = PID_FILE_LOCK.set(file);
    Ok(())
}

fn release_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
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
    FlushConntrack(Vec<ConntrackTarget>),
    /// 同步策略分流規則（`from`/`to` + 各 WAN 獨立表；空集合 = 全部移除）
    SetPolicies(Vec<PolicyRule>),
    /// 優雅退出：移除本程式下發的預設路由
    ClearRoutes,
}

type NetlinkSender = std::sync::mpsc::SyncSender<NetlinkCmd>;

/// conntrack 清理目標：網卡名 +「DOWN 判定時記下的最後已知 IPv4」。
///
/// 為什麼要帶舊 IP：flush 是延後執行的，PPPoE 重撥 / USB 重插 / netifd 拆介面
/// 之後現查 IP 會失敗或換新；沒有舊 IP 就清不到 NAT 到舊位址的既有連線
/// ——正是「長連線卡死」最需要清理的場景。
type ConntrackTarget = (String, Option<std::net::Ipv4Addr>);

/// worker 執行過的「全量期望狀態」操作種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkOp {
    Ipv4Routes,
    Ipv6Routes,
    ProbePaths,
    Conntrack,
    Policies,
}

/// 操作結果回報：主迴圈據此判斷「已入佇列」是否真的生效，
/// 失敗就強制下個 tick 重下（而不是像以前一樣只印一行 error 就永久停留）。
#[derive(Debug, Clone)]
struct NetlinkOutcome {
    op: NetlinkOp,
    ok: bool,
    /// 失敗原因（給主迴圈做去重告警用；成功時為 None）
    detail: Option<String>,
    /// 操作完成後「核心實際生效的 IPv4 預設路由變體」（僅 Ipv4Routes 會帶）。
    /// `ecmp_mode=auto` 可能在內核不支援時退回 standard，主迴圈必須知道實情。
    variant: Option<InstalledVariant>,
}

impl NetlinkOutcome {
    fn new(op: NetlinkOp, ok: bool, detail: Option<String>) -> Self {
        Self {
            op,
            ok,
            detail,
            variant: None,
        }
    }

    fn with_variant(mut self, variant: InstalledVariant) -> Self {
        self.variant = Some(variant);
        self
    }
}

type NetlinkResultSender = std::sync::mpsc::Sender<NetlinkOutcome>;
type NetlinkResultReceiver = std::sync::mpsc::Receiver<NetlinkOutcome>;

fn spawn_netlink_worker(
    route_mgr: RouteManager,
    conntrack_mgr: ConntrackManager,
) -> io::Result<(
    NetlinkSender,
    NetlinkResultReceiver,
    std::thread::JoinHandle<()>,
)> {
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
                let mut flush: Vec<ConntrackTarget> = Vec::new();
                let mut policies: Option<Vec<PolicyRule>> = None;
                let mut clear_routes = false;
                for c in batch {
                    match c {
                        NetlinkCmd::Apply(wans) => apply = Some(wans),
                        NetlinkCmd::ApplyV6(wans) => apply_v6 = Some(wans),
                        NetlinkCmd::SetProbePaths(paths, clean) => {
                            probe_paths = Some((paths, clean))
                        }
                        NetlinkCmd::FlushConntrack(targets) => {
                            for (name, ip) in targets {
                                match flush.iter_mut().find(|(n, _)| *n == name) {
                                    Some((_, existing)) => {
                                        if existing.is_none() {
                                            *existing = ip;
                                        }
                                    }
                                    None => flush.push((name, ip)),
                                }
                            }
                        }
                        NetlinkCmd::SetPolicies(rules) => policies = Some(rules),
                        NetlinkCmd::ClearRoutes => clear_routes = true,
                    }
                }

                if let Some(wans) = apply {
                    let (ok, detail, variant) = match route_mgr.apply_default_routes(&wans) {
                        Ok(()) => (true, None, Some(route_mgr.installed_ipv4_variant())),
                        Err(e) => {
                            debug!("Failed to update kernel IPv4 FIB routes: {e}");
                            (false, Some(e.to_string()), None)
                        }
                    };
                    let outcome = match variant {
                        Some(v) => {
                            NetlinkOutcome::new(NetlinkOp::Ipv4Routes, ok, detail).with_variant(v)
                        }
                        None => NetlinkOutcome::new(NetlinkOp::Ipv4Routes, ok, detail),
                    };
                    let _ = result_tx.send(outcome);
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
                        // 也一起清掉（只清當前設定裡有的目標是不夠的）。
                        // **只清探針 /32**：同一批指令裡的 Apply 才剛裝好 underlay /32，
                        // 連它一起清就會讓隧道封裝封包走 ECMP 自環（見 route.rs 的
                        // RUNTIME_SWEEP_METRICS 說明；啟動前那次才清 underlay）。
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
                if let Some(rules) = policies {
                    let (ok, detail) = match route_mgr.set_policy_rules(&rules) {
                        Ok(()) => (true, None),
                        Err(e) => {
                            debug!("Policy rule update failed: {e}");
                            (false, Some(e.to_string()))
                        }
                    };
                    let _ = result_tx.send(NetlinkOutcome::new(NetlinkOp::Policies, ok, detail));
                }
                if !flush.is_empty() {
                    let names = flush
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let (ok, detail) = match conntrack_mgr.flush_interfaces_conntrack(&flush) {
                        Ok(_) => (true, None),
                        Err(e) => {
                            debug!("[{names}] Conntrack flush failed: {e}");
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
        .map_err(|e| io::Error::other(format!("cannot spawn netlink worker thread: {e}")))?;

    Ok((tx, result_rx, handle))
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
        monitor.refresh_cached_ip();
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
        monitor.refresh_cached_ip();
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
    // 清掉上一次執行可能留下的主表 /32：探針（metric 42760）與隧道 underlay（42761）
    // 都在這裡清。按專屬 metric 轉儲掃描，能涵蓋已從設定移除、或當時設備還不存在的目標；
    // underlay /32 的出口（ifindex/gateway）上次執行可能已經不同，開機時一次清乾淨，
    // 之後由 apply_default_routes → sync_underlay_routes 按當前期望重新補回。
    // 執行期（SetProbePaths 的 clean）則只清探針 /32——那裡清 underlay 會把剛裝好的刪掉。
    match route_mgr.sweep_all_own_host_routes() {
        Ok(0) => {}
        Ok(n) => info!("Cleaned up {n} leftover mwan4 host route(s) on startup"),
        Err(e) => warn!("Failed to clean up leftover mwan4 host routes: {e}"),
    }
    // 策略分流規則的保留區段也先清：上次執行的規則可能指向已不存在的表/網關，
    // 或與這次的 policy 集合不同（`set_policy_rules` 只信記憶體快取）。
    if let Err(e) = route_mgr.sweep_policy_rules() {
        warn!("Failed to sweep stale policy rules on startup: {e}");
    }
    // 只用來「問內核路徑」的查詢用 socket：判斷主表有沒有涵蓋目標、以及探針失敗時
    // 是不是「本機根本沒有路」。與 worker 的寫入 socket 分開，避免互相干擾。
    let mut query_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => {
            // 這是事件迴圈上同步使用的查詢 socket：逾時縮短到 300ms，避免內核一時
            // 不回應時每次查詢阻塞 2 秒（多張網卡疊加會凍住整個 current_thread runtime）
            if let Err(e) = m.set_netlink_timeout(Duration::from_millis(300)) {
                warn!(
                    "Failed to shorten netlink query socket timeouts ({e}); \
                     queries may block longer than expected"
                );
            }
            Some(m)
        }
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
    // worker 執行緒建立失敗（極端資源不足）不該用 expect 直接 abort：
    // panic=abort 下 expect 會讓進程在 pid 檔與路由清理之前直接消失。
    let (netlink_tx, netlink_rx, netlink_worker) =
        match spawn_netlink_worker(route_mgr, conntrack_mgr) {
            Ok(parts) => parts,
            Err(e) => {
                error!("Failed to start the netlink worker: {e}");
                release_pid_file();
                process::exit(1);
            }
        };

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
            effective_weight: iface_cfg.weight,
            last_tx_bytes: None,
            last_rx_bytes: None,
            last_stats_at: None,
            tx_bps: 0.0,
            rx_bps: 0.0,
            tx_bps_ewma: 0.0,
            rx_bps_ewma: 0.0,
            load_ewma_ready: false,
            load_pressure_active: false,
            down_bps_capacity: iface_cfg.max_mbps.map(|mbps| mbps * 1_000_000.0),
            up_bps_capacity: iface_cfg
                .up_mbps
                .or(iface_cfg.max_mbps)
                .map(|mbps| mbps * 1_000_000.0),
            targets: iface_cfg.probe_targets.clone(),
            preferred_target: 0,
            underlay_targets: iface_cfg.underlay_targets.clone(),
            cached_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_known_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_conntrack_flush: None,
            last_probe_error: None,
            last_error_is_local: false,
            local_condition_warned: false,
            probe_path_missing: false,
            last_path_check: None,
            down_since: None,
            last_down_at: None,
            flushed_while_down: false,
            lqe: LinkQualityEstimator::new(iface_cfg.name.clone(), &config),
        });
    }

    // 只有至少一張網卡設定了 gateway6 才需要處理 IPv6 路由
    let has_ipv6 = monitors.iter().any(|m| m.gateway6.is_some());
    if has_ipv6 {
        info!("IPv6 default route management enabled (interfaces with gateway6)");
    }

    // 多路徑哈希策略（選填）：寫入內核 sysctl，改善 flow 分流的均勻度。
    // 失敗只告警（舊內核沒有這個檔案），不影響啟動。
    if let Some(policy) = config.multipath_hash_policy {
        apply_multipath_hash_policy(policy, has_ipv6);
    }

    // 6. 主非同步事件循環 (Single-threaded Non-blocking Event Loop)
    let probe_interval = Duration::from_millis(config.check_interval_ms);
    let probe_timeout = Duration::from_millis(config.probe_timeout_ms);
    let conntrack_flush_min_interval =
        Duration::from_millis(config.conntrack_flush_min_interval_ms);
    // 使用 resilient nexthop group 時，核心只會重映射故障成員的 flow，其餘連線本來
    // 就不會斷；這時若還在「成員變動」時清 conntrack，反而會親手打斷那些被保留的連線。
    // 因此實際安裝的是 resilient 時關閉 flush-on-switch（flush-on-down 仍然保留：
    // 已死鏈路上的連線本來就該清掉）。
    //
    // FIX-8：判斷依據是 worker 回報的**實際安裝變體**，而不是設定值 `ecmp_mode`——
    // `auto` 在內核不支援 resilient（< 5.14 或成員數超限）而退回 standard 時，
    // 仍必須在切換瞬間清 conntrack。首次回報前保守視為 standard（與預設一致）。
    let mut kernel_resilient = false;
    let mut kernel_variant_known = false;
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
    // conntrack 清理失敗的告警去重（同一種錯誤只提醒一次，之後每 20 次一次）
    let mut conntrack_fail_count: u64 = 0;
    let mut last_conntrack_fail: Option<String> = None;
    // netlink worker 意外結束只告警一次（避免每個 tick 刷屏）
    let mut netlink_worker_gone = false;
    // strict rp_filter + 共用探針目標的告警只說一次
    let mut strict_shared_warned = false;
    // 「全部線路都降級、仍保底承載一條」的告警去重（品質恢復後重新允許告警）
    let mut degrade_fallback_warned = false;
    // 動態/容量權重狀態：更新限速 + 需要重下路由的旗標。
    // 起點刻意往前推一個 interval，讓第一個 tick 就算出容量比例/品質權重，
    // 而不是先跑 10 秒的設定 weight 才切換。
    let dynamic_weight_interval = Duration::from_millis(config.dynamic_weight_interval_ms);
    let mut weights_dirty = false;
    let mut last_weight_update = Instant::now()
        .checked_sub(dynamic_weight_interval)
        .unwrap_or_else(Instant::now);
    // 策略分流規則的下發狀態（差異比對 + 失敗重試 + 定期心跳）
    let mut policies_dirty = !config.policies.is_empty();
    let mut policies_inflight = false;
    let mut policies_retry_at: u64 = 0;
    let mut last_policy_signature: Option<Vec<PolicyRule>> = None;

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
                                if let Some(variant) = outcome.variant {
                                    let resilient = variant == InstalledVariant::Resilient;
                                    if !kernel_variant_known || resilient != kernel_resilient {
                                        kernel_variant_known = true;
                                        kernel_resilient = resilient;
                                        info!(
                                            "Installed IPv4 default route variant: {} \
                                             (flush_conntrack_on_switch {})",
                                            if resilient {
                                                "resilient nexthop group"
                                            } else {
                                                "standard ECMP"
                                            },
                                            if config.flush_conntrack_on_switch && !resilient {
                                                "enabled"
                                            } else {
                                                "suppressed"
                                            }
                                        );
                                    }
                                }
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
                        NetlinkOp::Conntrack => {
                            if !outcome.ok {
                                let detail =
                                    outcome.detail.unwrap_or_else(|| "unknown".into());
                                conntrack_fail_count += 1;
                                if last_conntrack_fail.as_deref() != Some(detail.as_str())
                                    || conntrack_fail_count % 20 == 1
                                {
                                    warn!(
                                        "Conntrack flush failed ({detail}); will retry while the \
                                         link stays down (occurrence {conntrack_fail_count})"
                                    );
                                    last_conntrack_fail = Some(detail);
                                }
                                // 失敗的 flush 不能算「本次 DOWN 已清」：把仍在 DOWN 的線
                                // 重設，靜默期與限流過後會再送一次（清理本身冪等）。
                                for monitor in monitors.iter_mut() {
                                    if monitor.down_since.is_some() {
                                        monitor.flushed_while_down = false;
                                    }
                                }
                            } else {
                                conntrack_fail_count = 0;
                                last_conntrack_fail = None;
                            }
                        }
                        NetlinkOp::Policies => {
                            policies_inflight = false;
                            if !outcome.ok {
                                // 保留舊簽章不動：下個週期會重送同一份期望狀態
                                policies_dirty = true;
                                policies_retry_at = tick_count + 6;
                            }
                        }
                    }
                }

                // worker 若意外結束，try_recv 只回 Disconnected，上面的 while let 直接跳出
                // 且不會有任何告警——inflight 旗標會永遠卡住，看起來像「一直在等下發」。
                if !netlink_worker_gone
                    && matches!(
                        netlink_rx.try_recv(),
                        Err(std::sync::mpsc::TryRecvError::Disconnected)
                    )
                {
                    netlink_worker_gone = true;
                    error!(
                        "Netlink worker exited unexpectedly; kernel routes and conntrack will no \
                         longer be updated until the service is restarted"
                    );
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
                    probe_futs.push(prober::probe_interface(
                        &monitor.ifname,
                        &monitor.targets,
                        probe_timeout,
                        monitor.preferred_target,
                    ));
                }
                let samples = futures_util::future::join_all(probe_futs).await;
                let mut state_changed = false;
                // 本 tick 內需要清理 conntrack 的網卡（以 monitors 下標記錄）。
                // bool = 是否來自 flush-on-down：只有這種來源才需要在「成功入隊之後」
                // 標記 `flushed_while_down`（flush-on-switch 時線路仍是 UP，沒有這回事）。
                // 統一延後到路由下發之後才入隊：conntrack 全表 dump 可達數秒，
                // 排在 Apply 前面（同一 worker 執行緒 FIFO）會拖慢故障切換的實際收斂。
                let mut flush_pending: Vec<(usize, bool)> = Vec::new();

                // 餵入樣本更新各鏈路 LQE 狀態機
                for (monitor, sample) in monitors.iter_mut().zip(samples.into_iter()) {
                    // 探通的目標成為下個週期的主目標：健康時每週期只發一條探針。
                    // 某個目標被過濾時，它先失敗一次，之後由探通的那個接手，不會每週期
                    // 都白吃一次超時；直到接手的主目標也失敗才會再回退到它。
                    if sample.success {
                        if let Some(idx) = monitor.targets.iter().position(|t| *t == sample.target) {
                            monitor.preferred_target = idx;
                        }
                    }

                    let (new_state, changed) = monitor.lqe.update(&sample);
                    if changed {
                        state_changed = true;
                        // 狀態切換時順勢刷新快取的 IP
                        monitor.refresh_cached_ip();

                        // 只記錄「何時進入 DOWN」（以及恢復時重置），
                        // 真正的 conntrack 清理延後到確認這不是短暫抖動之後，
                        // 見下方「抖動保護」排程處的說明。
                        match new_state {
                            LinkState::Down => {
                                let now = Instant::now();
                                monitor.down_since = Some(now);
                                monitor.last_down_at = Some(now);
                            }
                            _ => {
                                monitor.down_since = None;
                                monitor.flushed_while_down = false;
                            }
                        }
                    }

                    // 記錄最近一次失敗原因：這是現場區分「線路真的丟包」與
                    // 「本機沒有路由／設備名錯誤」的唯一線索，必須進狀態檔。
                    match sample.error_msg.as_deref() {
                        Some(msg) => {
                            let is_local = sample.error_kind == Some(prober::ProbeErrorKind::Local);
                            monitor.last_error_is_local = is_local;
                            if is_local && !monitor.local_condition_warned {
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
                            monitor.last_error_is_local = false;
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
                // 1. 若存活網卡 Metric 相同（例如皆為預設 10），全部加入 Multipath ECMP 做分流
                //    （按 flow 哈希，多並行連線的總吞吐可疊加）
                // 2. 若存活網卡 Metric 不同，僅挑選 Metric 數值最小（優先級最高）的存活網卡下發為預設路由（完全主備容災）
                let min_up_metric = monitors
                    .iter()
                    .filter(|m| m.lqe.state == LinkState::Up && m.ifindex != 0)
                    .map(|m| m.metric)
                    .min();

                // 「Up 且 metric 最小」= 尚未計入降級前的承載資格。
                // ⚠️ 探針主表 /32 的 wants_it（下方 probe-path 決策）必須用這個，
                // **不能**用 is_active：那裡的 `!active` 語意是「這條線當前不承載流量」，
                // 而降級的線只是被移出 ECMP（仍在探測、仍是 Up 且 metric 最小），
                // 不該被當成「非活躍線」去搶主表 /32。
                let up_primary = |m: &WanMonitor| {
                    m.lqe.state == LinkState::Up && m.ifindex != 0 && Some(m.metric) == min_up_metric
                };

                // 基於實測品質的降級：窗口已滿且丟包率達到 degrade_loss_threshold 的線
                // 不參與 ECMP（但仍繼續探測，品質恢復後自動回歸）。
                // 舊行為只看「有沒有判 DOWN」，於是 20%~50% 丟包的線照樣吃一半流量。
                let any_undegraded = monitors
                    .iter()
                    .any(|m| up_primary(m) && !m.lqe.is_degraded());
                // 保底：全部降級時不能一條都不承載（否則會完全沒有預設路由），
                // 在「Up 且 metric 最小」的線裡取設定順序最前面的那條。
                let degrade_fallback_slot = if any_undegraded {
                    None
                } else {
                    monitors
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| up_primary(m))
                        .min_by_key(|(slot, m)| (m.metric, *slot))
                        .map(|(slot, _)| slot)
                };
                match degrade_fallback_slot {
                    None => degrade_fallback_warned = false,
                    Some(slot) => {
                        if !degrade_fallback_warned {
                            degrade_fallback_warned = true;
                            warn!(
                                "[{}] All usable WANs are degraded (window loss >= {:.1}%); \
                                 keeping it as the default route anyway so the router is not left \
                                 without an exit. It is still being probed and will rejoin the \
                                 other WANs as soon as its loss drops",
                                monitors[slot].ifname,
                                config.degrade_loss_threshold * 100.0
                            );
                        }
                    }
                }

                let is_active = |slot: usize, m: &WanMonitor| {
                    up_primary(m) && (!m.lqe.is_degraded() || degrade_fallback_slot == Some(slot))
                };

                // 取樣各 WAN 的即時速率（狀態檔 / LuCI 顯示用，也讓分流效果可驗證）
                let stats_now = Instant::now();
                for monitor in monitors.iter_mut() {
                    sample_interface_rates(monitor, stats_now);
                }

                // 動態權重：`weight_mode = quality`（依 LQE 品質）與 `load_aware`
                // （依實測速率 vs 容量）可獨立或疊加。更新有限速——每次變更都會重下
                // ECMP 路由，內核可能重算 multipath hash，過度頻繁會反覆打斷既有 flow。
                // 品質差到門檻的線仍由降級/DOWN 機制移出。
                // 容量比例分流（有 max_mbps）本身也是動態下發的一部分：
                // 基準權重由 weight 換成 ∝ max_mbps，必須走同一條重下路徑。
                let dynamic_weights_on = config.weight_mode == WeightMode::Quality
                    || config.load_aware
                    || config.capacity_weights_on();
                if dynamic_weights_on && last_weight_update.elapsed() >= dynamic_weight_interval {
                    let active_flags: Vec<bool> = monitors
                        .iter()
                        .enumerate()
                        .map(|(slot, m)| is_active(slot, m))
                        .collect();
                    if config.load_aware {
                        update_load_pressure(
                            &mut monitors,
                            &active_flags,
                            config.load_target_ratio,
                            config.load_recover_ratio,
                        );
                    }
                    let new_weights =
                        compute_dynamic_weights(&monitors, |slot, _| active_flags[slot], &config);
                    let changed = monitors
                        .iter()
                        .enumerate()
                        .any(|(slot, m)| m.effective_weight != new_weights[slot]);
                    if changed {
                        let desc: Vec<String> = monitors
                            .iter()
                            .enumerate()
                            .filter(|(slot, m)| m.effective_weight != new_weights[*slot])
                            .map(|(slot, m)| {
                                format!(
                                    "{}:{}->{}",
                                    m.ifname, m.effective_weight, new_weights[slot]
                                )
                            })
                            .collect();
                        info!(
                            "Dynamic ECMP weights updated (quality={}, load={}, capacity={}): {}",
                            config.weight_mode == WeightMode::Quality,
                            config.load_aware,
                            config.capacity_weights_on(),
                            desc.join(" ")
                        );
                        for (slot, monitor) in monitors.iter_mut().enumerate() {
                            monitor.effective_weight = new_weights[slot];
                        }
                        weights_dirty = true;
                    }
                    last_weight_update = Instant::now();
                }

                // 無分配的快速比較：多數 tick 存活集合其實沒變，
                // 先用迭代直接比對，只有真的變了才構建路由描述並入隊。
                let active_count = monitors
                    .iter()
                    .enumerate()
                    .filter(|(slot, m)| is_active(*slot, m))
                    .count();
                let set_unchanged = match &last_active_ifindexes {
                    // 尚未下發過任何路由：沒有存活線路時維持「不做」（不刪除既有路由）
                    None => active_count == 0,
                    Some(prev) => {
                        prev.len() == active_count
                            && monitors
                                .iter()
                                .enumerate()
                                .filter(|(slot, m)| is_active(*slot, m))
                                .map(|(_, m)| m.ifindex)
                                .eq(prev.iter().copied())
                    }
                };

                // 只有在指令真的進佇列時才更新 last_active_ifindexes。
                // 若佇列滿了就丟棄（worker 可能卡在 conntrack dump），
                // 保留舊值讓下一個 tick 重試，否則路由會永久停留在錯誤狀態。
                //
                // need_apply 除了「集合真的變了」以外，還包含三種自我修復：
                //   * weights_dirty：動態權重剛更新；
                //   * v4_apply_dirty：worker 回報內核拒絕（EINVAL/ENODEV…）後重下；
                //   * 心跳：集合沒變也定期重下，修復被別的程序／內核事件改掉的路由。
                let route_heartbeat =
                    tick_count % ROUTE_HEARTBEAT_TICKS == 0 && last_active_ifindexes.is_some();
                let need_apply = (!set_unchanged
                    || weights_dirty
                    || (v4_apply_dirty && tick_count >= v4_retry_at)
                    || route_heartbeat)
                    && !v4_apply_inflight;

                if need_apply {
                    let new_set: Vec<u32> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| m.ifindex)
                        .collect();
                    if set_unchanged {
                        debug!(
                            "Re-applying IPv4 default route for {:?} \
                             (self-heal / heartbeat / dynamic weights)",
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
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| ActiveWanRoute {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            weight: m.effective_weight,
                            metric: m.metric,
                            underlay_targets: m.underlay_targets.clone(),
                        })
                        .collect();

                    // 只有設定了 gateway6 的網卡才會產生 IPv6 nexthop；
                    // IPv6 路由跟隨同一個 IPv4 健康狀態（同一條實體鏈路）
                    let current_active_v6: Vec<ActiveWanRouteV6> = if has_ipv6 {
                        monitors
                            .iter()
                            .enumerate()
                            .filter(|(slot, m)| is_active(*slot, m) && m.gateway6.is_some())
                            .map(|(_, m)| ActiveWanRouteV6 {
                                ifname: m.ifname.clone(),
                                ifindex: m.ifindex,
                                gateway: m.gateway6,
                                weight: m.effective_weight,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    match netlink_tx.try_send(NetlinkCmd::Apply(current_active)) {
                        Ok(()) => {
                            v4_apply_inflight = true;
                            v4_apply_dirty = false;
                            weights_dirty = false;

                            // ECMP 的 nexthop 集合一變，核心就會重算 multipath hash，
                            // 既有連線可能被改送到另一條 WAN（源 IP 變了）而卡死，
                            // 所以「成員新進入存活集合」時要清一次 conntrack，
                            // 而不只是該線自己判 DOWN 的時候。開機首次下發不算切換，跳過。
                            //
                            // 清理名單只包含「新進入存活集合」的成員：
                            //   `is_active(m) && !prev.contains(&m.ifindex)`
                            // 為什麼不再連坐其他存活成員——修復前的條件是
                            // `is_active(m) && (multipath_involved || !prev.contains(&m.ifindex))`，
                            // 而 `multipath_involved = prev.len() > 1 || new_set.len() > 1`
                            // 在雙線 ECMP 下**恆為真**，於是只要成員集合一變，所有存活成員
                            // （包含一直健康的那條）都被列入清理名單；而清理本身是按 WAN IP
                            // 匹配 ORIG/REPLY（conntrack.rs），列進名單等於清掉該線全部連線。
                            // 實測日誌：
                            //   [INFO ] [Conntrack] Flushing active conntrack sessions for wan1 ...
                            //   [INFO ] [Conntrack] Flushing active conntrack sessions for wan0, wan1 ...
                            // 只有 wan1 健康卻被清、恢復瞬間兩條都清 → NAT 後的連線被 RST，
                            // 使用者看到的就是「網站打不開、連線斷掉」。
                            //
                            // 離開集合的成員本來就不在 is_active 裡，由 flush-on-down 的
                            // 25 秒靜默路徑（CONNTRACK_FLUSH_DOWN_QUIET）負責清理。
                            //
                            // flush-on-switch 是否生效由「實際安裝變體」決定（FIX-8）：
                            // resilient 只重映射故障成員的 bucket，清 conntrack 反而
                            // 會親手打斷被保留的連線，所以只有 standard 才清。
                            let flush_on_switch =
                                config.flush_conntrack_on_switch && !kernel_resilient;
                            if !set_unchanged && flush_on_switch && last_active_ifindexes.is_some() {
                                let prev: Vec<u32> =
                                    last_active_ifindexes.clone().unwrap_or_default();
                                flush_pending.extend(
                                    monitors
                                        .iter()
                                        .enumerate()
                                        .filter(|(slot, m)| {
                                            is_active(*slot, m)
                                                && !prev.contains(&m.ifindex)
                                                // 剛從 DOWN 回來的線還在抖動靜默期：
                                                // flush-on-switch 若在此時清它，等於繞過
                                                // 25 秒保護，把「其實還活著」的連線砍掉
                                                // （README 承諾「期間若恢復就不清」）。
                                                && !m.last_down_at.is_some_and(|t| {
                                                    t.elapsed() < CONNTRACK_FLUSH_DOWN_QUIET
                                                })
                                        })
                                        .map(|(idx, _)| (idx, false)),
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
                        // 「承載中」= Up 且 metric 最小，**不排除降級的線**。
                        //
                        // ⚠️ 這裡刻意不用 is_active：這個 `!active` 的語意是「這條線當前
                        // 不承載流量 → 需要主表 /32 才收得到回程」。降級的線只是被移出
                        // ECMP，它仍在探測、仍是 Up 且 metric 最小；若把它算成「非活躍線」，
                        // 它就會以「想補 /32」的身分去跟真正承載的線搶同一個目標的 /32
                        // （owner_of 只挑一個擁有者），反而讓承載中的線拿不到回程路徑。
                        let primary = up_primary(m);
                        let strict = effective_rp_filter(&m.ifname) == 1;
                        let shared = monitors.iter().any(|o| {
                            o.ifname != m.ifname && o.targets.iter().any(|t| m.targets.contains(t))
                        });
                        // 活躍線走主表那條預設路由，反向檢查自然過，不需要補
                        let wants_it = !primary && (!main_has_default || (strict && !shared));
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
                        wants.push((slot, m.metric, primary, strict, shared, wants_it, usable));
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
                                "{}:up_primary={} strict={} shared={} want={} usable={}",
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

                // 策略分流規則（from/to + 各 WAN 獨立表）：目標 WAN DOWN 時整條政策
                // 從期望集合移除（流量回退 ECMP），恢復後自動回來；定期心跳重下，
                // 修復被外部刪掉的規則（`set_policy_rules` 內部做差異比對）。
                if tick_count % PROBE_PATH_REFRESH_TICKS == 0 {
                    policies_dirty = true;
                }
                let policy_wanted = build_policy_rules(&config, &monitors);
                let policy_changed =
                    last_policy_signature.as_deref() != Some(policy_wanted.as_slice());
                if (policy_changed || policies_dirty)
                    && !policies_inflight
                    && tick_count >= policies_retry_at
                {
                    debug!(
                        "Policy rule update queued: {} rule(s) from {} configured policies",
                        policy_wanted.len(),
                        config.policies.len()
                    );
                    match netlink_tx.try_send(NetlinkCmd::SetPolicies(policy_wanted.clone())) {
                        Ok(()) => {
                            policies_inflight = true;
                            policies_dirty = false;
                            last_policy_signature = Some(policy_wanted);
                        }
                        Err(err) => {
                            debug!("Policy rule update still queued; will retry next tick: {err}");
                        }
                    }
                }

                // 路由下發之後才排程 conntrack 清理：多張網卡合併為一條指令、
                // worker 只掃一次全表。每網卡限流在這裡檢查，入隊成功才更新時間戳。
                //
                // 抖動保護（重要）：線路剛被判 DOWN 就清 conntrack，會把該線路上「其實還活著」
                // 的連線一次全砍掉。實測隧道抖動觸發一次 DOWN 就砍了 495 條，使用者直接看到
                // 「網站打不開、連線斷掉」，而幾秒後線路自己就恢復了。
                // 因此這裡改成：DOWN 之後再等 CONNTRACK_FLUSH_DOWN_QUIET，確認它「持續」
                // 不可用才清；期間若恢復（抖動），連線就保住了，代價只是晚幾秒切換。
                if config.flush_conntrack_on_down {
                    let now = Instant::now();
                    for (idx, monitor) in monitors.iter().enumerate() {
                        if monitor.flushed_while_down {
                            continue;
                        }
                        if let Some(since) = monitor.down_since {
                            if now.duration_since(since) >= CONNTRACK_FLUSH_DOWN_QUIET {
                                // ⚠️ 這裡只收集，**不**先標記 `flushed_while_down`：
                                // 下面還有 `conntrack_flush_min_interval` 限流，被跳過的線
                                // 若已經標記，下個 tick 開頭就會被上面的
                                // `if monitor.flushed_while_down { continue; }` 略過
                                // → 整段 DOWN 期間再也不會嘗試清理（只有下次 UP→DOWN 才重置），
                                // 這次 DOWN 的 flush 就永久丟失了。
                                // 置位一律延後到真正入隊成功之後（見 flush_conntrack）。
                                flush_pending.push((idx, true));
                            }
                        }
                    }
                }

                if !flush_pending.is_empty() {
                    flush_conntrack(
                        &mut monitors,
                        flush_pending,
                        &netlink_tx,
                        Instant::now(),
                        conntrack_flush_min_interval,
                    );
                }

                // 每 2 個週期（約 1 秒）或狀態變更時，原子更新 /tmp/mwan4_status.json 提供給 LuCI 即時讀取
                if tick_count % 2 == 0 || state_changed {
                    let active_names: Vec<&str> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| m.ifname.as_str())
                        .collect();
                    let route_desc = build_route_desc(&monitors, &active_names);
                    write_status_file(&monitors, &route_desc, &config);
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
        // 策略規則一定要拆：它們指向各 WAN 的探針表，而探針表馬上就會被拆掉；
        // 留著會讓匹配的流量查不到路由（黑洞），而不是回退 ECMP。
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetPolicies(Vec::new())) {
            warn!("Failed to request policy rule cleanup: {e}");
        }
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

/// 線路判 DOWN 之後，要「持續」不可用多久才動手清 conntrack。
///
/// 為什麼要拖：隧道型線路（VXLAN/WireGuard）常有幾秒到十幾秒的抖動，而清 conntrack
/// 會把該線路上所有連線一次砍掉（實測一次 495 條），使用者立刻看到「網站打不開」。
///
/// 這個值要蓋過「判 DOWN + 抖動本身 + 恢復所需時間」：
/// 以預設參數為例，連續 3 次失敗 ≈ 2.4s 才判 DOWN，恢復要 5 次連續成功 ≈ 4s
/// （實測這台設備用了 9 次 ≈ 7s），所以一次 8 秒的抖動實測約 12 秒才能回到 UP。
/// 10 秒的靜默期剛好被跨過去、仍然誤清；25 秒能穩穩擋住這類抖動。
///
/// 代價：真斷線時晚 25 秒清連線。但用戶端 TCP 本來就要自我重傳超時（通常 20s+），
/// 所以實際感受幾乎沒有差別；而誤清是「立刻全斷」，兩者不對等。
const CONNTRACK_FLUSH_DOWN_QUIET: Duration = Duration::from_secs(25);

struct WanMonitor {
    ifname: String,
    ifindex: u32,
    gateway: Option<std::net::Ipv4Addr>,
    gateway6: Option<std::net::Ipv6Addr>,
    metric: u32,
    weight: u32,
    /// 實際下發到 ECMP 的權重：未啟用任何動態模式時等於 `weight`；
    /// `weight_mode=quality` / `load_aware` 時由品質與負載計算
    /// （見 `compute_dynamic_weights`）。
    effective_weight: u32,
    /// 介面累計位元組（取自 /sys/class/net/<if>/statistics），用於計算即時速率
    last_tx_bytes: Option<u64>,
    last_rx_bytes: Option<u64>,
    /// 上次取樣時刻與算出的速率（bit/s），供狀態檔 / LuCI 顯示
    last_stats_at: Option<Instant>,
    tx_bps: f64,
    rx_bps: f64,
    /// 速率的 EWMA 平滑值（bit/s）。壓力判定看平滑值，避免單拍突發就觸發權重變更。
    tx_bps_ewma: f64,
    rx_bps_ewma: f64,
    /// EWMA 是否已用第一筆實測值初始化（從 0 慢慢爬升會讓剛啟動的線被誤判成空閒）。
    load_ewma_ready: bool,
    /// 這條線目前是否處於「過載、被下修權重」狀態（Schmitt trigger 的記憶位）。
    load_pressure_active: bool,
    /// 下載（WAN 入口）容量（bit/s）；None = 未設定，不參與負載感知。
    down_bps_capacity: Option<f64>,
    /// 上傳（WAN 出口）容量（bit/s）；未設定時沿用下載容量。
    up_bps_capacity: Option<f64>,
    targets: Vec<std::net::SocketAddr>,
    /// 下個探測週期的「主目標」下標（上次探通的那個）。健康時每週期只探它一條，
    /// 失敗才回退其餘目標——這是壓低短命 TCP 連線數的關鍵，見 `prober::probe_interface`。
    preferred_target: usize,
    /// 這條線若是隧道（VXLAN/WireGuard），其 underlay 對端位址；非隧道留空。
    /// 非空同時代表「不能拿這條線去當別條隧道的 underlay 出口」。
    underlay_targets: Vec<std::net::Ipv4Addr>,
    /// 快取的介面 IPv4（每次寫狀態檔都做 socket + ioctl 太昂貴）
    cached_ip: Option<std::net::Ipv4Addr>,
    /// 最後一次成功查到的介面 IPv4。**失敗時不清空**：介面消失/換 IP 後
    /// conntrack 清理還需要用它來匹配 NAT 到舊位址的連線。
    last_known_ip: Option<std::net::Ipv4Addr>,
    /// 上次對這張網卡做 conntrack 清理的時間（用於限流）
    last_conntrack_flush: Option<Instant>,
    /// 最近一次探測失敗的原因（成功時清空）。
    /// 寫進狀態檔，讓「介面不存在／本機無路由」不再被誤認成「運營商丟包」。
    last_probe_error: Option<String>,
    /// 最近一次失敗是否屬於本機條件（依 errno 分類，不看 strerror 文案）。
    /// 與 `probe_path_missing` 一起決定狀態檔的 `local_condition`。
    last_error_is_local: bool,
    /// 是否已針對「本機條件造成的失敗」告警過（同一輪只提醒一次）
    local_condition_warned: bool,
    /// 內核查詢的結論：經這張網卡到探針目標「根本沒有路」。
    /// 這種情況探針會以「超時」結束（內核按 on-link 丟進黑洞），必須另外標記，
    /// 否則日誌與介面都會把它誤報成運營商丟包。
    probe_path_missing: bool,
    /// 上次做「路徑是否存在」查詢的時間（限流，避免每 tick 都查）
    last_path_check: Option<Instant>,
    /// 本輪進入 DOWN 的時刻；恢復 UP 時清空。
    /// 用來區分「短暫抖動」與「真的掛了」——前者不該清 conntrack。
    down_since: Option<Instant>,
    /// 最後一次進入 DOWN 的時刻。**恢復後不清空**：用來判斷「剛從 DOWN 回來的線」
    /// 還在抖動靜默期內，不該被 flush-on-switch 當成新進入成員清掉。
    last_down_at: Option<Instant>,
    /// 這次 DOWN 期間是否已經清過 conntrack（避免每 tick 重複清）
    flushed_while_down: bool,
    lqe: LinkQualityEstimator,
}

impl WanMonitor {
    /// 刷新快取的介面 IP。
    ///
    /// 查得到 → 同時更新 `cached_ip`（顯示）與 `last_known_ip`（conntrack 清理）。
    /// 查不到 → **只清 `cached_ip`**，`last_known_ip` 保留：介面已消失/正在重撥時，
    /// 舊 NAT 位址的連線還掛在 conntrack 裡，那正是最需要清理的對象。
    fn refresh_cached_ip(&mut self) {
        match crate::netlink::util::get_interface_ipv4(&self.ifname) {
            Ok(ip) => {
                self.cached_ip = Some(ip);
                self.last_known_ip = Some(ip);
            }
            Err(_) => self.cached_ip = None,
        }
    }
}

/// 把本 tick 收集到的 conntrack 清理候選送去 worker（同網卡去重 + 最小間隔限流），
/// 並在**真正入隊成功之後**才更新 `last_conntrack_flush` 與 `flushed_while_down`。
///
/// `pending` 的元素是 `(monitors 下標, 是否來自 flush-on-down)`：flush-on-switch 的路徑
/// 只是「成員集合變了，請清掉新進成員的連線」，線路本身仍是 UP，不該動 `flushed_while_down`。
///
/// 為什麼置位必須晚於入隊（FIX-7）：這裡會因為 `conntrack_flush_min_interval` 跳過剛清過的
/// 網卡。若呼叫端在收集階段就先設 `flushed_while_down = true`，被跳過的那條線下個 tick 開頭
/// 就撞上 `if monitor.flushed_while_down { continue; }`，整段 DOWN 期間不會再嘗試清理
/// （只有下一次 UP→DOWN 才會重置）—— 這次 DOWN 的清理就永久丟失了。
fn flush_conntrack(
    monitors: &mut [WanMonitor],
    pending: Vec<(usize, bool)>,
    netlink_tx: &NetlinkSender,
    now: Instant,
    min_interval: Duration,
) {
    let mut targets: Vec<ConntrackTarget> = Vec::new();
    // 與 targets 逐項對應：該網卡的下標、以及「是否來自 flush-on-down」
    let mut marked: Vec<(usize, bool)> = Vec::new();
    for (idx, from_down) in pending {
        let monitor = &monitors[idx];
        if let Some(last) = monitor.last_conntrack_flush {
            if now.duration_since(last) < min_interval {
                debug!(
                    "[{}] Skipping conntrack flush: within min interval",
                    monitor.ifname
                );
                continue;
            }
        }
        // 同一張網卡只清一次；來源旗標用 OR 合併，避免重複項把 flush-on-down 的標記吞掉。
        // 舊 IP 合併時「有值優先」：flush-on-switch 的項目可能是後加的。
        match targets.iter().position(|(n, _)| n == &monitor.ifname) {
            Some(pos) => {
                marked[pos].1 |= from_down;
                if targets[pos].1.is_none() {
                    targets[pos].1 = monitor.last_known_ip;
                }
            }
            None => {
                targets.push((monitor.ifname.clone(), monitor.last_known_ip));
                marked.push((idx, from_down));
            }
        }
    }
    if targets.is_empty() {
        return;
    }
    match netlink_tx.try_send(NetlinkCmd::FlushConntrack(targets)) {
        Ok(()) => {
            for (idx, from_down) in marked {
                monitors[idx].last_conntrack_flush = Some(now);
                if from_down {
                    monitors[idx].flushed_while_down = true;
                }
            }
        }
        Err(err) => {
            warn!("Failed to queue conntrack flush: {err}");
        }
    }
}

/// 產生 LuCI 顯示用的活躍路由描述字串。
///
/// `active_names` 由呼叫端用**同一套 is_active 判據**算出（含降級與保底），
/// 避免這裡複製一份判斷而與路由下發的實際結果不一致（降級狀態若兩處判得不同，
/// 介面顯示「Multipath ECMP」但核心只有一條路由）。
fn build_route_desc(monitors: &[WanMonitor], active_names: &[&str]) -> String {
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
    /// 實際下發到 ECMP 的權重（動態權重啟用時可能與 `weight` 不同）
    effective_weight: u32,
    /// 即時速率（bit/s，取樣自 /sys/class/net/<if>/statistics）
    tx_bps: f64,
    rx_bps: f64,
    /// 負載利用率（%）：`max(rx/下載容量, tx/上傳容量) × 100`；未設定容量時為 null。
    /// 這就是負載感知判斷「這條線是否過載」的依據。
    load_pct: Option<f64>,
    /// 這條線目前是否因過載而被下修權重（狀態檔/LuCI 用來看分流是否正在轉移）
    offloaded: bool,
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
    /// 這條線是否因實測丟包率超標而降級（= 不參與 ECMP，但仍繼續探測）
    degraded: bool,
    /// 目前滑動窗口內的樣本數（未達 window_size 前不做丟包率判定）
    samples_in_window: usize,
    /// 窗口是否已填滿（false 表示樣本還不夠，degraded/判死都還沒生效）
    window_full: bool,
    /// 最近一次狀態變更的原因：consecutive_timeouts / window_loss / rtt / recovery
    /// （尚未發生過狀態變更時為 null）
    state_reason: Option<String>,
}

#[derive(serde::Serialize)]
struct DaemonStatus {
    updated_at: u64,
    /// 前端據此判斷資料是否過期（秒），避免把陳舊快照當成即時狀態
    stale_after_secs: u64,
    active_routes: String,
    interfaces: Vec<InterfaceStatus>,
    /// 策略分流規則狀態（未設定 policies 時省略）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies: Vec<PolicyStatus>,
}

#[derive(serde::Serialize)]
struct PolicyStatus {
    name: String,
    interface: String,
    priority: u32,
    /// 目前是否已下發（目標 WAN 健康且規則同步成功）
    active: bool,
    source: Vec<String>,
    destination: Vec<String>,
}

/// 把設定的多路徑哈希策略寫進內核 sysctl。
///
/// 只在值不同時才寫；失敗只告警（舊內核沒有這個檔案、或 /proc 不可寫），
/// 不影響守護進程啟動。IPv6 只有在介面設定了 gateway6 時才一起設定。
fn apply_multipath_hash_policy(policy: MultipathHashPolicy, has_ipv6: bool) {
    let want = policy.sysctl_value().to_string();
    let mut paths = vec!["/proc/sys/net/ipv4/fib_multipath_hash_policy".to_string()];
    if has_ipv6 {
        paths.push("/proc/sys/net/ipv6/fib_multipath_hash_policy".to_string());
    }
    for path in paths {
        let current = std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_string());
        if current.as_deref() == Some(want.as_str()) {
            info!(
                "Multipath hash policy already '{}' ({path})",
                policy.as_str()
            );
            continue;
        }
        match std::fs::write(&path, format!("{want}\n")) {
            Ok(()) => info!(
                "Set multipath hash policy to '{}' ({path})",
                policy.as_str()
            ),
            Err(e) => warn!(
                "Failed to set multipath hash policy '{}' at {path}: {e} \
                 (kernel too old or /proc not writable?)",
                policy.as_str()
            ),
        }
    }
}

/// 動態權重的「刻度」：整數權重若都是 1，`round(1 × 0.25)` 會被夾成 1，
/// 下修完全沒有效果。啟用負載感知時把基準權重整體放大到至少這個刻度，
/// 讓「空閒線」與「被下修的線」之間真的有整數差；倍率由最小設定權重反推，
/// 因此**權重比例不變**（weight 1:1 放大成 4:4），只是刻度變細。
const DYNAMIC_WEIGHT_RESOLUTION: u32 = 4;

/// 這條線當前的負載利用率：`max(rx / 下載容量, tx / 上傳容量)`。
///
/// 取兩個方向的最大值：全雙工乙太網的收發各自獨立，任一方向接近上限就代表
/// 這條線的某個方向已經吃滿，該把部分流量移走。沒設定容量時回傳 `None`。
fn load_utilization(m: &WanMonitor) -> Option<f64> {
    let down = m.down_bps_capacity?;
    let up = m.up_bps_capacity.unwrap_or(down);
    if !(down.is_finite() && down > 0.0 && up.is_finite() && up > 0.0) {
        return None;
    }
    Some((m.rx_bps_ewma / down).max(m.tx_bps_ewma / up))
}

/// 更新每條線「是否處於過載下修」的遲滯狀態（Schmitt trigger）。
///
/// 進入：利用率 >= `target`；退出：利用率 <= `recover`（recover < target）。
/// 為什麼要記憶位：沒有它，一條線在 target 附近擺盪就會讓權重每幾秒跳一次，
/// 而每次權重變更都是一次 `RTM_NEWROUTE`，可能重算 multipath hash、打斷既有 flow。
fn update_load_pressure(monitors: &mut [WanMonitor], active: &[bool], target: f64, recover: f64) {
    for (slot, m) in monitors.iter_mut().enumerate() {
        if !active.get(slot).copied().unwrap_or(false) {
            continue;
        }
        let Some(util) = load_utilization(m) else {
            m.load_pressure_active = false;
            continue;
        };
        if m.load_pressure_active {
            if util <= recover {
                m.load_pressure_active = false;
            }
        } else if util >= target {
            m.load_pressure_active = true;
        }
    }
}

/// 負載因子（`min_ratio` ~ 1.0）：過載的線下修，其餘維持 1.0。
///
/// 在 target 與 recover 之間線性內插：稍微過載只小幅下修、嚴重過載才壓到下限，
/// 比 0/1 階梯更容易收斂到平衡點而不來回震盪。
fn load_factor(m: &WanMonitor, target: f64, recover: f64, min_ratio: f64) -> f64 {
    if !m.load_pressure_active {
        return 1.0;
    }
    let Some(util) = load_utilization(m) else {
        return 1.0;
    };
    let span = target - recover;
    let pressure = if span > 0.0 {
        ((util - recover) / span).clamp(0.0, 1.0)
    } else {
        1.0
    };
    1.0 - pressure * (1.0 - min_ratio)
}

/// 品質因子（`min_ratio` ~ 1.0）：依 LQE 實測丟包與 RTT 下修。
fn quality_factor(m: &WanMonitor, best_rtt: f64, min_ratio: f64) -> f64 {
    let loss = if m.lqe.window_full() {
        m.lqe.loss_rate().clamp(0.0, 1.0)
    } else {
        0.0
    };
    let mut factor = 1.0 - loss;
    if let Some(rtt) = m.lqe.rtt_ewma_ms {
        if rtt.is_finite() && rtt > 0.0 && best_rtt.is_finite() && best_rtt > 0.0 {
            factor *= (best_rtt / rtt).clamp(min_ratio, 1.0);
        }
    }
    factor.clamp(min_ratio, 1.0)
}

/// 計算各線的等效 ECMP 權重（品質模式與負載感知各自獨立、也可疊加）。
///
/// 基準權重（`base`）：
/// - 只要任何一條線設定了 `max_mbps`，就啟用**容量比例分流**：
///   `base = weight × (max_mbps / 活躍線中的最小 max_mbps)`，
///   即權重比 = 最大頻寬比（最小那條正規化為 1）；非活躍線維持 `weight`。
/// - 否則 `base = weight`。
///
/// 動態因子（可獨立或疊加）：
/// - `weight_mode = quality`：`factor_q = (1 - 丟包) × clamp(最佳 RTT / 本線 RTT, min, 1)`；
/// - `load_aware`：`factor_l = 1 - 壓力 × (1 - min)`（見 `load_factor`）；
/// - 合成因子 = `factor_q × factor_l`。
///
/// 最終權重 = `clamp(round(base × 刻度 × 因子), 1, 255)`。刻度是為了在小權重時
/// 仍有整數解析度（見 `DYNAMIC_WEIGHT_RESOLUTION`），並限制在不會超過 255。
/// 非承載線維持設定值（不會被下發，僅狀態檔顯示用）。
fn compute_dynamic_weights(
    monitors: &[WanMonitor],
    is_active: impl Fn(usize, &WanMonitor) -> bool,
    config: &DaemonConfig,
) -> Vec<u32> {
    let quality_on = config.weight_mode == WeightMode::Quality;
    // 容量比例分流改看「監控物件是否帶容量」，與實際用於比例的欄位一致
    // （loop 的啟用判斷才看 config；兩者在 validate 下必然同步）。
    let bandwidth_on = monitors.iter().any(|m| m.down_bps_capacity.is_some());
    let min_ratio = config.dynamic_weight_min_ratio.clamp(0.05, 1.0);
    let active_flags: Vec<bool> = monitors
        .iter()
        .enumerate()
        .map(|(slot, m)| is_active(slot, m))
        .collect();
    let active_count = active_flags.iter().filter(|a| **a).count();
    // 只有一條承載線時無處可分（權重再怎麼調都只有它），不做負載下修以避免白寫路由。
    let load_on = config.load_aware && active_count >= 2;

    // 基準權重：容量比例分流時 ∝ weight × 最大頻寬。
    // 以「活躍線中的最小容量」正規化，讓最小那條為 1、其餘按比例放大
    // （比例超過上限時最後會被 clamp，等效上限 255:1）。
    let mut bases: Vec<f64> = monitors.iter().map(|m| m.weight.max(1) as f64).collect();
    if bandwidth_on {
        let min_cap = monitors
            .iter()
            .enumerate()
            .filter(|(slot, _)| active_flags[*slot])
            .filter_map(|(_, m)| m.down_bps_capacity)
            .filter(|c| c.is_finite() && *c > 0.0)
            .fold(f64::INFINITY, f64::min);
        if min_cap.is_finite() && min_cap > 0.0 {
            for (slot, m) in monitors.iter().enumerate() {
                if !active_flags[slot] {
                    continue;
                }
                if let Some(cap) = m.down_bps_capacity.filter(|c| c.is_finite() && *c > 0.0) {
                    bases[slot] = m.weight.max(1) as f64 * (cap / min_cap);
                }
            }
        }
    }

    // 刻度放大只在「確實有線被下修」時套用：沒有壓力就保持原權重，
    // 不為了放大刻度而多下發一次路由。
    let any_pressure = load_on
        && monitors
            .iter()
            .enumerate()
            .any(|(slot, m)| active_flags[slot] && m.load_pressure_active);
    let scale = if any_pressure {
        let active_bases: Vec<f64> = bases
            .iter()
            .enumerate()
            .filter(|(slot, _)| active_flags[*slot])
            .map(|(_, b)| *b)
            .collect();
        let min_base = active_bases.iter().copied().fold(f64::INFINITY, f64::min);
        let max_base = active_bases.iter().copied().fold(0.0_f64, f64::max);
        if min_base.is_finite() && min_base > 0.0 && max_base > 0.0 {
            // 想要的刻度（讓最小權重至少 RESOLUTION 格）與不超過上限的刻度取小。
            let want = (DYNAMIC_WEIGHT_RESOLUTION as f64 / min_base).max(1.0);
            let fit = (config::MAX_WEIGHT as f64 / max_base).max(1.0);
            want.min(fit).max(1.0)
        } else {
            1.0
        }
    } else {
        1.0
    };

    let best_rtt = monitors
        .iter()
        .enumerate()
        .filter(|(slot, _)| active_flags[*slot])
        .filter_map(|(_, m)| m.lqe.rtt_ewma_ms)
        .filter(|r| r.is_finite() && *r > 0.0)
        .fold(f64::INFINITY, f64::min);

    monitors
        .iter()
        .enumerate()
        .map(|(slot, m)| {
            if !active_flags[slot] {
                return m.weight;
            }
            let mut factor = 1.0;
            if quality_on {
                factor *= quality_factor(m, best_rtt, min_ratio);
            }
            if load_on {
                factor *= load_factor(
                    m,
                    config.load_target_ratio,
                    config.load_recover_ratio,
                    min_ratio,
                );
            }
            let w = bases[slot] * scale * factor;
            (w.round() as u32).clamp(1, config::MAX_WEIGHT)
        })
        .collect()
}

/// 把 `config.policies` 展開成可下發的策略規則集合。
///
/// 目標 WAN 目前不健康（非 UP 或 ifindex 解析不到）時整條政策停用，
/// 讓流量自動回退到 ECMP 預設路由，而不是黑洞在死線上。
fn build_policy_rules(config: &DaemonConfig, monitors: &[WanMonitor]) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    for (index, policy) in config.policies.iter().enumerate() {
        let Some(target) = monitors.iter().find(|m| m.ifname == policy.interface) else {
            continue;
        };
        if target.lqe.state != LinkState::Up || target.ifindex == 0 {
            continue;
        }
        let Some(slot) = config
            .interfaces
            .iter()
            .position(|i| i.name == policy.interface)
        else {
            continue;
        };
        let priority = policy
            .priority
            .unwrap_or(POLICY_RULE_PRIORITY_BASE + index as u32);
        let sources: Vec<Option<(std::net::Ipv4Addr, u8)>> = if policy.source.is_empty() {
            vec![None]
        } else {
            policy
                .source
                .iter()
                .map(|raw| config::parse_ipv4_prefix(raw).ok())
                .collect()
        };
        let destinations: Vec<Option<(std::net::Ipv4Addr, u8)>> = if policy.destination.is_empty() {
            vec![None]
        } else {
            policy
                .destination
                .iter()
                .map(|raw| config::parse_ipv4_prefix(raw).ok())
                .collect()
        };
        for source in &sources {
            for destination in &destinations {
                rules.push(PolicyRule {
                    name: policy.name.clone(),
                    ifindex: target.ifindex,
                    table: PROBE_TABLE_BASE + slot as u32,
                    priority,
                    source: *source,
                    destination: *destination,
                });
            }
        }
    }
    rules
}

/// 負載取樣的 EWMA 平滑係數。取樣週期即探測週期（預設 500ms），
/// alpha = 0.3 的時間常數約 1.5 秒：足以濾掉單拍突發，又不會慢到跟不上一次真實的流量轉移。
const LOAD_EWMA_ALPHA: f64 = 0.3;

/// 讀取網卡累計位元組並換算即時速率（bit/s）。讀不到就保持上次的值。
///
/// 來源是 `/sys/class/net/<if>/statistics/{tx,rx}_bytes`（介面累計值），
/// 對路由器轉發流量而言這正是該 WAN 的實際承載量，用來驗證分流是否均勻。
fn sample_interface_rates(monitor: &mut WanMonitor, now: Instant) {
    let read = |kind: &str| -> Option<u64> {
        std::fs::read_to_string(format!(
            "/sys/class/net/{}/statistics/{kind}",
            monitor.ifname
        ))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    };
    let (Some(tx), Some(rx)) = (read("tx_bytes"), read("rx_bytes")) else {
        return;
    };
    if let (Some(prev_tx), Some(prev_rx), Some(prev_at)) = (
        monitor.last_tx_bytes,
        monitor.last_rx_bytes,
        monitor.last_stats_at,
    ) {
        let secs = now.duration_since(prev_at).as_secs_f64();
        if secs > 0.0 {
            // 介面重建時計數器可能歸零：saturating_sub 讓速率歸零而不是暴衝
            let d_tx = tx.saturating_sub(prev_tx);
            let d_rx = rx.saturating_sub(prev_rx);
            monitor.tx_bps = d_tx as f64 * 8.0 / secs;
            monitor.rx_bps = d_rx as f64 * 8.0 / secs;
            // EWMA 平滑：壓力判定看平滑值，單拍突發不該讓 ECMP 權重跳動。
            // 第一筆直接當初值，否則從 0 慢慢爬升會讓剛啟動的線被誤判成空閒。
            if monitor.load_ewma_ready {
                monitor.tx_bps_ewma += LOAD_EWMA_ALPHA * (monitor.tx_bps - monitor.tx_bps_ewma);
                monitor.rx_bps_ewma += LOAD_EWMA_ALPHA * (monitor.rx_bps - monitor.rx_bps_ewma);
            } else {
                monitor.tx_bps_ewma = monitor.tx_bps;
                monitor.rx_bps_ewma = monitor.rx_bps;
                monitor.load_ewma_ready = true;
            }
        }
    }
    monitor.last_tx_bytes = Some(tx);
    monitor.last_rx_bytes = Some(rx);
    monitor.last_stats_at = Some(now);
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

fn write_status_file(monitors: &[WanMonitor], active_routes: &str, config: &DaemonConfig) {
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
            effective_weight: m.effective_weight,
            tx_bps: (m.tx_bps * 100.0).round() / 100.0,
            rx_bps: (m.rx_bps * 100.0).round() / 100.0,
            load_pct: load_utilization(m).map(|u| (u * 10000.0).round() / 100.0),
            offloaded: m.load_pressure_active,
            rtt_ms: (m.lqe.rtt_ewma_ms.unwrap_or(0.0) * 100.0).round() / 100.0,
            jitter_ms: (m.lqe.jitter_ewma_ms * 100.0).round() / 100.0,
            loss_rate: (m.lqe.loss_rate() * 10000.0).round() / 100.0,
            consecutive_successes: m.lqe.consecutive_successes,
            consecutive_timeouts: m.lqe.consecutive_timeouts,
            targets: m.targets.iter().map(|t| t.to_string()).collect(),
            ifindex: m.ifindex,
            last_error: m.last_probe_error.clone(),
            local_condition: m.last_error_is_local || m.probe_path_missing,
            degraded: m.lqe.is_degraded(),
            samples_in_window: m.lqe.window_len(),
            window_full: m.lqe.window_full(),
            state_reason: m.lqe.state_reason().map(|r| r.as_str().to_string()),
        });
    }

    // 策略規則狀態：`active` = 目標 WAN 健康且規則在期望集合內（與實際下發同步）
    let policy_rules = build_policy_rules(config, monitors);
    let policies: Vec<PolicyStatus> = config
        .policies
        .iter()
        .enumerate()
        .map(|(index, policy)| {
            let priority = policy
                .priority
                .unwrap_or(POLICY_RULE_PRIORITY_BASE + index as u32);
            PolicyStatus {
                name: policy.name.clone(),
                interface: policy.interface.clone(),
                priority,
                active: policy_rules.iter().any(|r| r.priority == priority),
                source: policy.source.clone(),
                destination: policy.destination.clone(),
            }
        })
        .collect();

    let status = DaemonStatus {
        updated_at: now,
        stale_after_secs: STATUS_STALE_SECS,
        active_routes: active_routes.to_string(),
        interfaces: iface_statuses,
        policies,
    };

    if let Ok(json) = serde_json::to_string(&status) {
        if let Err(e) = write_status_atomic(&json) {
            debug!("failed to update status file: {e}");
        }
    }
}

/// 原子且防符號連結地寫入狀態檔。
///
/// `/tmp` 是 1777：可寫者能預先放一個指向任意路徑的符號連結，讓 root 的
/// `fs::write` 跟著它覆寫目標檔案。這裡改用 `create_new`（O_CREAT|O_EXCL）：
/// 目標已存在（含符號連結）時直接失敗，先移除再建立（`remove_file` 只刪連結本身、
/// 不會跟隨），最後用 rename 原子替換。
fn write_status_atomic(json: &str) -> io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(STATUS_TMP_FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(STATUS_TMP_FILE)?;
    file.write_all(json.as_bytes())?;
    drop(file);
    std::fs::rename(STATUS_TMP_FILE, STATUS_FILE)
}

#[cfg(test)]
mod tests {
    // 測試裡「先取預設值、再改一兩個欄位」比整包 struct literal 清楚得多，
    // 尤其只需要動 config 的單一欄位時。
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    fn monitor(name: &str, last_flush: Option<Instant>) -> WanMonitor {
        WanMonitor {
            ifname: name.to_string(),
            ifindex: 1,
            gateway: None,
            gateway6: None,
            metric: 10,
            weight: 1,
            effective_weight: 1,
            last_tx_bytes: None,
            last_rx_bytes: None,
            last_stats_at: None,
            tx_bps: 0.0,
            rx_bps: 0.0,
            tx_bps_ewma: 0.0,
            rx_bps_ewma: 0.0,
            load_ewma_ready: false,
            load_pressure_active: false,
            down_bps_capacity: None,
            up_bps_capacity: None,
            targets: Vec::new(),
            preferred_target: 0,
            underlay_targets: Vec::new(),
            cached_ip: None,
            last_known_ip: None,
            last_conntrack_flush: last_flush,
            last_probe_error: None,
            last_error_is_local: false,
            local_condition_warned: false,
            probe_path_missing: false,
            last_path_check: None,
            down_since: None,
            last_down_at: None,
            flushed_while_down: false,
            lqe: LinkQualityEstimator::new(name.to_string(), &DaemonConfig::default()),
        }
    }

    fn flushed_names(rx: &std::sync::mpsc::Receiver<NetlinkCmd>) -> Vec<String> {
        match rx.try_recv() {
            Ok(NetlinkCmd::FlushConntrack(targets)) => {
                targets.into_iter().map(|(name, _)| name).collect()
            }
            Ok(_) => panic!("應送出 FlushConntrack，實際送出了其他指令"),
            Err(err) => panic!("應送出 FlushConntrack，實際沒有送出指令：{err}"),
        }
    }

    /// FIX-7 回歸：被最小間隔限流跳過的 flush-on-down 候選**不得**被標記成「本次 DOWN 已清過」。
    ///
    /// 舊版順序是「先置位、後限流」，於是那條線在下個 tick 開頭就被
    /// `if monitor.flushed_while_down { continue; }` 略過，整段 DOWN 期間再也不會嘗試清理
    /// （只有下一次 UP→DOWN 才重置）→ 這次 DOWN 的 flush 永久丟失。
    #[test]
    fn test_flush_on_down_marker_is_set_only_after_enqueue() {
        let now = Instant::now();
        let min_interval = Duration::from_secs(10);
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(4);
        // 1 秒前才清過 → 這次落在最小間隔內
        let mut monitors = vec![monitor("wan1", Some(now - Duration::from_secs(1)))];

        flush_conntrack(&mut monitors, vec![(0, true)], &tx, now, min_interval);
        assert!(
            rx.try_recv().is_err(),
            "最小間隔內不該送出任何 conntrack 清理指令"
        );
        assert!(
            !monitors[0].flushed_while_down,
            "被限流跳過的線若先被標記，整段 DOWN 期間都不會再重試"
        );
        assert_eq!(
            monitors[0].last_conntrack_flush,
            Some(now - Duration::from_secs(1)),
            "被跳過時不該更新清理時間戳"
        );

        // 間隔過後重試：這次真的入隊，才准標記
        let later = now + Duration::from_secs(11);
        flush_conntrack(&mut monitors, vec![(0, true)], &tx, later, min_interval);
        assert_eq!(flushed_names(&rx), vec!["wan1".to_string()]);
        assert!(monitors[0].flushed_while_down);
        assert_eq!(monitors[0].last_conntrack_flush, Some(later));
    }

    /// flush-on-switch 進來的候選不該動 `flushed_while_down`（線路仍是 UP）；
    /// 同一張網卡同時來自兩個來源時只清一次，且來源旗標必須合併。
    #[test]
    fn test_flush_on_switch_does_not_mark_down_flush() {
        let now = Instant::now();
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(4);
        let mut monitors = vec![monitor("wan1", None), monitor("wan0", None)];

        flush_conntrack(
            &mut monitors,
            vec![(0, false), (1, false), (0, true)],
            &tx,
            now,
            Duration::from_secs(10),
        );

        assert_eq!(
            flushed_names(&rx),
            vec!["wan1".to_string(), "wan0".to_string()],
            "同一張網卡只能出現一次，且順序依第一次出現的下標"
        );
        assert!(
            monitors[0].flushed_while_down,
            "wan1 也來自 flush-on-down，來源旗標應合併"
        );
        assert!(
            !monitors[1].flushed_while_down,
            "flush-on-switch 不得把線路標成『DOWN 期間已清』"
        );
    }

    /// 品質模式：RTT 較差的線被下修。`load_aware` 關閉時不套用刻度放大，
    /// 因此維持舊行為（4 × 0.25 = 1）。
    #[test]
    fn test_compute_quality_weights_rtt_and_loss() {
        let mut cfg = DaemonConfig::default();
        cfg.weight_mode = WeightMode::Quality;
        cfg.dynamic_weight_min_ratio = 0.25;
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        let mut c = monitor("wan3", None);
        a.weight = 4;
        b.weight = 4;
        c.weight = 4;
        a.lqe.rtt_ewma_ms = Some(100.0);
        b.lqe.rtt_ewma_ms = Some(400.0);
        c.lqe.rtt_ewma_ms = None; // 沒有 RTT 樣本 → 不懲罰
        let monitors = vec![a, b, c];
        // 全部承載；視窗未填滿 → 丟包不計
        let weights = compute_dynamic_weights(&monitors, |_, _| true, &cfg);
        assert_eq!(weights[0], 4, "最佳 RTT 維持原權重");
        assert_eq!(weights[1], 1, "RTT 4 倍差 → 下修到 min_ratio（4*0.25=1）");
        assert_eq!(weights[2], 4, "沒有 RTT 樣本不該被懲罰");

        // 非承載線維持設定權重（不會被下發，但狀態檔顯示用）
        let weights = compute_dynamic_weights(&monitors, |slot, _| slot == 0, &cfg);
        assert_eq!(weights[1], 4);
        assert_eq!(weights[2], 4);
    }

    /// 負載感知：一條線過載時，透過「刻度放大 + 下修因子」把 ECMP 權重比例
    /// 往空閒線傾斜（把部分 flow 轉移過去）；壓力解除後還原設定權重。
    #[test]
    fn test_compute_load_weights_shifts_traffic_to_idle_line() {
        let mut cfg = DaemonConfig::default();
        cfg.load_aware = true;
        cfg.load_target_ratio = 0.80;
        cfg.load_recover_ratio = 0.60;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut busy = monitor("wan1", None);
        let mut idle = monitor("wan2", None);
        // 兩條線容量相同（100 Mbps），busy 打滿、idle 幾乎沒流量
        for m in [&mut busy, &mut idle] {
            m.down_bps_capacity = Some(100_000_000.0);
            m.up_bps_capacity = Some(100_000_000.0);
        }
        busy.rx_bps_ewma = 95_000_000.0; // 95%
        idle.rx_bps_ewma = 5_000_000.0; // 5%
        let mut monitors = vec![busy, idle];
        let active = [true, true];

        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(monitors[0].load_pressure_active, "95% 應觸發過載下修");
        assert!(!monitors[1].load_pressure_active, "5% 不該觸發");

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg);
        // busy factor = 0.25、idle = 1.0；刻度放大 4 倍 → 1 : 4
        assert_eq!(weights, vec![1, 4], "過載線應被下修、空閒線放大來接流量");

        // 遲滯死區（60%~80%）：已下修的線不解除，避免在門檻附近來回跳動
        monitors[0].rx_bps_ewma = 70_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(
            monitors[0].load_pressure_active,
            "落在 recover 與 target 之間應保持下修"
        );

        // 低於 recover（60%）→ 壓力解除、權重還原，且不再套用刻度放大
        monitors[0].rx_bps_ewma = 10_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(!monitors[0].load_pressure_active);
        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg);
        assert_eq!(weights, vec![1, 1], "壓力解除後回到設定權重");

        // 兩條線都過載：因子相同 → 權重比例不變（無處可去，不製造無意義的路由變更）
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        for m in [&mut a, &mut b] {
            m.down_bps_capacity = Some(100_000_000.0);
            m.rx_bps_ewma = 90_000_000.0;
        }
        let mut both = vec![a, b];
        update_load_pressure(
            &mut both,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        let weights = compute_dynamic_weights(&both, |s, _| active[s], &cfg);
        assert_eq!(weights, vec![1, 1], "全線過載時維持原比例");

        // 只有一條承載線時不做負載下修（無處可分）
        let only = vec![monitor("wan1", None)];
        let weights = compute_dynamic_weights(&only, |_, _| true, &cfg);
        assert_eq!(weights, vec![1]);
    }

    /// 容量比例分流：設定 max_mbps 後，基準權重自動 ∝ 最大頻寬，
    /// 不需要手動換算 weight（1000 vs 200 → 5:1；1000 vs 10 → 100:1）。
    #[test]
    fn test_compute_bandwidth_proportional_weights() {
        let cfg = DaemonConfig::default();

        // 1000 : 200 = 5 : 1
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(200_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg);
        assert_eq!(weights, vec![5, 1], "權重比應等於最大頻寬比 1000:200");

        // 極端差距（1000 : 10 = 100 : 1）仍可表達
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(10_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg);
        assert_eq!(weights, vec![100, 1]);

        // 差距超過 255:1 時夾在單一 nexthop 的上限
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(1_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg);
        assert_eq!(weights, vec![config::MAX_WEIGHT, 1], "超過 255:1 應夾住");

        // weight 仍可當手動倍率：2×1000 : 1×500 = 4 : 1
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.weight = 2;
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(500_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg);
        assert_eq!(weights, vec![4, 1]);

        // 完全沒設容量 → 退回設定 weight（既有行為不變）
        let cfg2 = DaemonConfig::default();
        assert!(!cfg2.capacity_weights_on());
        let weights = compute_dynamic_weights(
            &[monitor("wan1", None), monitor("wan2", None)],
            |_, _| true,
            &cfg2,
        );
        assert_eq!(weights, vec![1, 1]);
    }

    /// 容量比例分流 + 負載感知：過載線在容量基準上再被下修。
    #[test]
    fn test_bandwidth_baseline_plus_load_offload() {
        let mut cfg = DaemonConfig::default();
        cfg.load_aware = true;
        cfg.load_target_ratio = 0.80;
        cfg.load_recover_ratio = 0.60;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut busy = monitor("wan1", None);
        let mut idle = monitor("wan2", None);
        busy.down_bps_capacity = Some(1_000_000_000.0);
        busy.up_bps_capacity = Some(1_000_000_000.0);
        idle.down_bps_capacity = Some(200_000_000.0);
        idle.up_bps_capacity = Some(200_000_000.0);
        busy.rx_bps_ewma = 950_000_000.0; // wan1 95%（過載）
        idle.rx_bps_ewma = 10_000_000.0; // wan2 5%
        let mut monitors = vec![busy, idle];
        let active = [true, true];
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(monitors[0].load_pressure_active);

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg);
        // 基準 5:1；wan1 因子 0.25（刻度 4）→ 20×0.25=5、wan2=4 → 5:4
        assert_eq!(weights, vec![5, 4], "過載線在容量基準上被進一步下修");
    }

    /// 未設定容量時（未啟用 load_aware 的設定不會走到這裡，但函式要防守）
    /// 利用率視為未知，不得觸發壓力。
    #[test]
    fn test_load_pressure_requires_capacity() {
        let mut m = monitor("wan1", None);
        m.rx_bps_ewma = 999_000_000.0;
        assert_eq!(load_utilization(&m), None);
        let mut monitors = vec![m];
        update_load_pressure(&mut monitors, &[true], 0.8, 0.6);
        assert!(!monitors[0].load_pressure_active, "沒有容量就不判定過載");
    }

    #[test]
    fn test_build_policy_rules_expands_and_skips_dead_target() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces[0].name = "wan1".to_string();
        cfg.interfaces[1].name = "wan2".to_string();
        cfg.policies = vec![
            config::PolicyConfig {
                name: "guest".to_string(),
                source: vec!["192.168.3.0/24".to_string(), "192.168.4.0/24".to_string()],
                destination: vec!["10.0.0.0/8".to_string()],
                interface: "wan2".to_string(),
                priority: None,
                extra: Default::default(),
            },
            config::PolicyConfig {
                name: "dead".to_string(),
                source: vec![],
                destination: vec![],
                interface: "wan1".to_string(),
                priority: None,
                extra: Default::default(),
            },
        ];

        let mut up = monitor("wan2", None);
        up.lqe.state = LinkState::Up;
        up.ifindex = 22;
        let mut down = monitor("wan1", None);
        down.lqe.state = LinkState::Down;
        down.ifindex = 11;
        let monitors = vec![down, up];

        let rules = build_policy_rules(&cfg, &monitors);
        assert_eq!(rules.len(), 2, "2 個來源 × 1 個目的，且 Down 的政策被跳過");
        for rule in &rules {
            assert_eq!(rule.name, "guest");
            assert_eq!(rule.ifindex, 22);
            assert_eq!(rule.table, PROBE_TABLE_BASE + 1, "用目標 WAN 的獨立表");
            assert_eq!(rule.priority, POLICY_RULE_PRIORITY_BASE, "預設依政策順序");
            assert_eq!(rule.destination, Some(("10.0.0.0".parse().unwrap(), 8)));
        }
        let sources: Vec<_> = rules.iter().filter_map(|r| r.source).collect();
        assert!(sources.contains(&("192.168.3.0".parse().unwrap(), 24)));
        assert!(sources.contains(&("192.168.4.0".parse().unwrap(), 24)));

        // 目標恢復 UP 後，match-all 的政策也回來（source/destination 都是 None）
        let mut up_dead = monitor("wan1", None);
        up_dead.lqe.state = LinkState::Up;
        up_dead.ifindex = 11;
        let mut up_guest = monitor("wan2", None);
        up_guest.lqe.state = LinkState::Up;
        up_guest.ifindex = 22;
        let monitors = vec![up_dead, up_guest];
        let rules = build_policy_rules(&cfg, &monitors);
        assert_eq!(rules.len(), 3);
        let wildcard = rules.iter().find(|r| r.name == "dead").unwrap();
        assert_eq!(wildcard.source, None);
        assert_eq!(wildcard.destination, None);
    }
}
