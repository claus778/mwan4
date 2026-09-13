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
use netlink::route::{ActiveWanRoute, ActiveWanRouteV6, RouteManager};
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
    /// 清理指定網卡們的 conntrack 連線（多張網卡合併為一次全表 dump）
    FlushConntrack(Vec<String>),
    /// 優雅退出：移除本程式下發的預設路由
    ClearRoutes,
}

type NetlinkSender = std::sync::mpsc::SyncSender<NetlinkCmd>;

fn spawn_netlink_worker(
    route_mgr: RouteManager,
    conntrack_mgr: ConntrackManager,
) -> (NetlinkSender, std::thread::JoinHandle<()>) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(NETLINK_QUEUE_CAPACITY);

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
                let mut flush: Vec<String> = Vec::new();
                let mut clear_routes = false;
                for c in batch {
                    match c {
                        NetlinkCmd::Apply(wans) => apply = Some(wans),
                        NetlinkCmd::ApplyV6(wans) => apply_v6 = Some(wans),
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
                    if let Err(e) = route_mgr.apply_default_routes(&wans) {
                        error!("Failed to update kernel IPv4 FIB routes: {e}");
                    }
                }
                if let Some(wans) = apply_v6 {
                    if let Err(e) = route_mgr.apply_ipv6_default_routes(&wans) {
                        error!("Failed to update kernel IPv6 FIB routes: {e}");
                    }
                }
                if !flush.is_empty() {
                    if let Err(e) = conntrack_mgr.flush_interfaces_conntrack(&flush) {
                        warn!("[{}] Conntrack flush failed: {e}", flush.join(", "));
                    }
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

    (tx, handle)
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

/// 依據核心事件更新各網卡的 ifindex 與快取 IP
fn refresh_interface_state(monitors: &mut [WanMonitor], reason: &str) {
    for monitor in monitors.iter_mut() {
        if let Ok(idx) = if_nametoindex(&monitor.ifname) {
            if idx != monitor.ifindex {
                info!(
                    "Interface {} ifindex changed: {} -> {} ({reason})",
                    monitor.ifname, monitor.ifindex, idx
                );
                monitor.ifindex = idx;
            }
        }
        monitor.cached_ip = crate::netlink::util::get_interface_ipv4(&monitor.ifname).ok();
    }
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
fn refresh_affected_interfaces(monitors: &mut [WanMonitor], events: &[netlink::link::LinkEvent]) {
    for monitor in monitors.iter_mut() {
        let mut touched = false;
        let mut reindex = false;
        for e in events {
            match e {
                netlink::link::LinkEvent::Link { ifname: Some(name), .. } if name == &monitor.ifname => {
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
            if let Ok(idx) = if_nametoindex(&monitor.ifname) {
                if idx != monitor.ifindex {
                    info!(
                        "Interface {} ifindex changed: {} -> {} (kernel link event)",
                        monitor.ifname, monitor.ifindex, idx
                    );
                    monitor.ifindex = idx;
                }
            }
        }
        monitor.cached_ip = crate::netlink::util::get_interface_ipv4(&monitor.ifname).ok();
    }
}

#[cfg(not(target_os = "linux"))]
fn refresh_affected_interfaces(_monitors: &mut [WanMonitor], _events: &[netlink::link::LinkEvent]) {
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
    let conntrack_mgr = match ConntrackManager::new() {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Conntrack socket: {e}");
            release_pid_file();
            process::exit(1);
        }
    };
    let (netlink_tx, netlink_worker) = spawn_netlink_worker(route_mgr, conntrack_mgr);

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
            cached_ip: crate::netlink::util::get_interface_ipv4(&iface_cfg.name).ok(),
            last_conntrack_flush: None,
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

    info!("mwan4 event loop running. Press Ctrl+C to terminate.");

    loop {
        tokio::select! {
            _ = wait_terminate(&mut sigterm, &mut sigint) => {
                info!("Received termination signal (SIGINT/SIGTERM), exiting cleanly...");
                break;
            }
            events = wait_link_event(&mut link_watch) => {
                if events.is_empty() {
                    warn!("Link watcher stopped; falling back to periodic refresh only");
                    disable_link_watch(&mut link_watch);
                    continue;
                }
                if log::log_enabled!(log::Level::Debug) {
                    let ifindexes: Vec<u32> = events.iter().map(|e| e.ifindex()).collect();
                    debug!("Kernel link/address events for ifindex {ifindexes:?}");
                }
                // 接收緩衝溢位（ENOBUFS）代表中間有事件遺失：
                // 做一次全量 resync，訂閱保持有效（低記憶體路由器開機期容易發生）
                if events
                    .iter()
                    .any(|e| matches!(e, netlink::link::LinkEvent::Resync))
                {
                    warn!("Netlink event buffer overflowed (ENOBUFS); resynchronizing interface state");
                    refresh_interface_state(&mut monitors, "netlink overflow");
                } else {
                    refresh_affected_interfaces(&mut monitors, &events);
                }
            }
            _ = ticker.tick() => {
                tick_count += 1;

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
                }

                // 啟動時解析不到 ifindex 的網卡，一旦可用就立刻補上（不必等輪詢）
                for monitor in monitors.iter_mut() {
                    if monitor.ifindex == 0 {
                        if let Ok(idx) = if_nametoindex(&monitor.ifname) {
                            info!("Resolved ifindex for {}: {}", monitor.ifname, idx);
                            monitor.ifindex = idx;
                        }
                    }
                }

                // 後備輪詢：只在沒訂閱到核心事件時才需要每 5 分鐘兜一次
                if tick_count % IFINDEX_REFRESH_TICKS == 0 {
                    refresh_interface_state(&mut monitors, "periodic refresh");
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

                if !set_unchanged {
                    let new_set: Vec<u32> = monitors
                        .iter()
                        .filter(|m| is_active(m))
                        .map(|m| m.ifindex)
                        .collect();
                    info!(
                        "Active WAN set changed: {:?} -> {:?}",
                        last_active_ifindexes, new_set
                    );

                    let current_active: Vec<ActiveWanRoute> = monitors
                        .iter()
                        .filter(|m| is_active(m))
                        .map(|m| ActiveWanRoute {
                            ifname: m.ifname.clone(),
                            ifindex: m.ifindex,
                            gateway: m.gateway,
                            weight: m.weight,
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

                    // 只有在指令真的進佇列時才更新 last_active_ifindexes。
                    // 若佇列滿了就丟棄（worker 可能卡在 conntrack dump），
                    // 保留舊值讓下一個 tick 重試，否則路由會永久停留在錯誤狀態。
                    match netlink_tx.try_send(NetlinkCmd::Apply(current_active)) {
                        Ok(()) => {
                            // ECMP 的 nexthop 集合一變，核心就會重算 multipath hash，
                            // 既有連線可能被改送到另一條 WAN（源 IP 變了）而卡死。
                            // 因此「成員進出」時也要清一次 conntrack，而不只是 DOWN 的時候。
                            // 開機首次下發不算切換，跳過以免誤清。
                            if flush_on_switch && last_active_ifindexes.is_some() {
                                flush_pending.extend(
                                    monitors
                                        .iter()
                                        .enumerate()
                                        .filter(|(_, m)| is_active(m))
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
        // 注意：若你是透過 WAN 端 SSH 重啟服務，這會讓連線短暫中斷，
        // 可在設定檔把 remove_routes_on_exit 設為 false。
        if let Err(e) = netlink_tx.send(NetlinkCmd::ClearRoutes) {
            warn!("Failed to request default route cleanup: {e}");
        }
    } else {
        warn!("Leaving the mwan4 default route in place (remove_routes_on_exit = false)");
    }
    // 斷開通道讓 worker 執行緒結束
    drop(netlink_tx);
    if netlink_worker.join().is_err() {
        warn!("Netlink worker thread panicked during shutdown");
    }

    let _ = std::fs::remove_file(STATUS_FILE);
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
    /// 快取的介面 IPv4（每次寫狀態檔都做 socket + ioctl 太昂貴）
    cached_ip: Option<std::net::Ipv4Addr>,
    /// 上次對這張網卡做 conntrack 清理的時間（用於限流）
    last_conntrack_flush: Option<Instant>,
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
}

#[derive(serde::Serialize)]
struct DaemonStatus {
    updated_at: u64,
    active_routes: String,
    interfaces: Vec<InterfaceStatus>,
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
        });
    }

    let status = DaemonStatus {
        updated_at: now,
        active_routes: active_routes.to_string(),
        interfaces: iface_statuses,
    };

    if let Ok(json) = serde_json::to_string(&status) {
        if std::fs::write(STATUS_TMP_FILE, json).is_ok() {
            let _ = std::fs::rename(STATUS_TMP_FILE, STATUS_FILE);
        }
    }
}
