use log::{debug, error, info, warn};
use std::env;
use std::io;
use std::process;
use std::time::{Duration, Instant};

mod config;
mod lqe;
mod netlink;
mod prober;

use config::{DaemonConfig, EcmpMode, HashField, MultipathHashPolicy, WeightMode};
use lqe::{LinkQualityEstimator, LinkState};
use netlink::conntrack::ConntrackManager;
use netlink::route::{
    AF_INET, ActiveWanRoute, ActiveWanRouteV6, InstalledVariant, POLICY_RULE_PRIORITY_BASE,
    PROBE_RULE_PRIORITY_BASE, PROBE_TABLE_BASE, PolicyRule, ProbePath, RouteManager,
};
use netlink::util::if_nametoindex;

const STATUS_FILE: &str = "/tmp/mwan4_status.json";
const STATUS_TMP_FILE: &str = "/tmp/mwan4_status.json.tmp";
/// 单实例锁：避免两个 mwan4 行程互相抢夺同一条预设路由
const PID_FILE: &str = "/var/run/mwan4.pid";

/// PID 档路径（可用 `MWAN4_PID_FILE` 覆盖）。
/// 供整合测试在 userns/netns 里跑（那些环境写不进 /var/run）。
fn pid_file_path() -> String {
    std::env::var("MWAN4_PID_FILE").unwrap_or_else(|_| PID_FILE.to_string())
}

/// 后备轮询间隔（约 5 分钟）。
/// 正常情况由 RTNLGRP_LINK / IFADDR 事件即时驱动，
/// 这里只是订阅失败或事件遗漏时的安全网。
const IFINDEX_REFRESH_TICKS: u64 = 600;
/// netlink 指令伫列容量（worker 卡住时丢弃指令而不是无限堆积）
const NETLINK_QUEUE_CAPACITY: usize = 64;
/// 探针路径（独立表 + oif 规则）的定期重新校验间隔（tick 数，约 30 秒）
const PROBE_PATH_REFRESH_TICKS: u64 = 60;
/// 存活集合没有变化时，仍定期重下一次预设路由以自我修复（tick 数，约 30 秒）
const ROUTE_HEARTBEAT_TICKS: u64 = 60;
/// 状态档新鲜度门槛（秒）：超过这个时间没有更新，LuCI 会标成「资料已过期」，
/// 而不是把最后一次快照（可能刚好是两条 DOWN）当成即时状态一直显示。
const STATUS_STALE_SECS: u64 = 10;

/// link watcher 失效后的重订阅间隔（tick 数，约 30 秒）
const LINK_WATCH_RETRY_TICKS: u64 = 60;

/// 过载状态转换时允许「插队」重下权重的最小间隔。
///
/// 转换点值得立刻生效（新连线该马上改走另一条线），但状态机在门槛附近仍可能
/// 每秒翻转一次，而每一次权重变更都是一次 `RTM_NEWROUTE`；这里给一个 1 秒的下限，
/// 让「立刻」不等于「每拍都写」。
const WEIGHT_UPDATE_MIN_SPACING: Duration = Duration::from_millis(1000);

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

/// PID 档案持有的 flock；行程存活期间一直开著（行程结束由核心自动释放）。
static PID_FILE_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// 检查是否已有另一个 mwan4 行程在跑，并取得 PID 档案的独占锁。
///
/// 为什么用 `flock` 而不是「读 PID → 查 /proc/<pid>」：
/// - 两个实例同时启动时，读-判断-写之间有 race，可能都通过检查；
/// - 行程被 abort（panic=abort）后旧 PID 会被核心复用，新实例看到 /proc/<pid>
///   存在就误判「已经有实例在跑」而拒绝启动，procd 进入无尽重试。
///
/// flock 随行程结束自动释放，两种问题都不存在。档案内容只是给人看的。
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

/// 交给 netlink worker 执行绪处理的指令
///
/// Netlink 的 send/recv 都是阻塞式系统呼叫（conntrack 全表 dump 甚至可达数秒），
/// 若直接在 `current_thread` 的非同步主回圈里执行，会把整个探测周期卡住。
/// 因此统一丢到专属执行绪处理，主回圈只做非阻塞的 try_send。
enum NetlinkCmd {
    /// 下发（或于清单为空时删除）IPv4 预设路由
    Apply(Vec<ActiveWanRoute>),
    /// 下发（或于清单为空时删除）IPv6 预设路由
    ApplyV6(Vec<ActiveWanRouteV6>),
    /// 建立／更新「探针路径」：每张 WAN 一张独立表 + 一条 `oif <wan>` 规则，
    /// 必要时再于主表补探针目标的 /32（给 rp_filter 的反向路径检查用）。
    /// 这是让探针不再依赖主表预设路由的关键（见 netlink::route 的说明）。
    ///
    /// `clean_host_routes` 只在启动后第一次下发时为 true：把上一次执行可能残留的
    /// 主表 /32 先清掉，之后才按需补回。
    SetProbePaths(Vec<ProbePath>, bool),
    /// 清理指定网卡们的 conntrack 连线（多张网卡合并为一次全表 dump）
    FlushConntrack(Vec<ConntrackTarget>),
    /// 同步策略分流规则（`from`/`to` + 各 WAN 独立表；空集合 = 全部移除）
    SetPolicies(Vec<PolicyRule>),
    /// 优雅退出：移除本程式下发的预设路由
    ClearRoutes,
}

type NetlinkSender = std::sync::mpsc::SyncSender<NetlinkCmd>;

/// conntrack 清理目标：网卡名 +「DOWN 判定时记下的最后已知 IPv4」。
///
/// 为什么要带旧 IP：flush 是延后执行的，PPPoE 重拨 / USB 重插 / netifd 拆介面
/// 之后现查 IP 会失败或换新；没有旧 IP 就清不到 NAT 到旧位址的既有连线
/// ——正是「长连线卡死」最需要清理的场景。
type ConntrackTarget = (String, Option<std::net::Ipv4Addr>);

/// worker 执行过的「全量期望状态」操作种类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkOp {
    Ipv4Routes,
    Ipv6Routes,
    ProbePaths,
    Conntrack,
    Policies,
}

/// 操作结果回报：主回圈据此判断「已入伫列」是否真的生效，
/// 失败就强制下个 tick 重下（而不是像以前一样只印一行 error 就永久停留）。
#[derive(Debug, Clone)]
struct NetlinkOutcome {
    op: NetlinkOp,
    ok: bool,
    /// 失败原因（给主回圈做去重告警用；成功时为 None）
    detail: Option<String>,
    /// 操作完成后「核心实际生效的 IPv4 预设路由变体」（仅 Ipv4Routes 会带）。
    /// `ecmp_mode=auto` 可能在内核不支援时退回 standard，主回圈必须知道实情。
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
                // worker 卡在耗时操作（如 conntrack 全表 dump）时，伫列里可能积压
                // 多条陈旧的 Apply。它们都是「全量期望状态」且幂等，只有最新一条
                // 有意义——先排空伫列合并成一批再执行，避免把陈旧状态逐条重放。
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
                        // 按专属 metric 转储扫描：连「已从设定移除的目标」留下的 /32
                        // 也一起清掉（只清当前设定里有的目标是不够的）。
                        // **只清探针 /32**：同一批指令里的 Apply 才刚装好 underlay /32，
                        // 连它一起清就会让隧道封装封包走 ECMP 自环（见 route.rs 的
                        // RUNTIME_SWEEP_METRICS 说明；启动前那次才清 underlay）。
                        if let Err(e) = route_mgr.sweep_own_probe_host_routes() {
                            debug!("Probe host route cleanup failed: {e}");
                        }
                    }
                    // 单一网卡暂时不可用（ENODEV / ENETUNREACH）属预期情况：
                    // 记 debug 并在下个周期重试，不要当成致命错误刷屏。
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
// 讯号处理：OpenWrt procd 停止服务时送的是 SIGTERM，
// 只监听 ctrl_c()（SIGINT）会导致服务永远无法优雅退出。
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
// 网卡事件监看：订阅核心的 link / ifaddr 组播，取代定时轮询 ifindex 与 IP
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
type LinkWatch = Option<netlink::link::LinkWatcher>;
/// 非 Linux 平台没有 netlink 可用。这里刻意用一个空哨兵型别而不是 `()`，
/// 好让 `let mut link_watch = ...` 在所有平台都维持同样的形状
/// （`()` 会触发 clippy::let_unit_value）。
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

/// 目前是否仍有可用的 link 事件订阅（非 Linux 平台永远没有）
#[cfg(target_os = "linux")]
fn link_watch_active(w: &LinkWatch) -> bool {
    w.is_some()
}

#[cfg(not(target_os = "linux"))]
fn link_watch_active(_w: &LinkWatch) -> bool {
    false
}

/// 重新解析某张网卡的 ifindex；解析不到就把它标成「不可用」（0）。
///
/// 旧行为是「解析失败就保留旧值」，于是网卡被删除／改名后，一个已经不存在
/// （甚至可能被别的设备复用）的 ifindex 会被继续写进内核路由。这里改成失败即归零，
/// 而 `is_active` / 路由下发都要求 `ifindex != 0`，因此不会再拿死 index 去下发。
///
/// 回传 true 表示 ifindex 有变动（呼叫端可据此重下探针路径）。
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

/// 依据核心事件更新各网卡的 ifindex 与快取 IP
fn refresh_interface_state(monitors: &mut [WanMonitor], reason: &str) -> bool {
    let mut changed = false;
    for monitor in monitors.iter_mut() {
        changed |= refresh_ifindex(monitor, reason);
        monitor.refresh_cached_ip();
    }
    changed
}

/// 依据核心事件只刷新「受影响的」网卡，而不是任何介面的事件都全量重查。
///
/// - Link 事件携带 IFLA_IFNAME：按名称匹配（网卡重建后 ifindex 会变、名称不变，
///   所以必须能用名称重新解析 ifindex）
/// - Address 事件只有 ifindex：按当前 ifindex 匹配即可（位址变动不换 ifindex）
///
/// 路由器上 LAN 桥、wifi、IPv6 临时位址的事件远多于 WAN 事件，
/// 过滤掉不相关事件可避免每次都对全部网卡做 7~9 个系统呼叫。
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
    // 1. 初始化日志输出（预设为 INFO 等级）
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // 2. 解析命令列参数
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

    // 3a. 只验证设定档而不启动（给 init 脚本 / CI 使用，避免设定错误时靠 procd 重启硬试）
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

    // 3. 载入配置
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

    // 3b. 单实例锁：两个 mwan4 同时操作同一条预设路由会互相覆盖
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

    // 4. 初始化 Linux 核心 Netlink 控制器，并交由专属执行绪操作
    //    这里用明确的错误讯息 + exit(1) 取代 expect()：
    //    release 版开了 panic=abort，panic 只会留下一行堆叠，procd 也拿不到有用的退出码
    let route_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize Netlink Route socket: {e} (is CAP_NET_ADMIN granted?)");
            release_pid_file();
            process::exit(1);
        }
    };
    // 启动前先扫掉自己保留区段内残留的探针规则／表内路由：上次执行的介面顺序若与
    // 这次不同，残留的 `oif <wan> lookup <旧表>` 会把探针导向旧闸道。
    let mut route_mgr = route_mgr;
    if let Err(e) = route_mgr.sweep_probe_paths() {
        warn!("Failed to sweep stale probe paths on startup: {e}");
    }
    // 清掉上一次执行可能留下的主表 /32：探针（metric 42760）与隧道 underlay（42761）
    // 都在这里清。按专属 metric 转储扫描，能涵盖已从设定移除、或当时设备还不存在的目标；
    // underlay /32 的出口（ifindex/gateway）上次执行可能已经不同，开机时一次清干净，
    // 之后由 apply_default_routes → sync_underlay_routes 按当前期望重新补回。
    // 执行期（SetProbePaths 的 clean）则只清探针 /32——那里清 underlay 会把刚装好的删掉。
    match route_mgr.sweep_all_own_host_routes() {
        Ok(0) => {}
        Ok(n) => info!("Cleaned up {n} leftover mwan4 host route(s) on startup"),
        Err(e) => warn!("Failed to clean up leftover mwan4 host routes: {e}"),
    }
    // 策略分流规则的保留区段也先清：上次执行的规则可能指向已不存在的表/网关，
    // 或与这次的 policy 集合不同（`set_policy_rules` 只信记忆体快取）。
    if let Err(e) = route_mgr.sweep_policy_rules() {
        warn!("Failed to sweep stale policy rules on startup: {e}");
    }
    // 只用来「问内核路径」的查询用 socket：判断主表有没有涵盖目标、以及探针失败时
    // 是不是「本机根本没有路」。与 worker 的写入 socket 分开，避免互相干扰。
    let mut query_mgr = match RouteManager::new(config.route_priority, config.ecmp_mode) {
        Ok(m) => {
            // 这是事件回圈上同步使用的查询 socket：逾时缩短到 300ms，避免内核一时
            // 不回应时每次查询阻塞 2 秒（多张网卡叠加会冻住整个 current_thread runtime）
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
    // worker 执行绪建立失败（极端资源不足）不该用 expect 直接 abort：
    // panic=abort 下 expect 会让进程在 pid 档与路由清理之前直接消失。
    let (netlink_tx, netlink_rx, netlink_worker) =
        match spawn_netlink_worker(route_mgr, conntrack_mgr) {
            Ok(parts) => parts,
            Err(e) => {
                error!("Failed to start the netlink worker: {e}");
                release_pid_file();
                process::exit(1);
            }
        };

    // 5. 初始化各 WAN 网卡的 LQE 状态机与 ifindex 解析
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

    // 只有至少一张网卡设定了 gateway6 才需要处理 IPv6 路由
    let has_ipv6 = monitors.iter().any(|m| m.gateway6.is_some());
    if has_ipv6 {
        info!("IPv6 default route management enabled (interfaces with gateway6)");
    } else if let Ok(table) = std::fs::read_to_string("/proc/net/ipv6_route") {
        // 没设 gateway6 = 不管理 IPv6 路由：v6 流量会一直走 netifd 那一条预设路由（单线），
        // 而这年头视频（YouTube、Bilibili 的 QUIC）常常正好走 v6 —— §6.1 的「按连线分流」
        // 对它完全没有作用。这种「IPv4 分流调好了、v6 视频还是卡」的落差不说清楚很难查，
        // 所以在真的存在 v6 预设路由时提示一次。
        if has_kernel_ipv6_default_route(&table) {
            info!(
                "IPv6 default route exists but no interface has 'gateway6' configured: IPv6 \
                 traffic is NOT managed by mwan4 (no failover, no per-connection spreading) and \
                 keeps using the kernel's single default route. Video over IPv6 will not benefit \
                 from the multipath hash policy. Set gateway6 on each WAN to include IPv6."
            );
        }
    }

    // 多路径哈希策略：写入内核 sysctl，决定「怎么分」——只有 policy 这一个有效开关
    // （见 `apply_multipath_hash` 的说明：实测 fields 会被内核忽略）。
    // 失败只告警（旧内核没有这些档案），不影响启动。
    let effective_hash = apply_multipath_hash(config.multipath_hash_policy, has_ipv6);
    let effective_hash_v4 = effective_hash
        .iter()
        .find(|(label, _)| *label == "ipv4")
        .map(|(_, eff)| *eff)
        .unwrap_or_default();
    // 两条线以上而内核只按 L3 哈希就是实打实的缺陷：同一个目的 IP（视频 CDN 的典型
    // 形态）的所有连线只会走同一条 WAN，另一条线完全用不到——这正是「多 WAN 了还是卡」
    // 最常见的成因。使用者明确选了 l3/inner 时只提示（他知道自己在做什么）；
    // 若他是写 null（不写入、沿用系统预设）而拿到 L3，那是没预料到的 → 告警。
    if monitors.len() >= 2 && effective_hash_v4.l3_only() {
        if config.multipath_hash_policy.is_some() {
            info!(
                "Multipath hash granularity is L3-only ({}) because multipath_hash_policy is \
                 set explicitly; connections to the same destination IP stay on one WAN \
                 (video CDNs, multi-threaded downloads). Use \"l4\" to spread them per \
                 connection.",
                effective_hash_v4.describe()
            );
        } else {
            warn!(
                "Multipath hash granularity is L3-only ({}): with multipath_hash_policy set to \
                 null the kernel's own default is used, and it hashes addresses only - every \
                 connection to the same destination IP uses ONE WAN, so a video CDN's \
                 connections cannot be spread over both lines. Set multipath_hash_policy to \
                 \"l4\" (the default when the key is omitted).",
                effective_hash_v4.describe()
            );
        }
    }

    // 6. 主非同步事件循环 (Single-threaded Non-blocking Event Loop)
    let probe_interval = Duration::from_millis(config.check_interval_ms);
    let probe_timeout = Duration::from_millis(config.probe_timeout_ms);
    let conntrack_flush_min_interval =
        Duration::from_millis(config.conntrack_flush_min_interval_ms);
    // 使用 resilient nexthop group 时，核心只会重映射故障成员的 flow，其余连线本来
    // 就不会断；这时若还在「成员变动」时清 conntrack，反而会亲手打断那些被保留的连线。
    // 因此实际安装的是 resilient 时关闭 flush-on-switch（flush-on-down 仍然保留：
    // 已死链路上的连线本来就该清掉）。
    //
    // FIX-8：判断依据是 worker 回报的**实际安装变体**，而不是设定值 `ecmp_mode`——
    // `auto` 在内核不支援 resilient（< 5.14 或成员数超限）而退回 standard 时，
    // 仍必须在切换瞬间清 conntrack。首次回报前保守视为 standard（与预设一致）。
    let mut kernel_resilient = false;
    let mut kernel_variant_known = false;
    let mut ticker = tokio::time::interval(probe_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let (mut sigterm, mut sigint) = install_signal_handlers();
    let mut link_watch = install_link_watcher();

    let mut tick_count: u64 = 0;
    // None 代表「尚未下发过任何路由」，与「已知没有存活线路」区分开来，
    // 避免开机第一次探测就把别人（netifd）的预设路由删掉
    let mut last_active_ifindexes: Option<Vec<u32>> = None;
    // IPv6 路由更新入队失败时暂存待重试的 payload。
    // last_active_ifindexes 只跟随 IPv4 的入队结果更新，若不显式重试，
    // v6 更新在 need_apply 变回 false 后会永久丢失。
    let mut v6_pending: Option<Vec<ActiveWanRouteV6>> = None;
    // 探针路径需要（重）下发：开机、ifindex 变动、上次失败、或定期校验
    let mut probe_paths_dirty = true;
    let mut probe_paths_inflight = false;
    let mut probe_paths_retry_at: u64 = 0;
    // 第一次下发探针路径时，顺手清掉上一次执行可能残留的主表 /32
    let mut probe_host_routes_cleanup = true;
    // 预设路由下发失败（worker 回报）或心跳到期时，即使存活集合没变也要重下
    let mut v4_apply_dirty = false;
    let mut v4_apply_inflight = false;
    let mut v4_retry_at: u64 = 0;
    // link watcher 失效后的重订阅时间点
    let mut link_watch_retry_at: u64 = 0;
    // 路由下发失败的告警去重（避免永久失败时刷屏冲掉 logd 环形缓冲）
    let mut route_fail_count: u64 = 0;
    let mut last_route_fail: Option<String> = None;
    // conntrack 清理失败的告警去重（同一种错误只提醒一次，之后每 20 次一次）
    let mut conntrack_fail_count: u64 = 0;
    let mut last_conntrack_fail: Option<String> = None;
    // netlink worker 意外结束只告警一次（避免每个 tick 刷屏）
    let mut netlink_worker_gone = false;
    // strict rp_filter + 共用探针目标的告警只说一次
    let mut strict_shared_warned = false;
    // 「全部线路都降级、仍保底承载一条」的告警去重（品质恢复后重新允许告警）
    let mut degrade_fallback_warned = false;
    // 「动态因子在 standard ECMP 下被忽略」的告警去重（只说一次）
    let mut dynamic_factor_gate_warned = false;
    // 动态/容量权重状态：更新限速 + 需要重下路由的旗标。
    // 起点刻意往前推一个 interval，让第一个 tick 就算出容量比例/品质权重，
    // 而不是先跑 10 秒的设定 weight 才切换。
    let dynamic_weight_interval = Duration::from_millis(config.dynamic_weight_interval_ms);
    let mut weights_dirty = false;
    let mut last_weight_update = Instant::now()
        .checked_sub(dynamic_weight_interval)
        .unwrap_or_else(Instant::now);
    // 策略分流规则的下发状态（差异比对 + 失败重试 + 定期心跳）
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
                    // 订阅失效是可恢复的：关掉它、退回轮询，并在稍后尝试重新订阅
                    // （旧行为是永久放弃事件驱动，ifindex 最长 5 分钟才被修正）
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
                // 接收缓冲溢位（ENOBUFS）代表中间有事件遗失：
                // 做一次全量 resync，订阅保持有效（低记忆体路由器开机期容易发生）
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

                // 0) 收集 worker 的操作结果。失败不再只是「印一行 error 就永久停留」：
                //    这里把它标成 dirty，下个 tick 重下同一份期望状态（Apply 是幂等的）。
                while let Ok(outcome) = netlink_rx.try_recv() {
                    match outcome.op {
                        NetlinkOp::Ipv4Routes => {
                            v4_apply_inflight = false;
                            if !outcome.ok {
                                // 去重告警：同一个错误只报一次（之后每 20 次提醒一次），
                                // 避免永久失败时以每 2 秒一条的速度把 logd 环形缓冲冲掉，
                                // 反而盖掉真正有用的讯息
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
                            // IPv6 的期望状态会在心跳或集合变动时一起重送
                            if !outcome.ok {
                                debug!("IPv6 FIB update failed; it will be re-applied with the next heartbeat");
                            }
                        }
                        NetlinkOp::ProbePaths => {
                            probe_paths_inflight = false;
                            if !outcome.ok {
                                // 网卡暂时不可用属预期情况（设备已 down），退避后再试
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
                                // 失败的 flush 不能算「本次 DOWN 已清」：把仍在 DOWN 的线
                                // 重设，静默期与限流过后会再送一次（清理本身幂等）。
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
                                // 保留旧签章不动：下个周期会重送同一份期望状态
                                policies_dirty = true;
                                policies_retry_at = tick_count + 6;
                            }
                        }
                    }
                }

                // worker 若意外结束，try_recv 只回 Disconnected，上面的 while let 直接跳出
                // 且不会有任何告警——inflight 旗标会永远卡住，看起来像「一直在等下发」。
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

                // 0b) link watcher 若曾失效，这里尝试重新订阅（不必等 5 分钟轮询）
                if !link_watch_active(&link_watch) && tick_count >= link_watch_retry_at {
                    link_watch = install_link_watcher();
                    if link_watch_active(&link_watch) {
                        info!("Link watcher re-subscribed successfully");
                    } else {
                        link_watch_retry_at = tick_count + LINK_WATCH_RETRY_TICKS;
                    }
                }

                // 上一个 tick 的 IPv6 路由更新若因伫列满而未入队，这里补送
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

                // 并行探测所有 WAN 接口（直接借用 monitors，不再每个 tick clone 一份）
                let mut probe_futs = Vec::with_capacity(monitors.len());
                for monitor in monitors.iter() {
                    // 上一拍失败的线视为「疑似故障」：把该线的所有探针目标同时发出，
                    // 否则「先等主目标超时、再探其余目标」会让整拍花 2 × timeout
                    // （预设 800ms > 500ms 周期），判 DOWN 与恢复都要多花近一倍时间。
                    probe_futs.push(prober::probe_interface(
                        &monitor.ifname,
                        &monitor.targets,
                        probe_timeout,
                        monitor.preferred_target,
                        monitor.lqe.consecutive_timeouts > 0,
                    ));
                }
                let samples = futures_util::future::join_all(probe_futs).await;
                let mut state_changed = false;
                // 本 tick 内需要清理 conntrack 的网卡（以 monitors 下标记录）。
                // bool = 是否来自 flush-on-down：只有这种来源才需要在「成功入队之后」
                // 标记 `flushed_while_down`（flush-on-switch 时线路仍是 UP，没有这回事）。
                // 统一延后到路由下发之后才入队：conntrack 全表 dump 可达数秒，
                // 排在 Apply 前面（同一 worker 执行绪 FIFO）会拖慢故障切换的实际收敛。
                let mut flush_pending: Vec<(usize, bool)> = Vec::new();

                // 喂入样本更新各链路 LQE 状态机
                for (monitor, sample) in monitors.iter_mut().zip(samples.into_iter()) {
                    // 探通的目标成为下个周期的主目标：健康时每周期只发一条探针。
                    // 某个目标被过滤时，它先失败一次，之后由探通的那个接手，不会每周期
                    // 都白吃一次超时；直到接手的主目标也失败才会再回退到它。
                    if sample.success {
                        if let Some(idx) = monitor.targets.iter().position(|t| *t == sample.target) {
                            monitor.preferred_target = idx;
                        }
                    }

                    let (new_state, changed) = monitor.lqe.update(&sample);
                    if changed {
                        state_changed = true;
                        // 状态切换时顺势刷新快取的 IP
                        monitor.refresh_cached_ip();

                        // 只记录「何时进入 DOWN」（以及恢复时重置），
                        // 真正的 conntrack 清理延后到确认这不是短暂抖动之后，
                        // 见下方「抖动保护」排程处的说明。
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

                    // 记录最近一次失败原因：这是现场区分「线路真的丢包」与
                    // 「本机没有路由／设备名错误」的唯一线索，必须进状态档。
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

                            // 「设备 UP 但没有经它的路」时内核会按 on-link 送出，探针只会超时——
                            // 这与真正的丢包在日志上长得一模一样。连续失败时主动问一次内核，
                            // 把这种情况标成 local_condition（每张网卡最多每 2 秒查一次）。
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

                // 启动时解析不到 ifindex 的网卡，一旦可用就立刻补上（不必等轮询）
                for monitor in monitors.iter_mut() {
                    if monitor.ifindex == 0 && refresh_ifindex(monitor, "retry after startup") {
                        info!(
                            "Resolved ifindex for {}: {}",
                            monitor.ifname, monitor.ifindex
                        );
                        probe_paths_dirty = true;
                    }
                }

                // 后备轮询：只在没订阅到核心事件时才需要每 5 分钟兜一次
                if tick_count % IFINDEX_REFRESH_TICKS == 0
                    && refresh_interface_state(&mut monitors, "periodic refresh")
                {
                    probe_paths_dirty = true;
                }

                // 依据 Metric 优先级挑选当前生效的网卡群：
                // 1. 若存活网卡 Metric 相同（例如皆为预设 10），全部加入 Multipath ECMP 做分流
                //    （按 flow 哈希，多并行连线的总吞吐可叠加）
                // 2. 若存活网卡 Metric 不同，仅挑选 Metric 数值最小（优先级最高）的存活网卡下发为预设路由（完全主备容灾）
                let min_up_metric = monitors
                    .iter()
                    .filter(|m| m.lqe.state == LinkState::Up && m.ifindex != 0)
                    .map(|m| m.metric)
                    .min();

                // 「Up 且 metric 最小」= 尚未计入降级前的承载资格。
                // ⚠️ 探针主表 /32 的 wants_it（下方 probe-path 决策）必须用这个，
                // **不能**用 is_active：那里的 `!active` 语意是「这条线当前不承载流量」，
                // 而降级的线只是被移出 ECMP（仍在探测、仍是 Up 且 metric 最小），
                // 不该被当成「非活跃线」去抢主表 /32。
                let up_primary = |m: &WanMonitor| {
                    m.lqe.state == LinkState::Up && m.ifindex != 0 && Some(m.metric) == min_up_metric
                };

                // 基于实测品质的降级：窗口已满且丢包率达到 degrade_loss_threshold 的线
                // 不参与 ECMP（但仍继续探测，品质恢复后自动回归）。
                // 旧行为只看「有没有判 DOWN」，于是 20%~50% 丢包的线照样吃一半流量。
                let any_undegraded = monitors
                    .iter()
                    .any(|m| up_primary(m) && !m.lqe.is_degraded());
                // 保底：全部降级时不能一条都不承载（否则会完全没有预设路由），
                // 在「Up 且 metric 最小」的线里取设定顺序最前面的那条。
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

                // 取样各 WAN 的即时速率（状态档 / LuCI 显示用，也让分流效果可验证）
                let stats_now = Instant::now();
                for monitor in monitors.iter_mut() {
                    sample_interface_rates(monitor, stats_now);
                }

                // 动态权重：`weight_mode = quality`（依 LQE 品质）与 `load_aware`
                // （依实测速率 vs 容量）可独立或叠加。更新有限速——每次变更都会重下
                // ECMP 路由，内核可能重算 multipath hash，过度频繁会反复打断既有 flow。
                // 品质差到门槛的线仍由降级/DOWN 机制移出。
                // 容量比例分流（有 max_mbps）本身也是动态下发的一部分：
                // 基准权重由 weight 换成 ∝ max_mbps，必须走同一条重下路径。
                let dynamic_weights_on = config.weight_mode == WeightMode::Quality
                    || config.load_aware
                    || config.capacity_weights_on();
                // 动态因子（quality / load_aware）只在「不是 standard ECMP」或使用者明确
                // 覆写时才生效：standard 模式底下的每一次权重变更都会重算整张 multipath
                // hash，把 24%~39% 的**既有**连线改送到另一条 WAN（NAT 源 IP 跟著换 →
                // 对端 RST/大量重传），而它无法把已建立的大流量搬走，净效果是「打断连线
                // 却换不到分流」。实测（2026-09，使用者路由器）quality+load_aware+standard
                // 让 wg 权重每 10~20 秒在 1 与 4 之间跳动，期间使用者持续回报卡顿。
                let dynamic_factors_on = dynamic_factors_allowed(&config, kernel_resilient);
                // 只在「已经知道内核实际装的是 standard」之后才告警。
                // 为什么必须等回报：worker 的变体回报要等第一次下发才有，而闸门在开机第一拍
                // 只能保守当成 standard——否则会在**支援 resilient 的机器上**（ecmp_mode:
                // auto）印出「dynamic weight factors are IGNORED」，使用者照提示去改设定
                // 才发现早就设好了（实机 2026-09 踩到）。
                if dynamic_weights_on
                    && !dynamic_factors_on
                    && kernel_variant_known
                    && !dynamic_factor_gate_warned
                    && (config.weight_mode == WeightMode::Quality || config.load_aware)
                {
                    dynamic_factor_gate_warned = true;
                    let remedy = if config.ecmp_mode == EcmpMode::Standard {
                        "Use ecmp_mode: resilient (or auto) to make weight changes safe, or set \
                         allow_dynamic_weights_on_standard: true to override this guard."
                    } else {
                        "ecmp_mode is 'auto'/'resilient' but this kernel has no usable nexthop \
                         object support (auto falls back to standard), so the guard stays on; \
                         set allow_dynamic_weights_on_standard: true only if you accept the \
                         rehash cost above."
                    };
                    warn!(
                        "weight_mode/load_aware is configured but the installed ECMP variant is \
                         'standard': dynamic weight factors are IGNORED (keep only the static \
                         weight / max_mbps ratio). In standard mode every weight change recomputes \
                         the whole multipath hash and re-homes 24%~39% of *established* connections \
                         (their NAT source IP changes -> RST / heavy retransmits), while it cannot \
                         move the established flows that caused the imbalance. {remedy}"
                    );
                }
                // 负载压力的 Schmitt 触发器每拍都要更新：它纯粹是记忆体状态（不写内核），
                // 而「某条线刚开始吃满 / 刚解除」这个转换点必须被立刻看到——
                // 旧版把它夹在 10 秒限速里，于是过载发生后的头 10 秒新连线照样往那条线丢，
                // 视频就是在这段时间里开始缓冲。
                let active_flags: Vec<bool> = monitors
                    .iter()
                    .enumerate()
                    .map(|(slot, m)| is_active(slot, m))
                    .collect();
                let pressure_transition = if dynamic_weights_on
                    && config.load_aware
                    && dynamic_factors_on
                {
                    update_load_pressure(
                        &mut monitors,
                        &active_flags,
                        config.load_target_ratio,
                        config.load_recover_ratio,
                    )
                } else {
                    false
                };
                if dynamic_weights_on
                    && weight_update_due(
                        last_weight_update.elapsed(),
                        dynamic_weight_interval,
                        pressure_transition,
                        WEIGHT_UPDATE_MIN_SPACING,
                    )
                {
                    let new_weights = compute_dynamic_weights(
                        &monitors,
                        |slot, _| active_flags[slot],
                        &config,
                        dynamic_factors_on,
                    );
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
                            "Dynamic ECMP weights updated (quality={}, load={}, capacity={}, \
                             load-transition={}): {}",
                            config.weight_mode == WeightMode::Quality,
                            config.load_aware,
                            config.capacity_weights_on(),
                            pressure_transition,
                            desc.join(" ")
                        );
                        for (slot, monitor) in monitors.iter_mut().enumerate() {
                            monitor.effective_weight = new_weights[slot];
                        }
                        weights_dirty = true;
                    }
                    last_weight_update = Instant::now();
                }

                // 无分配的快速比较：多数 tick 存活集合其实没变，
                // 先用迭代直接比对，只有真的变了才构建路由描述并入队。
                let active_count = monitors
                    .iter()
                    .enumerate()
                    .filter(|(slot, m)| is_active(*slot, m))
                    .count();
                let set_unchanged = match &last_active_ifindexes {
                    // 尚未下发过任何路由：没有存活线路时维持「不做」（不删除既有路由）
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

                // 只有在指令真的进伫列时才更新 last_active_ifindexes。
                // 若伫列满了就丢弃（worker 可能卡在 conntrack dump），
                // 保留旧值让下一个 tick 重试，否则路由会永久停留在错误状态。
                //
                // need_apply 除了「集合真的变了」以外，还包含三种自我修复：
                //   * weights_dirty：动态权重刚更新；
                //   * v4_apply_dirty：worker 回报内核拒绝（EINVAL/ENODEV…）后重下；
                //   * 心跳：集合没变也定期重下，修复被别的程序／内核事件改掉的路由。
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
                        // 只印 `[3, 11] -> [3]` 完全看不出「为什么少了一条」：降级、
                        // 判 DOWN、ifindex 解析失败都长得一样。把每条线的状态与
                        // 「是否在集合内 / 是否降级」一起写出来，排障才不用猜。
                        let detail: Vec<String> = monitors
                            .iter()
                            .enumerate()
                            .map(|(slot, m)| {
                                format!(
                                    "{}#{}:{}{}{}",
                                    m.ifname,
                                    m.ifindex,
                                    m.lqe.state,
                                    if is_active(slot, m) {
                                        " in"
                                    } else {
                                        " out"
                                    },
                                    if m.lqe.is_degraded() { " degraded" } else { "" }
                                )
                            })
                            .collect();
                        info!(
                            "Active WAN set changed: {:?} -> {:?} [{}]",
                            last_active_ifindexes,
                            new_set,
                            detail.join(" | ")
                        );
                    }
                    // 存活集合一变，「哪些线需要主表 /32」也跟著变（见探针路径那一段），
                    // 这里标记重下，否则 /32 会停留在不该留的时候
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

                    // 只有设定了 gateway6 的网卡才会产生 IPv6 nexthop；
                    // IPv6 路由跟随同一个 IPv4 健康状态（同一条实体链路）
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

                            // ECMP 的 nexthop 集合一变，核心就会重算 multipath hash，
                            // 既有连线可能被改送到另一条 WAN（源 IP 变了）而卡死，
                            // 所以「成员新进入存活集合」时要清一次 conntrack，
                            // 而不只是该线自己判 DOWN 的时候。开机首次下发不算切换，跳过。
                            //
                            // 清理名单只包含「新进入存活集合」的成员：
                            //   `is_active(m) && !prev.contains(&m.ifindex)`
                            // 为什么不再连坐其他存活成员——修复前的条件是
                            // `is_active(m) && (multipath_involved || !prev.contains(&m.ifindex))`，
                            // 而 `multipath_involved = prev.len() > 1 || new_set.len() > 1`
                            // 在双线 ECMP 下**恒为真**，于是只要成员集合一变，所有存活成员
                            // （包含一直健康的那条）都被列入清理名单；而清理本身是按 WAN IP
                            // 匹配 ORIG/REPLY（conntrack.rs），列进名单等于清掉该线全部连线。
                            // 实测日志：
                            //   [INFO ] [Conntrack] Flushing active conntrack sessions for wan1 ...
                            //   [INFO ] [Conntrack] Flushing active conntrack sessions for wan0, wan1 ...
                            // 只有 wan1 健康却被清、恢复瞬间两条都清 → NAT 后的连线被 RST，
                            // 使用者看到的就是「网站打不开、连线断掉」。
                            //
                            // 离开集合的成员本来就不在 is_active 里，由 flush-on-down 的
                            // 25 秒静默路径（CONNTRACK_FLUSH_DOWN_QUIET）负责清理。
                            //
                            // flush-on-switch 是否生效由「实际安装变体」决定（FIX-8）：
                            // resilient 只重映射故障成员的 bucket，清 conntrack 反而
                            // 会亲手打断被保留的连线，所以只有 standard 才清。
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
                                                // 刚从 DOWN 回来的线还在抖动静默期：
                                                // flush-on-switch 若在此时清它，等于绕过
                                                // 25 秒保护，把「其实还活著」的连线砍掉
                                                // （README 承诺「期间若恢复就不清」）。
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
                                        // try_send 失败时指令会原样退回，暂存待下个 tick 重试，
                                        // 否则 v6 更新会随 need_apply 变回 false 而永久丢失
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

                // 探针路径（每张 WAN 一张独立表 + `oif <wan>` 规则）：让探针完全不依赖
                // 主表那条预设路由。这是「停线→恢复」不再自锁的结构性保证。
                // 触发时机：开机、ifindex 变动、上次失败、每 30 秒定期校验。
                if tick_count % PROBE_PATH_REFRESH_TICKS == 0 {
                    probe_paths_dirty = true;
                }
                if probe_paths_dirty && !probe_paths_inflight && tick_count >= probe_paths_retry_at {
                    // 「主表有没有预设路由」是这一切的关键判断，必须问内核，而且问的必须是
                    // **预设路由**（含我们自己下发的那条）——不能问「有没有到目标的路」：
                    // 我们自己补的探针 /32 也是「到目标的路」，会形成自我参照
                    // （补了 → 认为已涵盖 → 决定不补 → 把刚补的删掉 → 又没涵盖 → 再补），
                    // 实测会变成装/删各 13 次的振荡，那条线永远累积不到恢复所需的连续成功。
                    let main_has_default = match query_mgr
                        .as_mut()
                        .map(|q| q.has_main_default_route(AF_INET))
                    {
                        Some(Ok(has)) => has,
                        Some(Err(e)) => {
                            // 查不到时偏向「没有」：多补一条 /32 只是短暂影响该目标的转发，
                            // 而不补则可能让线路永远回不来（原本的 bug）
                            debug!("default-route query failed ({e}); assuming there is none");
                            false
                        }
                        None => false,
                    };

                    // 1) 先算每条线「想不想要」主表 /32
                    let mut wants: Vec<(usize, u32, bool, bool, bool, bool, bool)> = Vec::new();
                    for (slot, m) in monitors.iter().enumerate() {
                        if m.ifindex == 0 {
                            continue;
                        }
                        // 「承载中」= Up 且 metric 最小，**不排除降级的线**。
                        //
                        // ⚠️ 这里刻意不用 is_active：这个 `!active` 的语意是「这条线当前
                        // 不承载流量 → 需要主表 /32 才收得到回程」。降级的线只是被移出
                        // ECMP，它仍在探测、仍是 Up 且 metric 最小；若把它算成「非活跃线」，
                        // 它就会以「想补 /32」的身分去跟真正承载的线抢同一个目标的 /32
                        // （owner_of 只挑一个拥有者），反而让承载中的线拿不到回程路径。
                        let primary = up_primary(m);
                        let strict = effective_rp_filter(&m.ifname) == 1;
                        let shared = monitors.iter().any(|o| {
                            o.ifname != m.ifname && o.targets.iter().any(|t| m.targets.contains(t))
                        });
                        // 活跃线走主表那条预设路由，反向检查自然过，不需要补
                        let wants_it = !primary && (!main_has_default || (strict && !shared));
                        // 「这条线能不能真的用」——用内核查询判断（绑定该设备时到目标有没有路），
                        // 比看 sysfs 可靠（netns/精简系统不一定有 /sys/class/net）：
                        // 设备已 down 时内核会回「没有路」，我们就不该把唯一的 /32 给它。
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

                    // 2) 同一个目标只能有一个拥有者（主表同一前缀只有一条路由）：
                    //    在「想补」的线里挑选，**优先挑设备真的可用的**（否则会把机会浪费在
                    //    已经 down 的线上，另一条拿不到回程路径 → 两条一起掉），同群再取
                    //    metric 最小者，让主线优先被监测而不是取决于设定顺序或竞速。
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

                // 策略分流规则（from/to + 各 WAN 独立表）：目标 WAN DOWN 时整条政策
                // 从期望集合移除（流量回退 ECMP），恢复后自动回来；定期心跳重下，
                // 修复被外部删掉的规则（`set_policy_rules` 内部做差异比对）。
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

                // 路由下发之后才排程 conntrack 清理：多张网卡合并为一条指令、
                // worker 只扫一次全表。每网卡限流在这里检查，入队成功才更新时间戳。
                //
                // 抖动保护（重要）：线路刚被判 DOWN 就清 conntrack，会把该线路上「其实还活著」
                // 的连线一次全砍掉。实测隧道抖动触发一次 DOWN 就砍了 495 条，使用者直接看到
                // 「网站打不开、连线断掉」，而几秒后线路自己就恢复了。
                // 因此这里改成：DOWN 之后再等 CONNTRACK_FLUSH_DOWN_QUIET，确认它「持续」
                // 不可用才清；期间若恢复（抖动），连线就保住了，代价只是晚几秒切换。
                if config.flush_conntrack_on_down {
                    let now = Instant::now();
                    for (idx, monitor) in monitors.iter().enumerate() {
                        if monitor.flushed_while_down {
                            continue;
                        }
                        if let Some(since) = monitor.down_since {
                            if now.duration_since(since) >= CONNTRACK_FLUSH_DOWN_QUIET {
                                // ⚠️ 这里只收集，**不**先标记 `flushed_while_down`：
                                // 下面还有 `conntrack_flush_min_interval` 限流，被跳过的线
                                // 若已经标记，下个 tick 开头就会被上面的
                                // `if monitor.flushed_while_down { continue; }` 略过
                                // → 整段 DOWN 期间再也不会尝试清理（只有下次 UP→DOWN 才重置），
                                // 这次 DOWN 的 flush 就永久丢失了。
                                // 置位一律延后到真正入队成功之后（见 flush_conntrack）。
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

                // 每 2 个周期（约 1 秒）或状态变更时，原子更新 /tmp/mwan4_status.json 提供给 LuCI 即时读取
                if tick_count % 2 == 0 || state_changed {
                    let active_names: Vec<&str> = monitors
                        .iter()
                        .enumerate()
                        .filter(|(slot, m)| is_active(*slot, m))
                        .map(|(_, m)| m.ifname.as_str())
                        .collect();
                    let route_desc = build_route_desc(&monitors, &active_names);
                    write_status_file(&monitors, &route_desc, &config, effective_hash_v4);
                }

                // 每 10 个周期（约 5 秒）输出一次所有 WAN 的即时品质摘要
                if tick_count % 10 == 0 {
                    for monitor in &monitors {
                        info!("[{}] {}", monitor.ifname, monitor.lqe.summary());
                    }
                }
            }
        }
    }

    // 7. 优雅退出
    if config.remove_routes_on_exit {
        // 移除本程式下发的预设路由，避免残留指向已失效的链路。
        // 注意：这会在「旧实例已退出、新实例还没下发」的窗口内让整台路由器失去出口，
        // 因此预设是 false，需要明确开启。
        if let Err(e) = netlink_tx.send(NetlinkCmd::ClearRoutes) {
            warn!("Failed to request default route cleanup: {e}");
        }
    } else {
        // 预设路由保留（避免重启窗口断网），但**探针路径一定要拆掉**：
        // 那是一组 `oif <wan> lookup <table>` 规则与独立表路由，留著会指向
        // 可能已经不存在的网关，也会让下次启动的规则语意变得不可预期。
        info!("Leaving the mwan4 default route in place (remove_routes_on_exit = false)");
        // 策略规则一定要拆：它们指向各 WAN 的探针表，而探针表马上就会被拆掉；
        // 留著会让匹配的流量查不到路由（黑洞），而不是回退 ECMP。
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetPolicies(Vec::new())) {
            warn!("Failed to request policy rule cleanup: {e}");
        }
        if let Err(e) = netlink_tx.send(NetlinkCmd::SetProbePaths(Vec::new(), false)) {
            warn!("Failed to request probe path cleanup: {e}");
        }
    }
    // 断开通道让 worker 执行绪结束
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

/// 线路判 DOWN 之后，要「持续」不可用多久才动手清 conntrack。
///
/// 为什么要拖：隧道型线路（VXLAN/WireGuard）常有几秒到十几秒的抖动，而清 conntrack
/// 会把该线路上所有连线一次砍掉（实测一次 495 条），使用者立刻看到「网站打不开」。
///
/// 这个值要盖过「判 DOWN + 抖动本身 + 恢复所需时间」：
/// 以预设参数为例，连续 3 次失败 ≈ 2.4s 才判 DOWN，恢复要 5 次连续成功 ≈ 4s
/// （实测这台设备用了 9 次 ≈ 7s），所以一次 8 秒的抖动实测约 12 秒才能回到 UP。
/// 10 秒的静默期刚好被跨过去、仍然误清；25 秒能稳稳挡住这类抖动。
///
/// 代价：真断线时晚 25 秒清连线。但用户端 TCP 本来就要自我重传超时（通常 20s+），
/// 所以实际感受几乎没有差别；而误清是「立刻全断」，两者不对等。
const CONNTRACK_FLUSH_DOWN_QUIET: Duration = Duration::from_secs(25);

struct WanMonitor {
    ifname: String,
    ifindex: u32,
    gateway: Option<std::net::Ipv4Addr>,
    gateway6: Option<std::net::Ipv6Addr>,
    metric: u32,
    weight: u32,
    /// 实际下发到 ECMP 的权重：未启用任何动态模式时等于 `weight`；
    /// `weight_mode=quality` / `load_aware` 时由品质与负载计算
    /// （见 `compute_dynamic_weights`）。
    effective_weight: u32,
    /// 介面累计位元组（取自 /sys/class/net/<if>/statistics），用于计算即时速率
    last_tx_bytes: Option<u64>,
    last_rx_bytes: Option<u64>,
    /// 上次取样时刻与算出的速率（bit/s），供状态档 / LuCI 显示
    last_stats_at: Option<Instant>,
    tx_bps: f64,
    rx_bps: f64,
    /// 速率的 EWMA 平滑值（bit/s）。压力判定看平滑值，避免单拍突发就触发权重变更。
    tx_bps_ewma: f64,
    rx_bps_ewma: f64,
    /// EWMA 是否已用第一笔实测值初始化（从 0 慢慢爬升会让刚启动的线被误判成空闲）。
    load_ewma_ready: bool,
    /// 这条线目前是否处于「过载、被下修权重」状态（Schmitt trigger 的记忆位）。
    load_pressure_active: bool,
    /// 下载（WAN 入口）容量（bit/s）；None = 未设定，不参与负载感知。
    down_bps_capacity: Option<f64>,
    /// 上传（WAN 出口）容量（bit/s）；未设定时沿用下载容量。
    up_bps_capacity: Option<f64>,
    targets: Vec<std::net::SocketAddr>,
    /// 下个探测周期的「主目标」下标（上次探通的那个）。健康时每周期只探它一条，
    /// 失败才回退其余目标——这是压低短命 TCP 连线数的关键，见 `prober::probe_interface`。
    preferred_target: usize,
    /// 这条线若是隧道（VXLAN/WireGuard），其 underlay 对端位址；非隧道留空。
    /// 非空同时代表「不能拿这条线去当别条隧道的 underlay 出口」。
    underlay_targets: Vec<std::net::Ipv4Addr>,
    /// 快取的介面 IPv4（每次写状态档都做 socket + ioctl 太昂贵）
    cached_ip: Option<std::net::Ipv4Addr>,
    /// 最后一次成功查到的介面 IPv4。**失败时不清空**：介面消失/换 IP 后
    /// conntrack 清理还需要用它来匹配 NAT 到旧位址的连线。
    last_known_ip: Option<std::net::Ipv4Addr>,
    /// 上次对这张网卡做 conntrack 清理的时间（用于限流）
    last_conntrack_flush: Option<Instant>,
    /// 最近一次探测失败的原因（成功时清空）。
    /// 写进状态档，让「介面不存在／本机无路由」不再被误认成「运营商丢包」。
    last_probe_error: Option<String>,
    /// 最近一次失败是否属于本机条件（依 errno 分类，不看 strerror 文案）。
    /// 与 `probe_path_missing` 一起决定状态档的 `local_condition`。
    last_error_is_local: bool,
    /// 是否已针对「本机条件造成的失败」告警过（同一轮只提醒一次）
    local_condition_warned: bool,
    /// 内核查询的结论：经这张网卡到探针目标「根本没有路」。
    /// 这种情况探针会以「超时」结束（内核按 on-link 丢进黑洞），必须另外标记，
    /// 否则日志与介面都会把它误报成运营商丢包。
    probe_path_missing: bool,
    /// 上次做「路径是否存在」查询的时间（限流，避免每 tick 都查）
    last_path_check: Option<Instant>,
    /// 本轮进入 DOWN 的时刻；恢复 UP 时清空。
    /// 用来区分「短暂抖动」与「真的挂了」——前者不该清 conntrack。
    down_since: Option<Instant>,
    /// 最后一次进入 DOWN 的时刻。**恢复后不清空**：用来判断「刚从 DOWN 回来的线」
    /// 还在抖动静默期内，不该被 flush-on-switch 当成新进入成员清掉。
    last_down_at: Option<Instant>,
    /// 这次 DOWN 期间是否已经清过 conntrack（避免每 tick 重复清）
    flushed_while_down: bool,
    lqe: LinkQualityEstimator,
}

impl WanMonitor {
    /// 刷新快取的介面 IP。
    ///
    /// 查得到 → 同时更新 `cached_ip`（显示）与 `last_known_ip`（conntrack 清理）。
    /// 查不到 → **只清 `cached_ip`**，`last_known_ip` 保留：介面已消失/正在重拨时，
    /// 旧 NAT 位址的连线还挂在 conntrack 里，那正是最需要清理的对象。
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

/// 把本 tick 收集到的 conntrack 清理候选送去 worker（同网卡去重 + 最小间隔限流），
/// 并在**真正入队成功之后**才更新 `last_conntrack_flush` 与 `flushed_while_down`。
///
/// `pending` 的元素是 `(monitors 下标, 是否来自 flush-on-down)`：flush-on-switch 的路径
/// 只是「成员集合变了，请清掉新进成员的连线」，线路本身仍是 UP，不该动 `flushed_while_down`。
///
/// 为什么置位必须晚于入队（FIX-7）：这里会因为 `conntrack_flush_min_interval` 跳过刚清过的
/// 网卡。若呼叫端在收集阶段就先设 `flushed_while_down = true`，被跳过的那条线下个 tick 开头
/// 就撞上 `if monitor.flushed_while_down { continue; }`，整段 DOWN 期间不会再尝试清理
/// （只有下一次 UP→DOWN 才会重置）—— 这次 DOWN 的清理就永久丢失了。
fn flush_conntrack(
    monitors: &mut [WanMonitor],
    pending: Vec<(usize, bool)>,
    netlink_tx: &NetlinkSender,
    now: Instant,
    min_interval: Duration,
) {
    let mut targets: Vec<ConntrackTarget> = Vec::new();
    // 与 targets 逐项对应：该网卡的下标、以及「是否来自 flush-on-down」
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
        // 同一张网卡只清一次；来源旗标用 OR 合并，避免重复项把 flush-on-down 的标记吞掉。
        // 旧 IP 合并时「有值优先」：flush-on-switch 的项目可能是后加的。
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

/// 产生 LuCI 显示用的活跃路由描述字串。
///
/// `active_names` 由呼叫端用**同一套 is_active 判据**算出（含降级与保底），
/// 避免这里复制一份判断而与路由下发的实际结果不一致（降级状态若两处判得不同，
/// 介面显示「Multipath ECMP」但核心只有一条路由）。
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
    /// 实际下发到 ECMP 的权重（动态权重启用时可能与 `weight` 不同）
    effective_weight: u32,
    /// 即时速率（bit/s，取样自 /sys/class/net/<if>/statistics）
    tx_bps: f64,
    rx_bps: f64,
    /// 负载利用率（%）：`max(rx/下载容量, tx/上传容量) × 100`；未设定容量时为 null。
    /// 这就是负载感知判断「这条线是否过载」的依据。
    load_pct: Option<f64>,
    /// 这条线目前是否因过载而被下修权重（状态档/LuCI 用来看分流是否正在转移）
    offloaded: bool,
    rtt_ms: f64,
    jitter_ms: f64,
    loss_rate: f64,
    consecutive_successes: usize,
    consecutive_timeouts: usize,
    targets: Vec<String>,
    /// 内核 ifindex；0 = 这张网卡目前不存在（多半是名字写错或介面被停用）
    ifindex: u32,
    /// 最近一次探测失败的原因（成功时为 null）。
    /// 用来区分「本机没有路由／设备不存在」与「运营商丢包」。
    last_error: Option<String>,
    /// last_error 是否属于本机条件（true 时介面上会给出不同提示）
    local_condition: bool,
    /// 这条线是否因实测丢包率超标而降级（= 不参与 ECMP，但仍继续探测）
    degraded: bool,
    /// 目前滑动窗口内的样本数（未达 window_size 前不做丢包率判定）
    samples_in_window: usize,
    /// 窗口是否已填满（false 表示样本还不够，degraded/判死都还没生效）
    window_full: bool,
    /// 最近一次状态变更的原因：consecutive_timeouts / window_loss / rtt / recovery
    /// （尚未发生过状态变更时为 null）
    state_reason: Option<String>,
}

#[derive(serde::Serialize)]
struct DaemonStatus {
    updated_at: u64,
    /// 前端据此判断资料是否过期（秒），避免把陈旧快照当成即时状态
    stale_after_secs: u64,
    active_routes: String,
    interfaces: Vec<InterfaceStatus>,
    /// 策略分流规则状态（未设定 policies 时省略）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies: Vec<PolicyStatus>,
    /// 内核实际生效的多路径哈希设定（「怎么分」的粒度）
    hash: HashStatus,
}

/// 内核实际生效的多路径哈希设定。
///
/// 为什么放进状态档：「设定档写了 l4」和「内核真的按连线分流」是两件事
/// （内核版本、`/proc` 是否可写、有没有被别的程序改掉）。`l3_only: true` 就是
/// 「同一个目的 IP 的所有连线只走一条 WAN」——视频网站（多条连线打同一个 CDN IP）
/// 卡顿最常见的成因。
#[derive(serde::Serialize)]
struct HashStatus {
    /// `fib_multipath_hash_policy` 的读回值（null = 内核没有这个档案）
    policy: Option<u8>,
    /// `fib_multipath_hash_fields` 的读回值（null = 旧核心没有这个档案）
    fields: Option<u32>,
    /// fields 的可读描述（例如 `31 (src_ip+dst_ip+ip_proto+src_port+dst_port)`）
    fields_desc: String,
    l3_only: bool,
}

#[derive(serde::Serialize)]
struct PolicyStatus {
    name: String,
    interface: String,
    priority: u32,
    /// 目前是否已下发（目标 WAN 健康且规则同步成功）
    active: bool,
    source: Vec<String>,
    destination: Vec<String>,
}

/// `net.ipv{4,6}.fib_multipath_hash_fields` 的位元定义（内核 UAPI，见
/// `Documentation/networking/ip-sysctl.rst`；数值以 Linux 6.18 实测确认）。
/// 单一来源是 `config::HashField`，这里只是把常用组合（L3/L4）折成常数。
const HASH_FIELDS_L3: u32 =
    HashField::SrcIp.bit() | HashField::DstIp.bit() | HashField::IpProto.bit();
/// L4 = L3 + 来源/目的埠。
const HASH_FIELDS_L4: u32 = HASH_FIELDS_L3 | HashField::SrcPort.bit() | HashField::DstPort.bit();

/// 位元遮罩的可读描述（日志/状态档用，例如 `31 (src_ip+dst_ip+ip_proto+src_port+dst_port)`）。
///
/// 纯逻辑、可单元测试：把每个已设定位元映射回名称，未知位元以 `0x...` 标出，
/// 排障时不必再回查内核文件。
fn hash_fields_desc(mask: u32) -> String {
    const ALL: [HashField; 11] = [
        HashField::SrcIp,
        HashField::DstIp,
        HashField::IpProto,
        HashField::SrcPort,
        HashField::DstPort,
        HashField::InnerSrcIp,
        HashField::InnerDstIp,
        HashField::InnerIpProto,
        HashField::FlowLabel,
        HashField::InnerSrcPort,
        HashField::InnerDstPort,
    ];
    let mut names: Vec<&str> = ALL
        .iter()
        .filter(|f| mask & f.bit() != 0)
        .map(|f| f.as_str())
        .collect();
    let known: u32 = ALL.iter().fold(0u32, |acc, f| acc | f.bit());
    let unknown = mask & !known;
    if unknown != 0 {
        names.push("(unknown bits)");
    }
    if names.is_empty() {
        return "none".to_string();
    }
    format!("{mask} ({})", names.join("+"))
}

/// 内核实际生效的多路径哈希设定（写入后读回）。
///
/// 为什么必须读回：「设定档写了 l4」不等于「内核真的按连线分流」（内核版本不支援、
/// `/proc` 不可写、被别的程序改掉都可能）。把读回值写进 log 与状态档，
/// 才能一眼看出实际粒度、而不是靠猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct EffectiveHash {
    /// `fib_multipath_hash_policy` 的读回值（档案不存在时为 None）
    policy: Option<u8>,
    /// `fib_multipath_hash_fields` 的读回值（旧核心没有这个档案时为 None）
    fields: Option<u32>,
}

impl EffectiveHash {
    /// 是否只按 L3 哈希 —— 也就是「同一个目的 IP 的所有连线只会走同一条 WAN」。
    ///
    /// 这一点直接决定「视频网站会不会卡」：同一个 CDN 网域解析出来的 IP 往往只有
    /// 一两个，浏览器对它开的每条连线（TCP 分段请求、QUIC 串流）若只按 IP 哈希，
    /// 就会全部挤在同一条 WAN 上，另一条线完全用不到 —— 多 WAN 却还在缓冲。
    ///
    /// 判据只用 **policy**：本机实测（Linux 7.1.8，netns，真实 UDP 封包以 TX 计数判出口，
    /// 本地发出与**转发**流量都测过）`fib_multipath_hash_fields` 写成 1/7/8/9/31/32
    /// 都不改变哈希结果，`policy` 才是有效开关；`policy=0`（L3）与 `policy=2`（inner，
    /// 对未封装流量等同 L3）都不会按埠分散。刻意**不**把 fields 的埠位元当反证：
    /// daemon 的 fields 写入本来就从 policy 推导（且只补不删），拿它当证据会让
    /// 「使用者把 l4 改成 l3 之后 fields 还留着埠位元」这种情况静默失去提示。
    fn l3_only(&self) -> bool {
        !matches!(self.policy, Some(1))
    }

    fn describe(&self) -> String {
        match self.fields {
            Some(mask) => format!(
                "policy={} fields={}",
                self.policy
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                hash_fields_desc(mask)
            ),
            None => format!(
                "policy={} fields=n/a (kernel has no fib_multipath_hash_fields)",
                self.policy
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into())
            ),
        }
    }
}

/// 当 `fib_multipath_hash_fields` 非 0 时，所求策略该怎么处理。
///
/// 为什么还要处理位元：本机实测（Linux 7.1.8，netns，以网卡 TX 计数判出口）该档案
/// **可写入、可读回，但完全不影响哈希结果**——策略才是有效开关（policy=0 时「同一个
/// 目的 IP、只差来源埠」的 24 条连线 100% 走同一条 WAN；policy=1 时变成 12/12）。
/// 但部分内核版本确实以位元为准（旧版本曾观测到相反行为），所以这里两者都写、
/// 并把读回值回报给使用者，而不是假设哪一个才是真理。
#[derive(Debug, PartialEq, Eq)]
enum HashFieldsAction {
    /// `fields == 0`（旧内核）：`fib_multipath_hash_policy` 才是有效开关，不动位元
    PolicyGoverns,
    /// 现有位元缺了策略要求的位元 → 补上后写回
    Extend(u32),
    /// 现有位元已涵盖策略要求（可能比要求更细，例如 l3 要求遇上 fields=31）
    Covered,
    /// `inner` 的语义无法与这组位元逐位对应 → 只告警，不猜
    CannotExpress,
}

/// 依策略与现有位元决定动作（纯逻辑，I/O 在 `apply_multipath_hash`）。
fn hash_fields_action(policy: MultipathHashPolicy, current: u32) -> HashFieldsAction {
    let need = match policy {
        MultipathHashPolicy::L3 => HASH_FIELDS_L3,
        MultipathHashPolicy::L4 => HASH_FIELDS_L4,
        MultipathHashPolicy::Inner => return HashFieldsAction::CannotExpress,
    };
    if current == 0 {
        HashFieldsAction::PolicyGoverns
    } else if current & need == need {
        HashFieldsAction::Covered
    } else {
        HashFieldsAction::Extend(current | need)
    }
}

/// 把设定的多路径哈希策略写进内核 sysctl，并回传实际生效的值。
///
/// - `policy = Some(p)` → 写入 `fib_multipath_hash_policy`（**有效开关**）；
///   `None` = 完全不碰，沿用系统预设。
/// - 另外依 `hash_fields_action` 把 `fib_multipath_hash_fields` 缺少的位元补齐
///   （只补不删：内核不接受写 0，而且这个档案在部分内核上根本不被参考）。
///
/// 只在值不同时才写；失败只告警（旧内核没有这些档案、或 /proc 不可写），
/// 不影响守护进程启动。IPv6 只有在介面设定了 gateway6 时才一起设定。
///
/// 为什么要读回并回传：设定档写了 `l4` 不等于「真的按连线分流」（可能内核不支援、
/// /proc 不可写、或被别的程序改掉）。把两个档案的读回值写进 log 与状态档，
/// 使用者才看得出**实际**粒度；`EffectiveHash::l3_only()` 就是「同一个目的 IP 的
/// 多条连线会挤在同一条 WAN」的判据。
fn apply_multipath_hash(
    policy: Option<MultipathHashPolicy>,
    has_ipv6: bool,
) -> Vec<(&'static str, EffectiveHash)> {
    let mut paths = vec![(
        "ipv4",
        "/proc/sys/net/ipv4/fib_multipath_hash_policy".to_string(),
    )];
    if has_ipv6 {
        paths.push((
            "ipv6",
            "/proc/sys/net/ipv6/fib_multipath_hash_policy".to_string(),
        ));
    }

    let mut applied = Vec::with_capacity(paths.len());
    for (label, path) in paths {
        let mut eff = EffectiveHash::default();

        // 1) policy（有效开关）：只在有设定时才碰它
        if let Some(policy) = policy {
            let want = policy.sysctl_value().to_string();
            let current = std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string());
            if current.as_deref() != Some(want.as_str()) {
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
        eff.policy = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok());

        // 2) fields：依策略补齐缺少的位元（只补不删）
        let fields_path = path.replace("fib_multipath_hash_policy", "fib_multipath_hash_fields");
        let current_fields = std::fs::read_to_string(&fields_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        eff.fields = current_fields;
        if let (Some(current), Some(policy)) = (current_fields, policy) {
            match hash_fields_action(policy, current) {
                HashFieldsAction::PolicyGoverns | HashFieldsAction::Covered => {}
                HashFieldsAction::Extend(want) => {
                    match std::fs::write(&fields_path, format!("{want}\n")) {
                        Ok(()) => {
                            info!(
                                "Extended fib_multipath_hash_fields {current} -> {} at \
                                 {fields_path} (requested '{}')",
                                hash_fields_desc(want),
                                policy.as_str()
                            );
                            eff.fields = Some(want);
                        }
                        Err(e) => warn!(
                            "Failed to extend fib_multipath_hash_fields to {want} at \
                             {fields_path}: {e}; the requested '{}' granularity may not be in \
                             effect",
                            policy.as_str()
                        ),
                    }
                }
                HashFieldsAction::CannotExpress => warn!(
                    "The '{}' hash policy is not bit-for-bit expressible by \
                     fib_multipath_hash_fields (currently {current}), and measured on Linux \
                     7.1.8 the policy is what actually selects the hash keys: \
                     non-encapsulated traffic in 'inner' mode behaves exactly like 'l3' \
                     (connections to the same destination IP stay on one WAN). Use 'l4' unless \
                     you really need the inner-header behaviour.",
                    policy.as_str()
                ),
            }
        }

        info!("Multipath hash in effect ({label}): {}", eff.describe());
        applied.push((label, eff));
    }
    applied
}

/// 动态因子（`weight_mode: quality` / `load_aware`）是否允许套用。
///
/// 只有两种情况允许：内核**实际**安装的是 `resilient`（权重/成员变更只会重映射
/// 故障或空闲的 bucket），或使用者明确以 `allow_dynamic_weights_on_standard` 覆写。
///
/// 为什么 standard 预设要挡：standard 是单一 `RTA_MULTIPATH` 路由，任何权重变更都会让
/// 内核重算整张 multipath hash。实测（Linux 6.12/6.18、512 个 flow key）1:1 → 1:10
/// 会把 **39%** 的既有 flow 改送到另一条 WAN、1:10 → 1:2 会搬走 **24%**；转发流量换了
/// NAT 源 IP 后对端只看到未知四元组（RST／大量重传），而 per-flow 哈希本来就搬不动
/// 已建立的大流量 —— 净效果是「打断连线却换不到分流」。实机 2026-09 案例：
/// quality + load_aware + standard 让权重每 10~20 秒在 1 与 4 之间跳动，
/// 使用者持续回报「一条线突然很卡、网路卡顿」。
fn dynamic_factors_allowed(config: &DaemonConfig, kernel_resilient: bool) -> bool {
    let wants_factors = config.weight_mode == WeightMode::Quality || config.load_aware;
    !wants_factors || config.allow_dynamic_weights_on_standard || kernel_resilient
}

/// 动态权重的「刻度」：整数权重若都是 1，`round(1 × 0.25)` 会被夹成 1，
/// 下修完全没有效果。启用负载感知时把基准权重整体放大到至少这个刻度，
/// 让「空闲线」与「被下修的线」之间真的有整数差；倍率由最小设定权重反推，
/// 因此**权重比例不变**（weight 1:1 放大成 4:4），只是刻度变细。
const DYNAMIC_WEIGHT_RESOLUTION: u32 = 4;

/// 这条线当前的负载利用率：`max(rx / 下载容量, tx / 上传容量)`。
///
/// 取两个方向的最大值：全双工乙太网的收发各自独立，任一方向接近上限就代表
/// 这条线的某个方向已经吃满，该把部分流量移走。没设定容量时回传 `None`。
fn load_utilization(m: &WanMonitor) -> Option<f64> {
    let down = m.down_bps_capacity?;
    let up = m.up_bps_capacity.unwrap_or(down);
    if !(down.is_finite() && down > 0.0 && up.is_finite() && up > 0.0) {
        return None;
    }
    Some((m.rx_bps_ewma / down).max(m.tx_bps_ewma / up))
}

/// 更新每条线「是否处于过载下修」的迟滞状态（Schmitt trigger）。
///
/// 进入：利用率 >= `target`；退出：利用率 <= `recover`（recover < target）。
/// 为什么要记忆位：没有它，一条线在 target 附近摆荡就会让权重每几秒跳一次，
/// 而每次权重变更都是一次 `RTM_NEWROUTE`，可能重算 multipath hash、打断既有 flow。
///
/// 回传「这一次是否有任何一条线的压力状态发生变化」：转换点就是值得**立刻**
/// 重下权重的时刻（见 `weight_update_due`）。持续在迟滞死区里微调则仍然受限速约束。
fn update_load_pressure(
    monitors: &mut [WanMonitor],
    active: &[bool],
    target: f64,
    recover: f64,
) -> bool {
    let mut changed = false;
    for (slot, m) in monitors.iter_mut().enumerate() {
        if !active.get(slot).copied().unwrap_or(false) {
            continue;
        }
        let Some(util) = load_utilization(m) else {
            if m.load_pressure_active {
                m.load_pressure_active = false;
                changed = true;
            }
            continue;
        };
        let was = m.load_pressure_active;
        if m.load_pressure_active {
            if util <= recover {
                m.load_pressure_active = false;
            }
        } else if util >= target {
            m.load_pressure_active = true;
        }
        changed |= m.load_pressure_active != was;
    }
    changed
}

/// 这一次循环该不该重下 ECMP 权重？
///
/// - `elapsed` 距上次下发的间隔、`interval` = `dynamic_weight_interval_ms`：
///   一般情况下的限速，避免每次权重微调都是一次 `RTM_NEWROUTE`。
/// - `pressure_transition`：有线的过载状态刚翻转。这是「某条线开始吃满/刚解除」
///   的瞬间，新连线该立刻改走另一条线——卡顿就发生在这一段里。因此允许跳过
///   interval，但仍受 `min_spacing` 约束（状态机在门槛附近仍可能翻转，别把路由表刷爆）。
fn weight_update_due(
    elapsed: Duration,
    interval: Duration,
    pressure_transition: bool,
    min_spacing: Duration,
) -> bool {
    elapsed >= interval || (pressure_transition && elapsed >= min_spacing)
}

/// 负载因子（`min_ratio` ~ 1.0）：过载的线下修，其余维持 1.0。
///
/// 在 target 与 recover 之间线性内插：稍微过载只小幅下修、严重过载才压到下限，
/// 比 0/1 阶梯更容易收敛到平衡点而不来回震荡。
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

/// 品质因子（`min_ratio` ~ 1.0）：依 LQE 实测丢包与 RTT 下修。
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

/// 计算各线的等效 ECMP 权重（品质模式与负载感知各自独立、也可叠加）。
///
/// 基准权重（`base`）：
/// - 只要任何一条线设定了 `max_mbps`，就启用**容量比例分流**：
///   `base = weight × (max_mbps / 活跃线中的最小 max_mbps)`，
///   即权重比 = 最大频宽比（最小那条正规化为 1）；非活跃线维持 `weight`。
/// - 否则 `base = weight`。
///
/// 动态因子（可独立或叠加）：
/// - `weight_mode = quality`：`factor_q = (1 - 丢包) × clamp(最佳 RTT / 本线 RTT, min, 1)`；
/// - `load_aware`：`factor_l = 1 - 压力 × (1 - min)`（见 `load_factor`）；
/// - 合成因子 = `factor_q × factor_l`。
///
/// 最终权重 = `clamp(round(base × 刻度 × 因子), 1, 255)`。刻度是为了在小权重时
/// 仍有整数解析度（见 `DYNAMIC_WEIGHT_RESOLUTION`），并限制在不会超过 255。
/// 非承载线维持设定值（不会被下发，仅状态档显示用）。
fn compute_dynamic_weights(
    monitors: &[WanMonitor],
    is_active: impl Fn(usize, &WanMonitor) -> bool,
    config: &DaemonConfig,
    allow_dynamic_factors: bool,
) -> Vec<u32> {
    // `allow_dynamic_factors = false`（standard ECMP 的预设）时只算**容量比例**的
    // 静态基准权重，品质/负载因子完全不套用：standard 是单一 RTA_MULTIPATH 路由，
    // 任何权重变更都会让内核重算整张 multipath hash（实测搬走 24%~39% 的既有 flow，
    // 转发流量换源 IP 后连线被 RST/重传），而 per-flow 哈希本来就搬不动已建立的大流量，
    // 因此那个变更只会打断连线、换不到分流。详见 `allow_dynamic_weights_on_standard`。
    let quality_on = config.weight_mode == WeightMode::Quality && allow_dynamic_factors;
    // 容量比例分流改看「监控物件是否带容量」，与实际用于比例的栏位一致
    // （loop 的启用判断才看 config；两者在 validate 下必然同步）。
    let bandwidth_on = monitors.iter().any(|m| m.down_bps_capacity.is_some());
    let min_ratio = config.dynamic_weight_min_ratio.clamp(0.05, 1.0);
    let active_flags: Vec<bool> = monitors
        .iter()
        .enumerate()
        .map(|(slot, m)| is_active(slot, m))
        .collect();
    let active_count = active_flags.iter().filter(|a| **a).count();
    // 只有一条承载线时无处可分（权重再怎么调都只有它），不做负载下修以避免白写路由。
    let load_on = config.load_aware && active_count >= 2 && allow_dynamic_factors;

    // 基准权重：容量比例分流时 ∝ weight × 最大频宽。
    // 以「活跃线中的最小容量」正规化，让最小那条为 1、其余按比例放大
    // （比例超过上限时最后会被 clamp，等效上限 255:1）。
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

    // 刻度放大只在「确实有线被下修」时套用：没有压力就保持原权重，
    // 不为了放大刻度而多下发一次路由。
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
            // 想要的刻度（让最小权重至少 RESOLUTION 格）与不超过上限的刻度取小。
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

/// 把 `config.policies` 展开成可下发的策略规则集合。
///
/// 目标 WAN 目前不健康（非 UP 或 ifindex 解析不到）时整条政策停用，
/// 让流量自动回退到 ECMP 预设路由，而不是黑洞在死线上。
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

/// 负载取样的 EWMA 平滑系数。取样周期即探测周期（预设 500ms），
/// alpha = 0.3 的时间常数约 1.5 秒：足以滤掉单拍突发，又不会慢到跟不上一次真实的流量转移。
const LOAD_EWMA_ALPHA: f64 = 0.3;

/// 读取网卡累计位元组并换算即时速率（bit/s）。读不到就保持上次的值。
///
/// 来源是 `/sys/class/net/<if>/statistics/{tx,rx}_bytes`（介面累计值），
/// 对路由器转发流量而言这正是该 WAN 的实际承载量，用来验证分流是否均匀。
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
            // 介面重建时计数器可能归零：saturating_sub 让速率归零而不是暴冲
            let d_tx = tx.saturating_sub(prev_tx);
            let d_rx = rx.saturating_sub(prev_rx);
            monitor.tx_bps = d_tx as f64 * 8.0 / secs;
            monitor.rx_bps = d_rx as f64 * 8.0 / secs;
            // EWMA 平滑：压力判定看平滑值，单拍突发不该让 ECMP 权重跳动。
            // 第一笔直接当初值，否则从 0 慢慢爬升会让刚启动的线被误判成空闲。
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

/// 读取某张网卡「有效」的 rp_filter 值（`all` 与该装置取大者，与内核规则一致）。
///
/// 为什么需要：内核的反向路径检查**只查主表**。strict（1）时回程必须走同一张
/// 网卡，因此非活跃线必须在主表有一条到探针目标的 /32 才收得到 SYN-ACK；
/// loose（2）时只要主表有任何到该目标的路由即可（有一条预设路由就够）。
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

/// 这张网卡目前「可用」吗（不是 admin down、也不是载波掉）？
///
/// 用途：主表同一个共用探针目标只能有一个 /32 拥有者，必须挑一条真的能把路由装上的
/// 线——否则机会会浪费在已经 down 的那条上，另一条拿不到回程路径，两条会一起掉
/// （本地 netns 实测踩过这个坑）。读不到（例如部分虚拟装置没有这个档案）时保守回传 true。
fn interface_oper_usable(ifname: &str) -> bool {
    match std::fs::read_to_string(format!("/sys/class/net/{ifname}/operstate")) {
        Ok(state) => {
            let state = state.trim();
            state != "down" && state != "lowerlayerdown"
        }
        Err(_) => true,
    }
}

/// 问内核「这个目标有没有路」。`oif` 有值时问的是「绑定该设备时有没有路」。
///
/// 回传 `None` = 查不到（socket 不可用或查询失败），呼叫端要保守处理。
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

/// 内核目前有没有一条**真正的**（非 `lo`）IPv6 预设路由 `::/0`？
///
/// 用途：没设定 `gateway6` 时守护进程不管理 IPv6 路由，v6 流量会一直走 netifd 那条
/// 单线预设路由；IPv6 上跑的常常正好是视频（QUIC/HTTP-3），值得提示一次
/// （见启动处的说明）。刻意排除 `lo`：多数系统在 `lo` 上有一条 `::/0` 的 null route
/// （metric ffffffff），把它算成「有 v6 出口」会让提示永远不出现。
///
/// `/proc/net/ipv6_route` 每行格式：`<dest 32hex> <plen 2hex> <src> <splen> <nexthop>
/// <metric> <refcnt> <use> <flags> <dev>`。
fn has_kernel_ipv6_default_route(table: &str) -> bool {
    table.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let dest = fields.next().unwrap_or("");
        let plen = fields.next().unwrap_or("");
        let dev = fields.last().unwrap_or("");
        dest.len() == 32
            && dest.bytes().all(|b| b == b'0')
            && plen == "00"
            && !dev.is_empty()
            && dev != "lo"
    })
}

fn write_status_file(
    monitors: &[WanMonitor],
    active_routes: &str,
    config: &DaemonConfig,
    hash: EffectiveHash,
) {
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

    // 策略规则状态：`active` = 目标 WAN 健康且规则在期望集合内（与实际下发同步）
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
        hash: HashStatus {
            policy: hash.policy,
            fields: hash.fields,
            fields_desc: hash
                .fields
                .map(hash_fields_desc)
                .unwrap_or_else(|| "n/a".to_string()),
            l3_only: hash.l3_only(),
        },
    };

    if let Ok(json) = serde_json::to_string(&status) {
        if let Err(e) = write_status_atomic(&json) {
            debug!("failed to update status file: {e}");
        }
    }
}

/// 原子且防符号连结地写入状态档。
///
/// `/tmp` 是 1777：可写者能预先放一个指向任意路径的符号连结，让 root 的
/// `fs::write` 跟著它覆写目标档案。这里改用 `create_new`（O_CREAT|O_EXCL）：
/// 目标已存在（含符号连结）时直接失败，先移除再建立（`remove_file` 只删连结本身、
/// 不会跟随），最后用 rename 原子替换。
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
    // 测试里「先取预设值、再改一两个栏位」比整包 struct literal 清楚得多，
    // 尤其只需要动 config 的单一栏位时。
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    /// `fib_multipath_hash_fields` 非 0 时，`fib_multipath_hash_policy` 会被内核忽略，
    /// 因此必须靠位元补写才能让设定生效；`inner` 无法逐位对应，只告警不猜。
    #[test]
    fn test_hash_fields_action_matches_kernel_semantics() {
        use MultipathHashPolicy::{Inner, L3, L4};

        // 旧内核（没有这个档案时读不到，或被写成 0）：policy 就是有效开关
        assert_eq!(hash_fields_action(L3, 0), HashFieldsAction::PolicyGoverns);
        assert_eq!(hash_fields_action(L4, 0), HashFieldsAction::PolicyGoverns);

        // Linux 6.18 预设 fields=7：l4 缺埠位元必须补上，否则「按连线分流」是假的
        assert_eq!(hash_fields_action(L4, 7), HashFieldsAction::Extend(31));
        // 已含埠位元（或更细）就不再动它：不覆写使用者/发行版原本的设定
        assert_eq!(hash_fields_action(L4, 31), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L4, 63), HashFieldsAction::Covered);
        // 只缺部分位元时补成联集，不覆盖既有位元
        assert_eq!(hash_fields_action(L4, 8), HashFieldsAction::Extend(31));
        // l3 只要有 IP + 协议位元即满足；fields=31 比要求更细，属已涵盖
        assert_eq!(hash_fields_action(L3, 7), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L3, 31), HashFieldsAction::Covered);
        assert_eq!(hash_fields_action(L3, 2), HashFieldsAction::Extend(7));
        // inner 的语义（外层 + 内层五元组按封装与否切换）无法用这组位元逐位表达
        assert_eq!(
            hash_fields_action(Inner, 7),
            HashFieldsAction::CannotExpress
        );
        assert_eq!(
            hash_fields_action(Inner, 0),
            HashFieldsAction::CannotExpress
        );
    }

    /// 位元遮罩的可读描述：日志/状态档靠它说明「实际生效的粒度」。
    #[test]
    fn test_hash_fields_desc_renders_names() {
        assert_eq!(hash_fields_desc(0), "none");
        assert_eq!(hash_fields_desc(7), "7 (src_ip+dst_ip+ip_proto)");
        assert_eq!(
            hash_fields_desc(HASH_FIELDS_L4),
            "31 (src_ip+dst_ip+ip_proto+src_port+dst_port)"
        );
        // 内层标头与 flow label 也要认得（隧道/QUIC 视频流量用的位元）
        assert_eq!(
            hash_fields_desc(
                HASH_FIELDS_L4 | HashField::InnerSrcPort.bit() | HashField::InnerDstPort.bit()
            ),
            "1567 (src_ip+dst_ip+ip_proto+src_port+dst_port+inner_src_port+inner_dst_port)"
        );
        assert_eq!(
            hash_fields_desc(HashField::FlowLabel.bit()),
            "256 (flow_label)"
        );
        // 不认得的位元不能被静默吃掉，否则日志会误导
        assert_eq!(hash_fields_desc(1 << 20), "1048576 ((unknown bits))");
    }

    /// 「只按 L3 哈希」的判定：只看 policy（实测 fields 会被内核忽略，
    /// daemon 的 fields 值本身就是从 policy 推导出来的）。
    #[test]
    fn test_effective_hash_l3_only_semantics() {
        // 内核预设：policy=0 只哈希 IP → 同一个目的 IP 的连线全走一条 WAN
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: Some(7),
            }
            .l3_only()
        );
        // 从 l4 改回 l3 时 fields 仍留着埠位元（只补不删）——不得因此失去提示
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: Some(31),
            }
            .l3_only()
        );
        // l4：按连线分流
        assert!(
            !EffectiveHash {
                policy: Some(1),
                fields: Some(31),
            }
            .l3_only()
        );
        // inner 对未封装流量等同 L3（实测：只差来源埠的连线全部同一条线）
        assert!(
            EffectiveHash {
                policy: Some(2),
                fields: Some(224),
            }
            .l3_only()
        );
        // 读不到 policy（/proc 不可写）时保守当 L3：宁可多一次提示
        assert!(EffectiveHash::default().l3_only());
        assert!(
            EffectiveHash {
                policy: None,
                fields: Some(31)
            }
            .l3_only()
        );
        // 旧内核没有 fields 档案时 policy 就是唯一判据
        assert!(
            !EffectiveHash {
                policy: Some(1),
                fields: None
            }
            .l3_only()
        );
        assert!(
            EffectiveHash {
                policy: Some(0),
                fields: None
            }
            .l3_only()
        );
    }

    /// IPv6 覆盖提示的判据：只看「非 lo 的 ::/0」。
    #[test]
    fn test_has_kernel_ipv6_default_route_ignores_lo_reject_route() {
        // 多数系统在 lo 上有一条 ::/0 的 null route（metric ffffffff）：不算出口
        let lo_only = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                       00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert!(!has_kernel_ipv6_default_route(lo_only));
        // 真的有一张网卡承载 ::/0 → 提示
        let real = format!(
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00000400 00000001 00000000 00000001   wan1\n{lo_only}"
        );
        assert!(has_kernel_ipv6_default_route(&real));
        // 只有非 ::/0 的前缀（fe80::/64、/128 主机路由）不算
        let other = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 \
                     00000000000000000000000000000000 00000400 00000001 00000000 00000001 eth0\n";
        assert!(!has_kernel_ipv6_default_route(other));
        // 空表 / 读取失败
        assert!(!has_kernel_ipv6_default_route(""));
    }

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
            Ok(_) => panic!("应送出 FlushConntrack，实际送出了其他指令"),
            Err(err) => panic!("应送出 FlushConntrack，实际没有送出指令：{err}"),
        }
    }

    /// FIX-7 回归：被最小间隔限流跳过的 flush-on-down 候选**不得**被标记成「本次 DOWN 已清过」。
    ///
    /// 旧版顺序是「先置位、后限流」，于是那条线在下个 tick 开头就被
    /// `if monitor.flushed_while_down { continue; }` 略过，整段 DOWN 期间再也不会尝试清理
    /// （只有下一次 UP→DOWN 才重置）→ 这次 DOWN 的 flush 永久丢失。
    #[test]
    fn test_flush_on_down_marker_is_set_only_after_enqueue() {
        let now = Instant::now();
        let min_interval = Duration::from_secs(10);
        let (tx, rx) = std::sync::mpsc::sync_channel::<NetlinkCmd>(4);
        // 1 秒前才清过 → 这次落在最小间隔内
        let mut monitors = vec![monitor("wan1", Some(now - Duration::from_secs(1)))];

        flush_conntrack(&mut monitors, vec![(0, true)], &tx, now, min_interval);
        assert!(
            rx.try_recv().is_err(),
            "最小间隔内不该送出任何 conntrack 清理指令"
        );
        assert!(
            !monitors[0].flushed_while_down,
            "被限流跳过的线若先被标记，整段 DOWN 期间都不会再重试"
        );
        assert_eq!(
            monitors[0].last_conntrack_flush,
            Some(now - Duration::from_secs(1)),
            "被跳过时不该更新清理时间戳"
        );

        // 间隔过后重试：这次真的入队，才准标记
        let later = now + Duration::from_secs(11);
        flush_conntrack(&mut monitors, vec![(0, true)], &tx, later, min_interval);
        assert_eq!(flushed_names(&rx), vec!["wan1".to_string()]);
        assert!(monitors[0].flushed_while_down);
        assert_eq!(monitors[0].last_conntrack_flush, Some(later));
    }

    /// flush-on-switch 进来的候选不该动 `flushed_while_down`（线路仍是 UP）；
    /// 同一张网卡同时来自两个来源时只清一次，且来源旗标必须合并。
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
            "同一张网卡只能出现一次，且顺序依第一次出现的下标"
        );
        assert!(
            monitors[0].flushed_while_down,
            "wan1 也来自 flush-on-down，来源旗标应合并"
        );
        assert!(
            !monitors[1].flushed_while_down,
            "flush-on-switch 不得把线路标成『DOWN 期间已清』"
        );
    }

    /// 品质模式：RTT 较差的线被下修。`load_aware` 关闭时不套用刻度放大，
    /// 因此维持旧行为（4 × 0.25 = 1）。
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
        c.lqe.rtt_ewma_ms = None; // 没有 RTT 样本 → 不惩罚
        let monitors = vec![a, b, c];
        // 全部承载；视窗未填满 → 丢包不计
        let weights = compute_dynamic_weights(&monitors, |_, _| true, &cfg, true);
        assert_eq!(weights[0], 4, "最佳 RTT 维持原权重");
        assert_eq!(weights[1], 1, "RTT 4 倍差 → 下修到 min_ratio（4*0.25=1）");
        assert_eq!(weights[2], 4, "没有 RTT 样本不该被惩罚");

        // 非承载线维持设定权重（不会被下发，但状态档显示用）
        let weights = compute_dynamic_weights(&monitors, |slot, _| slot == 0, &cfg, true);
        assert_eq!(weights[1], 4);
        assert_eq!(weights[2], 4);
    }

    /// 负载感知：一条线过载时，透过「刻度放大 + 下修因子」把 ECMP 权重比例
    /// 往空闲线倾斜（把部分 flow 转移过去）；压力解除后还原设定权重。
    #[test]
    fn test_compute_load_weights_shifts_traffic_to_idle_line() {
        let mut cfg = DaemonConfig::default();
        cfg.load_aware = true;
        cfg.load_target_ratio = 0.80;
        cfg.load_recover_ratio = 0.60;
        cfg.dynamic_weight_min_ratio = 0.25;

        let mut busy = monitor("wan1", None);
        let mut idle = monitor("wan2", None);
        // 两条线容量相同（100 Mbps），busy 打满、idle 几乎没流量
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
        assert!(monitors[0].load_pressure_active, "95% 应触发过载下修");
        assert!(!monitors[1].load_pressure_active, "5% 不该触发");

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        // busy factor = 0.25、idle = 1.0；刻度放大 4 倍 → 1 : 4
        assert_eq!(weights, vec![1, 4], "过载线应被下修、空闲线放大来接流量");

        // 迟滞死区（60%~80%）：已下修的线不解除，避免在门槛附近来回跳动
        monitors[0].rx_bps_ewma = 70_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(
            monitors[0].load_pressure_active,
            "落在 recover 与 target 之间应保持下修"
        );

        // 低于 recover（60%）→ 压力解除、权重还原，且不再套用刻度放大
        monitors[0].rx_bps_ewma = 10_000_000.0;
        update_load_pressure(
            &mut monitors,
            &active,
            cfg.load_target_ratio,
            cfg.load_recover_ratio,
        );
        assert!(!monitors[0].load_pressure_active);
        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![1, 1], "压力解除后回到设定权重");

        // 两条线都过载：因子相同 → 权重比例不变（无处可去，不制造无意义的路由变更）
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
        let weights = compute_dynamic_weights(&both, |s, _| active[s], &cfg, true);
        assert_eq!(weights, vec![1, 1], "全线过载时维持原比例");

        // 只有一条承载线时不做负载下修（无处可分）
        let only = vec![monitor("wan1", None)];
        let weights = compute_dynamic_weights(&only, |_, _| true, &cfg, true);
        assert_eq!(weights, vec![1]);
    }

    /// 容量比例分流：设定 max_mbps 后，基准权重自动 ∝ 最大频宽，
    /// 不需要手动换算 weight（1000 vs 200 → 5:1；1000 vs 10 → 100:1）。
    #[test]
    fn test_compute_bandwidth_proportional_weights() {
        let cfg = DaemonConfig::default();

        // 1000 : 200 = 5 : 1
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(200_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![5, 1], "权重比应等于最大频宽比 1000:200");

        // 极端差距（1000 : 10 = 100 : 1）仍可表达
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(10_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![100, 1]);

        // 差距超过 255:1 时夹在单一 nexthop 的上限
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(1_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![config::MAX_WEIGHT, 1], "超过 255:1 应夹住");

        // weight 仍可当手动倍率：2×1000 : 1×500 = 4 : 1
        let mut a = monitor("wan1", None);
        let mut b = monitor("wan2", None);
        a.weight = 2;
        a.down_bps_capacity = Some(1_000_000_000.0);
        b.down_bps_capacity = Some(500_000_000.0);
        let weights = compute_dynamic_weights(&[a, b], |_, _| true, &cfg, true);
        assert_eq!(weights, vec![4, 1]);

        // 完全没设容量 → 退回设定 weight（既有行为不变）
        let cfg2 = DaemonConfig::default();
        assert!(!cfg2.capacity_weights_on());
        let weights = compute_dynamic_weights(
            &[monitor("wan1", None), monitor("wan2", None)],
            |_, _| true,
            &cfg2,
            true,
        );
        assert_eq!(weights, vec![1, 1]);
    }

    #[test]
    fn test_dynamic_factors_gate_requires_resilient_or_opt_in() {
        // 只有容量比例（没开 quality / load_aware）时没有动态因子要挡
        let cfg = DaemonConfig::default();
        assert!(dynamic_factors_allowed(&cfg, false));
        assert!(dynamic_factors_allowed(&cfg, true));

        // standard（kernel_resilient = false）下 quality / load_aware 一律被忽略…
        let mut quality = DaemonConfig::default();
        quality.weight_mode = WeightMode::Quality;
        assert!(!dynamic_factors_allowed(&quality, false));

        let mut load = DaemonConfig::default();
        load.load_aware = true;
        assert!(!dynamic_factors_allowed(&load, false));

        // …除非内核实际安装的是 resilient…
        assert!(dynamic_factors_allowed(&quality, true));
        assert!(dynamic_factors_allowed(&load, true));

        // …或使用者明确覆写。
        let mut override_cfg = DaemonConfig::default();
        override_cfg.load_aware = true;
        override_cfg.allow_dynamic_weights_on_standard = true;
        assert!(dynamic_factors_allowed(&override_cfg, false));
    }

    /// 容量比例分流 + 负载感知：过载线在容量基准上再被下修。
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
        busy.rx_bps_ewma = 950_000_000.0; // wan1 95%（过载）
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

        let weights = compute_dynamic_weights(&monitors, |s, _| active[s], &cfg, true);
        // 基准 5:1；wan1 因子 0.25（刻度 4）→ 20×0.25=5、wan2=4 → 5:4
        assert_eq!(weights, vec![5, 4], "过载线在容量基准上被进一步下修");
    }

    /// 未设定容量时（未启用 load_aware 的设定不会走到这里，但函式要防守）
    /// 利用率视为未知，不得触发压力。
    #[test]
    fn test_load_pressure_requires_capacity() {
        let mut m = monitor("wan1", None);
        m.rx_bps_ewma = 999_000_000.0;
        assert_eq!(load_utilization(&m), None);
        let mut monitors = vec![m];
        update_load_pressure(&mut monitors, &[true], 0.8, 0.6);
        assert!(!monitors[0].load_pressure_active, "没有容量就不判定过载");
    }

    /// 过载状态转换要能被「看见」（回传值就是 main 回圈用来插队重下权重的讯号），
    /// 但没有转换时不得回传 true（否则每拍都会重下路由）。
    #[test]
    fn test_load_pressure_reports_transitions_only() {
        let mut busy = monitor("wan1", None);
        let mut calm = monitor("wan2", None);
        busy.down_bps_capacity = Some(100_000_000.0);
        busy.up_bps_capacity = Some(100_000_000.0);
        calm.down_bps_capacity = Some(100_000_000.0);
        calm.up_bps_capacity = Some(100_000_000.0);
        busy.rx_bps_ewma = 90_000_000.0; // 90% → 过载
        calm.rx_bps_ewma = 10_000_000.0; // 10%
        let mut monitors = vec![busy, calm];
        let active = [true, true];

        // 进入过载：一次转换
        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(monitors[0].load_pressure_active);
        // 维持在门槛与恢复线之间（0.7）：状态不变 → 不该再产生转换
        monitors[0].rx_bps_ewma = 70_000_000.0;
        assert!(!update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(monitors[0].load_pressure_active, "迟滞死区内维持原状态");
        // 掉到恢复线以下 0.5 → 解除，也是一次转换
        monitors[0].rx_bps_ewma = 50_000_000.0;
        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(!monitors[0].load_pressure_active);

        // 非活跃线不参与判定，也不该产生转换（否则停机期间会白写路由）
        monitors[0].rx_bps_ewma = 99_000_000.0;
        assert!(!update_load_pressure(
            &mut monitors,
            &[false, true],
            0.8,
            0.6
        ));

        // 容量被清掉（例如设定改变）时压力必须解除，否则权重会永远被下修
        monitors[0].down_bps_capacity = None;
        monitors[0].load_pressure_active = true;
        assert!(update_load_pressure(&mut monitors, &active, 0.8, 0.6));
        assert!(!monitors[0].load_pressure_active);
    }

    /// 权重下发的时机：平常受限速约束；过载状态转换时允许插队（新连线该马上改走另一条线），
    /// 但仍保留一个最小间隔，避免状态机在门槛附近翻转时把路由表刷爆。
    #[test]
    fn test_weight_update_due_rate_limit_and_transition_bypass() {
        let interval = Duration::from_secs(10);
        let floor = Duration::from_millis(1000);

        // 没到期、没有转换 → 不重下
        assert!(!weight_update_due(
            Duration::from_millis(500),
            interval,
            false,
            floor
        ));
        // 没到期但有转换 → 插队（只要超过最小间隔）
        assert!(weight_update_due(
            Duration::from_millis(1000),
            interval,
            true,
            floor
        ));
        // 转换 + 仍在最小间隔内 → 不重下（挡掉门槛附近的每秒翻转）
        assert!(!weight_update_due(
            Duration::from_millis(999),
            interval,
            true,
            floor
        ));
        // 到期就一定重下（即使没有转换）
        assert!(weight_update_due(interval, interval, false, floor));
        assert!(weight_update_due(
            Duration::from_secs(30),
            interval,
            false,
            floor
        ));
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
        assert_eq!(rules.len(), 2, "2 个来源 × 1 个目的，且 Down 的政策被跳过");
        for rule in &rules {
            assert_eq!(rule.name, "guest");
            assert_eq!(rule.ifindex, 22);
            assert_eq!(rule.table, PROBE_TABLE_BASE + 1, "用目标 WAN 的独立表");
            assert_eq!(rule.priority, POLICY_RULE_PRIORITY_BASE, "预设依政策顺序");
            assert_eq!(rule.destination, Some(("10.0.0.0".parse().unwrap(), 8)));
        }
        let sources: Vec<_> = rules.iter().filter_map(|r| r.source).collect();
        assert!(sources.contains(&("192.168.3.0".parse().unwrap(), 24)));
        assert!(sources.contains(&("192.168.4.0".parse().unwrap(), 24)));

        // 目标恢复 UP 后，match-all 的政策也回来（source/destination 都是 None）
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
