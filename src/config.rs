use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// ECMP 权重上限。
///
/// 标准 multipath 的 `rtnh_hops` 可表达 weight-1 = 255（权重 256），但 resilient
/// nexthop group 的 `struct nexthop_grp.weight` 在 Linux < 6.9 只允许 ≤ 254
/// （weight_high 是 6.9 才加入），设 256 会让 `RTM_NEWNEXTHOP` 回 EINVAL、
/// resilient 直接失效。统一上限设 255，两种模式与所有内核版本行为一致。
pub const MAX_WEIGHT: u32 = 255;

/// 滑动窗口上限：过大的窗口会让低记忆体装置在启动时一次预分配过大缓冲，
/// 也会拖慢每次样本更新。1024 个样本 @500ms 已足够覆盖 8 分钟的历史。
pub const MAX_WINDOW_SIZE: usize = 1024;

/// 网卡名称长度上限（Linux IFNAMSIZ - 1）
pub const MAX_IFNAME_LEN: usize = 15;

/// 探测周期上限（毫秒）：1 小时。避免手写设定把节奏调到近乎停止。
pub const MAX_CHECK_INTERVAL_MS: u64 = 3_600_000;
/// 降级相关「连续拍数」栏位的上限（防呆：设定得比这个还大等于关闭该机制）。
pub const MAX_DEGRADE_STREAK: usize = 600;

/// 多 WAN 等价路径（ECMP）的实作方式。
///
/// - `standard`：单一 multipath 路由（RTA_MULTIPATH）。nexthop 集合一变
///   （含线路恢复 UP 加入新成员），核心会重算整条路由的 multipath hash，
///   既有 flow 可能被改送到另一条 WAN、源 IP 改变而断线。
/// - `resilient`：改用 resilient nexthop group（Linux 5.14+）。集合变动时核心
///   只重新分配「故障成员」占用的 bucket，其余 flow 保持粘滞、不会断线。
/// - `auto`（**预设**）：优先用 resilient，核心不支援时自动退回 standard 并记住结果。
///
/// 为什么预设改成 `auto`：standard 的重哈希会**连坐没出问题的那条线**。
/// 本机 netns 实测（Linux 6.18、32 个 flow key、以网卡 TX 计数确认真实出口）：
///
/// | 变更 | standard 被改派的既有 flow | resilient |
/// | --- | --- | --- |
/// | 权重 1:1 → 1:10 | **40%** | **0%**（只搬空闲 bucket） |
/// | 新增成员（线路恢复回归 ECMP） | **40%** | **0%** |
/// | 移除成员（降级／判 DOWN） | **43%** | 只搬走**该成员自己**的 bucket |
///
/// 被改派的 flow 换了出口 WAN 就换了 NAT 源 IP，对端只看到未知四元组
/// （RST／大量重传），使用者感受就是「玩到一半突然卡顿」。resilient 之所以
/// 不连坐：核心只重新分配**空闲** bucket（`NHA_RES_GROUP_IDLE_TIMER` 默认 120 秒，
/// 使用中的 bucket 会被延后迁移），所以其他线的既有 flow 原地不动。
/// 核心不支援 nexthop object（旧核心／非 Linux）时 `auto` 退回 standard，等同旧版行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EcmpMode {
    Standard,
    /// 预设：核心支援就用 resilient，否则退回 standard
    #[default]
    Auto,
    Resilient,
}

/// 内核多路径（ECMP）哈希策略。
///
/// 写入 `net.ipv{4,6}.fib_multipath_hash_policy`：
/// - `l3`：只哈希来源/目的 IP。flow 数少（例如同一个 NAT 闸道下的多个连线，
///   或同一个视频 CDN IP 的多个连线）会全部落到同一条 WAN；
/// - `l4`（**本专案预设**）：再加上 L4 来源/目的埠，分流最均匀，一般建议值；
/// - `inner`：L3 + 隧道内层标头（VXLAN/GRE 等封装流量的内层五元组）。
///   本机实测：**没有封装**的流量（一般网页/视频）在 `inner` 下的出口选择与 `l3` 相同，
///   也就是同一个目的 IP 的多条连线仍然挤在同一条 WAN。非隧道环境请用 `l4`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MultipathHashPolicy {
    L3,
    L4,
    Inner,
}

impl MultipathHashPolicy {
    pub fn sysctl_value(self) -> u8 {
        match self {
            Self::L3 => 0,
            Self::L4 => 1,
            Self::Inner => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::L3 => "l3",
            Self::L4 => "l4",
            Self::Inner => "inner",
        }
    }
}

/// `net.ipv{4,6}.fib_multipath_hash_fields` 的单个位元（内核 UAPI，Linux 5.12+）。
///
/// 用途：把内核读回的位元遮罩**翻译成人看得懂的名字**（log / 状态档），并在 netns
/// 回归测试里构造遮罩。刻意不提供设定档栏位——见
/// `DaemonConfig::multipath_hash_policy` 说明：实测（Linux 7.1.8）
/// `fib_multipath_hash_fields` 可以写入、也能读回，但**完全不影响哈希结果**，
/// 真正决定分流粒度的是 `fib_multipath_hash_policy`。这里的数值取自内核 UAPI 文件
/// （`Documentation/networking/ip-sysctl.rst`），并在本机核心上验证过「都能写入」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashField {
    SrcIp,
    DstIp,
    IpProto,
    SrcPort,
    DstPort,
    InnerSrcIp,
    InnerDstIp,
    InnerIpProto,
    FlowLabel,
    InnerSrcPort,
    InnerDstPort,
}

impl HashField {
    pub const fn bit(self) -> u32 {
        match self {
            Self::SrcIp => 1,
            Self::DstIp => 2,
            Self::IpProto => 4,
            Self::SrcPort => 8,
            Self::DstPort => 16,
            Self::InnerSrcIp => 32,
            Self::InnerDstIp => 64,
            Self::InnerIpProto => 128,
            Self::FlowLabel => 256,
            Self::InnerSrcPort => 512,
            Self::InnerDstPort => 1024,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SrcIp => "src_ip",
            Self::DstIp => "dst_ip",
            Self::IpProto => "ip_proto",
            Self::SrcPort => "src_port",
            Self::DstPort => "dst_port",
            Self::InnerSrcIp => "inner_src_ip",
            Self::InnerDstIp => "inner_dst_ip",
            Self::InnerIpProto => "inner_ip_proto",
            Self::FlowLabel => "flow_label",
            Self::InnerSrcPort => "inner_src_port",
            Self::InnerDstPort => "inner_dst_port",
        }
    }
}

/// ECMP 权重模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WeightMode {
    /// 固定使用介面的 `weight`（预设，行为与旧版一致）
    #[default]
    Static,
    /// 依 LQE 实测品质动态调整权重：丢包与 RTT 较差的线少分流量，
    /// 品质恢复后自动回到设定的 `weight`。变更会重下 ECMP 路由（有限速）。
    Quality,
}

/// 一条来源/目的策略分流规则。
///
/// 以 `ip rule` 的 `from`/`to` + 该 WAN 的独立路由表实现：匹配的**转发流量**
/// 走指定 WAN，其余流量仍走 ECMP 预设路由。刻意不用 fwmark／nftables，
/// 与本专案「转发面零封包标记」的架构一致。
///
/// 目标 WAN 被判 DOWN 时，规则会被暂时移除，流量自动回退到 ECMP。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// 规则名称（显示与日志用；必须唯一）
    pub name: String,
    /// 来源前缀（CIDR，例如 "192.168.3.0/24"）。空清单 = 不限制来源
    #[serde(default)]
    pub source: Vec<String>,
    /// 目的前缀（CIDR）。空清单 = 不限制目的
    #[serde(default)]
    pub destination: Vec<String>,
    /// 目标 WAN 介面名称（必须是 `interfaces` 之一）
    pub interface: String,
    /// 规则优先序（选填）。预设依 `policies` 阵列顺序从
    /// `POLICY_RULE_PRIORITY_BASE` 起算；数字越小越先匹配
    #[serde(default)]
    pub priority: Option<u32>,
    /// 未知栏位（以 `_` 开头者视为注解）
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// 解析 `a.b.c.d/prefix` 形式的 IPv4 前缀（允许 /0 ~ /32）。
pub fn parse_ipv4_prefix(raw: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = raw
        .split_once('/')
        .ok_or_else(|| format!("'{raw}' is not CIDR (expected e.g. 192.168.3.0/24)"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| format!("'{raw}' has an invalid IPv4 address"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("'{raw}' has an invalid prefix length"))?;
    if prefix > 32 {
        return Err(format!("'{raw}' prefix must be within 0 ~ 32"));
    }
    Ok((addr, prefix))
}

/// WAN 接口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// 网卡名称，例如 "wan1", "wan2", "eth0"
    pub name: String,
    /// 网关 IP 地址，例如 "192.168.1.1"（点对点/WireGuard/PPPoE 无需网关，可为 None 或 0.0.0.0）
    #[serde(default)]
    pub gateway: Option<Ipv4Addr>,
    /// IPv6 网关地址（选填）。设定后会随该网卡的 IPv4 健康状态一并下发 ::/0 预设路由
    #[serde(default)]
    pub gateway6: Option<Ipv6Addr>,
    /// 路由优先级 Metric（预设 1）
    #[serde(default = "default_metric")]
    pub metric: u32,
    /// ECMP 多路路由权重（预设 1，合法范围 1~255）
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 这条线的**最大频宽**（Mbps）。有设定时，ECMP 基准权重会自动改成
    /// ∝ `weight × max_mbps`（容量比例分流），也作为下行（WAN 入口）方向的容量；
    /// 启用 `load_aware` 时必填。JSON 也接受旧名 `down_mbps`。
    #[serde(default, alias = "down_mbps")]
    pub max_mbps: Option<f64>,
    /// 上行（WAN 出口）频宽上限（Mbps）；未设定时沿用 `max_mbps`。
    /// 非对称线路（例如 1000/50）才需要填。
    #[serde(default)]
    pub up_mbps: Option<f64>,
    /// 探测目标地址列表（TCP SYN 探测 IP:Port），如 ["223.5.5.5:53", "114.114.114.114:53"]
    #[serde(default = "default_probe_targets")]
    pub probe_targets: Vec<SocketAddr>,
    /// 隧道型 WAN 的 underlay 对端位址（选填）。
    ///
    /// VXLAN 的 remote、WireGuard 的 endpoint 这类「封装封包真正要去的地方」，
    /// 必须经由**其他** WAN（非隧道的那条）抵达。若放任它们走 ECMP 预设路由，
    /// 就有约 1/N 的机率被塞回这条隧道自己 —— 封装封包进隧道、隧道再封装，形成自环。
    ///
    /// 实测（VXLAN 当第二条线、与 eth1 组成双线 ECMP）：设成 resilient 后隧道立刻
    /// 丢包 60% 并被判 DOWN，`ip route get <对端>` 却仍显示正确的那条
    /// （它只反映固定哈希的单次采样，会骗人）。
    ///
    /// 设了这个栏位后，守护进程会在 main 表为每个位址补一条 /32
    /// （前缀比预设路由长，必然优先），固定走「非隧道、metric 最小」的那条 WAN。
    #[serde(default)]
    pub underlay_targets: Vec<Ipv4Addr>,
    /// 未知栏位（以 `_` 开头者视为注解）。validate() 会拒绝真正的拼字错误。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_metric() -> u32 {
    1
}

fn default_weight() -> u32 {
    1
}

/// 预设探测目标：大陆地区公共 DNS（阿里 223.5.5.5、114DNS 114.114.114.114）。
///
/// 两者都监听 TCP 53，SYN 必有应答（SYN-ACK 或 RST 都算链路可达），比境外
/// 1.1.1.1 / 8.8.8.8 在国内线路上稳定；且 TCP 探针不受 ICMP 限速影响。
fn default_probe_targets() -> Vec<SocketAddr> {
    vec![
        "223.5.5.5:53".parse().unwrap(),
        "114.114.114.114:53".parse().unwrap(),
    ]
}

/// 守护进程全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// 探测周期（毫秒），规范要求 500ms
    #[serde(default = "default_check_interval_ms")]
    pub check_interval_ms: u64,
    /// 单次探测超时时间（毫秒），应小于或等于探测周期
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    /// 滑动窗口长度，规范要求 10
    #[serde(default = "default_window_size")]
    pub window_size: usize,
    /// DOWN 丢包率阈值（窗口丢包率大于此值视为 DOWN），规范要求 > 50%
    #[serde(default = "default_loss_threshold_down")]
    pub loss_threshold_down: f64,
    /// 恢复 UP 所需的窗口丢包率上限。
    ///
    /// **当前仅作参考**：恢复判据已改为只看 `recovery_success_count` 与 RTT（见 `lqe.rs`）。
    /// 这个门槛与 window_size 耦合，在 window=10、0.10 时等于「窗口内最多 1 次失败」，
    /// 会把 `recovery_success_count` 静默抬高（设定 5 实际要 9 次连续成功），
    /// 造成 DOWN 快、UP 慢的反复翻转。栏位保留是为了相容既有设定档（删掉会让旧设定档
    /// 以 serde 错误拒绝启动），范围仍由 `validate()` 检查。
    #[serde(default = "default_loss_threshold_up")]
    pub loss_threshold_up: f64,
    /// 降级丢包率阈值（预设 0.20 = 20%；`0.0` = 关闭此功能，沿用旧行为）。
    ///
    /// 语意：滑动窗口**已填满**且窗口丢包率 >= 此值时，该线路「降级」= 不参与 ECMP
    /// （但仍继续探测，品质恢复后自动回归）。
    /// 为什么需要：介于此值与 `loss_threshold_down`（预设 0.50）之间的线路不会被判 DOWN，
    /// 于是照样吃一半流量——实测注入 20% 丢包时主表仍是两条 nexthop 的 ECMP，
    /// 使用者感受就是「有双网卡时经常检查到丢包」。
    #[serde(default = "default_degrade_loss_threshold")]
    pub degrade_loss_threshold: f64,
    /// 降级退出的迟滞量（预设 0.10）。
    ///
    /// 语意：**退出**降级需要窗口丢包率 <= `degrade_loss_threshold - degrade_hysteresis`
    /// （预设即 <= 0.10），与进入门槛（>= 0.20，预设）之间留出一段死区。
    ///
    /// 为什么需要：窗口长度 10 的量化步长是 10%（1 次失败 = 10%），注入 12%~30% 丢包时
    /// 窗口丢包率恰好会在 10% / 20% / 30% 之间摆动。单一门槛下 `is_degraded()` 每几秒
    /// 就进出一次，每次都触发 `Active WAN set changed` 并重下 ECMP 路由
    /// （实测 20 秒内 5~6 次，路由成员抖动）。迟滞让「刚降级」的线必须明显变好才准回来。
    ///
    /// 必须严格小于 `degrade_loss_threshold`（功能关闭时不比对）。
    #[serde(default = "default_degrade_hysteresis")]
    pub degrade_hysteresis: f64,
    /// 退出降级所需的**连续**样本数（预设 6）。
    ///
    /// 任一笔不满足退出条件就把累积次数归零重数：避免「刚好有一拍量到 0%」这种单次侥幸
    /// 就让线路回到 ECMP，下一秒又被踢出去。
    #[serde(default = "default_degrade_exit_samples")]
    pub degrade_exit_samples: usize,
    /// 进入降级所需的**连续样本数**（预设 20，≈2 个窗口）。
    ///
    /// 为什么需要：窗口只有 `window_size` 个样本（预设 10，量化步长 10%）。
    /// 一条「还在正常工作、只是被自己的流量打满而变慢」的线——典型例子是
    /// 隧道型 WAN（WireGuard/VXLAN）：满载时 SYN 探针很容易超过 `probe_timeout_ms`，
    /// 只要某一次窗口刚好累积到 `>= degrade_loss_threshold`，该线就被立刻移出 ECMP：
    /// 全部流量瞬时压到另一条线（实测：另一条 150Mbps 的线瞬间被打满，使用者看到
    /// 「一条线突然很卡、整网卡顿」），几秒后该线又恢复、再次加回来，
    /// 每次都重算整张 multipath hash（standard 模式会把大量既有连线改送另一条 WAN）。
    ///
    /// 要求「连续 N 个样本都超标」把单一窗口的偶然抖动与持续劣化分开：
    /// 预设 20（`window_size = 10` 时约 2 个窗口，500ms 周期约 10 秒）。
    ///
    /// 为什么不是「1 个窗口就够」：窗口是 FIFO，一旦某个窗口里出现 2 次超时，
    /// 这个 20% 会**持续存在 8 个样本**才会被新的成功样本挤出去——也就是说
    /// 「连续 2 个样本超标」几乎是单一窗口达标的必然结果，挡不住任何东西。
    /// 真正能挡掉的是「达标只维持一两个窗口就恢复」的抖动，所以门槛必须是
    /// 样本数（预设约 2 个窗口），而不是「几次评估」。
    /// 设 1 = 沿用旧行为（单次达标即降级）。
    #[serde(default = "default_degrade_enter_samples")]
    pub degrade_enter_samples: usize,
    /// 降级后至少要离开 ECMP 几个样本才准回来（预设 20，0 = 不限制）。
    ///
    /// 为什么需要：`degrade_exit_samples`（预设 6）只看「最近几拍变好了」，
    /// 对「因为被打满而丢探针」的线来说，流量一移走它就立刻变好，于是
    /// 「移出 → 5 秒后回来 → 又被打满 → 又移出」形成数秒级的循环。
    /// 每次循环都会重映射既有 flow（standard 模式还会 flush conntrack），
    /// 使用者体验就是「网路一直卡」。要求离开 ECMP 至少一段时间，
    /// 让它在外面多观察一会再回来。预设 20 拍（500ms 周期约 10 秒）。
    #[serde(default = "default_degrade_min_out_samples")]
    pub degrade_min_out_samples: usize,
    /// 连续超时次数触发 DOWN，规范要求 3 次
    #[serde(default = "default_consecutive_fail_down")]
    pub consecutive_fail_down: usize,
    /// 连续成功次数触发 UP 恢复（Hysteresis 防震荡），规范要求 5 次
    #[serde(default = "default_recovery_success_count")]
    pub recovery_success_count: usize,
    /// 最大容许 RTT（毫秒），超过视为异常
    #[serde(default = "default_max_rtt_ms")]
    pub max_rtt_ms: f64,
    /// 平滑 RTT 连续超标几次才判定 DOWN（避免单一尖峰造成震荡）
    #[serde(default = "default_rtt_fail_count")]
    pub rtt_fail_count: usize,
    /// 当线路 DOWN 时，是否清理该网卡上的 conntrack 连接
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_down: bool,
    /// 当存活网卡集合变化时（例如主线路恢复、ECMP 成员进出）是否清理 conntrack。
    /// ECMP 的 nexthop 集合一变，核心会重算 multipath hash，
    /// 既有连线可能被改送到另一条 WAN 而卡死，清掉才能立刻重建。
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_switch: bool,
    /// 同一张网卡两次 conntrack 清理之间的最小间隔（毫秒），防止链路抖动时反复全表 dump
    #[serde(default = "default_conntrack_flush_min_interval_ms")]
    pub conntrack_flush_min_interval_ms: u64,
    /// 下发到核心的预设路由 metric（RTA_PRIORITY），预设 0
    #[serde(default = "default_route_priority")]
    pub route_priority: u32,
    /// ECMP 实作方式（standard / auto / resilient），预设 **`auto`**。
    ///
    /// 为什么不预设 `standard`：standard 是单一 `RTA_MULTIPATH` 路由，**任何**成员或
    /// 权重变动都会让核心重算整张 multipath hash —— 实测会连坐搬走 40%~43% 的既有 flow
    /// （包含没出问题那条线上的 flow），换了出口就换 NAT 源 IP、连线被打断，使用者看到的
    /// 是「玩到一半突然卡顿」。`auto` 在核心支援 nexthop object 时用 resilient
    /// （只搬空闲 bucket，既有 flow 不动），不支援时自动退回 standard。
    /// 要强制旧行为请明确设 `standard`；详见 `EcmpMode`。
    #[serde(default)]
    pub ecmp_mode: EcmpMode,
    /// 优雅退出时是否移除本程式下发的预设路由（预设 **false**）。
    ///
    /// 预设改为 false 的原因：预设路由是本机（含所有 LAN 客户端）唯一的出口，
    /// 服务重启／套件升级／`uci commit` 触发 reload 时删掉它，会在「旧实例已退出、
    /// 新实例还没下发」的窗口内把整台路由器打成离线；若新实例启动失败，更是永久断网。
    /// 需要「退出即清干净」的部署再明确设为 true。
    #[serde(default = "default_remove_routes_on_exit")]
    pub remove_routes_on_exit: bool,
    /// 启动时设定内核 `net.ipv{4,6}.fib_multipath_hash_policy`。
    /// **预设 `l4`；明确写 `null` = 不写入、沿用系统预设**（旧行为）。变更需重启服务。
    ///
    /// 为什么预设是 `l4` 而不是「不写入」：本机实测（Linux 7.1.8，netns，真实 UDP 封包
    /// 以网卡 TX 计数判出口）内核预设的 `fib_multipath_hash_policy=0` 只哈希来源/目的 IP，
    /// 于是「同一个目的 IP、只差来源埠」的 24 条连线**100% 走同一条 WAN**
    /// （视频网站对同一个 CDN IP 开多条连线，正是这个形态），另一条线完全用不到；
    /// 写成 `1`（l4）后同样的 24 条连线变成 12/12 分开。这就是「双 WAN 了还是卡」
    /// 最常见的成因。要刻意维持 L3 粒度请写 `l3`，要完全不碰内核设定写 `null`。
    ///
    /// 注意 `fib_multipath_hash_fields`：同一个实验里，该档案无论写成 1 / 7 / 8 / 9 / 31 / 32
    /// 都不改变哈希结果（可写入、可读回，但被内核忽略）——所以**有效开关是 policy**。
    /// 守护进程仍会依 policy 把缺少的位元补齐（旧内核上 policy 才是唯一开关，
    /// 部分新版内核则以位元为准），并把两者的读回值写进 log 与状态档。
    #[serde(default = "default_multipath_hash_policy")]
    pub multipath_hash_policy: Option<MultipathHashPolicy>,
    /// ECMP 权重模式：`static`（预设）或 `quality`（依 LQE 品质动态调整）
    #[serde(default)]
    pub weight_mode: WeightMode,
    /// 动态权重的最小更新间隔（毫秒，预设 10000，范围 1000 ~ 3600000）。
    /// 每次更新都会重下 ECMP 路由（内核可能重算 multipath hash），因此必须限速。
    #[serde(default = "default_dynamic_weight_interval_ms")]
    pub dynamic_weight_interval_ms: u64,
    /// 动态权重的下修下限（比例，预设 0.25，范围 0.05 ~ 1.0）：
    /// 品质再差也不会低于 `weight × 此值`（真正不可用的线由降级/DOWN 机制移出）。
    #[serde(default = "default_dynamic_weight_min_ratio")]
    pub dynamic_weight_min_ratio: f64,
    /// 负载感知分流（预设 false）。
    ///
    /// 启用后，守护进程会依每条 WAN 的实测速率（tx_bps / rx_bps 的 EWMA）与
    /// `interfaces[].max_mbps` / `up_mbps` 算出利用率；当**某条线**的利用率
    /// 超过 `load_target_ratio`，就在下一次动态权重更新时把它与其他线的 ECMP
    /// 权重比例往「空闲线」倾斜，把部分 flow 转移过去。
    ///
    /// 纯流量面：不新增路由、不碰 conntrack，只调整既有 ECMP 的权重比例。
    /// 更新节奏沿用 `dynamic_weight_interval_ms`（每次都是一次 RTM_NEWROUTE）。
    #[serde(default)]
    pub load_aware: bool,
    /// 负载感知的触发门槛（预设 0.80）：利用率 >= 此值视为「过载」，开始下修权重。
    ///
    /// 必须大于 `load_recover_ratio`。范围 (0, 1]。
    #[serde(default = "default_load_target_ratio")]
    pub load_target_ratio: f64,
    /// 负载感知的退出门槛（预设 0.60）：利用率 <= 此值时压力才完全解除。
    ///
    /// 与触发门槛之间的死区就是迟滞：被下修过的线必须低于此值才恢复原权重，
    /// 借此避免「下修→流量移走→立刻恢复→流量又回来」的控制回圈震荡。
    #[serde(default = "default_load_recover_ratio")]
    pub load_recover_ratio: f64,
    /// 是否允许在 `standard` ECMP 下套用动态因子（quality / load_aware）（预设 false）。
    ///
    /// 为什么预设关闭：`standard` 是一个 `RTA_MULTIPATH` 路由，任何权重变更都会让
    /// 内核**重算整张 multipath hash**。实测（Linux 6.12/6.18，512 个 flow key）：
    /// 权重从 1:1 改成 1:10 会让 **39%** 的既有 flow 被改送到另一条 WAN，
    /// 1:10 改成 1:2 会搬走 **24%**。转发流量经 NAT 后源 IP 会跟著换，
    /// 对端看到未知的四元组 → 连线被 RST 或大量重传；而动态权重**本来就无法**
    /// 把已经建立的大流量搬走（per-flow 哈希），所以净效果是「打断连线却换不到分流」。
    /// `resilient`（nexthop group）则只重映射故障/空闲的 bucket（实测：满载中的
    /// bucket 不会被搬动），因此动态因子在 `resilient` 下才是安全的。
    ///
    /// 这不是移除功能：把 `ecmp_mode` 改成 `resilient` / `auto` 后动态因子就会生效；
    /// 若确实理解上述代价仍要在 `standard` 下使用，明确设为 true。
    #[serde(default)]
    pub allow_dynamic_weights_on_standard: bool,
    /// 来源/目的策略分流规则（选填；见 `PolicyConfig`）。
    /// 匹配的转发流量走指定 WAN，其余仍走 ECMP；目标 WAN DOWN 时自动回退 ECMP。
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    /// WAN 接口配置列表
    pub interfaces: Vec<InterfaceConfig>,
    /// 未知栏位（以 `_` 开头者视为注解）。validate() 会拒绝真正的拼字错误。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_check_interval_ms() -> u64 {
    500
}
/// 单次探测超时必须小于探测周期，否则实际周期会被超时拖长
fn default_probe_timeout_ms() -> u64 {
    400
}
fn default_window_size() -> usize {
    10
}
fn default_loss_threshold_down() -> f64 {
    0.50
}
fn default_loss_threshold_up() -> f64 {
    0.10
}
/// 预设 0.20：介于「可接受」与 `loss_threshold_down`(0.50) 之间的线路不该再吃一半流量。
/// 0.0 = 关闭（沿用「只要没判 DOWN 就照常承载」的旧行为）。
fn default_degrade_loss_threshold() -> f64 {
    0.20
}
/// 预设 0.10：退出门槛 = 0.20 - 0.10 = 0.10，与进入门槛（0.20）之间形成死区，
/// 让「窗口丢包率在 10%/20% 之间摆动」的线不会每几秒进出一次降级。
fn default_degrade_hysteresis() -> f64 {
    0.10
}
/// 预设 6 次连续样本（≈3 秒）才准退出降级，挡掉单次侥幸。
fn default_degrade_exit_samples() -> usize {
    6
}
/// 预设 20 个连续样本（`window_size=10` 时约 2 个窗口、500ms 周期约 10 秒）超标才进入降级：
/// 把「单一窗口的偶然抖动」与「持续劣化」分开，避免一条只是被打满（探针偶尔超时）
/// 的线被反复移出/加回 ECMP（每次都会重映射既有 flow、standard 模式还会 flush conntrack）。
fn default_degrade_enter_samples() -> usize {
    20
}
/// 预设 20 拍（500ms 周期约 10 秒）的「最短离开时间」，
/// 挡掉「移出→5 秒后回来→又被打满→又移出」的数秒级循环。
fn default_degrade_min_out_samples() -> usize {
    20
}
fn default_consecutive_fail_down() -> usize {
    3
}
fn default_recovery_success_count() -> usize {
    5
}
fn default_max_rtt_ms() -> f64 {
    1500.0
}
fn default_rtt_fail_count() -> usize {
    3
}
fn default_conntrack_flush_min_interval_ms() -> u64 {
    10_000
}
fn default_flush_conntrack() -> bool {
    true
}
fn default_route_priority() -> u32 {
    0
}
fn default_dynamic_weight_interval_ms() -> u64 {
    10_000
}
fn default_dynamic_weight_min_ratio() -> f64 {
    0.25
}
fn default_load_target_ratio() -> f64 {
    0.80
}
fn default_load_recover_ratio() -> f64 {
    0.60
}
/// 预设 false：见 `remove_routes_on_exit` 的说明。删掉唯一一条预设路由
/// 会在重启窗口内让整台路由器失去出口（且新实例失败时无法自行恢复）。
fn default_remove_routes_on_exit() -> bool {
    false
}

/// 预设 `l4`：见 `DaemonConfig::multipath_hash_policy` 的说明。
/// 明确写 `null` 才会变成「不写入、沿用系统预设」。
fn default_multipath_hash_policy() -> Option<MultipathHashPolicy> {
    Some(MultipathHashPolicy::L4)
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: default_check_interval_ms(),
            probe_timeout_ms: default_probe_timeout_ms(),
            window_size: default_window_size(),
            loss_threshold_down: default_loss_threshold_down(),
            loss_threshold_up: default_loss_threshold_up(),
            degrade_loss_threshold: default_degrade_loss_threshold(),
            degrade_hysteresis: default_degrade_hysteresis(),
            degrade_exit_samples: default_degrade_exit_samples(),
            degrade_enter_samples: default_degrade_enter_samples(),
            degrade_min_out_samples: default_degrade_min_out_samples(),
            consecutive_fail_down: default_consecutive_fail_down(),
            recovery_success_count: default_recovery_success_count(),
            max_rtt_ms: default_max_rtt_ms(),
            rtt_fail_count: default_rtt_fail_count(),
            flush_conntrack_on_down: default_flush_conntrack(),
            flush_conntrack_on_switch: default_flush_conntrack(),
            conntrack_flush_min_interval_ms: default_conntrack_flush_min_interval_ms(),
            route_priority: default_route_priority(),
            ecmp_mode: EcmpMode::default(),
            remove_routes_on_exit: default_remove_routes_on_exit(),
            multipath_hash_policy: default_multipath_hash_policy(),
            weight_mode: WeightMode::default(),
            dynamic_weight_interval_ms: default_dynamic_weight_interval_ms(),
            dynamic_weight_min_ratio: default_dynamic_weight_min_ratio(),
            load_aware: false,
            load_target_ratio: default_load_target_ratio(),
            load_recover_ratio: default_load_recover_ratio(),
            allow_dynamic_weights_on_standard: false,
            policies: Vec::new(),
            interfaces: vec![
                InterfaceConfig {
                    name: "wan1".to_string(),
                    gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    gateway6: None,
                    metric: 1,
                    weight: 1,
                    max_mbps: None,
                    up_mbps: None,
                    probe_targets: default_probe_targets(),
                    underlay_targets: Vec::new(),
                    extra: Default::default(),
                },
                InterfaceConfig {
                    name: "wan2".to_string(),
                    gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
                    gateway6: None,
                    metric: 1,
                    weight: 1,
                    max_mbps: None,
                    up_mbps: None,
                    probe_targets: default_probe_targets(),
                    underlay_targets: Vec::new(),
                    extra: Default::default(),
                },
            ],
            extra: Default::default(),
        }
    }
}

impl DaemonConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: DaemonConfig = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// 是否依最大频宽比例计算 ECMP 权重：只要有一条线设定了 `max_mbps`。
    /// `validate()` 已保证「要嘛全填、要嘛全不填」，因此任一即可代表全部。
    pub fn capacity_weights_on(&self) -> bool {
        self.interfaces.iter().any(|i| i.max_mbps.is_some())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.interfaces.is_empty() {
            return Err("At least one WAN interface must be configured".into());
        }
        // 每张 WAN 会占用一个探针 slot（独立表＋oif 规则），slot 数有上限
        if self.interfaces.len() > crate::netlink::route::PROBE_SLOT_MAX as usize {
            return Err(format!(
                "too many interfaces: {} (limit is {})",
                self.interfaces.len(),
                crate::netlink::route::PROBE_SLOT_MAX
            ));
        }
        if self.window_size == 0 {
            return Err("window_size must be greater than 0".into());
        }
        if self.window_size > MAX_WINDOW_SIZE {
            return Err(format!(
                "window_size {} out of range (1 ~ {MAX_WINDOW_SIZE})",
                self.window_size
            ));
        }
        if self.check_interval_ms == 0 {
            return Err("check_interval_ms must be greater than 0".into());
        }
        if self.check_interval_ms > MAX_CHECK_INTERVAL_MS {
            return Err(format!(
                "check_interval_ms {} out of range (1 ~ {MAX_CHECK_INTERVAL_MS})",
                self.check_interval_ms
            ));
        }
        if self.probe_timeout_ms == 0 {
            return Err("probe_timeout_ms must be greater than 0".into());
        }
        // 逾时大于周期会让每个周期至少被阻塞 probe_timeout，实际探测节奏被拉长，
        // 且期间事件回圈无法处理讯号／link 事件。旧版只在启动时 warn，这里直接挡。
        if self.probe_timeout_ms > self.check_interval_ms {
            return Err(format!(
                "probe_timeout_ms ({}) must not exceed check_interval_ms ({})",
                self.probe_timeout_ms, self.check_interval_ms
            ));
        }
        // 未知栏位：`_comment` 之类以 `_` 开头者视为注解，其余多半是拼字错误，
        // 宁可启动前大声失败，也不要默默用预设值跑整个生命周期。
        for key in self.extra.keys() {
            if !key.starts_with('_') {
                return Err(format!(
                    "unknown top-level config field: '{key}' (prefix comments with '_')"
                ));
            }
        }
        if self.consecutive_fail_down == 0 {
            return Err("consecutive_fail_down must be greater than 0".into());
        }
        if self.recovery_success_count == 0 {
            return Err("recovery_success_count must be greater than 0".into());
        }
        if self.rtt_fail_count == 0 {
            return Err("rtt_fail_count must be greater than 0".into());
        }
        // `1e999` 会被 serde_json 解析成 +inf：`inf <= 0.0` 为 false 会通过检查，
        // 之后所有 RTT 都「不超标」，等于静默关闭 RTT 判据。
        if !self.max_rtt_ms.is_finite() || self.max_rtt_ms <= 0.0 {
            return Err("max_rtt_ms must be a finite number greater than 0".into());
        }
        if !(0.0..=1.0).contains(&self.loss_threshold_down) {
            return Err("loss_threshold_down must be within 0.0 ~ 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.loss_threshold_up) {
            return Err("loss_threshold_up must be within 0.0 ~ 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.degrade_loss_threshold) {
            return Err("degrade_loss_threshold must be within 0.0 ~ 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.degrade_hysteresis) {
            return Err("degrade_hysteresis must be within 0.0 ~ 1.0".into());
        }
        if self.degrade_exit_samples == 0 {
            return Err("degrade_exit_samples must be greater than 0".into());
        }
        // 进入降级的连续评估次数：1 = 旧行为（单次达标即降级），上限只是防呆
        // （设定成几百拍等于永不降级，那就该直接把 degrade_loss_threshold 设 0）。
        if self.degrade_enter_samples == 0 || self.degrade_enter_samples > MAX_DEGRADE_STREAK {
            return Err(format!(
                "degrade_enter_samples {} out of range (1 ~ {MAX_DEGRADE_STREAK})",
                self.degrade_enter_samples
            ));
        }
        if self.degrade_min_out_samples > MAX_DEGRADE_STREAK {
            return Err(format!(
                "degrade_min_out_samples {} out of range (0 ~ {MAX_DEGRADE_STREAK})",
                self.degrade_min_out_samples
            ));
        }
        // 降级门槛必须严格低于判死门槛：否则会出现「先降级、下一秒就判 DOWN」的
        // 自相矛盾设定（降级的意义就是「还有救、只是别再吃流量」）。
        // 0.0 = 关闭降级功能，此时不与判死门槛比较。
        if self.degrade_loss_threshold > 0.0
            && self.degrade_loss_threshold >= self.loss_threshold_down
        {
            return Err(format!(
                "degrade_loss_threshold ({}) must be less than loss_threshold_down ({})",
                self.degrade_loss_threshold, self.loss_threshold_down
            ));
        }
        // 迟滞量必须严格小于降级门槛：否则退出门槛（门槛 - 迟滞）会落在 0 以下或等于进入门槛，
        // 前者永远退不出降级（线路被判 UP 却永远不参与 ECMP），后者等于没有迟滞。
        // 0.0 = 关闭降级功能，此时不比对。
        if self.degrade_loss_threshold > 0.0
            && self.degrade_hysteresis >= self.degrade_loss_threshold
        {
            return Err(format!(
                "degrade_hysteresis ({}) must be less than degrade_loss_threshold ({})",
                self.degrade_hysteresis, self.degrade_loss_threshold
            ));
        }

        let mut seen = std::collections::HashSet::new();
        for iface in &self.interfaces {
            if iface.name.is_empty() {
                return Err("Interface name cannot be empty".into());
            }
            // 名称会用在 /proc、/sys 路径与 IFNAMSIZ 限制上：含 '/' 会造成路径穿越，
            // 过长则 if_nametoindex 永远失败
            if iface.name.len() > MAX_IFNAME_LEN {
                return Err(format!(
                    "Interface name '{}' is too long (max {MAX_IFNAME_LEN} characters)",
                    iface.name
                ));
            }
            if !iface
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            {
                return Err(format!(
                    "Interface name '{}' contains invalid characters (allowed: letters, digits, '_', '-', '.')",
                    iface.name
                ));
            }
            if !seen.insert(iface.name.clone()) {
                return Err(format!("Duplicate interface name: {}", iface.name));
            }
            if iface.probe_targets.is_empty() {
                return Err(format!("Interface {} has no probe targets", iface.name));
            }
            if iface.weight == 0 || iface.weight > MAX_WEIGHT {
                return Err(format!(
                    "Interface {} weight {} out of range (1 ~ {})",
                    iface.name, iface.weight, MAX_WEIGHT
                ));
            }
            // 容量（最大频宽）必须是有限正数：0 或 inf 会让利用率永远是 0／NaN，
            // 容量比例分流也会退化成无意义的比例。
            if let Some(max) = iface.max_mbps {
                if !max.is_finite() || max <= 0.0 {
                    return Err(format!(
                        "Interface {} max_mbps {max} must be a finite number greater than 0",
                        iface.name
                    ));
                }
            }
            if let Some(up) = iface.up_mbps {
                if !up.is_finite() || up <= 0.0 {
                    return Err(format!(
                        "Interface {} up_mbps {up} must be a finite number greater than 0",
                        iface.name
                    ));
                }
            }
            // 启用负载感知却没填最大频宽：演算法既无法按容量比例分流，
            // 也无从判定过载，宁可启动前大声失败，也不要默默照旧分流。
            if self.load_aware && iface.max_mbps.is_none() {
                return Err(format!(
                    "Interface {} needs max_mbps when load_aware is enabled",
                    iface.name
                ));
            }
            if let Some(gw) = iface.gateway {
                if gw.is_loopback() || gw.is_multicast() || gw.is_broadcast() {
                    return Err(format!(
                        "Interface {} gateway {gw} is not a usable unicast address",
                        iface.name
                    ));
                }
            }
            if let Some(gw6) = iface.gateway6 {
                if gw6.is_loopback() || gw6.is_multicast() {
                    return Err(format!(
                        "Interface {} gateway6 {gw6} is not a usable unicast address",
                        iface.name
                    ));
                }
            }
            for underlay in &iface.underlay_targets {
                if underlay.is_loopback() || underlay.is_multicast() || underlay.is_broadcast() {
                    return Err(format!(
                        "Interface {} underlay target {underlay} is not a usable unicast address",
                        iface.name
                    ));
                }
            }
            // 路由模组只支援 IPv4，若给了 IPv6 目标只会永远连不上
            for target in &iface.probe_targets {
                if !target.is_ipv4() {
                    return Err(format!(
                        "Interface {} probe target {} is not IPv4 (IPv6 is unsupported)",
                        iface.name, target
                    ));
                }
                if target.port() == 0 {
                    return Err(format!(
                        "Interface {} probe target {} has port 0",
                        iface.name, target
                    ));
                }
            }
            for key in iface.extra.keys() {
                if !key.starts_with('_') {
                    return Err(format!(
                        "Interface {}: unknown config field '{key}' (prefix comments with '_')",
                        iface.name
                    ));
                }
            }
        }

        // 容量比例分流是「整组权重按最大频宽缩放」，只给部分线容量会让比例无从定义。
        // 要嘛全部都填 max_mbps、要嘛全部不填（load_aware 已在回圈内强制全部要填）。
        let with_capacity = self
            .interfaces
            .iter()
            .filter(|i| i.max_mbps.is_some())
            .count();
        if with_capacity != 0 && with_capacity != self.interfaces.len() {
            return Err(
                "either set 'max_mbps' on every interface or on none of them \
                 (capacity-proportional ECMP needs all capacities)"
                    .into(),
            );
        }

        // 动态权重参数
        if self.dynamic_weight_interval_ms < 1_000 || self.dynamic_weight_interval_ms > 3_600_000 {
            return Err(format!(
                "dynamic_weight_interval_ms {} out of range (1000 ~ 3600000)",
                self.dynamic_weight_interval_ms
            ));
        }
        if !self.dynamic_weight_min_ratio.is_finite()
            || !(0.05..=1.0).contains(&self.dynamic_weight_min_ratio)
        {
            return Err("dynamic_weight_min_ratio must be within 0.05 ~ 1.0".into());
        }

        // 负载感知门槛：目标必须在 (0,1]，且严格大于恢复门槛（两者之间才是迟滞死区）。
        if !self.load_target_ratio.is_finite() || !(0.0..=1.0).contains(&self.load_target_ratio) {
            return Err("load_target_ratio must be within 0.0 ~ 1.0".into());
        }
        if self.load_target_ratio == 0.0 {
            return Err("load_target_ratio must be greater than 0".into());
        }
        if !self.load_recover_ratio.is_finite() || !(0.0..=1.0).contains(&self.load_recover_ratio) {
            return Err("load_recover_ratio must be within 0.0 ~ 1.0".into());
        }
        if self.load_recover_ratio >= self.load_target_ratio {
            return Err(format!(
                "load_recover_ratio ({}) must be less than load_target_ratio ({})",
                self.load_recover_ratio, self.load_target_ratio
            ));
        }

        // 策略分流规则：名称/目标/前缀/优先序/展开后的条数
        use crate::netlink::route::{POLICY_RULE_PRIORITY_BASE, POLICY_SLOT_MAX};
        let mut policy_names = std::collections::HashSet::new();
        let mut explicit_priorities: Vec<u32> = Vec::new();
        let mut expanded_rules = 0usize;
        for policy in &self.policies {
            if policy.name.is_empty() || policy.name.len() > 64 {
                return Err("policy name must be 1 ~ 64 characters".into());
            }
            if !policy_names.insert(policy.name.clone()) {
                return Err(format!("Duplicate policy name: {}", policy.name));
            }
            if !self.interfaces.iter().any(|i| i.name == policy.interface) {
                return Err(format!(
                    "Policy '{}' targets unknown interface '{}'",
                    policy.name, policy.interface
                ));
            }
            if let Some(priority) = policy.priority {
                if !(POLICY_RULE_PRIORITY_BASE..POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX)
                    .contains(&priority)
                {
                    return Err(format!(
                        "Policy '{}' priority {priority} out of range ({} ~ {})",
                        policy.name,
                        POLICY_RULE_PRIORITY_BASE,
                        POLICY_RULE_PRIORITY_BASE + POLICY_SLOT_MAX - 1
                    ));
                }
                if explicit_priorities.contains(&priority) {
                    return Err(format!(
                        "Policy '{}' reuses priority {priority}",
                        policy.name
                    ));
                }
                explicit_priorities.push(priority);
            }
            for raw in policy.source.iter().chain(policy.destination.iter()) {
                parse_ipv4_prefix(raw).map_err(|e| format!("Policy '{}': {e}", policy.name))?;
            }
            for key in policy.extra.keys() {
                if !key.starts_with('_') {
                    return Err(format!(
                        "Policy '{}': unknown config field '{key}' (prefix comments with '_')",
                        policy.name
                    ));
                }
            }
            let sources = policy.source.len().max(1);
            let destinations = policy.destination.len().max(1);
            expanded_rules += sources * destinations;
        }
        if expanded_rules > POLICY_SLOT_MAX as usize {
            return Err(format!(
                "policies expand to {expanded_rules} rules (limit {POLICY_SLOT_MAX}); \
                 reduce source/destination entries"
            ));
        }
        if !explicit_priorities.is_empty() && explicit_priorities.len() != self.policies.len() {
            return Err(
                "either set 'priority' on every policy or on none of them (mixed is ambiguous)"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // 测试里「先取预设值、再改一两个栏位」比整包 struct literal 清楚得多，
    // 尤其只需要动 interfaces[0].weight 这类巢状栏位时。
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    #[test]
    fn test_default_config_valid() {
        let cfg = DaemonConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.interfaces.len(), 2);
    }

    #[test]
    fn test_default_probe_targets_are_mainland_dns() {
        let want = vec!["223.5.5.5:53", "114.114.114.114:53"];
        let cfg = DaemonConfig::default();
        let got: Vec<String> = cfg.interfaces[0]
            .probe_targets
            .iter()
            .map(|t| t.to_string())
            .collect();
        assert_eq!(got, want, "预设探测目标应为大陆公共 DNS（TCP 53）");
        assert!(cfg.validate().is_ok());

        // 旧设定档省略 probe_targets 时也必须拿到同一组预设，不能退回境外 DNS
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        let got_old: Vec<String> = old.interfaces[0]
            .probe_targets
            .iter()
            .map(|t| t.to_string())
            .collect();
        assert_eq!(got_old, want);
    }

    #[test]
    fn test_json_roundtrip() {
        let cfg = DaemonConfig::default();
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let parsed: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.check_interval_ms, 500);
        assert_eq!(parsed.window_size, 10);
        assert_eq!(parsed.interfaces[0].name, "wan1");
    }

    #[test]
    fn test_invalid_config() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces.clear();
        assert!(cfg.validate().is_err());

        let mut cfg2 = DaemonConfig::default();
        cfg2.window_size = 0;
        assert!(cfg2.validate().is_err());

        // 过大的窗口必须被挡下，避免低记忆体装置启动时超大预分配
        let mut cfg3 = DaemonConfig::default();
        cfg3.window_size = MAX_WINDOW_SIZE + 1;
        assert!(cfg3.validate().is_err());

        let mut cfg4 = DaemonConfig::default();
        cfg4.window_size = MAX_WINDOW_SIZE;
        assert!(cfg4.validate().is_ok());
    }

    #[test]
    fn test_probe_timeout_must_be_positive() {
        let mut cfg = DaemonConfig::default();
        cfg.probe_timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_zero_counters_rejected() {
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 0;
        assert!(cfg.validate().is_err());

        let mut cfg2 = DaemonConfig::default();
        cfg2.recovery_success_count = 0;
        assert!(cfg2.validate().is_err());
    }

    #[test]
    fn test_weight_range_enforced() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces[0].weight = 0;
        assert!(cfg.validate().is_err());

        let mut cfg2 = DaemonConfig::default();
        cfg2.interfaces[0].weight = MAX_WEIGHT + 1;
        assert!(cfg2.validate().is_err());

        let mut cfg3 = DaemonConfig::default();
        cfg3.interfaces[0].weight = MAX_WEIGHT;
        assert!(cfg3.validate().is_ok());
    }

    #[test]
    fn test_ipv6_probe_target_rejected() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces[0].probe_targets = vec!["[2606:4700::1111]:443".parse().unwrap()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_duplicate_interface_rejected() {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces[1].name = "wan1".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_degrade_entry_and_reentry_defaults_and_validation() {
        // 预设：连续 20 个样本超标才降级（≈2 个窗口）、最少离开 20 个样本才准回来。
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.degrade_enter_samples, 20);
        assert_eq!(cfg.degrade_min_out_samples, 20);
        assert!(cfg.validate().is_ok());

        // 旧设定档没有这两个栏位时必须拿到预设值（0 = 立刻降级／不设最短离开时间，
        // 都是我们刻意不要的旧行为）
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.degrade_enter_samples, 20);
        assert_eq!(old.degrade_min_out_samples, 20);

        // 明确设定时要能覆写（1 = 旧的「单次达标即降级」语意）
        let explicit: DaemonConfig = serde_json::from_str(
            r#"{"degrade_enter_samples":1,"degrade_min_out_samples":0,
                "interfaces":[{"name":"wan1"}]}"#,
        )
        .unwrap();
        assert_eq!(explicit.degrade_enter_samples, 1);
        assert_eq!(explicit.degrade_min_out_samples, 0);
        assert!(explicit.validate().is_ok());

        // 0 次代表「永不降级」这种自相矛盾的设定必须被挡下（要关就设门槛 0）
        let mut zero = DaemonConfig::default();
        zero.degrade_enter_samples = 0;
        assert!(zero.validate().is_err());

        let mut too_big = DaemonConfig::default();
        too_big.degrade_enter_samples = MAX_DEGRADE_STREAK + 1;
        assert!(too_big.validate().is_err());

        let mut out_too_big = DaemonConfig::default();
        out_too_big.degrade_min_out_samples = MAX_DEGRADE_STREAK + 1;
        assert!(out_too_big.validate().is_err());
    }

    #[test]
    fn test_dynamic_weight_standard_override_defaults() {
        // 预设 false：standard ECMP 下不套用动态因子（每次权重变更都会重算整张
        // multipath hash、搬走 24%~39% 的既有连线）。这是安全性预设，不是可选项。
        let cfg = DaemonConfig::default();
        assert!(!cfg.allow_dynamic_weights_on_standard);
        assert!(cfg.validate().is_ok());

        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.allow_dynamic_weights_on_standard);

        let opt_in: DaemonConfig = serde_json::from_str(
            r#"{"allow_dynamic_weights_on_standard":true,"interfaces":[{"name":"wan1"}]}"#,
        )
        .unwrap();
        assert!(opt_in.allow_dynamic_weights_on_standard);
        assert!(opt_in.validate().is_ok());
    }

    #[test]
    fn test_degrade_loss_threshold_defaults_and_validation() {
        // 预设 0.20：介于「可接受」与判死(0.50)之间
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_loss_threshold - 0.20).abs() < f64::EPSILON);
        assert!(cfg.validate().is_ok());

        // 旧设定档没有这个栏位时，必须拿到预设值而不是 0（=关闭），否则升级后行为会倒退
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_loss_threshold - 0.20).abs() < f64::EPSILON);

        // 范围检查
        let mut too_big = DaemonConfig::default();
        too_big.degrade_loss_threshold = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_loss_threshold = -0.1;
        assert!(negative.validate().is_err());

        // 0.0 = 关闭功能，合法
        let mut disabled = DaemonConfig::default();
        disabled.degrade_loss_threshold = 0.0;
        assert!(disabled.validate().is_ok());

        // 必须严格小于判死门槛，否则「降级」与「判死」互相矛盾
        let mut not_less = DaemonConfig::default();
        not_less.degrade_loss_threshold = 0.5;
        assert!(not_less.validate().is_err());

        // 刚好小于则合法（0.49 < 0.50）
        let mut just_below = DaemonConfig::default();
        just_below.degrade_loss_threshold = 0.49;
        assert!(just_below.validate().is_ok());
    }

    #[test]
    fn test_degrade_hysteresis_defaults_and_validation() {
        // 预设 0.10 / 6：退出门槛 = 0.20 - 0.10 = 0.10，连续 6 次达标才退出
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.degrade_exit_samples, 6);
        assert!(cfg.validate().is_ok());

        // 旧设定档没有这两个栏位时必须拿到预设值（不是 0 / 0），否则升级后行为会倒退
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(old.degrade_exit_samples, 6);

        // 范围检查
        let mut too_big = DaemonConfig::default();
        too_big.degrade_hysteresis = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_hysteresis = -0.1;
        assert!(negative.validate().is_err());

        let mut zero_samples = DaemonConfig::default();
        zero_samples.degrade_exit_samples = 0;
        assert!(zero_samples.validate().is_err());

        // 迟滞量必须严格小于降级门槛：等于门槛（退出门槛 = 0）与大于门槛都必须被挡下，
        // 否则这条线一旦降级就再也回不来（永远不参与 ECMP）。
        let mut equal = DaemonConfig::default();
        equal.degrade_hysteresis = 0.20;
        assert!(equal.validate().is_err());

        let mut greater = DaemonConfig::default();
        greater.degrade_hysteresis = 0.30;
        assert!(greater.validate().is_err());

        // 刚好小于则合法（0.19 < 0.20）
        let mut just_below = DaemonConfig::default();
        just_below.degrade_hysteresis = 0.19;
        assert!(just_below.validate().is_ok());

        // 0.0 = 关闭降级功能：此时不比对两者大小
        let mut disabled = DaemonConfig::default();
        disabled.degrade_loss_threshold = 0.0;
        disabled.degrade_hysteresis = 0.90;
        assert!(disabled.validate().is_ok());
    }

    #[test]
    fn test_default_timeout_shorter_than_interval() {
        let cfg = DaemonConfig::default();
        assert!(cfg.probe_timeout_ms <= cfg.check_interval_ms);
    }

    #[test]
    fn test_remove_routes_on_exit_defaults_to_false() {
        // 预设必须是 false：删掉唯一一条预设路由会在服务重启窗口内
        // 让整台路由器（含所有 LAN 客户端）失去出口。
        assert!(!DaemonConfig::default().remove_routes_on_exit);
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.remove_routes_on_exit);
    }

    #[test]
    fn test_ecmp_mode_default_and_parsing() {
        // 预设改成 auto（核心支援就用 resilient，否则退回 standard）。
        // 为什么不再默认 standard：standard 的每一次成员／权重变动都会重算整张
        // multipath hash，实测连坐搬走 40%~43% 的既有 flow（含健康那条线的 flow），
        // 换出口＝换 NAT 源 IP＝连线被打断，这是「多线时游戏突然卡顿」的根因。
        // 要旧行为必须**明确**写 "standard"（下面的解析测试覆盖）。
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.ecmp_mode, EcmpMode::Auto);
        assert_eq!(DaemonConfig::default().ecmp_mode, EcmpMode::Auto);

        for (raw, want) in [
            ("standard", EcmpMode::Standard),
            ("auto", EcmpMode::Auto),
            ("resilient", EcmpMode::Resilient),
        ] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"ecmp_mode":"{raw}","interfaces":[{{"name":"wan1"}}]}}"#
            ))
            .unwrap();
            assert_eq!(cfg.ecmp_mode, want);
        }

        // 非预期字串必须直接报错，而不是静默当成 standard
        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"ecmp_mode":"bogus","interfaces":[{"name":"wan1"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn test_multipath_hash_policy_parsing_and_values() {
        // 没有这个栏位 → 预设 l4：新核心的 fields=7 会让「不写入」等于 L3 哈希，
        // 同一个目的 IP 的所有连线只走一条 WAN（视频 CDN 的典型症状）
        let bare: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(bare.multipath_hash_policy, Some(MultipathHashPolicy::L4));
        assert_eq!(
            DaemonConfig::default().multipath_hash_policy,
            Some(MultipathHashPolicy::L4)
        );
        // 明确写 null = 不写入内核（旧行为，保留逃生口）
        let off: DaemonConfig = serde_json::from_str(
            r#"{"multipath_hash_policy":null,"interfaces":[{"name":"wan1"}]}"#,
        )
        .unwrap();
        assert_eq!(off.multipath_hash_policy, None);

        for (raw, want, value) in [
            ("l3", MultipathHashPolicy::L3, 0u8),
            ("l4", MultipathHashPolicy::L4, 1),
            ("inner", MultipathHashPolicy::Inner, 2),
        ] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"multipath_hash_policy":"{raw}","interfaces":[{{"name":"wan1"}}]}}"#
            ))
            .unwrap();
            assert_eq!(cfg.multipath_hash_policy, Some(want));
            assert_eq!(want.sysctl_value(), value);
            assert!(cfg.validate().is_ok());
        }

        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"multipath_hash_policy":"bogus","interfaces":[{"name":"wan1"}]}"#
            )
            .is_err()
        );
    }

    /// 位元值取自内核 UAPI（`Documentation/networking/ip-sysctl.rst`），并与
    /// `src/main.rs` 的 L3/L4 遮罩常数一致；数值本身在本机核心上验证过可写入
    /// （见 netns 回归测试 F 段）。
    #[test]
    fn test_hash_field_bits_match_kernel_uapi() {
        assert_eq!(HashField::SrcIp.bit(), 1);
        assert_eq!(HashField::DstIp.bit(), 2);
        assert_eq!(HashField::IpProto.bit(), 4);
        assert_eq!(HashField::SrcPort.bit(), 8);
        assert_eq!(HashField::DstPort.bit(), 16);
        assert_eq!(HashField::InnerSrcIp.bit(), 32);
        assert_eq!(HashField::InnerDstIp.bit(), 64);
        assert_eq!(HashField::InnerIpProto.bit(), 128);
        assert_eq!(HashField::FlowLabel.bit(), 256);
        assert_eq!(HashField::InnerSrcPort.bit(), 512);
        assert_eq!(HashField::InnerDstPort.bit(), 1024);
        // 具名/遮罩的呈现（log、状态档用）
        assert_eq!(HashField::SrcPort.as_str(), "src_port");
        assert_eq!(HashField::InnerDstPort.as_str(), "inner_dst_port");
    }

    #[test]
    fn test_weight_mode_and_dynamic_weight_validation() {
        // 预设 static + 合理预设值
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.weight_mode, WeightMode::Static);
        assert_eq!(cfg.dynamic_weight_interval_ms, 10_000);
        assert!((cfg.dynamic_weight_min_ratio - 0.25).abs() < f64::EPSILON);
        assert!(cfg.validate().is_ok());

        let quality: DaemonConfig =
            serde_json::from_str(r#"{"weight_mode":"quality","interfaces":[{"name":"wan1"}]}"#)
                .unwrap();
        assert_eq!(quality.weight_mode, WeightMode::Quality);
        assert!(quality.validate().is_ok());

        for extra in [
            r#","dynamic_weight_interval_ms":10"#,
            r#","dynamic_weight_interval_ms":99999999"#,
            r#","dynamic_weight_min_ratio":0.0"#,
            r#","dynamic_weight_min_ratio":1.5"#,
        ] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"weight_mode":"quality"{extra},"interfaces":[{{"name":"wan1"}}]}}"#
            ))
            .unwrap();
            assert!(cfg.validate().is_err(), "should reject {extra}");
        }
    }

    #[test]
    fn test_load_aware_config_defaults_and_validation() {
        // 预设关闭，且门槛是合理的 0.80 / 0.60
        let cfg = DaemonConfig::default();
        assert!(!cfg.load_aware);
        assert!((cfg.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!((cfg.load_recover_ratio - 0.60).abs() < f64::EPSILON);
        assert_eq!(cfg.interfaces[0].max_mbps, None);
        assert_eq!(cfg.interfaces[0].up_mbps, None);
        assert!(!cfg.capacity_weights_on());
        assert!(cfg.validate().is_ok());

        // 旧设定档没有这些栏位时，必须沿用预设（不能变成 0 或开启）
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.load_aware);
        assert!((old.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!(old.validate().is_ok());

        // 启用负载感知：每条线都必须填最大频宽
        let missing: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[{"name":"wan1"},{"name":"wan2"}]}"#,
        )
        .unwrap();
        assert!(missing.validate().is_err(), "缺 max_mbps 必须被挡下");

        let ok: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[
                {"name":"wan1","max_mbps":1000,"up_mbps":50},
                {"name":"wan2","max_mbps":500}]}"#,
        )
        .unwrap();
        assert!(ok.validate().is_ok());
        assert!(ok.capacity_weights_on());
        // 非对称线路的 up_mbps 可省略（沿用 max_mbps）
        assert_eq!(ok.interfaces[1].up_mbps, None);

        // 旧名 down_mbps 仍可解析（serde alias）
        let aliased: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[
                {"name":"wan1","down_mbps":1000},
                {"name":"wan2","down_mbps":500}]}"#,
        )
        .unwrap();
        assert_eq!(aliased.interfaces[0].max_mbps, Some(1000.0));
        assert!(aliased.validate().is_ok());

        // 容量必须是有限正数
        for bad in [
            r#"{"name":"wan1","max_mbps":0}"#,
            r#"{"name":"wan1","max_mbps":-1}"#,
            r#"{"name":"wan1","max_mbps":100,"up_mbps":0}"#,
        ] {
            let cfg: DaemonConfig =
                serde_json::from_str(&format!(r#"{{"load_aware":true,"interfaces":[{bad}]}}"#))
                    .unwrap();
            assert!(cfg.validate().is_err(), "应拒绝容量 {bad}");
        }

        // 1e999 这类超范围数字在 JSON 解析阶段就会被 serde_json 拒绝，不会进到 validate
        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"load_aware":true,"interfaces":[{"name":"wan1","max_mbps":1e999}]}"#
            )
            .is_err()
        );

        // 容量要嘛全填、要嘛全不填：只给部分线容量会让比例无从定义
        let partial: DaemonConfig = serde_json::from_str(
            r#"{"interfaces":[{"name":"wan1","max_mbps":1000},{"name":"wan2"}]}"#,
        )
        .unwrap();
        assert!(
            partial.validate().is_err(),
            "部分线才有 max_mbps 必须被挡下"
        );

        // 门槛关系：recover 必须严格小于 target，target 必须 > 0
        for (target, recover) in [(0.8, 0.8), (0.8, 0.9), (0.0, 0.0)] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"load_target_ratio":{target},"load_recover_ratio":{recover},
                    "interfaces":[{{"name":"wan1"}}]}}"#
            ))
            .unwrap();
            assert!(
                cfg.validate().is_err(),
                "应拒绝 target={target} recover={recover}"
            );
        }
    }

    #[test]
    fn test_policies_validation() {
        let base = r#""interfaces":[{"name":"wan1"},{"name":"wan2"}]"#;
        let ok: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"guest","source":["192.168.3.0/24"],
                "interface":"wan2"}}],{base}}}"#
        ))
        .unwrap();
        assert!(ok.validate().is_ok(), "{:?}", ok.validate());

        // 展开多来源 x 多目的仍在上限内
        let expanded: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"multi",
                "source":["192.168.3.0/24","192.168.4.0/24"],
                "destination":["10.0.0.0/8","172.16.0.0/12"],
                "interface":"wan1"}}],{base}}}"#
        ))
        .unwrap();
        assert!(expanded.validate().is_ok());

        // 目标 WAN 不存在
        let unknown: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"x","interface":"wan9"}}],{base}}}"#
        ))
        .unwrap();
        assert!(unknown.validate().is_err());

        // 前缀格式错误
        for bad in ["192.168.3.0", "192.168.3.0/33", "300.1.1.1/24"] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"policies":[{{"name":"x","source":["{bad}"],"interface":"wan1"}}],{base}}}"#
            ))
            .unwrap();
            assert!(cfg.validate().is_err(), "should reject source {bad}");
        }

        // 名称重复 / 空名称
        let dup: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"x","interface":"wan1"}},
                {{"name":"x","interface":"wan2"}}],{base}}}"#
        ))
        .unwrap();
        assert!(dup.validate().is_err());
        let empty: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"","interface":"wan1"}}],{base}}}"#
        ))
        .unwrap();
        assert!(empty.validate().is_err());

        // 显式优先序：重复、超界、只设一半
        let dup_prio: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"a","interface":"wan1","priority":9000}},
                {{"name":"b","interface":"wan2","priority":9000}}],{base}}}"#
        ))
        .unwrap();
        assert!(dup_prio.validate().is_err());
        let out_of_range: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"a","interface":"wan1","priority":8999}}],{base}}}"#
        ))
        .unwrap();
        assert!(out_of_range.validate().is_err());
        let mixed: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"a","interface":"wan1","priority":9000}},
                {{"name":"b","interface":"wan2"}}],{base}}}"#
        ))
        .unwrap();
        assert!(mixed.validate().is_err());

        // 展开后超过 64 条
        let sources: Vec<String> = (0..70).map(|i| format!("\"10.{i}.0.0/16\"")).collect();
        let too_many: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"big","source":[{}],"interface":"wan1"}}],{base}}}"#,
            sources.join(",")
        ))
        .unwrap();
        assert!(too_many.validate().is_err());

        // 未知栏位（非注解）
        let unknown_field: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"x","interface":"wan1","bogus":1}}],{base}}}"#
        ))
        .unwrap();
        assert!(unknown_field.validate().is_err());
    }

    #[test]
    fn test_parse_ipv4_prefix_allows_host_and_default() {
        assert_eq!(
            parse_ipv4_prefix("0.0.0.0/0").unwrap(),
            (Ipv4Addr::new(0, 0, 0, 0), 0)
        );
        assert_eq!(
            parse_ipv4_prefix("192.168.3.7/32").unwrap(),
            (Ipv4Addr::new(192, 168, 3, 7), 32)
        );
        assert!(parse_ipv4_prefix("192.168.3.0").is_err());
        assert!(parse_ipv4_prefix("192.168.3.0/33").is_err());
    }
}
