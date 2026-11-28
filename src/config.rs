use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::str::FromStr;

/// ECMP 权重上限：resilient 的 nexthop_grp.weight 在 Linux < 6.9 只允许 ≤ 254，设 256 会让 RTM_NEWNEXTHOP 回 EINVAL。
pub const MAX_WEIGHT: u32 = 255;

/// 滑动窗口上限：过大窗口会让低记忆体装置启动时一次预分配过大缓冲，也拖慢每次样本更新。
pub const MAX_WINDOW_SIZE: usize = 1024;

/// 网卡名称长度上限（Linux IFNAMSIZ - 1）
pub const MAX_IFNAME_LEN: usize = 15;

/// 探测周期上限（毫秒）：1 小时。
pub const MAX_CHECK_INTERVAL_MS: u64 = 3_600_000;
/// 降级相关「连续拍数」栏位的上限（防呆）。
pub const MAX_DEGRADE_STREAK: usize = 600;

/// 多 WAN 等价路径（ECMP）的实作方式。
/// standard 的成员/权重变动会让核心重算整张 multipath hash，实测连坐搬走 40%~43% 的既有 flow（换出口＝换 NAT 源 IP＝断线）；resilient 只重映射故障/空闲 bucket。`auto`（预设）核心支援就用 resilient，否则退回 standard。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EcmpMode {
    Standard,
    #[default]
    Auto,
    Resilient,
}

/// 内核多路径（ECMP）哈希策略，写入 `net.ipv{4,6}.fib_multipath_hash_policy`；本专案预设 `l4`（`l3` 只哈希 IP，同一目的 IP 的多条连线会全挤一条 WAN，实测 24 条 100% 同线）。
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

/// `net.ipv{4,6}.fib_multipath_hash_fields` 的单个位元（Linux 6.12+ `include/net/ip_fib.h` UAPI）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashField {
    SrcIp,
    DstIp,
    IpProto,
    FlowLabel,
    SrcPort,
    DstPort,
    InnerSrcIp,
    InnerDstIp,
    InnerIpProto,
    InnerFlowLabel,
    InnerSrcPort,
    InnerDstPort,
}

impl HashField {
    pub const fn bit(self) -> u32 {
        match self {
            Self::SrcIp => 1,
            Self::DstIp => 2,
            Self::IpProto => 4,
            Self::FlowLabel => 8,
            Self::SrcPort => 16,
            Self::DstPort => 32,
            Self::InnerSrcIp => 64,
            Self::InnerDstIp => 128,
            Self::InnerIpProto => 256,
            Self::InnerFlowLabel => 512,
            Self::InnerSrcPort => 1024,
            Self::InnerDstPort => 2048,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SrcIp => "src_ip",
            Self::DstIp => "dst_ip",
            Self::IpProto => "ip_proto",
            Self::FlowLabel => "flow_label",
            Self::SrcPort => "src_port",
            Self::DstPort => "dst_port",
            Self::InnerSrcIp => "inner_src_ip",
            Self::InnerDstIp => "inner_dst_ip",
            Self::InnerIpProto => "inner_ip_proto",
            Self::InnerFlowLabel => "inner_flow_label",
            Self::InnerSrcPort => "inner_src_port",
            Self::InnerDstPort => "inner_dst_port",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    /// TCP SYN 握手探测（预设，兼容任何 TCP 端口，穿透力强）。
    #[default]
    Tcp,
    /// 真实 UDP DNS 查询探测（发标准 A 记录查询并校验应答，识别 TCP 假通 / 劫持，不占本地 53 端口）。
    Dns,
}

impl ProbeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Dns => "dns",
        }
    }
}

/// 每 WAN 上游 DNS 服务器地址：支持裸 IPv4（默认端口 53）或 `IP:Port`（如 `202.96.128.86` / `1.2.3.4:5353`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsServer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl DnsServer {
    pub const DEFAULT_PORT: u16 = 53;

    #[cfg(test)]
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn socket_addr(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.ip, self.port))
    }
}

impl fmt::Display for DnsServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == Self::DEFAULT_PORT {
            write!(f, "{}", self.ip)
        } else {
            write!(f, "{}:{}", self.ip, self.port)
        }
    }
}

impl FromStr for DnsServer {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let s = raw.trim();
        if let Some((ip_str, port_str)) = s.rsplit_once(':') {
            let ip: Ipv4Addr = ip_str
                .parse()
                .map_err(|_| format!("'{raw}' has an invalid IPv4 address"))?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("'{raw}' has an invalid port"))?;
            if port == 0 {
                return Err(format!("'{raw}' port must be within 1 ~ 65535"));
            }
            Ok(Self { ip, port })
        } else {
            let ip: Ipv4Addr = s
                .parse()
                .map_err(|_| format!("'{raw}' is not a valid IPv4 or IPv4:Port"))?;
            Ok(Self {
                ip,
                port: Self::DEFAULT_PORT,
            })
        }
    }
}

impl Serialize for DnsServer {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DnsServer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WeightMode {
    #[default]
    Static,
    /// 依 LQE 实测品质动态调整权重（丢包/RTT 差的线少分流量；变更会重下 ECMP 路由）。
    Quality,
    /// 余量感知聚合分流：综合剩余可用带宽与链路品质，按空闲余量动态倾斜多线权重（单/双数多 WAN 均适用），
    /// 在最低资源占用下实现多连接近带宽聚合效果（100% 兼容 Flow Offload）。
    Aggregate,
}

/// 一条来源/目的策略分流规则：以 `ip rule` 的 from/to + 该 WAN 独立路由表实现，不用 fwmark／nftables；目标 WAN DOWN 时规则暂时移除、回退 ECMP。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// 规则名称（唯一）
    pub name: String,
    /// 来源前缀（CIDR）。空清单 = 不限制来源
    #[serde(default)]
    pub source: Vec<String>,
    /// 目的前缀（CIDR）。空清单 = 不限制目的
    #[serde(default)]
    pub destination: Vec<String>,
    /// 目标 WAN 介面名称（必须是 `interfaces` 之一）
    pub interface: String,
    /// 规则优先序（选填）；预设依 `policies` 阵列顺序从 `POLICY_RULE_PRIORITY_BASE` 起算。
    #[serde(default)]
    pub priority: Option<u32>,
    /// 未知栏位（以 `_` 开头者视为注解）
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// 网卡名称，例如 "wan1"
    pub name: String,
    /// 网关 IP。点对点/WireGuard/PPPoE 无需网关，可为 None 或 0.0.0.0
    #[serde(default)]
    pub gateway: Option<Ipv4Addr>,
    /// IPv6 网关地址（选填）
    #[serde(default)]
    pub gateway6: Option<Ipv6Addr>,
    /// 路由优先级 Metric（预设 1）
    #[serde(default = "default_metric")]
    pub metric: u32,
    /// ECMP 多路路由权重（预设 1，范围 1~255）
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 这条线的最大频宽（Mbps）；设定后 ECMP 基准权重改为 ∝ `weight × max_mbps`，也作为下行容量，启用 `load_aware` 时必填（JSON 也接受旧名 `down_mbps`）。
    #[serde(default, alias = "down_mbps")]
    pub max_mbps: Option<f64>,
    /// 上行（WAN 出口）频宽上限（Mbps）；未设定时沿用 `max_mbps`（非对称线路才需要填）。
    #[serde(default)]
    pub up_mbps: Option<f64>,
    /// 探测目标地址列表（TCP SYN 或 UDP DNS 探测 IP:Port），如 ["223.5.5.5:53", ...]
    #[serde(default = "default_probe_targets")]
    pub probe_targets: Vec<SocketAddr>,
    /// 单接口探测模式覆写（选填；留空时继承全局 `probe_mode`）。
    #[serde(default)]
    pub probe_mode: Option<ProbeMode>,
    /// 该 WAN 专属的上游 DNS 服务器清单（支持 `IP` 或 `IP:Port`，选填，预设空 = 不干预）：
    /// 健康时在内核主表自动维护 `/32` 路由（metric 42762）固定走该 WAN 出口，同时也作为可选内置 DNS 转发器的上游地址。
    #[serde(default)]
    pub dns_servers: Vec<DnsServer>,
    /// 隧道型 WAN 的 underlay 对端位址（选填）：封装封包真正要去的地方必须经由**其他** WAN 抵达，否则有约 1/N 机率被塞回隧道自己形成自环。
    /// 设定后守护进程在 main 表为每个位址补一条 /32，固定走「非隧道、metric 最小」的那条 WAN。
    #[serde(default)]
    pub underlay_targets: Vec<Ipv4Addr>,
    /// 未知栏位（以 `_` 开头者视为注解）；validate() 会拒绝真正的拼字错误。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_metric() -> u32 {
    1
}

fn default_weight() -> u32 {
    1
}

/// 预设探测目标：大陆地区公共 DNS（阿里 223.5.5.5、114DNS 114.114.114.114），TCP 53 的 SYN 必有应答（SYN-ACK 或 RST 皆算可达），在国内线路比境外 DNS 稳定且不受 ICMP 限速影响。
fn default_probe_targets() -> Vec<SocketAddr> {
    vec![
        "223.5.5.5:53".parse().unwrap(),
        "114.114.114.114:53".parse().unwrap(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// 探测周期（毫秒），规范要求 500ms
    #[serde(default = "default_check_interval_ms")]
    pub check_interval_ms: u64,
    /// 单次探测超时（毫秒），不得超过探测周期
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    /// 滑动窗口长度，规范要求 10
    #[serde(default = "default_window_size")]
    pub window_size: usize,
    /// DOWN 丢包率阈值（窗口丢包率大于此值判 DOWN）
    #[serde(default = "default_loss_threshold_down")]
    pub loss_threshold_down: f64,
    /// 恢复 UP 的窗口丢包率上限；**当前仅作参考**（恢复判据只看 `recovery_success_count` 与 RTT），栏位保留仅为相容既有设定档。
    #[serde(default = "default_loss_threshold_up")]
    pub loss_threshold_up: f64,
    /// 降级丢包率阈值（预设 0.20，`0.0` = 关闭）：窗口已填满且丢包率 >= 此值即不参与 ECMP；实测介于 0.20 与 `loss_threshold_down`(0.50) 的线会照样吃一半流量。
    #[serde(default = "default_degrade_loss_threshold")]
    pub degrade_loss_threshold: f64,
    /// 降级退出的迟滞量（预设 0.10）：丢包率 <= `degrade_loss_threshold - 此值` 才退出降级，与进入门槛之间留出死区。
    /// 必须严格小于 `degrade_loss_threshold`（功能关闭时不比对）。
    #[serde(default = "default_degrade_hysteresis")]
    pub degrade_hysteresis: f64,
    /// 退出降级所需的**连续**样本数（预设 6）；任一笔不满足就归零重数。
    #[serde(default = "default_degrade_exit_samples")]
    pub degrade_exit_samples: usize,
    /// 进入降级所需的**连续样本数**（预设 20，≈2 个窗口）：把单一窗口的偶然抖动与持续劣化分开；设 1 = 旧行为。
    #[serde(default = "default_degrade_enter_samples")]
    pub degrade_enter_samples: usize,
    /// 降级后至少离开 ECMP 几个样本才准回来（预设 20，0 = 不限制），挡掉「移出→几秒后回来→又被打满」的数秒级循环。
    #[serde(default = "default_degrade_min_out_samples")]
    pub degrade_min_out_samples: usize,
    /// 连续超时次数触发 DOWN，规范要求 3 次
    #[serde(default = "default_consecutive_fail_down")]
    pub consecutive_fail_down: usize,
    /// 连续成功次数触发 UP 恢复（Hysteresis 防震荡），规范要求 5 次
    #[serde(default = "default_recovery_success_count")]
    pub recovery_success_count: usize,
    /// 最大容许 RTT（毫秒）
    #[serde(default = "default_max_rtt_ms")]
    pub max_rtt_ms: f64,
    /// 平滑 RTT 连续超标几次才判 DOWN（避免单一尖峰造成震荡）
    #[serde(default = "default_rtt_fail_count")]
    pub rtt_fail_count: usize,
    /// 线路 DOWN 时是否清理该网卡上的 conntrack
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_down: bool,
    /// 存活网卡集合变化时是否清理 conntrack：集合一变核心会重算 multipath hash，既有连线可能被改送而卡死，清掉才能立刻重建。
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_switch: bool,
    /// 同一张网卡两次 conntrack 清理之间的最小间隔（毫秒），防止链路抖动时反复全表 dump
    #[serde(default = "default_conntrack_flush_min_interval_ms")]
    pub conntrack_flush_min_interval_ms: u64,
    /// 下发到核心的预设路由 metric（RTA_PRIORITY），预设 0
    #[serde(default = "default_route_priority")]
    pub route_priority: u32,
    /// ECMP 实作方式（standard / auto / resilient），预设 **`auto`**。
    /// standard 的任何成员/权重变动都会重算整张 multipath hash，实测连坐搬走 40%~43% 的既有 flow；`auto` 有 nexthop object 时用 resilient，否则退回 standard。
    #[serde(default)]
    pub ecmp_mode: EcmpMode,
    /// resilient nexthop group 的空闲桶迁移时间（秒，预设 30，范围 1 ~ 3600）：
    /// 内核默认 120 秒过慢，导致负载偏移/线路恢复后数分钟内新流仍挤旧线；30 秒既保护活跃长连接不断线，又让空闲桶更快再均衡。
    #[serde(default = "default_resilient_idle_timer_secs")]
    pub resilient_idle_timer_secs: u32,
    /// resilient nexthop group 的不均衡强制迁移超时（秒，预设 60，范围 0 ~ 3600，0 = 不强制）：
    /// 仅靠 idle_timer 在持续大流量/测速场景下会导致活跃桶永远不迁移回刚恢复的 WAN；设置上限可确保在限定时间内恢复多线均衡。
    #[serde(default = "default_resilient_unbalanced_timer_secs")]
    pub resilient_unbalanced_timer_secs: u32,
    /// 优雅退出时是否移除本程式下发的预设路由（预设 **false**）：删掉唯一出口会在旧实例已退出、新实例未下发的窗口内把路由器打成离线。
    #[serde(default = "default_remove_routes_on_exit")]
    pub remove_routes_on_exit: bool,
    /// 启动时设定内核 `net.ipv{4,6}.fib_multipath_hash_policy`（预设 `l4`；明确写 `null` = 不写入）。变更需重启服务。
    /// 实测内核预设的 L3 会让同一目的 IP、只差来源埠的 24 条连线 100% 走同一条 WAN；`fib_multipath_hash_fields` 可写入但被内核忽略，有效开关是 policy。
    #[serde(default = "default_multipath_hash_policy")]
    pub multipath_hash_policy: Option<MultipathHashPolicy>,
    /// ECMP 权重模式：`static`（预设）或 `quality`（依 LQE 品质动态调整）
    #[serde(default)]
    pub weight_mode: WeightMode,
    /// 动态权重的最小更新间隔（毫秒，预设 10000，范围 1000 ~ 3600000）；每次更新都会重下 ECMP 路由。
    #[serde(default = "default_dynamic_weight_interval_ms")]
    pub dynamic_weight_interval_ms: u64,
    /// 动态权重的下修下限（比例，预设 0.25，范围 0.05 ~ 1.0）：品质再差也不会低于 `weight × 此值`。
    #[serde(default = "default_dynamic_weight_min_ratio")]
    pub dynamic_weight_min_ratio: f64,
    /// 负载感知分流（预设 false）：依实测速率与 `max_mbps`/`up_mbps` 算利用率，超过 `load_target_ratio` 就把 ECMP 权重往空闲线倾斜（纯流量面，节奏沿用 `dynamic_weight_interval_ms`）。
    #[serde(default)]
    pub load_aware: bool,
    /// 负载感知的触发门槛（预设 0.80，范围 (0, 1]）：利用率 >= 此值开始下修权重，必须大于 `load_recover_ratio`。
    #[serde(default = "default_load_target_ratio")]
    pub load_target_ratio: f64,
    /// 负载感知的退出门槛（预设 0.60）：利用率 <= 此值才恢复原权重，与触发门槛之间的死区即迟滞。
    #[serde(default = "default_load_recover_ratio")]
    pub load_recover_ratio: f64,
    /// 是否允许在 `standard` ECMP 下套用动态因子（quality / load_aware）（预设 false）。
    /// standard 下权重一变就重算整张 hash，实测 1:1→1:10 搬走 39%、1:10→1:2 搬走 24% 的既有 flow，却搬不动已建立的大流量；改 `resilient`/`auto` 即可生效。
    #[serde(default)]
    pub allow_dynamic_weights_on_standard: bool,
    /// 全局健康探测协议：`tcp`（预设，TCP SYN）或 `dns`（真实 UDP DNS 查询，防假通；不占用本地端口）。
    #[serde(default)]
    pub probe_mode: ProbeMode,
    /// `probe_mode = "dns"` 时查询的测试域名（预设 `baidu.com`）。
    #[serde(default = "default_dns_probe_domain")]
    pub dns_probe_domain: String,
    /// 可选内置轻量级多线 UDP DNS 转发器监听地址（预设 `127.0.0.1`）。仅在 `dns_listen_port > 0` 时启用。
    #[serde(default = "default_dns_listen_addr")]
    pub dns_listen_addr: String,
    /// 可选内置轻量级多线 UDP DNS 转发器监听端口（预设 `0` = 关闭，绝不默认占用 53 端口影响第三方 DNS 软件；可设为如 `5354` 供 AdGuardHome / SmartDNS / MosDNS 作上游）。
    #[serde(default)]
    pub dns_listen_port: u16,
    /// 内置 DNS 转发器单次上游查询超时（毫秒，预设 2000，范围 100 ~ 15000）。
    #[serde(default = "default_dns_forward_timeout_ms")]
    pub dns_forward_timeout_ms: u64,
    /// 可选的独立 resolv 输出路径（预设 `null` = 不写入任何文件，绝不覆盖 `/etc/resolv.conf` 或干扰第三方 DNS 软件）；
    /// 若显式填写如 `/tmp/mwan4_resolv.conf`，会在健康 WAN 的 `dns_servers` 变化时原子写入供第三方软件按需引用。
    #[serde(default)]
    pub dns_resolv_file: Option<String>,
    /// 来源/目的策略分流规则（选填）；匹配的转发流量走指定 WAN，目标 WAN DOWN 时回退 ECMP。
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    /// WAN 接口配置列表
    pub interfaces: Vec<InterfaceConfig>,
    /// 未知栏位（以 `_` 开头者视为注解）；validate() 会拒绝真正的拼字错误。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_check_interval_ms() -> u64 {
    1000
}
/// 单次探测超时必须小于探测周期，否则实际周期会被超时拖长；800ms 可容忍测速满载时的短时缓冲膨胀。
fn default_probe_timeout_ms() -> u64 {
    800
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
/// 预设 0.0（关闭）：测速满载时探针延迟抖动不应轻易将健康线路移出 ECMP（移出会导致带宽减半并中断既有 NAT 长连接）。
fn default_degrade_loss_threshold() -> f64 {
    0.0
}
/// 预设 0.10：若用户手动开启降级（如 0.20），退出门槛 = 门槛 - 迟滞。
fn default_degrade_hysteresis() -> f64 {
    0.10
}
/// 预设 6 次连续样本才准退出降级，挡掉单次侥幸。
fn default_degrade_exit_samples() -> usize {
    6
}
/// 预设 20 个连续样本（约 2 个窗口）超标才进入降级，把单一窗口的偶然抖动与持续劣化分开。
fn default_degrade_enter_samples() -> usize {
    20
}
/// 预设 20 拍的最短离开时间，挡掉「移出→几秒后回来」的数秒级循环。
fn default_degrade_min_out_samples() -> usize {
    20
}
fn default_consecutive_fail_down() -> usize {
    4
}
fn default_recovery_success_count() -> usize {
    3
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
/// 预设 false：删掉唯一一条预设路由会在重启窗口内让整台路由器失去出口。
fn default_remove_routes_on_exit() -> bool {
    false
}

/// 预设 `l4`：明确写 `null` 才是「不写入、沿用系统预设」。
fn default_multipath_hash_policy() -> Option<MultipathHashPolicy> {
    Some(MultipathHashPolicy::L4)
}

fn default_dns_probe_domain() -> String {
    "baidu.com".to_string()
}

fn default_dns_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_dns_forward_timeout_ms() -> u64 {
    2000
}

fn default_resilient_idle_timer_secs() -> u32 {
    30
}

fn default_resilient_unbalanced_timer_secs() -> u32 {
    60
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
            resilient_idle_timer_secs: default_resilient_idle_timer_secs(),
            resilient_unbalanced_timer_secs: default_resilient_unbalanced_timer_secs(),
            remove_routes_on_exit: default_remove_routes_on_exit(),
            multipath_hash_policy: default_multipath_hash_policy(),
            weight_mode: WeightMode::default(),
            dynamic_weight_interval_ms: default_dynamic_weight_interval_ms(),
            dynamic_weight_min_ratio: default_dynamic_weight_min_ratio(),
            load_aware: false,
            load_target_ratio: default_load_target_ratio(),
            load_recover_ratio: default_load_recover_ratio(),
            allow_dynamic_weights_on_standard: false,
            probe_mode: ProbeMode::default(),
            dns_probe_domain: default_dns_probe_domain(),
            dns_listen_addr: default_dns_listen_addr(),
            dns_listen_port: 0,
            dns_forward_timeout_ms: default_dns_forward_timeout_ms(),
            dns_resolv_file: None,
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
                    probe_mode: None,
                    dns_servers: Vec::new(),
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
                    probe_mode: None,
                    dns_servers: Vec::new(),
                    underlay_targets: Vec::new(),
                    extra: Default::default(),
                },
            ],
            extra: Default::default(),
        }
    }
}

impl DaemonConfig {
    /// 自动识别 JSON 或 OpenWrt UCI 配置文件格式加载并校验。
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: DaemonConfig = if crate::uci::looks_like_json(&content) {
            serde_json::from_str(&content)?
        } else {
            let doc = crate::uci::UciDocument::parse(&content)?;
            doc.to_daemon_config()?
        };
        config.validate()?;
        Ok(config)
    }

    /// 是否依最大频宽比例计算 ECMP 权重：只要有一条线设定了 `max_mbps`。
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
        // 逾时大于周期会让每个周期至少被阻塞 probe_timeout，实际探测节奏被拉长，事件回圈也无法处理讯号／link 事件。
        if self.probe_timeout_ms > self.check_interval_ms {
            return Err(format!(
                "probe_timeout_ms ({}) must not exceed check_interval_ms ({})",
                self.probe_timeout_ms, self.check_interval_ms
            ));
        }
        // 以 `_` 开头的未知栏位视为注解，其余多半是拼字错误，宁可启动前大声失败。
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
        // `1e999` 会被 serde_json 解析成 +inf：`inf <= 0.0` 为 false 会通过检查，等于静默关闭 RTT 判据。
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
        // 1 = 旧行为（单次达标即降级），上限只是防呆。
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
        // 降级门槛必须严格低于判死门槛，否则会「先降级、下一秒判 DOWN」（0.0 = 关闭降级时不比对）。
        if self.degrade_loss_threshold > 0.0
            && self.degrade_loss_threshold >= self.loss_threshold_down
        {
            return Err(format!(
                "degrade_loss_threshold ({}) must be less than loss_threshold_down ({})",
                self.degrade_loss_threshold, self.loss_threshold_down
            ));
        }
        // 迟滞量必须严格小于降级门槛，否则退出门槛会 <= 0（永远退不出降级）或等于进入门槛（等于没有迟滞）。
        if self.degrade_loss_threshold > 0.0
            && self.degrade_hysteresis >= self.degrade_loss_threshold
        {
            return Err(format!(
                "degrade_hysteresis ({}) must be less than degrade_loss_threshold ({})",
                self.degrade_hysteresis, self.degrade_loss_threshold
            ));
        }

        if !(1..=3600).contains(&self.resilient_idle_timer_secs) {
            return Err(format!(
                "resilient_idle_timer_secs {} out of range (1 ~ 3600)",
                self.resilient_idle_timer_secs
            ));
        }
        if self.resilient_unbalanced_timer_secs > 3600 {
            return Err(format!(
                "resilient_unbalanced_timer_secs {} out of range (0 ~ 3600)",
                self.resilient_unbalanced_timer_secs
            ));
        }
        crate::dns::validate_dns_domain(&self.dns_probe_domain)?;
        if self.dns_listen_addr.parse::<IpAddr>().is_err() {
            return Err(format!(
                "dns_listen_addr '{}' is not a valid IP address",
                self.dns_listen_addr
            ));
        }
        if !(100..=15_000).contains(&self.dns_forward_timeout_ms) {
            return Err(format!(
                "dns_forward_timeout_ms {} out of range (100 ~ 15000)",
                self.dns_forward_timeout_ms
            ));
        }
        if let Some(ref path) = self.dns_resolv_file {
            if path.is_empty() || !path.starts_with('/') || path.contains('\0') {
                return Err(format!(
                    "dns_resolv_file '{path}' must be a valid absolute file path"
                ));
            }
            if Path::new(path)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "dns_resolv_file '{path}' must not contain '..' path traversal"
                ));
            }
        }

        let mut seen = std::collections::HashSet::new();
        for iface in &self.interfaces {
            if iface.name.is_empty() {
                return Err("Interface name cannot be empty".into());
            }
            // 名称会用在 /proc、/sys 路径：含 '/' 会造成路径穿越，过长则 if_nametoindex 永远失败
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
            // 容量必须是有限正数：0 或 inf 会让利用率永远 0／NaN，容量比例分流也失去意义。
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
            // 启用负载感知却没填最大频宽：演算法无从判定过载，宁可启动前失败。
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
            for dns in &iface.dns_servers {
                if dns.ip.is_unspecified()
                    || dns.ip.is_loopback()
                    || dns.ip.is_multicast()
                    || dns.ip.is_broadcast()
                {
                    return Err(format!(
                        "Interface {} dns_server {dns} is not a usable unicast IPv4 address",
                        iface.name
                    ));
                }
                if dns.port == 0 {
                    return Err(format!(
                        "Interface {} dns_server {dns} has port 0",
                        iface.name
                    ));
                }
            }
            // 路由模组只支援 IPv4，给了 IPv6 目标只会永远连不上
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

        // 容量比例分流是整组权重按最大频宽缩放，只给部分线容量会让比例无从定义。
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
        assert_eq!(parsed.check_interval_ms, 1000);
        assert_eq!(parsed.probe_timeout_ms, 800);
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
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.degrade_enter_samples, 20);
        assert_eq!(cfg.degrade_min_out_samples, 20);
        assert!(cfg.validate().is_ok());

        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.degrade_enter_samples, 20);
        assert_eq!(old.degrade_min_out_samples, 20);

        let explicit: DaemonConfig = serde_json::from_str(
            r#"{"degrade_enter_samples":1,"degrade_min_out_samples":0,
                "interfaces":[{"name":"wan1"}]}"#,
        )
        .unwrap();
        assert_eq!(explicit.degrade_enter_samples, 1);
        assert_eq!(explicit.degrade_min_out_samples, 0);
        assert!(explicit.validate().is_ok());

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
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_loss_threshold - 0.0).abs() < f64::EPSILON);
        assert!(cfg.validate().is_ok());

        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_loss_threshold - 0.0).abs() < f64::EPSILON);

        let mut too_big = DaemonConfig::default();
        too_big.degrade_loss_threshold = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_loss_threshold = -0.1;
        assert!(negative.validate().is_err());

        let mut enabled = DaemonConfig::default();
        enabled.degrade_loss_threshold = 0.20;
        assert!(enabled.validate().is_ok());

        let mut not_less = DaemonConfig::default();
        not_less.degrade_loss_threshold = 0.5;
        assert!(not_less.validate().is_err());

        let mut just_below = DaemonConfig::default();
        just_below.degrade_loss_threshold = 0.49;
        assert!(just_below.validate().is_ok());
    }

    #[test]
    fn test_degrade_hysteresis_defaults_and_validation() {
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.degrade_exit_samples, 6);
        assert!(cfg.validate().is_ok());

        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(old.degrade_exit_samples, 6);

        let mut too_big = DaemonConfig::default();
        too_big.degrade_hysteresis = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_hysteresis = -0.1;
        assert!(negative.validate().is_err());

        let mut zero_samples = DaemonConfig::default();
        zero_samples.degrade_exit_samples = 0;
        assert!(zero_samples.validate().is_err());

        let mut equal = DaemonConfig::default();
        equal.degrade_loss_threshold = 0.20;
        equal.degrade_hysteresis = 0.20;
        assert!(equal.validate().is_err());

        let mut greater = DaemonConfig::default();
        greater.degrade_loss_threshold = 0.20;
        greater.degrade_hysteresis = 0.30;
        assert!(greater.validate().is_err());

        let mut just_below = DaemonConfig::default();
        just_below.degrade_loss_threshold = 0.20;
        just_below.degrade_hysteresis = 0.19;
        assert!(just_below.validate().is_ok());

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
        assert!(!DaemonConfig::default().remove_routes_on_exit);
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.remove_routes_on_exit);
    }

    #[test]
    fn test_ecmp_mode_default_and_parsing() {
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

        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"ecmp_mode":"bogus","interfaces":[{"name":"wan1"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn test_multipath_hash_policy_parsing_and_values() {
        let bare: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(bare.multipath_hash_policy, Some(MultipathHashPolicy::L4));
        assert_eq!(
            DaemonConfig::default().multipath_hash_policy,
            Some(MultipathHashPolicy::L4)
        );
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

    /// 位元值取自 Linux 6.12+ `include/net/ip_fib.h` UAPI，并与 `src/main.rs` 的 L3/L4 遮罩常数一致。
    #[test]
    fn test_hash_field_bits_match_kernel_uapi() {
        assert_eq!(HashField::SrcIp.bit(), 1);
        assert_eq!(HashField::DstIp.bit(), 2);
        assert_eq!(HashField::IpProto.bit(), 4);
        assert_eq!(HashField::FlowLabel.bit(), 8);
        assert_eq!(HashField::SrcPort.bit(), 16);
        assert_eq!(HashField::DstPort.bit(), 32);
        assert_eq!(HashField::InnerSrcIp.bit(), 64);
        assert_eq!(HashField::InnerDstIp.bit(), 128);
        assert_eq!(HashField::InnerIpProto.bit(), 256);
        assert_eq!(HashField::InnerFlowLabel.bit(), 512);
        assert_eq!(HashField::InnerSrcPort.bit(), 1024);
        assert_eq!(HashField::InnerDstPort.bit(), 2048);
        assert_eq!(HashField::SrcPort.as_str(), "src_port");
        assert_eq!(HashField::InnerDstPort.as_str(), "inner_dst_port");
    }

    #[test]
    fn test_weight_mode_and_dynamic_weight_validation() {
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
        let cfg = DaemonConfig::default();
        assert!(!cfg.load_aware);
        assert!((cfg.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!((cfg.load_recover_ratio - 0.60).abs() < f64::EPSILON);
        assert_eq!(cfg.interfaces[0].max_mbps, None);
        assert_eq!(cfg.interfaces[0].up_mbps, None);
        assert!(!cfg.capacity_weights_on());
        assert!(cfg.validate().is_ok());

        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.load_aware);
        assert!((old.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!(old.validate().is_ok());

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
        assert_eq!(ok.interfaces[1].up_mbps, None);

        let aliased: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[
                {"name":"wan1","down_mbps":1000},
                {"name":"wan2","down_mbps":500}]}"#,
        )
        .unwrap();
        assert_eq!(aliased.interfaces[0].max_mbps, Some(1000.0));
        assert!(aliased.validate().is_ok());

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

        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"load_aware":true,"interfaces":[{"name":"wan1","max_mbps":1e999}]}"#
            )
            .is_err()
        );

        let partial: DaemonConfig = serde_json::from_str(
            r#"{"interfaces":[{"name":"wan1","max_mbps":1000},{"name":"wan2"}]}"#,
        )
        .unwrap();
        assert!(
            partial.validate().is_err(),
            "部分线才有 max_mbps 必须被挡下"
        );

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

        let expanded: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"multi",
                "source":["192.168.3.0/24","192.168.4.0/24"],
                "destination":["10.0.0.0/8","172.16.0.0/12"],
                "interface":"wan1"}}],{base}}}"#
        ))
        .unwrap();
        assert!(expanded.validate().is_ok());

        let unknown: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"x","interface":"wan9"}}],{base}}}"#
        ))
        .unwrap();
        assert!(unknown.validate().is_err());

        for bad in ["192.168.3.0", "192.168.3.0/33", "300.1.1.1/24"] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"policies":[{{"name":"x","source":["{bad}"],"interface":"wan1"}}],{base}}}"#
            ))
            .unwrap();
            assert!(cfg.validate().is_err(), "should reject source {bad}");
        }

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

        let sources: Vec<String> = (0..70).map(|i| format!("\"10.{i}.0.0/16\"")).collect();
        let too_many: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"big","source":[{}],"interface":"wan1"}}],{base}}}"#,
            sources.join(",")
        ))
        .unwrap();
        assert!(too_many.validate().is_err());

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

    #[test]
    fn test_dns_config_defaults_and_validation() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.probe_mode, ProbeMode::Tcp);
        assert_eq!(cfg.dns_probe_domain, "baidu.com");
        assert_eq!(cfg.dns_resolv_file, None);
        assert!(cfg.interfaces[0].dns_servers.is_empty());
        assert_eq!(cfg.interfaces[0].probe_mode, None);
        assert!(cfg.validate().is_ok());

        // 兼容旧配置（不含新 DNS 字段）
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.probe_mode, ProbeMode::Tcp);
        assert_eq!(old.dns_probe_domain, "baidu.com");
        assert_eq!(old.dns_resolv_file, None);
        assert!(old.validate().is_ok());

        // 合法 DNS 探测、自定义端口与路由绑定配置
        let ok: DaemonConfig = serde_json::from_str(
            r#"{
                "probe_mode": "dns",
                "dns_probe_domain": "www.baidu.com",
                "dns_listen_addr": "127.0.0.1",
                "dns_listen_port": 5354,
                "dns_forward_timeout_ms": 1500,
                "dns_resolv_file": "/tmp/mwan4_resolv.conf",
                "interfaces": [
                    {"name": "wan1", "probe_mode": "tcp", "dns_servers": ["202.96.128.86"]},
                    {"name": "wan2", "dns_servers": ["221.6.4.66:5353", "223.5.5.5"]}
                ]
            }"#,
        )
        .unwrap();
        assert!(ok.validate().is_ok());
        assert_eq!(ok.probe_mode, ProbeMode::Dns);
        assert_eq!(ok.dns_listen_port, 5354);
        assert_eq!(ok.interfaces[0].probe_mode, Some(ProbeMode::Tcp));
        assert_eq!(ok.interfaces[0].dns_servers[0].port, 53);
        assert_eq!(ok.interfaces[1].dns_servers[0].port, 5353);
        assert_eq!(
            ok.interfaces[1].dns_servers[0].to_string(),
            "221.6.4.66:5353"
        );
        assert_eq!(ok.interfaces[1].dns_servers[1].to_string(), "223.5.5.5");

        // 非法端口 0 与非法监听地址
        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"interfaces":[{"name":"wan1","dns_servers":["223.5.5.5:0"]}]}"#
            )
            .is_err()
        );
        let mut bad_listen = DaemonConfig::default();
        bad_listen.dns_listen_addr = "not-an-ip".into();
        assert!(bad_listen.validate().is_err());
        let mut bad_timeout = DaemonConfig::default();
        bad_timeout.dns_forward_timeout_ms = 50;
        assert!(bad_timeout.validate().is_err());

        // 非法域名
        let mut bad_domain = DaemonConfig::default();
        bad_domain.dns_probe_domain = "-invalid..domain".into();
        assert!(bad_domain.validate().is_err());

        // 非法 resolv 路径（相对路径或路径穿越）
        for bad_path in ["", "relative/resolv.conf", "/tmp/../etc/resolv.conf"] {
            let mut bad = DaemonConfig::default();
            bad.dns_resolv_file = Some(bad_path.into());
            assert!(bad.validate().is_err(), "should reject path '{bad_path}'");
        }

        // 非法 DNS 服务器地址（0.0.0.0 / loopback / multicast / broadcast）
        for bad_ip in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            let mut bad = DaemonConfig::default();
            bad.interfaces[0].dns_servers = vec![DnsServer::new(bad_ip, 53)];
            assert!(bad.validate().is_err(), "should reject dns {bad_ip}");
        }
    }
}
