use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// ECMP 權重上限。
///
/// 標準 multipath 的 `rtnh_hops` 可表達 weight-1 = 255（權重 256），但 resilient
/// nexthop group 的 `struct nexthop_grp.weight` 在 Linux < 6.9 只允許 ≤ 254
/// （weight_high 是 6.9 才加入），設 256 會讓 `RTM_NEWNEXTHOP` 回 EINVAL、
/// resilient 直接失效。統一上限設 255，兩種模式與所有內核版本行為一致。
pub const MAX_WEIGHT: u32 = 255;

/// 滑動窗口上限：過大的窗口會讓低記憶體裝置在啟動時一次預分配過大緩衝，
/// 也會拖慢每次樣本更新。1024 個樣本 @500ms 已足夠覆蓋 8 分鐘的歷史。
pub const MAX_WINDOW_SIZE: usize = 1024;

/// 網卡名稱長度上限（Linux IFNAMSIZ - 1）
pub const MAX_IFNAME_LEN: usize = 15;

/// 探測週期上限（毫秒）：1 小時。避免手寫設定把節奏調到近乎停止。
pub const MAX_CHECK_INTERVAL_MS: u64 = 3_600_000;

/// 多 WAN 等價路徑（ECMP）的實作方式。
///
/// - `standard`：單一 multipath 路由（RTA_MULTIPATH）。nexthop 集合一變
///   （含線路恢復 UP 加入新成員），核心會重算整條路由的 multipath hash，
///   既有 flow 可能被改送到另一條 WAN、源 IP 改變而斷線。
/// - `resilient`：改用 resilient nexthop group（Linux 5.14+）。集合變動時核心
///   只重新分配「故障成員」佔用的 bucket，其餘 flow 保持粘滯、不會斷線。
/// - `auto`：優先用 resilient，核心不支援時自動退回 standard 並記住結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EcmpMode {
    #[default]
    Standard,
    Auto,
    Resilient,
}

/// 內核多路徑（ECMP）哈希策略。
///
/// 寫入 `net.ipv{4,6}.fib_multipath_hash_policy`：
/// - `l3`：只哈希來源/目的 IP。flow 數少（例如同一個 NAT 閘道下的多個連線）
///   容易全部落到同一條 WAN；
/// - `l4`（內核預設）：再加上 L4 來源/目的埠，分流最均勻，一般建議值；
/// - `inner`：L3 + 隧道內層標頭（VXLAN/GRE 等封裝流量的內層五元組）。
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

/// ECMP 權重模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WeightMode {
    /// 固定使用介面的 `weight`（預設，行為與舊版一致）
    #[default]
    Static,
    /// 依 LQE 實測品質動態調整權重：丟包與 RTT 較差的線少分流量，
    /// 品質恢復後自動回到設定的 `weight`。變更會重下 ECMP 路由（有限速）。
    Quality,
}

/// 一條來源/目的策略分流規則。
///
/// 以 `ip rule` 的 `from`/`to` + 該 WAN 的獨立路由表實現：匹配的**轉發流量**
/// 走指定 WAN，其餘流量仍走 ECMP 預設路由。刻意不用 fwmark／nftables，
/// 與本專案「轉發面零封包標記」的架構一致。
///
/// 目標 WAN 被判 DOWN 時，規則會被暫時移除，流量自動回退到 ECMP。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// 規則名稱（顯示與日誌用；必須唯一）
    pub name: String,
    /// 來源前綴（CIDR，例如 "192.168.3.0/24"）。空清單 = 不限制來源
    #[serde(default)]
    pub source: Vec<String>,
    /// 目的前綴（CIDR）。空清單 = 不限制目的
    #[serde(default)]
    pub destination: Vec<String>,
    /// 目標 WAN 介面名稱（必須是 `interfaces` 之一）
    pub interface: String,
    /// 規則優先序（選填）。預設依 `policies` 陣列順序從
    /// `POLICY_RULE_PRIORITY_BASE` 起算；數字越小越先匹配
    #[serde(default)]
    pub priority: Option<u32>,
    /// 未知欄位（以 `_` 開頭者視為註解）
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// 解析 `a.b.c.d/prefix` 形式的 IPv4 前綴（允許 /0 ~ /32）。
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
    /// 網卡名稱，例如 "wan1", "wan2", "eth0"
    pub name: String,
    /// 網關 IP 地址，例如 "192.168.1.1"（點對點/WireGuard/PPPoE 無需網關，可為 None 或 0.0.0.0）
    #[serde(default)]
    pub gateway: Option<Ipv4Addr>,
    /// IPv6 網關地址（選填）。設定後會隨該網卡的 IPv4 健康狀態一併下發 ::/0 預設路由
    #[serde(default)]
    pub gateway6: Option<Ipv6Addr>,
    /// 路由優先級 Metric（預設 1）
    #[serde(default = "default_metric")]
    pub metric: u32,
    /// ECMP 多路路由權重（預設 1，合法範圍 1~255）
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 這條線的**最大頻寬**（Mbps）。有設定時，ECMP 基準權重會自動改成
    /// ∝ `weight × max_mbps`（容量比例分流），也作為下行（WAN 入口）方向的容量；
    /// 啟用 `load_aware` 時必填。JSON 也接受舊名 `down_mbps`。
    #[serde(default, alias = "down_mbps")]
    pub max_mbps: Option<f64>,
    /// 上行（WAN 出口）頻寬上限（Mbps）；未設定時沿用 `max_mbps`。
    /// 非對稱線路（例如 1000/50）才需要填。
    #[serde(default)]
    pub up_mbps: Option<f64>,
    /// 探測目標地址列表（TCP SYN 探測 IP:Port），如 ["223.5.5.5:53", "114.114.114.114:53"]
    #[serde(default = "default_probe_targets")]
    pub probe_targets: Vec<SocketAddr>,
    /// 隧道型 WAN 的 underlay 對端位址（選填）。
    ///
    /// VXLAN 的 remote、WireGuard 的 endpoint 這類「封裝封包真正要去的地方」，
    /// 必須經由**其他** WAN（非隧道的那條）抵達。若放任它們走 ECMP 預設路由，
    /// 就有約 1/N 的機率被塞回這條隧道自己 —— 封裝封包進隧道、隧道再封裝，形成自環。
    ///
    /// 實測（VXLAN 當第二條線、與 eth1 組成雙線 ECMP）：設成 resilient 後隧道立刻
    /// 丟包 60% 並被判 DOWN，`ip route get <對端>` 卻仍顯示正確的那條
    /// （它只反映固定哈希的單次採樣，會騙人）。
    ///
    /// 設了這個欄位後，守護進程會在 main 表為每個位址補一條 /32
    /// （前綴比預設路由長，必然優先），固定走「非隧道、metric 最小」的那條 WAN。
    #[serde(default)]
    pub underlay_targets: Vec<Ipv4Addr>,
    /// 未知欄位（以 `_` 開頭者視為註解）。validate() 會拒絕真正的拼字錯誤。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_metric() -> u32 {
    1
}

fn default_weight() -> u32 {
    1
}

/// 預設探測目標：大陸地區公共 DNS（阿里 223.5.5.5、114DNS 114.114.114.114）。
///
/// 兩者都監聽 TCP 53，SYN 必有應答（SYN-ACK 或 RST 都算鏈路可達），比境外
/// 1.1.1.1 / 8.8.8.8 在國內線路上穩定；且 TCP 探針不受 ICMP 限速影響。
fn default_probe_targets() -> Vec<SocketAddr> {
    vec![
        "223.5.5.5:53".parse().unwrap(),
        "114.114.114.114:53".parse().unwrap(),
    ]
}

/// 守護進程全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// 探測週期（毫秒），規範要求 500ms
    #[serde(default = "default_check_interval_ms")]
    pub check_interval_ms: u64,
    /// 單次探測超時時間（毫秒），應小於或等於探測週期
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    /// 滑動窗口長度，規範要求 10
    #[serde(default = "default_window_size")]
    pub window_size: usize,
    /// DOWN 丟包率閾值（窗口丟包率大於此值視為 DOWN），規範要求 > 50%
    #[serde(default = "default_loss_threshold_down")]
    pub loss_threshold_down: f64,
    /// 恢復 UP 所需的窗口丟包率上限。
    ///
    /// **當前僅作參考**：恢復判據已改為只看 `recovery_success_count` 與 RTT（見 `lqe.rs`）。
    /// 這個門檻與 window_size 耦合，在 window=10、0.10 時等於「窗口內最多 1 次失敗」，
    /// 會把 `recovery_success_count` 靜默抬高（設定 5 實際要 9 次連續成功），
    /// 造成 DOWN 快、UP 慢的反覆翻轉。欄位保留是為了相容既有設定檔（刪掉會讓舊設定檔
    /// 以 serde 錯誤拒絕啟動），範圍仍由 `validate()` 檢查。
    #[serde(default = "default_loss_threshold_up")]
    pub loss_threshold_up: f64,
    /// 降級丟包率閾值（預設 0.20 = 20%；`0.0` = 關閉此功能，沿用舊行為）。
    ///
    /// 語意：滑動窗口**已填滿**且窗口丟包率 >= 此值時，該線路「降級」= 不參與 ECMP
    /// （但仍繼續探測，品質恢復後自動回歸）。
    /// 為什麼需要：介於此值與 `loss_threshold_down`（預設 0.50）之間的線路不會被判 DOWN，
    /// 於是照樣吃一半流量——實測注入 20% 丟包時主表仍是兩條 nexthop 的 ECMP，
    /// 使用者感受就是「有雙網卡時經常檢查到丟包」。
    #[serde(default = "default_degrade_loss_threshold")]
    pub degrade_loss_threshold: f64,
    /// 降級退出的遲滯量（預設 0.10）。
    ///
    /// 語意：**退出**降級需要窗口丟包率 <= `degrade_loss_threshold - degrade_hysteresis`
    /// （預設即 <= 0.10），與進入門檻（>= 0.20，預設）之間留出一段死區。
    ///
    /// 為什麼需要：窗口長度 10 的量化步長是 10%（1 次失敗 = 10%），注入 12%~30% 丟包時
    /// 窗口丟包率恰好會在 10% / 20% / 30% 之間擺動。單一門檻下 `is_degraded()` 每幾秒
    /// 就進出一次，每次都觸發 `Active WAN set changed` 並重下 ECMP 路由
    /// （實測 20 秒內 5~6 次，路由成員抖動）。遲滯讓「剛降級」的線必須明顯變好才准回來。
    ///
    /// 必須嚴格小於 `degrade_loss_threshold`（功能關閉時不比對）。
    #[serde(default = "default_degrade_hysteresis")]
    pub degrade_hysteresis: f64,
    /// 退出降級所需的**連續**樣本數（預設 6）。
    ///
    /// 任一筆不滿足退出條件就把累積次數歸零重數：避免「剛好有一拍量到 0%」這種單次僥倖
    /// 就讓線路回到 ECMP，下一秒又被踢出去。
    #[serde(default = "default_degrade_exit_samples")]
    pub degrade_exit_samples: usize,
    /// 連續超時次數觸發 DOWN，規範要求 3 次
    #[serde(default = "default_consecutive_fail_down")]
    pub consecutive_fail_down: usize,
    /// 連續成功次數觸發 UP 恢復（Hysteresis 防震盪），規範要求 5 次
    #[serde(default = "default_recovery_success_count")]
    pub recovery_success_count: usize,
    /// 最大容許 RTT（毫秒），超過視為異常
    #[serde(default = "default_max_rtt_ms")]
    pub max_rtt_ms: f64,
    /// 平滑 RTT 連續超標幾次才判定 DOWN（避免單一尖峰造成震盪）
    #[serde(default = "default_rtt_fail_count")]
    pub rtt_fail_count: usize,
    /// 當線路 DOWN 時，是否清理該網卡上的 conntrack 連接
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_down: bool,
    /// 當存活網卡集合變化時（例如主線路恢復、ECMP 成員進出）是否清理 conntrack。
    /// ECMP 的 nexthop 集合一變，核心會重算 multipath hash，
    /// 既有連線可能被改送到另一條 WAN 而卡死，清掉才能立刻重建。
    #[serde(default = "default_flush_conntrack")]
    pub flush_conntrack_on_switch: bool,
    /// 同一張網卡兩次 conntrack 清理之間的最小間隔（毫秒），防止鏈路抖動時反覆全表 dump
    #[serde(default = "default_conntrack_flush_min_interval_ms")]
    pub conntrack_flush_min_interval_ms: u64,
    /// 下發到核心的預設路由 metric（RTA_PRIORITY），預設 0
    #[serde(default = "default_route_priority")]
    pub route_priority: u32,
    /// ECMP 實作方式（standard / auto / resilient），預設 standard。
    /// 想要「線路切換時既有連線不被 ECMP 重哈希打斷」請設為 resilient 或 auto。
    #[serde(default)]
    pub ecmp_mode: EcmpMode,
    /// 優雅退出時是否移除本程式下發的預設路由（預設 **false**）。
    ///
    /// 預設改為 false 的原因：預設路由是本機（含所有 LAN 客戶端）唯一的出口，
    /// 服務重啟／套件升級／`uci commit` 觸發 reload 時刪掉它，會在「舊實例已退出、
    /// 新實例還沒下發」的窗口內把整台路由器打成離線；若新實例啟動失敗，更是永久斷網。
    /// 需要「退出即清乾淨」的部署再明確設為 true。
    #[serde(default = "default_remove_routes_on_exit")]
    pub remove_routes_on_exit: bool,
    /// 選填：啟動時設定內核 `net.ipv{4,6}.fib_multipath_hash_policy`。
    /// 不設定 = 沿用系統預設（多數發行版為 `l4`）。變更需重啟服務。
    #[serde(default)]
    pub multipath_hash_policy: Option<MultipathHashPolicy>,
    /// ECMP 權重模式：`static`（預設）或 `quality`（依 LQE 品質動態調整）
    #[serde(default)]
    pub weight_mode: WeightMode,
    /// 動態權重的最小更新間隔（毫秒，預設 10000，範圍 1000 ~ 3600000）。
    /// 每次更新都會重下 ECMP 路由（內核可能重算 multipath hash），因此必須限速。
    #[serde(default = "default_dynamic_weight_interval_ms")]
    pub dynamic_weight_interval_ms: u64,
    /// 動態權重的下修下限（比例，預設 0.25，範圍 0.05 ~ 1.0）：
    /// 品質再差也不會低於 `weight × 此值`（真正不可用的線由降級/DOWN 機制移出）。
    #[serde(default = "default_dynamic_weight_min_ratio")]
    pub dynamic_weight_min_ratio: f64,
    /// 負載感知分流（預設 false）。
    ///
    /// 啟用後，守護進程會依每條 WAN 的實測速率（tx_bps / rx_bps 的 EWMA）與
    /// `interfaces[].max_mbps` / `up_mbps` 算出利用率；當**某條線**的利用率
    /// 超過 `load_target_ratio`，就在下一次動態權重更新時把它與其他線的 ECMP
    /// 權重比例往「空閒線」傾斜，把部分 flow 轉移過去。
    ///
    /// 純流量面：不新增路由、不碰 conntrack，只調整既有 ECMP 的權重比例。
    /// 更新節奏沿用 `dynamic_weight_interval_ms`（每次都是一次 RTM_NEWROUTE）。
    #[serde(default)]
    pub load_aware: bool,
    /// 負載感知的觸發門檻（預設 0.80）：利用率 >= 此值視為「過載」，開始下修權重。
    ///
    /// 必須大於 `load_recover_ratio`。範圍 (0, 1]。
    #[serde(default = "default_load_target_ratio")]
    pub load_target_ratio: f64,
    /// 負載感知的退出門檻（預設 0.60）：利用率 <= 此值時壓力才完全解除。
    ///
    /// 與觸發門檻之間的死區就是遲滯：被下修過的線必須低於此值才恢復原權重，
    /// 藉此避免「下修→流量移走→立刻恢復→流量又回來」的控制迴圈震盪。
    #[serde(default = "default_load_recover_ratio")]
    pub load_recover_ratio: f64,
    /// 來源/目的策略分流規則（選填；見 `PolicyConfig`）。
    /// 匹配的轉發流量走指定 WAN，其餘仍走 ECMP；目標 WAN DOWN 時自動回退 ECMP。
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    /// WAN 接口配置列表
    pub interfaces: Vec<InterfaceConfig>,
    /// 未知欄位（以 `_` 開頭者視為註解）。validate() 會拒絕真正的拼字錯誤。
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_check_interval_ms() -> u64 {
    500
}
/// 單次探測超時必須小於探測週期，否則實際週期會被超時拖長
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
/// 預設 0.20：介於「可接受」與 `loss_threshold_down`(0.50) 之間的線路不該再吃一半流量。
/// 0.0 = 關閉（沿用「只要沒判 DOWN 就照常承載」的舊行為）。
fn default_degrade_loss_threshold() -> f64 {
    0.20
}
/// 預設 0.10：退出門檻 = 0.20 - 0.10 = 0.10，與進入門檻（0.20）之間形成死區，
/// 讓「窗口丟包率在 10%/20% 之間擺動」的線不會每幾秒進出一次降級。
fn default_degrade_hysteresis() -> f64 {
    0.10
}
/// 預設 6 次連續樣本（≈3 秒）才准退出降級，擋掉單次僥倖。
fn default_degrade_exit_samples() -> usize {
    6
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
/// 預設 false：見 `remove_routes_on_exit` 的說明。刪掉唯一一條預設路由
/// 會在重啟窗口內讓整台路由器失去出口（且新實例失敗時無法自行恢復）。
fn default_remove_routes_on_exit() -> bool {
    false
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
            multipath_hash_policy: None,
            weight_mode: WeightMode::default(),
            dynamic_weight_interval_ms: default_dynamic_weight_interval_ms(),
            dynamic_weight_min_ratio: default_dynamic_weight_min_ratio(),
            load_aware: false,
            load_target_ratio: default_load_target_ratio(),
            load_recover_ratio: default_load_recover_ratio(),
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

    /// 是否依最大頻寬比例計算 ECMP 權重：只要有一條線設定了 `max_mbps`。
    /// `validate()` 已保證「要嘛全填、要嘛全不填」，因此任一即可代表全部。
    pub fn capacity_weights_on(&self) -> bool {
        self.interfaces.iter().any(|i| i.max_mbps.is_some())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.interfaces.is_empty() {
            return Err("At least one WAN interface must be configured".into());
        }
        // 每張 WAN 會佔用一個探針 slot（獨立表＋oif 規則），slot 數有上限
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
        // 逾時大於週期會讓每個週期至少被阻塞 probe_timeout，實際探測節奏被拉長，
        // 且期間事件迴圈無法處理訊號／link 事件。舊版只在啟動時 warn，這裡直接擋。
        if self.probe_timeout_ms > self.check_interval_ms {
            return Err(format!(
                "probe_timeout_ms ({}) must not exceed check_interval_ms ({})",
                self.probe_timeout_ms, self.check_interval_ms
            ));
        }
        // 未知欄位：`_comment` 之類以 `_` 開頭者視為註解，其餘多半是拼字錯誤，
        // 寧可啟動前大聲失敗，也不要默默用預設值跑整個生命週期。
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
        // `1e999` 會被 serde_json 解析成 +inf：`inf <= 0.0` 為 false 會通過檢查，
        // 之後所有 RTT 都「不超標」，等於靜默關閉 RTT 判據。
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
        // 降級門檻必須嚴格低於判死門檻：否則會出現「先降級、下一秒就判 DOWN」的
        // 自相矛盾設定（降級的意義就是「還有救、只是別再吃流量」）。
        // 0.0 = 關閉降級功能，此時不與判死門檻比較。
        if self.degrade_loss_threshold > 0.0
            && self.degrade_loss_threshold >= self.loss_threshold_down
        {
            return Err(format!(
                "degrade_loss_threshold ({}) must be less than loss_threshold_down ({})",
                self.degrade_loss_threshold, self.loss_threshold_down
            ));
        }
        // 遲滯量必須嚴格小於降級門檻：否則退出門檻（門檻 - 遲滯）會落在 0 以下或等於進入門檻，
        // 前者永遠退不出降級（線路被判 UP 卻永遠不參與 ECMP），後者等於沒有遲滯。
        // 0.0 = 關閉降級功能，此時不比對。
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
            // 名稱會用在 /proc、/sys 路徑與 IFNAMSIZ 限制上：含 '/' 會造成路徑穿越，
            // 過長則 if_nametoindex 永遠失敗
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
            // 容量（最大頻寬）必須是有限正數：0 或 inf 會讓利用率永遠是 0／NaN，
            // 容量比例分流也會退化成無意義的比例。
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
            // 啟用負載感知卻沒填最大頻寬：演算法既無法按容量比例分流，
            // 也無從判定過載，寧可啟動前大聲失敗，也不要默默照舊分流。
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
            // 路由模組只支援 IPv4，若給了 IPv6 目標只會永遠連不上
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

        // 容量比例分流是「整組權重按最大頻寬縮放」，只給部分線容量會讓比例無從定義。
        // 要嘛全部都填 max_mbps、要嘛全部不填（load_aware 已在迴圈內強制全部要填）。
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

        // 動態權重參數
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

        // 負載感知門檻：目標必須在 (0,1]，且嚴格大於恢復門檻（兩者之間才是遲滯死區）。
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

        // 策略分流規則：名稱/目標/前綴/優先序/展開後的條數
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
    // 測試裡「先取預設值、再改一兩個欄位」比整包 struct literal 清楚得多，
    // 尤其只需要動 interfaces[0].weight 這類巢狀欄位時。
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
        assert_eq!(got, want, "預設探測目標應為大陸公共 DNS（TCP 53）");
        assert!(cfg.validate().is_ok());

        // 舊設定檔省略 probe_targets 時也必須拿到同一組預設，不能退回境外 DNS
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

        // 過大的窗口必須被擋下，避免低記憶體裝置啟動時超大預分配
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
    fn test_degrade_loss_threshold_defaults_and_validation() {
        // 預設 0.20：介於「可接受」與判死(0.50)之間
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_loss_threshold - 0.20).abs() < f64::EPSILON);
        assert!(cfg.validate().is_ok());

        // 舊設定檔沒有這個欄位時，必須拿到預設值而不是 0（=關閉），否則升級後行為會倒退
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_loss_threshold - 0.20).abs() < f64::EPSILON);

        // 範圍檢查
        let mut too_big = DaemonConfig::default();
        too_big.degrade_loss_threshold = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_loss_threshold = -0.1;
        assert!(negative.validate().is_err());

        // 0.0 = 關閉功能，合法
        let mut disabled = DaemonConfig::default();
        disabled.degrade_loss_threshold = 0.0;
        assert!(disabled.validate().is_ok());

        // 必須嚴格小於判死門檻，否則「降級」與「判死」互相矛盾
        let mut not_less = DaemonConfig::default();
        not_less.degrade_loss_threshold = 0.5;
        assert!(not_less.validate().is_err());

        // 剛好小於則合法（0.49 < 0.50）
        let mut just_below = DaemonConfig::default();
        just_below.degrade_loss_threshold = 0.49;
        assert!(just_below.validate().is_ok());
    }

    #[test]
    fn test_degrade_hysteresis_defaults_and_validation() {
        // 預設 0.10 / 6：退出門檻 = 0.20 - 0.10 = 0.10，連續 6 次達標才退出
        let cfg = DaemonConfig::default();
        assert!((cfg.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.degrade_exit_samples, 6);
        assert!(cfg.validate().is_ok());

        // 舊設定檔沒有這兩個欄位時必須拿到預設值（不是 0 / 0），否則升級後行為會倒退
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!((old.degrade_hysteresis - 0.10).abs() < f64::EPSILON);
        assert_eq!(old.degrade_exit_samples, 6);

        // 範圍檢查
        let mut too_big = DaemonConfig::default();
        too_big.degrade_hysteresis = 1.5;
        assert!(too_big.validate().is_err());

        let mut negative = DaemonConfig::default();
        negative.degrade_hysteresis = -0.1;
        assert!(negative.validate().is_err());

        let mut zero_samples = DaemonConfig::default();
        zero_samples.degrade_exit_samples = 0;
        assert!(zero_samples.validate().is_err());

        // 遲滯量必須嚴格小於降級門檻：等於門檻（退出門檻 = 0）與大於門檻都必須被擋下，
        // 否則這條線一旦降級就再也回不來（永遠不參與 ECMP）。
        let mut equal = DaemonConfig::default();
        equal.degrade_hysteresis = 0.20;
        assert!(equal.validate().is_err());

        let mut greater = DaemonConfig::default();
        greater.degrade_hysteresis = 0.30;
        assert!(greater.validate().is_err());

        // 剛好小於則合法（0.19 < 0.20）
        let mut just_below = DaemonConfig::default();
        just_below.degrade_hysteresis = 0.19;
        assert!(just_below.validate().is_ok());

        // 0.0 = 關閉降級功能：此時不比對兩者大小
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
        // 預設必須是 false：刪掉唯一一條預設路由會在服務重啟窗口內
        // 讓整台路由器（含所有 LAN 客戶端）失去出口。
        assert!(!DaemonConfig::default().remove_routes_on_exit);
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.remove_routes_on_exit);
    }

    #[test]
    fn test_ecmp_mode_default_and_parsing() {
        // 舊設定檔沒有 ecmp_mode，必須沿用 standard，不能改變既有行為
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.ecmp_mode, EcmpMode::Standard);
        assert_eq!(DaemonConfig::default().ecmp_mode, EcmpMode::Standard);

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

        // 非預期字串必須直接報錯，而不是靜默當成 standard
        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"ecmp_mode":"bogus","interfaces":[{"name":"wan1"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn test_multipath_hash_policy_parsing_and_values() {
        // 舊設定檔沒有這個欄位 → None（沿用系統預設，不改變行為）
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert_eq!(old.multipath_hash_policy, None);

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

    #[test]
    fn test_weight_mode_and_dynamic_weight_validation() {
        // 預設 static + 合理預設值
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
        // 預設關閉，且門檻是合理的 0.80 / 0.60
        let cfg = DaemonConfig::default();
        assert!(!cfg.load_aware);
        assert!((cfg.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!((cfg.load_recover_ratio - 0.60).abs() < f64::EPSILON);
        assert_eq!(cfg.interfaces[0].max_mbps, None);
        assert_eq!(cfg.interfaces[0].up_mbps, None);
        assert!(!cfg.capacity_weights_on());
        assert!(cfg.validate().is_ok());

        // 舊設定檔沒有這些欄位時，必須沿用預設（不能變成 0 或開啟）
        let old: DaemonConfig =
            serde_json::from_str(r#"{"interfaces":[{"name":"wan1"}]}"#).unwrap();
        assert!(!old.load_aware);
        assert!((old.load_target_ratio - 0.80).abs() < f64::EPSILON);
        assert!(old.validate().is_ok());

        // 啟用負載感知：每條線都必須填最大頻寬
        let missing: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[{"name":"wan1"},{"name":"wan2"}]}"#,
        )
        .unwrap();
        assert!(missing.validate().is_err(), "缺 max_mbps 必須被擋下");

        let ok: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[
                {"name":"wan1","max_mbps":1000,"up_mbps":50},
                {"name":"wan2","max_mbps":500}]}"#,
        )
        .unwrap();
        assert!(ok.validate().is_ok());
        assert!(ok.capacity_weights_on());
        // 非對稱線路的 up_mbps 可省略（沿用 max_mbps）
        assert_eq!(ok.interfaces[1].up_mbps, None);

        // 舊名 down_mbps 仍可解析（serde alias）
        let aliased: DaemonConfig = serde_json::from_str(
            r#"{"load_aware":true,"interfaces":[
                {"name":"wan1","down_mbps":1000},
                {"name":"wan2","down_mbps":500}]}"#,
        )
        .unwrap();
        assert_eq!(aliased.interfaces[0].max_mbps, Some(1000.0));
        assert!(aliased.validate().is_ok());

        // 容量必須是有限正數
        for bad in [
            r#"{"name":"wan1","max_mbps":0}"#,
            r#"{"name":"wan1","max_mbps":-1}"#,
            r#"{"name":"wan1","max_mbps":100,"up_mbps":0}"#,
        ] {
            let cfg: DaemonConfig =
                serde_json::from_str(&format!(r#"{{"load_aware":true,"interfaces":[{bad}]}}"#))
                    .unwrap();
            assert!(cfg.validate().is_err(), "應拒絕容量 {bad}");
        }

        // 1e999 這類超範圍數字在 JSON 解析階段就會被 serde_json 拒絕，不會進到 validate
        assert!(
            serde_json::from_str::<DaemonConfig>(
                r#"{"load_aware":true,"interfaces":[{"name":"wan1","max_mbps":1e999}]}"#
            )
            .is_err()
        );

        // 容量要嘛全填、要嘛全不填：只給部分線容量會讓比例無從定義
        let partial: DaemonConfig = serde_json::from_str(
            r#"{"interfaces":[{"name":"wan1","max_mbps":1000},{"name":"wan2"}]}"#,
        )
        .unwrap();
        assert!(
            partial.validate().is_err(),
            "部分線才有 max_mbps 必須被擋下"
        );

        // 門檻關係：recover 必須嚴格小於 target，target 必須 > 0
        for (target, recover) in [(0.8, 0.8), (0.8, 0.9), (0.0, 0.0)] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"load_target_ratio":{target},"load_recover_ratio":{recover},
                    "interfaces":[{{"name":"wan1"}}]}}"#
            ))
            .unwrap();
            assert!(
                cfg.validate().is_err(),
                "應拒絕 target={target} recover={recover}"
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

        // 展開多來源 x 多目的仍在上限內
        let expanded: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"multi",
                "source":["192.168.3.0/24","192.168.4.0/24"],
                "destination":["10.0.0.0/8","172.16.0.0/12"],
                "interface":"wan1"}}],{base}}}"#
        ))
        .unwrap();
        assert!(expanded.validate().is_ok());

        // 目標 WAN 不存在
        let unknown: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"x","interface":"wan9"}}],{base}}}"#
        ))
        .unwrap();
        assert!(unknown.validate().is_err());

        // 前綴格式錯誤
        for bad in ["192.168.3.0", "192.168.3.0/33", "300.1.1.1/24"] {
            let cfg: DaemonConfig = serde_json::from_str(&format!(
                r#"{{"policies":[{{"name":"x","source":["{bad}"],"interface":"wan1"}}],{base}}}"#
            ))
            .unwrap();
            assert!(cfg.validate().is_err(), "should reject source {bad}");
        }

        // 名稱重複 / 空名稱
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

        // 顯式優先序：重複、超界、只設一半
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

        // 展開後超過 64 條
        let sources: Vec<String> = (0..70).map(|i| format!("\"10.{i}.0.0/16\"")).collect();
        let too_many: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"policies":[{{"name":"big","source":[{}],"interface":"wan1"}}],{base}}}"#,
            sources.join(",")
        ))
        .unwrap();
        assert!(too_many.validate().is_err());

        // 未知欄位（非註解）
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
