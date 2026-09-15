use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// rtnexthop 的 weight 是 u8（核心語意 weight-1），因此上限為 256
pub const MAX_WEIGHT: u32 = 256;

/// 滑動窗口上限：過大的窗口會讓低記憶體裝置在啟動時一次預分配過大緩衝，
/// 也會拖慢每次樣本更新。1024 個樣本 @500ms 已足夠覆蓋 8 分鐘的歷史。
pub const MAX_WINDOW_SIZE: usize = 1024;

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
    /// ECMP 多路路由權重（預設 1，合法範圍 1~256）
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 探測目標地址列表（TCP SYN 探測 IP:Port），如 ["1.1.1.1:443", "8.8.8.8:443"]
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
}

fn default_metric() -> u32 {
    1
}

fn default_weight() -> u32 {
    1
}

fn default_probe_targets() -> Vec<SocketAddr> {
    vec![
        "1.1.1.1:443".parse().unwrap(),
        "8.8.8.8:443".parse().unwrap(),
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
    /// 恢復 UP 所需的窗口丟包率上限（防震盪，預設 10%）
    #[serde(default = "default_loss_threshold_up")]
    pub loss_threshold_up: f64,
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
    /// WAN 接口配置列表
    pub interfaces: Vec<InterfaceConfig>,
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
            interfaces: vec![
                InterfaceConfig {
                    name: "wan1".to_string(),
                    gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    gateway6: None,
                    metric: 1,
                    weight: 1,
                    probe_targets: default_probe_targets(),
                    underlay_targets: Vec::new(),
                },
                InterfaceConfig {
                    name: "wan2".to_string(),
                    gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
                    gateway6: None,
                    metric: 1,
                    weight: 1,
                    probe_targets: default_probe_targets(),
                    underlay_targets: Vec::new(),
                },
            ],
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
        if self.probe_timeout_ms == 0 {
            return Err("probe_timeout_ms must be greater than 0".into());
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
        if self.max_rtt_ms <= 0.0 {
            return Err("max_rtt_ms must be greater than 0".into());
        }
        if !(0.0..=1.0).contains(&self.loss_threshold_down) {
            return Err("loss_threshold_down must be within 0.0 ~ 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.loss_threshold_up) {
            return Err("loss_threshold_up must be within 0.0 ~ 1.0".into());
        }

        let mut seen = std::collections::HashSet::new();
        for iface in &self.interfaces {
            if iface.name.is_empty() {
                return Err("Interface name cannot be empty".into());
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
            // 路由模組只支援 IPv4，若給了 IPv6 目標只會永遠連不上
            for target in &iface.probe_targets {
                if !target.is_ipv4() {
                    return Err(format!(
                        "Interface {} probe target {} is not IPv4 (IPv6 is unsupported)",
                        iface.name, target
                    ));
                }
            }
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
}
