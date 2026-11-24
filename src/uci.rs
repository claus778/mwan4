//! 纯 Rust 原生 OpenWrt UCI 解析、写入与 CLI 子命令（`mwan4 uci ...`）。
//!
//! 设计目标：
//! 1. 零外部依赖、零子进程：不依赖外部 `uci` 二进制，在 OpenWrt 与标准 Linux 上均可直接读写 `/etc/config/mwan4`；
//! 2. `mwan4 -c /etc/config/mwan4` 与 `mwan4 --check-config /etc/config/mwan4` 可直接加载 UCI 配置，无需先经 shell 转换；
//! 3. 提供与 OpenWrt `uci` 语法一致的子命令：`show / get / set / add_list / del_list / delete / commit / validate / export-json`。

use crate::config::{
    DaemonConfig, DnsServer, EcmpMode, InterfaceConfig, MultipathHashPolicy, PolicyConfig,
    ProbeMode, WeightMode,
};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

pub const DEFAULT_UCI_PATH: &str = "/etc/config/mwan4";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UciEntry {
    Option(String, String),
    List(String, Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UciSection {
    pub sec_type: String,
    pub name: Option<String>,
    pub entries: Vec<UciEntry>,
}

impl UciSection {
    pub fn effective_name(&self, index: usize) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("@{}[{index}]", self.sec_type))
    }

    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.entries.iter().rev().find_map(|e| match e {
            UciEntry::Option(k, v) if k == key => Some(v.as_str()),
            _ => None,
        })
    }

    pub fn get_list(&self, key: &str) -> Vec<String> {
        for e in &self.entries {
            if let UciEntry::List(k, vals) = e {
                if k == key {
                    return vals.clone();
                }
            }
        }
        // 兼容把 list 误写成空白分隔的 option（与 init.d 行为一致）
        if let Some(single) = self.get_option(key) {
            return single.split_whitespace().map(str::to_string).collect();
        }
        Vec::new()
    }

    pub fn set_option(&mut self, key: &str, value: String) {
        self.entries
            .retain(|e| !matches!(e, UciEntry::List(k, _) if k == key));
        if let Some(UciEntry::Option(_, v)) = self
            .entries
            .iter_mut()
            .find(|e| matches!(e, UciEntry::Option(k, _) if k == key))
        {
            *v = value;
        } else {
            self.entries.push(UciEntry::Option(key.to_string(), value));
        }
    }

    pub fn add_list(&mut self, key: &str, value: String) {
        // 若此前是同名 option，升级为 list
        let mut promoted: Option<Vec<String>> = None;
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| matches!(e, UciEntry::Option(k, _) if k == key))
        {
            if let UciEntry::Option(_, old) = self.entries.remove(pos) {
                let mut v: Vec<String> = old.split_whitespace().map(str::to_string).collect();
                v.push(value.clone());
                promoted = Some(v);
            }
        }
        if let Some(vals) = promoted {
            self.entries.push(UciEntry::List(key.to_string(), vals));
            return;
        }
        if let Some(UciEntry::List(_, vals)) = self
            .entries
            .iter_mut()
            .find(|e| matches!(e, UciEntry::List(k, _) if k == key))
        {
            vals.push(value);
        } else {
            self.entries
                .push(UciEntry::List(key.to_string(), vec![value]));
        }
    }

    pub fn del_list(&mut self, key: &str, value: &str) -> bool {
        let mut removed = false;
        self.entries.retain_mut(|e| match e {
            UciEntry::List(k, vals) if k == key => {
                let before = vals.len();
                vals.retain(|v| v != value);
                if vals.len() != before {
                    removed = true;
                }
                !vals.is_empty()
            }
            _ => true,
        });
        removed
    }

    pub fn delete_key(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| match e {
            UciEntry::Option(k, _) | UciEntry::List(k, _) => k != key,
        });
        self.entries.len() != before
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UciDocument {
    pub sections: Vec<UciSection>,
}

/// 按 UCI 词法切分单行（支持单引号、双引号与 `#` 注释）。
fn tokenize_uci_line(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        if c == '#' {
            break;
        }
        if c == '\'' || c == '"' {
            let quote = c;
            chars.next();
            let mut buf = String::new();
            let mut closed = false;
            while let Some(ch) = chars.next() {
                if ch == quote {
                    closed = true;
                    break;
                }
                if quote == '"' && ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        buf.push(escaped);
                        continue;
                    }
                }
                buf.push(ch);
            }
            if !closed {
                return Err(format!("unterminated quote in UCI line: {line}"));
            }
            tokens.push(buf);
        } else {
            let mut buf = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_whitespace() || ch == '#' {
                    break;
                }
                buf.push(ch);
                chars.next();
            }
            tokens.push(buf);
        }
    }
    Ok(tokens)
}

fn quote_uci(val: &str) -> String {
    let escaped = val.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn parse_uci_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enabled" => Ok(true),
        "0" | "false" | "no" | "off" | "disabled" => Ok(false),
        other => Err(format!("invalid boolean value '{other}'")),
    }
}

/// 判断文本内容是否是 JSON（用于 `load_from_file` 自动识别 JSON 与 UCI）。
pub fn looks_like_json(content: &str) -> bool {
    content.trim_start().starts_with('{')
}

impl UciDocument {
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut sections: Vec<UciSection> = Vec::new();
        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let tokens = tokenize_uci_line(raw_line).map_err(|e| format!("line {line_no}: {e}"))?;
            if tokens.is_empty() {
                continue;
            }
            match tokens[0].as_str() {
                "package" => {}
                "config" => {
                    if tokens.len() < 2 {
                        return Err(format!("line {line_no}: 'config' requires a section type"));
                    }
                    let sec_type = tokens[1].clone();
                    let name = tokens.get(2).cloned();
                    sections.push(UciSection {
                        sec_type,
                        name,
                        entries: Vec::new(),
                    });
                }
                "option" => {
                    if tokens.len() < 3 {
                        return Err(format!("line {line_no}: 'option' requires key and value"));
                    }
                    let sec = sections.last_mut().ok_or_else(|| {
                        format!("line {line_no}: 'option' appears before any 'config' section")
                    })?;
                    sec.set_option(&tokens[1], tokens[2].clone());
                }
                "list" => {
                    if tokens.len() < 3 {
                        return Err(format!("line {line_no}: 'list' requires key and value"));
                    }
                    let sec = sections.last_mut().ok_or_else(|| {
                        format!("line {line_no}: 'list' appears before any 'config' section")
                    })?;
                    sec.add_list(&tokens[1], tokens[2].clone());
                }
                other => {
                    return Err(format!("line {line_no}: unexpected UCI keyword '{other}'"));
                }
            }
        }
        Ok(Self { sections })
    }

    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("failed to read {}: {e}", path.as_ref().display()))?;
        Self::parse(&content)
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (i, sec) in self.sections.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            match &sec.name {
                Some(name) => {
                    out.push_str(&format!("config {} {}\n", sec.sec_type, quote_uci(name)))
                }
                None => out.push_str(&format!("config {}\n", sec.sec_type)),
            }
            for entry in &sec.entries {
                match entry {
                    UciEntry::Option(k, v) => {
                        out.push_str(&format!("\toption {k} {}\n", quote_uci(v)));
                    }
                    UciEntry::List(k, vals) => {
                        for v in vals {
                            out.push_str(&format!("\tlist {k} {}\n", quote_uci(v)));
                        }
                    }
                }
            }
        }
        out
    }

    pub fn save_file_atomic<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        use std::io::Write;

        let target = path.as_ref();
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let content = self.serialize();
        let tmp_path = format!("{}.mwan4.tmp", target.display());
        let _ = std::fs::remove_file(&tmp_path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        drop(file);
        std::fs::rename(&tmp_path, target)
    }

    fn find_section_idx(&self, selector: &str) -> Option<usize> {
        // 支持按名称（global / wan1）或按类型+下标（@interface[0]）定位
        if let Some(rest) = selector.strip_prefix('@') {
            if let Some((sec_type, idx_part)) = rest.split_once('[') {
                if let Some(num_str) = idx_part.strip_suffix(']') {
                    if let Ok(target_nth) = num_str.parse::<usize>() {
                        let mut seen = 0usize;
                        for (i, s) in self.sections.iter().enumerate() {
                            if s.sec_type == sec_type {
                                if seen == target_nth {
                                    return Some(i);
                                }
                                seen += 1;
                            }
                        }
                    }
                }
            }
        }
        self.sections
            .iter()
            .position(|s| s.name.as_deref() == Some(selector))
    }

    /// 按 OpenWrt `uci show mwan4` 风格格式化输出。
    pub fn format_show(&self, filter: Option<&str>) -> Result<String, String> {
        let mut out = String::new();
        let (sec_filter, opt_filter) = match filter {
            None => (None, None),
            Some(f) => {
                let stripped = f.strip_prefix("mwan4.").unwrap_or(f);
                if let Some((s, o)) = stripped.split_once('.') {
                    (Some(s), Some(o))
                } else {
                    (Some(stripped), None)
                }
            }
        };

        let mut type_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut matched_any = false;

        for (idx, sec) in self.sections.iter().enumerate() {
            let nth = *type_counts.entry(sec.sec_type.as_str()).or_insert(0);
            *type_counts.get_mut(sec.sec_type.as_str()).unwrap() += 1;
            let disp_name = sec
                .name
                .clone()
                .unwrap_or_else(|| format!("@{}[{nth}]", sec.sec_type));

            if let Some(want_sec) = sec_filter {
                let matches_sec = self.find_section_idx(want_sec) == Some(idx);
                if !matches_sec {
                    continue;
                }
            }

            if opt_filter.is_none() {
                matched_any = true;
                out.push_str(&format!("mwan4.{disp_name}={}\n", sec.sec_type));
            }
            for entry in &sec.entries {
                match entry {
                    UciEntry::Option(k, v) => {
                        if opt_filter.is_some_and(|want| want != k) {
                            continue;
                        }
                        matched_any = true;
                        out.push_str(&format!("mwan4.{disp_name}.{k}={}\n", quote_uci(v)));
                    }
                    UciEntry::List(k, vals) => {
                        if opt_filter.is_some_and(|want| want != k) {
                            continue;
                        }
                        matched_any = true;
                        let joined = vals
                            .iter()
                            .map(|v| quote_uci(v))
                            .collect::<Vec<_>>()
                            .join(" ");
                        out.push_str(&format!("mwan4.{disp_name}.{k}={joined}\n"));
                    }
                }
            }
        }

        if sec_filter.is_some() && !matched_any {
            return Err(format!("UCI entry not found: {}", filter.unwrap_or("")));
        }
        Ok(out)
    }

    /// 转换为 `DaemonConfig`（字段与 `/etc/init.d/mwan4` 完全对齐）。
    pub fn to_daemon_config(&self) -> Result<DaemonConfig, String> {
        let mut cfg = DaemonConfig::default();
        cfg.interfaces.clear();
        cfg.policies.clear();

        if let Some(global) = self.sections.iter().find(|s| s.sec_type == "global") {
            if let Some(v) = global.get_option("check_interval_ms") {
                cfg.check_interval_ms = v
                    .parse()
                    .map_err(|_| format!("global.check_interval_ms: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("probe_timeout_ms") {
                cfg.probe_timeout_ms = v
                    .parse()
                    .map_err(|_| format!("global.probe_timeout_ms: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("window_size") {
                cfg.window_size = v
                    .parse()
                    .map_err(|_| format!("global.window_size: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("loss_threshold_down") {
                cfg.loss_threshold_down = v
                    .parse()
                    .map_err(|_| format!("global.loss_threshold_down: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("degrade_loss_threshold") {
                cfg.degrade_loss_threshold = v
                    .parse()
                    .map_err(|_| format!("global.degrade_loss_threshold: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("degrade_hysteresis") {
                cfg.degrade_hysteresis = v
                    .parse()
                    .map_err(|_| format!("global.degrade_hysteresis: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("degrade_exit_samples") {
                cfg.degrade_exit_samples = v
                    .parse()
                    .map_err(|_| format!("global.degrade_exit_samples: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("degrade_enter_samples") {
                cfg.degrade_enter_samples = v
                    .parse()
                    .map_err(|_| format!("global.degrade_enter_samples: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("degrade_min_out_samples") {
                cfg.degrade_min_out_samples = v.parse().map_err(|_| {
                    format!("global.degrade_min_out_samples: invalid integer '{v}'")
                })?;
            }
            if let Some(v) = global.get_option("consecutive_fail_down") {
                cfg.consecutive_fail_down = v
                    .parse()
                    .map_err(|_| format!("global.consecutive_fail_down: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("recovery_success_count") {
                cfg.recovery_success_count = v
                    .parse()
                    .map_err(|_| format!("global.recovery_success_count: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("max_rtt_ms") {
                cfg.max_rtt_ms = v
                    .parse()
                    .map_err(|_| format!("global.max_rtt_ms: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("rtt_fail_count") {
                cfg.rtt_fail_count = v
                    .parse()
                    .map_err(|_| format!("global.rtt_fail_count: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("route_priority") {
                cfg.route_priority = v
                    .parse()
                    .map_err(|_| format!("global.route_priority: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("conntrack_flush_min_interval_ms") {
                cfg.conntrack_flush_min_interval_ms = v.parse().map_err(|_| {
                    format!("global.conntrack_flush_min_interval_ms: invalid integer '{v}'")
                })?;
            }
            if let Some(v) = global
                .get_option("flush_conntrack")
                .or_else(|| global.get_option("flush_conntrack_on_down"))
            {
                cfg.flush_conntrack_on_down = parse_uci_bool(v)?;
            }
            if let Some(v) = global.get_option("flush_conntrack_on_switch") {
                cfg.flush_conntrack_on_switch = parse_uci_bool(v)?;
            }
            if let Some(v) = global.get_option("remove_routes_on_exit") {
                cfg.remove_routes_on_exit = parse_uci_bool(v)?;
            }
            if let Some(v) = global.get_option("ecmp_mode") {
                cfg.ecmp_mode = match v {
                    "standard" => EcmpMode::Standard,
                    "auto" => EcmpMode::Auto,
                    "resilient" => EcmpMode::Resilient,
                    other => {
                        return Err(format!(
                            "global.ecmp_mode: invalid '{other}' (expected standard / auto / resilient)"
                        ));
                    }
                };
            }
            if let Some(v) = global.get_option("resilient_idle_timer_secs") {
                cfg.resilient_idle_timer_secs = v.parse().map_err(|_| {
                    format!("global.resilient_idle_timer_secs: invalid integer '{v}'")
                })?;
            }
            if let Some(v) = global.get_option("multipath_hash_policy") {
                cfg.multipath_hash_policy = match v {
                    "" | "null" => None,
                    "l3" => Some(MultipathHashPolicy::L3),
                    "l4" => Some(MultipathHashPolicy::L4),
                    "inner" => Some(MultipathHashPolicy::Inner),
                    other => {
                        return Err(format!(
                            "global.multipath_hash_policy: invalid '{other}' (expected l3 / l4 / inner)"
                        ));
                    }
                };
            }
            if let Some(v) = global.get_option("weight_mode") {
                cfg.weight_mode = match v {
                    "static" => WeightMode::Static,
                    "quality" => WeightMode::Quality,
                    "aggregate" => WeightMode::Aggregate,
                    other => {
                        return Err(format!(
                            "global.weight_mode: invalid '{other}' (expected static / quality / aggregate)"
                        ));
                    }
                };
            }
            if let Some(v) = global.get_option("dynamic_weight_interval_ms") {
                cfg.dynamic_weight_interval_ms = v.parse().map_err(|_| {
                    format!("global.dynamic_weight_interval_ms: invalid integer '{v}'")
                })?;
            }
            if let Some(v) = global.get_option("dynamic_weight_min_ratio") {
                cfg.dynamic_weight_min_ratio = v.parse().map_err(|_| {
                    format!("global.dynamic_weight_min_ratio: invalid number '{v}'")
                })?;
            }
            if let Some(v) = global.get_option("load_aware") {
                cfg.load_aware = parse_uci_bool(v)?;
            }
            if let Some(v) = global.get_option("load_target_ratio") {
                cfg.load_target_ratio = v
                    .parse()
                    .map_err(|_| format!("global.load_target_ratio: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("load_recover_ratio") {
                cfg.load_recover_ratio = v
                    .parse()
                    .map_err(|_| format!("global.load_recover_ratio: invalid number '{v}'"))?;
            }
            if let Some(v) = global.get_option("allow_dynamic_weights_on_standard") {
                cfg.allow_dynamic_weights_on_standard = parse_uci_bool(v)?;
            }
            if let Some(v) = global.get_option("probe_mode") {
                cfg.probe_mode = match v {
                    "tcp" => ProbeMode::Tcp,
                    "dns" => ProbeMode::Dns,
                    other => {
                        return Err(format!(
                            "global.probe_mode: invalid '{other}' (expected tcp / dns)"
                        ));
                    }
                };
            }
            if let Some(v) = global.get_option("dns_probe_domain") {
                cfg.dns_probe_domain = v.to_string();
            }
            if let Some(v) = global.get_option("dns_listen_addr") {
                cfg.dns_listen_addr = v.to_string();
            }
            if let Some(v) = global.get_option("dns_listen_port") {
                cfg.dns_listen_port = v
                    .parse()
                    .map_err(|_| format!("global.dns_listen_port: invalid port '{v}'"))?;
            }
            if let Some(v) = global.get_option("dns_forward_timeout_ms") {
                cfg.dns_forward_timeout_ms = v
                    .parse()
                    .map_err(|_| format!("global.dns_forward_timeout_ms: invalid integer '{v}'"))?;
            }
            if let Some(v) = global.get_option("dns_resolv_file") {
                cfg.dns_resolv_file = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                };
            }
        }

        for (idx, sec) in self.sections.iter().enumerate() {
            match sec.sec_type.as_str() {
                "interface" => {
                    if let Some(en) = sec.get_option("enabled") {
                        if !parse_uci_bool(en)? {
                            continue;
                        }
                    }
                    let sec_label = sec.effective_name(idx);
                    let name = sec
                        .get_option("name")
                        .map(str::to_string)
                        .or_else(|| sec.name.clone())
                        .ok_or_else(|| format!("interface '{sec_label}' requires 'name'"))?;
                    let gateway: Option<Ipv4Addr> =
                        match sec.get_option("gateway") {
                            None | Some("") | Some("0.0.0.0") => None,
                            Some(v) => Some(v.parse().map_err(|_| {
                                format!("interface '{name}': invalid gateway '{v}'")
                            })?),
                        };
                    let gateway6: Option<Ipv6Addr> =
                        match sec.get_option("gateway6") {
                            None | Some("") | Some("::") => None,
                            Some(v) => Some(v.parse().map_err(|_| {
                                format!("interface '{name}': invalid gateway6 '{v}'")
                            })?),
                        };
                    let metric: u32 = match sec.get_option("metric") {
                        Some(v) => v
                            .parse()
                            .map_err(|_| format!("interface '{name}': invalid metric '{v}'"))?,
                        None => 10,
                    };
                    let weight: u32 = match sec.get_option("weight") {
                        Some(v) => v
                            .parse()
                            .map_err(|_| format!("interface '{name}': invalid weight '{v}'"))?,
                        None => 1,
                    };
                    let max_mbps: Option<f64> =
                        match sec
                            .get_option("max_mbps")
                            .or_else(|| sec.get_option("down_mbps"))
                        {
                            None | Some("") => None,
                            Some(v) => Some(v.parse().map_err(|_| {
                                format!("interface '{name}': invalid max_mbps '{v}'")
                            })?),
                        };
                    let up_mbps: Option<f64> =
                        match sec.get_option("up_mbps") {
                            None | Some("") => None,
                            Some(v) => Some(v.parse().map_err(|_| {
                                format!("interface '{name}': invalid up_mbps '{v}'")
                            })?),
                        };
                    let probe_mode: Option<ProbeMode> = match sec.get_option("probe_mode") {
                        None | Some("") => None,
                        Some("tcp") => Some(ProbeMode::Tcp),
                        Some("dns") => Some(ProbeMode::Dns),
                        Some(other) => {
                            return Err(format!(
                                "interface '{name}': invalid probe_mode '{other}'"
                            ));
                        }
                    };
                    let raw_targets = sec.get_list("probe_targets");
                    let probe_targets: Vec<SocketAddr> = if raw_targets.is_empty() {
                        vec![
                            "223.5.5.5:53".parse().unwrap(),
                            "114.114.114.114:53".parse().unwrap(),
                        ]
                    } else {
                        raw_targets
                            .iter()
                            .map(|t| {
                                t.parse().map_err(|_| {
                                    format!("interface '{name}': invalid probe target '{t}'")
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()?
                    };
                    let dns_servers: Vec<DnsServer> = sec
                        .get_list("dns_servers")
                        .iter()
                        .map(|d| d.parse().map_err(|e| format!("interface '{name}': {e}")))
                        .collect::<Result<Vec<_>, _>>()?;
                    let underlay_targets: Vec<Ipv4Addr> = sec
                        .get_list("underlay_targets")
                        .iter()
                        .map(|u| {
                            u.parse().map_err(|_| {
                                format!("interface '{name}': invalid underlay target '{u}'")
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    cfg.interfaces.push(InterfaceConfig {
                        name,
                        gateway,
                        gateway6,
                        metric,
                        weight,
                        max_mbps,
                        up_mbps,
                        probe_targets,
                        probe_mode,
                        dns_servers,
                        underlay_targets,
                        extra: Default::default(),
                    });
                }
                "policy" => {
                    let sec_label = sec.effective_name(idx);
                    let name = sec
                        .get_option("name")
                        .map(str::to_string)
                        .or_else(|| sec.name.clone())
                        .unwrap_or(sec_label);
                    let interface = sec
                        .get_option("interface")
                        .map(str::to_string)
                        .ok_or_else(|| format!("policy '{name}' requires 'interface'"))?;
                    let priority: Option<u32> = match sec.get_option("priority") {
                        None | Some("") => None,
                        Some(v) => Some(
                            v.parse()
                                .map_err(|_| format!("policy '{name}': invalid priority '{v}'"))?,
                        ),
                    };
                    cfg.policies.push(PolicyConfig {
                        name,
                        source: sec.get_list("source"),
                        destination: sec.get_list("destination"),
                        interface,
                        priority,
                        extra: Default::default(),
                    });
                }
                _ => {}
            }
        }

        Ok(cfg)
    }
}

fn split_uci_path(raw: &str) -> Result<(&str, Option<&str>), String> {
    let trimmed = raw.strip_prefix("mwan4.").unwrap_or(raw);
    if trimmed.is_empty() {
        return Err("empty UCI path".into());
    }
    if let Some((sec, opt)) = trimmed.split_once('.') {
        if sec.is_empty() || opt.is_empty() {
            return Err(format!("invalid UCI path '{raw}'"));
        }
        Ok((sec, Some(opt)))
    } else {
        Ok((trimmed, None))
    }
}

fn print_uci_help(bin_name: &str) {
    println!(
        r#"MWAN4 native UCI command interface

USAGE:
    {bin_name} uci [-f <FILE>] <COMMAND> [ARGS...]

OPTIONS:
    -f, --file <FILE>    UCI config path (default: {DEFAULT_UCI_PATH})

COMMANDS:
    show [section[.option]]              Show UCI configuration
    get <section>.<option>               Get an option or list value
    set <section>=<type>                 Create a named section
    set <section>.<option>=<value>       Set an option value
    add_list <section>.<option>=<value>  Append a value to a list
    del_list <section>.<option>=<value>  Remove a value from a list
    delete <section>[.<option>]          Delete a section or option
    validate | commit                    Validate UCI config against mwan4 rules
    export-json                          Convert UCI config to formatted JSON

EXAMPLES:
    {bin_name} uci show
    {bin_name} uci set global.weight_mode=aggregate
    {bin_name} uci set global.dns_listen_port=5354
    {bin_name} uci add_list wan1.dns_servers=202.96.128.86
    {bin_name} uci validate
"#
    );
}

/// 执行 `mwan4 uci ...` 子命令。
pub fn run_uci_cli(bin_name: &str, args: &[String]) -> Result<(), String> {
    let mut file_path = DEFAULT_UCI_PATH.to_string();
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-f" | "--file" => {
                if idx + 1 >= args.len() {
                    return Err("--file requires a path argument".into());
                }
                file_path = args[idx + 1].clone();
                idx += 2;
            }
            other if other.starts_with("--file=") => {
                file_path = other["--file=".len()..].to_string();
                idx += 1;
            }
            "-h" | "--help" => {
                print_uci_help(bin_name);
                return Ok(());
            }
            _ => break,
        }
    }

    if idx >= args.len() {
        print_uci_help(bin_name);
        return Ok(());
    }

    let cmd = args[idx].as_str();
    let rest = &args[idx + 1..];

    match cmd {
        "show" => {
            let doc = UciDocument::load_file(&file_path)?;
            let out = doc.format_show(rest.first().map(|s| s.as_str()))?;
            print!("{out}");
            Ok(())
        }
        "get" => {
            let key = rest.first().ok_or("uci get requires <section>.<option>")?;
            let doc = UciDocument::load_file(&file_path)?;
            let (sec_sel, opt) = split_uci_path(key)?;
            let opt = opt.ok_or("uci get requires <section>.<option>")?;
            let sec_idx = doc
                .find_section_idx(sec_sel)
                .ok_or_else(|| format!("UCI section not found: {sec_sel}"))?;
            let sec = &doc.sections[sec_idx];
            if let Some(val) = sec.get_option(opt) {
                println!("{val}");
                return Ok(());
            }
            let list = sec.get_list(opt);
            if !list.is_empty() {
                println!("{}", list.join(" "));
                return Ok(());
            }
            Err(format!("UCI option not found: {key}"))
        }
        "set" => {
            let expr = rest
                .first()
                .ok_or("uci set requires <section>.<option>=<value> or <section>=<type>")?;
            let (lhs, val) = expr
                .split_once('=')
                .ok_or("uci set requires '=' separator (e.g. global.ecmp_mode=auto)")?;
            let mut doc = if Path::new(&file_path).exists() {
                UciDocument::load_file(&file_path)?
            } else {
                UciDocument::default()
            };
            let (sec_sel, opt) = split_uci_path(lhs)?;
            match opt {
                None => {
                    if let Some(i) = doc.find_section_idx(sec_sel) {
                        doc.sections[i].sec_type = val.to_string();
                    } else {
                        doc.sections.push(UciSection {
                            sec_type: val.to_string(),
                            name: Some(sec_sel.to_string()),
                            entries: Vec::new(),
                        });
                    }
                }
                Some(opt_name) => {
                    let sec_idx = doc
                        .find_section_idx(sec_sel)
                        .ok_or_else(|| format!("UCI section not found: {sec_sel}"))?;
                    doc.sections[sec_idx].set_option(opt_name, val.to_string());
                }
            }
            doc.save_file_atomic(&file_path)
                .map_err(|e| format!("failed to save {file_path}: {e}"))?;
            Ok(())
        }
        "add_list" => {
            let expr = rest
                .first()
                .ok_or("uci add_list requires <section>.<option>=<value>")?;
            let (lhs, val) = expr
                .split_once('=')
                .ok_or("uci add_list requires '=' separator")?;
            let mut doc = UciDocument::load_file(&file_path)?;
            let (sec_sel, opt) = split_uci_path(lhs)?;
            let opt = opt.ok_or("uci add_list requires <section>.<option>=<value>")?;
            let sec_idx = doc
                .find_section_idx(sec_sel)
                .ok_or_else(|| format!("UCI section not found: {sec_sel}"))?;
            doc.sections[sec_idx].add_list(opt, val.to_string());
            doc.save_file_atomic(&file_path)
                .map_err(|e| format!("failed to save {file_path}: {e}"))?;
            Ok(())
        }
        "del_list" => {
            let expr = rest
                .first()
                .ok_or("uci del_list requires <section>.<option>=<value>")?;
            let (lhs, val) = expr
                .split_once('=')
                .ok_or("uci del_list requires '=' separator")?;
            let mut doc = UciDocument::load_file(&file_path)?;
            let (sec_sel, opt) = split_uci_path(lhs)?;
            let opt = opt.ok_or("uci del_list requires <section>.<option>=<value>")?;
            let sec_idx = doc
                .find_section_idx(sec_sel)
                .ok_or_else(|| format!("UCI section not found: {sec_sel}"))?;
            if !doc.sections[sec_idx].del_list(opt, val) {
                return Err(format!("value '{val}' not found in {lhs}"));
            }
            doc.save_file_atomic(&file_path)
                .map_err(|e| format!("failed to save {file_path}: {e}"))?;
            Ok(())
        }
        "delete" => {
            let key = rest
                .first()
                .ok_or("uci delete requires <section> or <section>.<option>")?;
            let mut doc = UciDocument::load_file(&file_path)?;
            let (sec_sel, opt) = split_uci_path(key)?;
            let sec_idx = doc
                .find_section_idx(sec_sel)
                .ok_or_else(|| format!("UCI section not found: {sec_sel}"))?;
            match opt {
                None => {
                    doc.sections.remove(sec_idx);
                }
                Some(opt_name) => {
                    if !doc.sections[sec_idx].delete_key(opt_name) {
                        return Err(format!("UCI option not found: {key}"));
                    }
                }
            }
            doc.save_file_atomic(&file_path)
                .map_err(|e| format!("failed to save {file_path}: {e}"))?;
            Ok(())
        }
        "validate" | "commit" => {
            let doc = UciDocument::load_file(&file_path)?;
            let cfg = doc.to_daemon_config()?;
            cfg.validate()?;
            println!("UCI configuration OK: {file_path}");
            Ok(())
        }
        "export-json" => {
            let doc = UciDocument::load_file(&file_path)?;
            let cfg = doc.to_daemon_config()?;
            cfg.validate()?;
            let json = serde_json::to_string_pretty(&cfg)
                .map_err(|e| format!("JSON serialization failed: {e}"))?;
            println!("{json}");
            Ok(())
        }
        other => Err(format!(
            "unknown uci command '{other}' (try '{bin_name} uci --help')"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_repo_uci_config_and_validate() {
        let doc = UciDocument::load_file("openwrt/luci-app-mwan4/root/etc/config/mwan4")
            .expect("should parse repository UCI config");
        let cfg = doc
            .to_daemon_config()
            .expect("should convert UCI config to DaemonConfig");
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
        assert_eq!(cfg.interfaces.len(), 2);
        assert_eq!(cfg.interfaces[0].name, "wan1");
        assert_eq!(cfg.interfaces[1].name, "wan2");
    }

    #[test]
    fn test_uci_roundtrip_mutations_and_show() {
        let sample = r#"
config global 'global'
	option enabled '1'
	option weight_mode 'aggregate'
	option dns_listen_port '5354'
	option resilient_idle_timer_secs '20'

config interface 'wan1'
	option name 'wan1'
	option gateway '192.168.1.1'
	option metric '10'
	option max_mbps '300'
	list probe_targets '223.5.5.5:53'
	list dns_servers '202.96.128.86'

config interface 'wan2'
	option name 'wan2'
	option metric '10'
	option max_mbps '200'
	list probe_targets '114.114.114.114:53'
	list dns_servers '221.6.4.66:5353'
"#;
        let mut doc = UciDocument::parse(sample).unwrap();
        let cfg = doc.to_daemon_config().unwrap();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.weight_mode, WeightMode::Aggregate);
        assert_eq!(cfg.dns_listen_port, 5354);
        assert_eq!(cfg.resilient_idle_timer_secs, 20);
        assert_eq!(cfg.interfaces[1].gateway, None);
        assert_eq!(cfg.interfaces[1].dns_servers[0].port, 5353);

        let w1 = doc.find_section_idx("wan1").unwrap();
        doc.sections[w1].add_list("dns_servers", "223.5.5.5".into());
        assert_eq!(
            doc.sections[w1].get_list("dns_servers"),
            vec!["202.96.128.86", "223.5.5.5"]
        );
        assert!(doc.sections[w1].del_list("dns_servers", "202.96.128.86"));
        assert_eq!(doc.sections[w1].get_list("dns_servers"), vec!["223.5.5.5"]);

        let serialized = doc.serialize();
        let reparsed = UciDocument::parse(&serialized).unwrap();
        assert_eq!(reparsed, doc);

        let show = reparsed
            .format_show(Some("mwan4.global.weight_mode"))
            .unwrap();
        assert_eq!(show.trim(), "mwan4.global.weight_mode='aggregate'");
    }
}
