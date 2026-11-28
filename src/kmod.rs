//! 内核态精细分流调度模块（`kmod-mwan4-sched` / `/proc/net/mwan4_sched`）的用户态控制面胶水层。
//!
//! 当路由器已加载 `mwan4_sched.ko` 时，守护进程自动通过 `/proc/net/mwan4_sched` 下发活跃 WAN
//! 列表、权重、带宽上限与实时 RTT/丢包指标，并配套下发 `ip rule fwmark -> table` 规则；
//! 未加载内核模块时自动静默回退到原生 Resilient ECMP，零侵入、零依赖。

use std::io;
use std::path::Path;

/// 内核模块暴露的 procfs 控制接口路径。
pub const PROC_PATH: &str = "/proc/net/mwan4_sched";

/// 专用 fwmark 掩码（高字节 bit 16..23），避开常见防火墙/WireGuard/代理软件占用的低位 mark。
pub const FWMARK_MASK: u32 = 0x00FF_0000;
pub const FWMARK_SHIFT: u32 = 16;

/// 内核调度模式（与 `kernel/mwan4_sched/mwan4_sched.c` 中 `enum mwan4_sched_mode` 一致）。
pub const KMOD_MODE_OFF: u32 = 0;
pub const KMOD_MODE_BALANCED: u32 = 1;
pub const KMOD_MODE_LATENCY: u32 = 2;

/// 为第 `slot` 条 WAN 分配唯一的非零 fwmark（槽位 0..=254）。
pub fn fwmark_for_slot(slot: usize) -> u32 {
    let id = ((slot as u32) + 1).min(254);
    (id << FWMARK_SHIFT) & FWMARK_MASK
}

/// 检测内核模块是否已加载。
pub fn is_available() -> bool {
    Path::new(PROC_PATH).exists()
}

/// 下发给内核调度器的单条活跃 WAN 快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmodWanSpec {
    pub name: String,
    pub ifindex: u32,
    pub fwmark: u32,
    pub weight: u32,
    pub down_kbps: u64,
    pub up_kbps: u64,
    pub rtt_us: u32,
    pub loss_pm: u32,
    pub degraded: bool,
}

/// 组装写入 `/proc/net/mwan4_sched` 的纯文本控制帧。
pub fn format_payload(mode: u32, latency_fastlane: bool, wans: &[KmodWanSpec]) -> String {
    let mut out = format!(
        "mode {} {:08x} {}\n",
        mode,
        FWMARK_MASK,
        if latency_fastlane { 1 } else { 0 }
    );
    for w in wans {
        out.push_str(&format!(
            "wan {} {} {:08x} {} {} {} {} {} {}\n",
            w.name,
            w.ifindex,
            w.fwmark,
            w.weight.max(1),
            w.down_kbps,
            w.up_kbps,
            w.rtt_us,
            w.loss_pm.min(1000),
            if w.degraded { 1 } else { 0 }
        ));
    }
    out
}

/// 将最新 WAN 调度表原子写入内核模块。
pub fn sync_kernel_scheduler(
    mode: u32,
    latency_fastlane: bool,
    wans: &[KmodWanSpec],
) -> io::Result<()> {
    let payload = format_payload(mode, latency_fastlane, wans);
    std::fs::write(PROC_PATH, payload.as_bytes())
}

/// 守护进程退出时关闭内核态首包调度，避免残留旧状态。
pub fn disable_kernel_scheduler() -> io::Result<()> {
    std::fs::write(PROC_PATH, format!("mode {KMOD_MODE_OFF}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fwmark_for_slot() {
        assert_eq!(fwmark_for_slot(0), 0x0001_0000);
        assert_eq!(fwmark_for_slot(1), 0x0002_0000);
        assert_eq!(fwmark_for_slot(63), 0x0040_0000);
        assert_eq!(fwmark_for_slot(0) & FWMARK_MASK, fwmark_for_slot(0));
    }

    #[test]
    fn test_format_payload() {
        let specs = vec![
            KmodWanSpec {
                name: "wan1".to_string(),
                ifindex: 2,
                fwmark: fwmark_for_slot(0),
                weight: 2,
                down_kbps: 1_000_000,
                up_kbps: 100_000,
                rtt_us: 12_500,
                loss_pm: 0,
                degraded: false,
            },
            KmodWanSpec {
                name: "wan2".to_string(),
                ifindex: 3,
                fwmark: fwmark_for_slot(1),
                weight: 1,
                down_kbps: 500_000,
                up_kbps: 50_000,
                rtt_us: 24_000,
                loss_pm: 50,
                degraded: false,
            },
        ];
        let body = format_payload(KMOD_MODE_BALANCED, true, &specs);
        assert!(body.starts_with("mode 1 00ff0000 1\n"));
        assert!(body.contains("wan wan1 2 00010000 2 1000000 100000 12500 0 0\n"));
        assert!(body.contains("wan wan2 3 00020000 1 500000 50000 24000 50 0\n"));
    }
}
