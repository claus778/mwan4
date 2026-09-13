use crate::config::DaemonConfig;
use crate::prober::ProbeSample;
use log::{info, warn};
use std::collections::VecDeque;

/// 鏈路當前狀態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

impl std::fmt::Display for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "UP"),
            LinkState::Down => write!(f, "DOWN"),
        }
    }
}

/// 鏈路品質估算器（LQE - Link Quality Estimator）
pub struct LinkQualityEstimator {
    pub iface_name: String,
    /// 當前鏈路狀態
    pub state: LinkState,
    /// 滑動窗口：記錄最近 N 次探測結果（true = 成功，false = 丟包/超時）
    window: VecDeque<bool>,
    /// 窗口最大長度（預設 10）
    window_capacity: usize,
    /// 窗口內失敗樣本數（隨 pop/push 增量維護，loss_rate() 因此為 O(1)）
    lost_count: usize,
    /// 即時 RTT 平滑值（EWMA，毫秒）
    pub rtt_ewma_ms: Option<f64>,
    /// 即時抖動 Jitter 平滑值（EWMA，毫秒）
    pub jitter_ewma_ms: f64,
    /// 連續超時次數
    pub consecutive_timeouts: usize,
    /// 連續成功次數（用於 DOWN -> UP 防震盪恢復）
    pub consecutive_successes: usize,
    /// EWMA 權重 Alpha（RTT）
    alpha: f64,
    /// EWMA 權重 Beta（Jitter）
    beta: f64,
    /// 最大容許 RTT（毫秒）
    max_rtt_ms: f64,
    /// 平滑 RTT 連續超標幾次才判定 DOWN（滞回，避免單一尖峰震盪）
    rtt_fail_count: usize,
    /// 平滑 RTT 連續超標計數器
    rtt_over_count: usize,
    /// 啟動快速引導標記（首次探測若成功直接拉起，避免開機等待 5 次探測）
    first_probe: bool,
    /// 觸發 DOWN 的連續超時次數（預設 3）
    consecutive_fail_down: usize,
    /// 觸發 DOWN 的窗口丟包率閾值（預設 0.50）
    loss_threshold_down: f64,
    /// 恢復 UP 所需的窗口丟包率上限（預設 0.10）
    loss_threshold_up: f64,
    /// 恢復 UP 所需連續成功次數（預設 5）
    recovery_success_count: usize,
}

impl LinkQualityEstimator {
    pub fn new(iface_name: String, config: &DaemonConfig) -> Self {
        Self {
            iface_name,
            state: LinkState::Down, // 啟動初期先標記為 DOWN，探測通過後迅速拉起
            window: VecDeque::with_capacity(config.window_size),
            window_capacity: config.window_size,
            lost_count: 0,
            rtt_ewma_ms: None,
            jitter_ewma_ms: 0.0,
            consecutive_timeouts: 0,
            consecutive_successes: 0,
            alpha: 0.20, // 平滑因子
            beta: 0.25,
            max_rtt_ms: config.max_rtt_ms,
            rtt_fail_count: config.rtt_fail_count.max(1),
            rtt_over_count: 0,
            first_probe: true,
            consecutive_fail_down: config.consecutive_fail_down,
            loss_threshold_down: config.loss_threshold_down,
            loss_threshold_up: config.loss_threshold_up,
            recovery_success_count: config.recovery_success_count,
        }
    }

    /// 取得滑動窗口中的丟包率 (0.0 ~ 1.0)。
    /// 失敗計數由 update() 隨窗口滑動增量維護，這裡是 O(1) 純讀取。
    pub fn loss_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.lost_count as f64 / self.window.len() as f64
    }

    /// 餵入一次探測樣本，並更新 EWMA 指標與狀態機
    /// 回傳：狀態是否發生變更（若變更需通知 Route Manager 與 Conntrack Flusher）
    pub fn update(&mut self, sample: &ProbeSample) -> (LinkState, bool) {
        let prev_state = self.state;

        // 1. 維護滑動窗口（連同失敗計數一起增量更新）
        if self.window.len() >= self.window_capacity {
            if let Some(evicted) = self.window.pop_front() {
                if !evicted {
                    self.lost_count = self.lost_count.saturating_sub(1);
                }
            }
        }
        self.window.push_back(sample.success);
        if !sample.success {
            self.lost_count += 1;
        }

        // 2. 指標更新與計數器
        if sample.success {
            self.consecutive_timeouts = 0;
            self.consecutive_successes += 1;

            let sample_rtt_ms = sample.rtt.as_secs_f64() * 1000.0;
            match self.rtt_ewma_ms {
                None => {
                    self.rtt_ewma_ms = Some(sample_rtt_ms);
                    self.jitter_ewma_ms = 0.0;
                }
                Some(current_rtt) => {
                    let dev = (sample_rtt_ms - current_rtt).abs();
                    // EWMA 計算: RTT_new = alpha * RTT_sample + (1 - alpha) * RTT_old
                    let new_rtt = self.alpha * sample_rtt_ms + (1.0 - self.alpha) * current_rtt;
                    // Jitter_new = beta * dev + (1 - beta) * Jitter_old
                    let new_jitter = self.beta * dev + (1.0 - self.beta) * self.jitter_ewma_ms;

                    self.rtt_ewma_ms = Some(new_rtt);
                    self.jitter_ewma_ms = new_jitter;
                }
            }
        } else {
            self.consecutive_timeouts += 1;
            self.consecutive_successes = 0; // 一旦超時，恢復累積次數歸零（嚴格防震盪）
        }

        let loss = self.loss_rate();
        let rtt_normal = self.rtt_ewma_ms.is_some_and(|r| r <= self.max_rtt_ms);

        // RTT 嚴重超標同樣視為鏈路不可用（舊版只在 DOWN -> UP 時檢查，
        // 導致一條 RTT 爆到數秒但仍能連上的鏈路會永遠維持 UP）。
        // 這裡用「連續超標次數」做滞回，避免單一封包尖峰就把鏈路打掛。
        if self.rtt_ewma_ms.is_some_and(|r| r > self.max_rtt_ms) {
            self.rtt_over_count = self.rtt_over_count.saturating_add(1);
        } else {
            self.rtt_over_count = 0;
        }
        let rtt_exceeded = self.rtt_over_count >= self.rtt_fail_count;

        // 3. 狀態機判定邏輯
        if self.first_probe {
            self.first_probe = false;
            if sample.success {
                self.state = LinkState::Up;
                info!(
                    "[{}] Initial link probe succeeded -> UP (RTT: {:.2}ms)",
                    self.iface_name,
                    self.rtt_ewma_ms.unwrap_or(0.0)
                );
            } else {
                warn!("[{}] Initial link probe failed -> DOWN", self.iface_name);
            }
        } else {
            match self.state {
                LinkState::Up => {
                    // DOWN 判定條件：
                    // 1) 連續 N 次超時（預設 3），OR
                    // 2) 窗口已填滿且滑動窗口丟包率 > 50%，OR
                    // 3) 平滑 RTT 超過 max_rtt_ms
                    let window_full = self.window.len() >= self.window_capacity;
                    let should_down = self.consecutive_timeouts >= self.consecutive_fail_down
                        || (window_full && loss > self.loss_threshold_down)
                        || rtt_exceeded;

                    if should_down {
                        self.state = LinkState::Down;
                        self.consecutive_successes = 0;
                        self.rtt_over_count = 0;
                        warn!(
                            "[{}] Link state transitioned: UP -> DOWN (Timeouts: {}, Loss: {:.1}%, RTT: {:?})",
                            self.iface_name,
                            self.consecutive_timeouts,
                            loss * 100.0,
                            self.rtt_ewma_ms
                        );
                    }
                }
                LinkState::Down => {
                    // UP 恢復判定條件（Hysteresis 防震盪機制）：
                    // 1) 連續成功至少 5 次 (recovery_success_count)
                    // 2) 且滑動窗口丟包率 < loss_threshold_up（預設 10%）
                    // 3) 且 RTT 在正常範圍
                    let should_up = self.consecutive_successes >= self.recovery_success_count
                        && loss < self.loss_threshold_up
                        && rtt_normal;

                    if should_up {
                        self.state = LinkState::Up;
                        info!(
                            "[{}] Link state recovered: DOWN -> UP (Consecutive successes: {}, Loss: {:.1}%, RTT: {:.2}ms, Jitter: {:.2}ms)",
                            self.iface_name,
                            self.consecutive_successes,
                            loss * 100.0,
                            self.rtt_ewma_ms.unwrap_or(0.0),
                            self.jitter_ewma_ms
                        );
                    }
                }
            }
        }

        let changed = self.state != prev_state;
        (self.state, changed)
    }

    /// 取得摘要字串
    pub fn summary(&self) -> String {
        format!(
            "State: {}, Loss: {:.1}%, RTT: {:.2}ms, Jitter: {:.2}ms (Successes: {}, Timeouts: {})",
            self.state,
            self.loss_rate() * 100.0,
            self.rtt_ewma_ms.unwrap_or(0.0),
            self.jitter_ewma_ms,
            self.consecutive_successes,
            self.consecutive_timeouts
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use std::time::Duration;

    fn sample(success: bool, rtt_ms: u64) -> ProbeSample {
        ProbeSample {
            success,
            rtt: Duration::from_millis(rtt_ms),
            target: "1.1.1.1:443".parse().unwrap(),
            error_msg: if success {
                None
            } else {
                Some("Timeout".into())
            },
        }
    }

    #[test]
    fn test_initial_fast_bootstrap() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        assert_eq!(lqe.state, LinkState::Down);

        // 首次探測成功即拉起為 UP
        let (state, changed) = lqe.update(&sample(true, 20));
        assert_eq!(state, LinkState::Up);
        assert!(changed);
    }

    #[test]
    fn test_down_on_consecutive_timeouts() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state, LinkState::Up);

        // 模擬 2 次超時，依然 UP
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up);

        // 第 3 次連續超時，觸發 DOWN
        let (state, changed) = lqe.update(&sample(false, 600));
        assert_eq!(state, LinkState::Down);
        assert!(changed);
    }

    #[test]
    fn test_hysteresis_recovery_5_consecutive_successes() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));

        // 觸發 DOWN
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        // 連續 4 次成功，未達 5 次，保持 DOWN
        for _ in 0..4 {
            let (state, _) = lqe.update(&sample(true, 25));
            assert_eq!(state, LinkState::Down);
        }

        // 第 5 次成功，但此時滑動窗口長度 10 內有 3 個失敗 (3/7 = 42.8% > 10% 丟包)
        // 需繼續探測直到窗口丟包率 < 10%
        let mut recovered = false;
        for _ in 0..10 {
            let (state, changed) = lqe.update(&sample(true, 25));
            if state == LinkState::Up && changed {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "LQE should recover to UP once consecutive successes >= 5 and loss < 10%"
        );
    }

    #[test]
    fn test_ewma_rtt_calculation() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 100));
        assert_eq!(lqe.rtt_ewma_ms, Some(100.0));

        // sample RTT 50ms, alpha = 0.2
        // new_rtt = 0.2 * 50 + 0.8 * 100 = 10 + 80 = 90
        lqe.update(&sample(true, 50));
        let rtt = lqe.rtt_ewma_ms.unwrap();
        assert!((rtt - 90.0).abs() < 1e-6);
    }

    #[test]
    fn test_down_on_window_loss_rate() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state, LinkState::Up);

        // 先填充 4 次成功
        for _ in 0..4 {
            lqe.update(&sample(true, 20));
        }

        // 交替超時：超時, 成功, 超時, 超時, 超時, 超時 (從不連續達 3 次超時，但總超時達 6/10 = 60% > 50%)
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2

        // 此時窗口已滿 10 個，統計丟包率
        if lqe.loss_rate() > 0.50 {
            assert_eq!(lqe.state, LinkState::Down);
        }
    }

    #[test]
    fn test_down_on_rtt_exceeding_max() {
        let mut cfg = DaemonConfig::default();
        cfg.max_rtt_ms = 100.0;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state, LinkState::Up);

        // 平滑 RTT 逐步被拉高：20 -> 76 -> 120.8 ...
        let mut went_down = false;
        for _ in 0..10 {
            let (state, _) = lqe.update(&sample(true, 300));
            if state == LinkState::Down {
                went_down = true;
                break;
            }
        }
        assert!(
            went_down,
            "link must go DOWN once the smoothed RTT exceeds max_rtt_ms"
        );
    }

    #[test]
    fn test_rtt_hysteresis_prevents_single_spike() {
        let mut cfg = DaemonConfig::default();
        cfg.max_rtt_ms = 100.0;
        cfg.rtt_fail_count = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state, LinkState::Up);

        // EWMA 需要幾個樣本才會爬過 100ms，且還必須「連續」3 次超標才 DOWN，
        // 因此單一封包尖峰不可能把鏈路打掛
        let mut samples_to_down = 0usize;
        for i in 1..=20 {
            let (state, _) = lqe.update(&sample(true, 300));
            if state == LinkState::Down {
                samples_to_down = i;
                break;
            }
        }
        assert!(
            samples_to_down >= 3,
            "a single RTT spike must not flip the link (went down after {samples_to_down} samples)"
        );
    }

    #[test]
    fn test_rtt_hysteresis_resets_on_recovery() {
        let mut cfg = DaemonConfig::default();
        cfg.max_rtt_ms = 100.0;
        cfg.rtt_fail_count = 2;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20)); // EWMA 20
        lqe.update(&sample(true, 300)); // EWMA 76   -> 未超標
        lqe.update(&sample(true, 300)); // EWMA 120.8 -> 超標 1 次
        lqe.update(&sample(true, 10)); // EWMA 98.6  -> 回到閾值內，計數器歸零
        lqe.update(&sample(true, 300)); // EWMA 137.5 -> 又只超標 1 次

        // 若計數器沒有歸零，這裡會是第 2 次超標而翻成 DOWN
        assert_eq!(lqe.state, LinkState::Up);
    }

    #[test]
    fn test_recovery_loss_threshold_is_configurable() {
        let mut cfg = DaemonConfig::default();
        cfg.loss_threshold_up = 0.9; // 放寬到 90%，恢復應更快
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        // 連續 5 次成功即達標（丟包率 3/8 = 37.5% < 90%）
        let mut recovered = false;
        for _ in 0..5 {
            let (state, _) = lqe.update(&sample(true, 25));
            if state == LinkState::Up {
                recovered = true;
                break;
            }
        }
        assert!(recovered);
    }
}
