use crate::config::DaemonConfig;
use crate::prober::ProbeSample;
use log::{info, warn};
use std::collections::VecDeque;

/// 边界比较的浮点容差：避免 `0.15 - 0.05 < 0.1` 这类 ulp 误差让线路永久卡在降级。
const LOSS_FLOAT_EPS: f64 = 1e-9;

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

/// 最近一次状态变更的原因（写入日志与状态档：单看 `Loss: 30%` 与 50% 门槛会自相矛盾）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateReason {
    ConsecutiveTimeouts,
    WindowLoss,
    Rtt,
    Recovery,
}

impl StateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StateReason::ConsecutiveTimeouts => "consecutive_timeouts",
            StateReason::WindowLoss => "window_loss",
            StateReason::Rtt => "rtt",
            StateReason::Recovery => "recovery",
        }
    }
}

pub struct LinkQualityEstimator {
    pub iface_name: String,
    pub state: LinkState,
    /// 最近 N 次探测的成功与否（true = 成功）
    window: VecDeque<bool>,
    window_capacity: usize,
    /// 窗口内失败数；随 pop/push 增量维护，loss_rate() 因此是 O(1)
    lost_count: usize,
    /// 平滑 RTT（EWMA，毫秒）
    pub rtt_ewma_ms: Option<f64>,
    pub jitter_ewma_ms: f64,
    pub consecutive_timeouts: usize,
    pub consecutive_successes: usize,
    alpha: f64,
    beta: f64,
    max_rtt_ms: f64,
    rtt_fail_count: usize,
    rtt_over_count: usize,
    /// 首次探测若成功直接拉起，避免开机多等几拍
    first_probe: bool,
    consecutive_fail_down: usize,
    loss_threshold_down: f64,
    recovery_success_count: usize,
    /// 0.0 = 关闭降级功能
    degrade_loss_threshold: f64,
    degrade_exit_samples: usize,
    degrade_hysteresis: f64,
    degrade_enter_samples: usize,
    degrade_enter_streak: usize,
    degrade_min_out_samples: usize,
    degrade_out_samples: usize,
    degraded: bool,
    degrade_exit_streak: usize,
    /// 距离上次恢复 UP 的样本数；恢复后窗口仍留有停机期失败样本，须先换过一轮才准降级。
    samples_in_up: usize,
    last_state_reason: Option<StateReason>,
}

impl LinkQualityEstimator {
    pub fn new(iface_name: String, config: &DaemonConfig) -> Self {
        Self {
            iface_name,
            state: LinkState::Down, // 启动初期先标记为 DOWN，探测通过后迅速拉起
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
            recovery_success_count: config.recovery_success_count,
            degrade_loss_threshold: config.degrade_loss_threshold,
            degrade_exit_samples: config.degrade_exit_samples.max(1),
            // 退出门槛不预先做减法（0.15 - 0.05 在 double 下 < 0.1），比较时改用加法 + 容差。
            degrade_hysteresis: config.degrade_hysteresis.max(0.0),
            degrade_enter_samples: config.degrade_enter_samples.max(1),
            degrade_enter_streak: 0,
            degrade_min_out_samples: config.degrade_min_out_samples,
            degrade_out_samples: 0,
            degraded: false,
            degrade_exit_streak: 0,
            // 从未 UP 过的线（例如开机一路失败）不受此保护，维持原本的降级行为。
            samples_in_up: config.window_size,
            last_state_reason: None,
        }
    }

    /// 滑动窗口丢包率 (0.0 ~ 1.0)；失败计数增量维护，这里是 O(1) 纯读取。
    pub fn loss_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.lost_count as f64 / self.window.len() as f64
    }

    /// 目前窗口内的样本数（状态档用）。
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    pub fn window_full(&self) -> bool {
        self.window.len() >= self.window_capacity
    }

    pub fn state_reason(&self) -> Option<StateReason> {
        self.last_state_reason
    }

    /// 降级 = 不参与 ECMP（仍持续探测，恢复后自动回归）。
    ///
    /// 带迟滞的状态机：窗口量化步长 10%，纯比较当下丢包率会让线路每几秒进出一次降级，每次
    /// 都重下 ECMP 路由（实测 20 秒内 5~6 次）。门槛 0.0 表示关闭此功能。
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// 依本次样本更新降级状态机。
    ///
    /// 进入：窗口填满且 loss >= 门槛，连续 enter_samples 拍（坏线要快让出流量，不加迟滞）。
    /// 退出：`loss + hysteresis <= 门槛`（避开浮点减法）连续 exit_samples 拍，且已离开 min_out_samples 拍。
    fn update_degrade_state(&mut self, loss: f64, window_full: bool) {
        if self.degrade_loss_threshold <= 0.0 {
            self.degraded = false;
            self.degrade_exit_streak = 0;
            self.degrade_enter_streak = 0;
            self.degrade_out_samples = 0;
            return;
        }
        if !window_full {
            self.degrade_exit_streak = 0;
            self.degrade_enter_streak = 0;
            return;
        }
        if !self.degraded {
            // 刚恢复的线窗口里还有停机期失败样本，据此降级会造成数秒路由抖动 → 先等窗口换一轮。
            if self.samples_in_up < self.window_capacity {
                self.degrade_enter_streak = 0;
                return;
            }
            if loss >= self.degrade_loss_threshold {
                self.degrade_enter_streak = self.degrade_enter_streak.saturating_add(1);
                if self.degrade_enter_streak >= self.degrade_enter_samples {
                    self.degraded = true;
                    self.degrade_out_samples = 0;
                    self.degrade_exit_streak = 0;
                    self.degrade_enter_streak = 0;
                    // 降级本身不印任何东西，这行是「路由成员为何变少」的唯一线索。
                    warn!(
                        "[{}] Line degraded: removed from ECMP (window loss {:.1}% >= threshold {:.1}% \
                         for {} consecutive samples, {} failures in the last {} samples). \
                         It keeps being probed and rejoins ECMP automatically once it recovers \
                         (at least {} samples out).",
                        self.iface_name,
                        loss * 100.0,
                        self.degrade_loss_threshold * 100.0,
                        self.degrade_enter_samples,
                        self.lost_count,
                        self.window.len(),
                        self.degrade_min_out_samples
                    );
                }
            } else {
                self.degrade_enter_streak = 0;
            }
            return;
        }
        // 累积离开 ECMP 的拍数，挡掉「移出→马上回来→又被移出」的数秒循环。
        self.degrade_out_samples = self.degrade_out_samples.saturating_add(1);
        // 丢包率落到退出门槛以下（加法比较 + 容差，避开浮点舍入）才开始累积连续次数。
        if loss + self.degrade_hysteresis <= self.degrade_loss_threshold + LOSS_FLOAT_EPS {
            self.degrade_exit_streak = self.degrade_exit_streak.saturating_add(1);
            if self.degrade_exit_streak >= self.degrade_exit_samples
                && self.degrade_out_samples >= self.degrade_min_out_samples
            {
                let out = self.degrade_out_samples;
                self.degraded = false;
                self.degrade_exit_streak = 0;
                self.degrade_out_samples = 0;
                self.degrade_enter_streak = 0;
                info!(
                    "[{}] Line recovered from degraded state: rejoining ECMP after {} samples out \
                     (window loss {:.1}% <= exit threshold {:.1}%)",
                    self.iface_name,
                    out,
                    loss * 100.0,
                    (self.degrade_loss_threshold - self.degrade_hysteresis) * 100.0
                );
            }
        } else {
            self.degrade_exit_streak = 0;
        }
    }

    /// 喂入一次探测样本；回传 (状态, 是否变更)（变更需通知 Route Manager 与 Conntrack Flusher）。
    pub fn update(&mut self, sample: &ProbeSample) -> (LinkState, bool) {
        let prev_state = self.state;

        if self.state == LinkState::Up {
            self.samples_in_up = self.samples_in_up.saturating_add(1);
        }

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
                    let new_rtt = self.alpha * sample_rtt_ms + (1.0 - self.alpha) * current_rtt;
                    let new_jitter = self.beta * dev + (1.0 - self.beta) * self.jitter_ewma_ms;

                    self.rtt_ewma_ms = Some(new_rtt);
                    self.jitter_ewma_ms = new_jitter;
                }
            }
        } else {
            self.consecutive_timeouts += 1;
            self.consecutive_successes = 0; // 一旦超时，恢复累积次数归零（严格防震荡）
        }

        let loss = self.loss_rate();
        let rtt_normal = self.rtt_ewma_ms.is_some_and(|r| r <= self.max_rtt_ms);
        let window_full = self.window_full();

        // 降级判定必须每拍都跑（窗口未满时也要把退出累积归零），见 update_degrade_state。
        self.update_degrade_state(loss, window_full);

        // 平滑 RTT 连续超标 rtt_fail_count 次同样判 DOWN（滞回，避免单一封包尖峰打挂链路）。
        // 只在成功样本上累积：失败样本不更新 EWMA，靠陈旧 RTT 会把归因误成 rtt 而非 consecutive_timeouts。
        if sample.success {
            if self.rtt_ewma_ms.is_some_and(|r| r > self.max_rtt_ms) {
                self.rtt_over_count = self.rtt_over_count.saturating_add(1);
            } else {
                self.rtt_over_count = 0;
            }
        }
        let rtt_exceeded = self.rtt_over_count >= self.rtt_fail_count;

        if self.first_probe {
            self.first_probe = false;
            if sample.success {
                self.state = LinkState::Up;
                self.last_state_reason = Some(StateReason::Recovery);
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
                    let down_reason = if self.consecutive_timeouts >= self.consecutive_fail_down {
                        Some(StateReason::ConsecutiveTimeouts)
                    } else if window_full && loss > self.loss_threshold_down {
                        Some(StateReason::WindowLoss)
                    } else if rtt_exceeded {
                        Some(StateReason::Rtt)
                    } else {
                        None
                    };

                    if let Some(reason) = down_reason {
                        self.state = LinkState::Down;
                        self.consecutive_successes = 0;
                        self.rtt_over_count = 0;
                        self.last_state_reason = Some(reason);
                        // 印出实际触发条件与配置门槛，否则 Loss 30% 与门槛 50% 看似矛盾。
                        warn!(
                            "[{}] Link state transitioned: UP -> DOWN (reason: {} | timeouts: {} (fail threshold {}) | window loss: {:.1}% (down threshold {:.1}%) | RTT: {:?} (max {:.0}ms))",
                            self.iface_name,
                            reason.as_str(),
                            self.consecutive_timeouts,
                            self.consecutive_fail_down,
                            loss * 100.0,
                            self.loss_threshold_down * 100.0,
                            self.rtt_ewma_ms,
                            self.max_rtt_ms
                        );
                    }
                }
                LinkState::Down => {
                    // 恢复判据刻意不看窗口丢包率：与 window_size 耦合会把 recovery_success_count=5 静默抬到 9，
                    // 造成 DOWN 1.5 秒 / UP 4.5 秒的强不对称而反复翻转；回 UP 后品质仍差会被上面的 DOWN 判据打下去。
                    let should_up =
                        self.consecutive_successes >= self.recovery_success_count && rtt_normal;

                    if should_up {
                        self.state = LinkState::Up;
                        // 恢复后重新起算：覆盖本拍可能已用残留停机旧样本判成的降级。
                        self.samples_in_up = 0;
                        self.degraded = false;
                        self.degrade_exit_streak = 0;
                        self.last_state_reason = Some(StateReason::Recovery);
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
            target: "223.5.5.5:53".parse().unwrap(),
            error_msg: if success {
                None
            } else {
                Some("Timeout".into())
            },
            error_kind: if success {
                None
            } else {
                Some(crate::prober::ProbeErrorKind::Timeout)
            },
        }
    }

    #[test]
    fn test_initial_fast_bootstrap() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        assert_eq!(lqe.state, LinkState::Down);

        let (state, changed) = lqe.update(&sample(true, 20));
        assert_eq!(state, LinkState::Up);
        assert!(changed);
    }

    #[test]
    fn test_down_on_consecutive_timeouts() {
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state, LinkState::Up);

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up);

        let (state, changed) = lqe.update(&sample(false, 600));
        assert_eq!(state, LinkState::Down);
        assert!(changed);
    }

    #[test]
    fn test_hysteresis_recovery_5_consecutive_successes() {
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        for _ in 0..4 {
            let (state, _) = lqe.update(&sample(true, 25));
            assert_eq!(state, LinkState::Down);
        }

        // 窗口内仍有 3 个失败样本，但恢复判据只看连续成功数（旧逻辑会被窗口数学抬成 9 次）。
        let (state, changed) = lqe.update(&sample(true, 25));
        assert_eq!(
            state,
            LinkState::Up,
            "配置 5 次连续成功就该恢复，不能被窗口数学抬成 9 次"
        );
        assert!(changed);
        assert_eq!(lqe.state_reason(), Some(StateReason::Recovery));
    }

    #[test]
    fn test_ewma_rtt_calculation() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 100));
        assert_eq!(lqe.rtt_ewma_ms, Some(100.0));

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

        for _ in 0..4 {
            lqe.update(&sample(true, 20));
        }

        // 交替超时凑到 60% 窗口丢包率且从不连续 3 次超时。
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2

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

        // EWMA 要几拍才爬过阈值，且须连续 3 次超标 → 单一尖峰不会打挂链路。
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
        lqe.update(&sample(true, 300)); // EWMA 76   -> 未超标
        lqe.update(&sample(true, 300)); // EWMA 120.8 -> 超标 1 次
        lqe.update(&sample(true, 10)); // EWMA 98.6  -> 回到阈值内，计数器归零
        lqe.update(&sample(true, 300)); // EWMA 137.5 -> 又只超标 1 次

        // 若计数器没有归零，这里会是第 2 次超标而翻成 DOWN
        assert_eq!(lqe.state, LinkState::Up);
    }

    #[test]
    fn test_recovery_is_not_gated_by_window_loss() {
        // FIX-4：恢复判据不含窗口丢包率（3 次超时后第 5 次成功即恢复，窗口仍 37.5% 失败）。
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        for i in 1..5 {
            let (state, _) = lqe.update(&sample(true, 25));
            assert_eq!(state, LinkState::Down, "第 {i} 次成功还不到门槛");
        }
        let (state, changed) = lqe.update(&sample(true, 25));
        assert_eq!(state, LinkState::Up);
        assert!(changed);
        assert!(lqe.loss_rate() > 0.10);
    }

    #[test]
    fn test_recovery_counter_resets_on_failure() {
        // 连续成功累积途中出现一次失败即归零（不是窗口内累加）。
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        for _ in 0..4 {
            lqe.update(&sample(true, 25));
        }
        lqe.update(&sample(false, 600)); // 归零
        for _ in 0..4 {
            lqe.update(&sample(true, 25));
        }
        assert_eq!(
            lqe.state,
            LinkState::Down,
            "一次失败必须把连续成功计数归零，不能在窗口内凑数恢复"
        );
    }

    #[test]
    fn test_recovery_success_count_is_configurable() {
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        let mut recovered = false;
        for _ in 0..3 {
            let (state, _) = lqe.update(&sample(true, 25));
            if state == LinkState::Up {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "recovery_success_count=3 应在 3 次连续成功后恢复"
        );
    }

    #[test]
    fn test_recovery_does_not_immediately_degrade() {
        // 回归：恢复当下窗口仍有 40% 停机旧样本，旧行为会立刻降级造成数秒路由抖动。
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
        // 聚焦「恢复后不立刻降级」；开启降级且 enter_samples 设 1 才能用 2 次超时走到降级。
        cfg.degrade_loss_threshold = 0.20;
        cfg.degrade_enter_samples = 1;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        for _ in 0..4 {
            lqe.update(&sample(false, 600));
        }
        assert_eq!(lqe.state, LinkState::Down);

        for _ in 0..5 {
            lqe.update(&sample(true, 25));
        }
        assert_eq!(lqe.state, LinkState::Up);
        assert!(
            lqe.loss_rate() > cfg.degrade_loss_threshold,
            "前提：窗口内仍有超过门槛的停机旧样本"
        );
        assert!(!lqe.is_degraded(), "恢复后不得因窗口内的停机旧样本立刻降级");

        for i in 0..cfg.window_size {
            lqe.update(&sample(true, 25));
            assert!(!lqe.is_degraded(), "恢复后第 {i} 拍就降级了");
        }

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up, "2 次超时还不到 DOWN 门槛");
        assert!(lqe.is_degraded(), "窗口换过一轮后，20% 丢包仍必须触发降级");
    }

    #[test]
    fn test_degrade_requires_a_full_window() {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.20;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..9 {
            lqe.update(&sample(false, 600));
        }
        assert!(!lqe.window_full());
        assert!(!lqe.is_degraded(), "窗口未填满前样本数不足，不能据以降级");

        // 满窗 100% 只累积 1 个超标样本，预设 enter=20 仍不降级（单窗口达标可能只是抖动）。
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!(!lqe.is_degraded(), "进入迟滞（20 个样本）未满足前不得降级");

        for i in 1..=18 {
            lqe.update(&sample(false, 600));
            assert!(!lqe.is_degraded(), "第 {} 个超标样本还不到 20", i + 1);
        }
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "连续 20 个样本超标后必须降级");
    }

    #[test]
    fn test_degrade_threshold_boundary() {
        let cfg = cfg_degrade_exit_focused(); // degrade_loss_threshold = 0.20
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..9 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);
        assert!(!lqe.is_degraded(), "10% 未达 20% 门槛");

        lqe.update(&sample(false, 600));
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        assert!(lqe.is_degraded(), "20% 达到门槛即降级");

        assert_eq!(lqe.state, LinkState::Up, "20% 丢包不该判 DOWN");

        // FIX-6：退出门槛 = 0.20 - 0.10 = 0.10 且需连续 6 拍，前 8 拍窗口仍 20% 不算数。
        for i in 1..=8 {
            lqe.update(&sample(true, 20));
            assert!(
                lqe.is_degraded(),
                "第 {i} 拍窗口丢包率仍是 20%，高于退出门槛 10%，不得退出降级"
            );
        }
        for i in 1..6 {
            lqe.update(&sample(true, 20));
            assert!(lqe.is_degraded(), "连续达标 {i} 拍 < 6，不得退出降级");
        }
        lqe.update(&sample(true, 20));
        assert!(
            !lqe.is_degraded(),
            "连续 6 拍窗口丢包率 <= 10% 后应自动恢复承载资格"
        );
    }

    #[test]
    fn test_degrade_disabled_by_zero_threshold() {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.0; // 0.0 = 关闭
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..10 {
            lqe.update(&sample(false, 600));
        }
        assert!(lqe.window_full());
        assert!(!lqe.is_degraded(), "门槛 0.0 代表关闭降级功能");
        assert_eq!(lqe.state, LinkState::Down, "全丢包仍由既有的 DOWN 判据处理");
    }

    /// 退出/迟滞测试用设定：开启降级 0.20、enter_samples=1、min_out=0（走最短进入路径）。
    fn cfg_degrade_exit_focused() -> DaemonConfig {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.20;
        cfg.degrade_enter_samples = 1;
        cfg.degrade_min_out_samples = 0;
        cfg
    }

    /// 推到「已降级、窗口 = [F,F,S*8]（恰好 20%）、退出累积 = 0」的状态。
    fn enter_degraded_holding_twenty_percent(lqe: &mut LinkQualityEstimator) {
        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "窗口 20% 应达进入门槛（预设 0.20）");

        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        assert_eq!(
            lqe.degrade_exit_streak, 0,
            "20% 不满足退出条件，累积必须为 0"
        );
    }

    #[test]
    fn test_degrade_hysteresis_holds_in_the_dead_zone() {
        let cfg = cfg_degrade_exit_focused(); // 进入 0.20 / 退出 0.10 / 连续 6 拍
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        // 周期 [F,F,S*8]：任何 10 长窗口恒 20%，停在死区内不得退出。
        for round in 0..10 {
            lqe.update(&sample(false, 600));
            lqe.update(&sample(false, 600));
            for _ in 0..8 {
                lqe.update(&sample(true, 20));
            }
            assert!(
                (lqe.loss_rate() - 0.20).abs() < 1e-9,
                "第 {round} 轮窗口应稳定在 20%"
            );
            assert!(lqe.is_degraded(), "20% 落在死区内，不得退出降级");
            assert_eq!(lqe.degrade_exit_streak, 0, "20% 不达退出门槛，累积必须归零");
        }

        for i in 1..=5 {
            lqe.update(&sample(true, 20));
            assert!(lqe.is_degraded(), "连续达标 {i} 拍 < 6，不得退出降级");
        }
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "连续第 6 拍达标后才退出降级");
    }

    #[test]
    fn test_degrade_exit_streak_resets_on_a_single_violation() {
        let cfg = cfg_degrade_exit_focused();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        for _ in 0..3 {
            lqe.update(&sample(true, 20));
        }
        assert_eq!(lqe.degrade_exit_streak, 3);

        lqe.update(&sample(false, 600)); // 窗口滚掉 1 个失败样本，仍是 10%，达标
        lqe.update(&sample(false, 600)); // 20% → 不达标，累积归零
        assert_eq!(
            lqe.degrade_exit_streak, 0,
            "一次不满足就必须清零（严格连续）"
        );
        assert!(lqe.is_degraded(), "累积归零不等于退出降级");

        for i in 1..=13 {
            lqe.update(&sample(true, 20));
            assert!(
                lqe.is_degraded(),
                "第 {i} 拍不得退出（连续计数已于 20% 那拍归零）"
            );
        }
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "重新累积到连续 6 拍后才退出");
    }

    #[test]
    fn test_degrade_exit_samples_is_configurable() {
        let mut cfg = cfg_degrade_exit_focused();
        cfg.degrade_exit_samples = 2; // 连续 2 拍达标即退出
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        lqe.update(&sample(true, 20));
        assert!(lqe.is_degraded(), "连续达标 1 拍 < 2，不得退出降级");
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "连续达标 2 拍即达门槛，应退出降级");
    }

    #[test]
    fn test_degrade_hysteresis_is_configurable() {
        // 同样稳定 10% 丢包：迟滞 0.10 → 退出门槛 0.10 会退出；迟滞 0.15 → 门槛 0.05 永远留在降级。
        for (hysteresis, expect_exit) in [(0.10_f64, true), (0.15, false)] {
            let mut cfg = cfg_degrade_exit_focused();
            cfg.degrade_hysteresis = hysteresis;
            let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
            enter_degraded_holding_twenty_percent(&mut lqe);

            lqe.update(&sample(true, 20)); // 窗口滚掉一个失败样本 → [F,S*9] = 10%
            assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);

            for _ in 0..2 {
                lqe.update(&sample(false, 600));
                for _ in 0..9 {
                    lqe.update(&sample(true, 20));
                    assert!(
                        (lqe.loss_rate() - 0.10).abs() < 1e-9,
                        "周期序列应让窗口丢包率稳定停在 10%"
                    );
                }
            }

            assert_eq!(
                lqe.is_degraded(),
                !expect_exit,
                "迟滞 {hysteresis} 下，稳定 10% 丢包的退出结果与预期不符"
            );
        }
    }

    #[test]
    fn test_degrade_exit_boundary_survives_float_rounding() {
        // 回归：退出门槛 0.15-0.05 数学上 = 10%，用减法比较会被浮点舍入永久卡在降级。
        let mut cfg = cfg_degrade_exit_focused();
        cfg.degrade_loss_threshold = 0.15;
        cfg.degrade_hysteresis = 0.05;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        let mut exited = false;
        for i in 0..20 {
            let s = if i % 10 == 0 {
                sample(false, 600)
            } else {
                sample(true, 20)
            };
            lqe.update(&s);
            if !lqe.is_degraded() {
                exited = true;
                break;
            }
        }
        assert!(
            exited,
            "稳定 10% 丢包（退出门槛）必须能退出降级，不得因浮点舍入被永久卡住"
        );
    }

    #[test]
    fn test_degrade_entry_requires_sustained_loss() {
        // 回归（实机 2026-09）：单一窗口刚好 20% 曾立刻移出 ECMP；改为须连续 enter_samples 拍超标。
        let mut cfg = DaemonConfig::default(); // enter = 20 samples, window = 10
        cfg.degrade_loss_threshold = 0.20;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..10 {
            lqe.update(&sample(true, 20));
        }
        assert!(lqe.window_full());

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        for i in 0..12 {
            lqe.update(&sample(true, 20));
            assert!(!lqe.is_degraded(), "第 {i} 拍：短暂抖动不得降级");
        }
        assert_eq!(lqe.degrade_enter_streak, 0, "掉回门槛以下必须重新累积");

        // 第 1 个超时样本窗口丢包率仅 10%，故需约 21 次超时凑满 20 个超标样本。
        for i in 1..=20 {
            lqe.update(&sample(false, 600));
            assert!(
                !lqe.is_degraded(),
                "第 {i} 个样本尚未累积满 20 个超标样本，不得降级"
            );
        }
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "持续劣化累积满 20 个超标样本后必须降级");
    }

    #[test]
    fn test_degrade_enter_samples_one_degrades_immediately() {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.20;
        cfg.degrade_enter_samples = 1;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        assert!(!lqe.is_degraded(), "10% 未达门槛");
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "20% 且进入迟滞为 1 → 立即降级");
    }

    #[test]
    fn test_degrade_min_out_samples_delays_reentry() {
        // 回归（实机 2026-09）：移出→5 秒后回来→又被移出，每次循环都重映射 flow；min_out 让它多待一会。
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.20;
        cfg.degrade_enter_samples = 1;
        cfg.degrade_exit_samples = 1; // 达标 1 拍即可退出（把焦点放在最短离开时间）
        cfg.degrade_min_out_samples = 20;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "前提：已降级");

        for i in 1..=19 {
            lqe.update(&sample(true, 20));
            assert!(lqe.is_degraded(), "第 {i} 拍：未满足最短离开时间不得回归");
        }
        assert_eq!(lqe.loss_rate(), 0.0, "此时丢包率已回到 0%");
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "满 20 个样本后才准回到 ECMP");
    }

    #[test]
    fn test_timeouts_do_not_accumulate_rtt_over_count() {
        // 回归：失败样本不更新 EWMA，也不得累积 RTT 超标计数（否则归因被陈旧 RTT 误成 rtt）。
        let mut cfg = DaemonConfig::default();
        cfg.max_rtt_ms = 50.0;
        cfg.rtt_fail_count = 2;
        cfg.consecutive_fail_down = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 500)); // EWMA 超标 1 次
        assert_eq!(lqe.state, LinkState::Up);

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);
        assert_eq!(
            lqe.state_reason(),
            Some(StateReason::ConsecutiveTimeouts),
            "应由连续超时触发，而不是被陈旧 RTT 误导成 rtt"
        );
    }

    #[test]
    fn test_state_reason_reports_triggering_condition() {
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        assert_eq!(lqe.state_reason(), None);

        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state_reason(), Some(StateReason::Recovery));

        // 连续超时触发时窗口丢包率仅 30%，与 50% 门槛无关 → 原因必须说清楚。
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);
        assert_eq!(lqe.state_reason(), Some(StateReason::ConsecutiveTimeouts));
        assert_eq!(
            StateReason::ConsecutiveTimeouts.as_str(),
            "consecutive_timeouts"
        );
    }
}
