use crate::config::DaemonConfig;
use crate::prober::ProbeSample;
use log::{info, warn};
use std::collections::VecDeque;

/// 丢包率比较用的浮点容差。
///
/// 丢包率是分数（例如 1/10 = 0.1），而门槛是设定档的十进位小数；两者数学上相等时
/// double 仍可能差一个 ulp（例：`0.1 + 0.05 > 0.15`、`0.15 - 0.05 < 0.1`）。
/// 边界比较加上这个容差，避免线路因舍入误差卡在降级状态进不来也出不去。
const LOSS_FLOAT_EPS: f64 = 1e-9;

/// 链路当前状态
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

/// 最近一次状态变更的原因。
///
/// 为什么需要：日志原本只说 `Loss: 30%`，而配置的 `loss_threshold_down` 是 50%，
/// 看起来自相矛盾（其实是「连续 3 次超时」触发的）。把它写进日志与状态档，
/// 「为什么被移出 ECMP / 为什么判死」才不需要回头猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateReason {
    /// 连续超时次数达到 `consecutive_fail_down`
    ConsecutiveTimeouts,
    /// 窗口已满且窗口丢包率超过 `loss_threshold_down`
    WindowLoss,
    /// 平滑 RTT 连续超过 `max_rtt_ms`
    Rtt,
    /// 连续成功次数达到 `recovery_success_count` 而恢复 UP
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

/// 链路品质估算器（LQE - Link Quality Estimator）
pub struct LinkQualityEstimator {
    pub iface_name: String,
    /// 当前链路状态
    pub state: LinkState,
    /// 滑动窗口：记录最近 N 次探测结果（true = 成功，false = 丢包/超时）
    window: VecDeque<bool>,
    /// 窗口最大长度（预设 10）
    window_capacity: usize,
    /// 窗口内失败样本数（随 pop/push 增量维护，loss_rate() 因此为 O(1)）
    lost_count: usize,
    /// 即时 RTT 平滑值（EWMA，毫秒）
    pub rtt_ewma_ms: Option<f64>,
    /// 即时抖动 Jitter 平滑值（EWMA，毫秒）
    pub jitter_ewma_ms: f64,
    /// 连续超时次数
    pub consecutive_timeouts: usize,
    /// 连续成功次数（用于 DOWN -> UP 防震荡恢复）
    pub consecutive_successes: usize,
    /// EWMA 权重 Alpha（RTT）
    alpha: f64,
    /// EWMA 权重 Beta（Jitter）
    beta: f64,
    /// 最大容许 RTT（毫秒）
    max_rtt_ms: f64,
    /// 平滑 RTT 连续超标几次才判定 DOWN（滞回，避免单一尖峰震荡）
    rtt_fail_count: usize,
    /// 平滑 RTT 连续超标计数器
    rtt_over_count: usize,
    /// 启动快速引导标记（首次探测若成功直接拉起，避免开机等待 5 次探测）
    first_probe: bool,
    /// 触发 DOWN 的连续超时次数（预设 3）
    consecutive_fail_down: usize,
    /// 触发 DOWN 的窗口丢包率阈值（预设 0.50）
    loss_threshold_down: f64,
    /// 恢复 UP 所需连续成功次数（预设 5）
    recovery_success_count: usize,
    /// 降级（不参与 ECMP）的窗口丢包率门槛（0.0 = 关闭）
    degrade_loss_threshold: f64,
    /// 退出降级所需的连续样本数（`degrade_exit_samples`）
    degrade_exit_samples: usize,
    /// 退出降级的丢包率迟滞量（`degrade_hysteresis`）
    degrade_hysteresis: f64,
    /// 进入降级所需的连续评估次数（`degrade_enter_samples`）
    degrade_enter_samples: usize,
    /// 连续满足进入条件的评估次数（一次不达标即归零）
    degrade_enter_streak: usize,
    /// 降级后至少要离开 ECMP 几个样本才准回来（`degrade_min_out_samples`）
    degrade_min_out_samples: usize,
    /// 已连续处于降级（离开 ECMP）几个样本
    degrade_out_samples: usize,
    /// 当前是否处于降级状态（**带迟滞的状态机**，非单纯比较当下丢包率）
    degraded: bool,
    /// 连续满足退出条件的样本数（严格连续：一次不满足即归零）
    degrade_exit_streak: usize,
    /// 距离上一次「恢复到 UP」已经过的样本数（从未 UP 过的线初始化为窗口大小）。
    ///
    /// 为什么需要：DOWN 期间的失败样本仍留在滑动窗口里，恢复当下窗口丢包率往往
    /// 远高于降级门槛（实测 44%），若立刻据此降级，刚回到 ECMP 的线会被马上移出，
    /// 等窗口滚干净后又加回来 —— 数秒内出现「[两条] -> [一条] -> [两条]」的
    /// 路由抖动，每次变动都会重映射 flow（standard 模式还会 flush conntrack）。
    /// 因此恢复后先让窗口换过一轮，再允许用丢包率降级。
    samples_in_up: usize,
    /// 最近一次状态变更的原因（供日志与状态档说明）
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
            // 退出门槛 = 进入门槛 - 迟滞量，但**不在这里先做减法**：
            // `0.15 - 0.05` 在 double 下是 `0.09999999999999999`，而 1/10 是 `0.1`，
            // 两者在数学上相等却无法用 `<=` 命中，会让线路在 10% 丢包时永久卡在降级。
            // 比较时改用「loss + hysteresis <= threshold + 容差」（见 update_degrade_state）。
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

    /// 取得滑动窗口中的丢包率 (0.0 ~ 1.0)。
    /// 失败计数由 update() 随窗口滑动增量维护，这里是 O(1) 纯读取。
    pub fn loss_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.lost_count as f64 / self.window.len() as f64
    }

    /// 目前窗口内的样本数（状态档用：让「为什么还没降级」看得出来是样本不够）
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// 窗口是否已填满（未填满前不做丢包率判定）
    pub fn window_full(&self) -> bool {
        self.window.len() >= self.window_capacity
    }

    /// 最近一次状态变更的原因（尚未发生过任何变更时为 None）
    pub fn state_reason(&self) -> Option<StateReason> {
        self.last_state_reason
    }

    /// 这条线是否「降级」：不参与 ECMP（但仍继续探测，品质恢复后自动回归）。
    ///
    /// 为什么不能只看「有没有判 DOWN」：介于 `degrade_loss_threshold`（预设 0.20）
    /// 与 `loss_threshold_down`（0.50）之间的线路不会被判 DOWN，于是照样吃一半流量，
    /// 使用者感受就是「有双网卡时经常检查到丢包」。
    ///
    /// 为什么不能是「当下丢包率 >= 门槛」的纯函式：窗口量化步长是 10%（10 个样本、1 次失败
    /// 就是 10%），注入 12%~30% 丢包时窗口丢包率会一直在 10%/20%/30% 之间摆动，
    /// 纯函式每几秒就进出一次降级 → 每次都让 `Active WAN set changed` 重下 ECMP 路由
    /// （实测 20 秒内 5~6 次）。因此改成带迟滞的状态机（见 `update_degrade_state`）。
    ///
    /// 门槛为 0.0 时视为关闭该功能（沿用旧行为），此时永远不降级。
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// 依本次样本更新降级状态机（进入门槛 / 退出门槛 + 最短连续保持）。
    ///
    /// - 进入：尚未降级、窗口已填满、丢包率 >= `degrade_loss_threshold` → 立刻降级并把
    ///   退出累积清零（坏线要快点让出流量，所以进入不加迟滞）。
    /// - 退出：已降级、窗口已填满、丢包率满足
    ///   `loss + degrade_hysteresis <= degrade_loss_threshold`（等价于「进入门槛 - 迟滞」，
    ///   但避开浮点减法的舍入误差）→ 累积一次；达 `degrade_exit_samples` 才真正
    ///   退出。**任何一笔不满足退出条件（含窗口还没填满）都把累积归零**，确保「连续」。
    ///
    /// 两个门槛之间是死区：已在降级状态的线停在 20% 丢包不会被踢回来又踢出去。
    fn update_degrade_state(&mut self, loss: f64, window_full: bool) {
        if self.degrade_loss_threshold <= 0.0 {
            // 功能关闭：永远不降级（沿用旧行为）
            self.degraded = false;
            self.degrade_exit_streak = 0;
            self.degrade_enter_streak = 0;
            self.degrade_out_samples = 0;
            return;
        }
        if !window_full {
            // 样本不足时不做任何判定；累积中的进/出序列都因为「不满足条件」而归零
            self.degrade_exit_streak = 0;
            self.degrade_enter_streak = 0;
            return;
        }
        if !self.degraded {
            // 刚恢复的线：窗口里还有停机期间的失败样本。此时据以降级会让它立刻被
            // 移出 ECMP、几秒后又加回来（实测三次路由变动）。等窗口换过一轮再判定。
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
                    // 这一行是「路由成员为什么变少」的唯一线索：降级本身不会印任何东西，
                    // 只有 `Active WAN set changed` 会出现，排障时完全看不出原因。
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
        // 已降级：累积「已经离开 ECMP 多少拍」，用来挡掉「移出→几秒后回来→又被
        // 打满→又移出」的数秒级循环（每次循环都要重映射既有 flow）。
        self.degrade_out_samples = self.degrade_out_samples.saturating_add(1);
        // 只有丢包率落到退出门槛以下才开始累积「连续」计数。
        // 用加法比较（loss + hysteresis <= threshold）并带一个极小容差，
        // 避免 `0.15 - 0.05 = 0.0999...` 这类浮点舍入让数学上相等的情况判为不达标。
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

    /// 喂入一次探测样本，并更新 EWMA 指标与状态机
    /// 回传：状态是否发生变更（若变更需通知 Route Manager 与 Conntrack Flusher）
    pub fn update(&mut self, sample: &ProbeSample) -> (LinkState, bool) {
        let prev_state = self.state;

        // 这笔样本进来前仍是 UP，就累积「恢复后已过几拍」（给 update_degrade_state 用）。
        if self.state == LinkState::Up {
            self.samples_in_up = self.samples_in_up.saturating_add(1);
        }

        // 1. 维护滑动窗口（连同失败计数一起增量更新）
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

        // 2. 指标更新与计数器
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
                    // EWMA 计算: RTT_new = alpha * RTT_sample + (1 - alpha) * RTT_old
                    let new_rtt = self.alpha * sample_rtt_ms + (1.0 - self.alpha) * current_rtt;
                    // Jitter_new = beta * dev + (1 - beta) * Jitter_old
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

        // 降级判定独立于 UP/DOWN 状态机：降级的线仍是 UP、仍在探测，只是不参与 ECMP。
        // 必须在每个样本都更新（含窗口未填满时把退出累积归零），见 update_degrade_state。
        self.update_degrade_state(loss, window_full);

        // RTT 严重超标同样视为链路不可用（旧版只在 DOWN -> UP 时检查，
        // 导致一条 RTT 爆到数秒但仍能连上的链路会永远维持 UP）。
        // 这里用「连续超标次数」做滞回，避免单一封包尖峰就把链路打挂。
        //
        // 只在**成功样本**上评估：失败（超时）样本不会更新 EWMA，若也计入超标次数，
        // 一条实际在「连续超时」的线可能靠著陈旧的 RTT 值先触发 reason=rtt，
        // 让日志与状态档的归因变成 RTT 而不是 consecutive_timeouts（误导排障）。
        if sample.success {
            if self.rtt_ewma_ms.is_some_and(|r| r > self.max_rtt_ms) {
                self.rtt_over_count = self.rtt_over_count.saturating_add(1);
            } else {
                self.rtt_over_count = 0;
            }
        }
        let rtt_exceeded = self.rtt_over_count >= self.rtt_fail_count;

        // 3. 状态机判定逻辑
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
                    // DOWN 判定条件：
                    // 1) 连续 N 次超时（预设 3），OR
                    // 2) 窗口已填满且滑动窗口丢包率 > 50%，OR
                    // 3) 平滑 RTT 超过 max_rtt_ms
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
                        // 把「实际触发的条件」与「配置门槛」一起写出来，否则只看到
                        // `Loss: 30%` 会与配置的 50% 门槛互相矛盾（其实是连续超时触发的）
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
                    // UP 恢复判定条件（Hysteresis 防震荡机制）：
                    // 1) 连续成功至少 recovery_success_count 次
                    // 2) 且 RTT 在正常范围
                    //
                    // 刻意**不再检查窗口丢包率**：旧版附加 `loss <= loss_threshold_up`，
                    // 而窗口丢包率与 window_size 耦合——window=10、门槛 10% 时等于
                    // 「窗口内最多 1 次失败」，DOWN 由尾部 3 连败触发后要连续 9 次成功
                    // 才把失败样本滚出窗口，设定的 recovery_success_count=5 被静默抬成 9
                    // （实测日志正是 `Consecutive successes: 9`）：DOWN 约 1.5 秒、
                    // UP 要 4.5 秒以上，强不对称 → 线路反复翻转。
                    // 防震荡并未因此消失：回到 UP 之后若品质仍差，上面的 DOWN 判据
                    // （连续超时／窗口丢包率／RTT）会立刻再把它打下去。
                    let should_up =
                        self.consecutive_successes >= self.recovery_success_count && rtt_normal;

                    if should_up {
                        self.state = LinkState::Up;
                        // 恢复后重新起算：本拍上面可能已用残留的停机旧样本判成降级，
                        // 这里覆盖掉，并让后续 window_capacity 拍内不再据旧样本进入降级
                        // （见 samples_in_up）。
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

        // 首次探测成功即拉起为 UP
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

        // 模拟 2 次超时，依然 UP
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up);

        // 第 3 次连续超时，触发 DOWN
        let (state, changed) = lqe.update(&sample(false, 600));
        assert_eq!(state, LinkState::Down);
        assert!(changed);
    }

    #[test]
    fn test_hysteresis_recovery_5_consecutive_successes() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        lqe.update(&sample(true, 20));

        // 触发 DOWN
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        // 连续 4 次成功，未达 5 次，保持 DOWN
        for _ in 0..4 {
            let (state, _) = lqe.update(&sample(true, 25));
            assert_eq!(state, LinkState::Down);
        }

        // 第 5 次成功就必须恢复：此时窗口内仍残留 3 个失败样本，但恢复判据只看
        // recovery_success_count + RTT（FIX-4）。旧逻辑会要求窗口丢包率 <= 10%，
        // 也就是要再把那 3 个失败样本滚出窗口 → 实际需要 9 次连续成功，
        // 把配置的 recovery_success_count=5 静默抬成 9（实测日志 `Consecutive successes: 9`）。
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

        // 交替超时：超时, 成功, 超时, 超时, 超时, 超时 (从不连续达 3 次超时，但总超时达 6/10 = 60% > 50%)
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2
        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600)); // 1
        lqe.update(&sample(false, 600)); // 2

        // 此时窗口已满 10 个，统计丢包率
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

        // EWMA 需要几个样本才会爬过 100ms，且还必须「连续」3 次超标才 DOWN，
        // 因此单一封包尖峰不可能把链路打挂
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
        // FIX-4：恢复判据不再包含窗口丢包率。
        // 旧断言（`loss <= loss_threshold_up`）会让窗口内残留的失败样本把
        // recovery_success_count 架空，语意已变更 → 这里按新语意重写：
        // 3 次超时造成 DOWN 后，第 5 次连续成功就恢复（窗口内仍有 3/8 = 37.5% 失败）。
        let cfg = DaemonConfig::default();
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
        // 恢复当下窗口内确实还有残留失败 → 证明恢复没被窗口丢包率挡住
        assert!(lqe.loss_rate() > 0.10);
    }

    #[test]
    fn test_recovery_counter_resets_on_failure() {
        // 防震荡仍然有效：连续成功累积途中只要出现一次失败就归零，
        // 不是「窗口内累加成功次数」。
        let cfg = DaemonConfig::default();
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
        cfg.recovery_success_count = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        // 连续 3 次成功即达标（与窗口大小无关）
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
        // 回归：恢复当下窗口仍残留停机期间的失败样本（此例 4/10 = 40%，远超 20% 门槛）。
        // 旧行为会立刻把刚回来的线标成 degraded 并移出 ECMP，等窗口滚干净后又加回来，
        // 数秒内出现「[两条] -> [一条] -> [两条]」的路由抖动与随之而来的 flow 重映射。
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
        // 本测试聚焦「恢复后不因窗口内残留的停机样本立刻降级」；
        // 进入迟滞（degrade_enter_samples）另有专门测试，这里设 1 才能用 2 次超时
        // 走到降级（同时不触发连续 3 次超时的 DOWN）。
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

        // 窗口换过一轮之前（接下来全部成功）都不得降级。
        for i in 0..cfg.window_size {
            lqe.update(&sample(true, 25));
            assert!(!lqe.is_degraded(), "恢复后第 {i} 拍就降级了");
        }

        // 保护不是永久关闭降级：窗口换过一轮后，真实的 20% 丢包仍要能降级。
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up, "2 次超时还不到 DOWN 门槛");
        assert!(lqe.is_degraded(), "窗口换过一轮后，20% 丢包仍必须触发降级");
    }

    // -----------------------------------------------------------------------
    // FIX-2：基于实测品质的降级（不参与 ECMP，但仍继续探测）
    // -----------------------------------------------------------------------

    #[test]
    fn test_degrade_requires_a_full_window() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        // 窗口未满（样本不足）时不得降级，即使目前样本全是失败
        for _ in 0..9 {
            lqe.update(&sample(false, 600));
        }
        assert!(!lqe.window_full());
        assert!(!lqe.is_degraded(), "窗口未填满前样本数不足，不能据以降级");

        // 第 10 个样本让窗口填满（10/10 = 100% >= 20%）。此时只累积到第 1 个超标样本，
        // 预设 degrade_enter_samples = 20 还不该降级：单一窗口的达标可能只是
        // 「线路被自己的流量打满、探针刚好超时」这种会自行恢复的抖动。
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!(!lqe.is_degraded(), "进入迟滞（20 个样本）未满足前不得降级");

        // 持续满窗失败：第 19 个连续超标样本仍不降级
        for i in 1..=18 {
            lqe.update(&sample(false, 600));
            assert!(!lqe.is_degraded(), "第 {} 个超标样本还不到 20", i + 1);
        }
        // 第 20 个连续超标样本 → 降级
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "连续 20 个样本超标后必须降级");
    }

    #[test]
    fn test_degrade_threshold_boundary() {
        // 进入迟滞设 1：本测试的焦点是丢包率门槛与退出迟滞，不夹带进入迟滞
        // （degrade_enter_samples 本身见 test_degrade_entry_requires_consecutive_evaluations）。
        let cfg = cfg_degrade_exit_focused(); // degrade_loss_threshold = 0.20
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        // 窗口 10 个样本、1 次失败 = 10% < 20% → 不降级
        for _ in 0..9 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);
        assert!(!lqe.is_degraded(), "10% 未达 20% 门槛");

        // 再一个失败 → 2/10 = 20% >= 20% → 降级（门槛是「达到即降级」）
        lqe.update(&sample(false, 600));
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        assert!(lqe.is_degraded(), "20% 达到门槛即降级");

        // 但仍不该被判死（判死要窗口丢包率 > 50% 或连续 3 次超时）
        assert_eq!(lqe.state, LinkState::Up, "20% 丢包不该判 DOWN");

        // 品质恢复 → 自动回归。
        // FIX-6 之后是**双门槛 + 最短连续保持**：退出门槛 = 0.20 - 0.10 = 0.10，
        // 且要连续 6 拍达标，所以前 8 拍（窗口仍有 2 次失败 = 20%）不算数。
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

    // -----------------------------------------------------------------------
    // FIX-6：降级的双门槛迟滞 + 最短连续保持
    //
    // 为什么要这组测试：窗口长度 10 的量化步长是 10%，注入 12%~30% 丢包时窗口丢包率
    // 会在 10% / 20% / 30% 之间摆动。旧的纯函式 `loss_rate() >= 0.20` 于是每几秒
    // 进出一次降级 → 每次都让「Active WAN set changed」重下 ECMP 路由（实测 20 秒内 5~6 次）。
    // -----------------------------------------------------------------------

    /// 降级「退出/迟滞」测试用的设定：进入迟滞设 1（单一窗口达标即降级）、
    /// 最短离开时间设 0。
    ///
    /// 为什么：本组测试的取样点是「已降级 + 窗口恰好 20%」，走最短进入路径才不必为了
    /// 触发 2 拍进入迟滞而把窗口弄成 30%（那会改变退出门槛的取样点）。
    /// 进入迟滞（`degrade_enter_samples`）与最短离开时间（`degrade_min_out_samples`）
    /// 本身另有专门测试。
    fn cfg_degrade_exit_focused() -> DaemonConfig {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_enter_samples = 1;
        cfg.degrade_min_out_samples = 0;
        cfg
    }

    /// 把 lqe 推进到「已降级、窗口 = [F,F,S*8]（恰好 20%）、退出累积 = 0」的状态。
    ///
    /// 20% 正好是进入门槛，同时远高于退出门槛（20% - 10% = 10%），是迟滞判定最关键的取样点。
    fn enter_degraded_holding_twenty_percent(lqe: &mut LinkQualityEstimator) {
        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "窗口 20% 应达进入门槛（预设 0.20）");

        // 再喂 8 次成功，把两个失败样本推到窗口最前面（窗口仍是 20%）
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

        // 周期序列 [F,F,S*8]：任何 10 长窗口都恰好 2 次失败 → 丢包率永远是 20%。
        // 旧版纯函式在这个点上会反复「降级（20% >= 0.20）/ 退出（20% > 0.10 其实不会退出）」
        // ── 真正的抖动来自 20%↔10% 的摆动，这里先确认「停在 20% 不退出」。
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

        // 只有连续达标（<= 10%）满 6 拍才退出：第 1 拍起窗口就只剩 1 个失败样本，
        // 第 5 拍仍在降级，第 6 拍才退出。
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

        // 连续达标 3 拍（窗口丢包率 10% → 0% → 0%）
        for _ in 0..3 {
            lqe.update(&sample(true, 20));
        }
        assert_eq!(lqe.degrade_exit_streak, 3);

        // 中间夹一次不满足（窗口回到 20%）→ 前面 3 拍全部作废
        lqe.update(&sample(false, 600)); // 窗口滚掉 1 个失败样本，仍是 10%，达标
        lqe.update(&sample(false, 600)); // 20% → 不达标，累积归零
        assert_eq!(
            lqe.degrade_exit_streak, 0,
            "一次不满足就必须清零（严格连续）"
        );
        assert!(lqe.is_degraded(), "累积归零不等于退出降级");

        // 之后必须重新凑满连续 6 拍：前 8 拍窗口仍有 2 次失败，第 9 拍才开始重新累积
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
        // 同一个「窗口丢包率稳定停在 10%」的序列（周期 [F,S*9]：每个 10 长窗口恰好 1 次失败），
        // 两种迟滞量给出不同结果：
        //   预设 0.10 → 退出门槛 0.10 → 10% 达标，连续 6 拍后退出降级；
        //   调成 0.15 → 退出门槛 0.05 → 10% 不达标，永远留在降级。
        for (hysteresis, expect_exit) in [(0.10_f64, true), (0.15, false)] {
            let mut cfg = cfg_degrade_exit_focused();
            cfg.degrade_hysteresis = hysteresis;
            let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
            enter_degraded_holding_twenty_percent(&mut lqe);

            lqe.update(&sample(true, 20)); // 窗口滚掉一个失败样本 → [F,S*9] = 10%
            assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);

            // 两轮「1 次失败 + 9 次成功」的周期序列
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
        // 回归测试：门槛 0.15、迟滞 0.05 时，退出门槛数学上是 10%。
        // 旧版用 `0.15 - 0.05`（= 0.09999999999999999）比较，而窗口丢包率 1/10 = 0.1，
        // `0.1 <= 0.0999...` 恒为 false → 线路即使稳定在 10% 也永久卡在降级。
        let mut cfg = cfg_degrade_exit_focused();
        cfg.degrade_loss_threshold = 0.15;
        cfg.degrade_hysteresis = 0.05;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        // 周期序列 [F,S*9]：每个 10 长窗口恰好 1 次失败 = 10%，
        // 属于「loss + hysteresis <= threshold」的边界，应能连续达标后退出。
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
        // 回归（实机 2026-09）：隧道型 WAN 满载时 SYN 探针偶尔超时 → 单一窗口刚好 20%，
        // 旧行为立刻把该线移出 ECMP（全部流量瞬时压到另一条线、10 秒后又加回来），
        // 使用者看到的是「一条线突然很卡 + 连线一直断」。新的进入条件要求
        // 「连续 degrade_enter_samples 个样本都超标」，短暂抖动不该降级。
        let cfg = DaemonConfig::default(); // enter = 20 samples, window = 10
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..10 {
            lqe.update(&sample(true, 20));
        }
        assert!(lqe.window_full());

        // 短暂抖动：一个窗口内 2 次超时（20%），之后恢复 → 全程不得降级
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        for i in 0..12 {
            lqe.update(&sample(true, 20));
            assert!(!lqe.is_degraded(), "第 {i} 拍：短暂抖动不得降级");
        }
        assert_eq!(lqe.degrade_enter_streak, 0, "掉回门槛以下必须重新累积");

        // 持续劣化：连续超时（窗口丢包率只升不降）→ 累积满 20 个超标样本才降级。
        // 第 1 个超时样本的窗口丢包率只有 10%，所以 20 个「超标」样本约需要 21 次超时。
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
        // 设 1 = 旧行为（单一窗口达标即降级），确认这个旋钮真的能还原旧语意。
        let mut cfg = DaemonConfig::default();
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
        // 回归（实机 2026-09）：线路因为被打满而降级后，流量一移走它就立刻变好，
        // 「移出 → 5 秒后回来 → 又被打满 → 又移出」形成数秒级循环，
        // 每次循环都重映射既有 flow。最短离开时间让它在外面多待一会。
        let mut cfg = DaemonConfig::default();
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

        // 恢复到 0% 丢包，但离开 ECMP 还不到 20 个样本 → 不得回归
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
        // 回归：失败（超时）样本不更新 EWMA，也不该累积 RTT 连续超标计数。
        // 旧版会让一条「连续超时」的线靠陈旧的高 RTT 先以 reason=rtt 判 DOWN，
        // 把排障方向带偏（明明该看 consecutive_timeouts）。
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
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        assert_eq!(lqe.state_reason(), None);

        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state_reason(), Some(StateReason::Recovery));

        // 连续超时触发（此时窗口丢包率仅 30%，与 50% 门槛无关 → 原因必须说清楚）
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
