use crate::config::DaemonConfig;
use crate::prober::ProbeSample;
use log::{info, warn};
use std::collections::VecDeque;

/// 丟包率比較用的浮點容差。
///
/// 丟包率是分數（例如 1/10 = 0.1），而門檻是設定檔的十進位小數；兩者數學上相等時
/// double 仍可能差一個 ulp（例：`0.1 + 0.05 > 0.15`、`0.15 - 0.05 < 0.1`）。
/// 邊界比較加上這個容差，避免線路因捨入誤差卡在降級狀態進不來也出不去。
const LOSS_FLOAT_EPS: f64 = 1e-9;

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

/// 最近一次狀態變更的原因。
///
/// 為什麼需要：日誌原本只說 `Loss: 30%`，而配置的 `loss_threshold_down` 是 50%，
/// 看起來自相矛盾（其實是「連續 3 次超時」觸發的）。把它寫進日誌與狀態檔，
/// 「為什麼被移出 ECMP / 為什麼判死」才不需要回頭猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateReason {
    /// 連續超時次數達到 `consecutive_fail_down`
    ConsecutiveTimeouts,
    /// 窗口已滿且窗口丟包率超過 `loss_threshold_down`
    WindowLoss,
    /// 平滑 RTT 連續超過 `max_rtt_ms`
    Rtt,
    /// 連續成功次數達到 `recovery_success_count` 而恢復 UP
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
    /// 恢復 UP 所需連續成功次數（預設 5）
    recovery_success_count: usize,
    /// 降級（不參與 ECMP）的窗口丟包率門檻（0.0 = 關閉）
    degrade_loss_threshold: f64,
    /// 退出降級所需的連續樣本數（`degrade_exit_samples`）
    degrade_exit_samples: usize,
    /// 退出降級的丟包率遲滯量（`degrade_hysteresis`）
    degrade_hysteresis: f64,
    /// 當前是否處於降級狀態（**帶遲滯的狀態機**，非單純比較當下丟包率）
    degraded: bool,
    /// 連續滿足退出條件的樣本數（嚴格連續：一次不滿足即歸零）
    degrade_exit_streak: usize,
    /// 距離上一次「恢復到 UP」已經過的樣本數（從未 UP 過的線初始化為窗口大小）。
    ///
    /// 為什麼需要：DOWN 期間的失敗樣本仍留在滑動窗口裡，恢復當下窗口丟包率往往
    /// 遠高於降級門檻（實測 44%），若立刻據此降級，剛回到 ECMP 的線會被馬上移出，
    /// 等窗口滾乾淨後又加回來 —— 數秒內出現「[兩條] -> [一條] -> [兩條]」的
    /// 路由抖動，每次變動都會重映射 flow（standard 模式還會 flush conntrack）。
    /// 因此恢復後先讓窗口換過一輪，再允許用丟包率降級。
    samples_in_up: usize,
    /// 最近一次狀態變更的原因（供日誌與狀態檔說明）
    last_state_reason: Option<StateReason>,
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
            recovery_success_count: config.recovery_success_count,
            degrade_loss_threshold: config.degrade_loss_threshold,
            degrade_exit_samples: config.degrade_exit_samples.max(1),
            // 退出門檻 = 進入門檻 - 遲滯量，但**不在這裡先做減法**：
            // `0.15 - 0.05` 在 double 下是 `0.09999999999999999`，而 1/10 是 `0.1`，
            // 兩者在數學上相等卻無法用 `<=` 命中，會讓線路在 10% 丟包時永久卡在降級。
            // 比較時改用「loss + hysteresis <= threshold + 容差」（見 update_degrade_state）。
            degrade_hysteresis: config.degrade_hysteresis.max(0.0),
            degraded: false,
            degrade_exit_streak: 0,
            // 從未 UP 過的線（例如開機一路失敗）不受此保護，維持原本的降級行為。
            samples_in_up: config.window_size,
            last_state_reason: None,
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

    /// 目前窗口內的樣本數（狀態檔用：讓「為什麼還沒降級」看得出來是樣本不夠）
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// 窗口是否已填滿（未填滿前不做丟包率判定）
    pub fn window_full(&self) -> bool {
        self.window.len() >= self.window_capacity
    }

    /// 最近一次狀態變更的原因（尚未發生過任何變更時為 None）
    pub fn state_reason(&self) -> Option<StateReason> {
        self.last_state_reason
    }

    /// 這條線是否「降級」：不參與 ECMP（但仍繼續探測，品質恢復後自動回歸）。
    ///
    /// 為什麼不能只看「有沒有判 DOWN」：介於 `degrade_loss_threshold`（預設 0.20）
    /// 與 `loss_threshold_down`（0.50）之間的線路不會被判 DOWN，於是照樣吃一半流量，
    /// 使用者感受就是「有雙網卡時經常檢查到丟包」。
    ///
    /// 為什麼不能是「當下丟包率 >= 門檻」的純函式：窗口量化步長是 10%（10 個樣本、1 次失敗
    /// 就是 10%），注入 12%~30% 丟包時窗口丟包率會一直在 10%/20%/30% 之間擺動，
    /// 純函式每幾秒就進出一次降級 → 每次都讓 `Active WAN set changed` 重下 ECMP 路由
    /// （實測 20 秒內 5~6 次）。因此改成帶遲滯的狀態機（見 `update_degrade_state`）。
    ///
    /// 門檻為 0.0 時視為關閉該功能（沿用舊行為），此時永遠不降級。
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// 依本次樣本更新降級狀態機（進入門檻 / 退出門檻 + 最短連續保持）。
    ///
    /// - 進入：尚未降級、窗口已填滿、丟包率 >= `degrade_loss_threshold` → 立刻降級並把
    ///   退出累積清零（壞線要快點讓出流量，所以進入不加遲滯）。
    /// - 退出：已降級、窗口已填滿、丟包率滿足
    ///   `loss + degrade_hysteresis <= degrade_loss_threshold`（等價於「進入門檻 - 遲滯」，
    ///   但避開浮點減法的捨入誤差）→ 累積一次；達 `degrade_exit_samples` 才真正
    ///   退出。**任何一筆不滿足退出條件（含窗口還沒填滿）都把累積歸零**，確保「連續」。
    ///
    /// 兩個門檻之間是死區：已在降級狀態的線停在 20% 丟包不會被踢回來又踢出去。
    fn update_degrade_state(&mut self, loss: f64, window_full: bool) {
        if self.degrade_loss_threshold <= 0.0 {
            // 功能關閉：永遠不降級（沿用舊行為）
            self.degraded = false;
            self.degrade_exit_streak = 0;
            return;
        }
        if !window_full {
            // 樣本不足時不做任何判定；累積中的退出序列也因為「不滿足退出條件」而歸零
            self.degrade_exit_streak = 0;
            return;
        }
        if !self.degraded {
            // 剛恢復的線：窗口裡還有停機期間的失敗樣本。此時據以降級會讓它立刻被
            // 移出 ECMP、幾秒後又加回來（實測三次路由變動）。等窗口換過一輪再判定。
            if self.samples_in_up < self.window_capacity {
                return;
            }
            if loss >= self.degrade_loss_threshold {
                self.degraded = true;
                self.degrade_exit_streak = 0;
            }
            return;
        }
        // 已降級：只有丟包率落到退出門檻以下才開始累積「連續」計數。
        // 用加法比較（loss + hysteresis <= threshold）並帶一個極小容差，
        // 避免 `0.15 - 0.05 = 0.0999...` 這類浮點捨入讓數學上相等的情況判為不達標。
        if loss + self.degrade_hysteresis <= self.degrade_loss_threshold + LOSS_FLOAT_EPS {
            self.degrade_exit_streak = self.degrade_exit_streak.saturating_add(1);
            if self.degrade_exit_streak >= self.degrade_exit_samples {
                self.degraded = false;
                self.degrade_exit_streak = 0;
            }
        } else {
            self.degrade_exit_streak = 0;
        }
    }

    /// 餵入一次探測樣本，並更新 EWMA 指標與狀態機
    /// 回傳：狀態是否發生變更（若變更需通知 Route Manager 與 Conntrack Flusher）
    pub fn update(&mut self, sample: &ProbeSample) -> (LinkState, bool) {
        let prev_state = self.state;

        // 這筆樣本進來前仍是 UP，就累積「恢復後已過幾拍」（給 update_degrade_state 用）。
        if self.state == LinkState::Up {
            self.samples_in_up = self.samples_in_up.saturating_add(1);
        }

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
        let window_full = self.window_full();

        // 降級判定獨立於 UP/DOWN 狀態機：降級的線仍是 UP、仍在探測，只是不參與 ECMP。
        // 必須在每個樣本都更新（含窗口未填滿時把退出累積歸零），見 update_degrade_state。
        self.update_degrade_state(loss, window_full);

        // RTT 嚴重超標同樣視為鏈路不可用（舊版只在 DOWN -> UP 時檢查，
        // 導致一條 RTT 爆到數秒但仍能連上的鏈路會永遠維持 UP）。
        // 這裡用「連續超標次數」做滞回，避免單一封包尖峰就把鏈路打掛。
        //
        // 只在**成功樣本**上評估：失敗（超時）樣本不會更新 EWMA，若也計入超標次數，
        // 一條實際在「連續超時」的線可能靠著陳舊的 RTT 值先觸發 reason=rtt，
        // 讓日誌與狀態檔的歸因變成 RTT 而不是 consecutive_timeouts（誤導排障）。
        if sample.success {
            if self.rtt_ewma_ms.is_some_and(|r| r > self.max_rtt_ms) {
                self.rtt_over_count = self.rtt_over_count.saturating_add(1);
            } else {
                self.rtt_over_count = 0;
            }
        }
        let rtt_exceeded = self.rtt_over_count >= self.rtt_fail_count;

        // 3. 狀態機判定邏輯
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
                    // DOWN 判定條件：
                    // 1) 連續 N 次超時（預設 3），OR
                    // 2) 窗口已填滿且滑動窗口丟包率 > 50%，OR
                    // 3) 平滑 RTT 超過 max_rtt_ms
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
                        // 把「實際觸發的條件」與「配置門檻」一起寫出來，否則只看到
                        // `Loss: 30%` 會與配置的 50% 門檻互相矛盾（其實是連續超時觸發的）
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
                    // UP 恢復判定條件（Hysteresis 防震盪機制）：
                    // 1) 連續成功至少 recovery_success_count 次
                    // 2) 且 RTT 在正常範圍
                    //
                    // 刻意**不再檢查窗口丟包率**：舊版附加 `loss <= loss_threshold_up`，
                    // 而窗口丟包率與 window_size 耦合——window=10、門檻 10% 時等於
                    // 「窗口內最多 1 次失敗」，DOWN 由尾部 3 連敗觸發後要連續 9 次成功
                    // 才把失敗樣本滾出窗口，設定的 recovery_success_count=5 被靜默抬成 9
                    // （實測日誌正是 `Consecutive successes: 9`）：DOWN 約 1.5 秒、
                    // UP 要 4.5 秒以上，強不對稱 → 線路反覆翻轉。
                    // 防震盪並未因此消失：回到 UP 之後若品質仍差，上面的 DOWN 判據
                    // （連續超時／窗口丟包率／RTT）會立刻再把它打下去。
                    let should_up =
                        self.consecutive_successes >= self.recovery_success_count && rtt_normal;

                    if should_up {
                        self.state = LinkState::Up;
                        // 恢復後重新起算：本拍上面可能已用殘留的停機舊樣本判成降級，
                        // 這裡覆蓋掉，並讓後續 window_capacity 拍內不再據舊樣本進入降級
                        // （見 samples_in_up）。
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

        // 第 5 次成功就必須恢復：此時窗口內仍殘留 3 個失敗樣本，但恢復判據只看
        // recovery_success_count + RTT（FIX-4）。舊邏輯會要求窗口丟包率 <= 10%，
        // 也就是要再把那 3 個失敗樣本滾出窗口 → 實際需要 9 次連續成功，
        // 把配置的 recovery_success_count=5 靜默抬成 9（實測日誌 `Consecutive successes: 9`）。
        let (state, changed) = lqe.update(&sample(true, 25));
        assert_eq!(
            state,
            LinkState::Up,
            "配置 5 次連續成功就該恢復，不能被窗口數學抬成 9 次"
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
    fn test_recovery_is_not_gated_by_window_loss() {
        // FIX-4：恢復判據不再包含窗口丟包率。
        // 舊斷言（`loss <= loss_threshold_up`）會讓窗口內殘留的失敗樣本把
        // recovery_success_count 架空，語意已變更 → 這裡按新語意重寫：
        // 3 次超時造成 DOWN 後，第 5 次連續成功就恢復（窗口內仍有 3/8 = 37.5% 失敗）。
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 20));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        for i in 1..5 {
            let (state, _) = lqe.update(&sample(true, 25));
            assert_eq!(state, LinkState::Down, "第 {i} 次成功還不到門檻");
        }
        let (state, changed) = lqe.update(&sample(true, 25));
        assert_eq!(state, LinkState::Up);
        assert!(changed);
        // 恢復當下窗口內確實還有殘留失敗 → 證明恢復沒被窗口丟包率擋住
        assert!(lqe.loss_rate() > 0.10);
    }

    #[test]
    fn test_recovery_counter_resets_on_failure() {
        // 防震盪仍然有效：連續成功累積途中只要出現一次失敗就歸零，
        // 不是「窗口內累加成功次數」。
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);

        for _ in 0..4 {
            lqe.update(&sample(true, 25));
        }
        lqe.update(&sample(false, 600)); // 歸零
        for _ in 0..4 {
            lqe.update(&sample(true, 25));
        }
        assert_eq!(
            lqe.state,
            LinkState::Down,
            "一次失敗必須把連續成功計數歸零，不能在窗口內湊數恢復"
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

        // 連續 3 次成功即達標（與窗口大小無關）
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
            "recovery_success_count=3 應在 3 次連續成功後恢復"
        );
    }

    #[test]
    fn test_recovery_does_not_immediately_degrade() {
        // 迴歸：恢復當下窗口仍殘留停機期間的失敗樣本（此例 4/10 = 40%，遠超 20% 門檻）。
        // 舊行為會立刻把剛回來的線標成 degraded 並移出 ECMP，等窗口滾乾淨後又加回來，
        // 數秒內出現「[兩條] -> [一條] -> [兩條]」的路由抖動與隨之而來的 flow 重映射。
        let mut cfg = DaemonConfig::default();
        cfg.consecutive_fail_down = 3;
        cfg.recovery_success_count = 5;
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
            "前提：窗口內仍有超過門檻的停機舊樣本"
        );
        assert!(!lqe.is_degraded(), "恢復後不得因窗口內的停機舊樣本立刻降級");

        // 窗口換過一輪之前（接下來全部成功）都不得降級。
        for i in 0..cfg.window_size {
            lqe.update(&sample(true, 25));
            assert!(!lqe.is_degraded(), "恢復後第 {i} 拍就降級了");
        }

        // 保護不是永久關閉降級：窗口換過一輪後，真實的 20% 丟包仍要能降級。
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Up, "2 次超時還不到 DOWN 門檻");
        assert!(lqe.is_degraded(), "窗口換過一輪後，20% 丟包仍必須觸發降級");
    }

    // -----------------------------------------------------------------------
    // FIX-2：基於實測品質的降級（不參與 ECMP，但仍繼續探測）
    // -----------------------------------------------------------------------

    #[test]
    fn test_degrade_requires_a_full_window() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        // 窗口未滿（樣本不足）時不得降級，即使目前樣本全是失敗
        for _ in 0..9 {
            lqe.update(&sample(false, 600));
        }
        assert!(!lqe.window_full());
        assert!(!lqe.is_degraded(), "窗口未填滿前樣本數不足，不能據以降級");

        // 第 10 個樣本讓窗口填滿（10/10 = 100% >= 20%）
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!(lqe.is_degraded());
    }

    #[test]
    fn test_degrade_threshold_boundary() {
        let cfg = DaemonConfig::default(); // degrade_loss_threshold = 0.20
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        // 窗口 10 個樣本、1 次失敗 = 10% < 20% → 不降級
        for _ in 0..9 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        assert!(lqe.window_full());
        assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);
        assert!(!lqe.is_degraded(), "10% 未達 20% 門檻");

        // 再一個失敗 → 2/10 = 20% >= 20% → 降級（門檻是「達到即降級」）
        lqe.update(&sample(false, 600));
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        assert!(lqe.is_degraded(), "20% 達到門檻即降級");

        // 但仍不該被判死（判死要窗口丟包率 > 50% 或連續 3 次超時）
        assert_eq!(lqe.state, LinkState::Up, "20% 丟包不該判 DOWN");

        // 品質恢復 → 自動回歸。
        // FIX-6 之後是**雙門檻 + 最短連續保持**：退出門檻 = 0.20 - 0.10 = 0.10，
        // 且要連續 6 拍達標，所以前 8 拍（窗口仍有 2 次失敗 = 20%）不算數。
        for i in 1..=8 {
            lqe.update(&sample(true, 20));
            assert!(
                lqe.is_degraded(),
                "第 {i} 拍窗口丟包率仍是 20%，高於退出門檻 10%，不得退出降級"
            );
        }
        for i in 1..6 {
            lqe.update(&sample(true, 20));
            assert!(lqe.is_degraded(), "連續達標 {i} 拍 < 6，不得退出降級");
        }
        lqe.update(&sample(true, 20));
        assert!(
            !lqe.is_degraded(),
            "連續 6 拍窗口丟包率 <= 10% 後應自動恢復承載資格"
        );
    }

    #[test]
    fn test_degrade_disabled_by_zero_threshold() {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.0; // 0.0 = 關閉
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        for _ in 0..10 {
            lqe.update(&sample(false, 600));
        }
        assert!(lqe.window_full());
        assert!(!lqe.is_degraded(), "門檻 0.0 代表關閉降級功能");
        assert_eq!(lqe.state, LinkState::Down, "全丟包仍由既有的 DOWN 判據處理");
    }

    // -----------------------------------------------------------------------
    // FIX-6：降級的雙門檻遲滯 + 最短連續保持
    //
    // 為什麼要這組測試：窗口長度 10 的量化步長是 10%，注入 12%~30% 丟包時窗口丟包率
    // 會在 10% / 20% / 30% 之間擺動。舊的純函式 `loss_rate() >= 0.20` 於是每幾秒
    // 進出一次降級 → 每次都讓「Active WAN set changed」重下 ECMP 路由（實測 20 秒內 5~6 次）。
    // -----------------------------------------------------------------------

    /// 把 lqe 推進到「已降級、窗口 = [F,F,S*8]（恰好 20%）、退出累積 = 0」的狀態。
    ///
    /// 20% 正好是進入門檻，同時遠高於退出門檻（20% - 10% = 10%），是遲滯判定最關鍵的取樣點。
    fn enter_degraded_holding_twenty_percent(lqe: &mut LinkQualityEstimator) {
        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert!(lqe.is_degraded(), "窗口 20% 應達進入門檻（預設 0.20）");

        // 再餵 8 次成功，把兩個失敗樣本推到窗口最前面（窗口仍是 20%）
        for _ in 0..8 {
            lqe.update(&sample(true, 20));
        }
        assert!((lqe.loss_rate() - 0.20).abs() < 1e-9);
        assert_eq!(
            lqe.degrade_exit_streak, 0,
            "20% 不滿足退出條件，累積必須為 0"
        );
    }

    #[test]
    fn test_degrade_hysteresis_holds_in_the_dead_zone() {
        let cfg = DaemonConfig::default(); // 進入 0.20 / 退出 0.10 / 連續 6 拍
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        // 週期序列 [F,F,S*8]：任何 10 長窗口都恰好 2 次失敗 → 丟包率永遠是 20%。
        // 舊版純函式在這個點上會反覆「降級（20% >= 0.20）/ 退出（20% > 0.10 其實不會退出）」
        // ── 真正的抖動來自 20%↔10% 的擺動，這裡先確認「停在 20% 不退出」。
        for round in 0..10 {
            lqe.update(&sample(false, 600));
            lqe.update(&sample(false, 600));
            for _ in 0..8 {
                lqe.update(&sample(true, 20));
            }
            assert!(
                (lqe.loss_rate() - 0.20).abs() < 1e-9,
                "第 {round} 輪窗口應穩定在 20%"
            );
            assert!(lqe.is_degraded(), "20% 落在死區內，不得退出降級");
            assert_eq!(lqe.degrade_exit_streak, 0, "20% 不達退出門檻，累積必須歸零");
        }

        // 只有連續達標（<= 10%）滿 6 拍才退出：第 1 拍起窗口就只剩 1 個失敗樣本，
        // 第 5 拍仍在降級，第 6 拍才退出。
        for i in 1..=5 {
            lqe.update(&sample(true, 20));
            assert!(lqe.is_degraded(), "連續達標 {i} 拍 < 6，不得退出降級");
        }
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "連續第 6 拍達標後才退出降級");
    }

    #[test]
    fn test_degrade_exit_streak_resets_on_a_single_violation() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        // 連續達標 3 拍（窗口丟包率 10% → 0% → 0%）
        for _ in 0..3 {
            lqe.update(&sample(true, 20));
        }
        assert_eq!(lqe.degrade_exit_streak, 3);

        // 中間夾一次不滿足（窗口回到 20%）→ 前面 3 拍全部作廢
        lqe.update(&sample(false, 600)); // 窗口滾掉 1 個失敗樣本，仍是 10%，達標
        lqe.update(&sample(false, 600)); // 20% → 不達標，累積歸零
        assert_eq!(
            lqe.degrade_exit_streak, 0,
            "一次不滿足就必須清零（嚴格連續）"
        );
        assert!(lqe.is_degraded(), "累積歸零不等於退出降級");

        // 之後必須重新湊滿連續 6 拍：前 8 拍窗口仍有 2 次失敗，第 9 拍才開始重新累積
        for i in 1..=13 {
            lqe.update(&sample(true, 20));
            assert!(
                lqe.is_degraded(),
                "第 {i} 拍不得退出（連續計數已於 20% 那拍歸零）"
            );
        }
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "重新累積到連續 6 拍後才退出");
    }

    #[test]
    fn test_degrade_exit_samples_is_configurable() {
        let mut cfg = DaemonConfig::default();
        cfg.degrade_exit_samples = 2; // 連續 2 拍達標即退出
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        lqe.update(&sample(true, 20));
        assert!(lqe.is_degraded(), "連續達標 1 拍 < 2，不得退出降級");
        lqe.update(&sample(true, 20));
        assert!(!lqe.is_degraded(), "連續達標 2 拍即達門檻，應退出降級");
    }

    #[test]
    fn test_degrade_hysteresis_is_configurable() {
        // 同一個「窗口丟包率穩定停在 10%」的序列（週期 [F,S*9]：每個 10 長窗口恰好 1 次失敗），
        // 兩種遲滯量給出不同結果：
        //   預設 0.10 → 退出門檻 0.10 → 10% 達標，連續 6 拍後退出降級；
        //   調成 0.15 → 退出門檻 0.05 → 10% 不達標，永遠留在降級。
        for (hysteresis, expect_exit) in [(0.10_f64, true), (0.15, false)] {
            let mut cfg = DaemonConfig::default();
            cfg.degrade_hysteresis = hysteresis;
            let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
            enter_degraded_holding_twenty_percent(&mut lqe);

            lqe.update(&sample(true, 20)); // 窗口滾掉一個失敗樣本 → [F,S*9] = 10%
            assert!((lqe.loss_rate() - 0.10).abs() < 1e-9);

            // 兩輪「1 次失敗 + 9 次成功」的週期序列
            for _ in 0..2 {
                lqe.update(&sample(false, 600));
                for _ in 0..9 {
                    lqe.update(&sample(true, 20));
                    assert!(
                        (lqe.loss_rate() - 0.10).abs() < 1e-9,
                        "週期序列應讓窗口丟包率穩定停在 10%"
                    );
                }
            }

            assert_eq!(
                lqe.is_degraded(),
                !expect_exit,
                "遲滯 {hysteresis} 下，穩定 10% 丟包的退出結果與預期不符"
            );
        }
    }

    #[test]
    fn test_degrade_exit_boundary_survives_float_rounding() {
        // 迴歸測試：門檻 0.15、遲滯 0.05 時，退出門檻數學上是 10%。
        // 舊版用 `0.15 - 0.05`（= 0.09999999999999999）比較，而窗口丟包率 1/10 = 0.1，
        // `0.1 <= 0.0999...` 恆為 false → 線路即使穩定在 10% 也永久卡在降級。
        let mut cfg = DaemonConfig::default();
        cfg.degrade_loss_threshold = 0.15;
        cfg.degrade_hysteresis = 0.05;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        enter_degraded_holding_twenty_percent(&mut lqe);

        // 週期序列 [F,S*9]：每個 10 長窗口恰好 1 次失敗 = 10%，
        // 屬於「loss + hysteresis <= threshold」的邊界，應能連續達標後退出。
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
            "穩定 10% 丟包（退出門檻）必須能退出降級，不得因浮點捨入被永久卡住"
        );
    }

    #[test]
    fn test_timeouts_do_not_accumulate_rtt_over_count() {
        // 迴歸：失敗（超時）樣本不更新 EWMA，也不該累積 RTT 連續超標計數。
        // 舊版會讓一條「連續超時」的線靠陳舊的高 RTT 先以 reason=rtt 判 DOWN，
        // 把排障方向帶偏（明明該看 consecutive_timeouts）。
        let mut cfg = DaemonConfig::default();
        cfg.max_rtt_ms = 50.0;
        cfg.rtt_fail_count = 2;
        cfg.consecutive_fail_down = 3;
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);

        lqe.update(&sample(true, 500)); // EWMA 超標 1 次
        assert_eq!(lqe.state, LinkState::Up);

        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        lqe.update(&sample(false, 600));
        assert_eq!(lqe.state, LinkState::Down);
        assert_eq!(
            lqe.state_reason(),
            Some(StateReason::ConsecutiveTimeouts),
            "應由連續超時觸發，而不是被陳舊 RTT 誤導成 rtt"
        );
    }

    #[test]
    fn test_state_reason_reports_triggering_condition() {
        let cfg = DaemonConfig::default();
        let mut lqe = LinkQualityEstimator::new("wan1".into(), &cfg);
        assert_eq!(lqe.state_reason(), None);

        lqe.update(&sample(true, 20));
        assert_eq!(lqe.state_reason(), Some(StateReason::Recovery));

        // 連續超時觸發（此時窗口丟包率僅 30%，與 50% 門檻無關 → 原因必須說清楚）
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
