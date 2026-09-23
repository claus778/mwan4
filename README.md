# MWAN4 (Multi-WAN 4)

專為 Linux / OpenWrt 深度設計的極輕量、零負擔、高性能「多 WAN 故障轉移與健康監控守護進程（Daemon）」。

用以徹底替代架構笨重、頻繁呼叫 Shell 腳本、吃 CPU 且嚴重破壞硬體加速（Flow Offload）的傳統 `mwan3`。

---

## 為什麼需要 MWAN4？（對比傳統 MWAN3）

| 特性 / 指標 | 傳統 OpenWrt mwan3 | MWAN4 (本專案) |
| :--- | :--- | :--- |
| **轉發面架構** | 依賴數十條 `iptables`/`nftables` fwmark 打標與 Policy Routing | **100% 依賴 Linux 原生 FIB (Multipath ECMP)**（轉發流量完全不經 fwmark／策略路由；僅探針的控制面為每張 WAN 各用一條 `oif` 規則，見 §1） |
| **硬體加速相容性** | ❌ **破壞硬體加速** (Flow Offload / HW NAT 遇到 packet mark 會失效) | ✅ **原生相容 Flow Offload** (PPE, MT798x, MT7621, x86) |
| **控制面操作方式** | 頻繁執行外部 Shell、`ip`、`ubus`、`logger` 進程 | **純 Netlink Sockets**（控制面零外部子進程） |
| **CPU 佔用率** | 較高（頻繁 fork/exec 腳本，尤其在弱 CPU 路由器） | **< 0.1%**（單線程非同步事件驅動） |
| **記憶體佔用 (RSS)** | 數十 MB（多個 shell 子進程 + 巨型規則表） | **< 4 MB** |
| **故障轉移時延** | 數秒至數十秒 | **< 1 秒**（原子化 FIB 路由切換 + Conntrack 精準清理） |
| **TCP 斷線卡死問題** | 經常殘留無效 session，需漫長 TCP 重傳超時 | **自動 Netlink 清理失效網卡 Conntrack**，秒級恢復 |

---

## 核心架構規範

### 1. 雙 WAN 探測器（Prober）
- **出口網卡強制綁定**：使用 Non-blocking Socket 並透過 `SO_BINDTODEVICE` 強制將探針綁定到特定網卡（如 `wan1`、`wan2`）。
- **探針路徑與預設路由解耦（重要）**：`SO_BINDTODEVICE` 只是把路由查找的 `oif` 固定到該設備，
  **並不代表一定找得到路**——主表若沒有「經該設備」的路由，內核會把封包當成 on-link 直接丟進黑洞
  （實測結果是 `connect()` 一直超時，而不是回報 `ENETUNREACH`），於是「預設路由被刪掉或被切到別條線」
  就等於「這條線永遠回不去」。因此啟動時會為每張 WAN 建立一張**獨立路由表**
  （`default via <gateway> dev <wan>`）＋一條 **`oif <wan> lookup <table>`** 規則
  （表號與規則優先序都從 10000 起算）。規則只匹配「綁定該設備的本機封包」，所以探針一定有路可走，
  而**轉發流量（`oif = br-lan`）與路由器其它本機流量完全不受影響**。
- **回程（`rp_filter`）處理**：內核的反向路徑檢查**只查主表**，看不到 FIB 規則。實測：主表沒有涵蓋
  探針目標的路由時，即使出向完全正常、封包也確實送達對端，回來的 SYN-ACK 仍會被當成 martian 丟掉
  （症狀是探針「一直超時」）。因此守護進程會在**必要時**於主表補一條探針目標的 `/32`（metric 42760）：
  - 主表根本沒有涵蓋該目標的路由時 → 一定補（否則收不到回程；此時也不會「搶」到本來可用的路徑）；
  - 主表有路、但 `rp_filter` 是 strict（`1`）且該目標**沒有被別的 WAN 共用**時 → 補（strict 要求
    回程走同一張網卡）；
  - 其餘情況（含 `rp_filter` 為 loose/關閉）→ **不補**，避免影響 LAN 到該目標的轉發路徑；
  - 線路變成活躍後會把 `/32` 收回。

  ⚠️ **已知限制**：`rp_filter=1`（strict）**且多條 WAN 共用同一個探針目標**時，主表裡同一個前綴只能
  指向一張網卡，因此同一時間只可能有一條線探得通。這種組合下守護進程**不會**下發 `/32`（否則會把
  持有主路由的那條線判成 martian、兩條線互相判死），並會明確告警建議改成：
  `sysctl -w net.ipv4.conf.all.rp_filter=2`（loose）＋各 WAN 介面 `.../<wan>.rp_filter=2`，
  或讓每條 WAN 使用各自的探針目標。

  可用下列指令核對：
  ```sh
  ip rule show | grep 'lookup 1000'                 # oif <wan> lookup <10000+i>
  ip route show table 10000                          # 第 0 張 WAN 的探針預設路由
  ip route get 223.5.5.5 oif wan1                    # 應顯示 via <gw>（有 via 才代表有路）
  ip route show table main | grep 'metric 42760'     # 只在必要時短暫出現的探針 /32
  ip route show table main | grep 'metric 42761'     # 隧道 underlay 對端的防自環 /32
  ```
  **保留區段**（本程式專用，請勿他用）：路由表 `10000..10063`、規則優先序 `10000..10063`、
  主表 metric `42760`（探針 /32）與 `42761`（隧道 underlay /32）。我們的規則都帶來源標記（`FRA_PROTOCOL = 0x4D`），啟動清掃**只刪帶這個
  標記的規則**，不會動到第三方的規則；清掃也不再主動刪保留表內的路由（沒有規則指向它就是惰性的，
  而且我們重用該表時會直接 REPLACE）。
- **探測協議**：以高效 TCP SYN 探測公共 DNS（預設為大陸地區的 `223.5.5.5:53`、`114.114.114.114:53`），週期預設為 500ms。TCP SYN 探針具備極高穿透力，不會被運營商 ICMP 限速或丟棄。
- **多目標容災（主目標 + 失敗回退）**：支援單一網卡配置多個探測目標，但每個週期只先探「上次探通的那個」；只有它失敗才並發探測其餘目標。好處是健康時每條 WAN 每週期只產生 1 條短命 TCP 連線（conntrack／LuCI 連線列表不會被探針灌滿），同時保留「單一 DNS 被牆或故障時自動切換目標」的容災能力。代價是線路全斷時，一個探測週期最壞多花一輪 `probe_timeout_ms`（預設 400ms）。
- **失敗原因可觀測**：狀態檔會記錄每張網卡的 `last_error` 與 `local_condition`
  （`No such device`／`Network is unreachable`／`Create socket failed`／
  `No targets configured`／`No route to host` 等屬於**本機條件**，不是運營商丟包），
  info 級日誌也會針對這類錯誤告警一次。超時文案只說
  `Timeout (no reply within 400ms)`，不斷言「丟包」（上游黑洞／本機無路由／對端不回
  SYN-ACK 的表象相同）。此外狀態檔還有 `degraded`（是否已因丟包被移出 ECMP）、
  `samples_in_window` / `window_full`（窗口是否已填滿，未滿則不做丟包率判定）與
  `state_reason`（`consecutive_timeouts` / `window_loss` / `rtt` / `recovery`，
  說明這次是被哪一條判據移出或救回）。

### 2. 鏈路評分與狀態機（LQE - Link Quality Estimator）
- **滑動窗口與平滑算法**：維護長度為 10 的滑動窗口，使用 EWMA（指數加權移動平均）動態估算 RTT 與抖動（Jitter）：
  $$\text{RTT}_{\text{new}} = \alpha \cdot \text{RTT}_{\text{sample}} + (1 - \alpha) \cdot \text{RTT}_{\text{old}} \quad (\alpha = 0.20)$$
  $$\text{Jitter}_{\text{new}} = \beta \cdot |\text{RTT}_{\text{sample}} - \text{RTT}_{\text{old}}| + (1 - \beta) \cdot \text{Jitter}_{\text{old}} \quad (\beta = 0.25)$$
- **狀態判定標準**：
  - **UP**：連續成功次數達標且 RTT 正常（見下方 Hysteresis）。
  - **DOWN**：連續 3 次探測超時（`consecutive_fail_down`），或滑動窗口丟包率 **> 50%**
    （`loss_threshold_down`），或平滑 RTT 連續超標（`rtt_fail_count` 次）。
    狀態檔的 `state_reason` 與 DOWN 日誌都會寫出**實際觸發**的那一條
    （`consecutive_timeouts` / `window_loss` / `rtt` / `recovery`），
    避免只看到 `Loss: 30%` 而與配置的 50% 門檻互相矛盾。
- **嚴格防震盪機制（Hysteresis）**：
  - 當線路處於 DOWN 時，必須**連續成功** `recovery_success_count` 次（預設 5）、
    且 RTT 正常，才能恢復為 UP。
  - 恢復判據**不再包含窗口丟包率**：`loss_threshold_up`（舊欄位，保留僅為相容設定檔）
    與 `window_size` 耦合——`window_size = 10`、門檻 10% 時等於「窗口內最多 1 次失敗」，
    於是 DOWN（尾部 3 連敗觸發）要連續 **9** 次成功才能恢復，把配置的
    `recovery_success_count = 5` 靜默抬成 9（實測日誌正是 `Consecutive successes: 9`），
    DOWN 約 1.5 秒、UP 要 4.5 秒以上，強不對稱造成反覆翻轉。
  - 防震盪並未因此消失：探測過程中若發生任何一次超時，連續成功計數立即歸零重新累積；
    回到 UP 之後若品質仍差，上面的 DOWN 判據會立刻再把它打下去。
  - 動態升 / 降級（`degrade_loss_threshold`，預設 0.20 = 20%，設 `0` 關閉）：
    滑動窗口**已填滿**且窗口丟包率 **>= 該值**時，這條線「降級」= 不參與 ECMP；
    但它**仍持續探測**，品質恢復後自動回到 ECMP。介於降級門檻與判死門檻（0.50）
    之間的線路不會被判 DOWN，舊版會讓它照樣吃一半流量（實測 20% 丟包時主表仍是
    兩條 nexthop 的 ECMP）。為避免「全部線路都降級 → 完全沒有預設路由」，
    此時會**保底**取 metric 最小的 Up 線承載並印出一次 warn。狀態檔的 `degraded`
    欄位可看出某條線是否正被排除。
  - **降級帶雙門檻遲滯 + 最短連續保持**（`degrade_hysteresis` 預設 0.10、
    `degrade_exit_samples` 預設 6）：**進入**降級看 `degrade_loss_threshold`（20%），
    **退出**降級要窗口丟包率 `<= degrade_loss_threshold - degrade_hysteresis`（預設 10%）
    且**連續** `degrade_exit_samples` 次都達標（中間夾一次不達標就重新數）。
    為什麼需要：窗口長度 10 的量化步長就是 10%，注入 12%~30% 丟包時窗口丟包率會在
    10% / 20% / 30% 之間擺動——單一門檻的純函式判定會每幾秒進出一次降級，
    每次都觸發 `Active WAN set changed` 並重下 ECMP 路由（實測 20 秒內 5~6 次，
    路由成員持續抖動）。遲滯讓「剛被踢出」的線必須明顯變好才准回來。
    `degrade_hysteresis` 必須嚴格小於 `degrade_loss_threshold`（`--check-config` 會擋）。

### 3. Netlink FIB 執行器（Route Manager）
- 100% 透過 Linux 原生 Netlink Socket (`NETLINK_ROUTE`) 操作內核路由表（`RT_TABLE_MAIN`），絕不呼叫 `ip route` 等外部命令。
- **原子化路由切換**：
  - 雙 WAN 正常：下發 ECMP 預設路由（支援配置權重 `weight`）。
  - 單 WAN 故障：原子化發送 `RTM_NEWROUTE`（`NLM_F_REPLACE`），即刻將預設路由收斂至存活線路。
  - 線路恢復：原子化切回雙路 ECMP 負載均衡。
- **全部斷線時的語意（實測決定）**：
  - 若主表**只有我們這一條**預設路由 → **保留**（刪掉會讓整機含所有 LAN 客戶端完全沒有出口）；
  - 若主表**還有別人的預設路由**（例如 netifd 的 metric 10/50）→ **刪掉我們這條，讓兜底接手**。
    原因：載波掉（拔網線、對端下線，介面仍是 UP）時內核**不會**自己移除「dev 指向該設備」的路由，
    它只是標成 linkdown 並繼續勝過 metric 更大的兜底，流量會一直被送往死鏈路。
  - 因為探針有自己的獨立表（不依賴這條預設路由），刪掉它不會讓 daemon 失去探測能力。
- **失敗可感知、可自癒**：netlink worker 會把每次下發的成功／失敗回報主迴圈；
  失敗時不更新「已下發」記錄，並在數秒後重下同一份期望狀態（同一個錯誤只告警一次，
  之後每 20 次提醒一次，避免永久失敗時把 logd 環形緩衝刷掉）。此外每 30 秒有一次
  心跳重下（冪等），修復被其它程序或內核事件改動的路由。
- **退出語意**：`remove_routes_on_exit` 預設 `false`——服務重啟／升級的窗口內保留預設路由，
  避免整網瞬斷；設為 `true` 時也**只會刪掉自己真的下發過的那條**（從未接管過就不碰 netifd 的路由）。
  無論設定為何，**探針路徑（獨立表內的路由、`oif` 規則、主表探針 `/32`）與隧道 underlay
  `/32` 一律會拆除**（underlay 路由指向的舊閘道若留著，會把封裝封包黑洞到失效出口）。

### 4. 連線黏滯：兩種 ECMP 模式（`ecmp_mode`）
多 WAN 最容易被測出來的坑是「**一有線路抖動，既有連線就集體斷**」。兩種模式的差異在於**鏈路集合變動時，內核如何重算多路徑哈希**：

| 模式 | 內核機制 | 鏈路變動時的行為 | 需求 |
| --- | --- | --- | --- |
| `standard`（預設） | `RTA_MULTIPATH`（傳統 multipath route） | 重算整張哈希表；未受影響的連線也可能被**重新分派到其他 WAN**，造成連線中斷 | 所有 Linux |
| `resilient` | 彈性 nexthop group（`RTM_NEWNEXTHOP` + `NHA_RES_GROUP`） | **只重映射故障成員對應的桶**；其餘連線仍黏在原 WAN，不掉線 | Linux ≥ 5.14 |
| `auto` | 先試 `resilient`，內核不支援則永久退回 `standard` | 同上；不支援時自動降級，不報錯 | — |

- 選用 `standard` 時，守護進程才會在切換瞬間 flush conntrack（讓連線盡快重建）；`resilient` 會**抑制** flush-on-switch，否則等於親手抹掉黏滯效果。
  flush 範圍：**只清「新進入存活集合」的成員**（`is_active(m) && !prev.contains(&m.ifindex)`）。
  舊版在雙線 ECMP 下會連健康成員一起清（見下一節的實測日誌），既打斷健康線的連線、
  也抵銷了 `resilient` 想保住黏滯的意義。
- 未特別指定時預設為 `standard`，行為與舊版一致；想真正解決「抖動即斷連」請改用 `resilient`（或 `auto`）。
- **flush-on-switch 的判據是「實際安裝成功的變體」**（FIX-8 已修）：worker 每次下發路由後
  會回報核心實際生效的是 `standard` 還是 `resilient`，因此 `auto` 在舊內核上退回 `standard`
  時，切換瞬間仍會正確清 conntrack。`standard` / `resilient` 兩種明確設定行為不變。
- 單一 ECMP 組的成員數上限為 256（bucket 數上限），超過會被視為不支援而退回 `standard`。
  bucket 數以巢狀在 `NHA_RES_GROUP` 裡的 `NHA_RES_GROUP_BUCKETS`（u16）傳遞，必須是 2 的冪且不小於成員數；
  早期版本誤用頂層的 `NHA_RES_BUCKET`(13) 並以 u32 編碼，內核會當成「沒給 bucket 數」回 `EINVAL`，
  導致 `resilient` 從未真正生效（成員 nexthop 建得出來、group 建不出來、預設路由不下發）。已在 r5 修正。

### 5. 連線快取清理（Conntrack Flushing）
- 透過 Netfilter Netlink（`NETLINK_NETFILTER` / `NFNL_SUBSYS_CTNETLINK`）直接與內核 conntrack 表交互。
- 當線路判定為 DOWN 時，程式會精準掃描並刪除綁定在該網卡 IP 上的活躍連線，使客戶端的 TCP/UDP 連線能立即由存活網卡重新 NAT，解決長連線卡死問題。
  為避免把「其實還活著」的連線一次砍掉（實測隧道抖動一次就砍 495 條，使用者立刻看到
  「網站打不開」），判 DOWN 後會先靜默 25 秒（`CONNTRACK_FLUSH_DOWN_QUIET`），
  期間若恢復就不清。
- **切換時只清新進入的成員**：ECMP 成員集合變動時（`flush_conntrack_on_switch`），
  清理名單只有「新進入存活集合」的線（`is_active(m) && !prev.contains(&m.ifindex)`）。
  舊版在雙線 ECMP 下會把**所有存活成員**（含一直健康的那條）一起清——因為
  `multipath_involved = prev.len() > 1 || new_set.len() > 1` 在雙線時恆為真，
  實測日誌是「只有 wan1 健康卻被清」「恢復瞬間兩條都清」，健康線上的 NAT 連線被 RST。
  離開集合的成員由上述 25 秒靜默路徑負責。

### 6. 分流進階功能

#### 6.1 多路徑哈希策略（`multipath_hash_policy`）

ECMP 的分流粒度由內核的 `fib_multipath_hash_policy` 決定。預設（多數發行版）是 L4，
本專案可以代為設定並在啟動時寫入（IPv4，若啟用 IPv6 則一併寫入 IPv6）：

```json
"multipath_hash_policy": "l4"
```

| 值 | sysctl | 適用 |
| --- | --- | --- |
| `l3` | 0 | 只哈希來源/目的 IP；NAT 閘道下多個連線容易全落到同一條 WAN |
| `l4` | 1 | 加上來源/目的埠，分流最均勻（建議） |
| `inner` | 2 | L3 + 隧道內層標頭（VXLAN/GRE 等封裝流量） |

留空/不設定 = 沿用系統預設。寫入失敗（舊內核沒有這個檔案）只告警，不影響啟動；
變更需重啟服務。此設定與 `weight`／`ecmp_mode` 互補：哈希策略決定「怎麼分」，權重決定「分多少」。

#### 6.2 品質感知動態權重（`weight_mode: "quality"`）

靜態權重只看設定值，線路品質變化時只能靠「降級（移出 ECMP）」這種 0/1 手段。
`weight_mode: "quality"` 會依 LQE 的實測品質**連續**調整各線權重：

```json
"weight_mode": "quality",
"dynamic_weight_interval_ms": 10000,
"dynamic_weight_min_ratio": 0.25
```

- 演算法：`factor = (1 - 窗口丟包率) × clamp(最佳 RTT / 本線 RTT, min_ratio, 1.0)`，
  等效權重 = `clamp(round(設定 weight × factor), 1, 255)`；窗口未填滿或沒有 RTT 樣本時不懲罰。
- 更新有限速（`dynamic_weight_interval_ms`，預設 10 秒）：每次變更都會重下 ECMP 路由，
  內核可能重算 multipath hash，過於頻繁會反覆打斷既有 flow。
  想要「切換不斷連」建議搭配 `ecmp_mode: "resilient"` 或 `"auto"`。
- 品質差到降級門檻的線仍由既有 `degrade_loss_threshold` 機制移出；動態權重只處理
  「還可用但品質有差」的區間。
- 狀態檔的 `effective_weight` 會顯示實際下發值（LuCI 的 Priority/Weight 欄位會顯示
  `W1 → 2` 這種變化），方便驗證。

#### 6.3 策略分流：來源/目的指定 WAN（`policies`）

除了按 flow 哈希的 ECMP，還可以讓**指定來源（可選目的）的轉發流量走指定 WAN**。
實作刻意不使用 fwmark/nftables，而是 `ip rule` 的 `from`/`to` + 該 WAN 的獨立路由表——
路由查找時直接命中，不在封包上打標，因此不破壞 Flow Offload：

```json
"policies": [
  {
    "name": "guest-to-wan2",
    "source": ["192.168.3.0/24"],
    "destination": [],
    "interface": "wan2"
  },
  {
    "name": "work-via-wan1",
    "source": ["192.168.1.0/24"],
    "destination": ["203.0.113.0/24"],
    "interface": "wan1",
    "priority": 9000
  }
]
```

- `source` / `destination` 都是 IPv4 CIDR 清單；留空 = 不限制（清單展開後總規則數上限 64）。
- 規則優先序預設依 `policies` 陣列順序（9000 起）；也可全部明確指定 `priority`
  （9000~9063，數字越小越先匹配；要嘛全部指定、要嘛全部不指定）。
- **目標 WAN 判 DOWN 時整條政策自動移除**，匹配流量回退 ECMP；恢復後自動裝回。
- 未匹配的流量仍走原本的 ECMP 預設路由，兩者不衝突。
- 注意：策略規則只匹配來源/目的前綴（不是埠），且僅 IPv4；使用 strict `rp_filter`（=1）
  的環境可能因回程反向檢查而丟包，請將 WAN 設為 loose（=2）或關閉（見排障指南）。
- LuCI 的「Policy Routing (Source / Destination)」表格可直接維護；標題列會顯示
  目前生效中的政策（`名稱→WAN`），未生效會標 `(inactive)`。

#### 6.4 分流效果可視化

狀態檔 `/tmp/mwan4_status.json` 每條 WAN 新增：

- `tx_bps` / `rx_bps`：即時速率（bit/s，取樣自 `/sys/class/net/<if>/statistics`），
  用來看 ECMP 是否真的把流量分到多條線；
- `effective_weight`：動態權重實際下發值；
- `policies[]`：每條政策的 `name` / `interface` / `priority` / `active`。

LuCI 的 WAN 卡片會顯示「Throughput (TX / RX)」，標題列會顯示政策狀態。

#### 6.5 依「最大頻寬」比例分流（`max_mbps`）

多條線的頻寬往往不同（例如 wan1 1000M、wan2 100M）。只要**每一條 WAN 都設定
`max_mbps`（該線最大頻寬，Mbps）**，ECMP 的基準權重就會自動變成
`weight × max_mbps` 的比例——不需要自己手算 weight：

```json
"interfaces": [
  { "name": "wan1", "max_mbps": 1000, "up_mbps": 100, "weight": 1, "probe_targets": ["223.5.5.5:53"] },
  { "name": "wan2", "max_mbps": 100,  "up_mbps": 20,  "weight": 1, "probe_targets": ["223.5.5.5:53"] }
]
```

- 上例的活躍權重比就是 **1000 : 100 = 10 : 1**（最小那條正規化成 1）。
- `weight` 仍可當**手動倍率**（例如 `weight: 2` 代表 `2 × max_mbps`）。
- 單一 nexthop 的權重上限是 255，所以比例差距超過 **255:1** 時會夾在 255:1
  （1000M 對 1M 這種極端組合會退化，但差距 ≤ 255 倍都能精確表達）。
- 設定是「**要嘛全部 WAN 都填 max_mbps、要嘛全部不填**」；只填一部分會被
  `--check-config` 擋下，因為比例無從定義。
- `up_mbps`（上行容量，選填）只用於負載感知的利用率；未填時沿用 `max_mbps`。

> 這是**靜態比例**：開機時依頻寬決定好權重就不再變。若還要「某條線快打滿時把
> flow 轉走」，再加上 §6.6 的 `load_aware`。

#### 6.6 負載感知分流：一條線吃滿就把流量轉到別條（`load_aware`）

§6.5 決定「按頻寬該分多少」，這一節處理「**實際流量把某條線打滿**」。
ECMP 只按 flow 哈希，即使權重按頻寬設好，也可能因為 flow 分佈而偏載；
品質感知只會因為丟包／RTT 才動作，對「還沒丟包但頻寬快爆」無感。
`load_aware` 用**實測速率 vs 該線最大頻寬**算出利用率，把過載那條的權重再下修，
空閒的線權重放大，讓後續的 flow 改走空閒線：

```json
"weight_mode": "static",
"load_aware": true,
"load_target_ratio": 0.80,
"load_recover_ratio": 0.60,
"dynamic_weight_interval_ms": 10000,
"interfaces": [
  { "name": "wan1", "max_mbps": 1000, "up_mbps": 100, "weight": 1, "probe_targets": ["223.5.5.5:53"] },
  { "name": "wan2", "max_mbps": 100,  "up_mbps": 20,  "weight": 1, "probe_targets": ["223.5.5.5:53"] }
]
```

- **利用率**：`max(rx_bps / max_mbps, tx_bps / up_mbps)`。速率取自
  `/sys/class/net/<if>/statistics` 的差分，再用 EWMA（`alpha = 0.3`，時間常數約 1.5 秒）
  平滑，單拍突發不會讓權重跳動。取兩個方向的最大值：全雙工線路的收發各自獨立，
  任一方向接近上限都算過載。**因此 `max_mbps` 必填**（`load_aware` 開啟時），
  非對稱線路再補 `up_mbps`。
- **基準仍是 §6.5 的容量比例**：過載下修是在 `weight × max_mbps` 的基準上乘一個
  因子，所以 1000:100 的兩條線不會因為「本來就分得多」而被誤判。
- **權重怎麼調**：進入下修的門檻是 `load_target_ratio`（預設 80%），
  解除要跌到 `load_recover_ratio`（預設 60%）——兩者之間的死區是遲滯，
  避免「下修→流量移走→立刻恢復→流量又回來」的震盪。在這段區間內因子線性內插，
  所以「稍微過載」只小幅下修、真的打滿才壓到 `dynamic_weight_min_ratio`。
- **刻度放大**：權重都是 1 時 `round(1 × 0.25)` 會被夾成 1，下修等於沒效果。
  有線被下修時會把整組基準權重放大到至少 4 格（比例不變、只是刻度變細），
  且不會超過 255；壓力解除就還原。
- **與品質感知疊加**：`weight_mode: "quality"` 與 `load_aware` 可同時開啟，
  合成因子 = 品質因子 × 負載因子。
- **更新節奏**：沿用 `dynamic_weight_interval_ms`（預設 10 秒）限速，每次變更是一次
  `RTM_NEWROUTE`。只調整既有 ECMP 的權重，不新增路由、不動 conntrack；
  成員集合沒變，所以也不會觸發 flush-on-switch。
- **可觀測**：狀態檔每條 WAN 多了 `load_pct`（利用率 %，未設容量時為 `null`）與
  `offloaded`（目前是否因過載被下修）；LuCI 卡片會在速率後面顯示
  `(85%, offloaded)`，配合 `W:1 → 4` 就能確認分流正在轉移。

> ⚠️ **本質限制：ECMP 是 per-flow 哈希，不能重分配「單一條大流量」。**
> 權重只決定「新的 flow 落到哪」，已經建立連線不會無痛搬家。所以：
> 由很多條連線組成的負載（P2P、多執行緒下載）效果最好；
> 只有一條 elephant flow 打滿一條線時，下修權重幫不上忙——那條 flow 會留在原地。
> 另外 `standard` ECMP 在權重變更時可能重算整張 multipath hash；
> 想避免既有連線被打斷，請搭配 `ecmp_mode: "resilient"` 或 `"auto"`。
> 全部線路都吃滿時，權重比例不會變（沒有地方可以轉），不會製造無意義的路由變更。

## 專案結構

```
mwan4/
├── Cargo.toml               # Rust 專案配置 (包含 size/lto release 配置)
├── .cargo/
│   └── config.toml          # 本機編譯網路／連結器設定（*.gitignore*，不隨倉庫散佈）
├── src/
│   ├── main.rs              # 守護進程入口、CLI 解析、主事件循環
│   ├── config.rs            # 配置解析 (JSON 支援與驗證)
│   ├── prober.rs            # Non-blocking SO_BINDTODEVICE TCP SYN 探針
│   ├── lqe.rs               # 滑動窗口、EWMA RTT/Jitter、防震盪狀態機
│   └── netlink/
│       ├── mod.rs
│       ├── route.rs         # 純 Rust Netlink FIB Route Manager (ECMP & Failover)
│       ├── conntrack.rs     # 純 Rust CtNetlink 故障連線精準清理器
│       └── util.rs          # 網卡 ifindex 解析、SIOCGIFADDR、對齊函數
├── openwrt/
│   ├── mwan4.json                       # 獨立部署用的設定範本 (/etc/mwan4/mwan4.json)
│   ├── mwan4.init.standalone-example    # 獨立部署用 procd 腳本範例（非套件用；.example 尾碼避免與套件內同名腳本衝突）
│   └── luci-app-mwan4/                  # LuCI 應用（套件實際安裝的 init 腳本位於其 root/etc/init.d/mwan4）
├── scripts/
│   ├── build_packages.py                # APK / IPK / 離線 bundle 打包（含簽名與翻譯編譯）
│   ├── po2lmo.py                        # .po → LuCI .lmo 翻譯編譯器
│   ├── build_mipsel24kc.sh              # mipsel_24kc（tier-3）build-std 交叉編譯
│   └── wsl-mipsel-setup.sh              # 上述腳本的一次性工具鏈安裝
├── openwrt/luci-app-mwan4/po/           # zh_Hans（現代 LuCI 語言碼）與 zh-cn 翻譯
├── .github/workflows/ci.yml             # CI：fmt / clippy / test / 多架構交叉編譯 / 打包冒煙測試
└── mwan4.example.json       # 範例配置文件
```

---

## 快速編譯指南

### 1. 本地檢查與單元測試
```bash
# 執行單元測試（包含 EWMA、狀態機、防震盪機制等驗證）
cargo test

# 針對 Linux musl 目標檢查
cargo check --target x86_64-unknown-linux-musl
```

### 2. 交叉編譯為 OpenWrt 靜態二進位檔案
建議使用 `cross` 工具進行零環境依賴的靜態編譯：

#### 安裝 cross 工具：
```bash
cargo install cross --git https://github.com/cross-rs/cross
```

#### 各路由器架構編譯指令：

* **x86_64 軟路由**：
  ```bash
  cross build --target x86_64-unknown-linux-musl --release
  ```

* **ARM64 (如 MT7981, MT7986, 樹莓派4, RK3399, RK3568 等)**：
  ```bash
  cross build --target aarch64-unknown-linux-musl --release
  ```

* **ARM 32-bit (如 IPQ4019, MT7622 等)**：
  ```bash
  cross build --target armv7-unknown-linux-musleabihf --release
  ```

* **MIPS 小端 (如 MT7621, MT7620 等，OpenWrt arch = `mipsel_24kc`)**：
  ⚠️ **不能用 `cross`／`rustup target add`**：`mipsel-unknown-linux-musl` 是 **tier-3** 目標，
  rustup 沒有預編譯 std（`rustup target add` 會回 *has no prebuilt artifacts available*），
  必須用 `-Z build-std` 從 `rust-src` 現場編 std，並自備 musl sysroot 當連結來源。
  倉庫已把整套流程收成一條指令（Windows 工作站走 WSL Debian；任何 Linux 主機同理）：
  ```bash
  # 一次性環境：rustup（stable + rust-src）+ musl.cc 的 mipsel-linux-musl 交叉工具鏈
  wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/wsl-mipsel-setup.sh

  # 交叉編譯（產物 target/mipsel-unknown-linux-musl/release/mwan4，靜態、soft-float）
  wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/build_mipsel24kc.sh
  ```
  細節：連結器用 musl.cc 的 `mipsel-linux-musl-gcc`（GCC 11.2.1，soft-float ABI）；
  目標特徵額外關掉 `fpxx`（MT7621 這類 24Kc 沒有 FPU，硬浮點指令會直接 SIGILL）。

編譯完成之二進位檔案位於 `target/<TARGET>/release/mwan4`，檔案大小僅約 1.5MB 左右（已內建 stripped + LTO）。

#### 沒有 C 交叉工具鏈時（例如在 Windows 上直接產出 Linux musl 二進位）

musl target 雖然是 self-contained（crt / libc.a 都由 Rust 自帶，見
`lib/rustlib/<target>/lib/self-contained/`），但 **rustc 仍會呼叫一個 `cc` 當連結驅動**。
Windows 上通常沒有 `cc`，此時會得到 `linker cc not found`。可改用 Rust 自帶的
`rust-lld` 直接連結：

```bash
SR="$(rustc --print sysroot)"
LLD="$SR/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld.exe"   # Windows 為 .exe

# 注意：link-self-contained 的 `+linker` 與 linker-flavor `gnu-lld` 目前仍是 nightly 選項，
# 在 stable 上需要 RUSTC_BOOTSTRAP=1 才能用（僅解鎖這兩個選項，不改語言特性）
RUSTC_BOOTSTRAP=1 \
RUSTFLAGS="-Zunstable-options -Clink-self-contained=+linker -Clinker-flavor=gnu-lld -Clinker=$LLD" \
cargo build --release --target aarch64-unknown-linux-musl
```

驗證產物確實是「靜態、正確架構」的 ELF（`PT_INTERP` 不存在 = 靜態）：

```bash
readelf -hl target/aarch64-unknown-linux-musl/release/mwan4   # Machine: AArch64, 無 INTERP
```

### 3. 打包 APK / IPK / 離線 bundle
`scripts/build_packages.py` 會把已編譯的二進位與 LuCI 前端打成可安裝套件：

```bash
# 列出支援的架構，以及對應二進位是否已編譯
python scripts/build_packages.py --list-archs

# 為「所有已編譯二進位的架構」出包；也可用 --arch 明確指定（可重複）
python scripts/build_packages.py
python scripts/build_packages.py --arch aarch64_cortex-a53 --arch x86_64

# CI / 密鑰管理：直接內嵌 PEM，完全不落盤
MWAN4_SIGNING_KEY_PEM="$(cat signing.key)" python scripts/build_packages.py
```

輸出位於 `dist/packages/`（`.apk` / `.ipk` / `mwan4.rsa.pub`）與 `dist/*-bundle.tar.gz`、`dist/install.sh`。幾個刻意的設計：

- **簽名私鑰只生成一次並持久化**（預設 `dist/keys/mwan4.rsa.key`，權限 0600）。私鑰一旦重生成，已裝機裝置就再也驗不過後續套件，因此金鑰必須穩定；`dist/keys/` 與 `*.rsa.key` 一律不入庫。
- **按真實架構出包**：不再產出「標 `arch = all`、內容卻是 aarch64 二進位」的假通用包，跨架構安裝會被 apk/opkg 直接拒絕。
- **依賴聲明**：APK 與 IPK 都宣告 `libc`（OpenWrt/ImmortalWrt 的 libc 包名就是 `libc`）。
  注意不要照 Alpine 寫成 `so:libc.musl-<arch>.so.1` —— OpenWrt 沒有這種 provider，依賴無法解析、安裝會直接失敗。
  錯架構的攔阻由 `.PKGINFO` 的 `arch` 欄位負責，裝到不匹配的架構會被 apk 拒絕。
- **翻譯於打包時編譯**：`.lmo` 由 `.po` 即時生成並裝到 `/usr/lib/lua/luci/i18n/`，避免入庫的 `.lmo` 過期後 UI 默默退回英文。
- **安裝後自檢**：套件 `post-install` 會先跑 `mwan4 --check-config` 再 enable/restart，設定有誤不會把服務帶進崩潰循環。

---

## OpenWrt 安裝與部署指南

### 步驟 1：傳送二進位檔案與設定檔至路由器
```bash
# 傳送執行檔
scp target/x86_64-unknown-linux-musl/release/mwan4 root@192.168.1.1:/usr/bin/mwan4
ssh root@192.168.1.1 "chmod +x /usr/bin/mwan4"

# 建立配置目錄並傳送設定檔
ssh root@192.168.1.1 "mkdir -p /etc/mwan4"
scp openwrt/mwan4.json root@192.168.1.1:/etc/mwan4/mwan4.json

# 傳送 procd 服務腳本（獨立部署範例；.example 尾碼是刻意的，避免與套件內的 /etc/init.d/mwan4 混淆）
scp openwrt/mwan4.init.standalone-example root@192.168.1.1:/etc/init.d/mwan4
ssh root@192.168.1.1 "chmod +x /etc/init.d/mwan4"

# 啟動前先驗證設定（唯讀、不影響線上服務；設定有誤會以非零 exit code 明確失敗）
ssh root@192.168.1.1 "mwan4 --check-config /etc/mwan4/mwan4.json"
```

### 步驟 2：配置 `/etc/mwan4/mwan4.json`
根據實際網路拓撲編輯網卡名稱與網關 IP：
```json
{
  "check_interval_ms": 500,
  "probe_timeout_ms": 400,
  "window_size": 10,
  "loss_threshold_down": 0.5,
  "loss_threshold_up": 0.1,
  "degrade_loss_threshold": 0.2,
  "degrade_hysteresis": 0.1,
  "degrade_exit_samples": 6,
  "consecutive_fail_down": 3,
  "recovery_success_count": 5,
  "max_rtt_ms": 1500.0,
  "flush_conntrack_on_down": true,
  "flush_conntrack_on_switch": true,
  "route_priority": 0,
  "remove_routes_on_exit": false,
  "ecmp_mode": "standard",
  "multipath_hash_policy": null,
  "weight_mode": "static",
  "policies": [],
  "interfaces": [
    {
      "name": "wan1",
      "gateway": "192.168.1.1",
      "metric": 1,
      "weight": 1,
      "probe_targets": [
        "223.5.5.5:53",
        "114.114.114.114:53"
      ]
    },
    {
      "name": "wan2",
      "gateway": "192.168.2.1",
      "metric": 1,
      "weight": 1,
      "probe_targets": [
        "223.5.5.5:53",
        "114.114.114.114:53"
      ]
    }
  ]
}
```

> `route_priority` 刻意**不**在 UCI／LuCI 暴露：它必須與 netifd 自己那條 WAN 預設路由
> 的 metric 一致（通常都是 0），守護進程才能接管預設路由；若設成非 0，netifd 那條
> metric 較小的路由會永遠勝出，故障轉移也就不會生效。

> 其餘選填欄位（未列出者都有預設值）：
> - `rtt_fail_count`（預設 3）：平滑 RTT 連續超標幾次才判 DOWN。
> - `conntrack_flush_min_interval_ms`（預設 10000）：同一張網卡兩次 conntrack 清理的最小間隔。
> - `gateway6`：該 WAN 的 IPv6 閘道，設定後會隨 IPv4 健康狀態一起下發 `::/0` 預設路由。
> - `underlay_targets`：隧道 WAN（VXLAN/WireGuard）的 underlay 對端位址清單，
>   用於自動補上防自環的 /32（見排障指南 §4）；未設定時 init 腳本會嘗試用
>   `ip -d link` 自動偵測，失敗時請手動填。
> - `multipath_hash_policy`：`l3` / `l4` / `inner`，啟動時寫入內核
>   `fib_multipath_hash_policy`（見 §6.1）。
> - `weight_mode` / `dynamic_weight_interval_ms` / `dynamic_weight_min_ratio`：
>   品質感知動態權重（見 §6.2）。
> - `max_mbps`（每條 WAN）：該線最大頻寬（Mbps）。全部 WAN 都設定時，
>   ECMP 基準權重自動 ∝ `weight × max_mbps`（見 §6.5）。JSON 也接受舊名 `down_mbps`。
> - `up_mbps`（每條 WAN，選填）：上行容量，非對稱線路負載感知用；未填沿用 `max_mbps`。
> - `load_aware` / `load_target_ratio` / `load_recover_ratio`：負載感知分流，
>   在容量比例基準上把過載線的流量轉移到空閒線（見 §6.6）。啟用時每條 WAN
>   都必須填 `max_mbps`。
> - `policies`：來源/目的策略分流（見 §6.3）。

### 步驟 3：啟動與設定開機自啟動
```bash
# 停用傳統 mwan3（若有安裝）
/etc/init.d/mwan3 stop 2>/dev/null || true
/etc/init.d/mwan3 disable 2>/dev/null || true

# 啟用並啟動 mwan4
/etc/init.d/mwan4 enable
/etc/init.d/mwan4 start
```

### 步驟 4：查看運作日誌與監控狀態
```bash
# 即時滾動日誌
logread -f -e mwan4
```

輸出範例：
```text
2026-09-12 21:40:00 info mwan4: Starting mwan4 daemon (Probe interval: 500ms, Timeout: 400ms, Window: 10, Hysteresis: 5 success, ECMP mode: Standard)
2026-09-12 21:40:00 info mwan4: Mapped interface wan1 -> ifindex 2
2026-09-12 21:40:00 info mwan4: Mapped interface wan2 -> ifindex 3
2026-09-12 21:40:00 info mwan4: [wan1] Initial link probe succeeded -> UP (RTT: 18.25ms)
2026-09-12 21:40:00 info mwan4: [wan2] Initial link probe succeeded -> UP (RTT: 22.40ms)
2026-09-12 21:40:00 info mwan4: [RouteManager] Atomic FIB Switch: ECMP Multipath default route [nexthop via 192.168.1.1 dev wan1 (w:1) nexthop via 192.168.2.1 dev wan2 (w:1)]
2026-09-12 21:40:00 info mwan4: [RouteManager] Kernel FIB route successfully committed.
2026-09-12 21:40:05 info mwan4: [wan1] State: UP, Loss: 0.0%, RTT: 17.80ms, Jitter: 0.42ms (Successes: 10, Timeouts: 0)
2026-09-12 21:40:05 info mwan4: [wan2] State: UP, Loss: 0.0%, RTT: 21.95ms, Jitter: 0.55ms (Successes: 10, Timeouts: 0)
```

當 `wan1` 斷線時日誌範例：
```text
2026-09-12 21:40:20 warn mwan4: [wan1] Link state transitioned: UP -> DOWN (Timeouts: 3, Loss: 30.0%, RTT: Some(18.2))
2026-09-12 21:40:20 info mwan4: [Conntrack] Flushing active conntrack sessions for wan1 (IP: 192.168.1.100)...
2026-09-12 21:40:20 info mwan4: [Conntrack] Successfully deleted 42 conntrack entries for IP 192.168.1.100
2026-09-12 21:40:20 info mwan4: [RouteManager] Atomic FIB Switch: Single default route via wan2 (3) dev wan2 [gw: 192.168.2.1]
2026-09-12 21:40:20 info mwan4: [RouteManager] Kernel FIB route successfully committed.
```

---

## LuCI Web 管理界面 (`luci-app-mwan4`)

專案內建標準 OpenWrt LuCI 界面（基於現代 LuCI-JS 架構），提供視覺化看板與 UCI 配置：

### 界面特色：
1. **即時健康監控看板**：
   - 頂部顯示守護進程狀態（🟢 運行中 / 🔴 已停止）與內核 FIB 路由狀態（ECMP / 單線容災）。
   - 網卡卡片網格即時展示各 WAN 的狀態徽章（UP/DOWN）、即時 RTT 延遲、Jitter 抖動、滑動窗口丟包率進度條、連續成功/超時計數。
   - 5 秒非同步輪詢自動刷新（離開頁面時自動停止），無需手動重新整理網頁。
2. **直觀易用的 UCI 配置表單**：
   - 全域參數（探測週期、超時、窗口大小、防震盪次數、Conntrack 自動清理）。
   - 表格式網卡列表（直接關聯系統網卡下拉選單、網關 IP、ECMP 權重、動態探測目標列表）。
   - 點擊「保存並應用」自動觸發 procd 重新載入，無縫生效。

### 手動安裝 LuCI 界面至路由器：
```bash
# 複製文件至 OpenWrt 對應目錄
scp openwrt/luci-app-mwan4/root/etc/config/mwan4 root@192.168.1.1:/etc/config/mwan4
scp openwrt/luci-app-mwan4/root/etc/init.d/mwan4 root@192.168.1.1:/etc/init.d/mwan4
ssh root@192.168.1.1 "chmod +x /etc/init.d/mwan4"

scp openwrt/luci-app-mwan4/root/usr/share/luci/menu.d/luci-app-mwan4.json root@192.168.1.1:/usr/share/luci/menu.d/
scp openwrt/luci-app-mwan4/root/usr/share/rpcd/acl.d/luci-app-mwan4.json root@192.168.1.1:/usr/share/rpcd/acl.d/

ssh root@192.168.1.1 "mkdir -p /www/luci-static/resources/view/mwan4"
scp openwrt/luci-app-mwan4/htdocs/luci-static/resources/view/mwan4/overview.js root@192.168.1.1:/www/luci-static/resources/view/mwan4/

# 安裝簡體中文語言包（預設語言為英文，安裝後在中文環境下自動呈現簡體中文）
# 注意：現代 LuCI（21.02+）的語言碼是 zh_Hans，lmo 檔名必須精確匹配才會被載入；
# 舊版 LuCI 用 zh-cn。打包腳本會同時裝兩個檔名，手動部署時照做即可：
#   python scripts/po2lmo.py openwrt/luci-app-mwan4/po/zh_Hans/mwan4.po /tmp/mwan4.zh_Hans.lmo
scp /tmp/mwan4.zh_Hans.lmo root@192.168.1.1:/usr/lib/lua/luci/i18n/mwan4.zh_Hans.lmo
scp /tmp/mwan4.zh_Hans.lmo root@192.168.1.1:/usr/lib/lua/luci/i18n/mwan4.zh-cn.lmo

# 重啟 rpcd 與 uhttpd 生效
ssh root@192.168.1.1 "rm -rf /tmp/luci-indexcache /tmp/luci-modulecache; /etc/init.d/rpcd restart; /etc/init.d/uhttpd restart"
```
登入 LuCI 後即可在 **「Network」->「MWAN4 Load Balancing」**（中文環境下為 **「網路」->「MWAN4 多路分流」**）查看並管理。

## 排障指南（實戰踩坑）

### 1. 隧道型 WAN（VXLAN / WireGuard）必須放行 UDP 埠

若某條「線路」本身是隧道（VXLAN、WireGuard、IPsec 等），請注意 **underlay 通 ≠ 隧道通**。
OpenWrt 的 `wan` zone 預設 `input=REJECT`，會把對端主動送來的 UDP 封包擋掉，
而症狀極容易誤判成對端的問題：

- `ping <隧道對端>` 100% 丟包，`ip -s link` 顯示 **TX 有包、RX 為 0**
- 於是很自然地去懷疑「對端沒啟動 / 對端寫死了我的舊 IP」

實測（VXLAN，vni 100 / dstport 4789）在 underlay 網卡上抓包才看清真相：

```
tcpdump -i eth1 -n "udp port 4789 or icmp"
我們發:   ... > 10.128.0.20.4789  VXLAN  ARP Request who-has 10.77.0.1
對端回:   10.128.0.20.54636 > ...4789  VXLAN  ARP Reply 10.77.0.1 is-at ...
我們卻回: ... > 10.128.0.20  ICMP udp port 4789 unreachable   ← 自己擋的
```

**對端一直在回包，是自己的防火牆拒了。** 放行即可：

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-VXLAN-4789'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].dest_port='4789'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall && /etc/init.d/firewall reload
```

> 判斷口訣：**「對端零回包」不等於「對端沒回」。** 先在 underlay 網卡上抓一次包再下結論，
> 能省掉一整圈冤枉路。busybox 沒有 `timeout`，限時抓包用 `tcpdump ... & PID=$!` + `sleep` + `kill $PID`。

### 2. `probe_targets` 要用 UCI `list`，不是 `option`

init 腳本用 `config_list_foreach probe_targets` 讀取，所以：

```sh
uci add_list mwan4.wan1.probe_targets='223.5.5.5:53'   # ✅ 正確
uci set     mwan4.wan1.probe_targets='223.5.5.5:53'    # ⚠️ 建出來的是 option
```

寫成 `option`（手寫設定檔或 `uci set` 都很容易踩）時會被**靜默忽略**，
悄悄退回預設的 `223.5.5.5:53 / 114.114.114.114:53`。
症狀是「設定檔看起來完全正確，但這條線就是莫名丟包、DOWN」——
因為它實際上在探一個你沒指定的目標。新版本已相容 `option` 並會記一條 log 提醒改成 `list`。
（LuCI 介面用的是 `DynamicList`，透過介面設定不會有這個問題。）

### 3. 動態 IP 不需要特殊處理

underlay 走 DHCP 時，隧道只要綁定 `tunlink`（netifd 會在 WAN 變化時自動重建隧道），
對端若是「來源不限制 / 動態學習」模式，我們換 IP 後它會自動跟上。
實測故障轉移過程中 DHCP 把 IP 從 `10.176.27.28` 換成 `10.176.43.73`，隧道照常恢復。

### 4. ⚠️ 隧道型 WAN 加入 ECMP 會自環（丟包／整條不可用）

**症狀**：把隧道（VXLAN/WireGuard）設成第二條線後，一切到 `ecmp_mode: resilient`
隧道就開始丟包、被判定 DOWN，嚴重時整台機器沒網。切回 `standard` 又看似正常。

**根因**：隧道的封裝封包目的地是 underlay 對端（例：VXLAN 的 `remote 10.128.0.20`），
而它得靠 main 表的**預設路由**送出。一旦預設路由是「含這條隧道的 ECMP」，
就有約 1/N 的機率把封裝封包**再塞回同一條隧道** —— 封裝包進隧道、隧道再封裝，
形成自環。實測：雙線 ECMP 下隧道丟包 60%，`ping` 5 個只回 2 個。

**這個 bug 特別會騙人**：`ip route get 10.128.0.20` 會顯示正確的 `dev eth1`，
看起來完全沒問題 —— 因為它只是固定哈希的**單次採樣**，而真實流量帶隨機源埠，
哈希結果不同。別被它騙了，要看實際丟包率。

**修法（本專案已自動處理）**：為對端補一條 `/32` 路由走「非隧道」的那條 WAN。
`/32` 前綴比預設路由長，必然優先，於是封裝封包永遠走 underlay，不再有機率回灌。

- OpenWrt 的 init 腳本會**自動探測 VXLAN 的 `remote`** 填進 `underlay_targets`，開箱即用。
- 掃描時機分兩種：**啟動前**會把殘留的探針 `/32`（metric 42760）與 underlay `/32`
  （metric 42761）一起清掉（上次執行的出口可能已經失效）；**執行期**的探針路徑清掃
  **只清探針 `/32`**，不會動 underlay —— 兩者若混在一起清，同一批指令裡剛裝好的
  underlay `/32` 會被誤刪，而記憶體快取還記著「已裝」就再也不補（實測：啟動後 40 秒
  一直是 0 條，隧道封裝封包只能走 ECMP，約 1/2 機率自環丟包）。
- 每次同步 underlay `/32` 前都會向內核轉儲一次實際狀態（`metric 42761`）：
  「快取說已裝、但內核裡其實沒有」的項目一律重下（`NLM_F_REPLACE` 冪等），
  所以外部 `ip route del` 或任何誤刪都能在下一次下發／心跳（30 秒）內自愈。
- 手寫設定檔時請自己填（也可用來覆蓋自動偵測的結果）：

```json
{
  "name": "vxlan0",
  "gateway": "10.77.0.1",
  "metric": 10,
  "weight": 1,
  "probe_targets": ["223.5.5.5:53"],
  "underlay_targets": ["10.128.0.20"]
}
```

驗證方式：設定生效後 main 表會多出 `10.128.0.20/32 via <物理線閘道> dev <物理線>`，
且隧道丟包率應回到接近 0。

## 已知限制與整合測試

### 已知限制（實測整理）

- **IPv6 conntrack 不會被清理**：清理器以 NAT 後的 WAN IPv4 位址匹配連線
  （`ORIG.src` / `REPLY.dst`）。IPv6 一般是路由而非 NAT，tuple 裡是 LAN 客戶端自己的
  全域位址、不會出現 WAN 位址，而內核 conntrack 也沒有「按出介面刪除」的下發介面。
  IPv6 長連線在切換後只能等自身超時（TCP 會以新來源位址重建）。若部署使用 NAT66，
  請以 `nft ... ct` 規則另行處理。
- **conntrack zone**：清理時會把 dump 到的 `CTA_ZONE` 原樣帶回刪除訊息，非 0 zone 的部署
  不會漏刪或誤刪；zone 0（絕大多數部署）行為不變。
- **IPv6 不允許「純 dev」multipath**：內核直接拒絕
  *"Device only routes can not be added for IPv6 using the multipath API"*。
  該 WAN 必須設定 `gateway6`（SLAAC/DHCPv6 環境通常都有）。
- **netlink 查詢在事件迴圈上是同步的**：查詢 socket 的逾時已縮到 300ms，但在網卡很多
  且內核一時無回應時仍可能造成短暫延遲；決策失敗時一律用保守值繼續（當成「沒有路」）。
- **建立/刪除路由帶專屬 `proto 77`（0x4D）**：刪除只會命中本程式下發的路由，不會誤刪
  netifd 或其它工具的路由；啟動清掃的殘留處理改用 protocol 通配符，才清得掉舊版本留下
  的 `/32`。
- **策略分流只支援 IPv4 且只匹配前綴**：`policies` 用 `from`/`to` 匹配來源/目的前綴，
  不支援埠號或應用層條件；IPv6 流量仍走 ECMP。
- **strict `rp_filter` 與策略分流衝突**：內核的反向路徑檢查只查主表，而策略流量是依規則
  查另一張表；`rp_filter=1` 的 WAN 可能把回程當成 martian 丟棄。請設 `rp_filter=2`
  （loose）或 `0`（多 WAN 環境本來就建議如此）。
- **動態權重會重下路由**：每次權重變更都是一次 `RTM_NEWROUTE`，`standard` ECMP 下內核會
  重算 multipath hash，既有 flow 可能被改派；已用 `dynamic_weight_interval_ms` 限速，
  要完全避免請用 `ecmp_mode: resilient`/`auto` 或維持 `weight_mode: static`。
- **負載感知只重分配 flow、不能搬「單一條大流量」**：ECMP 是 per-flow 哈希，
  下修權重只影響之後新建的連線。多連線的總量（下載、P2P）有效；單一 elephant flow
  佔滿一條線時無能為力。詳見 §6.6。
- **速率取樣來自介面計數器**：`tx_bps`/`rx_bps` 是 `/sys/class/net` 的累計值差分，
  介面重建（PPPoE 重撥）後第一次取樣會歸零，屬正常現象。

### `--check-config` 會擋下的設定（啟動前失敗，而不是默默接受）

- 未知欄位（`_` 開頭視為註解，例如 `_comment`）；網卡區塊與 `policies` 區塊同理
- `probe_timeout_ms > check_interval_ms`、`check_interval_ms` 超過 1 小時
- `max_rtt_ms` 非有限值（例如 `1e999` 會被 JSON 解析成 `+inf`，靜默關閉 RTT 判據）
- 網卡名稱含 `/`、空白或超過 15 字元；loopback／multicast 的 gateway／gateway6／
  underlay 目標；port 0 的探針目標
- 動態權重：`dynamic_weight_interval_ms` 不在 1000~3600000、
  `dynamic_weight_min_ratio` 不在 0.05~1.0
- 容量（`max_mbps` / `up_mbps`）不是有限正數；或只給部分 WAN 設了 `max_mbps`
  （容量比例分流要求全填或全不填）
- 負載感知：`load_target_ratio` 不在 (0,1]、`load_recover_ratio` 不小於
  `load_target_ratio`，或啟用 `load_aware` 卻有 WAN 沒填 `max_mbps`
- 策略分流：名稱重複/過長、目標 WAN 不在 `interfaces`、CIDR 非法（前綴需 0~32）、
  展開後超過 64 條、`priority` 超出 9000~9063／重複／只設定一部分

### 真實核心整合測試（netns）

路由編碼的正確性只有真實內核說得準（例如 DELNEXTHOP 的 header 必須全零，否則內核回
EINVAL 而刪除靜默失敗）。整合測試會在免洗 netns 裡建立 dummy 網卡、下發真正的
ECMP／resilient／策略路由並驗證：

```bash
cargo test --no-run
unshare -Urn sh -c \
  'MWAN4_NETNS_TEST=1 cargo test --offline -- --ignored netns --test-threads=1'
```

`unshare -Urn` 只需要使用者命名空間（userns + netns + CAP_NET_ADMIN），**不需要 root**，
也不會動到主機路由。涵蓋：標準 ECMP 安裝／全斷二態／退出清理、resilient group
建立→成員縮減→全斷拆除→cleanup、nexthop object 新增刪除、探針路徑（規則＋獨立表＋
主表 `/32`）、隧道 underlay `/32` 清理、IPv6 ECMP、**策略分流**（`from`/`to` 規則安裝／
核心查找命中指定表／移除／清掃）。

## 致謝

- [DeepSeek](https://www.deepseek.com)：參與架構設計、程式碼實作、跨平台編譯與路由器實機驗證。
- OpenWrt / LuCI：Netlink、rpcd、LuCI-JS 的既有實作與文件。

---

## 授權條款
MIT License.
