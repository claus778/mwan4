# MWAN4 (Multi-WAN 4)

专为 Linux / OpenWrt 深度设计的极轻量、零负担、高性能「多 WAN 故障转移与健康监控守护进程（Daemon）」。

用以彻底替代架构笨重、频繁呼叫 Shell 脚本、吃 CPU 且严重破坏硬体加速（Flow Offload）的传统 `mwan3`。

---

## 为什么需要 MWAN4？（对比传统 MWAN3）

| 特性 / 指标 | 传统 OpenWrt mwan3 | MWAN4 (本专案) |
| :--- | :--- | :--- |
| **转发面架构** | 依赖数十条 `iptables`/`nftables` fwmark 打标与 Policy Routing | **100% 依赖 Linux 原生 FIB (Multipath ECMP)**（转发流量完全不经 fwmark／策略路由；仅探针的控制面为每张 WAN 各用一条 `oif` 规则，见 §1） |
| **硬体加速相容性** | ❌ **破坏硬体加速** (Flow Offload / HW NAT 遇到 packet mark 会失效) | ✅ **原生相容 Flow Offload** (PPE, MT798x, MT7621, x86) |
| **控制面操作方式** | 频繁执行外部 Shell、`ip`、`ubus`、`logger` 进程 | **纯 Netlink Sockets**（控制面零外部子进程） |
| **CPU 占用率** | 较高（频繁 fork/exec 脚本，尤其在弱 CPU 路由器） | **< 0.1%**（单线程非同步事件驱动） |
| **记忆体占用 (RSS)** | 数十 MB（多个 shell 子进程 + 巨型规则表） | **< 4 MB** |
| **故障转移时延** | 数秒至数十秒 | **< 1 秒**（原子化 FIB 路由切换 + Conntrack 精准清理） |
| **TCP 断线卡死问题** | 经常残留无效 session，需漫长 TCP 重传超时 | **自动 Netlink 清理失效网卡 Conntrack**，秒级恢复 |

---

## 核心架构规范

### 1. 双 WAN 探测器（Prober）
- **出口网卡强制绑定**：使用 Non-blocking Socket 并透过 `SO_BINDTODEVICE` 强制将探针绑定到特定网卡（如 `wan1`、`wan2`）。
- **探针路径与预设路由解耦（重要）**：`SO_BINDTODEVICE` 只是把路由查找的 `oif` 固定到该设备，
  **并不代表一定找得到路**——主表若没有「经该设备」的路由，内核会把封包当成 on-link 直接丢进黑洞
  （实测结果是 `connect()` 一直超时，而不是回报 `ENETUNREACH`），于是「预设路由被删掉或被切到别条线」
  就等于「这条线永远回不去」。因此启动时会为每张 WAN 建立一张**独立路由表**
  （`default via <gateway> dev <wan>`）＋一条 **`oif <wan> lookup <table>`** 规则
  （表号与规则优先序都从 10000 起算）。规则只匹配「绑定该设备的本机封包」，所以探针一定有路可走，
  而**转发流量（`oif = br-lan`）与路由器其它本机流量完全不受影响**。
- **回程（`rp_filter`）处理**：内核的反向路径检查**只查主表**，看不到 FIB 规则。实测：主表没有涵盖
  探针目标的路由时，即使出向完全正常、封包也确实送达对端，回来的 SYN-ACK 仍会被当成 martian 丢掉
  （症状是探针「一直超时」）。因此守护进程会在**必要时**于主表补一条探针目标的 `/32`（metric 42760）：
  - 主表根本没有涵盖该目标的路由时 → 一定补（否则收不到回程；此时也不会「抢」到本来可用的路径）；
  - 主表有路、但 `rp_filter` 是 strict（`1`）且该目标**没有被别的 WAN 共用**时 → 补（strict 要求
    回程走同一张网卡）；
  - 其余情况（含 `rp_filter` 为 loose/关闭）→ **不补**，避免影响 LAN 到该目标的转发路径；
  - 线路变成活跃后会把 `/32` 收回。

  ⚠️ **已知限制**：`rp_filter=1`（strict）**且多条 WAN 共用同一个探针目标**时，主表里同一个前缀只能
  指向一张网卡，因此同一时间只可能有一条线探得通。这种组合下守护进程**不会**下发 `/32`（否则会把
  持有主路由的那条线判成 martian、两条线互相判死），并会明确告警建议改成：
  `sysctl -w net.ipv4.conf.all.rp_filter=2`（loose）＋各 WAN 介面 `.../<wan>.rp_filter=2`，
  或让每条 WAN 使用各自的探针目标。

  可用下列指令核对：
  ```sh
  ip rule show | grep 'lookup 1000'                 # oif <wan> lookup <10000+i>
  ip route show table 10000                          # 第 0 张 WAN 的探针预设路由
  ip route get 223.5.5.5 oif wan1                    # 应显示 via <gw>（有 via 才代表有路）
  ip route show table main | grep 'metric 42760'     # 只在必要时短暂出现的探针 /32
  ip route show table main | grep 'metric 42761'     # 隧道 underlay 对端的防自环 /32
  ```
  **保留区段**（本程式专用，请勿他用）：路由表 `10000..10063`、规则优先序 `10000..10063`、
  主表 metric `42760`（探针 /32）与 `42761`（隧道 underlay /32）。我们的规则都带来源标记（`FRA_PROTOCOL = 0x4D`），启动清扫**只删带这个
  标记的规则**，不会动到第三方的规则；清扫也不再主动删保留表内的路由（没有规则指向它就是惰性的，
  而且我们重用该表时会直接 REPLACE）。
- **探测协议**：以高效 TCP SYN 探测公共 DNS（预设为大陆地区的 `223.5.5.5:53`、`114.114.114.114:53`），周期预设为 500ms。TCP SYN 探针具备极高穿透力，不会被运营商 ICMP 限速或丢弃。
- **多目标容灾（主目标 + 失败回退）**：支援单一网卡配置多个探测目标，健康时每个周期只探「上次探通的那个」（每条 WAN 每周期只产生 1 条短命 TCP 连线，conntrack／LuCI 连线列表不会被探针灌满）；只有它失败才探测其余目标，保留「单一 DNS 被墙或故障时自动切换目标」的容灾能力。
- **上一拍失败时改为并行探测（r10）**：只要上一拍是失败的（`consecutive_timeouts > 0`），该线的**所有目标同时发出**（每个目标仍拿到完整的 `probe_timeout_ms`，没有任何目标被缩短；健康时依旧只发一条连线）。为什么：旧写法「先等主目标超时、再并发探其余目标」在全部目标都不回应时会让一个周期花掉 **2 × `probe_timeout_ms`**（预设 400ms → 800ms），比 `check_interval_ms`（预设 500ms）还长，而 `tokio::time::interval` 的 `MissedTickBehavior::Skip` 会把错过的拍**直接丢掉**，于是探测节奏被悄悄拉长成 800ms：
  - 连续 3 拍判 DOWN：**2.4 秒 → 1.5 秒**；
  - 连续 5 拍恢复：**4.0 秒 → 2.5 秒**（线路恢复后多快回到 ECMP）；
  - `degrade_enter_samples: 20` 等「拍数」设定本来是按 500ms 周期写的，旧行为下实际是 16 秒，现在是 10 秒。
  本机 netns 实测（两条 dummy WAN、两个目标都被黑洞、真实 daemon、以状态档摘要行的时间戳计拍长）：

  | | 每拍实际耗时 | 10 拍摘要间隔 |
  | --- | --- | --- |
  | 旧（先等主目标超时） | **806 ms** | 8.06 s |
  | 新（疑似故障时并行） | **500 ms** | 5.00 s |

  结果选择逻辑与旧版完全一致（主目标成功就用主目标，否则用第一个成功的目标，全失败时优先回传「非本机条件」的那一笔失败），因此 `preferred_target` 与状态档的失败原因不会因为并行而跳动。
- **失败原因可观测**：状态档会记录每张网卡的 `last_error` 与 `local_condition`
  （`No such device`／`Network is unreachable`／`Create socket failed`／
  `No targets configured`／`No route to host` 等属于**本机条件**，不是运营商丢包），
  info 级日志也会针对这类错误告警一次。超时文案只说
  `Timeout (no reply within 400ms)`，不断言「丢包」（上游黑洞／本机无路由／对端不回
  SYN-ACK 的表象相同）。此外状态档还有 `degraded`（是否已因丢包被移出 ECMP）、
  `samples_in_window` / `window_full`（窗口是否已填满，未满则不做丢包率判定）与
  `state_reason`（`consecutive_timeouts` / `window_loss` / `rtt` / `recovery`，
  说明这次是被哪一条判据移出或救回）。

### 2. 链路评分与状态机（LQE - Link Quality Estimator）
- **滑动窗口与平滑算法**：维护长度为 10 的滑动窗口，使用 EWMA（指数加权移动平均）动态估算 RTT 与抖动（Jitter）：
  $$\text{RTT}_{\text{new}} = \alpha \cdot \text{RTT}_{\text{sample}} + (1 - \alpha) \cdot \text{RTT}_{\text{old}} \quad (\alpha = 0.20)$$
  $$\text{Jitter}_{\text{new}} = \beta \cdot |\text{RTT}_{\text{sample}} - \text{RTT}_{\text{old}}| + (1 - \beta) \cdot \text{Jitter}_{\text{old}} \quad (\beta = 0.25)$$
- **一个探测周期 = 一个样本（r10 起）**：所有「连续几拍」的设定（`consecutive_fail_down`
  = 3、`recovery_success_count` = 5、`degrade_enter_samples` = 20 …）都是按
  `check_interval_ms`（预设 500ms）写的。旧版在「上一拍失败」时会把一个周期拉长成
  2 × `probe_timeout_ms`（800ms，见 §1），这些设定实际会被乘以 1.6
  （20 拍 = 16 秒而不是 10 秒）；并行探测后拍长回到 500ms，判 DOWN、恢复、
  进出降级的时间才与设定值一致。
- **状态判定标准**：
  - **UP**：连续成功次数达标且 RTT 正常（见下方 Hysteresis）。
  - **DOWN**：连续 3 次探测超时（`consecutive_fail_down`），或滑动窗口丢包率 **> 50%**
    （`loss_threshold_down`），或平滑 RTT 连续超标（`rtt_fail_count` 次）。
    状态档的 `state_reason` 与 DOWN 日志都会写出**实际触发**的那一条
    （`consecutive_timeouts` / `window_loss` / `rtt` / `recovery`），
    避免只看到 `Loss: 30%` 而与配置的 50% 门槛互相矛盾。
- **严格防震荡机制（Hysteresis）**：
  - 当线路处于 DOWN 时，必须**连续成功** `recovery_success_count` 次（预设 5）、
    且 RTT 正常，才能恢复为 UP。
  - 恢复判据**不再包含窗口丢包率**：`loss_threshold_up`（旧栏位，保留仅为相容设定档）
    与 `window_size` 耦合——`window_size = 10`、门槛 10% 时等于「窗口内最多 1 次失败」，
    于是 DOWN（尾部 3 连败触发）要连续 **9** 次成功才能恢复，把配置的
    `recovery_success_count = 5` 静默抬成 9（实测日志正是 `Consecutive successes: 9`），
    DOWN 约 1.5 秒、UP 要 4.5 秒以上，强不对称造成反复翻转。
  - 防震荡并未因此消失：探测过程中若发生任何一次超时，连续成功计数立即归零重新累积；
    回到 UP 之后若品质仍差，上面的 DOWN 判据会立刻再把它打下去。
  - 动态升 / 降级（`degrade_loss_threshold`，预设 0.20 = 20%，设 `0` 关闭）：
    滑动窗口**已填满**且窗口丢包率 **>= 该值**时，这条线「降级」= 不参与 ECMP；
    但它**仍持续探测**，品质恢复后自动回到 ECMP。介于降级门槛与判死门槛（0.50）
    之间的线路不会被判 DOWN，旧版会让它照样吃一半流量（实测 20% 丢包时主表仍是
    两条 nexthop 的 ECMP）。为避免「全部线路都降级 → 完全没有预设路由」，
    此时会**保底**取 metric 最小的 Up 线承载并印出一次 warn。状态档的 `degraded`
    栏位可看出某条线是否正被排除。
  - **降级带双门槛迟滞 + 最短连续保持**（`degrade_hysteresis` 预设 0.10、
    `degrade_exit_samples` 预设 6）：**进入**降级看 `degrade_loss_threshold`（20%），
    **退出**降级要窗口丢包率 `<= degrade_loss_threshold - degrade_hysteresis`（预设 10%）
    且**连续** `degrade_exit_samples` 次都达标（中间夹一次不达标就重新数）。
    为什么需要：窗口长度 10 的量化步长就是 10%，注入 12%~30% 丢包时窗口丢包率会在
    10% / 20% / 30% 之间摆动——单一门槛的纯函式判定会每几秒进出一次降级，
    每次都触发 `Active WAN set changed` 并重下 ECMP 路由（实测 20 秒内 5~6 次，
    路由成员持续抖动）。迟滞让「刚被踢出」的线必须明显变好才准回来。
    `degrade_hysteresis` 必须严格小于 `degrade_loss_threshold`（`--check-config` 会挡）。
  - **进入也要持续、离开也要待满**（`degrade_enter_samples` 预设 20、
    `degrade_min_out_samples` 预设 20，单位都是「探测样本数」）：
    - **进入**要「连续 20 个样本都超标」才算数（`window_size = 10` 时约 2 个窗口、
      500ms 周期约 10 秒）。为什么不是「1 个窗口就够」：窗口是 FIFO，某个窗口里
      出现 2 次超时后，这个 20% 会**再持续 8 个样本**才被挤出去，所以
      「连续 2 拍超标」几乎等于单一窗口达标，挡不住任何东西。
    - **离开**除了要连续达标 `degrade_exit_samples` 次，还要已经离开 ECMP 至少
      `degrade_min_out_samples` 个样本。
    - 为什么两者都要（实机 2026-09 案例）：一条隧道型 WAN（WireGuard）被自己的流量
      打满时 SYN 探针会偶尔超时 → 单一窗口刚好 20% → 旧版**立刻**把它移出 ECMP，
      全部流量瞬时压到另一条线（那条线瞬间被打满＝使用者说的「一条线突然很卡」），
      几秒后该线恢复、又被加回来，加回来后再次被打满 → 形成 10 秒级的
      「单线 ↔ 双线」循环。每一次循环都要重算整张 multipath hash
      （standard 模式还会 flush conntrack）＝「网路一直卡」。
      现在：短暂抖动不会降级；真的被降级的线也要在外面待满一段时间才准回来。
    - 两个值都设 1 / 0 可还原旧行为；`degrade_enter_samples` 设 0 会被
      `--check-config` 挡下（要关降级请把 `degrade_loss_threshold` 设 0）。
    - 降级/回归事件现在都会写 log（带窗口丢包率、门槛与累积拍数），
      `Active WAN set changed` 也会列出每条线的 `state / in|out / degraded`，
      不必再从「成员变少」去猜原因。

### 3. Netlink FIB 执行器（Route Manager）
- 100% 透过 Linux 原生 Netlink Socket (`NETLINK_ROUTE`) 操作内核路由表（`RT_TABLE_MAIN`），绝不呼叫 `ip route` 等外部命令。
- **原子化路由切换**：
  - 双 WAN 正常：下发 ECMP 预设路由（支援配置权重 `weight`）。
  - 单 WAN 故障：原子化发送 `RTM_NEWROUTE`（`NLM_F_REPLACE`），即刻将预设路由收敛至存活线路。
  - 线路恢复：原子化切回双路 ECMP 负载均衡。
- **全部断线时的语意（实测决定）**：
  - 若主表**只有我们这一条**预设路由 → **保留**（删掉会让整机含所有 LAN 客户端完全没有出口）；
  - 若主表**还有别人的预设路由**（例如 netifd 的 metric 10/50）→ **删掉我们这条，让兜底接手**。
    原因：载波掉（拔网线、对端下线，介面仍是 UP）时内核**不会**自己移除「dev 指向该设备」的路由，
    它只是标成 linkdown 并继续胜过 metric 更大的兜底，流量会一直被送往死链路。
  - 因为探针有自己的独立表（不依赖这条预设路由），删掉它不会让 daemon 失去探测能力。
- **失败可感知、可自愈**：netlink worker 会把每次下发的成功／失败回报主回圈；
  失败时不更新「已下发」记录，并在数秒后重下同一份期望状态（同一个错误只告警一次，
  之后每 20 次提醒一次，避免永久失败时把 logd 环形缓冲刷掉）。此外每 30 秒有一次
  心跳重下（幂等），修复被其它程序或内核事件改动的路由。
- **退出语意**：`remove_routes_on_exit` 预设 `false`——服务重启／升级的窗口内保留预设路由，
  避免整网瞬断；设为 `true` 时也**只会删掉自己真的下发过的那条**（从未接管过就不碰 netifd 的路由）。
  无论设定为何，**探针路径（独立表内的路由、`oif` 规则、主表探针 `/32`）与隧道 underlay
  `/32` 一律会拆除**（underlay 路由指向的旧闸道若留著，会把封装封包黑洞到失效出口）。

### 4. 连线黏滞：三种 ECMP 模式（`ecmp_mode`）
多 WAN 最容易被测出来的坑是「**一有线路抖动，既有连线就集体断**」，而**玩游戏时感受最痛**：
被改派到另一条 WAN 的连线换了 NAT 源 IP，对端只看到未知四元组（RST／大量重传），
玩家看到的是「玩到一半突然卡顿」。三种模式的差异在于**链路集合或权重变动时，内核如何重算多路径哈希**：

| 模式 | 内核机制 | 链路／权重变动时的行为（本机实测） | 需求 |
| --- | --- | --- | --- |
| `standard` | `RTA_MULTIPATH`（传统 multipath route） | 重算整张哈希表：权重 1:1→1:10 搬走 **40%**、新增成员（线路恢复回归）**40%**、移除成员（降级／DOWN）**43%** 的既有连线 —— **连健康线路上的连线也一起被改派** | 所有 Linux |
| `resilient` | 弹性 nexthop group（`RTM_NEWNEXTHOP` + `NHA_RES_GROUP`） | 只重映射**空闲** bucket（`NHA_RES_GROUP_IDLE_TIMER` 内核预设 120 秒，使用中的 bucket 延后迁移）：权重变更 **0%**、新增成员 **0%**；移除成员只搬走**该成员自己**的 bucket，线路回归后内核把**原本属于它**的 bucket 还给回去（实测 bucket 表与中断前**逐桶一致**） | Linux ≥ 5.14 |
| `auto`（**预设**） | 先试 `resilient`，内核不支援则永久退回 `standard` | 同上；不支援时自动降级，不报错 | — |

> 量法：本机 netns、Linux 6.18、32 个 flow key（32 个来源位址）、`fib_multipath_hash_fields=31`，
> 以**网卡 TX 计数**确认真实出口（不是 `ip route get`，它会吃到路由快取）。
> 回归测试见 `src/netlink/route/netns_tests.rs` 的 `netns_route_lifecycle`。
>
> 同一套量法在**真实守护进程**（netns 里跑 `mwan4`、配置里不写 `ecmp_mode`）上复现：
> 两条线在跑 → 把 wan1 的链路真的弄断（探针连续超时 → DOWN → 成员被移除，路由变成
> 单个成员）→ **健康线 wan0 上的 8/8 条 flow 一条都没动**；wan1 的 8 条被挤到 wan0；
> 等 wan1 恢复（成员回归）→ 那 8 条**回到 wan1**（bucket 表逐桶还原），wan0 上原有的 flow 不动。
> 对比 `standard`：任何一次成员变动都会重算整张哈希表，健康线上的 flow 也会被改派。

- **预设是 `auto`（r9 起）**：核心支援 nexthop object 就用 `resilient`，否则退回 `standard`（等同旧版行为）。
  要旧行为请**明确**写 `standard`。为什么不再预设 `standard`：它的重哈希会连坐健康线路
  （上表 40%~43%），而「抖动即断连」正是这个坑；`resilient` 才有「只动故障成员」的黏滞效果。
- 选用 `standard` 时，守护进程才会在切换瞬间 flush conntrack（让连线尽快重建）；`resilient` 会**抑制** flush-on-switch，否则等于亲手抹掉黏滞效果。
  flush 范围：**只清「新进入存活集合」的成员**（`is_active(m) && !prev.contains(&m.ifindex)`）。
  旧版在双线 ECMP 下会连健康成员一起清（见下一节的实测日志），既打断健康线的连线、
  也抵销了 `resilient` 想保住黏滞的意义。
- **动态权重因子（`weight_mode: quality` / `load_aware`）在 `standard` 下会被忽略**（只保留
  静态 `weight`／`max_mbps` 比例），并在启动后第一次更新时印一次 warn。注意判据是
  **内核实际安装的变体**：明确设 `standard`，或 `auto` 在旧核心上退回了 `standard`，都会挡。
  理由：`standard` 的每一次权重变更都是「重算整张 multipath hash」，实测（Linux 6.12/6.18、512 个 flow key）
  会把 **24%~39% 的既有连线**改送到另一条 WAN；转发流量换了 NAT 源 IP 之后对端只会
  看到未知四元组（RST／大量重传），而 per-flow 哈希又**搬不动**已建立的大流量，
  所以净效果是「打断连线却换不到分流」。预设 `auto` 在支援的核心上会让动态权重直接生效
  （`resilient` 只重映射故障/空闲的 bucket，实测满载中的 bucket 不会被搬动）；
  真的理解代价仍要在 `standard` 下使用时，设 `allow_dynamic_weights_on_standard: true`。
- **flush-on-switch 的判据是「实际安装成功的变体」**（FIX-8 已修）：worker 每次下发路由后
  会回报核心实际生效的是 `standard` 还是 `resilient`，因此 `auto` 在旧内核上退回 `standard`
  时，切换瞬间仍会正确清 conntrack。`standard` / `resilient` 两种明确设定行为不变。
- 单一 ECMP 组的成员数上限为 256（bucket 数上限），超过会被视为不支援而退回 `standard`。
  bucket 数以巢状在 `NHA_RES_GROUP` 里的 `NHA_RES_GROUP_BUCKETS`（u16）传递，必须是 2 的幂且不小于成员数；
  早期版本误用顶层的 `NHA_RES_BUCKET`(13) 并以 u32 编码，内核会当成「没给 bucket 数」回 `EINVAL`，
  导致 `resilient` 从未真正生效（成员 nexthop 建得出来、group 建不出来、预设路由不下发）。已在 r5 修正。

### 5. 连线快取清理（Conntrack Flushing）
- 透过 Netfilter Netlink（`NETLINK_NETFILTER` / `NFNL_SUBSYS_CTNETLINK`）直接与内核 conntrack 表交互。
- 当线路判定为 DOWN 时，程式会精准扫描并删除绑定在该网卡 IP 上的活跃连线，使客户端的 TCP/UDP 连线能立即由存活网卡重新 NAT，解决长连线卡死问题。
  为避免把「其实还活著」的连线一次砍掉（实测隧道抖动一次就砍 495 条，使用者立刻看到
  「网站打不开」），判 DOWN 后会先静默 25 秒（`CONNTRACK_FLUSH_DOWN_QUIET`），
  期间若恢复就不清。
- **切换时只清新进入的成员**：ECMP 成员集合变动时（`flush_conntrack_on_switch`），
  清理名单只有「新进入存活集合」的线（`is_active(m) && !prev.contains(&m.ifindex)`）。
  旧版在双线 ECMP 下会把**所有存活成员**（含一直健康的那条）一起清——因为
  `multipath_involved = prev.len() > 1 || new_set.len() > 1` 在双线时恒为真，
  实测日志是「只有 wan1 健康却被清」「恢复瞬间两条都清」，健康线上的 NAT 连线被 RST。
  离开集合的成员由上述 25 秒静默路径负责。

### 6. 分流进阶功能

#### 6.1 多路径哈希策略（`multipath_hash_policy`）——「多条连线为什么全挤一条线」

ECMP 的分流粒度由内核的 `fib_multipath_hash_policy` 决定（IPv4；启用 IPv6 时一并写入
IPv6 那一份）。**预设 `l4`（r10 起）**；明确写 `null`（或 UCI 留空）= 完全不写入、
沿用内核预设。

**为什么要把预设从「不写入」改成 `l4`**：内核预设是 `0`（只哈希来源／目的 IP），
于是**同一个目的 IP 的所有连线只会走同一条 WAN**。视频网站（YouTube / Bilibili …）
对同一个 CDN IP 会开多条连线（分段请求 + QUIC 串流），它们全部挤在一条线上的结果
就是：另一条线完全用不到，那条线一吃满就开始缓冲 —— 使用者看到的就是「双 WAN 了
还是卡」。本机 netns 实测（Linux 7.1.8、真实 UDP 封包、**以网卡 TX 计数**判定出口，
不用 `ip route get`——它会命中路由快取而量不到东西）：

| policy | 「同一个目的 IP、只差来源埠」的 24 条连线 | 结论 |
| --- | --- | --- |
| `0`（`l3`，内核预设） | **24/24 走同一条线** | 视频 CDN 的多条连线只用到一条 WAN |
| `1`（`l4`，**本专案预设**） | **12/24 + 12/24 分开** | 按连线分散，两条线都用到 |
| `2`（`inner`） | 24/24 走同一条线（无封装流量） | 只对 VXLAN/GRE 等封装流量有意义 |

同样的量测也用在**转发**流量上（veth 注入 → 内核转发 → 双 dummy WAN），结论一致。

```json
"multipath_hash_policy": "l4"
```

> ⚠️ **关于 `net.ipv4.fib_multipath_hash_fields`（与旧版说明相反）**：旧版 README 主张
> 这个位元遮罩会「架空 policy」（只要非 0 内核就只看位元）。**本机实测无法复现**：
> 该档案可以写入、也能读回（1/7/8/9/31/32 都接受，0 被拒），但**无论写成哪一个，
> 哈希结果都与 policy 一致**——`policy=0` 时 24 条只差来源埠的连线仍然 24/24 同一条线。
> 也就是说：**真正有效的是 policy**，位元在这个内核上只是被存起来。
> 因为无法确定哪些内核版本以位元为准，守护进程仍然会依 policy 把缺少的位元
> **只补不删**地补齐（`l4` → `31`、`l3` → `7`），并把 **policy 与位元两者的读回值**
> 一起写进 log 与状态档（`hash.policy` / `hash.fields` / `hash.l3_only`），
> 让「设定档写了 l4」与「内核真的按连线分流」这两件事能被分辨。

启动时会读回实际值并印出：

```text
Multipath hash in effect (ipv4): policy=1 fields=31 (src_ip+dst_ip+ip_proto+src_port+dst_port)
```

若实际生效的是 L3 粒度（`hash.l3_only = true`），而且有两条以上的 WAN，启动时会明确提示
（`null` = 使用者无意间拿到 L3 → `warn`；明确写 `l3` / `inner` → `info`，因为他知道自己在做什么）。
LuCI 的标题列也有「哈希粒度」徽章（`l4：按连线分散` / `仅 L3：同一目的 IP 只走一条 WAN`），
不必去翻 log。

| 值 | policy sysctl | 语义 | 适用 |
| --- | --- | --- | --- |
| `l3` | 0 | 只哈希来源／目的 IP | 同一个玩家到同一个伺服器的所有连线黏在同一条线**对游戏最友好**（抖动时不会一半被搬走）；代价是视频 CDN 的多条连线也只用到一条 WAN |
| `l4` | 1 | 再加上 L4 来源／目的埠 | **预设**；分流最均匀（视频、多执行绪下载、P2P） |
| `inner` | 2 | L3 + 隧道内层标头 | 只有 VXLAN/GRE 等封装流量受益；一般网页/视频流量等同 `l3` |
| `null` / 空 | 不写入 | 沿用系统预设 | 想自己管这个内核开关时 |
| （旧设定档没有这个栏位） | — | **= `l4`（r10 的新预设）** | — |

- 变更需重启服务；写入失败（旧内核没有这些档案、或 `/proc` 不可写）只告警，不影响启动。
- **升级提醒**：UCI 的预设值从空字串改成 `l4`。已安装的机器若原本就是
  `option multipath_hash_policy ''`，升级后**行为不变**（仍是内核预设 = L3），
  但守护进程启动时会 warn 一次告诉你「实际粒度是 L3、视频 CDN 的多条连线只会走一条 WAN」，
  照提示改成 `l4` 即可。
- 此设定与 `weight`／`ecmp_mode` 互补：**policy 决定「怎么分」，权重决定「分多少」**。

#### 6.2 品质感知动态权重（`weight_mode: "quality"`）

静态权重只看设定值，线路品质变化时只能靠「降级（移出 ECMP）」这种 0/1 手段。
`weight_mode: "quality"` 会依 LQE 的实测品质**连续**调整各线权重：

```json
"weight_mode": "quality",
"dynamic_weight_interval_ms": 10000,
"dynamic_weight_min_ratio": 0.25
```

- 演算法：`factor = (1 - 窗口丢包率) × clamp(最佳 RTT / 本线 RTT, min_ratio, 1.0)`，
  等效权重 = `clamp(round(设定 weight × factor), 1, 255)`；窗口未填满或没有 RTT 样本时不惩罚。
- 更新有限速（`dynamic_weight_interval_ms`，预设 10 秒）：每次变更都会重下 ECMP 路由，
  内核可能重算 multipath hash，过于频繁会反复打断既有 flow。
  **在实际安装的是 `standard`（明确设定 `standard`，或 `auto` 在旧核心上退回）时，动态因子会被整个忽略**
  （只留静态 weight/max_mbps 比例）并印一次 warn（**只有 worker 回报内核真的装了 standard
  之后才会印**：开机第一拍变体还没回报，不会在支援 resilient 的机器上误报）—— standard 的每次权重变更实测会搬走
  24%~39% 的既有连线，却搬不动真正造成偏载的大流量。预设 `auto` 在支援 nexthop object 的
  核心上（Linux ≥ 5.14）会让动态因子**直接生效**：resilient 只重映射空闲 bucket，
  权重变更实测搬走 0%，因此不会打断既有连线。要强制在 standard 下使用请设
  `allow_dynamic_weights_on_standard: true` 覆写此保护。
- 品质差到降级门槛的线仍由既有 `degrade_loss_threshold` 机制移出；动态权重只处理
  「还可用但品质有差」的区间。
- 状态档的 `effective_weight` 会显示实际下发值（LuCI 的 Priority/Weight 栏位会显示
  `W1 → 2` 这种变化），方便验证。

#### 6.3 策略分流：来源/目的指定 WAN（`policies`）

除了按 flow 哈希的 ECMP，还可以让**指定来源（可选目的）的转发流量走指定 WAN**。
实作刻意不使用 fwmark/nftables，而是 `ip rule` 的 `from`/`to` + 该 WAN 的独立路由表——
路由查找时直接命中，不在封包上打标，因此不破坏 Flow Offload：

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

- `source` / `destination` 都是 IPv4 CIDR 清单；留空 = 不限制（清单展开后总规则数上限 64）。
- 规则优先序预设依 `policies` 阵列顺序（9000 起）；也可全部明确指定 `priority`
  （9000~9063，数字越小越先匹配；要嘛全部指定、要嘛全部不指定）。
- **目标 WAN 判 DOWN 时整条政策自动移除**，匹配流量回退 ECMP；恢复后自动装回。
- 未匹配的流量仍走原本的 ECMP 预设路由，两者不冲突。
- 注意：策略规则只匹配来源/目的前缀（不是埠），且仅 IPv4；使用 strict `rp_filter`（=1）
  的环境可能因回程反向检查而丢包，请将 WAN 设为 loose（=2）或关闭（见排障指南）。
- LuCI 的「Policy Routing (Source / Destination)」表格可直接维护；标题列会显示
  目前生效中的政策（`名称→WAN`），未生效会标 `(inactive)`。

#### 6.4 分流效果可视化

状态档 `/tmp/mwan4_status.json` 每条 WAN 有：

- `tx_bps` / `rx_bps`：即时速率（bit/s，取样自 `/sys/class/net/<if>/statistics`），
  用来看 ECMP 是否真的把流量分到多条线；
- `effective_weight`：动态权重实际下发值；
- `load_pct` / `offloaded`：负载利用率与是否正被下修；
- `policies[]`：每条政策的 `name` / `interface` / `priority` / `active`。

另外有一个**顶层 `hash` 物件**，回报内核**实际生效**（读回，不是设定值）的多路径哈希：

- `hash.policy` / `hash.fields`：`fib_multipath_hash_policy` 与
  `fib_multipath_hash_fields` 的读回值（`null` = 内核没有那个档案）；
- `hash.fields_desc`：位元的可读描述，例如 `31 (src_ip+dst_ip+ip_proto+src_port+dst_port)`；
- `hash.l3_only`：**true = 同一个目的 IP 的所有连线只会走一条 WAN**（视频 CDN 卡顿的
  典型成因，见 §6.1）。设定档写了 `l4` 但内核没吃下去时，这里会照实呈现。

LuCI 的 WAN 卡片会显示「Throughput (TX / RX)」，标题列会显示政策状态与
**哈希粒度徽章**（`l4：按连线分散` / `仅 L3：同一目的 IP 只走一条 WAN`）。

#### 6.5 依「最大频宽」比例分流（`max_mbps`）

多条线的频宽往往不同（例如 wan1 1000M、wan2 100M）。只要**每一条 WAN 都设定
`max_mbps`（该线最大频宽，Mbps）**，ECMP 的基准权重就会自动变成
`weight × max_mbps` 的比例——不需要自己手算 weight：

```json
"interfaces": [
  { "name": "wan1", "max_mbps": 1000, "up_mbps": 100, "weight": 1, "probe_targets": ["223.5.5.5:53"] },
  { "name": "wan2", "max_mbps": 100,  "up_mbps": 20,  "weight": 1, "probe_targets": ["223.5.5.5:53"] }
]
```

- 上例的活跃权重比就是 **1000 : 100 = 10 : 1**（最小那条正规化成 1）。
- `weight` 仍可当**手动倍率**（例如 `weight: 2` 代表 `2 × max_mbps`）。
- 单一 nexthop 的权重上限是 255，所以比例差距超过 **255:1** 时会夹在 255:1
  （1000M 对 1M 这种极端组合会退化，但差距 ≤ 255 倍都能精确表达）。
- 设定是「**要嘛全部 WAN 都填 max_mbps、要嘛全部不填**」；只填一部分会被
  `--check-config` 挡下，因为比例无从定义。
- `up_mbps`（上行容量，选填）只用于负载感知的利用率；未填时沿用 `max_mbps`。

> 这是**静态比例**：开机时依频宽决定好权重就不再变。若还要「某条线快打满时把
> flow 转走」，再加上 §6.6 的 `load_aware`。

#### 6.6 负载感知分流：一条线吃满就把流量转到别条（`load_aware`）

§6.5 决定「按频宽该分多少」，这一节处理「**实际流量把某条线打满**」。
ECMP 只按 flow 哈希，即使权重按频宽设好，也可能因为 flow 分布而偏载；
品质感知只会因为丢包／RTT 才动作，对「还没丢包但频宽快爆」无感。
`load_aware` 用**实测速率 vs 该线最大频宽**算出利用率，把过载那条的权重再下修，
空闲的线权重放大，让后续的 flow 改走空闲线：

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
  `/sys/class/net/<if>/statistics` 的差分，再用 EWMA（`alpha = 0.3`，时间常数约 1.5 秒）
  平滑，单拍突发不会让权重跳动。取两个方向的最大值：全双工线路的收发各自独立，
  任一方向接近上限都算过载。**因此 `max_mbps` 必填**（`load_aware` 开启时），
  非对称线路再补 `up_mbps`。
- **基准仍是 §6.5 的容量比例**：过载下修是在 `weight × max_mbps` 的基准上乘一个
  因子，所以 1000:100 的两条线不会因为「本来就分得多」而被误判。
- **权重怎么调**：进入下修的门槛是 `load_target_ratio`（预设 80%），
  解除要跌到 `load_recover_ratio`（预设 60%）——两者之间的死区是迟滞，
  避免「下修→流量移走→立刻恢复→流量又回来」的震荡。在这段区间内因子线性内插，
  所以「稍微过载」只小幅下修、真的打满才压到 `dynamic_weight_min_ratio`。
- **刻度放大**：权重都是 1 时 `round(1 × 0.25)` 会被夹成 1，下修等于没效果。
  有线被下修时会把整组基准权重放大到至少 4 格（比例不变、只是刻度变细），
  且不会超过 255；压力解除就还原。
- **与品质感知叠加**：`weight_mode: "quality"` 与 `load_aware` 可同时开启，
  合成因子 = 品质因子 × 负载因子。
- **更新节奏**：沿用 `dynamic_weight_interval_ms`（预设 10 秒）限速，每次变更是一次
  `RTM_NEWROUTE`。只调整既有 ECMP 的权重，不新增路由、不动 conntrack；
  成员集合没变，所以也不会触发 flush-on-switch。
- **过载状态翻转时立刻生效（r10）**：限速只约束「持续微调」；当某条线的
  「是否过载」状态**翻转**（进入过载或解除过载）时会跳过 10 秒闸门，在下一拍（约 0.5 秒）
  就重下权重，但仍保留 1 秒的最小间隔（`WEIGHT_UPDATE_MIN_SPACING`）避免在门槛附近翻转时
  刷路由表。为什么：旧版把状态机的更新也关在 10 秒闸门里，于是「某条线刚开始吃满」的头
  10 秒里，新建的连线照样往那条线丢 —— 视频就是在这段时间里开始缓冲。日志会标出
  `load-transition=true` 让你看得出这次是转换插队、还是到期例行更新。
- **`standard` 模式下 `load_aware` 同样被忽略**（warn 一次，只留 `max_mbps` 容量比例）：
  standard 的权重变更会重算整张 multipath hash、把 24%~39% 的**既有**连线改送到另一条 WAN
  （实测），而它想搬走的正是那些既有的大流量 —— 结果是打断连线却没有分流效果。
  预设 `auto` 在支援 nexthop object 的核心上直接生效（resilient 权重变更实测搬走 0%）；
  要强制在 standard 下使用请设 `allow_dynamic_weights_on_standard: true`。
- **可观测**：状态档每条 WAN 多了 `load_pct`（利用率 %，未设容量时为 `null`）与
  `offloaded`（目前是否因过载被下修）；LuCI 卡片会在速率后面显示
  `(85%, offloaded)`，配合 `W:1 → 4` 就能确认分流正在转移。

> ⚠️ **本质限制：ECMP 是 per-flow 哈希，不能重分配「单一条大流量」。**
> 权重只决定「新的 flow 落到哪」，已经建立连线不会无痛搬家。所以：
> 由很多条连线组成的负载（P2P、多执行绪下载）效果最好；
> 只有一条 elephant flow 打满一条线时，下修权重帮不上忙——那条 flow 会留在原地。
> 另外 `standard` ECMP 在权重变更时可能重算整张 multipath hash；
> 预设 `auto`（resilient）不会——只有明确设 `standard` 才需要担心。
> 全部线路都吃满时，权重比例不会变（没有地方可以转），不会制造无意义的路由变更。

## 专案结构

```
mwan4/
├── Cargo.toml               # Rust 专案配置 (包含 size/lto release 配置)
├── .cargo/
│   └── config.toml          # 本机编译网路／连结器设定（*.gitignore*，不随仓库散布）
├── src/
│   ├── main.rs              # 守护进程入口、CLI 解析、主事件循环
│   ├── config.rs            # 配置解析 (JSON 支援与验证)
│   ├── prober.rs            # Non-blocking SO_BINDTODEVICE TCP SYN 探针
│   ├── lqe.rs               # 滑动窗口、EWMA RTT/Jitter、防震荡状态机
│   └── netlink/
│       ├── mod.rs
│       ├── route.rs         # 纯 Rust Netlink FIB Route Manager (ECMP & Failover)
│       ├── conntrack.rs     # 纯 Rust CtNetlink 故障连线精准清理器
│       └── util.rs          # 网卡 ifindex 解析、SIOCGIFADDR、对齐函数
├── openwrt/
│   ├── mwan4.json                       # 独立部署用的设定范本 (/etc/mwan4/mwan4.json)
│   ├── mwan4.init.standalone-example    # 独立部署用 procd 脚本范例（非套件用；.example 尾码避免与套件内同名脚本冲突）
│   └── luci-app-mwan4/                  # LuCI 应用（套件实际安装的 init 脚本位于其 root/etc/init.d/mwan4）
├── scripts/
│   ├── build_packages.py                # APK / IPK / 离线 bundle 打包（含签名与翻译编译）
│   ├── po2lmo.py                        # .po → LuCI .lmo 翻译编译器
│   ├── build_mipsel24kc.sh              # mipsel_24kc（tier-3）build-std 交叉编译
│   └── wsl-mipsel-setup.sh              # 上述脚本的一次性工具链安装
├── openwrt/luci-app-mwan4/po/           # zh_Hans（现代 LuCI 语言码）与 zh-cn 翻译
├── .github/workflows/ci.yml             # CI：fmt / clippy / test / 多架构交叉编译 / 打包冒烟测试
└── mwan4.example.json       # 范例配置文件
```

---

## 快速编译指南

### 1. 本地检查与单元测试
```bash
# 执行单元测试（包含 EWMA、状态机、防震荡机制等验证）
cargo test

# 针对 Linux musl 目标检查
cargo check --target x86_64-unknown-linux-musl
```

### 2. 交叉编译为 OpenWrt 静态二进位档案
建议使用 `cross` 工具进行零环境依赖的静态编译：

#### 安装 cross 工具：
```bash
cargo install cross --git https://github.com/cross-rs/cross
```

#### 各路由器架构编译指令：

* **x86_64 软路由**：
  ```bash
  cross build --target x86_64-unknown-linux-musl --release
  ```

* **ARM64 (如 MT7981, MT7986, 树莓派4, RK3399, RK3568 等)**：
  ```bash
  cross build --target aarch64-unknown-linux-musl --release
  ```

* **ARM 32-bit (如 IPQ4019, MT7622 等)**：
  ```bash
  cross build --target armv7-unknown-linux-musleabihf --release
  ```

* **MIPS 小端 (如 MT7621, MT7620 等，OpenWrt arch = `mipsel_24kc`)**：
  ⚠️ **不能用 `cross`／`rustup target add`**：`mipsel-unknown-linux-musl` 是 **tier-3** 目标，
  rustup 没有预编译 std（`rustup target add` 会回 *has no prebuilt artifacts available*），
  必须用 `-Z build-std` 从 `rust-src` 现场编 std，并自备 musl sysroot 当连结来源。
  仓库已把整套流程收成一条指令（Windows 工作站走 WSL Debian；任何 Linux 主机同理）：
  ```bash
  # 一次性环境：rustup（stable + rust-src）+ musl.cc 的 mipsel-linux-musl 交叉工具链
  wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/wsl-mipsel-setup.sh

  # 交叉编译（产物 target/mipsel-unknown-linux-musl/release/mwan4，静态、soft-float）
  wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/build_mipsel24kc.sh
  ```
  细节：连结器用 musl.cc 的 `mipsel-linux-musl-gcc`（GCC 11.2.1，soft-float ABI）；
  目标特征额外关掉 `fpxx`（MT7621 这类 24Kc 没有 FPU，硬浮点指令会直接 SIGILL）。

编译完成之二进位档案位于 `target/<TARGET>/release/mwan4`，档案大小仅约 1.5MB 左右（已内建 stripped + LTO）。

#### 没有 C 交叉工具链时（例如在 Windows 上直接产出 Linux musl 二进位）

musl target 虽然是 self-contained（crt / libc.a 都由 Rust 自带，见
`lib/rustlib/<target>/lib/self-contained/`），但 **rustc 仍会呼叫一个 `cc` 当连结驱动**。
Windows 上通常没有 `cc`，此时会得到 `linker cc not found`。可改用 Rust 自带的
`rust-lld` 直接连结：

```bash
SR="$(rustc --print sysroot)"
LLD="$SR/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld.exe"   # Windows 为 .exe

# 注意：link-self-contained 的 `+linker` 与 linker-flavor `gnu-lld` 目前仍是 nightly 选项，
# 在 stable 上需要 RUSTC_BOOTSTRAP=1 才能用（仅解锁这两个选项，不改语言特性）
RUSTC_BOOTSTRAP=1 \
RUSTFLAGS="-Zunstable-options -Clink-self-contained=+linker -Clinker-flavor=gnu-lld -Clinker=$LLD" \
cargo build --release --target aarch64-unknown-linux-musl
```

验证产物确实是「静态、正确架构」的 ELF（`PT_INTERP` 不存在 = 静态）：

```bash
readelf -hl target/aarch64-unknown-linux-musl/release/mwan4   # Machine: AArch64, 无 INTERP
```

### 3. 打包 APK / IPK / 离线 bundle
`scripts/build_packages.py` 会把已编译的二进位与 LuCI 前端打成可安装套件：

```bash
# 列出支援的架构，以及对应二进位是否已编译
python scripts/build_packages.py --list-archs

# 为「所有已编译二进位的架构」出包；也可用 --arch 明确指定（可重复）
python scripts/build_packages.py
python scripts/build_packages.py --arch aarch64_cortex-a53 --arch x86_64

# CI / 密钥管理：直接内嵌 PEM，完全不落盘
MWAN4_SIGNING_KEY_PEM="$(cat signing.key)" python scripts/build_packages.py
```

输出位于 `dist/packages/`（`.apk` / `.ipk` / `mwan4.rsa.pub`）与 `dist/*-bundle.tar.gz`、`dist/install.sh`。几个刻意的设计：

- **签名私钥只生成一次并持久化**（预设 `dist/keys/mwan4.rsa.key`，权限 0600）。私钥一旦重生成，已装机装置就再也验不过后续套件，因此金钥必须稳定；`dist/keys/` 与 `*.rsa.key` 一律不入库。
- **按真实架构出包**：不再产出「标 `arch = all`、内容却是 aarch64 二进位」的假通用包，跨架构安装会被 apk/opkg 直接拒绝。
- **依赖声明**：APK 与 IPK 都宣告 `libc`（OpenWrt/ImmortalWrt 的 libc 包名就是 `libc`）。
  注意不要照 Alpine 写成 `so:libc.musl-<arch>.so.1` —— OpenWrt 没有这种 provider，依赖无法解析、安装会直接失败。
  错架构的拦阻由 `.PKGINFO` 的 `arch` 栏位负责，装到不匹配的架构会被 apk 拒绝。
- **翻译于打包时编译**：`.lmo` 由 `.po` 即时生成并装到 `/usr/lib/lua/luci/i18n/`，避免入库的 `.lmo` 过期后 UI 默默退回英文。
- **安装后自检**：套件 `post-install` 会先跑 `mwan4 --check-config` 再 enable/restart，设定有误不会把服务带进崩溃循环。

---

## OpenWrt 安装与部署指南

### 步骤 1：传送二进位档案与设定档至路由器
```bash
# 传送执行档
scp target/x86_64-unknown-linux-musl/release/mwan4 root@192.168.1.1:/usr/bin/mwan4
ssh root@192.168.1.1 "chmod +x /usr/bin/mwan4"

# 建立配置目录并传送设定档
ssh root@192.168.1.1 "mkdir -p /etc/mwan4"
scp openwrt/mwan4.json root@192.168.1.1:/etc/mwan4/mwan4.json

# 传送 procd 服务脚本（独立部署范例；.example 尾码是刻意的，避免与套件内的 /etc/init.d/mwan4 混淆）
scp openwrt/mwan4.init.standalone-example root@192.168.1.1:/etc/init.d/mwan4
ssh root@192.168.1.1 "chmod +x /etc/init.d/mwan4"

# 启动前先验证设定（唯读、不影响线上服务；设定有误会以非零 exit code 明确失败）
ssh root@192.168.1.1 "mwan4 --check-config /etc/mwan4/mwan4.json"
```

### 步骤 2：配置 `/etc/mwan4/mwan4.json`
根据实际网路拓扑编辑网卡名称与网关 IP：
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
  "degrade_enter_samples": 20,
  "degrade_min_out_samples": 20,
  "consecutive_fail_down": 3,
  "recovery_success_count": 5,
  "max_rtt_ms": 1500.0,
  "flush_conntrack_on_down": true,
  "flush_conntrack_on_switch": true,
  "route_priority": 0,
  "remove_routes_on_exit": false,
  "ecmp_mode": "auto",
  "multipath_hash_policy": "l4",
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

> `route_priority` 刻意**不**在 UCI／LuCI 暴露：它必须与 netifd 自己那条 WAN 预设路由
> 的 metric 一致（通常都是 0），守护进程才能接管预设路由；若设成非 0，netifd 那条
> metric 较小的路由会永远胜出，故障转移也就不会生效。

> 其余选填栏位（未列出者都有预设值）：
> - `rtt_fail_count`（预设 3）：平滑 RTT 连续超标几次才判 DOWN。
> - `degrade_enter_samples`（预设 20）/ `degrade_min_out_samples`（预设 20）：
>   进入降级要连续几个样本超标、以及降级后至少离开 ECMP 几个样本才准回来
>   （单位为探测样本数；见 §2）。设 1 / 0 = 旧行为。
> - `allow_dynamic_weights_on_standard`（预设 false）：是否允许在 `standard` ECMP 下
>   套用 quality / load_aware 动态因子（预设忽略，见 §4 与 §6.2）。
> - `conntrack_flush_min_interval_ms`（预设 10000）：同一张网卡两次 conntrack 清理的最小间隔。
> - `gateway6`：该 WAN 的 IPv6 闸道，设定后会随 IPv4 健康状态一起下发 `::/0` 预设路由。
> - `underlay_targets`：隧道 WAN（VXLAN/WireGuard）的 underlay 对端位址清单，
>   用于自动补上防自环的 /32（见排障指南 §4）；未设定时 init 脚本会尝试用
>   `ip -d link` 自动侦测，失败时请手动填。
> - `ecmp_mode`（预设 **`auto`**）：`standard` / `auto` / `resilient`，见 §4。
>   要旧行为（单一 multipath 路由）必须明确写 `standard`。
> - `multipath_hash_policy`（预设 **`l4`**）：`l3` / `l4` / `inner`，启动时写入内核
>   `fib_multipath_hash_policy`。**这是「分流粒度」的有效开关**：`l3`（内核预设）下
>   同一个目的 IP 的连线只走一条 WAN，视频 CDN 的多条连线用不到第二条线；
>   `l4` 才会按连线分散（见 §6.1，含 netns 实测数据）。**写 `null` = 不写入内核**。
>   守护进程会把 `fib_multipath_hash_fields` 依 policy 补齐，并把 policy 与位元的
>   读回值印在 log（`Multipath hash in effect (...)`) 与状态档（`hash` 栏位）。
> - `weight_mode` / `dynamic_weight_interval_ms` / `dynamic_weight_min_ratio`：
>   品质感知动态权重（见 §6.2）。
> - `max_mbps`（每条 WAN）：该线最大频宽（Mbps）。全部 WAN 都设定时，
>   ECMP 基准权重自动 ∝ `weight × max_mbps`（见 §6.5）。JSON 也接受旧名 `down_mbps`。
> - `up_mbps`（每条 WAN，选填）：上行容量，非对称线路负载感知用；未填沿用 `max_mbps`。
> - `load_aware` / `load_target_ratio` / `load_recover_ratio`：负载感知分流，
>   在容量比例基准上把过载线的流量转移到空闲线（见 §6.6）。启用时每条 WAN
>   都必须填 `max_mbps`。
> - `policies`：来源/目的策略分流（见 §6.3）。

### 步骤 3：启动与设定开机自启动
```bash
# 停用传统 mwan3（若有安装）
/etc/init.d/mwan3 stop 2>/dev/null || true
/etc/init.d/mwan3 disable 2>/dev/null || true

# 启用并启动 mwan4
/etc/init.d/mwan4 enable
/etc/init.d/mwan4 start
```

### 步骤 4：查看运作日志与监控状态
```bash
# 即时滚动日志
logread -f -e mwan4
```

输出范例：
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

当 `wan1` 断线时日志范例：
```text
2026-09-12 21:40:20 warn mwan4: [wan1] Link state transitioned: UP -> DOWN (Timeouts: 3, Loss: 30.0%, RTT: Some(18.2))
2026-09-12 21:40:20 info mwan4: [Conntrack] Flushing active conntrack sessions for wan1 (IP: 192.168.1.100)...
2026-09-12 21:40:20 info mwan4: [Conntrack] Successfully deleted 42 conntrack entries for IP 192.168.1.100
2026-09-12 21:40:20 info mwan4: [RouteManager] Atomic FIB Switch: Single default route via wan2 (3) dev wan2 [gw: 192.168.2.1]
2026-09-12 21:40:20 info mwan4: [RouteManager] Kernel FIB route successfully committed.
```

---

## LuCI Web 管理界面 (`luci-app-mwan4`)

专案内建标准 OpenWrt LuCI 界面（基于现代 LuCI-JS 架构），提供视觉化看板与 UCI 配置：

### 界面特色：
1. **即时健康监控看板**：
   - 顶部显示守护进程状态（🟢 运行中 / 🔴 已停止）与内核 FIB 路由状态（ECMP / 单线容灾）。
   - 网卡卡片网格即时展示各 WAN 的状态徽章（UP/DOWN）、即时 RTT 延迟、Jitter 抖动、滑动窗口丢包率进度条、连续成功/超时计数。
   - 5 秒非同步轮询自动刷新（离开页面时自动停止），无需手动重新整理网页。
2. **分流粒度可验证**：标题列新增「哈希粒度」徽章，直接显示内核**实际生效**的
   policy/fields（读回值）。`仅 L3：同一目的 IP 只走一条 WAN` 就是把视频流量挤在
   一条线上的元凶（见 §6.1）。
3. **直观易用的 UCI 配置表单**：
   - 全域参数（探测周期、超时、窗口大小、防震荡次数、Conntrack 自动清理）。
   - 表格式网卡列表（直接关联系统网卡下拉选单、网关 IP、ECMP 权重、动态探测目标列表）。
   - 点击「保存并应用」自动触发 procd 重新载入，无缝生效。

### 手动安装 LuCI 界面至路由器：
```bash
# 复制文件至 OpenWrt 对应目录
scp openwrt/luci-app-mwan4/root/etc/config/mwan4 root@192.168.1.1:/etc/config/mwan4
scp openwrt/luci-app-mwan4/root/etc/init.d/mwan4 root@192.168.1.1:/etc/init.d/mwan4
ssh root@192.168.1.1 "chmod +x /etc/init.d/mwan4"

scp openwrt/luci-app-mwan4/root/usr/share/luci/menu.d/luci-app-mwan4.json root@192.168.1.1:/usr/share/luci/menu.d/
scp openwrt/luci-app-mwan4/root/usr/share/rpcd/acl.d/luci-app-mwan4.json root@192.168.1.1:/usr/share/rpcd/acl.d/

ssh root@192.168.1.1 "mkdir -p /www/luci-static/resources/view/mwan4"
scp openwrt/luci-app-mwan4/htdocs/luci-static/resources/view/mwan4/overview.js root@192.168.1.1:/www/luci-static/resources/view/mwan4/

# 安装简体中文语言包（预设语言为英文，安装后在中文环境下自动呈现简体中文）
# 注意：现代 LuCI（21.02+）的语言码是 zh_Hans，lmo 档名必须精确匹配才会被载入；
# 旧版 LuCI 用 zh-cn。打包脚本会同时装两个档名，手动部署时照做即可：
#   python scripts/po2lmo.py openwrt/luci-app-mwan4/po/zh_Hans/mwan4.po /tmp/mwan4.zh_Hans.lmo
scp /tmp/mwan4.zh_Hans.lmo root@192.168.1.1:/usr/lib/lua/luci/i18n/mwan4.zh_Hans.lmo
scp /tmp/mwan4.zh_Hans.lmo root@192.168.1.1:/usr/lib/lua/luci/i18n/mwan4.zh-cn.lmo

# 重启 rpcd 与 uhttpd 生效
ssh root@192.168.1.1 "rm -rf /tmp/luci-indexcache /tmp/luci-modulecache; /etc/init.d/rpcd restart; /etc/init.d/uhttpd restart"
```
登入 LuCI 后即可在 **「Network」->「MWAN4 Load Balancing」**（中文环境下为 **「网路」->「MWAN4 多路分流」**）查看并管理。

## 排障指南（实战踩坑）

### 1. 隧道型 WAN（VXLAN / WireGuard）必须放行 UDP 埠

若某条「线路」本身是隧道（VXLAN、WireGuard、IPsec 等），请注意 **underlay 通 ≠ 隧道通**。
OpenWrt 的 `wan` zone 预设 `input=REJECT`，会把对端主动送来的 UDP 封包挡掉，
而症状极容易误判成对端的问题：

- `ping <隧道对端>` 100% 丢包，`ip -s link` 显示 **TX 有包、RX 为 0**
- 于是很自然地去怀疑「对端没启动 / 对端写死了我的旧 IP」

实测（VXLAN，vni 100 / dstport 4789）在 underlay 网卡上抓包才看清真相：

```
tcpdump -i eth1 -n "udp port 4789 or icmp"
我们发:   ... > 10.128.0.20.4789  VXLAN  ARP Request who-has 10.77.0.1
对端回:   10.128.0.20.54636 > ...4789  VXLAN  ARP Reply 10.77.0.1 is-at ...
我们却回: ... > 10.128.0.20  ICMP udp port 4789 unreachable   ← 自己挡的
```

**对端一直在回包，是自己的防火墙拒了。** 放行即可：

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-VXLAN-4789'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].dest_port='4789'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall && /etc/init.d/firewall reload
```

> 判断口诀：**「对端零回包」不等于「对端没回」。** 先在 underlay 网卡上抓一次包再下结论，
> 能省掉一整圈冤枉路。busybox 没有 `timeout`，限时抓包用 `tcpdump ... & PID=$!` + `sleep` + `kill $PID`。

### 2. `probe_targets` 要用 UCI `list`，不是 `option`

init 脚本用 `config_list_foreach probe_targets` 读取，所以：

```sh
uci add_list mwan4.wan1.probe_targets='223.5.5.5:53'   # ✅ 正确
uci set     mwan4.wan1.probe_targets='223.5.5.5:53'    # ⚠️ 建出来的是 option
```

写成 `option`（手写设定档或 `uci set` 都很容易踩）时会被**静默忽略**，
悄悄退回预设的 `223.5.5.5:53 / 114.114.114.114:53`。
症状是「设定档看起来完全正确，但这条线就是莫名丢包、DOWN」——
因为它实际上在探一个你没指定的目标。新版本已相容 `option` 并会记一条 log 提醒改成 `list`。
（LuCI 介面用的是 `DynamicList`，透过介面设定不会有这个问题。）

### 3. 动态 IP 不需要特殊处理

underlay 走 DHCP 时，隧道只要绑定 `tunlink`（netifd 会在 WAN 变化时自动重建隧道），
对端若是「来源不限制 / 动态学习」模式，我们换 IP 后它会自动跟上。
实测故障转移过程中 DHCP 把 IP 从 `10.176.27.28` 换成 `10.176.43.73`，隧道照常恢复。

### 4. ⚠️ 隧道型 WAN 加入 ECMP 会自环（丢包／整条不可用）

**症状**：把隧道（VXLAN/WireGuard）设成第二条线后，一切到 `ecmp_mode: resilient`
隧道就开始丢包、被判定 DOWN，严重时整台机器没网。切回 `standard` 又看似正常。

**根因**：隧道的封装封包目的地是 underlay 对端（例：VXLAN 的 `remote 10.128.0.20`），
而它得靠 main 表的**预设路由**送出。一旦预设路由是「含这条隧道的 ECMP」，
就有约 1/N 的机率把封装封包**再塞回同一条隧道** —— 封装包进隧道、隧道再封装，
形成自环。实测：双线 ECMP 下隧道丢包 60%，`ping` 5 个只回 2 个。

**这个 bug 特别会骗人**：`ip route get 10.128.0.20` 会显示正确的 `dev eth1`，
看起来完全没问题 —— 因为它只是固定哈希的**单次采样**，而真实流量带随机源埠，
哈希结果不同。别被它骗了，要看实际丢包率。

**修法（本专案已自动处理）**：为对端补一条 `/32` 路由走「非隧道」的那条 WAN。
`/32` 前缀比预设路由长，必然优先，于是封装封包永远走 underlay，不再有机率回灌。

- OpenWrt 的 init 脚本会**自动探测 VXLAN 的 `remote`** 填进 `underlay_targets`，开箱即用。
- 扫描时机分两种：**启动前**会把残留的探针 `/32`（metric 42760）与 underlay `/32`
  （metric 42761）一起清掉（上次执行的出口可能已经失效）；**执行期**的探针路径清扫
  **只清探针 `/32`**，不会动 underlay —— 两者若混在一起清，同一批指令里刚装好的
  underlay `/32` 会被误删，而记忆体快取还记著「已装」就再也不补（实测：启动后 40 秒
  一直是 0 条，隧道封装封包只能走 ECMP，约 1/2 机率自环丢包）。
- 每次同步 underlay `/32` 前都会向内核转储一次实际状态（`metric 42761`）：
  「快取说已装、但内核里其实没有」的项目一律重下（`NLM_F_REPLACE` 幂等），
  所以外部 `ip route del` 或任何误删都能在下一次下发／心跳（30 秒）内自愈。
- 手写设定档时请自己填（也可用来覆盖自动侦测的结果）：

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

验证方式：设定生效后 main 表会多出 `10.128.0.20/32 via <物理线闸道> dev <物理线>`，
且隧道丢包率应回到接近 0。

### 5. 视频网站还是会卡？按这个顺序查

1. **分流粒度**：LuCI 标题列的「哈希粒度」徽章 / 状态档 `hash.l3_only`。
   若是 `仅 L3：同一目的 IP 只走一条 WAN`，视频 CDN 的多条连线全部挤在一条线上——
   先把它改成 `l4`（见 §6.1），这一步解决绝大多数「两条线却只用到一条」的抱怨。
   要确认「真的分开了」，看 LuCI 卡片两条线的 `Throughput (TX / RX)` 是否都有流量。
2. **一条线吃满、另一条闲置**：看 `load_pct` / `offloaded` 与 `W:1 → 4`。
   前提是**每条 WAN 都设了 `max_mbps`**（容量比例）且 `load_aware: true`；
   注意 `standard` ECMP 下动态因子会被忽略，请用预设 `ecmp_mode: auto`（resilient）。
3. **单一超大流量（单条 QUIC/TCP 串流）占满一条线**：ECMP 是 per-flow 哈希，
   **搬不动已建立的连线**（见 §6.6 的本质限制）。这不是分流算法能解决的：
   要么让该线不被打满（路由器侧 SQM/CAKE 限速、或把该应用导向另一条线），
   要么接受「新版连线才会被分散」。
4. **IPv6 视频没被分流**：没设 `gateway6` 时 mwan4 完全不碰 IPv6 路由，
   v6 流量会一直走单线（启动日志会提示一次，见 §已知限制）。
5. **线路本身在抖**：看日志有没有 `Line degraded` / `Active WAN set changed` 的密集循环，
   以及状态档的 `state_reason` / `samples_in_window`（窗口没满就不会判定，
   也就不会因为一次抖动被移出 ECMP）。

## 已知限制与整合测试

### 已知限制（实测整理）

- **IPv6 分流需要设定 `gateway6`**：没设 `gateway6` 的部署，守护进程**完全不碰** IPv6 路由，
  v6 流量会一直走 netifd 那一条单线预设路由（没有故障转移、没有 `multipath_hash_policy`
  的分流效果）。而这年头视频（YouTube、Bilibili 的 QUIC/HTTP-3）常常正好走 v6 ——
  「IPv4 明明两条线都在分流，v6 视频还是卡」就是这么来的。启动时若侦测到内核真的有一条
  非 `lo` 的 `::/0`、却没有任何 WAN 设定 `gateway6`，会 info 级提示一次（见 §1 的启动日志）。
- **IPv6 conntrack 不会被清理**：清理器以 NAT 后的 WAN IPv4 位址匹配连线
  （`ORIG.src` / `REPLY.dst`）。IPv6 一般是路由而非 NAT，tuple 里是 LAN 客户端自己的
  全域位址、不会出现 WAN 位址，而内核 conntrack 也没有「按出介面删除」的下发介面。
  IPv6 长连线在切换后只能等自身超时（TCP 会以新来源位址重建）。若部署使用 NAT66，
  请以 `nft ... ct` 规则另行处理。
- **conntrack zone**：清理时会把 dump 到的 `CTA_ZONE` 原样带回删除讯息，非 0 zone 的部署
  不会漏删或误删；zone 0（绝大多数部署）行为不变。
- **IPv6 不允许「纯 dev」multipath**：内核直接拒绝
  *"Device only routes can not be added for IPv6 using the multipath API"*。
  该 WAN 必须设定 `gateway6`（SLAAC/DHCPv6 环境通常都有）。
- **netlink 查询在事件回圈上是同步的**：查询 socket 的逾时已缩到 300ms，但在网卡很多
  且内核一时无回应时仍可能造成短暂延迟；决策失败时一律用保守值继续（当成「没有路」）。
- **建立/删除路由带专属 `proto 77`（0x4D）**：删除只会命中本程式下发的路由，不会误删
  netifd 或其它工具的路由；启动清扫的残留处理改用 protocol 通配符，才清得掉旧版本留下
  的 `/32`。
- **策略分流只支援 IPv4 且只匹配前缀**：`policies` 用 `from`/`to` 匹配来源/目的前缀，
  不支援埠号或应用层条件；IPv6 流量仍走 ECMP。
- **strict `rp_filter` 与策略分流冲突**：内核的反向路径检查只查主表，而策略流量是依规则
  查另一张表；`rp_filter=1` 的 WAN 可能把回程当成 martian 丢弃。请设 `rp_filter=2`
  （loose）或 `0`（多 WAN 环境本来就建议如此）。
- **哈希粒度由 `fib_multipath_hash_policy` 决定，不是 `fib_multipath_hash_fields`**：
  本机实测（Linux 7.1.8，netns，本地发出与转发流量都测过）位元遮罩可写入、可读回，
  但**不改变哈希结果**；`policy` 才是有效开关（见 §6.1）。守护进程两者都写（位元依 policy
  只补不删），并把读回值放进 log 与状态档，因此不必猜哪个内核以哪个为准。
- **`multipath_hash_policy` 预设从「不写入」改成 `l4`（r10）**：升级后若设定档里
  明写 `null`（UCI 的 `option multipath_hash_policy ''`）则行为不变（仍是 L3 粒度），
  启动时会 warn 一次提醒你视频 CDN 的多条连线只会走一条 WAN。见 §6.1 的升级提醒。
- **动态权重会重下路由**：每次权重变更都是一次 `RTM_NEWROUTE`；若内核实际安装的是
  `standard` ECMP，它会重算 multipath hash、既有 flow 可能被改派（实测 40%）。
  预设 `auto` 在支援 nexthop object 的核心上装的是 `resilient`（权重变更实测 0% 改派），
  已用 `dynamic_weight_interval_ms` 限速；明确设 `standard` 时若要完全避免，
  请改用 `resilient`/`auto` 或维持 `weight_mode: static`。
- **负载感知只重分配 flow、不能搬「单一条大流量」**：ECMP 是 per-flow 哈希，
  下修权重只影响之后新建的连线。多连线的总量（下载、P2P）有效；单一 elephant flow
  占满一条线时无能为力。详见 §6.6。
- **速率取样来自介面计数器**：`tx_bps`/`rx_bps` 是 `/sys/class/net` 的累计值差分，
  介面重建（PPPoE 重拨）后第一次取样会归零，属正常现象。

### `--check-config` 会挡下的设定（启动前失败，而不是默默接受）

- 未知栏位（`_` 开头视为注解，例如 `_comment`）；网卡区块与 `policies` 区块同理
- `probe_timeout_ms > check_interval_ms`、`check_interval_ms` 超过 1 小时
- `max_rtt_ms` 非有限值（例如 `1e999` 会被 JSON 解析成 `+inf`，静默关闭 RTT 判据）
- 网卡名称含 `/`、空白或超过 15 字元；loopback／multicast 的 gateway／gateway6／
  underlay 目标；port 0 的探针目标
- 动态权重：`dynamic_weight_interval_ms` 不在 1000~3600000、
  `dynamic_weight_min_ratio` 不在 0.05~1.0
- 容量（`max_mbps` / `up_mbps`）不是有限正数；或只给部分 WAN 设了 `max_mbps`
  （容量比例分流要求全填或全不填）
- 负载感知：`load_target_ratio` 不在 (0,1]、`load_recover_ratio` 不小于
  `load_target_ratio`，或启用 `load_aware` 却有 WAN 没填 `max_mbps`
- 策略分流：名称重复/过长、目标 WAN 不在 `interfaces`、CIDR 非法（前缀需 0~32）、
  展开后超过 64 条、`priority` 超出 9000~9063／重复／只设定一部分

### 真实核心整合测试（netns）

路由编码的正确性只有真实内核说得准（例如 DELNEXTHOP 的 header 必须全零，否则内核回
EINVAL 而删除静默失败）。整合测试会在免洗 netns 里建立 dummy 网卡、下发真正的
ECMP／resilient／策略路由并验证：

```bash
cargo test --no-run
unshare -Urn sh -c \
  'MWAN4_NETNS_TEST=1 cargo test --offline -- --ignored netns --test-threads=1'
```

`unshare -Urn` 只需要使用者命名空间（userns + netns + CAP_NET_ADMIN），**不需要 root**，
也不会动到主机路由。涵盖：标准 ECMP 安装／全断二态／退出清理、resilient group
建立→成员缩减→全断拆除→cleanup、nexthop object 新增删除、探针路径（规则＋独立表＋
主表 `/32`）、隧道 underlay `/32` 清理、IPv6 ECMP、**策略分流**（`from`/`to` 规则安装／
核心查找命中指定表／移除／清扫）。

## 致谢

- [DeepSeek](https://www.deepseek.com)：参与架构设计、程式码实作、跨平台编译与路由器实机验证。
- OpenWrt / LuCI：Netlink、rpcd、LuCI-JS 的既有实作与文件。

---

## 授权条款
MIT License.
