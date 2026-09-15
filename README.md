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
  ip route get 1.1.1.1 oif wan1                      # 應顯示 via <gw>（有 via 才代表有路）
  ip route show table main | grep 'metric 42760'     # 只在必要時短暫出現的探針 /32
  ```
  **保留區段**（本程式專用，請勿他用）：路由表 `10000..10063`、規則優先序 `10000..10063`、
  主表 metric `42760`。我們的規則都帶來源標記（`FRA_PROTOCOL = 0x4D`），啟動清掃**只刪帶這個
  標記的規則**，不會動到第三方的規則；清掃也不再主動刪保留表內的路由（沒有規則指向它就是惰性的，
  而且我們重用該表時會直接 REPLACE）。
- **探測協議**：以高效 TCP SYN 探測公共 DNS（如 `1.1.1.1:443`、`8.8.8.8:443`），週期預設為 500ms。TCP SYN 探針具備極高穿透力，不會被運營商 ICMP 限速或丟棄。
- **多目標容災**：支援單一網卡配置多個探測目標（並行探測），避免單一 DNS 伺服器異常引發誤判。
- **失敗原因可觀測**：狀態檔會記錄每張網卡的 `last_error` 與 `local_condition`
  （`No such device`／`Network is unreachable`／`Create socket failed` 等屬於**本機條件**，
  不是運營商丟包），info 級日誌也會針對這類錯誤告警一次。

### 2. 鏈路評分與狀態機（LQE - Link Quality Estimator）
- **滑動窗口與平滑算法**：維護長度為 10 的滑動窗口，使用 EWMA（指數加權移動平均）動態估算 RTT 與抖動（Jitter）：
  $$\text{RTT}_{\text{new}} = \alpha \cdot \text{RTT}_{\text{sample}} + (1 - \alpha) \cdot \text{RTT}_{\text{old}} \quad (\alpha = 0.20)$$
  $$\text{Jitter}_{\text{new}} = \beta \cdot |\text{RTT}_{\text{sample}} - \text{RTT}_{\text{old}}| + (1 - \beta) \cdot \text{Jitter}_{\text{old}} \quad (\beta = 0.25)$$
- **狀態判定標準**：
  - **UP**：丟包率 < 10% 且 RTT 正常。
  - **DOWN**：連續 3 次探測超時，或滑動窗口丟包率 > 50%。
- **嚴格防震盪機制（Hysteresis）**：
  - 當線路處於 DOWN 時，必須連續成功 `recovery_success_count` 次（預設 5），
    且滑動窗口丟包率 **不超過** `loss_threshold_up`（預設 0.10 = 10%）、RTT 正常，才能恢復為 UP。
  - 門檻是「不超過」（`<=`）而非嚴格小於：`window_size = 10` 時，嚴格小於等於
    「窗口內一次丟包都不准」，會讓 `recovery_success_count` 完全失效、且任何一次抖動
    都把恢復無限往後推。
  - 探測過程中若發生任何一次超時，連續成功計數立即歸零重新累積。
  - `loss_threshold_up` 已可由 UCI／LuCI 調整（丟包較大的線路可適度放寬）。

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
  無論設定為何，**探針路徑（獨立表內的路由、`oif` 規則、主表 `/32`）一律會拆除**。

### 4. 連線黏滯：兩種 ECMP 模式（`ecmp_mode`）
多 WAN 最容易被測出來的坑是「**一有線路抖動，既有連線就集體斷**」。兩種模式的差異在於**鏈路集合變動時，內核如何重算多路徑哈希**：

| 模式 | 內核機制 | 鏈路變動時的行為 | 需求 |
| --- | --- | --- | --- |
| `standard`（預設） | `RTA_MULTIPATH`（傳統 multipath route） | 重算整張哈希表；未受影響的連線也可能被**重新分派到其他 WAN**，造成連線中斷 | 所有 Linux |
| `resilient` | 彈性 nexthop group（`RTM_NEWNEXTHOP` + `NHA_RES_GROUP`） | **只重映射故障成員對應的桶**；其餘連線仍黏在原 WAN，不掉線 | Linux ≥ 5.14 |
| `auto` | 先試 `resilient`，內核不支援則永久退回 `standard` | 同上；不支援時自動降級，不報錯 | — |

- 選用 `standard` 時，守護進程才會在切換瞬間 flush conntrack（讓連線盡快重建）；`resilient` 會**抑制** flush-on-switch，否則等於親手抹掉黏滯效果。
  flush 範圍已刻意收斂：**只有涉及 multipath（變動前後任一側有多個成員）時才清全部存活成員**；
  主備模式（metric 不同、兩側各只有一個成員）只清新進入存活集合的那條，
  因此「主線恢復」不會再無故 RST 掉備線上健康的連線。
- 未特別指定時預設為 `standard`，行為與舊版一致；想真正解決「抖動即斷連」請改用 `resilient`（或 `auto`）。
- 單一 ECMP 組的成員數上限為 256（bucket 數上限），超過會被視為不支援而退回 `standard`。
  bucket 數以巢狀在 `NHA_RES_GROUP` 裡的 `NHA_RES_GROUP_BUCKETS`（u16）傳遞，必須是 2 的冪且不小於成員數；
  早期版本誤用頂層的 `NHA_RES_BUCKET`(13) 並以 u32 編碼，內核會當成「沒給 bucket 數」回 `EINVAL`，
  導致 `resilient` 從未真正生效（成員 nexthop 建得出來、group 建不出來、預設路由不下發）。已在 r5 修正。

### 5. 連線快取清理（Conntrack Flushing）
- 透過 Netfilter Netlink（`NETLINK_NETFILTER` / `NFNL_SUBSYS_CTNETLINK`）直接與內核 conntrack 表交互。
- 當線路判定為 DOWN 時，程式會精準掃描並刪除綁定在該網卡 IP 上的活躍連線，使客戶端的 TCP/UDP 連線能立即由存活網卡重新 NAT，解決長連線卡死問題。

---

## 專案結構

```
mwan4/
├── Cargo.toml               # Rust 專案配置 (包含 size/lto release 配置)
├── .cargo/
│   └── config.toml          # 編譯網路與代理配置
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
│   └── po2lmo.py                        # .po → LuCI .lmo 翻譯編譯器
├── .github/workflows/ci.yml             # CI：fmt / clippy / test / 多架構交叉編譯
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

* **MIPS (如 MT7621, MT7620 等)**：
  ```bash
  cross build --target mipsel-unknown-linux-musl --release
  ```

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
  "consecutive_fail_down": 3,
  "recovery_success_count": 5,
  "max_rtt_ms": 1500.0,
  "flush_conntrack_on_down": true,
  "flush_conntrack_on_switch": true,
  "route_priority": 0,
  "remove_routes_on_exit": false,
  "ecmp_mode": "standard",
  "interfaces": [
    {
      "name": "wan1",
      "gateway": "192.168.1.1",
      "metric": 1,
      "weight": 1,
      "probe_targets": [
        "1.1.1.1:443",
        "8.8.8.8:443"
      ]
    },
    {
      "name": "wan2",
      "gateway": "192.168.2.1",
      "metric": 1,
      "weight": 1,
      "probe_targets": [
        "1.1.1.1:443",
        "8.8.8.8:443"
      ]
    }
  ]
}
```

> `route_priority` 刻意**不**在 UCI／LuCI 暴露：它必須與 netifd 自己那條 WAN 預設路由
> 的 metric 一致（通常都是 0），守護進程才能接管預設路由；若設成非 0，netifd 那條
> metric 較小的路由會永遠勝出，故障轉移也就不會生效。

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
2026-09-12 21:40:00 info mwan4: Starting mwan4 daemon (Probe interval: 500ms, Timeout: 600ms, Window: 10, Hysteresis: 5 success)
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
   - 2 秒非同步輪詢自動刷新，無需手動重新整理網頁。
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
# 注意：此 .lmo 由 po/zh-cn/mwan4.po 編譯而來；若改過 .po，請用
#   python scripts/po2lmo.py openwrt/luci-app-mwan4/po/zh-cn/mwan4.po openwrt/luci-app-mwan4/mwan4.zh-cn.lmo
# 重新生成（打包腳本會自動做這件事，此處僅為手動部署說明）
scp openwrt/luci-app-mwan4/mwan4.zh-cn.lmo root@192.168.1.1:/usr/lib/lua/luci/i18n/

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
悄悄退回預設的 `1.1.1.1:443 / 8.8.8.8:443`。
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

## 致謝

- [DeepSeek](https://www.deepseek.com)：參與架構設計、程式碼實作、跨平台編譯與路由器實機驗證。
- OpenWrt / LuCI：Netlink、rpcd、LuCI-JS 的既有實作與文件。

---

## 授權條款
MIT License.
