# MWAN4 (Multi-WAN 4)

專為 Linux / OpenWrt 深度設計的極輕量、零負擔、高性能「多 WAN 故障轉移與健康監控守護進程（Daemon）」。

用以徹底替代架構笨重、頻繁呼叫 Shell 腳本、吃 CPU 且嚴重破壞硬體加速（Flow Offload）的傳統 `mwan3`。

---

## 為什麼需要 MWAN4？（對比傳統 MWAN3）

| 特性 / 指標 | 傳統 OpenWrt mwan3 | MWAN4 (本專案) |
| :--- | :--- | :--- |
| **轉發面架構** | 依賴數十條 `iptables`/`nftables` fwmark 打標與 Policy Routing | **100% 依賴 Linux 原生 FIB (Multipath ECMP)** |
| **硬體加速相容性** | ❌ **破壞硬體加速** (Flow Offload / HW NAT 遇到 packet mark 會失效) | ✅ **原生相容 Flow Offload** (PPE, MT798x, MT7621, x86) |
| **控制面操作方式** | 頻繁執行外部 Shell、`ip`、`ubus`、`logger` 進程 | **純 Netlink Sockets**（控制面零外部子進程） |
| **CPU 佔用率** | 較高（頻繁 fork/exec 腳本，尤其在弱 CPU 路由器） | **< 0.1%**（單線程非同步事件驅動） |
| **記憶體佔用 (RSS)** | 數十 MB（多個 shell 子進程 + 巨型規則表） | **< 4 MB** |
| **故障轉移時延** | 數秒至數十秒 | **< 1 秒**（原子化 FIB 路由切換 + Conntrack 精準清理） |
| **TCP 斷線卡死問題** | 經常殘留無效 session，需漫長 TCP 重傳超時 | **自動 Netlink 清理失效網卡 Conntrack**，秒級恢復 |

---

## 核心架構規範

### 1. 雙 WAN 探測器（Prober）
- **出口網卡強制綁定**：使用 Non-blocking Socket 並透過 `SO_BINDTODEVICE` 強制將探針綁定到特定網卡（如 `wan1`、`wan2`），完全免疫於預設路由的變更干擾。
- **探測協議**：以高效 TCP SYN 探測公共 DNS（如 `1.1.1.1:443`、`8.8.8.8:443`），週期預設為 500ms。TCP SYN 探針具備極高穿透力，不會被運營商 ICMP 限速或丟棄。
- **多目標容災**：支援單一網卡配置多個探測目標（並行探測），避免單一 DNS 伺服器異常引發誤判。

### 2. 鏈路評分與狀態機（LQE - Link Quality Estimator）
- **滑動窗口與平滑算法**：維護長度為 10 的滑動窗口，使用 EWMA（指數加權移動平均）動態估算 RTT 與抖動（Jitter）：
  $$\text{RTT}_{\text{new}} = \alpha \cdot \text{RTT}_{\text{sample}} + (1 - \alpha) \cdot \text{RTT}_{\text{old}} \quad (\alpha = 0.20)$$
  $$\text{Jitter}_{\text{new}} = \beta \cdot |\text{RTT}_{\text{sample}} - \text{RTT}_{\text{old}}| + (1 - \beta) \cdot \text{Jitter}_{\text{old}} \quad (\beta = 0.25)$$
- **狀態判定標準**：
  - **UP**：丟包率 < 10% 且 RTT 正常。
  - **DOWN**：連續 3 次探測超時，或滑動窗口丟包率 > 50%。
- **嚴格防震盪機制（Hysteresis）**：
  - 當線路處於 DOWN 時，必須連續成功 5 次探測且滑動窗口丟包率 < 10% 才能恢復為 UP。探測過程中若發生任何一次超時，計數器立即歸零重新累積。

### 3. Netlink FIB 執行器（Route Manager）
- 100% 透過 Linux 原生 Netlink Socket (`NETLINK_ROUTE`) 操作內核路由表（`RT_TABLE_MAIN`），絕不呼叫 `ip route` 等外部命令。
- **原子化路由切換**：
  - 雙 WAN 正常：下發 ECMP 預設路由（支援配置權重 `weight`）。
  - 單 WAN 故障：原子化發送 `RTM_NEWROUTE`（`NLM_F_REPLACE`），即刻將預設路由收斂至存活線路。
  - 線路恢復：原子化切回雙路 ECMP 負載均衡。

### 4. 連線黏滯：兩種 ECMP 模式（`ecmp_mode`）
多 WAN 最容易被測出來的坑是「**一有線路抖動，既有連線就集體斷**」。兩種模式的差異在於**鏈路集合變動時，內核如何重算多路徑哈希**：

| 模式 | 內核機制 | 鏈路變動時的行為 | 需求 |
| --- | --- | --- | --- |
| `standard`（預設） | `RTA_MULTIPATH`（傳統 multipath route） | 重算整張哈希表；未受影響的連線也可能被**重新分派到其他 WAN**，造成連線中斷 | 所有 Linux |
| `resilient` | 彈性 nexthop group（`RTM_NEWNEXTHOP` + `NHA_RES_GROUP`） | **只重映射故障成員對應的桶**；其餘連線仍黏在原 WAN，不掉線 | Linux ≥ 5.14 |
| `auto` | 先試 `resilient`，內核不支援則永久退回 `standard` | 同上；不支援時自動降級，不報錯 | — |

- 選用 `standard` 時，守護進程才會在切換瞬間 flush conntrack（讓連線盡快重建）；`resilient` 會**抑制** flush-on-switch，否則等於親手抹掉黏滯效果。
- 未特別指定時預設為 `standard`，行為與舊版一致；想真正解決「抖動即斷連」請改用 `resilient`（或 `auto`）。
- 單一 ECMP 組的成員數上限為 256（`NHA_RES_BUCKETS` 上限），超過會被視為不支援而退回 `standard`。

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
  "consecutive_fail_down": 3,
  "recovery_success_count": 5,
  "max_rtt_ms": 1500.0,
  "flush_conntrack_on_down": true,
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

---

## 授權條款
MIT License.
