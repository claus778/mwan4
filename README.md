# MWAN4 (Multi-WAN 4)

面向 Linux / OpenWrt 25+（标准内核 Linux 6.12+）的轻量级多 WAN 分流、聚合与故障转移守护进程（Rust 编写）。  
基于纯 Linux 原生 FIB（Netlink + ECMP / Resilient Nexthop），**零 nftables / fwmark，100% 兼容 Flow Offload**（不再兼容 OpenWrt 24 及更早版本、旧内核、opkg/ipk 或第三方分支）。

---

## 为什么选择 MWAN4？

| 维度 | 传统 mwan3 | MWAN4 |
| :--- | :--- | :--- |
| **转发架构** | `iptables`/`nftables` fwmark + 策略路由 | **纯内核 FIB（Multipath ECMP / Resilient）** |
| **硬件加速** | ❌ 破坏 Flow Offload / HW NAT | ✅ **原生兼容 Flow Offload**（MT798x / MT7621 / x86） |
| **控制面** | 频繁 fork Shell / `ip` / `ubus` | **纯 Netlink Socket + `/proc/net/dev`**（零子进程） |
| **资源占用** | 较高 CPU、数十 MB 内存 | **< 0.1% CPU、< 4 MB RSS** |
| **故障切换** | 数秒至数十秒 | **< 1 秒**（原子路由替换 + Conntrack 精准清理） |
| **多线分流** | 静态比例为主 | **240 弹性桶（单/双数 WAN 零偏斜）+ 余量聚合分流** |

---

## 核心特性

- **单/双数多 WAN 均衡与轻量聚合分流**
  - **240 弹性哈希桶**：`ecmp_mode: auto`（针对 OpenWrt 25+ / Linux 6.12+ 原生启用 Resilient Nexthop），240 桶可被 `2/3/4/5/6/8/10/12` 整除，消除单数（3/5 线）与双数多 WAN 的桶分配偏斜；默认 `resilient_idle_timer_secs = 30` + `resilient_unbalanced_timer_secs = 60`，保护活跃流不乱序并在恢复/调权后自动重平衡。
  - **不打断高速测速的 FIB 更新**：成员权重变更仅通过 `RTM_NEWNEXTHOP` 更新弹性桶而不重复重写路由表项，避免触发 `nf_flow_table` / 硬件 Flow Offload 缓存失效。
  - **余量感知聚合分流（`weight_mode: "aggregate"`）**：综合各 WAN 剩余空闲带宽与 RTT/丢包动态调整权重，并在多连接场景（多线程下载、P2P、视频分段）持续把新流导向最空闲的健康线路；支持非整数倍带宽精确比例化（如 `300M:200M` → `3:2`）。
  - **L4 哈希分流（默认 `multipath_hash_policy: "l4"`）**：按五元组打散同一目的 IP 的多条连接，并每 30 秒自检修复被外部脚本改回 L3 的内核参数。
- **高可靠健康探测（LQE）**
  - 支持 **TCP SYN** 与 **UDP DNS（RFC 1035）** 双模探测，使用 `SO_BINDTODEVICE` + 每 WAN 独立探针路由表，与主表解耦。
  - 滑动窗口 + EWMA RTT/Jitter + 迟滞防震荡与降级机制（高丢包线路自动移出 ECMP，恢复后自动回归）。
  - 自动清理故障线路的 IPv4 Conntrack；支持隧道 WAN（VXLAN / WireGuard）underlay `/32` 防自环路由。
- **非侵入式多 WAN DNS（不影响第三方 DNS 软件）**
  - 默认**不监听 53 端口、不改 dnsmasq、不碰 `/etc/resolv.conf`**，与 AdGuardHome / SmartDNS / MosDNS / OpenClash 零冲突。
  - 支持每 WAN 专属上游 DNS `/32` 出口绑定（`dns_servers`，支持 `IP` 或 `IP:Port`）、可选独立端口多线 UDP 转发（`dns_listen_port`，默认 `0` 关闭）及可选独立 resolv 文件导出（`dns_resolv_file`）。
- **策略分流（`policies`）**
  - 基于纯 `ip rule`（`from`/`to` IPv4 CIDR）指向对应 WAN 路由表，目标 WAN 故障时自动回退 ECMP，不影响 Flow Offload。
- **原生 UCI 命令 + LuCI-JS 管理界面**
  - 直接支持读取/校验 OpenWrt UCI 与 JSON 配置，内置 `mwan4 uci` 子命令与简洁的 LuCI 实时监控看板。

---

## 快速开始（OpenWrt 25+）

### 1. 安装与启动

推荐使用 `scripts/build_packages.py` 生成 `.apk` 包（OpenWrt 25+ 原生 `apk` 包管理器）；或手动部署二进制与 `openwrt/luci-app-mwan4/` 文件：

```sh
# 停用传统 mwan3（如有）
/etc/init.d/mwan3 stop 2>/dev/null; /etc/init.d/mwan3 disable 2>/dev/null

# 校验配置（支持 UCI 与 JSON）
mwan4 --check-config /etc/config/mwan4

# 启动并设置开机自启
/etc/init.d/mwan4 enable
/etc/init.d/mwan4 start

# 查看日志（稳态仅在状态变化时输出）
logread -f -e mwan4
```

安装 LuCI 后，在 **「网络 → MWAN4 多路分流」** 即可查看实时看板与修改配置。

### 2. 原生 UCI 命令（`mwan4 uci`）

无需外部 `uci` 工具即可直接读写 `/etc/config/mwan4`（可用 `-f <path>` 指定其他路径）：

```sh
mwan4 uci show                                   # 查看全部配置
mwan4 uci get global.weight_mode                 # 读取单项
mwan4 uci set global.weight_mode=aggregate       # 开启聚合分流
mwan4 uci set global.dns_listen_port=5354        # 开启可选独立端口 DNS 转发
mwan4 uci add_list wan1.dns_servers=202.96.128.86
mwan4 uci del_list wan1.dns_servers=202.96.128.86
mwan4 uci delete wan2.gateway                    # 留空网关（自动检测）
mwan4 uci validate                               # 校验配置
mwan4 uci export-json                            # 导出为 JSON
```

也可以直接用 UCI 文件运行守护进程：`mwan4 -c /etc/config/mwan4`。

---

## 配置示例

完整示例见 [mwan4.example.json](mwan4.example.json) 与 [openwrt/luci-app-mwan4/root/etc/config/mwan4](openwrt/luci-app-mwan4/root/etc/config/mwan4)。

```json
{
  "check_interval_ms": 1000,
  "probe_timeout_ms": 800,
  "degrade_loss_threshold": 0.0,
  "consecutive_fail_down": 4,
  "recovery_success_count": 3,
  "ecmp_mode": "auto",
  "resilient_idle_timer_secs": 30,
  "resilient_unbalanced_timer_secs": 60,
  "multipath_hash_policy": "l4",
  "weight_mode": "aggregate",
  "load_aware": false,
  "probe_mode": "tcp",
  "dns_listen_addr": "127.0.0.1",
  "dns_listen_port": 0,
  "policies": [],
  "interfaces": [
    {
      "name": "wan1",
      "gateway": "192.168.1.1",
      "metric": 1,
      "weight": 1,
      "max_mbps": 500,
      "probe_targets": ["223.5.5.5:53", "114.114.114.114:53"],
      "dns_servers": []
    },
    {
      "name": "wan2",
      "gateway": "192.168.2.1",
      "metric": 1,
      "weight": 1,
      "max_mbps": 300,
      "probe_targets": ["223.5.5.5:53", "114.114.114.114:53"],
      "dns_servers": []
    }
  ]
}
```

### 关键参数速查

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `ecmp_mode` | `auto` | `auto`（优先 resilient）/ `resilient` / `standard` |
| `resilient_idle_timer_secs` | `30` | 弹性桶空闲迁移时间（秒，`1..3600`） |
| `resilient_unbalanced_timer_secs` | `60` | 弹性桶失衡强制迁移时间（秒，`0..3600`，`0` 关闭） |
| `multipath_hash_policy` | `l4` | `l4`（按连接分流，含 Linux 6.12+ `fields` 掩码 55）/ `l3` / `inner` |
| `weight_mode` | `static` | `static`（静态/按 `max_mbps`）/ `quality`（品质动态）/ `aggregate`（余量感知聚合分流） |
| `load_aware` | `false` | 过载分流开关（开启时每条 WAN 需填 `max_mbps`） |
| `probe_mode` | `tcp` | `tcp`（TCP SYN）或 `dns`（UDP RFC 1035 查询，支持每 WAN 覆写） |
| `dns_listen_port` | `0` | 内置多线 UDP DNS 转发端口，`0` = 关闭（避免与第三方 DNS 冲突） |
| `dns_servers` | `[]` | 每 WAN 专属上游 DNS（支持 `IP` 或 `IP:Port`），自动绑定 `/32` 出口路由 |
| `gateway6` | `null` | 可选 IPv6 网关；配置后同步下发 IPv6 ECMP 路由 |
| `underlay_targets` | `[]` | 隧道 WAN 对端 IP，自动维护防自环 `/32`（守护进程通过 Netlink 自动探测 VXLAN 对端） |

---

## 编译、打包与测试

### 交叉编译

```bash
# x86_64
cross build --target x86_64-unknown-linux-musl --release

# ARM64 (MT798x / RK3568 / 树莓派4)
cross build --target aarch64-unknown-linux-musl --release

# ARMv7 (IPQ4019 / MT7622)
cross build --target armv7-unknown-linux-musleabihf --release

# MIPS 小端 (MT7621 / mipsel_24kc，tier-3 需使用仓库脚本)
bash scripts/build_mipsel24kc.sh
```

### 打包 OpenWrt 25+ APK

```bash
python3 scripts/build_packages.py --list-archs
python3 scripts/build_packages.py
```

产物输出至 `dist/packages/`（OpenWrt 25+ `.apk` 与自动编译的 LuCI `zh_Hans.lmo` 中文翻译）及 `dist/install.sh`。

### 测试

```bash
# 单元测试
cargo test --locked

# 真实 Linux 内核 netns 集成测试（无需 root，不修改宿主机路由）
cargo test --no-run
unshare -Urn sh -c 'MWAN4_NETNS_TEST=1 cargo test --offline -- --ignored netns --test-threads=1'
```

---

## 常见问题与注意事项

1. **单条连接无法突破单线带宽**：ECMP 基于 per-flow 哈希，多线程下载 / P2P / 多终端可叠加多线总带宽，但单条 TCP/QUIC 长连接仍受限于单条 WAN 带宽。
2. **隧道型 WAN（VXLAN / WireGuard）**：请在 OpenWrt 防火墙 `wan` 区域放行对应的隧道 UDP 端口；若 `underlay_targets` 未自动识别，请手动填写对端 IP 防止自环。
3. **IPv6 分流**：未填写 `gateway6` 时 MWAN4 不接管 IPv6 路由；IPv6 Conntrack 不按 NAT 源 IP 清理。
4. **`rp_filter` 建议**：多 WAN（尤其是使用策略分流或共用探针目标时）建议设为 loose 模式：`sysctl -w net.ipv4.conf.all.rp_filter=2`。
5. **保留路由资源（请勿他用）**：路由表与规则优先级 `10000..10063`（探针）、`9000..9063`（策略分流）、路由协议标记 `proto 77`（`0x4D`），主表专属 metric `42760`（探针 `/32`）、`42761`（underlay `/32`）、`42762`（DNS `/32`）。

---

## License

MIT License.
