//! 真实 Linux 核心的整合测试（需要 netns + CAP_NET_ADMIN）。
//!
//! 执行方式（在临时 netns 里跑，完全不影响主机路由）：
//! ```sh
//! cargo test --no-run
//! unshare -Urn sh -c 'MWAN4_NETNS_TEST=1 cargo test --offline -- --ignored netns_route_lifecycle --test-threads=1'
//! ```
//!
//! 为什么需要它们：路由编码（rtm_scope、protocol、resilient bucket、nexthop
//! 删除顺序）的正确性只有真实核心说得准——单元测试只能验证位元组布局。
//! 这些测试会建立 dummy 网卡、下发真正的 ECMP / resilient / 策略路由，并用
//! `ip route show` / `ip nexthop show` / `ip rule show` 验证结果。
//!
//! 没设 `MWAN4_NETNS_TEST=1` 时直接跳过，CI 的一般 `cargo test` 不受影响。
//! 全部情境集中在**一个测试函式**里：测试执行绪会并行跑多个测试，而路由表是
//! 全 netns 共用的，并行会让「全断时有没有兜底」之类的判断互相干扰。

use super::*;
use crate::config::{DaemonConfig, MultipathHashPolicy};

const ENV_GATE: &str = "MWAN4_NETNS_TEST";

fn netns_enabled() -> bool {
    std::env::var(ENV_GATE).as_deref() == Ok("1")
}

fn sh(args: &[&str]) -> bool {
    let (cmd, rest) = args.split_first().expect("command required");
    std::process::Command::new(cmd)
        .args(rest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sh_out(args: &[&str]) -> String {
    let (cmd, rest) = args.split_first().expect("command required");
    std::process::Command::new(cmd)
        .args(rest)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// 建立 / 清理一组 dummy 网卡
struct Dummies {
    names: Vec<String>,
}

impl Dummies {
    fn setup(specs: &[(&str, &str)]) -> Self {
        assert!(sh(&["ip", "link", "set", "lo", "up"]), "lo up failed");
        let mut names = Vec::new();
        for (name, addr) in specs {
            let _ = sh(&["ip", "link", "del", name]);
            assert!(
                sh(&["ip", "link", "add", name, "type", "dummy"]),
                "cannot add dummy {name} (需要 netns + CAP_NET_ADMIN？)"
            );
            assert!(sh(&["ip", "link", "set", name, "up"]), "cannot up {name}");
            assert!(
                sh(&["ip", "addr", "add", addr, "dev", name]),
                "cannot addr {name}"
            );
            names.push((*name).to_string());
        }
        Self { names }
    }
}

impl Drop for Dummies {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = sh(&["ip", "link", "del", name]);
        }
    }
}

fn ifindex(name: &str) -> u32 {
    crate::netlink::util::if_nametoindex(name).expect("ifindex")
}

fn veh(name: &str, metric: u32, underlay: Vec<Ipv4Addr>) -> ActiveWanRoute {
    veh_w(name, metric, 1, underlay)
}

fn veh_w(name: &str, metric: u32, weight: u32, underlay: Vec<Ipv4Addr>) -> ActiveWanRoute {
    ActiveWanRoute {
        ifname: name.to_string(),
        ifindex: ifindex(name),
        gateway: None,
        weight,
        metric,
        underlay_targets: underlay,
    }
}

/// 黏滞性量测用的 UDP 来源埠（固定；改成不同来源位址就等价于不同的 flow key）。
const FLOW_SPORT: u16 = 33000;

/// 网卡累计 TX 封包数（`ip route get` 会吃到路由快取，所以一律用真实封包计数判定出口）。
fn tx_packets(dev: &str) -> u64 {
    let out = sh_out(&["ip", "-s", "-j", "link", "show", dev]);
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("parse `ip -s -j link show {dev}`: {e}"));
    v[0]["stats64"]["tx"]["packets"].as_u64().unwrap_or(0)
}

/// 从「同一个来源位址」的多个来源埠各送一个真实 UDP 封包到同一个目的地。
///
/// 这就是视频网站的流量形态：同一个 CDN IP、同一个本机位址，只有来源埠不同。
/// 回传每一个来源埠的封包实际从哪张网卡出去（用 TX 计数判定）。
fn flow_map_ports(devs: &[&str], src: &str, dst: &str, ports: &[u16]) -> Vec<String> {
    use std::net::UdpSocket;
    let mut out = Vec::with_capacity(ports.len());
    for port in ports {
        let sock = UdpSocket::bind((src, *port)).expect("bind flow source port");
        let before: Vec<u64> = devs.iter().map(|d| tx_packets(d)).collect();
        sock.send_to(b"x", dst).expect("send flow packet");
        let after: Vec<u64> = devs.iter().map(|d| tx_packets(d)).collect();
        let dev = before
            .iter()
            .zip(&after)
            .position(|(b, a)| a > b)
            .map(|i| devs[i].to_string())
            .unwrap_or_else(|| panic!("来源埠 {port} 的封包没有从任何一张网卡出去（量测失效）"));
        out.push(dev);
    }
    out
}

/// 每个来源位址各送一个封包，回传它实际从哪张网卡出去（用 TX 计数判定）。
fn flow_map(devs: &[&str], srcs: &[String]) -> Vec<String> {
    srcs.iter()
        .flat_map(|src| flow_map_ports(devs, src, "8.8.8.8:53", &[FLOW_SPORT]))
        .collect()
}

fn moved_flows(a: &[String], b: &[String]) -> usize {
    assert_eq!(a.len(), b.len(), "flow_map 长度不一致");
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}

fn v6(name: &str, gateway: &str) -> ActiveWanRouteV6 {
    ActiveWanRouteV6 {
        ifname: name.to_string(),
        ifindex: ifindex(name),
        gateway: Some(gateway.parse().unwrap()),
        weight: 1,
    }
}

fn routes() -> String {
    sh_out(&["ip", "route", "show"])
}

/// 读回一个 /proc/sys 的整数设定（读取失败 — 例如旧核心没有这个档案 — 回传 None）。
fn read_sysctl(path: &str) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[test]
#[ignore = "needs unshare -Urn + CAP_NET_ADMIN; see module docs"]
fn netns_route_lifecycle() {
    if !netns_enabled() {
        eprintln!("skip: set MWAN4_NETNS_TEST=1 and run inside `unshare -Urn`");
        return;
    }

    // ---------------------------------------------------------------
    // A. 标准 ECMP（无网关 → scope=LINK）：安装 / 全断二态 / 清理
    //    这一节同时验证 P0 的两个修正：
    //      - 删除报文的 rtm_scope=NOWHERE（不修就删不掉 scope=LINK 的路由）
    //      - handle_all_links_down 依 variant 删除自己的路由
    // ---------------------------------------------------------------
    let _dummy_a = Dummies::setup(&[("mwa0", "10.0.0.2/24"), ("mwa1", "10.1.0.2/24")]);
    let mut rm = RouteManager::new(0, EcmpMode::Standard).unwrap();
    let wans = vec![veh("mwa0", 1, vec![]), veh("mwa1", 1, vec![])];

    rm.apply_default_routes(&wans).expect("standard ECMP apply");
    let r = routes();
    assert!(
        r.contains("nexthop dev mwa0") && r.contains("nexthop dev mwa1"),
        "双线 ECMP 未安装:\n{r}"
    );

    // 全断、且没有别的兜底路由 → 保留（删掉会让整机没有出口）
    rm.apply_default_routes(&[]).expect("all-down keep");
    assert!(
        routes().contains("nexthop dev mwa0"),
        "唯一一条预设路由在全断时必须保留"
    );

    // 有兜底路由（metric 100）→ 删掉我们那条，让兜底接手
    assert!(sh(&[
        "ip", "route", "add", "default", "dev", "mwa1", "metric", "100"
    ]));
    rm.apply_default_routes(&[]).expect("all-down remove");
    let r = routes();
    assert!(
        !r.contains("metric 0"),
        "全断且有兜底时，我们的 metric 0 预设路由应被移除:\n{r}"
    );
    assert!(r.contains("metric 100"), "兜底路由必须保留:\n{r}");

    // 重新接管 → cleanup（remove_routes_on_exit=true 的路径）只删自己那条
    rm.apply_default_routes(&wans).expect("re-apply");
    rm.cleanup_routes().expect("cleanup routes");
    let r = routes();
    assert!(
        !r.contains("metric 0"),
        "cleanup 后不应残留我们的预设路由:\n{r}"
    );
    assert!(r.contains("metric 100"), "cleanup 不该动到兜底路由:\n{r}");
    // 移除兜底，避免与后面段落新增的兜底路由撞 metric（同 prefix/metric 会 EEXIST）
    let _ = sh(&[
        "ip", "route", "del", "default", "dev", "mwa1", "metric", "100",
    ]);

    // ---------------------------------------------------------------
    // B. resilient nexthop group：两成员 → 缩成一成员 → 全断拆除 → cleanup
    //    验证 bucket 数固定（REPLACE 不变更 bucket）、nh 路由的删除与 group 拆除
    // ---------------------------------------------------------------
    let _dummy_b = Dummies::setup(&[("mwb0", "10.2.0.2/24"), ("mwb1", "10.3.0.2/24")]);
    let mut rm = RouteManager::new(2000, EcmpMode::Resilient).unwrap();
    let wans_b = vec![veh("mwb0", 1, vec![]), veh("mwb1", 1, vec![])];
    rm.apply_default_routes(&wans_b)
        .expect("resilient apply (kernel >= 5.14 required)");
    let nh = sh_out(&["ip", "nexthop", "show"]);
    assert!(
        nh.contains("group"),
        "resilient nexthop group 未建立:\n{nh}"
    );

    // 成员数 2 → 1：旧版会改 bucket 数而被核心以 EINVAL 拒绝；现在固定 256
    rm.apply_default_routes(&wans_b[..1])
        .expect("resilient shrink to one member");
    let nh = sh_out(&["ip", "nexthop", "show"]);
    assert!(nh.contains("group"), "缩减成员后 group 应仍存在:\n{nh}");

    // 有兜底 → 全断：必须把 nh-id 路由删掉（P0 修正；旧版用标准 key 删不掉）
    assert!(sh(&[
        "ip", "route", "add", "default", "dev", "mwb1", "metric", "200"
    ]));
    rm.apply_default_routes(&[]).expect("resilient all-down");
    let r = routes();
    assert!(
        !r.contains("nhid"),
        "全断且有兜底时，resilient 预设路由应被移除:\n{r}"
    );
    assert!(r.contains("metric 200"), "兜底路由必须保留:\n{r}");
    let _ = sh(&[
        "ip", "route", "del", "default", "dev", "mwb1", "metric", "200",
    ]);

    // cleanup 要把 group 与成员 nexthop 一起拆干净
    rm.cleanup_routes().expect("resilient cleanup");
    let nh = sh_out(&["ip", "nexthop", "show"]);
    assert!(
        !nh.contains("group"),
        "cleanup 后 resilient group 应被拆除:\n{nh}"
    );

    // ---------------------------------------------------------------
    // C. 探针路径（oif 规则 + 独立表 + 主表 /32）与 underlay /32 的退出清理
    // ---------------------------------------------------------------
    let _dummy_c = Dummies::setup(&[
        ("mwc0", "10.4.0.2/24"),
        ("mwc1", "10.5.0.2/24"),
        ("mwc2", "10.6.0.2/24"),
    ]);
    let mut rm = RouteManager::new(3000, EcmpMode::Standard).unwrap();

    let paths = vec![ProbePath {
        ifname: "mwc0".into(),
        ifindex: ifindex("mwc0"),
        gateway: None,
        targets: vec!["192.0.2.1".parse().unwrap()],
        table: PROBE_TABLE_BASE,
        priority: PROBE_RULE_PRIORITY_BASE,
        main_route_targets: vec!["192.0.2.1".parse().unwrap()],
    }];
    rm.set_probe_paths(&paths).expect("set probe paths");
    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(rules.contains("lookup 10000"), "oif 规则未建立:\n{rules}");
    let table = sh_out(&["ip", "route", "show", "table", "10000"]);
    assert!(table.contains("default"), "探针表内没有预设路由:\n{table}");
    let r = routes();
    assert!(
        r.contains("192.0.2.1") && r.contains("42760"),
        "主表探针 /32 未建立:\n{r}"
    );

    rm.set_probe_paths(&[]).expect("clear probe paths");
    assert!(
        !sh_out(&["ip", "rule", "show"]).contains("lookup 10000"),
        "规则未拆除"
    );
    let r = routes();
    assert!(!r.contains("42760"), "探针 /32 未拆除:\n{r}");

    // 隧道 underlay：apply 时自动补 /32，cleanup 时必须拆掉（否则指向旧闸道）
    let wans_c = vec![
        veh("mwc1", 1, vec![]),
        veh("mwc2", 10, vec!["192.0.2.200".parse().unwrap()]),
    ];
    rm.apply_default_routes(&wans_c)
        .expect("apply with underlay");
    let r = routes();
    assert!(
        r.contains("192.0.2.200") && r.contains("42761"),
        "underlay /32 未建立:\n{r}"
    );
    rm.cleanup_routes().expect("cleanup with underlay");
    let r = routes();
    assert!(!r.contains("42761"), "cleanup 后 underlay /32 未拆除:\n{r}");
    assert!(!r.contains("metric 3000"), "cleanup 后预设路由未拆除:\n{r}");

    // ---------------------------------------------------------------
    // D. IPv6 预设路由（如有需要可扩充；目前只验证安装与删除不报错）
    // ---------------------------------------------------------------
    // 内核不允许 IPv6 用「纯 dev」的 multipath（"Device only routes can not be
    // added for IPv6 using the multipath API"），所以 IPv6 段一定要有 gateway6
    // （生产设定本来就是这样，main 也只把 gateway6 非空的线放进 IPv6 路由）。
    if sh(&["ip", "-6", "addr", "add", "fd00::2/64", "dev", "mwc1"])
        && sh(&["ip", "-6", "addr", "add", "fd01::2/64", "dev", "mwc2"])
    {
        let mut rm6 = RouteManager::new(3001, EcmpMode::Standard).unwrap();
        let wans6 = vec![v6("mwc1", "fe80::1"), v6("mwc2", "fe80::1")];
        rm6.apply_ipv6_default_routes(&wans6)
            .expect("IPv6 ECMP apply");
        let r6 = sh_out(&["ip", "-6", "route", "show"]);
        assert!(
            r6.contains("nexthop via fe80::1 dev mwc1")
                && r6.contains("nexthop via fe80::1 dev mwc2"),
            "IPv6 ECMP 未安装:\n{r6}"
        );
        rm6.cleanup_routes().expect("IPv6 cleanup");
        let r6 = sh_out(&["ip", "-6", "route", "show"]);
        assert!(!r6.contains("metric 3001"), "IPv6 cleanup 未删除:\n{r6}");
    } else {
        eprintln!("skip IPv6 section: cannot add IPv6 address");
    }

    // ---------------------------------------------------------------
    // E. 已建立连线的黏滞性：ECMP 成员/权重变动时，既有 flow 会不会被搬走？
    //    这是 README §4 那张表（standard 40%~43% vs resilient 0%）的来源，也是把
    //    预设改成 auto 的理由：被搬走的 flow 换了出口网卡＝换了 NAT 源 IP，对端只
    //    看到未知四元组（RST／大量重传），使用者感受就是「玩游戏突然卡顿」。
    //
    //    量法：32 个「只差来源位址」的 flow key 各送一个真实 UDP 封包，看它从哪张
    //    网卡的 TX 计数出去。刻意不用 `ip route get`——它会命中路由快取，看起来
    //    「怎么改都不动」，量不到任何东西（本专案实测过这个假象）。
    // ---------------------------------------------------------------
    let _dummy_e = Dummies::setup(&[
        ("mwe0", "10.7.0.2/24"),
        ("mwe1", "10.8.0.2/24"),
        ("mwe2", "10.9.0.2/24"),
    ]);
    // flow key 要含埠位元；新核心的预设（7）不含埠，要先打开（policy 会被它覆盖）
    if std::fs::write("/proc/sys/net/ipv4/fib_multipath_hash_fields", "31\n").is_err() {
        eprintln!("skip flow-stickiness section: cannot set fib_multipath_hash_fields");
        return;
    }
    let srcs: Vec<String> = (1..=32).map(|i| format!("10.10.0.{i}")).collect();
    for src in &srcs {
        assert!(
            sh(&["ip", "addr", "add", &format!("{src}/32"), "dev", "lo"]),
            "cannot add flow source {src}"
        );
    }
    let two = vec![veh("mwe0", 4000, vec![]), veh("mwe1", 4000, vec![])];
    let three = vec![
        veh("mwe0", 4000, vec![]),
        veh("mwe1", 4000, vec![]),
        veh("mwe2", 4000, vec![]),
    ];
    let devs_two = ["mwe0", "mwe1"];
    let devs_three = ["mwe0", "mwe1", "mwe2"];

    // E1（本专案承诺的部分）：auto/resilient 下，成员变动不得搬动既有 flow
    let mut rm_auto = RouteManager::new(4000, EcmpMode::Auto).unwrap();
    rm_auto
        .apply_default_routes(&two)
        .expect("auto ECMP apply (需要核心支援 nexthop object)");
    assert_eq!(
        rm_auto.installed_ipv4_variant(),
        InstalledVariant::Resilient,
        "ecmp_mode=auto 在这个核心上应装成 resilient（否则这一节量不到黏滞效果）"
    );
    let auto_before = flow_map(&devs_two, &srcs);
    // 新增成员＝线路恢复后回归 ECMP，是「抖一下就把别人也搬走」最典型的场景
    rm_auto
        .apply_default_routes(&three)
        .expect("auto ECMP add member");
    let auto_after_add = flow_map(&devs_three, &srcs);
    assert_eq!(
        moved_flows(&auto_before, &auto_after_add),
        0,
        "resilient 新增成员后既有 flow 被改派：{auto_before:?} -> {auto_after_add:?}"
    );
    // 权重变更（动态权重/容量比例的路径）同样不得搬动
    let heavy = vec![
        veh_w("mwe0", 4000, 1, vec![]),
        veh_w("mwe1", 4000, 10, vec![]),
    ];
    rm_auto
        .apply_default_routes(&heavy)
        .expect("auto ECMP reweight");
    let auto_after_weight = flow_map(&devs_three, &srcs);
    assert_eq!(
        moved_flows(&auto_after_add, &auto_after_weight),
        0,
        "resilient 权重变更后既有 flow 被改派：{auto_after_add:?} -> {auto_after_weight:?}"
    );
    rm_auto.cleanup_routes().expect("auto cleanup");

    // E2（阳性对照）：standard 会重算整张 hash、连健康线路上的 flow 也一起搬走。
    // 断言这条是为了保护量测本身——如果这里也变成 0，那 E1 的 0 就毫无意义
    // （量测失效或核心行为变了，两种都该让人看到）。
    let mut rm_std = RouteManager::new(4000, EcmpMode::Standard).unwrap();
    rm_std
        .apply_default_routes(&two)
        .expect("standard ECMP apply");
    let std_before = flow_map(&devs_two, &srcs);
    rm_std
        .apply_default_routes(&three)
        .expect("standard ECMP add member");
    let std_after = flow_map(&devs_three, &srcs);
    let std_moved = moved_flows(&std_before, &std_after);
    eprintln!(
        "flow stickiness: standard 新增成员搬走 {std_moved}/{} 条既有 flow，resilient 搬走 0 条",
        srcs.len()
    );
    assert!(
        std_moved > 0,
        "standard 新增成员后竟然没有任何 flow 被改派——量测失效或核心行为改变"
    );
    rm_std.cleanup_routes().expect("standard cleanup");

    // ---------------------------------------------------------------
    // F. 多路径哈希策略：分流粒度到底由谁决定？
    //    这一节是整个「分流算法」的输入端。实测（本机 Linux 7.1.8、netns、真实 UDP
    //    封包以网卡 TX 计数判出口）：
    //      * `fib_multipath_hash_policy` 是**有效开关**：
    //          policy=0（l3）→「同一个目的 IP、只差来源埠」的 24 条连线 100% 同一条线；
    //          policy=1（l4）→ 同样的 24 条连线 12/12 分开；
    //          policy=2（inner）对**未封装**流量等同 l3（视频流量就是这样）。
    //      * `fib_multipath_hash_fields` 可写入、可读回，但写成 1/7/8/9/31/32
    //        都不改变上面的结果（内核对本地发出与**转发**流量都一样忽略它）。
    //    所以「多 WAN 却全部流量挤一条线」的根因是 policy 留 0，而不是位元；
    //    daemon 的预设（设定档不写这个栏位 = l4）才会把连线真的散开。
    //    「同一个目的 IP、只差来源埠」正是视频网站对同一个 CDN IP 开多条连线的形态。
    // ---------------------------------------------------------------
    let _dummy_f = Dummies::setup(&[("mwf0", "10.6.0.2/24"), ("mwf1", "10.6.1.2/24")]);
    let policy_path = "/proc/sys/net/ipv4/fib_multipath_hash_policy";
    let fields_path = "/proc/sys/net/ipv4/fib_multipath_hash_fields";
    assert!(
        sh(&["ip", "addr", "add", "10.6.9.9/32", "dev", "lo"]),
        "cannot add hash-section flow source"
    );
    let wans_f = vec![veh("mwf0", 4200, vec![]), veh("mwf1", 4200, vec![])];
    let mut rm_f = RouteManager::new(4200, EcmpMode::Standard).unwrap();
    rm_f.apply_default_routes(&wans_f)
        .expect("hash-section ECMP apply");
    let devs_f = ["mwf0", "mwf1"];
    // 同一个本机位址 → 同一个 CDN IP（8.8.8.8:53），只差来源埠
    let ports: Vec<u16> = (1..=24).map(|i| 33_000 + i).collect();
    let cdn = "8.8.8.8:53";
    let devs_used =
        |m: &[String]| -> usize { m.iter().collect::<std::collections::BTreeSet<_>>().len() };

    // (0) 先把 policy 还原成内核预设 0（= L3），确认「不设定」时的实际行为
    assert!(
        std::fs::write(policy_path, "0\n").is_ok(),
        "cannot reset hash policy"
    );
    let off = crate::apply_multipath_hash(None, false);
    assert_eq!(off[0].1.policy, Some(0), "写 null 时不得更动 policy");
    assert!(off[0].1.l3_only(), "policy=0 必须被判定成 L3-only");
    let l3_map = flow_map_ports(&devs_f, "10.6.9.9", cdn, &ports);
    assert_eq!(
        devs_used(&l3_map),
        1,
        "policy=0（L3）时，同一个目的 IP 的 24 条连线应全部落在同一条线（实测：{l3_map:?}）"
    );

    // (1) 设定档的预设（不写这个栏位 = l4）：policy=1 → 同样的连线散到两条线。
    //     这是「双 WAN 却还是卡」的关键修复：视频 CDN 的多条连线终于用得上第二条线。
    assert_eq!(
        DaemonConfig::default().multipath_hash_policy,
        Some(MultipathHashPolicy::L4)
    );
    let l4 = crate::apply_multipath_hash(Some(MultipathHashPolicy::L4), false);
    assert_eq!(l4[0].1.policy, Some(1), "l4 必须写成 policy=1");
    assert!(!l4[0].1.l3_only(), "policy=1 不该被判成 L3-only");
    assert_eq!(read_sysctl(fields_path), Some(31), "同时把位元补齐到 L4");
    let l4_map = flow_map_ports(&devs_f, "10.6.9.9", cdn, &ports);
    let on0 = l4_map.iter().filter(|d| d.as_str() == "mwf0").count();
    eprintln!(
        "hash granularity: policy=0 → {} 条全走 {}；policy=1 → {on0}/{} 走 mwf0、{} 走 mwf1",
        l3_map.len(),
        l3_map[0],
        l4_map.len(),
        l4_map.len() - on0
    );
    assert_eq!(
        devs_used(&l4_map),
        2,
        "policy=1（l4）时，同一个目的 IP 的连线必须散到两条线（实测：{l4_map:?}）"
    );

    // (2) 明确 l3 → policy=0 → 回到「只按 IP」，可观测（告警/状态档用的判据）
    let back = crate::apply_multipath_hash(Some(MultipathHashPolicy::L3), false);
    assert_eq!(back[0].1.policy, Some(0));
    assert!(back[0].1.l3_only());
    let l3_again = flow_map_ports(&devs_f, "10.6.9.9", cdn, &ports);
    assert_eq!(
        devs_used(&l3_again),
        1,
        "policy=0 必须回到「同一个目的 IP 全挤一条线」（实测：{l3_again:?}）"
    );

    // (3) inner 对未封装流量等同 l3：这里只验证判据（真实封装流量不在本测试范围）
    let inner = crate::apply_multipath_hash(Some(MultipathHashPolicy::Inner), false);
    assert_eq!(inner[0].1.policy, Some(2));
    assert!(
        inner[0].1.l3_only(),
        "inner 未封装流量等同 L3，必须被判成 L3-only"
    );

    rm_f.cleanup_routes().expect("hash-section cleanup");
}

/// 回归：nexthop object 的新增/删除必须真的生效。
///
/// 这里抓过一个只有真实核心才会现形的 bug：DELNEXTHOP 的 nhmsg 带了非零
/// `nh_protocol`，内核回 EINVAL，而 `is_absent_object` 把 EINVAL 当成
/// 「本来就不存在」吞掉——group 与成员永远拆不掉。单元测试只验位元组布局，
/// 抓不到「内核拒绝」。
#[test]
#[ignore = "needs unshare -Urn + CAP_NET_ADMIN; see module docs"]
fn netns_nexthop_object_lifecycle() {
    if !netns_enabled() {
        return;
    }
    let _d = Dummies::setup(&[("mwd0", "10.9.0.2/24")]);
    let idx = ifindex("mwd0");
    let mut rm = RouteManager::new(4000, EcmpMode::Resilient).unwrap();

    let listed = |s: &str| sh_out(&["ip", "nexthop", "show"]).contains(s);

    rm.ensure_nexthop(AF_INET, 9003, idx, None).unwrap();
    assert!(listed("9003"), "ensure_nexthop 未建立物件");

    // AF_INET（建立时用的 family）与 AF_UNSPEC（group 用）都要能删
    rm.delete_nexthop(AF_INET, 9003).expect("delete AF_INET");
    assert!(!listed("9003"), "delete_nexthop(AF_INET) 未删除");
    rm.ensure_nexthop(AF_INET, 9004, idx, None).unwrap();
    rm.delete_nexthop(AF_UNSPEC, 9004)
        .expect("delete AF_UNSPEC");
    assert!(!listed("9004"), "delete_nexthop(AF_UNSPEC) 未删除");
}

/// 策略分流规则的真实核心验证：`from`/`to` + 目标 WAN 独立表。
///
/// 这里验证的是「不用 fwmark/nftables 也能按来源分流」的核心假设：
/// 路由查找会命中 `from` 规则，并使用规则指定的表。
///
/// 注意 `ip route get ... from <src>` 的内核限制：来源必须是本机位址，
/// 否则 getroute 会先做来源验证而回 ENETUNREACH（与转发路径无关）。
/// 因此这里把「LAN 客户端位址」也配置成本机 dummy，模拟 LAN 来源。
#[test]
#[ignore = "needs unshare -Urn + CAP_NET_ADMIN; see module docs"]
fn netns_policy_routing() {
    if !netns_enabled() {
        return;
    }
    let _d = Dummies::setup(&[
        ("mwp0", "10.20.0.2/24"),
        ("mwp1", "10.21.0.2/24"),
        ("lanp", "192.168.9.5/24"),
    ]);
    let mut rm = RouteManager::new(5000, EcmpMode::Standard).unwrap();

    // 两张 WAN 的独立表（含 default via）由探针路径建立，策略规则沿用它们
    let paths = vec![
        ProbePath {
            ifname: "mwp0".to_string(),
            ifindex: ifindex("mwp0"),
            gateway: None,
            targets: vec!["223.5.5.5".parse().unwrap()],
            table: PROBE_TABLE_BASE,
            priority: PROBE_RULE_PRIORITY_BASE,
            main_route_targets: Vec::new(),
        },
        ProbePath {
            ifname: "mwp1".to_string(),
            ifindex: ifindex("mwp1"),
            gateway: None,
            targets: vec!["223.5.5.5".parse().unwrap()],
            table: PROBE_TABLE_BASE + 1,
            priority: PROBE_RULE_PRIORITY_BASE + 1,
            main_route_targets: Vec::new(),
        },
    ];
    rm.set_probe_paths(&paths).expect("probe paths");

    // 来源 192.168.9.0/24 走第二条 WAN
    let rule = PolicyRule {
        name: "guest".to_string(),
        ifindex: ifindex("mwp1"),
        table: PROBE_TABLE_BASE + 1,
        priority: POLICY_RULE_PRIORITY_BASE,
        source: Some(("192.168.9.0".parse().unwrap(), 24)),
        destination: None,
    };
    rm.set_policy_rules(std::slice::from_ref(&rule))
        .expect("install policy rule");

    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(
        rules.contains("from 192.168.9.0/24 lookup 10001"),
        "策略规则未安装:\n{rules}"
    );
    // 核心路由查找必须命中规则指定的表（表内 default dev mwp1）
    let get = sh_out(&["ip", "route", "get", "8.8.8.8", "from", "192.168.9.5"]);
    assert!(
        get.contains("dev mwp1") && get.contains("table 10001"),
        "来源分流未生效（应走 mwp1 / table 10001）:\n{get}"
    );

    // 目的限定的规则也要能安装与匹配
    let scoped = PolicyRule {
        name: "guest-dst".to_string(),
        ifindex: ifindex("mwp1"),
        table: PROBE_TABLE_BASE + 1,
        priority: POLICY_RULE_PRIORITY_BASE + 1,
        source: Some(("192.168.9.0".parse().unwrap(), 24)),
        destination: Some(("203.0.113.0".parse().unwrap(), 24)),
    };
    rm.set_policy_rules(&[rule.clone(), scoped.clone()])
        .expect("install scoped policy rule");
    let get = sh_out(&["ip", "route", "get", "203.0.113.9", "from", "192.168.9.5"]);
    assert!(get.contains("dev mwp1"), "目的限定策略未生效:\n{get}");

    // 移除后必须回到 main 表（此 netns 没有预设路由，查询会失败）
    rm.set_policy_rules(&[]).expect("remove policy rule");
    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(
        !rules.contains("192.168.9.0/24"),
        "策略规则未被移除:\n{rules}"
    );

    // sweep 也要能清掉残留（模拟上次执行留下的规则）
    rm.set_policy_rules(&[rule]).expect("reinstall policy rule");
    rm.sweep_policy_rules().expect("sweep policy rules");
    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(
        !rules.contains("192.168.9.0/24"),
        "sweep 未清掉策略规则:\n{rules}"
    );

    // FIX-8：auto 模式必须回报「实际安装生效的变体」，主回圈才能正确决定
    // 要不要在切换瞬间清 conntrack（不能只看设定值）。
    let mut auto_rm = RouteManager::new(5100, EcmpMode::Auto).unwrap();
    let wans = vec![veh("mwp0", 1, Vec::new()), veh("mwp1", 1, Vec::new())];
    auto_rm
        .apply_default_routes(&wans)
        .expect("auto default routes");
    let variant = auto_rm.installed_ipv4_variant();
    assert!(
        matches!(
            variant,
            InstalledVariant::Resilient | InstalledVariant::Standard
        ),
        "auto 模式必须回报实际生效的变体: {variant:?}"
    );
    auto_rm.cleanup_routes().expect("auto cleanup");

    rm.cleanup_routes().expect("cleanup");
}
