//! 真實 Linux 核心的整合測試（需要 netns + CAP_NET_ADMIN）。
//!
//! 執行方式（在臨時 netns 裡跑，完全不影響主機路由）：
//! ```sh
//! cargo test --no-run
//! unshare -Urn sh -c 'MWAN4_NETNS_TEST=1 cargo test --offline -- --ignored netns_route_lifecycle --test-threads=1'
//! ```
//!
//! 為什麼需要它們：路由編碼（rtm_scope、protocol、resilient bucket、nexthop
//! 刪除順序）的正確性只有真實核心說得準——單元測試只能驗證位元組佈局。
//! 這些測試會建立 dummy 網卡、下發真正的 ECMP / resilient / 策略路由，並用
//! `ip route show` / `ip nexthop show` / `ip rule show` 驗證結果。
//!
//! 沒設 `MWAN4_NETNS_TEST=1` 時直接跳過，CI 的一般 `cargo test` 不受影響。
//! 全部情境集中在**一個測試函式**裡：測試執行緒會並行跑多個測試，而路由表是
//! 全 netns 共用的，並行會讓「全斷時有沒有兜底」之類的判斷互相干擾。

use super::*;

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

/// 建立 / 清理一組 dummy 網卡
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
    ActiveWanRoute {
        ifname: name.to_string(),
        ifindex: ifindex(name),
        gateway: None,
        weight: 1,
        metric,
        underlay_targets: underlay,
    }
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

#[test]
#[ignore = "needs unshare -Urn + CAP_NET_ADMIN; see module docs"]
fn netns_route_lifecycle() {
    if !netns_enabled() {
        eprintln!("skip: set MWAN4_NETNS_TEST=1 and run inside `unshare -Urn`");
        return;
    }

    // ---------------------------------------------------------------
    // A. 標準 ECMP（無網關 → scope=LINK）：安裝 / 全斷二態 / 清理
    //    這一節同時驗證 P0 的兩個修正：
    //      - 刪除報文的 rtm_scope=NOWHERE（不修就刪不掉 scope=LINK 的路由）
    //      - handle_all_links_down 依 variant 刪除自己的路由
    // ---------------------------------------------------------------
    let _dummy_a = Dummies::setup(&[("mwa0", "10.0.0.2/24"), ("mwa1", "10.1.0.2/24")]);
    let mut rm = RouteManager::new(0, EcmpMode::Standard).unwrap();
    let wans = vec![veh("mwa0", 1, vec![]), veh("mwa1", 1, vec![])];

    rm.apply_default_routes(&wans).expect("standard ECMP apply");
    let r = routes();
    assert!(
        r.contains("nexthop dev mwa0") && r.contains("nexthop dev mwa1"),
        "雙線 ECMP 未安裝:\n{r}"
    );

    // 全斷、且沒有別的兜底路由 → 保留（刪掉會讓整機沒有出口）
    rm.apply_default_routes(&[]).expect("all-down keep");
    assert!(
        routes().contains("nexthop dev mwa0"),
        "唯一一條預設路由在全斷時必須保留"
    );

    // 有兜底路由（metric 100）→ 刪掉我們那條，讓兜底接手
    assert!(sh(&[
        "ip", "route", "add", "default", "dev", "mwa1", "metric", "100"
    ]));
    rm.apply_default_routes(&[]).expect("all-down remove");
    let r = routes();
    assert!(
        !r.contains("metric 0"),
        "全斷且有兜底時，我們的 metric 0 預設路由應被移除:\n{r}"
    );
    assert!(r.contains("metric 100"), "兜底路由必須保留:\n{r}");

    // 重新接管 → cleanup（remove_routes_on_exit=true 的路徑）只刪自己那條
    rm.apply_default_routes(&wans).expect("re-apply");
    rm.cleanup_routes().expect("cleanup routes");
    let r = routes();
    assert!(
        !r.contains("metric 0"),
        "cleanup 後不應殘留我們的預設路由:\n{r}"
    );
    assert!(r.contains("metric 100"), "cleanup 不該動到兜底路由:\n{r}");
    // 移除兜底，避免與後面段落新增的兜底路由撞 metric（同 prefix/metric 會 EEXIST）
    let _ = sh(&[
        "ip", "route", "del", "default", "dev", "mwa1", "metric", "100",
    ]);

    // ---------------------------------------------------------------
    // B. resilient nexthop group：兩成員 → 縮成一成員 → 全斷拆除 → cleanup
    //    驗證 bucket 數固定（REPLACE 不變更 bucket）、nh 路由的刪除與 group 拆除
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

    // 成員數 2 → 1：舊版會改 bucket 數而被核心以 EINVAL 拒絕；現在固定 256
    rm.apply_default_routes(&wans_b[..1])
        .expect("resilient shrink to one member");
    let nh = sh_out(&["ip", "nexthop", "show"]);
    assert!(nh.contains("group"), "縮減成員後 group 應仍存在:\n{nh}");

    // 有兜底 → 全斷：必須把 nh-id 路由刪掉（P0 修正；舊版用標準 key 刪不掉）
    assert!(sh(&[
        "ip", "route", "add", "default", "dev", "mwb1", "metric", "200"
    ]));
    rm.apply_default_routes(&[]).expect("resilient all-down");
    let r = routes();
    assert!(
        !r.contains("nhid"),
        "全斷且有兜底時，resilient 預設路由應被移除:\n{r}"
    );
    assert!(r.contains("metric 200"), "兜底路由必須保留:\n{r}");
    let _ = sh(&[
        "ip", "route", "del", "default", "dev", "mwb1", "metric", "200",
    ]);

    // cleanup 要把 group 與成員 nexthop 一起拆乾淨
    rm.cleanup_routes().expect("resilient cleanup");
    let nh = sh_out(&["ip", "nexthop", "show"]);
    assert!(
        !nh.contains("group"),
        "cleanup 後 resilient group 應被拆除:\n{nh}"
    );

    // ---------------------------------------------------------------
    // C. 探針路徑（oif 規則 + 獨立表 + 主表 /32）與 underlay /32 的退出清理
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
    assert!(rules.contains("lookup 10000"), "oif 規則未建立:\n{rules}");
    let table = sh_out(&["ip", "route", "show", "table", "10000"]);
    assert!(table.contains("default"), "探針表內沒有預設路由:\n{table}");
    let r = routes();
    assert!(
        r.contains("192.0.2.1") && r.contains("42760"),
        "主表探針 /32 未建立:\n{r}"
    );

    rm.set_probe_paths(&[]).expect("clear probe paths");
    assert!(
        !sh_out(&["ip", "rule", "show"]).contains("lookup 10000"),
        "規則未拆除"
    );
    let r = routes();
    assert!(!r.contains("42760"), "探針 /32 未拆除:\n{r}");

    // 隧道 underlay：apply 時自動補 /32，cleanup 時必須拆掉（否則指向舊閘道）
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
    assert!(!r.contains("42761"), "cleanup 後 underlay /32 未拆除:\n{r}");
    assert!(!r.contains("metric 3000"), "cleanup 後預設路由未拆除:\n{r}");

    // ---------------------------------------------------------------
    // D. IPv6 預設路由（如有需要可擴充；目前只驗證安裝與刪除不報錯）
    // ---------------------------------------------------------------
    // 內核不允許 IPv6 用「純 dev」的 multipath（"Device only routes can not be
    // added for IPv6 using the multipath API"），所以 IPv6 段一定要有 gateway6
    // （生產設定本來就是這樣，main 也只把 gateway6 非空的線放進 IPv6 路由）。
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
            "IPv6 ECMP 未安裝:\n{r6}"
        );
        rm6.cleanup_routes().expect("IPv6 cleanup");
        let r6 = sh_out(&["ip", "-6", "route", "show"]);
        assert!(!r6.contains("metric 3001"), "IPv6 cleanup 未刪除:\n{r6}");
    } else {
        eprintln!("skip IPv6 section: cannot add IPv6 address");
    }
}

/// 迴歸：nexthop object 的新增/刪除必須真的生效。
///
/// 這裡抓過一個只有真實核心才會現形的 bug：DELNEXTHOP 的 nhmsg 帶了非零
/// `nh_protocol`，內核回 EINVAL，而 `is_absent_object` 把 EINVAL 當成
/// 「本來就不存在」吞掉——group 與成員永遠拆不掉。單元測試只驗位元組佈局，
/// 抓不到「內核拒絕」。
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

    // AF_INET（建立時用的 family）與 AF_UNSPEC（group 用）都要能刪
    rm.delete_nexthop(AF_INET, 9003).expect("delete AF_INET");
    assert!(!listed("9003"), "delete_nexthop(AF_INET) 未刪除");
    rm.ensure_nexthop(AF_INET, 9004, idx, None).unwrap();
    rm.delete_nexthop(AF_UNSPEC, 9004)
        .expect("delete AF_UNSPEC");
    assert!(!listed("9004"), "delete_nexthop(AF_UNSPEC) 未刪除");
}

/// 策略分流規則的真實核心驗證：`from`/`to` + 目標 WAN 獨立表。
///
/// 這裡驗證的是「不用 fwmark/nftables 也能按來源分流」的核心假設：
/// 路由查找會命中 `from` 規則，並使用規則指定的表。
///
/// 注意 `ip route get ... from <src>` 的內核限制：來源必須是本機位址，
/// 否則 getroute 會先做來源驗證而回 ENETUNREACH（與轉發路徑無關）。
/// 因此這裡把「LAN 客戶端位址」也配置成本機 dummy，模擬 LAN 來源。
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

    // 兩張 WAN 的獨立表（含 default via）由探針路徑建立，策略規則沿用它們
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

    // 來源 192.168.9.0/24 走第二條 WAN
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
        "策略規則未安裝:\n{rules}"
    );
    // 核心路由查找必須命中規則指定的表（表內 default dev mwp1）
    let get = sh_out(&["ip", "route", "get", "8.8.8.8", "from", "192.168.9.5"]);
    assert!(
        get.contains("dev mwp1") && get.contains("table 10001"),
        "來源分流未生效（應走 mwp1 / table 10001）:\n{get}"
    );

    // 目的限定的規則也要能安裝與匹配
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

    // 移除後必須回到 main 表（此 netns 沒有預設路由，查詢會失敗）
    rm.set_policy_rules(&[]).expect("remove policy rule");
    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(
        !rules.contains("192.168.9.0/24"),
        "策略規則未被移除:\n{rules}"
    );

    // sweep 也要能清掉殘留（模擬上次執行留下的規則）
    rm.set_policy_rules(&[rule]).expect("reinstall policy rule");
    rm.sweep_policy_rules().expect("sweep policy rules");
    let rules = sh_out(&["ip", "rule", "show"]);
    assert!(
        !rules.contains("192.168.9.0/24"),
        "sweep 未清掉策略規則:\n{rules}"
    );

    // FIX-8：auto 模式必須回報「實際安裝生效的變體」，主迴圈才能正確決定
    // 要不要在切換瞬間清 conntrack（不能只看設定值）。
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
        "auto 模式必須回報實際生效的變體: {variant:?}"
    );
    auto_rm.cleanup_routes().expect("auto cleanup");

    rm.cleanup_routes().expect("cleanup");
}
