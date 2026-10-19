use std::{collections::HashMap, time::Instant};

use impulse_config::config::{LoadBalancing, RouteMatch, Upstream};
use impulse_edge::routing::{
    decision::RouteDecisionReason,
    index::RouteIndex,
    scan::{scan_lookup, scan_lookup_for_method},
};

fn test_upstream(host: Option<&str>, path_prefix: Option<&str>) -> Upstream {
    test_upstream_with_method(host, path_prefix, None)
}

fn test_upstream_with_method(
    host: Option<&str>,
    path_prefix: Option<&str>,
    method: Option<&str>,
) -> Upstream {
    Upstream {
        load_balancing: LoadBalancing {
            lb_type: "random".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        compression: Default::default(),
        cache: Default::default(),
        tls: None,
        route: RouteMatch {
            host: host.map(str::to_string),
            path_prefix: path_prefix.map(str::to_string),
            method: method.map(str::to_string),
        },
        backends: vec![],
    }
}

#[test]
fn longest_prefix_lookup_works() {
    let mut upstreams = HashMap::new();
    upstreams.insert("root".to_string(), test_upstream(None, Some("/")));
    upstreams.insert("api".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert("api-v1".to_string(), test_upstream(None, Some("/api/v1")));

    let index = RouteIndex::from_upstreams(&upstreams);
    let selected = index.lookup("/api/v1/users", None);
    assert_eq!(selected, Some("api-v1"));
}

#[test]
fn indexed_lookup_matches_scan_lookup() {
    let mut upstreams = HashMap::new();
    upstreams.insert("default-root".to_string(), test_upstream(None, Some("/")));
    upstreams.insert("default-api".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert(
        "api-host-only".to_string(),
        test_upstream(Some("api.example.com"), None),
    );
    upstreams.insert(
        "api-host-route".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    upstreams.insert(
        "admin-host-route".to_string(),
        test_upstream(Some("admin.example.com"), Some("/admin")),
    );

    let index = RouteIndex::from_upstreams(&upstreams);
    let queries = vec![
        ("/", None),
        ("/api/users", None),
        ("/api/users", Some("api.example.com")),
        ("/admin/users", Some("admin.example.com")),
        ("/unknown", Some("api.example.com")),
        ("/unknown", Some("missing.example.com")),
    ];

    for (path, host) in queries {
        assert_eq!(
            index.lookup(path, host),
            scan_lookup(&upstreams, path, host)
        );
    }
}

#[test]
fn host_specific_route_wins_on_tie() {
    let mut upstreams = HashMap::new();
    upstreams.insert("a-default".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert(
        "z-host".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );

    let index = RouteIndex::from_upstreams(&upstreams);
    assert_eq!(
        index.lookup("/api/users", Some("api.example.com")),
        Some("z-host")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
        Some("z-host")
    );
}

#[test]
fn lookup_normalizes_request_host_case_and_port() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup("/api/v1", Some("API.EXAMPLE.COM:443")),
        Some("api")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/v1", Some("API.EXAMPLE.COM:443")),
        Some("api")
    );
}

#[test]
fn lookup_normalizes_configured_host_case() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "api".to_string(),
        test_upstream(Some("API.Example.COM"), Some("/api")),
    );
    upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
    let index = RouteIndex::from_upstreams(&upstreams);
    assert_eq!(
        index.lookup("/api/v1", Some("api.example.com")),
        Some("api")
    );
}

#[test]
fn path_prefix_requires_segment_boundary() {
    let mut upstreams = HashMap::new();
    upstreams.insert("api".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert("root".to_string(), test_upstream(None, Some("/")));
    let index = RouteIndex::from_upstreams(&upstreams);
    assert_eq!(index.lookup("/api", None), Some("api"));
    assert_eq!(index.lookup("/api/v1", None), Some("api"));
    assert_eq!(index.lookup("/api2", None), Some("root"));
    assert_eq!(scan_lookup(&upstreams, "/api2", None), Some("root"));
}

#[test]
fn lookup_with_decision_reports_host_specific_tie_break() {
    let mut upstreams = HashMap::new();
    upstreams.insert("default-api".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert(
        "host-api".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    let decision = index
        .lookup_with_decision_for_method("/api/v1", Some("api.example.com"), None)
        .expect("decision");
    assert_eq!(decision.upstream, "host-api");
    assert_eq!(decision.reason, RouteDecisionReason::HostSpecificTieBreak);
}

#[test]
fn lookup_with_decision_reports_default_longer_path() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "host-root".to_string(),
        test_upstream(Some("api.example.com"), Some("/")),
    );
    upstreams.insert(
        "default-api-v2".to_string(),
        test_upstream(None, Some("/api/v2")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    let decision = index
        .lookup_with_decision_for_method("/api/v2/users", Some("api.example.com"), None)
        .expect("decision");
    assert_eq!(decision.upstream, "default-api-v2");
    assert_eq!(decision.reason, RouteDecisionReason::DefaultPathLonger);
}

#[test]
fn method_specific_route_wins_on_tie() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "all-api".to_string(),
        test_upstream_with_method(None, Some("/api"), None),
    );
    upstreams.insert(
        "post-api".to_string(),
        test_upstream_with_method(None, Some("/api"), Some("POST")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    let get = index
        .lookup_with_decision_for_method("/api/items", None, Some("GET"))
        .expect("GET route");
    assert_eq!(get.upstream, "all-api");

    let post = index
        .lookup_with_decision_for_method("/api/items", None, Some("POST"))
        .expect("POST route");
    assert_eq!(post.upstream, "post-api");

    assert_eq!(
        scan_lookup_for_method(&upstreams, "/api/items", None, Some("POST")),
        Some("post-api")
    );
}

#[test]
fn method_matching_is_case_insensitive() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "post-api".to_string(),
        test_upstream_with_method(None, Some("/api"), Some("post")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup_for_method("/api", None, Some("POST")),
        Some("post-api")
    );
}

#[test]
fn lexical_tie_break_is_deterministic_for_default_routes() {
    let mut upstreams = HashMap::new();
    upstreams.insert("zeta".to_string(), test_upstream(None, Some("/api")));
    upstreams.insert("alpha".to_string(), test_upstream(None, Some("/api")));

    let index = RouteIndex::from_upstreams(&upstreams);
    assert_eq!(index.lookup("/api/users", None), Some("alpha"));
    assert_eq!(scan_lookup(&upstreams, "/api/users", None), Some("alpha"));
}

#[test]
fn lexical_tie_break_is_deterministic_for_host_routes() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "zeta-host".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    upstreams.insert(
        "alpha-host".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );

    let index = RouteIndex::from_upstreams(&upstreams);
    assert_eq!(
        index.lookup("/api/users", Some("api.example.com")),
        Some("alpha-host")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
        Some("alpha-host")
    );
}

#[test]
fn indexed_lookup_is_insertion_order_invariant() {
    let mut upstreams_a = HashMap::new();
    upstreams_a.insert("zeta".to_string(), test_upstream(None, Some("/")));
    upstreams_a.insert(
        "beta-host".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    upstreams_a.insert("alpha".to_string(), test_upstream(None, Some("/api")));

    let mut upstreams_b = HashMap::new();
    upstreams_b.insert("alpha".to_string(), test_upstream(None, Some("/api")));
    upstreams_b.insert("zeta".to_string(), test_upstream(None, Some("/")));
    upstreams_b.insert(
        "beta-host".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );

    let index_a = RouteIndex::from_upstreams(&upstreams_a);
    let index_b = RouteIndex::from_upstreams(&upstreams_b);
    let queries = vec![
        ("/api/users", None),
        ("/api/users", Some("api.example.com")),
        ("/", None),
        ("/missing", Some("api.example.com")),
    ];

    for (path, host) in queries {
        assert_eq!(index_a.lookup(path, host), index_b.lookup(path, host));
    }
}

#[test]
fn wildcard_host_route_matches_subdomains() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "wildcard".to_string(),
        test_upstream(Some("*.example.com"), Some("/api")),
    );
    upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup("/api/users", Some("tenant.example.com")),
        Some("wildcard")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/users", Some("tenant.example.com")),
        Some("wildcard")
    );
    assert_eq!(
        index.lookup("/api/users", Some("example.com")),
        Some("default")
    );
}

#[test]
fn exact_host_route_beats_wildcard_on_tie() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "wildcard".to_string(),
        test_upstream(Some("*.example.com"), Some("/api")),
    );
    upstreams.insert(
        "exact".to_string(),
        test_upstream(Some("api.example.com"), Some("/api")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup("/api/users", Some("api.example.com")),
        Some("exact")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/users", Some("api.example.com")),
        Some("exact")
    );
    assert_eq!(
        index
            .lookup_with_decision_for_method("/api/users", Some("api.example.com"), None)
            .map(|decision| decision.reason),
        Some(RouteDecisionReason::ExactHostTieBreak)
    );
}

#[test]
fn more_specific_wildcard_beats_less_specific_wildcard() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "wide".to_string(),
        test_upstream(Some("*.example.com"), Some("/api")),
    );
    upstreams.insert(
        "narrow".to_string(),
        test_upstream(Some("*.a.example.com"), Some("/api")),
    );
    upstreams.insert("default".to_string(), test_upstream(None, Some("/")));
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup("/api/users", Some("x.a.example.com")),
        Some("narrow")
    );
    assert_eq!(
        scan_lookup(&upstreams, "/api/users", Some("x.a.example.com")),
        Some("narrow")
    );
    assert_eq!(
        index
            .lookup_with_decision_for_method("/api/users", Some("x.a.example.com"), None)
            .map(|decision| decision.reason),
        Some(RouteDecisionReason::WildcardSpecificityTieBreak)
    );
}

#[test]
fn wildcard_keeps_method_and_path_precedence() {
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "wildcard-post".to_string(),
        test_upstream_with_method(Some("*.example.com"), Some("/api"), Some("POST")),
    );
    upstreams.insert(
        "wildcard-all".to_string(),
        test_upstream_with_method(Some("*.example.com"), Some("/api"), None),
    );
    upstreams.insert(
        "wildcard-deep".to_string(),
        test_upstream(Some("*.example.com"), Some("/api/v2")),
    );
    let index = RouteIndex::from_upstreams(&upstreams);

    assert_eq!(
        index.lookup_for_method("/api/items", Some("tenant.example.com"), Some("POST")),
        Some("wildcard-post")
    );
    assert_eq!(
        scan_lookup_for_method(
            &upstreams,
            "/api/items",
            Some("tenant.example.com"),
            Some("POST")
        ),
        Some("wildcard-post")
    );
    assert_eq!(
        index
            .lookup_with_decision_for_method("/api/items", Some("tenant.example.com"), Some("POST"))
            .map(|decision| decision.reason),
        Some(RouteDecisionReason::MethodSpecificTieBreak)
    );

    assert_eq!(
        index.lookup_for_method("/api/v2/items", Some("tenant.example.com"), Some("GET")),
        Some("wildcard-deep")
    );
    assert_eq!(
        scan_lookup_for_method(
            &upstreams,
            "/api/v2/items",
            Some("tenant.example.com"),
            Some("GET")
        ),
        Some("wildcard-deep")
    );
}

fn build_route_table(route_count: usize) -> HashMap<String, Upstream> {
    let mut upstreams = HashMap::with_capacity(route_count);
    for i in 0..route_count {
        let name = format!("upstream-{i:05}");
        let path = format!("/svc/{i:05}");
        let host = (i % 2 == 1).then_some("bench.example.com");
        upstreams.insert(name, test_upstream(host, Some(&path)));
    }
    upstreams
}

fn measure_lookup<F>(iterations: usize, mut lookup: F) -> std::time::Duration
where
    F: FnMut() -> Option<String>,
{
    let start = Instant::now();
    let mut sink = 0usize;
    for _ in 0..iterations {
        if let Some(value) = lookup() {
            sink ^= value.len();
        }
    }
    std::hint::black_box(sink);
    start.elapsed()
}

#[test]
#[ignore = "microbenchmark"]
fn route_lookup_microbenchmarks() {
    for route_count in [100usize, 1_000, 10_000] {
        let upstreams = build_route_table(route_count);
        let index = RouteIndex::from_upstreams(&upstreams);
        let query_path = format!("/svc/{:05}/resource", route_count - 1);
        let host = Some("bench.example.com");
        let iterations = match route_count {
            100 => 200_000,
            1_000 => 100_000,
            _ => 20_000,
        };

        assert_eq!(
            index.lookup(&query_path, host),
            scan_lookup(&upstreams, &query_path, host)
        );

        let scan_time = measure_lookup(iterations, || {
            scan_lookup(&upstreams, &query_path, host).map(str::to_string)
        });
        let indexed_time = measure_lookup(iterations, || {
            index.lookup(&query_path, host).map(str::to_string)
        });
        let speedup = scan_time.as_secs_f64() / indexed_time.as_secs_f64();

        eprintln!(
            "routes={route_count:>5} scan={scan_time:?} indexed={indexed_time:?} speedup={speedup:.2}x"
        );

        if route_count >= 1_000 {
            assert!(
                indexed_time < scan_time,
                "expected indexed lookup to be faster for {route_count} routes"
            );
        }
    }
}
