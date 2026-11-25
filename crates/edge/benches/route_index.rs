mod support;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use impulse_edge::routing::index::RouteIndex;
use support::{ROUTE_SCALES, RouteIndexFixture};

fn benchmark_construction(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("route_index/construction");
    for route_count in ROUTE_SCALES {
        let fixture = RouteIndexFixture::new(route_count);
        group.throughput(Throughput::Elements(route_count as u64));
        group.bench_with_input(
            BenchmarkId::new("from_runtime_upstreams", route_count),
            &fixture.runtime_upstreams,
            |bencher, upstreams| {
                bencher
                    .iter(|| black_box(RouteIndex::from_runtime_upstreams(black_box(upstreams))));
            },
        );
    }
    group.finish();
}

fn benchmark_lookup(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("route_index/lookup");
    for route_count in ROUTE_SCALES {
        let fixture = RouteIndexFixture::new(route_count);

        group.bench_with_input(
            BenchmarkId::new("default_hit", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.default_hit.as_str()),
                        None,
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("default_miss", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.default_miss.as_str()),
                        None,
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("exact_host_hit", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.exact_host_path.as_str()),
                        Some(black_box(fixture.exact_host.as_str())),
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("exact_host_miss", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.exact_host_path.as_str()),
                        Some(black_box(fixture.exact_host_miss.as_str())),
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("wildcard_host_hit", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.wildcard_host_path.as_str()),
                        Some(black_box(fixture.wildcard_host.as_str())),
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("wildcard_host_miss", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.wildcard_host_path.as_str()),
                        Some(black_box(fixture.wildcard_host_miss.as_str())),
                        None,
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("method_hit", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.method_path.as_str()),
                        None,
                        Some(black_box(fixture.method.as_str())),
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("method_miss", route_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter(|| {
                    black_box(fixture.index.lookup_with_decision_for_method(
                        black_box(fixture.method_path.as_str()),
                        None,
                        Some(black_box(fixture.method_miss.as_str())),
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    route_index_benches,
    benchmark_construction,
    benchmark_lookup
);
criterion_main!(route_index_benches);
