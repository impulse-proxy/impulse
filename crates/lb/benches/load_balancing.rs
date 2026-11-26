mod support;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use support::{BACKEND_COUNTS, STRATEGIES, runtime_upstream, selector_runtime};

const KEYS: [&str; 8] = [
    "tenant:001",
    "tenant:002",
    "tenant:003",
    "tenant:004",
    "tenant:005",
    "tenant:006",
    "tenant:007",
    "tenant:008",
];

fn benchmark_selection(criterion: &mut Criterion) {
    for (label, strategy) in STRATEGIES {
        let mut group = criterion.benchmark_group(format!("load_balancing/selection/{label}"));
        for backend_count in BACKEND_COUNTS {
            let upstream = runtime_upstream(backend_count, strategy);
            let runtime = selector_runtime(&upstream);
            let selector = runtime
                .selector_by_id(impulse_contracts::UpstreamId::new(0))
                .expect("benchmark selector");
            let mut key_index = 0usize;

            group.throughput(Throughput::Elements(1));
            group.bench_function(BenchmarkId::new("pick", backend_count), |bencher| {
                bencher.iter(|| {
                    let key = KEYS[key_index % KEYS.len()];
                    key_index = key_index.wrapping_add(1);
                    black_box(selector.select_excluding(black_box(key), &[]))
                });
            });
        }
        group.finish();
    }
}

fn benchmark_pool_index_construction(criterion: &mut Criterion) {
    for (label, strategy) in STRATEGIES {
        let mut group = criterion.benchmark_group(format!("load_balancing/construction/{label}"));
        for backend_count in BACKEND_COUNTS {
            let upstream = runtime_upstream(backend_count, strategy);
            group.throughput(Throughput::Elements(backend_count as u64));
            group.bench_with_input(
                BenchmarkId::new("pool_and_index", backend_count),
                &upstream,
                |bencher, upstream| {
                    bencher.iter(|| {
                        let runtime = selector_runtime(black_box(upstream));
                        black_box(
                            runtime
                                .selector_by_id(impulse_contracts::UpstreamId::new(0))
                                .and_then(|selector| selector.select_excluding(KEYS[0], &[])),
                        );
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(
    load_balancing_benches,
    benchmark_selection,
    benchmark_pool_index_construction
);
criterion_main!(load_balancing_benches);
