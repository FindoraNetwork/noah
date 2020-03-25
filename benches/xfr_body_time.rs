extern crate criterion;

use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, Criterion};
use zei_utilities::bench::bench_xfr_body;

// Benchmark with time
criterion_group!(
    name = bench_xfr_body_with_time;
    config = Criterion::default().with_measurement(WallTime);
    targets = bench_xfr_body::<WallTime>
);
criterion_main!(bench_xfr_body_with_time);
