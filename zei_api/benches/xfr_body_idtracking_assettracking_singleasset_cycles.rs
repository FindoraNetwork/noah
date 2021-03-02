use bench_utils::api::xfr::xfr_body_idtracing_assettracing_singleasset;
use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

// Benchmark with cycles
criterion_group!(
    name = xfr_body_idtracing_assettracing_singleasset_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = xfr_body_idtracing_assettracing_singleasset::<CyclesPerByte>
);
criterion_main!(xfr_body_idtracing_assettracing_singleasset_with_cycles);
