use bench_utils::api::xfr::xfr_note_idtracing_assettracing_multiasset;
use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

// Benchmark with cycles
criterion_group!(
    name = xfr_note_idtracing_assettracing_multiasset_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = xfr_note_idtracing_assettracing_multiasset::<CyclesPerByte>
);
criterion_main!(xfr_note_idtracing_assettracing_multiasset_with_cycles);
