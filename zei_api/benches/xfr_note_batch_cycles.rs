use bench_utils::api::xfr::xfr_note_batch;
use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

// Benchmark with cycles
criterion_group!(
    name = xfr_note_batch_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = xfr_note_batch::<CyclesPerByte>
);
criterion_main!(xfr_note_batch_with_cycles);
