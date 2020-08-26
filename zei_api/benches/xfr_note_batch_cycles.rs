extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;
use zei_utilities::xfr_bench::xfr_note_batch;

// Benchmark with cycles
criterion_group!(
    name = xfr_note_batch_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = xfr_note_batch::<CyclesPerByte>
);
criterion_main!(xfr_note_batch_with_cycles);
