extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;
use zei_utilities::bench::bench_xfr_note;

// Benchmark with cycles
criterion_group!(
    name = bench_xfr_note_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench_xfr_note::<CyclesPerByte>
);
criterion_main!(bench_xfr_note_with_cycles);
