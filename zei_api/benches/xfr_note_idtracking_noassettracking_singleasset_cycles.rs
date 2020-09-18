use bench_utils::api::xfr::xfr_note_idtracking_noassettracking_singleasset;
use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;

// Benchmark with time
criterion_group!(
    name = xfr_note_idtracking_noassettracking_singleasset_with_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = xfr_note_idtracking_noassettracking_singleasset::<CyclesPerByte>
);
criterion_main!(xfr_note_idtracking_noassettracking_singleasset_with_cycles);
