extern crate criterion;

use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, Criterion};
use zei_utilities::xfr_bench::xfr_note_noidtracking_noassettracking_singleasset;

// Benchmark with time
criterion_group!(
    name = xfr_note_noidtracking_noassettracking_singleasset_with_time;
    config = Criterion::default().with_measurement(WallTime);
    targets = xfr_note_noidtracking_noassettracking_singleasset::<WallTime>
);
criterion_main!(xfr_note_noidtracking_noassettracking_singleasset_with_time);
