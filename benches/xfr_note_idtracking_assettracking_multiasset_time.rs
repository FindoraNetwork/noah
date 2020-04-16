extern crate criterion;

use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, Criterion};
use zei_utilities::xfr_bench::xfr_note_idtracking_assettracking_multiasset;

// Benchmark with time
criterion_group!(
    name = xfr_note_idtracking_assettracking_multiasset_with_time;
    config = Criterion::default().with_measurement(WallTime);
    targets = xfr_note_idtracking_assettracking_multiasset::<WallTime>
);
criterion_main!(xfr_note_idtracking_assettracking_multiasset_with_time);
