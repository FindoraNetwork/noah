use criterion::{criterion_group, criterion_main, Criterion};
use noah_algebra::ed25519::Ed25519Fq;
use noah_algebra::prelude::{test_rng, Scalar};
use noah_algebra::secp256k1::SECP256K1Fq;
use noah_crypto::hashing_to_the_curve::ed25519_elligator::Ed25519Elligator;
use noah_crypto::hashing_to_the_curve::ed25519_sswu_wb::Ed25519SSWU;
use noah_crypto::hashing_to_the_curve::ed25519_sw::Ed25519SW;
use noah_crypto::hashing_to_the_curve::secp256k1_sswu_wb::Secp256k1SSWU;
use noah_crypto::hashing_to_the_curve::secp256k1_sw::Secp256k1SW;
use noah_crypto::hashing_to_the_curve::traits::{
    ElligatorParameters, SWParameters, SimplifiedSWUParameters,
};

fn bench_ed25519_elligator(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_elligator");
    single_group.bench_function("ed25519 elligator".to_string(), |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = Ed25519Elligator::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_ed25519_sswu_wb(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_sswu_wb");
    single_group.bench_function("ed25519 simplified SWU map".to_string(), |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = Ed25519SSWU::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_ed25519_sw(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_sw");
    single_group.bench_function("ed25519 SW map".to_string(), |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = Ed25519SW::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_secp256k1_sswu_wb(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("secp256k1_sswu_wb");
    single_group.bench_function("secp256k1 simplified SWU map".to_string(), |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);
            let _ = Secp256k1SSWU::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_secp256k1_sw(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("secp256k1_sw");
    single_group.bench_function("secp256k1 SW map".to_string(), |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);
            let _ = Secp256k1SW::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

criterion_group!(
    benches,
    bench_ed25519_elligator,
    bench_ed25519_sswu_wb,
    bench_ed25519_sw,
    bench_secp256k1_sswu_wb,
    bench_secp256k1_sw
);
criterion_main!(benches);
