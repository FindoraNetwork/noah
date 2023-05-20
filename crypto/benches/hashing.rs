use criterion::{criterion_group, criterion_main, Criterion};
use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
use noah_algebra::prelude::{test_rng, Scalar};
use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};
use noah_crypto::hashing_to_the_curve::ed25519_elligator::Ed25519ElligatorParameters;
use noah_crypto::hashing_to_the_curve::ed25519_sswu_wb::Ed25519SSWUParameters;
use noah_crypto::hashing_to_the_curve::models::elligator::Elligator;
use noah_crypto::hashing_to_the_curve::models::sswu::SimplifiedSWUMap;
use noah_crypto::hashing_to_the_curve::models::sw::SWMap;
use noah_crypto::hashing_to_the_curve::secp256k1_sw::Secp256k1SWParameters;
use noah_crypto::hashing_to_the_curve::sswu::Secp256k1SSWUParameters;
use noah_crypto::hashing_to_the_curve::sw::Ed25519SWParameters;
use noah_crypto::hashing_to_the_curve::traits::HashingToCurve;

fn bench_ed25519_elligator(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_elligator");
    single_group.bench_function("ed25519 elligator".to_string(), |b| {
        b.iter(|| {
            type M = Elligator<Ed25519Point, Ed25519ElligatorParameters>;

            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = M::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_ed25519_sswu_wb(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_sswu_wb");
    single_group.bench_function("ed25519 simplified SWU map".to_string(), |b| {
        b.iter(|| {
            type M = SimplifiedSWUMap<Ed25519Point, Ed25519SSWUParameters>;

            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = M::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_ed25519_sw(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("ed25519_sw");
    single_group.bench_function("ed25519 SW map".to_string(), |b| {
        b.iter(|| {
            type M = SWMap<Ed25519Point, Ed25519SWParameters>;

            let mut rng = test_rng();
            let t = Ed25519Fq::random(&mut rng);
            let _ = M::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_secp256k1_sswu_wb(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("secp256k1_sswu_wb");
    single_group.bench_function("secp256k1 simplified SWU map".to_string(), |b| {
        b.iter(|| {
            type M = SimplifiedSWUMap<SECP256K1G1, Secp256k1SSWUParameters>;

            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);
            let _ = M::get_x_coordinate_without_cofactor_clearing(&t);
        });
    });
    single_group.finish();
}

fn bench_secp256k1_sw(c: &mut Criterion) {
    let mut single_group = c.benchmark_group("secp256k1_sw");
    single_group.bench_function("secp256k1 SW map".to_string(), |b| {
        b.iter(|| {
            type M = SWMap<SECP256K1G1, Secp256k1SWParameters>;

            let mut rng = test_rng();
            let t = SECP256K1Fq::random(&mut rng);
            let _ = M::get_x_coordinate_without_cofactor_clearing(&t);
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
