use criterion::{criterion_group, criterion_main, Criterion};
use merlin::Transcript;
use noah_algebra::bn254::{BN254PairingEngine, BN254Scalar};
use noah_algebra::prelude::*;
use noah_crypto::anemoi_jive::{AnemoiJive, AnemoiJive254, ANEMOI_JIVE_BN254_SALTS};
use noah_plonk::plonk::constraint_system::{ConstraintSystem, TurboCS};
use noah_plonk::plonk::indexer::indexer;
use noah_plonk::plonk::prover::prover;
use noah_plonk::plonk::verifier::verifier;
use noah_plonk::poly_commit::kzg_poly_com::KZGCommitmentScheme;
use noah_plonk::poly_commit::pcs::PolyComScheme;

fn merkle_tree_proof_bench(c: &mut Criterion) {
    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive254>();

    let va = cs.new_variable(BN254Scalar::from(1u64));
    let vb = cs.new_variable(BN254Scalar::from(2u64));
    let vc = cs.new_variable(BN254Scalar::from(3u64));

    let trace = AnemoiJive254::eval_jive_with_trace(
        &[BN254Scalar::from(1u64), BN254Scalar::from(2u64)],
        &[BN254Scalar::from(3u64), ANEMOI_JIVE_BN254_SALTS[0]],
    );

    for _ in 0..500 {
        let _ = cs.jive_crh::<AnemoiJive254>(&trace, &[va, vb, vc], ANEMOI_JIVE_BN254_SALTS[0]);
    }
    println!("number of constraints: {}", cs.size);
    cs.pad();
    let witness = cs.get_and_clear_witness();

    let mut prng = test_rng();
    let pcs = KZGCommitmentScheme::<BN254PairingEngine>::new(8195, &mut prng);

    let prover_params = indexer(&cs, &pcs).unwrap();
    let verifier_params = prover_params.get_verifier_params_ref();

    let mut transcript = Transcript::new(b"TestTurboPlonk");

    let mut single_group = c.benchmark_group("prover");
    single_group.sample_size(10);
    single_group.bench_function("batch of 500".to_string(), |b| {
        b.iter(|| {
            prover(
                &mut prng,
                &mut transcript,
                &pcs,
                &cs,
                &prover_params,
                &witness,
            )
            .unwrap()
        });
    });
    single_group.finish();

    let proof = prover(
        &mut prng,
        &mut transcript,
        &pcs,
        &cs,
        &prover_params,
        &witness,
    )
    .unwrap();

    let mut single_group = c.benchmark_group("verify");
    single_group.sample_size(10);
    single_group.bench_function("batch of 30".to_string(), |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"TestTurboPlonk");
            verifier(
                &mut transcript,
                &pcs.shrink_to_verifier_only(),
                &cs.shrink_to_verifier_only(),
                verifier_params,
                &[],
                &proof,
            )
            .unwrap()
        });
    });
    single_group.finish();
}

criterion_group!(benches, merkle_tree_proof_bench);
criterion_main!(benches);
