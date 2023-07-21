use criterion::{criterion_group, criterion_main, Criterion};
use merlin::Transcript;
use noah_algebra::bn254::BN254PairingEngine;
use noah_algebra::{bn254::BN254Scalar, prelude::*};
use noah_crypto::anemoi_jive::{AnemoiJive, AnemoiJive254};
use noah_plonk::plonk::constraint_system::{ConstraintSystem, TurboCS};
use noah_plonk::plonk::indexer::indexer;
use noah_plonk::plonk::prover::prover;
use noah_plonk::plonk::verifier::verifier;
use noah_plonk::poly_commit::kzg_poly_com::KZGCommitmentScheme;

fn bench_verifier(c: &mut Criterion) {
    let mut prng = test_rng();
    let pcs = KZGCommitmentScheme::<BN254PairingEngine>::new(260, &mut prng);

    let output_len = 7;
    let trace = AnemoiJive254::eval_stream_cipher_with_trace(
        &[
            BN254Scalar::from(1u64),
            BN254Scalar::from(2u64),
            BN254Scalar::from(3u64),
            BN254Scalar::from(4u64),
        ],
        output_len,
    );

    let mut cs = TurboCS::new();
    cs.load_anemoi_jive_parameters::<AnemoiJive254>();

    let one = cs.new_variable(BN254Scalar::from(1u64));
    let two = cs.new_variable(BN254Scalar::from(2u64));
    let three = cs.new_variable(BN254Scalar::from(3u64));
    let four = cs.new_variable(BN254Scalar::from(4u64));

    let mut output_var = vec![];
    for output in trace.output.iter() {
        output_var.push(cs.new_variable(output.clone()))
    }

    let _ = cs.anemoi_stream_cipher::<AnemoiJive254>(&trace, &[one, two, three, four], &output_var);
    cs.pad();

    let witness = cs.get_and_clear_witness();
    cs.verify_witness(&witness, &[]).unwrap();

    let prover_params = indexer(&cs, &pcs).unwrap();
    let verifier_params_ref = &prover_params.verifier_params;

    let mut transcript = Transcript::new(b"TestTurboPlonk");
    let proof = prover(
        &mut prng,
        &mut transcript,
        &pcs,
        &cs,
        &prover_params,
        &witness,
    )
        .unwrap();

    let verifier_cs = cs.shrink_to_verifier_only();

    let mut verifier_group = c.benchmark_group("bench_verifier");
    verifier_group.bench_function("verifier".to_string(), |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"TestTurboPlonk");
            verifier(
                &mut transcript,
                &pcs,
                &verifier_cs,
                verifier_params_ref,
                &[],
                &proof,
            )
                .unwrap()
        })
    });
    verifier_group.finish();
}

criterion_group!(benches, bench_verifier);
criterion_main!(benches);
