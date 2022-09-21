use ark_std::test_rng;
use ark_std::time::Instant;
use bulletproofs::{
    r1cs::{batch_verify, Prover, R1CSProof, Verifier},
    BulletproofGens, PedersenGens, RangeProof,
};
use merlin::Transcript;
use mix::MixValue;
use zei::setup::BulletproofParams;
use zei::xfr::asset_mixer::{prove_asset_mixing, AssetMixingInstance};
use zei_algebra::{
    prelude::*,
    ristretto::{CompressedRistretto, RistrettoScalar},
};
use zei_crypto::{
    basic::pedersen_comm::{PedersenCommitment, PedersenCommitmentRistretto},
    bulletproofs::mix::{self, MixCommitment, MixVariable},
};

fn main() {
    // Measurement of the verification time and batch verification time of Mix Bulletproofs in Zei
    bench_verify_asset_mixer();
    for i in 1..10 {
        bench_batch_verify_asset_mixer(i);
    }

    // Measurement of the verification time and batch verification time of Range Bulletproofs in Zei
    bench_verify_range();
    for i in [1, 2, 4, 8, 16] {
        bench_multiple_verify_range(i)
    }
    for i in [1, 2, 4, 8, 16] {
        bench_batch_verify_range(i);
    }
}

fn bench_verify_asset_mixer() {
    const COUNT: usize = 20;
    let mut transcripts = Vec::with_capacity(COUNT);
    let mut verifiers = Vec::with_capacity(COUNT);
    for _ in 0..COUNT {
        transcripts.push(Transcript::new(b"test"));
    }

    for (_, transcript) in [0; COUNT].iter().zip(transcripts.iter_mut()) {
        let mut verifier = Verifier::new(transcript);
        let proof = create_asset_mixer_proof();
        let in_vars = proof
            .1
            .iter()
            .map(|input| input.commit_verifier(&mut verifier))
            .collect_vec();

        let out_vars = proof
            .2
            .iter()
            .map(|output| output.commit_verifier(&mut verifier))
            .collect_vec();

        mix::mix(&mut verifier, &in_vars, None, &out_vars, None).unwrap();
        verifiers.push((verifier, proof.0));
    }

    let bp_circuit_gens = BulletproofGens::new(1024, 1);
    let pc_gens = PedersenGens::default();

    let start = Instant::now();
    for v in verifiers {
        assert!(v.0.verify(&v.1, &pc_gens, &bp_circuit_gens).is_ok());
    }
    println!(
        "non-batch verify mix bulletproofs takes time: {} s",
        start.elapsed().as_secs_f32() / COUNT as f32
    );
}

fn bench_batch_verify_asset_mixer(count: usize) {
    let mut asset_mix_instances = vec![];
    let mut proofs = vec![];
    let mut inputs_outputs = vec![];
    for _ in 0..count {
        let (inputs, outputs) = gen_inputs_outputs();
        let proof = prove_asset_mixing(&inputs, &outputs).unwrap();
        proofs.push(proof);
        inputs_outputs.push((inputs, outputs));
    }

    for ((inputs, outputs), proof) in inputs_outputs.iter().zip(proofs.iter_mut()) {
        let pc_gens = PedersenCommitmentRistretto::default();
        let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> = inputs
            .iter()
            .map(|(amount, typ, blind_a, blind_typ)| {
                (
                    pc_gens
                        .commit(RistrettoScalar::from(*amount), *blind_a)
                        .compress(),
                    pc_gens.commit(*typ, *blind_typ).compress(),
                )
            })
            .collect();
        let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> = outputs
            .iter()
            .map(|(amount, typ, blind_a, blind_typ)| {
                (
                    pc_gens
                        .commit(RistrettoScalar::from(*amount), *blind_a)
                        .compress(),
                    pc_gens.commit(*typ, *blind_typ).compress(),
                )
            })
            .collect();

        asset_mix_instances.push(AssetMixingInstance {
            inputs: input_coms,
            outputs: output_coms,
            proof: proof,
        });
    }

    let mut prng = test_rng();
    let mut params = BulletproofParams::default();

    let mut max_circuit_size = 0;
    let mut transcripts = Vec::with_capacity(count);
    let mut verifiers = Vec::with_capacity(count);
    for _ in 0..count {
        transcripts.push(Transcript::new(b"AssetMixingProof"));
    }
    for (instance, transcript) in asset_mix_instances.iter().zip(transcripts.iter_mut()) {
        let mut verifier = Verifier::new(transcript);
        prepare_asset_mixer_verifier(&mut verifier, instance).unwrap();
        let circuit_size = asset_mix_num_generators(instance.inputs.len(), instance.outputs.len());
        if circuit_size > max_circuit_size {
            max_circuit_size = circuit_size;
        }
        verifiers.push((verifier, &instance.proof.0));
    }

    max_circuit_size = max_circuit_size.next_power_of_two();
    if params.bp_circuit_gens.gens_capacity < max_circuit_size {
        params.increase_circuit_gens(max_circuit_size);
    }
    let pc_gens = PedersenGens::default();

    let start = Instant::now();
    assert!(batch_verify(&mut prng, verifiers, &pc_gens, &params.bp_circuit_gens).is_ok());
    println!(
        "batch verify of {} mix bulletproofs takes time: {} s",
        count,
        start.elapsed().as_secs_f32() / count as f32
    );
}

fn bench_verify_range() {
    const COUNT: usize = 20;
    let mut prng = test_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut proofs = vec![];
    let mut verifier_transcripts = vec![];

    for _ in 0..COUNT {
        let value = prng.gen_range(1u64..1000);
        let blinding = RistrettoScalar::random(&mut prng).0;
        let mut prover_transcript = Transcript::new(b"test");
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            value,
            &blinding,
            64,
        )
        .unwrap();
        proofs.push((proof, committed_value));

        let verifier_transcript = Transcript::new(b"test");
        verifier_transcripts.push(verifier_transcript);
    }

    let start = Instant::now();
    for ((proof, committed_value), transcipt) in proofs.iter().zip(verifier_transcripts.iter_mut())
    {
        assert!(proof
            .verify_single(&bp_gens, &pc_gens, transcipt, &committed_value, 64)
            .is_ok());
    }
    println!(
        "single verify range bulletproofs takes time: {} s",
        start.elapsed().as_secs_f32() / COUNT as f32
    );
}

fn bench_multiple_verify_range(count: usize) {
    let mut prng = test_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 16);
    let mut values = vec![];
    let mut blindings = vec![];

    for _ in 0..count {
        let value = prng.gen_range(1u64..1000);
        let blinding = RistrettoScalar::random(&mut prng).0;
        values.push(value);
        blindings.push(blinding);
    }

    let mut prover_transcript = Transcript::new(b"test");
    let (proof, committed_value) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &values,
        &blindings,
        64,
    )
    .unwrap();

    let mut verifier_transcript = Transcript::new(b"test");
    let start = Instant::now();
    assert!(proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &committed_value,
            64,
        )
        .is_ok());
    println!(
        "multiple verify of {} range bulletproofs takes time: {} s",
        count,
        start.elapsed().as_secs_f32() / count as f32
    );
}

fn bench_batch_verify_range(count: usize) {
    let mut prng = test_rng();
    let bp_gens = BulletproofGens::new(64, 16);
    let pc_gens = PedersenGens::default();
    let mut proofs = vec![];
    let mut committed_values = vec![];
    let mut verifier_transcripts = vec![];

    for _ in 0..count {
        let mut values = vec![];
        let mut blindings = vec![];

        for _ in 0..4 {
            let value = prng.gen_range(1u64..1000);
            let blinding = RistrettoScalar::random(&mut prng).0;
            values.push(value);
            blindings.push(blinding);
        }

        let mut prover_transcript = Transcript::new(b"test");
        let (proof, committed_value) = RangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            &values,
            &blindings,
            64,
        )
        .unwrap();

        proofs.push(proof);
        committed_values.push(committed_value);

        let verifier_transcript = Transcript::new(b"test");
        verifier_transcripts.push(verifier_transcript);
    }

    let mut committed_values_ref = vec![];
    for i in &committed_values {
        committed_values_ref.push(i.as_slice())
    }

    let start = Instant::now();
    assert!(RangeProof::batch_verify(
        &mut prng,
        &proofs.iter().map(|x| x).collect::<Vec<&RangeProof>>(),
        &mut verifier_transcripts,
        &committed_values_ref,
        &bp_gens,
        &pc_gens,
        64,
    )
    .is_ok());
    println!(
        "batch verify of {} range bulletproofs takes time: {} s",
        count,
        start.elapsed().as_secs_f32() / (count * 4) as f32
    );
}

fn create_asset_mixer_proof() -> (R1CSProof, Vec<MixCommitment>, Vec<MixCommitment>) {
    let (inputs, outputs) = gen_inputs_outputs();
    let mut in_mix_value = vec![];
    let mut out_mix_value = vec![];
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"test");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let in_com_and_vars: Vec<(MixCommitment, MixVariable)> = inputs
        .iter()
        .map(|(amount, typ, blind_a, blind_typ)| {
            let (amount_com, amount_var) =
                prover.commit(RistrettoScalar::from(*amount).0, blind_a.0);
            let (asset_type_com, asset_type_var) = prover.commit(typ.0, blind_typ.0);
            let mix_value = MixValue {
                amount: RistrettoScalar::from(*amount),
                asset_type: *typ,
            };
            in_mix_value.push(mix_value);

            (
                MixCommitment {
                    amount: CompressedRistretto(amount_com),
                    asset_type: CompressedRistretto(asset_type_com),
                },
                MixVariable {
                    amount: amount_var,
                    asset_type: asset_type_var,
                },
            )
        })
        .collect();
    let input_coms = in_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
    let input_vars = in_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

    let out_com_and_vars: Vec<(MixCommitment, MixVariable)> = outputs
        .iter()
        .map(|(amount, typ, blind_a, blind_typ)| {
            let (amount_com, amount_var) =
                prover.commit(RistrettoScalar::from(*amount).0, blind_a.0);
            let (asset_type_com, asset_type_var) = prover.commit(typ.0, blind_typ.0);
            let mix_value = MixValue {
                amount: RistrettoScalar::from(*amount),
                asset_type: *typ,
            };
            out_mix_value.push(mix_value);
            (
                MixCommitment {
                    amount: CompressedRistretto(amount_com),
                    asset_type: CompressedRistretto(asset_type_com),
                },
                MixVariable {
                    amount: amount_var,
                    asset_type: asset_type_var,
                },
            )
        })
        .collect();
    let output_coms = out_com_and_vars.iter().map(|(com, _)| *com).collect_vec();
    let output_vars = out_com_and_vars.iter().map(|(_, var)| *var).collect_vec();

    let n_gates = mix::mix(
        &mut prover,
        &input_vars,
        Some(&in_mix_value),
        &output_vars,
        Some(&out_mix_value),
    )
    .unwrap();

    let bp_circuit_gens = BulletproofGens::new(1024, 1);
    assert!(n_gates <= bp_circuit_gens.gens_capacity);

    let proof = prover.prove(&bp_circuit_gens).unwrap();
    (proof, input_coms, output_coms)
}

fn gen_inputs_outputs() -> (
    Vec<(u64, RistrettoScalar, RistrettoScalar, RistrettoScalar)>,
    Vec<(u64, RistrettoScalar, RistrettoScalar, RistrettoScalar)>,
) {
    let num = 5;
    let mut prng = test_rng();
    let mut inputs = vec![];
    let mut outputs = vec![];

    for _ in 0..num {
        let amount = prng.gen_range(1u64..100);
        inputs.push((
            amount,
            RistrettoScalar::from(amount % 3),
            RistrettoScalar::random(&mut prng),
            RistrettoScalar::random(&mut prng),
        ));
        outputs.push((
            amount,
            RistrettoScalar::from(amount % 3),
            RistrettoScalar::random(&mut prng),
            RistrettoScalar::random(&mut prng),
        ));
    }

    (inputs, outputs)
}

fn prepare_asset_mixer_verifier(
    verifier: &mut Verifier<&mut Transcript>,
    instance: &AssetMixingInstance<'_>,
) -> Result<usize> {
    let in_cloak = instance
        .inputs
        .iter()
        .map(|(amount, asset_type)| MixCommitment {
            amount: *amount,
            asset_type: *asset_type,
        })
        .collect_vec();

    let out_cloak = instance
        .outputs
        .iter()
        .map(|(amount, asset_type)| MixCommitment {
            amount: *amount,
            asset_type: *asset_type,
        })
        .collect_vec();

    let in_vars = in_cloak
        .iter()
        .map(|com| com.commit_verifier(verifier))
        .collect_vec();
    let out_vars = out_cloak
        .iter()
        .map(|com| com.commit_verifier(verifier))
        .collect_vec();

    mix::mix(verifier, &in_vars, None, &out_vars, None).c(d!(ZeiError::AssetMixerVerificationError))
}

fn asset_mix_num_generators(n_input: usize, n_output: usize) -> usize {
    let max = std::cmp::max(n_input, n_output);
    let min = std::cmp::min(n_input, n_output);

    let input_wires = n_input + n_output;
    let pad = max - min;
    let shuffle_input = 3 * n_input - 2;
    let shuffle_output = 3 * n_output - 2;
    let shuffle_mid = 3 * max - 2;
    let merge_input_mid_wires = n_input - 2;
    let merge_output_mid_wires = n_output - 2;
    let merge_input = 2 * n_input - 1;
    let merge_output = 2 * n_output - 1;
    let range_proof = 64 * n_output;

    input_wires
        + pad
        + merge_input_mid_wires
        + merge_output_mid_wires
        + shuffle_input
        + shuffle_output
        + shuffle_mid
        + range_proof
        + merge_input
        + merge_output
}
