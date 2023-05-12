use crate::errors::{NoahError, Result};
use crate::parameters::bulletproofs::BulletproofParams;
use crate::parameters::bulletproofs::BulletproofURS;
use bulletproofs::{
    r1cs::{batch_verify, Prover, R1CSProof, Verifier},
    BulletproofGens, PedersenGens,
};
use merlin::Transcript;
use noah_algebra::{
    prelude::*,
    ristretto::{CompressedRistretto, RistrettoScalar},
};
use noah_crypto::bulletproofs::mix::{mix, MixCommitment, MixValue};
use wasm_bindgen::__rt::std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The asset mixing proof.
pub struct AssetMixProof(#[serde(with = "noah_obj_serde")] pub R1CSProof);

impl PartialEq for AssetMixProof {
    fn eq(&self, other: &AssetMixProof) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for AssetMixProof {}

/// Prove asset mixing.
/// # Example
/// ```
/// use noah_algebra::ristretto::RistrettoScalar;
/// use noah::xfr::asset_mixer::prove_asset_mixing;
/// use noah_algebra::prelude::*;
/// let input = [
///            (60u64, RistrettoScalar::zero(), RistrettoScalar::from(10000u32), RistrettoScalar::from(200000u32)),
///            (100u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10001u32), RistrettoScalar::from(200001u32)),
///            (10u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10002u32), RistrettoScalar::from(200002u32)),
///            (50u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10003u32), RistrettoScalar::from(200003u32)),
///            ];
/// let output = [
///            (40u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10004u32), RistrettoScalar::from(200004u32)),
///            (9u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10005u32), RistrettoScalar::from(200005u32)),
///            (1u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10006u32), RistrettoScalar::from(200006u32)),
///            (80u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10007u32), RistrettoScalar::from(200007u32)),
///            (50u64, RistrettoScalar::zero(), RistrettoScalar::from(10008u32), RistrettoScalar::from(200008u32)),
///            (10u64, RistrettoScalar::zero(), RistrettoScalar::from(10009u32), RistrettoScalar::from(200009u32)),
///            (30u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10010u32), RistrettoScalar::from(200010u32)),
///        ];
/// let mut prng = test_rng();
/// let proof = prove_asset_mixing(&mut prng, &input, &output).unwrap();
///
/// ```
pub fn prove_asset_mixing<R: CryptoRng + RngCore>(
    prng: &mut R,
    inputs: &[(u64, RistrettoScalar, RistrettoScalar, RistrettoScalar)],
    outputs: &[(u64, RistrettoScalar, RistrettoScalar, RistrettoScalar)],
) -> Result<AssetMixProof> {
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"AssetMixingProof");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    fn extract_values_and_blinds(
        list: &[(u64, RistrettoScalar, RistrettoScalar, RistrettoScalar)],
    ) -> (Vec<MixValue>, Vec<MixValue>) {
        let values = list
            .iter()
            .map(|(amount, asset_type, _, _)| MixValue {
                amount: RistrettoScalar::from(*amount),
                asset_type: *asset_type,
            })
            .collect();
        let blinds = list
            .iter()
            .map(|(_, _, blind_amount, blind_asset_type)| MixValue {
                amount: *blind_amount,
                asset_type: *blind_asset_type,
            })
            .collect();
        (values, blinds)
    }
    let (in_values, in_blinds) = extract_values_and_blinds(inputs);
    let (out_values, out_blinds) = extract_values_and_blinds(outputs);

    let mut in_set = HashSet::new();
    for in_value in in_values.iter() {
        in_set.insert(in_value.asset_type.0);
    }

    let mut out_set = HashSet::new();
    for out_value in out_values.iter() {
        out_set.insert(out_value.asset_type.0);
    }
    if in_set != out_set {
        return Err(NoahError::ParameterError);
    }

    let in_vars = in_values
        .iter()
        .zip(in_blinds.iter())
        .map(|(v, b)| v.commit_prover(&mut prover, b).1)
        .collect_vec();
    let out_vars = out_values
        .iter()
        .zip(out_blinds.iter())
        .map(|(v, b)| v.commit_prover(&mut prover, b).1)
        .collect_vec();
    let n = in_vars.len();
    let m = out_vars.len();

    mix(
        &mut prover,
        &in_vars,
        Some(&in_values),
        &out_vars,
        Some(&out_values),
    )?;

    let num_gates = asset_mix_num_generators(n, m);
    let bp_gens = BulletproofGens::new(num_gates.next_power_of_two(), 1);
    let proof = prover.prove(prng, &bp_gens)?;
    Ok(AssetMixProof(proof))
}

/// An instance of asset mixing.
pub struct AssetMixingInstance<'a> {
    /// A list of Bulletproofs data commmitments for the inputs.
    pub inputs: Vec<(CompressedRistretto, CompressedRistretto)>,
    /// A list of Bulletproofs data commitments for the outputs.
    pub outputs: Vec<(CompressedRistretto, CompressedRistretto)>,
    /// The asset mixing proof.
    pub proof: &'a AssetMixProof,
}

/// Batch-verify asset mixing.
/// # Example
/// ```
/// use noah_algebra::ristretto::{RistrettoScalar, CompressedRistretto, PedersenCommitmentRistretto};
/// use noah_algebra::prelude::*;
/// use noah::xfr::asset_mixer::{prove_asset_mixing, AssetMixingInstance, batch_verify_asset_mixing};
/// use bulletproofs::PedersenGens;
/// use rand::thread_rng;
/// use noah::parameters::bulletproofs::BulletproofParams;
/// use noah_algebra::traits::PedersenCommitment;
/// let input = [
///            (60u64, RistrettoScalar::from(0u32), RistrettoScalar::from(10000u32), RistrettoScalar::from(200000u32)),
///            (100u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10001u32), RistrettoScalar::from(200001u32)),
///            (10u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10002u32), RistrettoScalar::from(200002u32)),
///            (50u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10003u32), RistrettoScalar::from(200003u32)),
///            ];
/// let output = [
///            (40u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10004u32), RistrettoScalar::from(200004u32)),
///            (9u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10005u32), RistrettoScalar::from(200005u32)),
///            (1u64, RistrettoScalar::from(1u32), RistrettoScalar::from(10006u32), RistrettoScalar::from(200006u32)),
///            (80u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10007u32), RistrettoScalar::from(200007u32)),
///            (50u64, RistrettoScalar::from(0u32), RistrettoScalar::from(10008u32), RistrettoScalar::from(200008u32)),
///            (10u64, RistrettoScalar::from(0u32), RistrettoScalar::from(10009u32), RistrettoScalar::from(200009u32)),
///            (30u64, RistrettoScalar::from(2u32), RistrettoScalar::from(10010u32), RistrettoScalar::from(200010u32)),
///        ];
///
/// let proof = prove_asset_mixing(&mut thread_rng(), &input, &output).unwrap();
/// let pc_gens = PedersenCommitmentRistretto::default();
/// let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
///      input.iter()
///           .map(|(amount, typ, blind_a, blind_typ)| {
///             (pc_gens.commit(RistrettoScalar::from(*amount), *blind_a).compress(),
///              pc_gens.commit(*typ, *blind_typ).compress())
///           })
///           .collect();
///    let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
///      output.iter()
///            .map(|(amount, typ, blind_a, blind_typ)| {
///              (pc_gens.commit(RistrettoScalar::from(*amount), *blind_a).compress(),
///               pc_gens.commit(*typ, *blind_typ).compress())
///            })
///            .collect();
///    let instance = AssetMixingInstance{
///        inputs: input_coms,
///        outputs: output_coms,
///        proof: &proof
///    };
///    let mut prng = thread_rng();
///    let mut params = BulletproofParams::default();
///    batch_verify_asset_mixing(&mut prng, &mut params, &[instance]).unwrap();
/// ```
pub fn batch_verify_asset_mixing<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &mut BulletproofParams,
    instances: &[AssetMixingInstance<'_>],
) -> Result<()> {
    let mut max_circuit_size = 0;
    let mut transcripts = Vec::with_capacity(instances.len());
    let mut verifiers = Vec::with_capacity(instances.len());
    for _ in 0..instances.len() {
        transcripts.push(Transcript::new(b"AssetMixingProof"));
    }
    for (instance, transcript) in instances.iter().zip(transcripts.iter_mut()) {
        let mut verifier = Verifier::new(transcript);
        prepare_asset_mixer_verifier(&mut verifier, instance)?;
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
    Ok(batch_verify(
        prng,
        verifiers,
        &pc_gens,
        &params.bp_circuit_gens,
    )?)
}

pub(crate) fn prepare_asset_mixer_verifier(
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

    Ok(mix(verifier, &in_vars, None, &out_vars, None)?)
}

fn asset_mix_num_generators(n_input: usize, n_output: usize) -> usize {
    let max = core::cmp::max(n_input, n_output);
    let min = core::cmp::min(n_input, n_output);

    let input_wires = n_input + n_output;
    let pad = max - min; // extra wires needed for padding merged input or merged output length
    let shuffle_input = 3 * n_input - 2; // n_input to bind amount and asset to same variable (2*n_inputs-2)  mult gates
    let shuffle_output = 3 * n_output - 2; // n_outputs to bind amount and asset to same variable (2*n_outputs-2)  mult gates
    let shuffle_mid = 3 * max - 2; // max to bind amount and asset to same variable (2*max-2)  mult gates
    let merge_input_mid_wires = n_input - 2; // merge require n_input - 2 additional wires
    let merge_output_mid_wires = n_output - 2; // merge require n_input - 2 additional wires
    let merge_input = 2 * n_input - 1; // n_input additional wires n_input - 1 mult gates
    let merge_output = 2 * n_output - 1; // n_output additional wires n_output - 1 mult gates
    let range_proof = 64 * n_output; // 64 gates per output

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
#[cfg(test)]
mod test {
    use crate::parameters::bulletproofs::BulletproofParams;
    use crate::xfr::asset_mixer::AssetMixingInstance;
    use noah_algebra::{
        prelude::*,
        ristretto::{CompressedRistretto, PedersenCommitmentRistretto, RistrettoScalar},
        traits::PedersenCommitment,
    };

    #[test]
    fn test_asset_mixer() {
        let mut prng = test_rng();
        let pc_gens = PedersenCommitmentRistretto::default();

        // asset type set to not match errors
        let input = [
            (
                60u64,
                RistrettoScalar::from(0u32),
                RistrettoScalar::from(10000u32),
                RistrettoScalar::from(200000u32),
            ),
            (
                100u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10001u32),
                RistrettoScalar::from(200001u32),
            ),
        ];
        let output = [
            (
                40u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10004u32),
                RistrettoScalar::from(200004u32),
            ),
            (
                10u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10004u32),
                RistrettoScalar::from(200004u32),
            ),
        ];
        let proof_result = super::prove_asset_mixing(&mut prng, &input, &output);
        assert!(proof_result.is_err());

        let output = [(
            40u64,
            RistrettoScalar::from(2u32),
            RistrettoScalar::from(10004u32),
            RistrettoScalar::from(200004u32),
        )];
        let proof_result = super::prove_asset_mixing(&mut prng, &input, &output);
        assert!(proof_result.is_err());

        let input = [
            (
                60u64,
                RistrettoScalar::from(0u32),
                RistrettoScalar::from(10000u32),
                RistrettoScalar::from(200000u32),
            ),
            (
                100u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10001u32),
                RistrettoScalar::from(200001u32),
            ),
            (
                10u64,
                RistrettoScalar::from(1u32),
                RistrettoScalar::from(10002u32),
                RistrettoScalar::from(200002u32),
            ),
            (
                50u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10003u32),
                RistrettoScalar::from(200003u32),
            ),
        ];
        let output = [
            (
                40u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10004u32),
                RistrettoScalar::from(200004u32),
            ),
            (
                9u64,
                RistrettoScalar::from(1u32),
                RistrettoScalar::from(10005u32),
                RistrettoScalar::from(200005u32),
            ),
            (
                1u64,
                RistrettoScalar::from(1u32),
                RistrettoScalar::from(10006u32),
                RistrettoScalar::from(200006u32),
            ),
            (
                80u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10007u32),
                RistrettoScalar::from(200007u32),
            ),
            (
                50u64,
                RistrettoScalar::from(0u32),
                RistrettoScalar::from(10008u32),
                RistrettoScalar::from(200008u32),
            ),
            (
                10u64,
                RistrettoScalar::from(0u32),
                RistrettoScalar::from(10009u32),
                RistrettoScalar::from(200009u32),
            ),
            (
                30u64,
                RistrettoScalar::from(2u32),
                RistrettoScalar::from(10010u32),
                RistrettoScalar::from(200010u32),
            ),
        ];

        let proof = super::prove_asset_mixing(&mut prng, &input, &output).unwrap();

        let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> = input
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
        let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> = output
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

        let instance = AssetMixingInstance {
            inputs: input_coms,
            outputs: output_coms,
            proof: &proof,
        };
        let mut params = BulletproofParams::default();
        super::batch_verify_asset_mixing(&mut prng, &mut params, &[instance]).unwrap();
    }
}
