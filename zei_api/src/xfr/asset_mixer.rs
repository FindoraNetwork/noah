use crate::setup::PublicParams;
use algebra::groups::Scalar as _;
use algebra::ristretto::{CompressedRistretto, RistrettoScalar as Scalar};
use bulletproofs::r1cs::{batch_verify, Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use crypto::bp_circuits::cloak::{cloak, CloakCommitment, CloakValue};
use itertools::Itertools;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;
use utils::serialization::zei_obj_serde;
use wasm_bindgen::__rt::std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMixProof(#[serde(with = "zei_obj_serde")] pub(crate) R1CSProof);

impl PartialEq for AssetMixProof {
  fn eq(&self, other: &AssetMixProof) -> bool {
    self.0.to_bytes() == other.0.to_bytes()
  }
}

impl Eq for AssetMixProof {}

/// I compute a proof that the assets were mixed correctly
/// # Example
/// ```
/// use algebra::ristretto::RistrettoScalar;
/// use zei::xfr::asset_mixer::prove_asset_mixing;
/// use algebra::groups::Scalar;
/// let input = [
///            (60u64, RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(10000), RistrettoScalar::from_u32(200000)),
///            (100u64, RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(10001), RistrettoScalar::from_u32(200001)),
///            (10u64, RistrettoScalar::from_u32(1), RistrettoScalar::from_u32(10002), RistrettoScalar::from_u32(200002)),
///            (50u64, RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(10003), RistrettoScalar::from_u32(200003)),
///            ];
/// let output = [
///            (40u64, RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(10004), RistrettoScalar::from_u32(200004)),
///            (9u64, RistrettoScalar::from_u32(1), RistrettoScalar::from_u32(10005), RistrettoScalar::from_u32(200005)),
///            (1u64, RistrettoScalar::from_u32(1), RistrettoScalar::from_u32(10006), RistrettoScalar::from_u32(200006)),
///            (80u64, RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(10007), RistrettoScalar::from_u32(200007)),
///            (50u64, RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(10008), RistrettoScalar::from_u32(200008)),
///            (10u64, RistrettoScalar::from_u32(0), RistrettoScalar::from_u32(10009), RistrettoScalar::from_u32(200009)),
///            (30u64, RistrettoScalar::from_u32(2), RistrettoScalar::from_u32(10010), RistrettoScalar::from_u32(200010)),
///        ];
///
/// let proof = prove_asset_mixing(&input, &output).unwrap();
///
/// ```
pub fn prove_asset_mixing(inputs: &[(u64, Scalar, Scalar, Scalar)],
                          outputs: &[(u64, Scalar, Scalar, Scalar)])
                          -> Result<AssetMixProof, ZeiError> {
  let pc_gens = PedersenGens::default();
  let mut prover_transcript = Transcript::new(b"AssetMixingProof");
  let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
  fn extract_values_and_blinds(list: &[(u64, Scalar, Scalar, Scalar)])
                               -> (Vec<CloakValue>, Vec<CloakValue>) {
    let values =
      list.iter()
          .map(|(amount, asset_type, _, _)| CloakValue { amount: Scalar::from_u64(*amount),
                                                         asset_type: *asset_type })
          .collect();
    let blinds =
      list.iter()
          .map(|(_, _, blind_amount, blind_asset_type)| CloakValue { amount: *blind_amount,
                                                                     asset_type:
                                                                       *blind_asset_type })
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
    return Err(ZeiError::ParameterError);
  }

  let in_vars = in_values.iter()
                         .zip(in_blinds.iter())
                         .map(|(v, b)| v.commit_prover(&mut prover, b).1)
                         .collect_vec();
  let out_vars = out_values.iter()
                           .zip(out_blinds.iter())
                           .map(|(v, b)| v.commit_prover(&mut prover, b).1)
                           .collect_vec();
  let n = in_vars.len();
  let m = out_vars.len();

  cloak(&mut prover,
        &in_vars,
        Some(&in_values),
        &out_vars,
        Some(&out_values)).map_err(|_| ZeiError::AssetMixerVerificationError)?;

  let num_gates = asset_mix_num_generators(n, m);
  let bp_gens = BulletproofGens::new(num_gates.next_power_of_two(), 1);
  let proof = prover.prove(&bp_gens)
                    .map_err(|_| ZeiError::AssetMixerVerificationError)?;
  Ok(AssetMixProof(proof))
}

pub struct AssetMixingInstance<'a> {
  pub inputs: Vec<(CompressedRistretto, CompressedRistretto)>,
  pub outputs: Vec<(CompressedRistretto, CompressedRistretto)>,
  pub proof: &'a AssetMixProof,
}

/// I verify that the assets were mixed correctly
/// # Example
/// ```
/// use algebra::ristretto::{RistrettoScalar, CompressedRistretto};
/// use algebra::groups::Scalar;
/// use zei::xfr::asset_mixer::{prove_asset_mixing, AssetMixingInstance, batch_verify_asset_mixing};
/// use bulletproofs::PedersenGens;
/// use rand::thread_rng;
/// use zei::setup::PublicParams;
/// use crypto::ristretto_pedersen::RistrettoPedersenGens;
/// let input = [
///            (60u64, RistrettoScalar::from_u64(0), RistrettoScalar::from_u64(10000), RistrettoScalar::from_u64(200000)),
///            (100u64, RistrettoScalar::from_u64(2), RistrettoScalar::from_u64(10001), RistrettoScalar::from_u64(200001)),
///            (10u64, RistrettoScalar::from_u64(1), RistrettoScalar::from_u64(10002), RistrettoScalar::from_u64(200002)),
///            (50u64, RistrettoScalar::from_u64(2), RistrettoScalar::from_u64(10003), RistrettoScalar::from_u64(200003)),
///            ];
/// let output = [
///            (40u64, RistrettoScalar::from_u64(2), RistrettoScalar::from_u64(10004), RistrettoScalar::from_u64(200004)),
///            (9u64, RistrettoScalar::from_u64(1), RistrettoScalar::from_u64(10005), RistrettoScalar::from_u64(200005)),
///            (1u64, RistrettoScalar::from_u64(1), RistrettoScalar::from_u64(10006), RistrettoScalar::from_u64(200006)),
///            (80u64, RistrettoScalar::from_u64(2), RistrettoScalar::from_u64(10007), RistrettoScalar::from_u64(200007)),
///            (50u64, RistrettoScalar::from_u64(0), RistrettoScalar::from_u64(10008), RistrettoScalar::from_u64(200008)),
///            (10u64, RistrettoScalar::from_u64(0), RistrettoScalar::from_u64(10009), RistrettoScalar::from_u64(200009)),
///            (30u64, RistrettoScalar::from_u64(2), RistrettoScalar::from_u64(10010), RistrettoScalar::from_u64(200010)),
///        ];
///
/// let proof = prove_asset_mixing(&input, &output).unwrap();
/// let pc_gens = RistrettoPedersenGens::default();
/// let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
///      input.iter()
///           .map(|(amount, typ, blind_a, blind_typ)| {
///             (pc_gens.commit(RistrettoScalar::from_u64(*amount), *blind_a).compress(),
///              pc_gens.commit(*typ, *blind_typ).compress())
///           })
///           .collect();
///    let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
///      output.iter()
///            .map(|(amount, typ, blind_a, blind_typ)| {
///              (pc_gens.commit(RistrettoScalar::from_u64(*amount), *blind_a).compress(),
///               pc_gens.commit(*typ, *blind_typ).compress())
///            })
///            .collect();
///    let instance = AssetMixingInstance{
///        inputs: input_coms,
///        outputs: output_coms,
///        proof: &proof
///    };
///    let mut prng = thread_rng();
///    let mut params = PublicParams::new();
///    assert_eq!(Ok(()),
///               batch_verify_asset_mixing(&mut prng, &mut params, &[instance]));
/// ```
pub fn batch_verify_asset_mixing<R: CryptoRng + RngCore>(prng: &mut R,
                                                         params: &mut PublicParams,
                                                         instances: &[AssetMixingInstance])
                                                         -> Result<(), ZeiError> {
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
    // info(format!("Zei: Increasing bulletproofs gens {} before batch verify asset mixing proofs", max_circuit_size));
    params.increase_circuit_gens(max_circuit_size);
    // info!("Zei: Bulletproof gens increased");
  }
  let pc_gens = (&params.pc_gens).into();
  batch_verify(prng, verifiers, &pc_gens, &params.bp_circuit_gens).map_err(|_| {
                                                            ZeiError::AssetMixerVerificationError
                                                          })
}

pub(crate) fn prepare_asset_mixer_verifier(verifier: &mut Verifier<&mut Transcript>,
                                           instance: &AssetMixingInstance)
                                           -> Result<usize, ZeiError> {
  let in_cloak = instance.inputs
                         .iter()
                         .map(|(amount, asset_type)| CloakCommitment { amount: *amount,
                                                                       asset_type: *asset_type })
                         .collect_vec();

  let out_cloak = instance.outputs
                          .iter()
                          .map(|(amount, asset_type)| CloakCommitment { amount: *amount,
                                                                        asset_type: *asset_type })
                          .collect_vec();

  let in_vars = in_cloak.iter()
                        .map(|com| com.commit_verifier(verifier))
                        .collect_vec();
  let out_vars = out_cloak.iter()
                          .map(|com| com.commit_verifier(verifier))
                          .collect_vec();

  crypto::bp_circuits::cloak::cloak(
    verifier,
    &in_vars,
    None,
    &out_vars,
    None).map_err(|_| ZeiError::AssetMixerVerificationError)
}

fn asset_mix_num_generators(n_input: usize, n_output: usize) -> usize {
  let max = std::cmp::max(n_input, n_output);
  let min = std::cmp::min(n_input, n_output);

  let input_wires = n_input + n_output;
  let pad = max - min; // extra wires needed for padding merged input or merged output length
  let shuffle_input = 3 * n_input - 2; // n_input to bind amount and asset to same variable (2*n_inputs-2)  mult gates
  let shuffle_output = 3 * n_output - 2; // n_outputs to bind amount and asset to same variable (2*n_outputs-2)  mult gates
  let shuffle_mid = 3 * max - 2; // max to bind amount and asset to same variable (2*max-2)  mult gates
  let merge_input_mid_wires = n_input - 2; // merge require n_input - 2 additional wires
  let merge_output_mid_wires = n_output - 2; // merge require n_input - 2 additional wires
  let merge_input = 2 * n_input - 1; // n_input additional wires n_input - 1 mult gates // TODO (fernando) why do we need additional wires here
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
  use crate::setup::PublicParams;
  use crate::xfr::asset_mixer::AssetMixingInstance;
  use algebra::groups::Scalar;
  use algebra::ristretto::{CompressedRistretto, RistrettoScalar};
  use crypto::ristretto_pedersen::RistrettoPedersenGens;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_asset_mixer() {
    let pc_gens = RistrettoPedersenGens::default();

    // asset type set to not match errors
    let input = [(60u64,
                  RistrettoScalar::from_u64(0),
                  RistrettoScalar::from_u64(10000),
                  RistrettoScalar::from_u64(200000)),
                 (100u64,
                  RistrettoScalar::from_u64(2),
                  RistrettoScalar::from_u64(10001),
                  RistrettoScalar::from_u64(200001))];
    let output = [(40u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10004),
                   RistrettoScalar::from_u64(200004)),
                  (10u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10004),
                   RistrettoScalar::from_u64(200004))];
    let proof_result = super::prove_asset_mixing(&input, &output);
    assert!(proof_result.is_err());

    let output = [(40u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10004),
                   RistrettoScalar::from_u64(200004))];
    let proof_result = super::prove_asset_mixing(&input, &output);
    assert!(proof_result.is_err());

    let input = [(60u64,
                  RistrettoScalar::from_u64(0),
                  RistrettoScalar::from_u64(10000),
                  RistrettoScalar::from_u64(200000)),
                 (100u64,
                  RistrettoScalar::from_u64(2),
                  RistrettoScalar::from_u64(10001),
                  RistrettoScalar::from_u64(200001)),
                 (10u64,
                  RistrettoScalar::from_u64(1),
                  RistrettoScalar::from_u64(10002),
                  RistrettoScalar::from_u64(200002)),
                 (50u64,
                  RistrettoScalar::from_u64(2),
                  RistrettoScalar::from_u64(10003),
                  RistrettoScalar::from_u64(200003))];
    let output = [(40u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10004),
                   RistrettoScalar::from_u64(200004)),
                  (9u64,
                   RistrettoScalar::from_u64(1),
                   RistrettoScalar::from_u64(10005),
                   RistrettoScalar::from_u64(200005)),
                  (1u64,
                   RistrettoScalar::from_u64(1),
                   RistrettoScalar::from_u64(10006),
                   RistrettoScalar::from_u64(200006)),
                  (80u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10007),
                   RistrettoScalar::from_u64(200007)),
                  (50u64,
                   RistrettoScalar::from_u64(0),
                   RistrettoScalar::from_u64(10008),
                   RistrettoScalar::from_u64(200008)),
                  (10u64,
                   RistrettoScalar::from_u64(0),
                   RistrettoScalar::from_u64(10009),
                   RistrettoScalar::from_u64(200009)),
                  (30u64,
                   RistrettoScalar::from_u64(2),
                   RistrettoScalar::from_u64(10010),
                   RistrettoScalar::from_u64(200010))];

    let proof = super::prove_asset_mixing(&input, &output).unwrap();

    let input_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
      input.iter()
           .map(|(amount, typ, blind_a, blind_typ)| {
             (pc_gens.commit(RistrettoScalar::from_u64(*amount), *blind_a)
                     .compress(),
              pc_gens.commit(*typ, *blind_typ).compress())
           })
           .collect();
    let output_coms: Vec<(CompressedRistretto, CompressedRistretto)> =
      output.iter()
            .map(|(amount, typ, blind_a, blind_typ)| {
              (pc_gens.commit(RistrettoScalar::from_u64(*amount), *blind_a)
                      .compress(),
               pc_gens.commit(*typ, *blind_typ).compress())
            })
            .collect();

    let instance = AssetMixingInstance { inputs: input_coms,
                                         outputs: output_coms,
                                         proof: &proof };
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let mut params = PublicParams::new();
    assert_eq!(Ok(()),
               super::batch_verify_asset_mixing(&mut prng, &mut params, &[instance]));
  }
}
