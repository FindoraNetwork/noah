use crate::anon_xfr::circuits::{build_multi_xfr_cs, AMultiXfrPubInputs, AMultiXfrWitness};
use crate::setup::{NodeParams, UserParams};
use merlin::Transcript;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::protocol::prover::{prover, verifier, PlonkPf};
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

const ANON_XFR_TRANSCRIPT: &[u8] = b"Anon Xfr";
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// I generates the plonk proof for a multi-inputs/outputs anonymous transaction.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `secret_inputs` - input to generate witness of the constraint system
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(rng: &mut R,
                                                params: &UserParams,
                                                secret_inputs: AMultiXfrWitness)
                                                -> Result<AXfrPlonkPf, ZeiError> {
  let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
  transcript.append_u64(N_INPUTS_TRANSCRIPT,
                        secret_inputs.payers_secrets.len() as u64);
  transcript.append_u64(N_OUTPUTS_TRANSCRIPT,
                        secret_inputs.payees_secrets.len() as u64);

  let (mut cs, _) = build_multi_xfr_cs(secret_inputs);
  let witness = cs.get_and_clear_witness();
  let zkproof = prover(rng,
                       &mut transcript,
                       &params.pcs,
                       &params.cs,
                       &params.prover_params,
                       &witness).map_err(|_| ZeiError::AXfrProofError)?;
  Ok(zkproof)
}

/// I verify the plonk proof for a multi-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and the constraint system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_xfr(params: &NodeParams,
                         pub_inputs: &AMultiXfrPubInputs,
                         proof: &AXfrPlonkPf)
                         -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
  transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
  transcript.append_u64(N_OUTPUTS_TRANSCRIPT,
                        pub_inputs.payees_commitments.len() as u64);
  let online_inputs = pub_inputs.to_vec();
  verifier(&mut transcript,
           &params.pcs,
           &params.cs,
           &params.verifier_params,
           &online_inputs,
           proof).map_err(|_| ZeiError::ZKProofVerificationError)
}

#[cfg(test)]
mod tests {
  use crate::anon_xfr::circuits::tests::new_multi_xfr_witness_for_test;
  use crate::anon_xfr::circuits::AMultiXfrPubInputs;
  use crate::anon_xfr::proofs::{prove_xfr, verify_xfr};
  use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::{One, Zero};
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_anon_multi_xfr_proof() {
    // single asset type
    let zero = BLSScalar::zero();
    // (n, m) = (3, 6)
    let inputs = vec![(/*amount=*/ 30, /*asset_type=*/ zero),
                      (20, zero),
                      (10, zero)];
    let outputs = vec![(5, zero),
                       (15, zero),
                       (22, zero),
                       (11, zero),
                       (0, zero),
                       (7, zero)];
    test_anon_xfr_proof(inputs, outputs);

    // (n, m) = (3, 3)
    let inputs = vec![(30, zero), (20, zero), (0, zero)];
    let outputs = vec![(5, zero), (17, zero), (28, zero)];
    test_anon_xfr_proof(outputs, inputs);

    // (n, m) = (1, 2)
    let inputs = vec![(30, zero)];
    let outputs = vec![(13, zero), (17, zero)];
    test_anon_xfr_proof(inputs.to_vec(), outputs.to_vec());
    // (n, m) = (2, 1)
    test_anon_xfr_proof(outputs, inputs);

    // (n, m) = (1, 1)
    let inputs = vec![(10, zero)];
    let outputs = vec![(10, zero)];
    test_anon_xfr_proof(outputs, inputs);

    // multiple asset types
    // (n, m) = (3, 6)
    let one = BLSScalar::one();
    let inputs = vec![(/*amount=*/ 50, /*asset_type=*/ zero),
                      (60, one),
                      (20, zero)];
    let outputs = vec![(19, one),
                       (15, zero),
                       (1, one),
                       (35, zero),
                       (20, zero),
                       (40, one)];
    test_anon_xfr_proof(inputs, outputs);

    // (n, m) = (3, 3)
    let inputs = vec![(23, zero), (20, one), (7, zero)];
    let outputs = vec![(5, one), (30, zero), (15, one)];
    test_anon_xfr_proof(outputs, inputs);
  }

  fn test_anon_xfr_proof(inputs: Vec<(u64, BLSScalar)>, outputs: Vec<(u64, BLSScalar)>) {
    let n_payers = inputs.len();
    let n_payees = outputs.len();
    // build cs
    let secret_inputs =
      new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), [0u8; 32]);
    let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
    let params = UserParams::from_file_if_exists(n_payers,
                                                 n_payees,
                                                 Some(1),
                                                 DEFAULT_BP_NUM_GENS,
                                                 None).unwrap();
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let proof = prove_xfr(&mut prng, &params, secret_inputs).unwrap();

    // A bad proof should fail the verification
    let bad_secret_inputs = new_multi_xfr_witness_for_test(inputs, outputs, [1u8; 32]);
    let bad_proof = prove_xfr(&mut prng, &params, bad_secret_inputs).unwrap();

    // verify good witness
    let node_params = NodeParams::from(params);
    assert!(verify_xfr(&node_params, &pub_inputs, &proof).is_ok());

    // verify bad witness
    assert!(verify_xfr(&node_params, &pub_inputs, &bad_proof).is_err());
  }
}
