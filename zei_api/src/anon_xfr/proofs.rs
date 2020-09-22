use crate::anon_xfr::circuits::{build_single_spend_cs, AXfrPubInputs, AXfrWitness};
use crate::setup::{NodeParams, UserParams};
use merlin::Transcript;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::plonk_setup::{ProverParams, VerifierParams};
use poly_iops::plonk::protocol::prover::{prover, verifier, PlonkPf};
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

const SINGLE_SPEND_TRANSCRIPT: &[u8] = b"AnonXfr Single Spend";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;
pub(crate) type AXfrProverParams = ProverParams<KZGCommitmentSchemeBLS>;
pub(crate) type AXfrVerifierParams = VerifierParams<KZGCommitmentSchemeBLS>;

/// I generates the plonk proof for a single-input/output anonymous transaction.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `secret_input` - input to generate witness of the constraint system
pub(crate) fn prove_single_spend<R: CryptoRng + RngCore>(rng: &mut R,
                                                         params: &UserParams,
                                                         secret_input: AXfrWitness)
                                                         -> Result<AXfrPlonkPf, ZeiError> {
  let mut cs = build_single_spend_cs(secret_input);
  let witness = cs.get_and_clear_witness();
  let mut transcript = Transcript::new(SINGLE_SPEND_TRANSCRIPT);
  let zkproof = prover(rng,
                       &mut transcript,
                       &params.pcs,
                       &params.cs,
                       &params.prover_params,
                       &witness).map_err(|_| ZeiError::AXfrProofError)?;
  Ok(zkproof)
}

/// I verify the plonk proof for a single-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and single spend constrain system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_single_spend(params: &NodeParams,
                                  pub_inputs: &AXfrPubInputs,
                                  proof: &AXfrPlonkPf)
                                  -> Result<(), ZeiError> {
  let mut transcript = Transcript::new(SINGLE_SPEND_TRANSCRIPT);
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
  use crate::anon_xfr::circuits::tests::gen_secret_pub_inputs;
  use crate::anon_xfr::proofs::{prove_single_spend, verify_single_spend};
  use crate::anon_xfr::structs::AXfrSecKey;
  use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
  use algebra::groups::{One, Scalar};
  use algebra::jubjub::JubjubScalar;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_anon_xfr_proof() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    // build cs
    let sec_key_in = AXfrSecKey(JubjubScalar::random(&mut prng));
    let (secret_inputs, pub_inputs) = gen_secret_pub_inputs(&sec_key_in).unwrap();
    let params = UserParams::from_file_if_exists(1, 4100, DEFAULT_BP_NUM_GENS, None).unwrap();
    let proof = prove_single_spend(&mut prng, &params, secret_inputs).unwrap();

    // A bad proof should fail the verification
    let bad_sk = AXfrSecKey(JubjubScalar::one());
    let (bad_secret_inputs, _) = gen_secret_pub_inputs(&bad_sk).unwrap();
    let bad_proof = prove_single_spend(&mut prng, &params, bad_secret_inputs).unwrap();

    // verify good witness
    let node_params = NodeParams::from(params);
    assert!(verify_single_spend(&node_params, &pub_inputs, &proof).is_ok());

    // verify bar witness
    assert!(verify_single_spend(&node_params, &pub_inputs, &bad_proof).is_err());
  }
}
