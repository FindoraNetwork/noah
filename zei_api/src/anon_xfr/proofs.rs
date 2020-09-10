use crate::anon_xfr::circuits::{AXfrPubInputs, TurboPlonkCS};
use algebra::bls12_381::BLSScalar;
use merlin::Transcript;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::plonk_setup::{
  preprocess_prover, preprocess_verifier, ProverParams, VerifierParams,
};
use poly_iops::plonk::protocol::prover::{prover, verifier, PlonkPf};
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

const COMMON_SEED: [u8; 32] = [0u8; 32];
const SINGLE_SPEND_TRANSCRIPT: &[u8] = b"AnonXfr Single Spend";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;
pub(crate) type AXfrProverParams = ProverParams<KZGCommitmentSchemeBLS>;
pub(crate) type AXfrVerifierParams = VerifierParams<KZGCommitmentSchemeBLS>;

/// An anonymous transfer prover.
/// * `cs_params` - the preprocessed prover parameters for the plonk proof
pub(crate) struct AXfrProver {
  pub cs_params: Option<AXfrProverParams>,
}

impl AXfrProver {
  pub fn new() -> Self {
    Self { cs_params: None }
  }

  /// I clear the preprocessed parameters
  pub fn reset_params(&mut self) {
    self.cs_params = None;
  }

  /// I generates the plonk proof for a single-input/output anonymous transaction.
  /// * `rng` - pseudo-random generator.
  /// * `pcs` - the KZG polynomial commitment scheme.
  /// * `cs` - the constraint system
  /// * `witness` - witness of the constraint system
  /// Before calling `prove_single_spend()`, `witness` was obtained from `cs.get_and_clear_witness()`
  pub fn prove_single_spend<R: CryptoRng + RngCore>(&mut self,
                                                    rng: &mut R,
                                                    pcs: &KZGCommitmentSchemeBLS,
                                                    cs: &TurboPlonkCS,
                                                    witness: &[BLSScalar])
                                                    -> Result<AXfrPlonkPf, ZeiError> {
    if self.cs_params.is_none() {
      self.cs_params =
        Some(preprocess_prover(cs, pcs, COMMON_SEED).map_err(|_| ZeiError::AXfrProverParamsError)?);
    }
    let mut transcript = Transcript::new(SINGLE_SPEND_TRANSCRIPT);
    let zkproof = prover(rng,
                         &mut transcript,
                         pcs,
                         cs,
                         self.cs_params.as_ref().unwrap(), // safe unwrap
                         witness).map_err(|_| ZeiError::AXfrProofError)?;
    Ok(zkproof)
  }
}

/// An anonymous transfer verifier.
/// * `cs_params` - the preprocessed verifier parameters for the plonk proof
pub(crate) struct AXfrVerifier {
  pub cs_params: Option<AXfrVerifierParams>,
}

impl AXfrVerifier {
  pub fn new() -> Self {
    Self { cs_params: None }
  }

  /// I clear the preprocessed parameters
  pub fn reset_params(&mut self) {
    self.cs_params = None;
  }

  /// I verify the plonk proof for a single-input/output anonymous transaction.
  /// * `pcs` - the KZG polynomial commitment scheme.
  /// * `cs` - the constraint system.
  /// * `pub_inputs` - the public inputs of the transaction.
  /// * `proof` - the proof
  pub fn verify_single_spend(&mut self,
                             pcs: &KZGCommitmentSchemeBLS,
                             cs: &TurboPlonkCS,
                             pub_inputs: &AXfrPubInputs,
                             proof: &AXfrPlonkPf)
                             -> Result<(), ZeiError> {
    if self.cs_params.is_none() {
      self.cs_params =
        Some(preprocess_verifier(pcs, cs, COMMON_SEED).map_err(|_| {
                                                        ZeiError::AXfrVerifierParamsError
                                                      })?);
    }
    let mut transcript = Transcript::new(SINGLE_SPEND_TRANSCRIPT);
    let online_inputs = pub_inputs.to_vec();
    verifier(&mut transcript,
             pcs,
             cs,
             self.cs_params.as_ref().unwrap(), // safe unwrap
             &online_inputs,
             proof).map_err(|_| ZeiError::ZKProofVerificationError)
  }
}

#[cfg(test)]
mod tests {
  use super::{AXfrProver, AXfrVerifier};
  use crate::anon_xfr::circuits::build_single_spend_cs;
  use crate::anon_xfr::circuits::tests::gen_secret_pub_inputs;
  use crate::anon_xfr::structs::AXfrSecKey;
  use algebra::groups::{One, Scalar};
  use algebra::jubjub::JubjubScalar;
  use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_anon_xfr_proof() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    // build cs
    let sec_key_in = AXfrSecKey(JubjubScalar::random(&mut prng));
    let (secret_inputs, pub_inputs) = gen_secret_pub_inputs(&sec_key_in).unwrap();
    let mut cs = build_single_spend_cs(secret_inputs);

    // build kzg pcs
    let pcs = KZGCommitmentSchemeBLS::new(4100, &mut prng);

    // build proof
    let witness = cs.get_and_clear_witness();
    let mut prover = AXfrProver::new();
    let proof = prover.prove_single_spend(&mut prng, &pcs, &cs, &witness)
                      .unwrap();

    // verify proof
    let mut verifier = AXfrVerifier::new();
    assert!(verifier.verify_single_spend(&pcs, &cs, &pub_inputs, &proof)
                    .is_ok());

    // A bad proof should fail the verification
    let bad_sk = AXfrSecKey(JubjubScalar::one());
    let (bad_secret_inputs, _) = gen_secret_pub_inputs(&bad_sk).unwrap();
    let mut new_cs = build_single_spend_cs(bad_secret_inputs);
    let bad_witness = new_cs.get_and_clear_witness();
    let bad_proof = prover.prove_single_spend(&mut prng, &pcs, &cs, &bad_witness)
                          .unwrap();
    assert!(verifier.verify_single_spend(&pcs, &cs, &pub_inputs, &bad_proof)
                    .is_err());
  }
}
