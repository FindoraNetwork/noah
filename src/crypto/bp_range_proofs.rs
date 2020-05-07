use crate::errors::ZeiError;
use crate::setup::PublicParams;
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Gives a bulletproof range proof that values committed using  `blindings`
/// are within [0..2^{`log_range_upper_bound`}-1].
pub fn prove_ranges(params: &PublicParams,
                    transcript: &mut Transcript,
                    values: &[u64],
                    blindings: &[Scalar],
                    log_range_upper_bound: usize)
                    -> Result<(RangeProof, Vec<CompressedRistretto>), ZeiError> {
  RangeProof::prove_multiple(&params.bp_gens,
                             &params.pc_gens,
                             transcript,
                             values,
                             blindings,
                             log_range_upper_bound).map_err(|_| ZeiError::RangeProofProveError)
}

/// Verify a bulletproof range proof that a set of committed values
/// are within [0..2^{`log_range_upper_bound`}-1].
/// State of transcript should match the state just before the proof was computed
pub fn verify_ranges<R: CryptoRng + RngCore>(prng: &mut R,
                                             params: &PublicParams,
                                             proof: &RangeProof,
                                             transcript: &mut Transcript,
                                             commitments: &[CompressedRistretto],
                                             log_range_upper_bound: usize)
                                             -> Result<(), ZeiError> {
  proof.verify_multiple_with_rng(&params.bp_gens,
                                 &params.pc_gens,
                                 transcript,
                                 commitments,
                                 log_range_upper_bound,
                                 prng)
       .map_err(|_| ZeiError::RangeProofVerifyError)
}

/// Batch verify a set bulletproof range proofs
/// State of transcripts should match the state just before each proof was computed
pub fn batch_verify_ranges<R: CryptoRng + RngCore>(prng: &mut R,
                                                   params: &PublicParams,
                                                   proofs: &[&RangeProof],
                                                   transcripts: &mut [Transcript],
                                                   commitments: &[&[CompressedRistretto]],
                                                   log_range_upper_bound: usize)
                                                   -> Result<(), ZeiError> {
  RangeProof::batch_verify(prng,
                           proofs,
                           transcripts,
                           commitments,
                           &params.bp_gens,
                           &params.pc_gens,
                           log_range_upper_bound).map_err(|_| ZeiError::RangeProofVerifyError)
}
