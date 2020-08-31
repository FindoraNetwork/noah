use crate::ristretto_pedersen::RistrettoPedersenGens;
use algebra::ristretto::CompressedRistretto;
use algebra::ristretto::RistrettoScalar as Scalar;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use itertools::Itertools;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

/// Gives a bulletproof range proof that values committed using  `blindings`
/// are within [0..2^{`log_range_upper_bound`}-1].
pub fn prove_ranges(bp_gens: &BulletproofGens,
                    pc_gens: &RistrettoPedersenGens,
                    transcript: &mut Transcript,
                    values: &[u64],
                    blindings: &[Scalar],
                    log_range_upper_bound: usize)
                    -> Result<(RangeProof, Vec<CompressedRistretto>), ZeiError> {
  let blindings = blindings.iter().map(|s| s.0).collect_vec();
  let pc_gens = pc_gens.into();
  let (proof, coms) =
    RangeProof::prove_multiple(bp_gens,
                               &pc_gens,
                               transcript,
                               values,
                               &blindings,
                               log_range_upper_bound).map_err(|_| ZeiError::RangeProofProveError)?;
  let commitments = coms.iter().map(|x| CompressedRistretto(*x)).collect_vec();
  Ok((proof, commitments))
}

/// Verify a bulletproof range proof that a set of committed values
/// are within [0..2^{`log_range_upper_bound`}-1].
/// State of transcript should match the state just before the proof was computed
pub fn verify_ranges<R: CryptoRng + RngCore>(prng: &mut R,
                                             bp_gens: &BulletproofGens,
                                             pc_gens: &PedersenGens,
                                             proof: &RangeProof,
                                             transcript: &mut Transcript,
                                             commitments: &[CompressedRistretto],
                                             log_range_upper_bound: usize)
                                             -> Result<(), ZeiError> {
  let commitments = commitments.iter().map(|x| x.0).collect_vec();
  proof.verify_multiple_with_rng(bp_gens,
                                 pc_gens,
                                 transcript,
                                 &commitments,
                                 log_range_upper_bound,
                                 prng)
       .map_err(|_| ZeiError::RangeProofVerifyError)
}

/// Batch verify a set bulletproof range proofs
/// State of transcripts should match the state just before each proof was computed
pub fn batch_verify_ranges<R: CryptoRng + RngCore>(prng: &mut R,
                                                   bp_gens: &BulletproofGens,
                                                   pc_gens: &RistrettoPedersenGens,
                                                   proofs: &[&RangeProof],
                                                   transcripts: &mut [Transcript],
                                                   commitments: &[&[CompressedRistretto]],
                                                   log_range_upper_bound: usize)
                                                   -> Result<(), ZeiError> {
  let mut comms = vec![];
  for slice in commitments {
    let v = slice.iter().map(|x| x.0).collect_vec();
    comms.push(v);
  }
  let mut slices: Vec<&[curve25519_dalek::ristretto::CompressedRistretto]> = vec![];
  for v in comms.iter() {
    slices.push(v.as_slice());
  }

  let pc_gens = pc_gens.into();
  RangeProof::batch_verify(prng,
                           proofs,
                           transcripts,
                           slices.as_slice(),
                           bp_gens,
                           &pc_gens,
                           log_range_upper_bound).map_err(|_| ZeiError::RangeProofVerifyError)
}
