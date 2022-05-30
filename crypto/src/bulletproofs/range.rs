//! Module for the Bulletproof range proof scheme
//!
//! This is mostly a wrapper.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;
use zei_algebra::prelude::*;
use zei_algebra::ristretto::CompressedRistretto;
use zei_algebra::ristretto::RistrettoScalar as Scalar;

/// Generate a Bulletproof range proof that values committed using `blindings`
/// are within [0..2^{`log_range_upper_bound`}-1].
pub fn prove_ranges(
    bp_gens: &BulletproofGens,
    transcript: &mut Transcript,
    values: &[u64],
    blindings: &[Scalar],
    log_range_upper_bound: usize,
) -> Result<(RangeProof, Vec<CompressedRistretto>)> {
    let blindings = blindings.iter().map(|s| s.0).collect_vec();
    let pc_gens = PedersenGens::default();
    let (proof, coms) = RangeProof::prove_multiple(
        bp_gens,
        &pc_gens,
        transcript,
        values,
        &blindings,
        log_range_upper_bound,
    )
    .c(d!(ZeiError::RangeProofProveError))?;
    let commitments = coms.iter().map(|x| CompressedRistretto(*x)).collect_vec();
    Ok((proof, commitments))
}

/// Batch-verify a set bulletproof range proofs
/// State of transcripts should match the state just before each proof was computed
pub fn batch_verify_ranges<R: CryptoRng + RngCore>(
    prng: &mut R,
    bp_gens: &BulletproofGens,
    proofs: &[&RangeProof],
    transcripts: &mut [Transcript],
    commitments: &[&[CompressedRistretto]],
    log_range_upper_bound: usize,
) -> Result<()> {
    let pc_gens = PedersenGens::default();
    let mut comms = vec![];
    for slice in commitments {
        let v = slice.iter().map(|x| x.0).collect_vec();
        comms.push(v);
    }
    let mut slices: Vec<&[curve25519_dalek::ristretto::CompressedRistretto]> = vec![];
    for v in comms.iter() {
        slices.push(v.as_slice());
    }

    RangeProof::batch_verify(
        prng,
        proofs,
        transcripts,
        slices.as_slice(),
        bp_gens,
        &pc_gens,
        log_range_upper_bound,
    )
    .c(d!(ZeiError::RangeProofVerifyError))
}
