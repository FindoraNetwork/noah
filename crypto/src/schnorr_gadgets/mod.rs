use crate::errors::Result;
use merlin::Transcript;
use noah_algebra::prelude::*;
use noah_algebra::traits::CurveGroup;

mod gadget1_square;
pub use gadget1_square::*;

mod gadget2_crossed_mul;
pub use gadget2_crossed_mul::*;

mod gadget3_move;
pub use gadget3_move::*;

mod gadget4_merged;
pub use gadget4_merged::*;

/// A trait for Schnorr gadgets.
pub trait SchnorrGadget<G: CurveGroup> {
    /// The struct of the proof.
    type Proof: Default + Clone;
    /// The struct of the instance.
    type Instance;
    /// The struct of the witness.
    type Witness;

    /// Generate the Schnorr proof.
    fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        transcript: &mut Transcript,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Proof;

    /// Verify the Schnorr proof.
    fn verify(
        transcript: &mut Transcript,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> Result<()>;
}
