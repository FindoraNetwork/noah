use crate::commitments::pcs::{PolyComScheme, ToBytes};
use algebra::groups::Scalar;
use merlin::Transcript;
use rand_core::SeedableRng;

pub trait PolyComTranscript {
    fn append_commitment<C: ToBytes>(&mut self, commitment: &C);
    fn append_field_elem<F: Scalar>(&mut self, point: &F);
    fn append_eval_proof<PCS: PolyComScheme>(&mut self, proof: &PCS::EvalProof);
    fn get_challenge_field_elem<F: Scalar>(&mut self, label: &'static [u8]) -> F;
}

impl PolyComTranscript for Transcript {
    fn append_commitment<C: ToBytes>(&mut self, commitment: &C) {
        self.append_message(b"append commitment", &commitment.to_bytes());
    }
    fn append_field_elem<F: Scalar>(&mut self, field_elem: &F) {
        self.append_message(b"append field point", &field_elem.to_bytes());
    }
    fn append_eval_proof<PCS: PolyComScheme>(&mut self, proof: &PCS::EvalProof) {
        self.append_message(b"append eval proof", &proof.to_bytes());
    }
    fn get_challenge_field_elem<F: Scalar>(&mut self, label: &'static [u8]) -> F {
        let mut buff = [0u8; 32];
        self.challenge_bytes(label, &mut buff[..]);
        F::random(&mut rand_chacha::ChaChaRng::from_seed(buff))
    }
}
