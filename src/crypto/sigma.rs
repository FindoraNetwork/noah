use merlin::Transcript;
use crate::algebra::groups::{Scalar, Group};

pub trait SigmaTranscript {
    fn init_sigma<S: Scalar, G: Group<S>>(&mut self, instance_name: &'static [u8], public_scalars: &[&S], public_elems: &[&G]);
    fn append_proof_commitment<S: Scalar, G: Group<S>>(&mut self, elem: &G);
    fn get_challenge<S: Scalar>(&mut self) -> S;
}

impl SigmaTranscript for Transcript{
    fn init_sigma<S: Scalar, G: Group<S>>(&mut self, instance_name: &'static [u8], public_scalars: &[&S], public_elems: &[&G]){
        self.append_message(b"Sigma Protocol domain", b"Sigma protocol single group v.0.1");
        self.append_message(b"Sigma Protocol instance", instance_name);
        for scalar in public_scalars{
            self.append_message(b"public scalar", scalar.to_bytes().as_slice())
        }
        for elem in public_elems{
            self.append_message(b"public elem", elem.to_compressed_bytes().as_slice())
        }
    }
    fn append_proof_commitment<S: Scalar, G: Group<S>>(&mut self, elem: &G){
        self.append_message(b"proof_commitment", elem.to_compressed_bytes().as_slice());
    }
    fn get_challenge<S: Scalar>(&mut self) -> S{
        let mut buffer = vec![0u8; 32]; // TODO(fernando) get number of bytes needed from S and remove the number 32
        self.challenge_bytes(b"Sigma challenge", &mut buffer);
        S::from_bytes(buffer.as_slice())
    }
}
