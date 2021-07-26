use algebra::groups::Group;
use algebra::ristretto::RistrettoPoint;
use digest::Digest;
use itertools::Itertools;
use ruc::*;
use utils::errors::ZeiError;

#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenGens<G> {
    bases: Vec<G>,
}

impl<G: Group> PedersenGens<G> {
    /// create new pedersen bases for vector commitments of size n
    pub fn new(n: usize) -> PedersenGens<G> {
        let mut bases = vec![];
        let mut base = G::get_base();
        bases.push(base.clone());
        for _ in 0..n {
            let mut hash = sha2::Sha512::new();
            hash.input(base.to_compressed_bytes());
            base = G::from_hash(hash);
            bases.push(base.clone());
        }
        PedersenGens { bases }
    }
    /// returns the i-th base
    pub fn get_base(&self, index: usize) -> Option<&G> {
        self.bases.get(index)
    }

    /// returns the blinding base
    pub fn get_blinding_base(&self) -> &G {
        self.bases.last().unwrap()
    }

    /// commit
    pub fn commit(&self, values: &[G::S], blinding: &G::S) -> Result<G> {
        if values.len() != self.bases.len() - 1 {
            return Err(eg!(ZeiError::ParameterError));
        }
        let mut scalars = values.iter().collect_vec();
        scalars.push(blinding);
        let bases = self.bases.iter().collect_vec();
        // we use naive multi exp it gives us constant time, and we don't lose when |values| is small
        Ok(algebra::multi_exp::MultiExp::naive_multi_exp(
            scalars, bases,
        ))
    }
}

impl From<bulletproofs::PedersenGens> for PedersenGens<RistrettoPoint> {
    fn from(bp_pc_gens: bulletproofs::PedersenGens) -> Self {
        PedersenGens {
            bases: vec![
                RistrettoPoint(bp_pc_gens.B),
                RistrettoPoint(bp_pc_gens.B_blinding),
            ],
        }
    }
}
