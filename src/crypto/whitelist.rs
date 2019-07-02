use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
use bulletproofs_yoloproof::r1cs::{R1CSProof, Prover, Variable, Verifier};
use crate::crypto::accumulators::merkle_tree::{MerkleTree, mt_build, MerkleRoot, mt_prove, PathDirection, MiMCHash};
use crate::crypto::bp_circuits::array_inclusion::array_membership;
use crate::crypto::bp_circuits::merkle_path::merkle_verify_mimc;
use crate::errors::ZeiError;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::{CryptoRng, Rng};


pub const THRESHOLD: usize = 10;

pub fn build_mt_whitelist(elements: &[Scalar]) -> Result<MerkleTree<Scalar>, ZeiError> {
    mt_build::<Scalar, MiMCHash>(elements)
}

pub struct WhitelistProof{
    witness_commitments: Vec<CompressedRistretto>,
    proof: R1CSProof,
}

pub fn prove_mt_membership<R: CryptoRng + Rng>(
    prng: &mut R,
    mt: &MerkleTree<Scalar>,
    index: usize,
    elem: &CompressedRistretto,
    blind: &Scalar) -> Result<WhitelistProof, ZeiError>
{
    let pc_gens = PedersenGens::default();

    let mut witness_commitments = vec![];


    let (s, path) = mt_prove(mt, index)?;
    let mut prover_transcript = Transcript::new(b"MerkleTreePath");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let (com_elem, var_elem) = prover.commit(s, *blind);
    if com_elem != *elem {
        return Err(ZeiError::ParameterError);
    }
    let mut var_path = vec![];
    for (direction, sibling) in path.iter() {
        let (dir_com, dir_var) = match *direction {
            PathDirection::RIGHT => prover.commit(Scalar::from(1u8), Scalar::random(prng)),
            PathDirection::LEFT => prover.commit(Scalar::from(0u8), Scalar::random(prng)),
        };
        let (sibling_com, sibling_var) = prover.commit(*sibling, Scalar::random(prng));
        var_path.push((dir_var, sibling_var));
        witness_commitments.push(dir_com);
        witness_commitments.push(sibling_com);
    }

    let num_left_wires = merkle_verify_mimc(&mut prover, var_elem, &var_path[..], mt.root.value, Scalar::from(mt.size as u64)).unwrap();
    let num_gens = num_left_wires.next_power_of_two();
    let bp_gens = BulletproofGens::new(num_gens, 1);
    let proof = prover.prove(&bp_gens).map_err(|_| ZeiError::WhitelistProveError)?;

    Ok(WhitelistProof{
        witness_commitments,
        proof,
    })
}
pub fn prove_array_membership(
    elements: &[Scalar],
    index: usize,
    elem: &CompressedRistretto,
    blind: &Scalar
) -> Result<WhitelistProof, ZeiError>
{
    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new(b"LinearInclusionProof");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    let (com_elem, var_elem) = prover.commit(elements[index], *blind);
    assert!(com_elem == *elem);
    let left_wires = array_membership(&mut prover, &elements[..], var_elem);
    let bp_gens= BulletproofGens::new(left_wires.next_power_of_two(), 1);
    let proof = prover.prove(&bp_gens).map_err(|_| ZeiError::WhitelistProveError)?;

    Ok(WhitelistProof{
        witness_commitments: vec![],
        proof,
    })
}

pub fn verify_mt_membership(
    mt_root: &MerkleRoot<Scalar>,
    elem_com: &CompressedRistretto,
    proof: &WhitelistProof
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();

    let mut verifier_transcript = Transcript::new(b"MerkleTreePath");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let elem_var = verifier.commit(*elem_com);
    let mut path_var = vec![];
    let mut direction: Variable = Variable::One();
    let mut even = true;
    for e in proof.witness_commitments.iter() {
        match even {
            true => {
                direction = verifier.commit(*e);
            }
            false => {
                let sibling = verifier.commit(*e);
                path_var.push((direction, sibling));
            }
        }
        even = !even;
    }
    let num_left_wires = merkle_verify_mimc(
        &mut verifier,
        elem_var,
        &path_var[..],
        mt_root.value,
        Scalar::from(mt_root.size as u64)).map_err(|_| ZeiError::WhitelistVerificationError)?;

    let num_gens = num_left_wires.next_power_of_two();
    let bp_gens = BulletproofGens::new(num_gens, 1);
    verifier.verify(&proof.proof, &pc_gens, &bp_gens).map_err(|_| ZeiError::WhitelistVerificationError)
}
pub fn verify_array_membership(
    elements: &[Scalar],
    elem_com: & CompressedRistretto,
    proof: &WhitelistProof
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();
    let mut verifier_transcript = Transcript::new(b"LinearInclusionProof");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let elem_var = verifier.commit(*elem_com);

    let num_left_wires = array_membership(&mut verifier, &elements[..], elem_var);
    let bp_gens = BulletproofGens::new(num_left_wires.next_power_of_two(), 1);
    verifier.verify(&proof.proof, &pc_gens, &bp_gens).map_err(|_| ZeiError::WhitelistVerificationError)
}

#[cfg(test)]
mod test{
    use crate::crypto::whitelist::build_mt_whitelist;
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use bulletproofs::PedersenGens;

    #[test]
    fn test_mt_membership() {
        let elements = [
            Scalar::from(1u8),
            Scalar::from(2u8),
            Scalar::from(3u8),
            Scalar::from(4u8),
            Scalar::from(5u8),
            Scalar::from(6u8),
            Scalar::from(7u8),
            Scalar::from(8u8),
        ];
        let mt = build_mt_whitelist(&elements).unwrap();

        let mut prng = ChaChaRng::from_seed([0u8;32]);

        let pc_gens = PedersenGens::default();
        for index in  &[0usize,5,7]{
            let blind = Scalar::random(&mut prng);
            let commitment = pc_gens.commit(elements[*index], blind).compress();
            let proof = super::prove_mt_membership(
                &mut prng,
                &mt,
                *index,
                &commitment,
                &blind).unwrap();

            assert!(super::verify_mt_membership(
                &mt.get_root(),
                &commitment,
                &proof).is_ok())
        }
    }

    #[test]
    fn test_array_membership() {
        let elements = [
            Scalar::from(1u8),
            Scalar::from(2u8),
            Scalar::from(3u8),
            Scalar::from(4u8),
            Scalar::from(5u8),
            Scalar::from(6u8),
            Scalar::from(7u8),
            Scalar::from(8u8),
        ];

        let mut prng = ChaChaRng::from_seed([0u8;32]);

        let pc_gens = PedersenGens::default();
        for index in 0usize..elements.len(){
            let blind = Scalar::random(&mut prng);
            let commitment = pc_gens.commit(elements[index], blind).compress();
            let proof = super::prove_array_membership(
                &elements,
                index,
                &commitment,
                &blind).unwrap();

            assert!(super::verify_array_membership(
                &elements,
                &commitment,
                &proof).is_ok())
        }
    }

}