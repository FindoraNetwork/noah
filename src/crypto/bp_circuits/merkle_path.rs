use bulletproofs_yoloproof::r1cs::{Variable, R1CSError, ConstraintSystem};
use super::mimc_hash::mimc_hash;

pub fn merkle_verify_mimc<CS: ConstraintSystem>(
    cs: &mut CS, element: Variable,
    path: &[(Variable, Variable)],
    root: Variable,
    tree_size: Variable,
) -> Result<(), R1CSError>
{
    let mut node = element.into();
    let path_len = path.len();
    let one = Variable::One();
    for level in (1 .. path_len).rev(){
        let (b,sibling) = path[path_len - level - 1];
        let (b,node_copy,b_x_node) = cs.multiply(b.into(), node);
        let (not_b,sibling_copy,not_b_x_sibling) =
            cs.multiply(one - b , sibling.into());

        let (_,_,b_x_sibling) = cs.multiply(b.into(), sibling_copy.into());
        let (_,_,not_b_x_node) = cs.multiply(not_b.into(), node_copy.into());

        //if b is 1, then path follow right direction, hence sibling is hashed on the left.
        //if b is 0, then path follow left direction, hence sibling is hashed on the right.
        // left child = b * sibling + (1 - b) * node
        // right child = b * node + (1 - b) * sibling
        node = mimc_hash(cs, &[b_x_sibling + not_b_x_node, b_x_node + not_b_x_sibling], level)?;
    }


    let (b,sibling) = path[path_len - 1];
    let (b,node_copy,b_x_node) = cs.multiply(b.into(), node);
    let (not_b,sibling_copy,not_b_x_sibling) =
        cs.multiply(one - b , sibling.into());

    let (_,_,b_x_sibling) = cs.multiply(b.into(), sibling_copy.into());
    let (_,_,not_b_x_node) = cs.multiply(not_b.into(), node_copy.into());
    node = mimc_hash(cs, &[tree_size.into(), b_x_sibling + not_b_x_node, b_x_node + not_b_x_sibling], 0)?;

    cs.constrain(node - root);
    Ok(())
}

#[cfg(test)]
mod test{
    use crate::crypto::accumulators::merkle_tree::{mt_build, mt_prove, MiMCHash, mt_verify, PathDirection};
    use curve25519_dalek::scalar::Scalar;
    use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
    use bulletproofs_yoloproof::r1cs::{Prover, Variable, Verifier};
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn test_bp_merkle_inclusion(){
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(10000, 1);
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

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
        let (merkle_tree, merkle_root) = mt_build::<Scalar, MiMCHash>(&elements).unwrap();
        let (elem, path) = mt_prove(&merkle_tree, 0);
        assert!(mt_verify::<_, MiMCHash>(&merkle_root, &elem, &path[..]));

        let mut prover_transcript = Transcript::new(b"MerkleTreePath");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let (com_size, var_size) = prover.commit(Scalar::from(merkle_root.size as u64), Scalar::random(&mut prng));
        let (com_root, var_root) = prover.commit(merkle_root.value, Scalar::random(&mut prng));
        let (com_elem, var_elem) = prover.commit(elem, Scalar::random(&mut prng));
        let com_var_path: Vec<((CompressedRistretto,CompressedRistretto),(Variable, Variable))> =
            path.
                iter().
                map(|(b,s)| {
                    let (com_b, var_b) = match  *b{
                        PathDirection::RIGHT =>  prover.commit(Scalar::from(1u8), Scalar::random(&mut prng)),
                        PathDirection::LEFT => prover.commit(Scalar::from(0u8), Scalar::random(&mut prng)),
                    };
                    let (com_s, var_s) = prover.commit(*s, Scalar::random(&mut prng));
                    ((com_b,com_s), (var_b, var_s))
        }).collect();
        let var_path: Vec<(Variable, Variable)> = com_var_path.iter().map(|(_,y)| y.clone()).collect();
        super::merkle_verify_mimc(&mut prover, var_elem, &var_path[..],var_root, var_size ).unwrap();
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"MerkleTreePath");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let ver_var_size = verifier.commit(com_size);
        let ver_var_root = verifier.commit(com_root);
        let ver_var_elem = verifier.commit(com_elem);
        let ver_var_path: Vec<(Variable, Variable)> =
            com_var_path.
                iter().
                map(|(coms,_)| {
                    let ver_var_b =  verifier.commit(coms.0);
                    let ver_var_s = verifier.commit(coms.1);
                    (ver_var_b, ver_var_s)
                }).collect();

        super::merkle_verify_mimc(&mut verifier, ver_var_elem, &ver_var_path[..],ver_var_root, ver_var_size).unwrap();
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

    }
}
