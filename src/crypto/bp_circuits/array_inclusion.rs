use bulletproofs_yoloproof::r1cs::{Variable, ConstraintSystem};
use curve25519_dalek::scalar::Scalar;

pub fn array_membership<CS: ConstraintSystem>(
    cs: &mut CS,
    set: &[Scalar], elem: Variable)
 -> usize{
    let k = set.len();

    if k == 1{
        cs.constrain(set[0] - elem);
        return 0;
    }

    let (_,_, mut out) = cs.multiply(set[0] - elem, set[1] - elem);
    for i in 2..k{
        let (_,_,out_i) = cs.multiply(set[i] - elem, out.into());
        out = out_i;
    }
    cs.constrain(out.into());
    return k-1
}

#[cfg(test)]
mod test{
    use super::array_membership;
    use bulletproofs_yoloproof::r1cs::{Prover, Verifier};
    use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
    use merlin::Transcript;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn test_membership(){
        let pc_gens = PedersenGens::default();
        let set = [
            Scalar::from(0u8),
            Scalar::from(10u8),
            Scalar::from(30u8),
            Scalar::from(40u8),
            Scalar::from(50u8),
            Scalar::from(60u8),
            Scalar::from(70u8)];

        let mut prover_transcript = Transcript::new(b"TransactionTest");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let (com_elem, var_elem) = prover.commit(set[4], Scalar::from(1299u32));
        let left_wires = array_membership(&mut prover, &set[..], var_elem);
        let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"TransactionTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let ver_elem_var = verifier.commit(com_elem);
        let left_wires = array_membership(&mut verifier, &set[..], ver_elem_var);
        let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());

        let set = [
            Scalar::from(0u8),
            Scalar::from(10u8),
            Scalar::from(30u8),
            Scalar::from(40u8),
            Scalar::from(556756756u32),
            Scalar::from(60u8),
            Scalar::from(70u8)];
        let mut verifier_transcript = Transcript::new(b"TransactionTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let ver_elem_var = verifier.commit(com_elem);
        let left_wires = array_membership(&mut verifier, &set[..], ver_elem_var);
        let bp_gens = BulletproofGens::new(left_wires.next_power_of_two(), 1);
        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_err());
    }
}