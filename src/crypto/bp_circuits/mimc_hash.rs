
#![allow(non_snake_case)]

use bulletproofs_yoloproof::r1cs::*;
use curve25519_dalek::scalar::Scalar;
use crate::crypto::accumulators::merkle_tree::{compute_mimc_constants, MiMCHash, MTHash};


pub(crate) fn mimc_func<CS: ConstraintSystem>(cs: &mut CS, x: LinearCombination, c: Scalar) -> Result<Variable, R1CSError>
{
    let c_var = cs.allocate(Some(c))?;
    let x_plus_c = x + c_var;
    let (left,_,out) = cs.multiply(x_plus_c.clone(), x_plus_c);
    let (_,_,out) = cs.multiply(out.into(), out.into());
    let (_,_,out) = cs.multiply(out.into(), left.into());
    Ok(out)
}


fn feistel_round<CS: ConstraintSystem>(cs: &mut CS, x: LinearCombination, y: LinearCombination, c: Scalar) -> Result<(LinearCombination, LinearCombination), R1CSError>
{
    let new_y = x.clone();
    let aux = mimc_func(cs, x, c)?;
    let new_x = y + aux;
    Ok((new_x, new_y))
}

pub(crate) fn feistel_network<CS: ConstraintSystem>(cs: &mut CS, x: LinearCombination, y: LinearCombination, c: &[Scalar]) -> Result<(LinearCombination, LinearCombination), R1CSError>
{
    let mut xi = x;
    let mut yi = y;
    for ci in c {
        let (a, b) = feistel_round(cs, xi, yi, *ci)?;
        xi = a;
        yi = b;
    }
    Ok((xi, yi))
}

pub(crate) fn mimc_hash<CS: ConstraintSystem>(cs: &mut CS, x: LinearCombination, y: LinearCombination, level: usize) -> Result<LinearCombination, R1CSError>{
    let c = compute_mimc_constants(level);

    let zero = cs.allocate(Some(Scalar::zero()))?;
    let (sa , sc) = feistel_network(cs, x.into(), zero.into() , &c[..])?;
    let (sa,_) = feistel_network(cs, y + sa, sc, &c[..])?;
     Ok(sa)
}

pub(crate) fn hash_proof<CS: ConstraintSystem>(cs: &mut CS, x: Variable, y: Variable, out: Variable) -> Result<(), R1CSError>{
    let sa = mimc_hash(cs, x.into(), y.into(), 1)?;
    cs.constrain(sa - out);
    Ok(())

}


#[cfg(test)]
mod test{
    use super::*;
    use merlin::Transcript;
    use bulletproofs_yoloproof::{PedersenGens, BulletproofGens};
    use bulletproofs_yoloproof::r1cs::Verifier;
    use curve25519_dalek::scalar::Scalar;
    use crate::crypto::accumulators::merkle_tree::MiMCHash;

    #[test]
    fn test_mimc_fn() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(10000, 1);
        let mut prover_transcript = Transcript::new(b"MiMCFunctionTest");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);


        let scalar_x = Scalar::from(2u8);
        let scalar_c = Scalar::from(0u8);
        let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
        let out = super::mimc_func(&mut prover, x.into(), scalar_c).unwrap();

        let expected_output = crate::crypto::accumulators::merkle_tree::mimc_f(&scalar_x, &scalar_c);
        let expected = prover.allocate(Some(expected_output)).unwrap();

        println!("{:?}", expected_output);

        prover.constrain(out - expected);

        let proof = prover.prove(&bp_gens).unwrap();


        let mut verifier_transcript = Transcript::new(b"MiMCFunctionTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let ver_x = verifier.commit(cx);
        let ver_out = super::mimc_func(&mut verifier, ver_x.into(), scalar_c).unwrap();
        let expected = verifier.allocate(Some(expected_output)).unwrap();
        verifier.constrain(ver_out - expected);

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }


    #[test]
    fn test_feistel_network() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(10000, 1);
        let mut prover_transcript = Transcript::new(b"FeistelNetworkTest");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);


        let scalar_x = Scalar::from(2u8);
        let scalar_y = Scalar::from(0u8);
        let scalar_c = [Scalar::from(0u8), Scalar::from(8u8),Scalar::from(0u8)];
        let (expected_output_x,expected_output_y) = crate::crypto::accumulators::merkle_tree::mimc_feistel(&scalar_x, &scalar_y, &scalar_c);
        println!("{:?}", expected_output_x);

        let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
        let (cy, y) = prover.commit(scalar_y, Scalar::from(11u8));
        let (outx,outy) = super::feistel_network(&mut prover, x.into(), y.into(), &scalar_c).unwrap();
        let expected_x = prover.allocate(Some(expected_output_x)).unwrap();
        let expected_y = prover.allocate(Some(expected_output_y)).unwrap();
        prover.constrain(outx - expected_x);
        prover.constrain(outy - expected_y);
        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"FeistelNetworkTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let ver_x = verifier.commit(cx);
        let ver_y = verifier.commit(cy);
        let (ver_out_x,ver_out_y) = super::feistel_network(&mut verifier, ver_x.into(), ver_y.into(), &scalar_c).unwrap();
        let expected_x = verifier.allocate(Some(expected_output_x)).unwrap();
        let expected_y = verifier.allocate(Some(expected_output_y)).unwrap();
        verifier.constrain(ver_out_x - expected_x);
        verifier.constrain(ver_out_y - expected_y);

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }


    #[test]
    fn test_mimc_hash() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(10000, 1);
        let mut prover_transcript = Transcript::new(b"MiMCHashTest");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let scalar_x = Scalar::from(10u8);
        let scalar_y = Scalar::from(20u8);
        let (cx, x) = prover.commit(scalar_x, Scalar::from(10u8));
        let (cy, y) = prover.commit(scalar_y, Scalar::from(11u8));
        let hasher = MiMCHash::new(1);
        let real_hash = hasher.digest(&scalar_x, &scalar_y);
        let (ch, h) = prover.commit(real_hash, Scalar::from(12u8));
        super::hash_proof(&mut prover, x, y, h).unwrap();

        let proof = prover.prove(&bp_gens).unwrap();

        let mut verifier_transcript = Transcript::new(b"MiMCHashTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let ver_x = verifier.commit(cx);
        let ver_y = verifier.commit(cy);
        let ver_h = verifier.commit(ch);
        super::hash_proof(&mut verifier, ver_x, ver_y, ver_h).unwrap();

        assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
    }

}


/*

#![allow(non_snake_case)]

use bulletproofs_yoloproof::r1cs::*;
use bulletproofs_yoloproof::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

// Shuffle gadget (documented in markdown file)

/// A proof-of-shuffle.
struct ShuffleProof(R1CSProof);

impl ShuffleProof {
    fn gadget<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        x: Vec<Variable>,
        y: Vec<Variable>,
        a: Variable,
        b: Variable,
    ) -> Result<(), R1CSError> {
        assert_eq!(x.len(), y.len());
        let k = x.len();

        if k == 1 {
            cs.constrain(y[0] - x[0]);
            return Ok(());
        }

        cs.specify_randomized_constraints(move |cs| {
            let z = cs.challenge_scalar(b"shuffle challenge");

            // Make last x multiplier for i = k-1 and k-2
            let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

            // Make multipliers for x from i == [0, k-3]
            let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
                o
            });

            // Make last y multiplier for i = k-1 and k-2
            let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

            // Make multipliers for y from i == [0, k-3]
            let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
                o
            });

            // Constrain last x mul output and last y mul output to be equal
            cs.constrain(first_mulx_out - first_muly_out);
            let var1 = cs.allocate(Some(Scalar::from(1u8)))?;
            cs.constrain((a - var1));

            Ok(())
        })
    }
}

impl ShuffleProof {
    /// Attempt to construct a proof that `output` is a permutation of `input`.
    ///
    /// Returns a tuple `(proof, input_commitments || output_commitments)`.
    pub fn prove<'a, 'b>(
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        input: &[Scalar],
        output: &[Scalar],
    ) -> Result<
        (
            ShuffleProof,
            Vec<CompressedRistretto>,
            Vec<CompressedRistretto>,
            CompressedRistretto,
            CompressedRistretto,
        ),
        R1CSError,
    > {
        // Apply a domain separator with the shuffle parameters to the transcript
        let k = input.len();
        transcript.commit_bytes(b"dom-sep", b"ShuffleProof");
        transcript.commit_bytes(b"k", Scalar::from(k as u64).as_bytes());

        let mut prover = Prover::new(&pc_gens, transcript);

        // Construct blinding factors using an RNG.
        // Note: a non-example implementation would want to operate on existing commitments.
        let mut blinding_rng = rand::thread_rng();

        let (input_commitments, input_vars): (Vec<_>, Vec<_>) = input
            .into_iter()
            .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
            .unzip();

        let (output_commitments, output_vars): (Vec<_>, Vec<_>) = output
            .into_iter()
            .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
            .unzip();

        let (a_c,a_var) = prover.commit(Scalar::from(0u8), Scalar::random(&mut blinding_rng ));
        let (b_c,b_var) = prover.commit(Scalar::from(1u8), Scalar::random(&mut blinding_rng ));

        ShuffleProof::gadget(&mut prover, input_vars, output_vars, a_var ,b_var)?;

        let proof = prover.prove(&bp_gens)?;

        Ok((ShuffleProof(proof), input_commitments, output_commitments, a_c, b_c))
    }
}

impl ShuffleProof {
    /// Attempt to verify a `ShuffleProof`.
    pub fn verify<'a, 'b>(
        &self,
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        input_commitments: &Vec<CompressedRistretto>,
        output_commitments: &Vec<CompressedRistretto>,
        a_commitment: &CompressedRistretto,
        b_commitment: &CompressedRistretto,

    ) -> Result<(), R1CSError> {
        // Apply a domain separator with the shuffle parameters to the transcript
        let k = input_commitments.len();
        transcript.commit_bytes(b"dom-sep", b"ShuffleProof");
        transcript.commit_bytes(b"k", Scalar::from(k as u64).as_bytes());

        let mut verifier = Verifier::new(transcript);

        let input_vars: Vec<_> = input_commitments
            .iter()
            .map(|V| verifier.commit(*V))
            .collect();

        let output_vars: Vec<_> = output_commitments
            .iter()
            .map(|V| verifier.commit(*V))
            .collect();

        let a_var = verifier.commit(*a_commitment);
        let b_var = verifier.commit(*b_commitment);

        ShuffleProof::gadget(&mut verifier, input_vars, output_vars, a_var, b_var)?;

        verifier.verify(&self.0, &pc_gens, &bp_gens)
    }
}

fn kshuffle_helper(k: usize) {
    use rand::Rng;

    // Common code
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new((2 * k + 1).next_power_of_two(), 1);

    let (proof, input_commitments, output_commitments, a_c, b_c) = {
        // Randomly generate inputs and outputs to kshuffle
        let mut rng = rand::thread_rng();
        let (min, max) = (0u64, std::u64::MAX);
        let input: Vec<Scalar> = (0..k)
            .map(|_| Scalar::from(rng.gen_range(min, max)))
            .collect();
        let mut output = input.clone();
        rand::thread_rng().shuffle(&mut output);

        let mut prover_transcript = Transcript::new(b"ShuffleProofTest");
        ShuffleProof::prove(&pc_gens, &bp_gens, &mut prover_transcript, &input, &output).unwrap()
    };

    {
        let mut verifier_transcript = Transcript::new(b"ShuffleProofTest");
        assert!(proof
            .verify(
                &pc_gens,
                &bp_gens,
                &mut verifier_transcript,
                &input_commitments,
                &output_commitments,
                &a_c,
                &b_c

            )
            .is_ok());
    }
}

mod test{
    use super::*;
    #[test]
    fn shuffle_gadget_test_1() {
        kshuffle_helper(1);
    }

    #[test]
    fn shuffle_gadget_test_2() {
        kshuffle_helper(2);
    }

    #[test]
    fn shuffle_gadget_test_3() {
        kshuffle_helper(3);
    }

    #[test]
    fn shuffle_gadget_test_4() {
        kshuffle_helper(4);
    }

    #[test]
    fn shuffle_gadget_test_5() {
        kshuffle_helper(5);
    }

    #[test]
    fn shuffle_gadget_test_6() {
        kshuffle_helper(6);
    }

    #[test]
    fn shuffle_gadget_test_7() {
        kshuffle_helper(7);
    }

    #[test]
    fn shuffle_gadget_test_24() {
        kshuffle_helper(24);
    }

    #[test]
    fn shuffle_gadget_test_42() {
        kshuffle_helper(42);
    }

    /// Constrains (a1 + a2) * (b1 + b2) = (c1 + c2)
    fn example_gadget<CS: ConstraintSystem>(
        cs: &mut CS,
        a1: LinearCombination,
        a2: LinearCombination,
        b1: LinearCombination,
        b2: LinearCombination,
        c1: LinearCombination,
        c2: LinearCombination,
    ) {
        let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
        cs.constrain(c1 + c2 - c_var);
    }

    // Prover's scope
    fn example_gadget_proof(
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
        let mut transcript = Transcript::new(b"R1CSExampleGadget");

        // 1. Create a prover
        let mut prover = Prover::new(pc_gens, &mut transcript);

        // 2. Commit high-level variables
        let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
            .into_iter()
            .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
            .unzip();

        // 3. Build a CS
        example_gadget(
            &mut prover,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            vars[4].into(),
            Scalar::from(c2).into(),
        );

        // 4. Make a proof
        let proof = prover.prove(bp_gens)?;

        Ok((proof, commitments))
    }

    // Verifier logic
    fn example_gadget_verify(
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        c2: u64,
        proof: R1CSProof,
        commitments: Vec<CompressedRistretto>,
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"R1CSExampleGadget");

        // 1. Create a verifier
        let mut verifier = Verifier::new(&mut transcript);

        // 2. Commit high-level variables
        let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

        // 3. Build a CS
        example_gadget(
            &mut verifier,
            vars[0].into(),
            vars[1].into(),
            vars[2].into(),
            vars[3].into(),
            vars[4].into(),
            Scalar::from(c2).into(),
        );

        // 4. Verify the proof
        verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(|_| R1CSError::VerificationError)
    }

    fn example_gadget_roundtrip_helper(
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

        example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
    }

    fn example_gadget_roundtrip_serialization_helper(
        a1: u64,
        a2: u64,
        b1: u64,
        b2: u64,
        c1: u64,
        c2: u64,
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

        let proof = proof.to_bytes();

        let proof = R1CSProof::from_bytes(&proof)?;

        example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
    }

    #[test]
    fn example_gadget_test() {
        // (3 + 4) * (6 + 1) = (40 + 9)
        assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 9).is_ok());
        // (3 + 4) * (6 + 1) != (40 + 10)
        assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 10).is_err());
    }

    #[test]
    fn example_gadget_serialization_test() {
        // (3 + 4) * (6 + 1) = (40 + 9)
        assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
        // (3 + 4) * (6 + 1) != (40 + 10)
        assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
    }

    // Range Proof gadget

    /// Enforces that the quantity of v is in the range [0, 2^n).
    pub fn range_proof<CS: ConstraintSystem>(
        cs: &mut CS,
        mut v: LinearCombination,
        v_assignment: Option<u64>,
        n: usize,
    ) -> Result<(), R1CSError> {
        let mut exp_2 = Scalar::one();
        for i in 0..n {
            // Create low-level variables and add them to constraints
            let (a, b, o) = cs.allocate_multiplier(v_assignment.map(|q| {
                let bit: u64 = (q >> i) & 1;
                ((1 - bit).into(), bit.into())
            }))?;

            // Enforce a * b = 0, so one of (a,b) is zero
            cs.constrain(o.into());

            // Enforce that a = 1 - b, so they both are 1 or 0.
            cs.constrain(a + (b - 1u64));

            // Add `-b_i*2^i` to the linear combination
            // in order to form the following constraint by the end of the loop:
            // v = Sum(b_i * 2^i, i = 0..n-1)
            v = v - b * exp_2;

            exp_2 = exp_2 + exp_2;
        }

        // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
        cs.constrain(v);

        Ok(())
    }

    #[test]
    fn range_proof_gadget() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = OsRng::new().unwrap();
        let m = 3; // number of values to test per `n`

        for n in [2, 10, 32, 63].iter() {
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            for v in values {
                assert!(range_proof_helper(v.into(), *n).is_ok());
            }
            assert!(range_proof_helper((max + 1).into(), *n).is_err());
        }
    }

    fn range_proof_helper(v_val: u64, n: usize) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitment) = {
            // Prover makes a `ConstraintSystem` instance representing a range proof gadget
            let mut prover_transcript = Transcript::new(b"RangeProofTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            let (com, var) = prover.commit(v_val.into(), Scalar::random(&mut rng));
            assert!(range_proof(&mut prover, var.into(), Some(v_val), n).is_ok());

            let proof = prover.prove(&bp_gens)?;

            (proof, com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"RangeProofTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var = verifier.commit(commitment);

        // Verifier adds constraints to the constraint system
        assert!(range_proof(&mut verifier, var.into(), None, n).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
    }
}
*/
