use crate::errors::Result;
use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
use crate::hashing_to_the_curve::models::elligator::{ElligatorParameters, ElligatorTrace};
use ark_bulletproofs::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
use ark_ed25519::Fq;
use ark_ff::Field;
use noah_algebra::ed25519::Ed25519Point;

/// A trace variable.
#[allow(unused)]
struct TraceVar {
    a2_var: Variable<Fq>,
    a3_var: Variable<Fq>,
    b1_var: Variable<Fq>,
}

impl TraceVar {
    /// Create a new point variable from field variables.
    #[allow(unused)]
    pub(crate) fn new(a2_var: Variable<Fq>, a3_var: Variable<Fq>, b1_var: Variable<Fq>) -> Self {
        Self {
            a2_var,
            a3_var,
            b1_var,
        }
    }

    /// Allocate a point in Bulletproofs.
    #[allow(unused)]
    pub(crate) fn allocate<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        trace: &Option<ElligatorTrace<Ed25519Point>>,
    ) -> Result<Self> {
        if trace.is_some() {
            let trace = trace.as_ref().unwrap();
            let a2_var = cs.allocate(Some(trace.a2.get_raw()))?;

            let a3_var = cs.allocate(Some(trace.a3.get_raw()))?;

            let b1_elem = if trace.b1 { Fq::ONE } else { Fq::ZERO };
            let b1_var = cs.allocate(Some(b1_elem))?;

            Ok(Self::new(a2_var, a3_var, b1_var))
        } else {
            let a2_var = cs.allocate(None)?;
            let a3_var = cs.allocate(None)?;
            let b1_var = cs.allocate(None)?;

            Ok(Self::new(a2_var, a3_var, b1_var))
        }
    }
}

/// A proof of scalar multiplication.
pub struct HashingGadget;

impl HashingGadget {
    #[allow(unused)]
    fn gadget<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        trace_var: &TraceVar,
        t_var: &Variable<Fq>,
        final_var: &Variable<Fq>,
    ) -> Result<()> {
        let (_, _, t_sq_var) = cs.multiply((*t_var).into(), (*t_var).into());

        let (_, _, a2_mul_a2_inv) = cs.multiply(
            t_sq_var * (Ed25519ElligatorParameters::QNR.get_raw()) + Fq::ONE,
            trace_var.a2_var.into(),
        );
        cs.constrain(a2_mul_a2_inv - Fq::ONE);

        let (_, _, b1_mul_minus_b1) = cs.multiply(
            trace_var.b1_var.into(),
            -LinearCombination::from(trace_var.b1_var) + Fq::ONE,
        );
        cs.constrain(b1_mul_minus_b1.into());

        let x1_var = -trace_var.a2_var * Ed25519ElligatorParameters::A.get_raw();

        let (_, _, x1_sq_var) = cs.multiply(x1_var.clone(), x1_var.clone());
        let (_, _, x1_cubic_var) = cs.multiply(x1_sq_var.into(), x1_var.clone());

        let y_squared_var = x1_cubic_var
            + x1_sq_var * Ed25519ElligatorParameters::A.get_raw()
            + x1_var.clone() * Ed25519ElligatorParameters::B.get_raw();

        let (_, _, a3_sq_var) = cs.multiply(trace_var.a3_var.into(), trace_var.a3_var.into());
        let (_, _, y_squared_adjusted_var) = cs.multiply(
            y_squared_var,
            LinearCombination::from(trace_var.b1_var)
                * (Fq::ONE - Ed25519ElligatorParameters::QNR.get_raw())
                + Ed25519ElligatorParameters::QNR.get_raw(),
        );

        cs.constrain(a3_sq_var - y_squared_adjusted_var);

        let (_, _, b1_times_double_x1_plus_a) = cs.multiply(
            trace_var.b1_var.into(),
            x1_var.clone() * Fq::from(2u32)
                + Ed25519ElligatorParameters::A.get_raw(),
        );

        cs.constrain(
            LinearCombination::from((*final_var))
                + Ed25519ElligatorParameters::A.get_raw()
                + x1_var.clone()
                - b1_times_double_x1_plus_a,
        );

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::bulletproofs::hashing_to_the_curve::ed25519_elligator::{HashingGadget, TraceVar};
    use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
    use crate::hashing_to_the_curve::models::elligator::Elligator;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use ark_bulletproofs::curve::zorro::G1Affine as G1AffineBig;
    use ark_bulletproofs::r1cs::{Prover, Verifier};
    use ark_bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use noah_algebra::ed25519::Ed25519Point;
    use noah_algebra::prelude::*;
    use noah_algebra::zorro::{PedersenCommitmentZorro, ZorroScalar};

    #[test]
    fn test_gadget() {
        let prng = &mut test_rng();

        let t = ZorroScalar::random(prng);
        let (final_x, trace) =
            Elligator::<Ed25519Point, Ed25519ElligatorParameters>::get_cofactor_uncleared_x_and_trace(&t).unwrap();

        let bp_gens = BulletproofGens::new(2048, 1);
        let pc_gens = PedersenCommitmentZorro::default();

        let prover_transcript = Transcript::new(b"ElligatorGadgetUnitTest");

        let pc_gens_for_prover = PedersenGens::<G1AffineBig>::from(&pc_gens);
        let mut prover = Prover::new(&pc_gens_for_prover, prover_transcript);

        let t_blinding = ZorroScalar::random(prng).get_raw();
        let (t_comm, t_var) = prover.commit(t.get_raw(), t_blinding);

        let x_blinding = ZorroScalar::random(prng).get_raw();
        let (x_comm, x_var) = prover.commit(final_x.get_raw(), x_blinding);

        let trace_var = TraceVar::allocate(&mut prover, &Some(trace)).unwrap();

        HashingGadget::gadget(&mut prover, &trace_var, &t_var, &x_var).unwrap();

        let proof = prover.prove(prng, &bp_gens).unwrap();

        let verifier_transcript = Transcript::new(b"ElligatorGadgetUnitTest");
        let mut verifier = Verifier::new(verifier_transcript);

        let t_var = verifier.commit(t_comm);
        let x_var = verifier.commit(x_comm);

        let trace_var = TraceVar::allocate(&mut verifier, &None).unwrap();

        HashingGadget::gadget(&mut verifier, &trace_var, &t_var, &x_var).unwrap();

        let pc_gens_for_verifier = PedersenGens::<G1AffineBig>::from(&pc_gens);
        verifier
            .verify(&proof, &pc_gens_for_verifier, &bp_gens)
            .unwrap();
    }
}
