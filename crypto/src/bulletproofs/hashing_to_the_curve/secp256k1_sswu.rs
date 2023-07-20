use crate::errors::Result;
use crate::hashing_to_the_curve::models::sswu::{SSWUParameters, SSWUTrace};
use crate::hashing_to_the_curve::secp256k1::sswu::Secp256k1SSWUParameters;
use ark_bulletproofs::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
use ark_ff::Field;
use ark_secp256k1::Fq;
use noah_algebra::secp256k1::SECP256K1G1;

/// A trace variable.
#[allow(unused)]
struct TraceVar {
    a3_var: Variable<Fq>,
    b1_var: Variable<Fq>,
    a4_var: Variable<Fq>,
}

impl TraceVar {
    /// Create a new point variable from field variables.
    #[allow(unused)]
    pub(crate) fn new(a3_var: Variable<Fq>, b1_var: Variable<Fq>, a4_var: Variable<Fq>) -> Self {
        Self {
            a3_var,
            b1_var,
            a4_var,
        }
    }

    /// Allocate a point in Bulletproofs.
    #[allow(unused)]
    pub(crate) fn allocate<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        trace: &Option<SSWUTrace<SECP256K1G1>>,
    ) -> Result<Self> {
        if trace.is_some() {
            let trace = trace.as_ref().unwrap();
            let a3_var = cs.allocate(Some(trace.a3.get_raw()))?;

            let a4_var = cs.allocate(Some(trace.a4.get_raw()))?;

            let b1_elem = if trace.b1 { Fq::ONE } else { Fq::ZERO };
            let b1_var = cs.allocate(Some(b1_elem))?;

            Ok(Self::new(a3_var, b1_var, a4_var))
        } else {
            let a3_var = cs.allocate(None)?;
            let a4_var = cs.allocate(None)?;
            let b1_var = cs.allocate(None)?;

            Ok(Self::new(a3_var, b1_var, a4_var))
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
        let (_, _, t2_var) = cs.multiply(
            (*t_var).into(),
            LinearCombination::from(*t_var) * Secp256k1SSWUParameters::QNR.get_raw(),
        );
        let (_, _, t4_var) = cs.multiply(t2_var.into(), t2_var.into());

        let a3_inv_var = LinearCombination::from(t4_var) + t2_var;
        let (_, _, a3_mul_a3_inv_var) = cs.multiply(trace_var.a3_var.into(), a3_inv_var);
        cs.constrain(a3_mul_a3_inv_var - Fq::ONE);

        let x1_var = (LinearCombination::from(trace_var.a3_var) + Fq::ONE)
            * Secp256k1SSWUParameters::C1.get_raw();

        let (_, _, x1_sq_var) = cs.multiply(x1_var.clone(), x1_var.clone());
        let (_, _, x1_cubic_var) = cs.multiply(x1_sq_var.into(), x1_var.clone());

        let y_squared_var = LinearCombination::from(x1_cubic_var)
            + Secp256k1SSWUParameters::B.get_raw()
            + x1_var.clone() * Secp256k1SSWUParameters::A.get_raw();

        let (_, _, a4_sq_var) = cs.multiply(trace_var.a4_var.into(), trace_var.a4_var.into());
        let (_, _, y_squared_adjusted_var) = cs.multiply(
            y_squared_var,
            LinearCombination::from(trace_var.b1_var)
                * (Fq::ONE - Secp256k1SSWUParameters::QNR.get_raw())
                + Secp256k1SSWUParameters::QNR.get_raw(),
        );
        cs.constrain(a4_sq_var - y_squared_adjusted_var);

        //   b1 * 1 + (1 - b1) * t2
        // = b1 + t2 - b1 * t2

        let (_, _, b1_t2_var) = cs.multiply(trace_var.b1_var.into(), t2_var.into());
        let x_multiplier_var = LinearCombination::from(trace_var.b1_var) + t2_var - b1_t2_var;

        let (_, _, x_var) = cs.multiply(x_multiplier_var, x1_var);

        let mut numerator_var = LinearCombination::<Fq>::from(
            Secp256k1SSWUParameters::get_isogeny_numerator_term(0).get_raw(),
        );
        let mut denominator_var = LinearCombination::<Fq>::from(
            Secp256k1SSWUParameters::get_isogeny_denominator_term(0).get_raw(),
        );

        let degree = Secp256k1SSWUParameters::ISOGENY_DEGREE;
        let mut cur_var = x_var;
        for i in 1u32..degree {
            numerator_var = numerator_var
                + cur_var
                    * Secp256k1SSWUParameters::get_isogeny_numerator_term(i as usize).get_raw();
            denominator_var = denominator_var
                + cur_var
                    * Secp256k1SSWUParameters::get_isogeny_denominator_term(i as usize).get_raw();

            let (_, _, new_cur_var) = cs.multiply(cur_var.into(), x_var.into());
            cur_var = new_cur_var;
        }
        numerator_var = numerator_var
            + cur_var
                * Secp256k1SSWUParameters::get_isogeny_numerator_term(degree as usize).get_raw();

        let (_, _, denominator_times_res_var) = cs.multiply(denominator_var, (*final_var).into());
        cs.constrain(numerator_var - denominator_times_res_var);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::bulletproofs::hashing_to_the_curve::secp256k1_sswu::{HashingGadget, TraceVar};
    use crate::hashing_to_the_curve::models::sswu::SSWUMap;
    use crate::hashing_to_the_curve::secp256k1::sswu::Secp256k1SSWUParameters;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use ark_bulletproofs::r1cs::{Prover, Verifier};
    use ark_bulletproofs::{BulletproofGens, PedersenGens};
    use ark_secq256k1::Affine as G1AffineBig;
    use merlin::Transcript;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::SECP256K1G1;
    use noah_algebra::secq256k1::{PedersenCommitmentSecq256k1, SECQ256K1Scalar};

    #[test]
    fn test_gadget() {
        let prng = &mut test_rng();

        let t = SECQ256K1Scalar::random(prng);
        let (final_x, trace) =
            SSWUMap::<SECP256K1G1, Secp256k1SSWUParameters>::get_cofactor_uncleared_x_and_trace(&t)
                .unwrap();

        let bp_gens = BulletproofGens::new(2048, 1);
        let pc_gens = PedersenCommitmentSecq256k1::default();

        let prover_transcript = Transcript::new(b"SSWUGadgetUnitTest");

        let pc_gens_for_prover = PedersenGens::<G1AffineBig>::from(&pc_gens);
        let mut prover = Prover::new(&pc_gens_for_prover, prover_transcript);

        let t_blinding = SECQ256K1Scalar::random(prng).get_raw();
        let (t_comm, t_var) = prover.commit(t.get_raw(), t_blinding);

        let x_blinding = SECQ256K1Scalar::random(prng).get_raw();
        let (x_comm, x_var) = prover.commit(final_x.get_raw(), x_blinding);

        let trace_var = TraceVar::allocate(&mut prover, &Some(trace)).unwrap();

        HashingGadget::gadget(&mut prover, &trace_var, &t_var, &x_var).unwrap();

        let proof = prover.prove(prng, &bp_gens).unwrap();

        let verifier_transcript = Transcript::new(b"SSWUGadgetUnitTest");
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
